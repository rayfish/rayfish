#![cfg(unix)]

//! Embedded mesh SSH server (`ray firewall ssh on`), Tailscale-style.
//!
//! The daemon runs a small SSH server bound to each of this node's mesh IPs on
//! port 22. A stock `ssh` client connecting to `<peer>.ray` (or the mesh IP)
//! lands here. There are no SSH keys: the connecting peer is already
//! cryptographically identified by the QUIC mesh link, and the kernel TCP stack
//! delivers the connection with the peer's mesh IP as the socket source (the
//! ingress anti-spoof check in [`crate::forward`] guarantees that IP is really
//! the peer's). We map that IP back to the peer identity via [`PeerTable`] and
//! admit the session iff the peer is in a shared network's `ssh_allow` list.
//!
//! Authorization is the only gate; SSH auth itself is the `none` method (the
//! identity is already proven). For now an authorized peer may log in as any
//! local unix user, including root; tighter user-mapping is future work.
//!
//! An authorized peer gets what a stock sshd session gives it: shells, `exec`,
//! sftp (so `scp` works), forwarding in both directions (`ssh -L`, `-D`,
//! `ProxyJump`, `-R`, and the unix-socket forms of both), agent forwarding
//! (`ssh -A`), locale environment variables, and signals. X11 forwarding is the
//! one thing missing, and it is refused explicitly rather than left hanging.
//!
//! An interactive session is handed to `login(1)` where the host has one, so
//! the things a directly-spawned shell silently skips come from the system
//! instead of from us: the PAM account check (a locked or expired account is
//! refused), the PAM session (logind session, `XDG_RUNTIME_DIR`, resource
//! limits), the utmp/wtmp records behind `who` and `last`, `/etc/nologin` and
//! the motd. Root is the exception: `login` refuses a root session on a tty
//! outside `/etc/securetty`, and refuses it by hanging, so root (and every
//! non-interactive session, which has no login record either way) still spawns
//! the shell directly.
//!
//! Forwarding runs in the daemon, which is root, so two rules keep it from
//! being worth more than a shell on the same host. A TCP forward goes anywhere
//! the host can reach (loopback services included), exactly like a shell would.
//! A unix-socket forward is checked against the login account's own permission
//! on the socket (or on the directory it would be created in) first, because
//! there the filesystem *is* the access control and root ignores it.
//!
//! Authorization is evaluated once, when the connection is accepted, so
//! `ray firewall ssh allow/deny` changes apply to *new* sessions; an
//! already-established session is not torn down by a later `deny`.

use std::collections::HashMap;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use iroh::EndpointId;
use pty_process::Size;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Sig};
use smol_str::SmolStr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::peers::{DeviceUserMap, PeerTable};

// The port a stock `ssh` client targets (`ssh user@host.ray`) and the internal
// port the embedded server actually binds. Both live in `crate::forward` (the
// always-compiled core) because the userspace SSH NAT there rewrites mesh `:22`
// <-> the listen port on every platform, including Android where this module is
// gated out. We can't bind `:22` directly: a host sshd on `0.0.0.0:22` makes the
// kernel reject a more-specific `<mesh-ip>:22` bind (EADDRINUSE), so the daemon
// binds `SSH_LISTEN_PORT` and translates the port in the forwarding path instead
// of an OS-firewall redirect. Re-exported here so the public path stays stable.
pub(crate) use crate::forward::{SSH_LISTEN_PORT, SSH_PORT};

/// How long a `ssh -L` / `-D` forwarded connection may take to reach its target
/// before the channel is dropped. Short enough that a black-holed address fails
/// while the person who typed the command is still watching.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-network SSH authorization snapshot: network name -> the network's SSH
/// allow rules (peer + permitted login users). Held in an [`ArcSwap`] so
/// `ray firewall ssh allow/deny` updates are picked up by a live listener
/// without a restart.
pub type SshAuthz = Arc<ArcSwap<HashMap<String, Vec<crate::config::SshRule>>>>;

/// Build an empty authorization snapshot.
pub fn new_authz() -> SshAuthz {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

/// The set of local unix accounts a peer may log in as, accumulated across the
/// networks shared with it. `*` (any user, including root) wins over everything;
/// an allow rule with no explicit users grants the non-root default; explicit
/// usernames grant exactly those. The per-user check is by **uid** so a uid-0
/// account under a non-`root` name can't slip past the non-root default.
#[derive(Default, Debug, PartialEq)]
struct UserPolicy {
    /// Some rule matched this peer (it may open a session at all).
    matched: bool,
    /// A rule granted `*`: any user, including root.
    any: bool,
    /// A rule granted the default (no explicit users): any non-root user.
    nonroot: bool,
    /// Explicitly named users.
    users: std::collections::HashSet<String>,
}

impl UserPolicy {
    /// Fold one matching rule's `users` list into the policy.
    fn add(&mut self, users: &[String]) {
        self.matched = true;
        if users.iter().any(|u| u == "*") {
            self.any = true;
        } else if users.is_empty() {
            self.nonroot = true;
        } else {
            self.users.extend(users.iter().cloned());
        }
    }

    /// Whether the peer is authorized to open a session at all (before the
    /// per-user check). No matching rule => reject every auth attempt.
    fn authorized(&self) -> bool {
        self.matched
    }

    /// Whether the requested login (`name`, resolved to `uid`) is permitted.
    fn permits(&self, name: &str, uid: u32) -> bool {
        self.any || self.users.contains(name) || (self.nonroot && uid != 0)
    }

    /// Which logins this policy grants, phrased for the SSH banner. `None` when
    /// the policy allows every user, since there is nothing the client needs
    /// warning about.
    fn restriction(&self) -> Option<String> {
        if self.any {
            return None;
        }
        let mut named: Vec<&str> = self.users.iter().map(String::as_str).collect();
        named.sort_unstable();
        Some(match (self.nonroot, named.is_empty()) {
            (true, true) => "any user except root".to_string(),
            (true, false) => format!("any user except root, plus {}", named.join(", ")),
            (false, false) => named.join(", "),
            (false, true) => "no users".to_string(),
        })
    }
}

/// The banner shown before authentication, or `None` when this peer can log in
/// unrestricted and there is nothing to explain.
///
/// Without it a rejection is invisible: mesh SSH offers only the `none` method,
/// so a client that is refused silently falls through to whatever the *system*
/// sshd offers and prompts for a password. Every mesh SSH authorization problem
/// then presents as "why is it asking for a password", or worse as a network
/// fault, with the real reason only in this node's log where the person
/// connecting cannot see it. Say it on the wire instead.
fn auth_banner(policy: &UserPolicy, peer: &EndpointId, networks: &[SmolStr]) -> Option<String> {
    let net = networks
        .iter()
        .min()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "<network>".to_string());
    if !policy.authorized() {
        return Some(format!(
            "rayfish mesh SSH: peer {} is not authorized on this node.\r\n\
             Authorize it here with: ray firewall ssh allow {net} {} [-u <users>]\r\n\
             A password prompt after this line comes from the system sshd, not rayfish.\r\n",
            peer.fmt_short(),
            peer.fmt_short(),
        ));
    }
    policy.restriction().map(|allowed| {
        format!(
            "rayfish mesh SSH: peer {} may log in as {allowed}.\r\n\
             Widen it with: ray firewall ssh allow {net} {} -u '*'\r\n",
            peer.fmt_short(),
            peer.fmt_short(),
        )
    })
}

/// Accumulate the login policy for `user` (a peer's user identity) across the
/// networks we currently share with it: every allow rule whose `peer` is `"*"`
/// or this identity contributes its permitted users.
fn resolve_user_policy(authz: &SshAuthz, user: &EndpointId, networks: &[SmolStr]) -> UserPolicy {
    let map = authz.load();
    let id = user.to_string();
    let mut policy = UserPolicy::default();
    for net in networks {
        if let Some(rules) = map.get(net.as_str()) {
            for rule in rules {
                if rule.peer == "*" || rule.peer == id {
                    policy.add(&rule.users);
                }
            }
        }
    }
    policy
}

/// Handle to a running SSH server so the daemon can stop it on `ray down` /
/// `ssh off`. Dropping or cancelling the token tears down every listener.
pub struct SshServer {
    peers: PeerTable,
    device_user_map: DeviceUserMap,
    authz: SshAuthz,
}

impl SshServer {
    pub fn new(peers: PeerTable, device_user_map: DeviceUserMap, authz: SshAuthz) -> Self {
        Self {
            peers,
            device_user_map,
            authz,
        }
    }

    /// Spawn a listener on each mesh address (at [`SSH_LISTEN_PORT`]). Runs until
    /// `token` is cancelled. Mesh `:22` is mapped to this port by the userspace
    /// NAT in `forward.rs`, so a stock client connects on `:22` while the host
    /// sshd keeps `:22` on every other interface.
    pub fn spawn(self, addrs: Vec<IpAddr>, token: CancellationToken) {
        tokio::spawn(async move {
            let key = match load_host_key() {
                Ok(k) => k,
                Err(e) => {
                    warn!(error = %e, "mesh SSH: could not load host key; SSH disabled");
                    return;
                }
            };
            let config = Arc::new(Config {
                keys: vec![key],
                // Identity is proven by the mesh link, so the `none` method is
                // the only one offered; our `auth_none` is the authorization gate.
                methods: MethodSet::from(&[MethodKind::None][..]),
                inactivity_timeout: Some(Duration::from_secs(3600)),
                auth_rejection_time: Duration::from_secs(1),
                ..Default::default()
            });
            for addr in addrs {
                let listener = match bind_listener(addr, SSH_LISTEN_PORT) {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(%addr, port = SSH_LISTEN_PORT, error = %e, "mesh SSH: cannot bind listener; skipping");
                        continue;
                    }
                };
                info!(%addr, port = SSH_LISTEN_PORT, "mesh SSH listening (reachable as :22)");
                let peers = self.peers.clone();
                let dum = self.device_user_map.clone();
                let authz = self.authz.clone();
                let config = config.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            accepted = listener.accept() => {
                                let (stream, peer) = match accepted {
                                    Ok(p) => p,
                                    Err(e) => { debug!(error = %e, "mesh SSH accept failed"); continue; }
                                };
                                let config = config.clone();
                                let peers = peers.clone();
                                let dum = dum.clone();
                                let authz = authz.clone();
                                tokio::spawn(async move {
                                    handle_conn(stream, peer, config, peers, dum, authz).await;
                                });
                            }
                        }
                    }
                    debug!(%addr, "mesh SSH listener stopped");
                });
            }
        });
    }
}

/// Bind a TCP listener on a specific mesh IP's port 22 with SO_REUSEADDR (and
/// SO_REUSEPORT on Unix) so it can coexist with a host sshd bound on the wildcard
/// address. Returns a tokio listener ready to accept.
fn bind_listener(ip: IpAddr, port: u16) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if ip.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = (ip, port).into();
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    let std_listener: std::net::TcpListener = sock.into();
    Ok(TcpListener::from_std(std_listener)?)
}

/// Resolve the connecting peer, decide authorization, and run the SSH session.
async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    peers: PeerTable,
    device_user_map: DeviceUserMap,
    authz: SshAuthz,
) {
    let src = peer.ip();
    let Some((peer_id, networks)) = peers.identity_and_networks(src) else {
        debug!(%src, "mesh SSH: connection from unknown mesh IP, dropping");
        return;
    };
    let user_identity = device_user_map.resolve(&peer_id);
    let policy = resolve_user_policy(&authz, &user_identity, &networks);
    debug!(%src, peer = %user_identity.fmt_short(), authorized = policy.authorized(), "mesh SSH connection");
    let banner = auth_banner(&policy, &user_identity, &networks);
    // The address the client believes it reached, not the internal listen port
    // the SSH NAT sent it to: this is what the session reports in
    // `SSH_CONNECTION` and what `login` records as the origin.
    let server = stream
        .local_addr()
        .map(|a| SocketAddr::new(a.ip(), SSH_PORT))
        .unwrap_or_else(|_| SocketAddr::new(src, SSH_PORT));
    let handler = SshHandler::new(policy, user_identity, banner, Origin { client: peer, server });
    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            let _ = session.await;
        }
        Err(e) => debug!(error = %e, "mesh SSH session ended with error"),
    }
}

/// Where a connection came from and where it landed, as the client sees it.
/// Feeds `SSH_CONNECTION` / `SSH_CLIENT` and the origin `login(1)` records.
#[derive(Clone, Copy)]
struct Origin {
    client: SocketAddr,
    server: SocketAddr,
}

impl Origin {
    /// The two variables every sshd sets, so a session can tell it is remote
    /// and from where. Same field order as OpenSSH.
    fn env(&self) -> [(String, String); 2] {
        let (c, s) = (self.client, self.server);
        [
            (
                "SSH_CONNECTION".to_string(),
                format!("{} {} {} {}", c.ip(), c.port(), s.ip(), s.port()),
            ),
            (
                "SSH_CLIENT".to_string(),
                format!("{} {} {}", c.ip(), c.port(), s.port()),
            ),
        ]
    }
}

/// A requested pseudo-terminal's initial geometry and terminal type.
struct PtyReq {
    term: String,
    col: u16,
    row: u16,
}

/// State for one session channel. A connection carries many of them: OpenSSH's
/// `ControlMaster` (and every IDE or tool that multiplexes over one connection)
/// opens a channel per command, several of them at a time. None of this can
/// live in a per-connection slot, or a later channel silently overwrites an
/// earlier one's channel and PTY.
#[derive(Default)]
struct ChannelState {
    /// The open channel, taken when its shell / exec / subsystem starts.
    channel: Option<Channel<Msg>>,
    /// A PTY requested for this channel before its session starts.
    pty: Option<PtyReq>,
    /// Set once the session starts; forwards window-resize events to the task
    /// that owns this channel's PTY.
    resize_tx: Option<mpsc::UnboundedSender<Size>>,
    /// Environment the client asked to pass in (`SendEnv` / `SetEnv`), already
    /// filtered by [`env_accepted`], plus `SSH_AUTH_SOCK` and `DISPLAY` when
    /// this channel forwards an agent or X11. Applied on top of the login
    /// environment when the session starts.
    env: Vec<(String, String)>,
    /// Live agent-forwarding socket, if the client asked for one (`ssh -A`).
    /// Dropped with the channel, which removes the socket and its directory.
    agent: Option<AgentSocket>,
    /// The running child, for `signal` requests. Empty until the session starts.
    child: Option<ChildProc>,
}

/// The agent-forwarding socket serving one channel: the private directory
/// holding the socket the session's `SSH_AUTH_SOCK` points at, and the token
/// that stops its accept loop. Dropping it (when the channel closes, or with
/// the whole connection) cancels the loop and takes the directory with it.
struct AgentSocket {
    dir: PathBuf,
    token: CancellationToken,
}

impl Drop for AgentSocket {
    fn drop(&mut self) {
        self.token.cancel();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A handle for signalling the process behind a session channel. The pid is
/// published by the session task once it has spawned, so a `signal` request
/// that arrives first finds 0 and is dropped rather than hitting some unrelated
/// process.
#[derive(Clone)]
struct ChildProc {
    pid: Arc<AtomicU32>,
    /// A PTY child is a session leader, so its pid is also its process group
    /// and the signal goes to the whole foreground job, like a terminal's
    /// ^C. A pipe child shares this daemon's group: signal the process alone.
    process_group: bool,
}

impl ChildProc {
    fn new(process_group: bool) -> Self {
        Self {
            pid: Arc::new(AtomicU32::new(0)),
            process_group,
        }
    }

    /// Send `sig` to the child, or do nothing if it has not started (or has
    /// already been reaped, in which case the pid is cleared).
    fn signal(&self, sig: i32) {
        let pid = self.pid.load(Ordering::Relaxed);
        if pid == 0 {
            return;
        }
        let target = if self.process_group {
            -(pid as i32)
        } else {
            pid as i32
        };
        // SAFETY: a plain kill(2); an already-exited pid fails with ESRCH.
        unsafe {
            libc::kill(target, sig);
        }
    }
}

/// Per-connection SSH handler. The peer's login policy is precomputed from its
/// identity before the handshake; `auth_none` resolves the requested unix user
/// and checks it against that policy. Everything that belongs to a single
/// session lives in `channels`, keyed by channel id.
struct SshHandler {
    /// Which local users this peer may log in as (computed at connect time).
    policy: UserPolicy,
    /// The connecting peer's user identity (for logging).
    user: EndpointId,
    /// Shown before auth when the peer is unauthorized or restricted, so a
    /// refusal reaches the person connecting instead of only this node's log.
    banner: Option<String>,
    /// The unix user the client asked to log in as (the `user` in `user@host`).
    login_user: String,
    /// The resolved login account, set in `auth_none` once the requested user
    /// passes the policy, so the session task doesn't re-run `getpwnam`. Shared,
    /// never consumed: every channel on the connection logs in as this account.
    login: Option<Arc<LoginInfo>>,
    /// The session channels currently open on this connection.
    channels: HashMap<ChannelId, ChannelState>,
    /// Reverse forwards (`ssh -R`) this connection asked for, keyed by the
    /// address and port the client named so `cancel-tcpip-forward` finds them,
    /// and the same for unix-socket reverse forwards keyed by path.
    forwards: HashMap<(String, u32), CancellationToken>,
    socket_forwards: HashMap<String, CancellationToken>,
    /// Parent of every token above: cancelled when the handler drops, so a
    /// connection that goes away takes its listeners with it.
    token: CancellationToken,
    /// Where this connection came from, for the session environment and the
    /// login record.
    origin: Origin,
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        self.token.cancel();
        // The connection is gone, so the sessions it carried have no terminal
        // and no client left: hang them up the way sshd does, or a peer that
        // drops off the mesh leaves a login shell running here forever.
        for state in self.channels.values() {
            if let Some(child) = &state.child {
                child.signal(libc::SIGHUP);
            }
        }
    }
}

impl SshHandler {
    fn new(
        policy: UserPolicy,
        user: EndpointId,
        banner: Option<String>,
        origin: Origin,
    ) -> Self {
        Self {
            policy,
            user,
            banner,
            login_user: String::new(),
            login: None,
            channels: HashMap::new(),
            forwards: HashMap::new(),
            socket_forwards: HashMap::new(),
            token: CancellationToken::new(),
            origin,
        }
    }

    /// The login this connection authenticated as, if any. Every forwarding
    /// path goes through here: russh dispatches channel opens and global
    /// requests only after auth succeeded, so this is `Some` by then, and a
    /// `None` means something is wrong and the request must be refused.
    fn authorized_login(&self) -> Option<Arc<LoginInfo>> {
        if !self.policy.authorized() {
            return None;
        }
        self.login.clone()
    }

    /// Take `id`'s opened channel and spawn the login shell (or the `exec` /
    /// subsystem command), wiring it to that channel. Returns immediately so
    /// the russh session task stays free to process further requests (resize,
    /// more channels, …). `false` means nothing was spawned and the caller must
    /// fail the request instead of reporting success.
    fn start(
        &mut self,
        channel_id: ChannelId,
        command: Option<String>,
        session: &mut Session,
    ) -> bool {
        // `login` is set in `auth_none` once the requested user is authorized;
        // cloned, never taken, so every channel on this connection gets it.
        let Some(info) = self.login.clone() else {
            return false;
        };
        let Some(state) = self.channels.get_mut(&channel_id) else {
            return false;
        };
        let Some(channel) = state.channel.take() else {
            return false;
        };
        let handle = session.handle();
        let login_name = info.name.clone();
        let pty = state.pty.take();
        let mut env = std::mem::take(&mut state.env);
        env.extend(self.origin.env());
        let origin = self.origin;
        let peer = self.user;
        let (resize_tx, resize_rx) = mpsc::unbounded_channel();
        state.resize_tx = Some(resize_tx);
        let child = ChildProc::new(pty.is_some());
        state.child = Some(child.clone());

        tokio::spawn(async move {
            // A PTY was requested -> interactive terminal. Otherwise (`ssh host
            // cmd` with no -t) use plain pipes so stdout/stderr aren't merged or
            // CRLF-translated, matching a conventional sshd.
            let spec = SessionSpec {
                info,
                command,
                env,
                child_proc: child,
                origin,
            };
            let result = match pty {
                Some(pty_req) => run_pty_session(channel, spec, pty_req, resize_rx).await,
                None => run_pipe_session(channel, handle.clone(), channel_id, spec).await,
            };
            let exit = match result {
                Ok(e) => e,
                Err(e) => {
                    warn!(peer = %peer.fmt_short(), user = %login_name, error = %e, "mesh SSH session failed");
                    Exit::Code(1)
                }
            };
            // A process killed by a signal is reported as one, the way a stock
            // sshd does, so the client prints "killed by SIGKILL" instead of a
            // made-up status.
            match exit {
                Exit::Code(code) => {
                    let _ = handle.exit_status_request(channel_id, code).await;
                }
                Exit::Signal(sig) => {
                    let _ = handle
                        .exit_signal_request(channel_id, sig, false, String::new(), String::new())
                        .await;
                }
            }
            let _ = handle.eof(channel_id).await;
            let _ = handle.close(channel_id).await;
        });
        true
    }

    /// Answer a session request we cannot serve, and end the channel with it.
    /// Every "cannot happen" path has to reach the client: answering success
    /// with nothing spawned behind it (or not answering at all) leaves the
    /// client waiting forever, with the reason only in this node's log.
    fn fail(
        &mut self,
        channel_id: ChannelId,
        reason: &str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        warn!(peer = %self.user.fmt_short(), channel = %channel_id, reason,
            "mesh SSH: cannot start a session on this channel");
        session.channel_failure(channel_id)?;
        session.exit_status_request(channel_id, 1)?;
        session.eof(channel_id)?;
        session.close(channel_id)?;
        self.channels.remove(&channel_id);
        Ok(())
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.banner.clone())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.login_user = user.to_string();
        if !self.policy.authorized() {
            info!(peer = %self.user.fmt_short(), "mesh SSH: rejecting unauthorized peer");
            return Ok(Auth::reject());
        }
        // Resolve the requested account so the per-user policy is enforced by
        // uid (a uid-0 account under a non-`root` name can't bypass the non-root
        // default). An unknown user is rejected here rather than failing later
        // after a shell spawn. The resolved info is reused by the session task.
        match resolve_login(user) {
            Ok(info) if self.policy.permits(user, info.uid) => {
                self.login = Some(Arc::new(info));
                Ok(Auth::Accept)
            }
            Ok(info) => {
                info!(peer = %self.user.fmt_short(), user, uid = info.uid,
                    "mesh SSH: peer not permitted to log in as this user");
                Ok(Auth::reject())
            }
            Err(e) => {
                debug!(peer = %self.user.fmt_short(), user, error = %e,
                    "mesh SSH: requested login user not found");
                Ok(Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.insert(
            channel.id(),
            ChannelState {
                channel: Some(channel),
                ..Default::default()
            },
        );
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // `ssh -L`, `ssh -D` and `ProxyJump` all ride this channel type.
        if self.authorized_login().is_none() {
            return Ok(false);
        }
        let Ok(port) = u16::try_from(port_to_connect) else {
            debug!(peer = %self.user.fmt_short(), port_to_connect,
                "mesh SSH: rejecting forward to an out-of-range port");
            return Ok(false);
        };
        let target = format!("{host_to_connect}:{port}");
        let peer = self.user;
        let handle = session.handle();
        let channel_id = channel.id();
        // Connect off the session task: it is shared by every channel on this
        // connection, so a slow or black-holed connect here would stall the
        // peer's shells and its other forwards. The cost is that a failed
        // connect closes an already-confirmed channel instead of failing the
        // open, so the client reports a dropped connection rather than
        // "connect failed"; the reason is logged here.
        tokio::spawn(async move {
            let connected = timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await;
            let upstream = match connected {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!(peer = %peer.fmt_short(), %target, error = %e,
                        "mesh SSH: forwarded connection failed");
                    let _ = handle.close(channel_id).await;
                    return;
                }
                Err(_) => {
                    debug!(peer = %peer.fmt_short(), %target,
                        "mesh SSH: forwarded connection timed out");
                    let _ = handle.close(channel_id).await;
                    return;
                }
            };
            debug!(peer = %peer.fmt_short(), %target, "mesh SSH: forwarding to");
            splice(channel, handle, upstream).await;
        });
        Ok(true)
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // `ssh -L <port>:/run/some.sock` and anything forwarding a unix socket
        // (docker, gpg-agent, a database's local socket).
        let Some(info) = self.authorized_login() else {
            return Ok(false);
        };
        let path = PathBuf::from(socket_path);
        if !account_can(&path, &info, 0o6) {
            warn!(peer = %self.user.fmt_short(), user = %info.name, socket = socket_path,
                "mesh SSH: refusing to forward a socket this account cannot use");
            return Ok(false);
        }
        let peer = self.user;
        let handle = session.handle();
        let channel_id = channel.id();
        tokio::spawn(async move {
            match timeout(CONNECT_TIMEOUT, UnixStream::connect(&path)).await {
                Ok(Ok(sock)) => {
                    debug!(peer = %peer.fmt_short(), socket = %path.display(),
                        "mesh SSH: forwarding to");
                    splice(channel, handle, sock).await;
                }
                Ok(Err(e)) => {
                    debug!(peer = %peer.fmt_short(), socket = %path.display(), error = %e,
                        "mesh SSH: forwarded socket connection failed");
                    let _ = handle.close(channel_id).await;
                }
                Err(_) => {
                    debug!(peer = %peer.fmt_short(), socket = %path.display(),
                        "mesh SSH: forwarded socket connection timed out");
                    let _ = handle.close(channel_id).await;
                }
            }
        });
        Ok(true)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // `ssh -R`: this host listens, the peer's side answers.
        if self.authorized_login().is_none() {
            return Ok(false);
        }
        let Ok(requested) = u16::try_from(*port) else {
            return Ok(false);
        };
        let bind = SocketAddr::new(reverse_bind_addr(address), requested);
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                warn!(peer = %self.user.fmt_short(), %bind, error = %e,
                    "mesh SSH: cannot bind a reverse forward");
                return Ok(false);
            }
        };
        // Port 0 means "pick one and tell me": the client needs the real port
        // back, both to print it and to cancel the forward later.
        let bound = listener.local_addr().map(|a| a.port()).unwrap_or(requested);
        *port = bound as u32;

        let key = (address.to_string(), *port);
        if let Some(previous) = self.forwards.remove(&key) {
            previous.cancel();
        }
        let token = self.token.child_token();
        self.forwards.insert(key, token.clone());

        info!(peer = %self.user.fmt_short(), listen = %SocketAddr::new(bind.ip(), bound),
            "mesh SSH: reverse forward open");
        let handle = session.handle();
        let peer = self.user;
        // The client matches an incoming forwarded connection against the
        // address it asked to have bound, so echo that back rather than the
        // address we narrowed it to.
        let advertised = address.to_string();
        tokio::spawn(async move {
            loop {
                let (sock, origin) = tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            debug!(error = %e, "mesh SSH: reverse forward accept failed");
                            continue;
                        }
                    },
                };
                let handle = handle.clone();
                let advertised = advertised.clone();
                tokio::spawn(async move {
                    let opened = handle
                        .channel_open_forwarded_tcpip(
                            advertised,
                            bound as u32,
                            origin.ip().to_string(),
                            origin.port() as u32,
                        )
                        .await;
                    match opened {
                        Ok(channel) => splice(channel, handle, sock).await,
                        Err(e) => debug!(peer = %peer.fmt_short(), error = %e,
                            "mesh SSH: peer refused a reverse-forwarded connection"),
                    }
                });
            }
            debug!(port = bound, "mesh SSH: reverse forward closed");
        });
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        match self.forwards.remove(&(address.to_string(), port)) {
            Some(token) => {
                token.cancel();
                Ok(true)
            }
            // Not ours to cancel: say so instead of reporting a success the
            // client would read as "the port is free now".
            None => Ok(false),
        }
    }

    async fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // `ssh -R /path/on/this/host.sock:...`, how gpg-agent and ssh-agent
        // sockets are published onto a remote host.
        let Some(info) = self.authorized_login() else {
            return Ok(false);
        };
        let path = PathBuf::from(socket_path);
        let Some(parent) = path.parent() else {
            return Ok(false);
        };
        // The daemon is root and could create this socket anywhere. Bind only
        // where the login account could have created it itself.
        if !account_can(parent, &info, 0o3) {
            warn!(peer = %self.user.fmt_short(), user = %info.name, socket = socket_path,
                "mesh SSH: refusing a reverse socket forward outside the account's reach");
            return Ok(false);
        }
        // A socket left behind by an earlier session of this same account is
        // stale and ours to clear. Anything else stays where it is.
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_socket() && (meta.uid() == info.uid || info.uid == 0) {
                let _ = std::fs::remove_file(&path);
            }
        }
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                warn!(peer = %self.user.fmt_short(), socket = socket_path, error = %e,
                    "mesh SSH: cannot bind a reverse socket forward");
                return Ok(false);
            }
        };
        if let Err(e) = hand_over(&path, &info, 0o600) {
            warn!(peer = %self.user.fmt_short(), socket = socket_path, error = %e,
                "mesh SSH: cannot hand the forwarded socket to the login account");
            let _ = std::fs::remove_file(&path);
            return Ok(false);
        }

        if let Some(previous) = self.socket_forwards.remove(socket_path) {
            previous.cancel();
        }
        let token = self.token.child_token();
        self.socket_forwards
            .insert(socket_path.to_string(), token.clone());

        info!(peer = %self.user.fmt_short(), socket = socket_path,
            "mesh SSH: reverse socket forward open");
        let handle = session.handle();
        let peer = self.user;
        let advertised = socket_path.to_string();
        tokio::spawn(async move {
            loop {
                let (sock, _) = tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            debug!(error = %e, "mesh SSH: reverse socket accept failed");
                            continue;
                        }
                    },
                };
                let handle = handle.clone();
                let advertised = advertised.clone();
                tokio::spawn(async move {
                    match handle.channel_open_forwarded_streamlocal(advertised).await {
                        Ok(channel) => splice(channel, handle, sock).await,
                        Err(e) => debug!(peer = %peer.fmt_short(), error = %e,
                            "mesh SSH: peer refused a reverse-forwarded socket connection"),
                    }
                });
            }
            // The listener holds the only reference to this path; take the
            // socket file with it so the next session can bind again.
            let _ = std::fs::remove_file(&path);
            debug!(socket = %path.display(), "mesh SSH: reverse socket forward closed");
        });
        Ok(true)
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        match self.socket_forwards.remove(socket_path) {
            Some(token) => {
                token.cancel();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // `ssh -A`: a socket on this host that speaks to the client's agent, so
        // a key never leaves the machine it lives on. The socket belongs to
        // this channel and goes away with it.
        let Some(info) = self.authorized_login() else {
            return Ok(false);
        };
        if !self.channels.contains_key(&channel) {
            return Ok(false);
        }
        let peer = self.user;
        let (agent_dir, listener, path) = match open_agent_socket(&info) {
            Ok(a) => a,
            Err(e) => {
                warn!(peer = %peer.fmt_short(), error = %e,
                    "mesh SSH: cannot set up agent forwarding");
                return Ok(false);
            }
        };
        let token = self.token.child_token();
        let accept_token = token.clone();
        let socket = path.clone();
        let handle = session.handle();
        tokio::spawn(async move {
            loop {
                let (sock, _) = tokio::select! {
                    _ = accept_token.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            debug!(error = %e, "mesh SSH: agent socket accept failed");
                            continue;
                        }
                    },
                };
                let handle = handle.clone();
                tokio::spawn(async move {
                    match handle.channel_open_agent().await {
                        Ok(channel) => splice(channel, handle, sock).await,
                        Err(e) => debug!(peer = %peer.fmt_short(), error = %e,
                            "mesh SSH: peer refused an agent connection"),
                    }
                });
            }
            debug!(socket = %socket.display(), "mesh SSH: agent forwarding closed");
        });

        // Safe: the channel was there at the top of this method and `&mut self`
        // has not been released since.
        if let Some(state) = self.channels.get_mut(&channel) {
            state
                .env
                .push(("SSH_AUTH_SOCK".to_string(), path.display().to_string()));
            state.agent = Some(AgentSocket {
                dir: agent_dir,
                token,
            });
        }
        Ok(true)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !env_accepted(variable_name) {
            debug!(peer = %self.user.fmt_short(), variable = variable_name,
                "mesh SSH: not accepting this environment variable");
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        state.env.push((
            variable_name.to_string(),
            variable_value.to_string(),
        ));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(number) = signal_number(&signal) else {
            debug!(peer = %self.user.fmt_short(), ?signal, "mesh SSH: unknown signal, ignored");
            return Ok(());
        };
        if let Some(child) = self.channels.get(&channel).and_then(|s| s.child.as_ref()) {
            debug!(peer = %self.user.fmt_short(), ?signal, "mesh SSH: signalling the session");
            child.signal(number);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // X11 forwarding is not implemented. Answer it: russh's default replies
        // nothing at all, and `ssh -X` then waits on a request that will never
        // come back instead of printing "X11 forwarding request failed" and
        // carrying on with a working shell.
        debug!(peer = %self.user.fmt_short(), "mesh SSH: refusing X11 forwarding (not supported)");
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Either the client closed the channel or it is answering the close the
        // session task sent when the process exited. Either way this channel's
        // state is dead; the rest of the connection's channels carry on.
        // Anything still running under it loses its client here, so hang it up
        // (a process that already exited has no pid left to signal).
        if let Some(state) = self.channels.remove(&channel)
            && let Some(child) = &state.child
        {
            child.signal(libc::SIGHUP);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // The PTY belongs to this channel alone: a second channel on the same
        // connection must keep its plain pipes.
        let Some(state) = self.channels.get_mut(&channel) else {
            return self.fail(
                channel,
                "pty requested on a channel that is not open",
                session,
            );
        };
        state.pty = Some(PtyReq {
            term: term.to_string(),
            col: col_width as u16,
            row: row_height as u16,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.start(channel, None, session) {
            return self.fail(
                channel,
                "shell requested on a channel with no session",
                session,
            );
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        if !self.start(channel, Some(cmd), session) {
            return self.fail(
                channel,
                "exec requested on a channel with no session",
                session,
            );
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // `sftp` is not optional in practice: OpenSSH 9.0+ `scp` speaks the SFTP
        // protocol by default, so without this both `scp` and `sftp` to a mesh
        // host fail. Every branch must answer the request -- russh's default
        // handler replies nothing at all, which leaves the client waiting
        // forever instead of reporting an error.
        if name != "sftp" {
            debug!(peer = %self.user.fmt_short(), subsystem = name,
                "mesh SSH: rejecting unsupported subsystem");
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Some(command) = sftp_subsystem_command() else {
            warn!(peer = %self.user.fmt_short(),
                "mesh SSH: no sftp-server binary found, so scp and sftp cannot work. \
                 Install the OpenSSH sftp server package (openssh-sftp-server on Debian \
                 and Ubuntu, openssh-server elsewhere)");
            session.channel_failure(channel)?;
            return Ok(());
        };
        // Run it through the login shell like the exec path, which is what a
        // stock sshd does for a subsystem too.
        if !self.start(channel, Some(command), session) {
            return self.fail(
                channel,
                "subsystem requested on a channel with no session",
                session,
            );
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Only the channel that asked for a PTY has somewhere to send this; a
        // resize on any other channel is not an error, just nothing to do.
        if let Some(tx) = self
            .channels
            .get(&channel)
            .and_then(|s| s.resize_tx.as_ref())
        {
            let _ = tx.send(Size::new(row_height as u16, col_width as u16));
        }
        session.channel_success(channel)?;
        Ok(())
    }
}

/// How a session's process ended. SSH reports the two cases differently, and a
/// client that gets a status for a signalled process prints a wrong exit code.
enum Exit {
    Code(u32),
    Signal(Sig),
}

impl Exit {
    fn from_status(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => Exit::Code(code as u32),
            (None, Some(sig)) => Exit::Signal(signal_name(sig)),
            (None, None) => Exit::Code(0),
        }
    }
}

/// The SSH name of a unix signal number. The protocol names a fixed set; the
/// rest go over the wire as their number, which is what OpenSSH does too.
fn signal_name(sig: i32) -> Sig {
    match sig {
        libc::SIGABRT => Sig::ABRT,
        libc::SIGALRM => Sig::ALRM,
        libc::SIGFPE => Sig::FPE,
        libc::SIGHUP => Sig::HUP,
        libc::SIGILL => Sig::ILL,
        libc::SIGINT => Sig::INT,
        libc::SIGKILL => Sig::KILL,
        libc::SIGPIPE => Sig::PIPE,
        libc::SIGQUIT => Sig::QUIT,
        libc::SIGSEGV => Sig::SEGV,
        libc::SIGTERM => Sig::TERM,
        libc::SIGUSR1 => Sig::USR1,
        other => Sig::Custom(other.to_string()),
    }
}

/// The unix signal a client's `signal` request names, or `None` for a name this
/// host has no signal for.
fn signal_number(sig: &Sig) -> Option<i32> {
    Some(match sig {
        Sig::ABRT => libc::SIGABRT,
        Sig::ALRM => libc::SIGALRM,
        Sig::FPE => libc::SIGFPE,
        Sig::HUP => libc::SIGHUP,
        Sig::ILL => libc::SIGILL,
        Sig::INT => libc::SIGINT,
        Sig::KILL => libc::SIGKILL,
        Sig::PIPE => libc::SIGPIPE,
        Sig::QUIT => libc::SIGQUIT,
        Sig::SEGV => libc::SIGSEGV,
        Sig::TERM => libc::SIGTERM,
        Sig::USR1 => libc::SIGUSR1,
        Sig::Custom(name) => match name.as_str() {
            "USR2" => libc::SIGUSR2,
            "TSTP" => libc::SIGTSTP,
            "CONT" => libc::SIGCONT,
            "WINCH" => libc::SIGWINCH,
            _ => return None,
        },
    })
}

/// Pump an SSH channel and a local socket against each other until either side
/// closes, then end the channel. Every forwarded connection is this: the
/// channel *is* the socket, whichever side asked for it.
async fn splice<S>(channel: Channel<Msg>, handle: Handle, mut local: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let channel_id = channel.id();
    let mut stream = channel.into_stream();
    if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut local).await {
        debug!(channel = %channel_id, error = %e, "mesh SSH: forwarded connection ended early");
    }
    let _ = handle.eof(channel_id).await;
    let _ = handle.close(channel_id).await;
}

/// Create the agent-forwarding socket for one session: a private directory
/// holding a single unix socket, both owned by the login account, so nothing
/// but that account can talk to the peer's ssh-agent through it. Returns the
/// directory, the bound listener, and the socket path the session's
/// `SSH_AUTH_SOCK` will name.
///
/// The directory name is random and created exclusively (`create_dir` fails on
/// an existing path), so nothing can be waiting at the path to be handed the
/// socket when the daemon chowns it away from root.
fn open_agent_socket(info: &LoginInfo) -> Result<(PathBuf, UnixListener, PathBuf)> {
    let dir = std::env::temp_dir().join(format!("rayfish-ssh-agent.{:016x}", rand::random::<u64>()));
    std::fs::create_dir(&dir).context("creating the agent socket directory")?;
    hand_over(&dir, info, 0o700)?;
    let path = dir.join("agent.sock");
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e).context("binding the agent socket");
        }
    };
    if let Err(e) = hand_over(&path, info, 0o600) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    Ok((dir, listener, path))
}

/// Environment variables a client may set on a session (`ssh -o SendEnv=` /
/// `SetEnv=`). Locale and terminal hints only, the same shape as the stock
/// `AcceptEnv LANG LC_*`: anything else lets the peer steer the login shell
/// (`LD_PRELOAD`, `PATH`, `BASH_ENV`) instead of just describing itself.
fn env_accepted(name: &str) -> bool {
    matches!(name, "LANG" | "TZ" | "COLORTERM" | "TERM") || name.starts_with("LC_")
}

/// Which local address an `ssh -R` listener binds. A reverse forward publishes
/// the *peer's* service on this host, so a wildcard or external bind address is
/// narrowed to loopback, exactly what a stock sshd does with its default
/// `GatewayPorts no`. The client's default (`localhost`) already lands there.
fn reverse_bind_addr(address: &str) -> IpAddr {
    match address {
        "" | "localhost" | "127.0.0.1" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        "::1" => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => {
            debug!(
                requested = other,
                "mesh SSH: reverse forward narrowed to loopback"
            );
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
    }
}

/// Whether `info`'s account has `want` (a unix permission triad: 4 read, 2
/// write, 1 execute/search) on `path`.
///
/// Unix-socket forwarding is the one place where the daemon's root privilege
/// would buy the peer something a shell wouldn't: the filesystem *is* the
/// access control on a socket, and connecting as root ignores it. So the
/// permission the login account has is checked here first. Like any check made
/// before the open, it is not atomic against a path swapped underneath it; it
/// stops the peer reaching sockets its account plainly cannot, not a local user
/// racing their own directory.
fn account_can(path: &Path, info: &LoginInfo, want: u32) -> bool {
    if info.uid == 0 {
        return true;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let mode = meta.permissions().mode();
    let bits = if meta.uid() == info.uid {
        (mode >> 6) & 7
    } else if meta.gid() == info.gid || in_group(info, meta.gid()) {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    bits & want == want
}

/// Whether the account is a member of `gid` through its supplementary groups.
fn in_group(info: &LoginInfo, gid: u32) -> bool {
    uzers::get_user_groups(&info.name, info.gid)
        .map(|groups| {
            groups
                .iter()
                .any(|g| g.gid() == gid)
        })
        .unwrap_or(false)
}

/// Hand `path` to the login account with `mode`, so a socket this root daemon
/// created is usable by (and only by) the user whose session it belongs to.
fn hand_over(path: &Path, info: &LoginInfo, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path.display()))?;
    std::os::unix::fs::chown(path, Some(info.uid), Some(info.gid))
        .with_context(|| format!("handing {} to {}", path.display(), info.name))?;
    Ok(())
}

/// The resolved local account a session logs in as. Held in an [`Arc`] on the
/// handler and cloned per channel, since every session on one connection logs
/// in as the same account.
struct LoginInfo {
    uid: u32,
    gid: u32,
    home: PathBuf,
    shell: PathBuf,
    name: String,
}

/// Resolve the requested unix user via `getpwnam`.
fn resolve_login(login_user: &str) -> Result<LoginInfo> {
    use uzers::os::unix::UserExt;
    let pw = uzers::get_user_by_name(login_user)
        .with_context(|| format!("no such local user: {login_user}"))?;
    Ok(LoginInfo {
        uid: pw.uid(),
        gid: pw.primary_group_id(),
        home: pw.home_dir().to_path_buf(),
        shell: pw.shell().to_path_buf(),
        name: pw.name().to_string_lossy().to_string(),
    })
}

/// The `login(1)` this host has, or `None` when the handoff cannot be used.
///
/// It needs root (it does the setuid itself) and an actual login binary, so a
/// daemon running unprivileged, or a host without one (a minimal container),
/// falls back to spawning the shell directly. `RAYFISH_SSH_NO_LOGIN` turns the
/// handoff off, for a host whose `login` does something surprising.
fn login_program() -> Option<PathBuf> {
    if uzers::get_effective_uid() != 0 || std::env::var_os("RAYFISH_SSH_NO_LOGIN").is_some() {
        return None;
    }
    ["/bin/login", "/usr/bin/login"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| {
            std::fs::metadata(p)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// The terminal a pty's child end will see, for `SSH_TTY`.
fn tty_name(pts: &impl std::os::fd::AsRawFd) -> Option<String> {
    let mut buf = [0 as libc::c_char; 128];
    // SAFETY: `buf` is a live array of `buf.len()` chars; ttyname_r writes a
    // NUL-terminated name into it or returns non-zero without touching it.
    let rc = unsafe { libc::ttyname_r(pts.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: ttyname_r returned success, so `buf` holds a NUL-terminated name.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    name.to_str().ok().map(str::to_string)
}

/// Build a `pre_exec` closure that drops the root daemon's privileges to the
/// target user **completely**: supplementary groups first (`initgroups`, so the
/// child does NOT inherit root's groups like gid 0/wheel), then `setgid`, then
/// `setuid`, in that order. It runs as root in the forked child just before
/// `exec`. **Fails closed:** if any step errors, the closure returns an error so
/// `exec` never happens and the shell never runs with leftover privileges.
fn drop_privs(
    uid: u32,
    gid: u32,
    name: &str,
) -> Result<impl FnMut() -> std::io::Result<()> + Send + Sync + 'static> {
    let cname = std::ffi::CString::new(name).context("user name contains NUL")?;
    // Nothing to drop when the server already *is* the target account. The
    // daemon runs as root in production, so uid 0 never takes this branch and
    // the drop below is unchanged there; it is the unprivileged case (a
    // hand-run daemon, or the tests) where these calls would fail with EPERM
    // and fail the session closed even though the child gains nothing.
    // SAFETY: geteuid/getegid take no arguments and cannot fail.
    let already_dropped =
        uid != 0 && unsafe { libc::geteuid() } == uid && unsafe { libc::getegid() } == gid;
    Ok(move || {
        if already_dropped {
            return Ok(());
        }
        // SAFETY: only direct syscalls, in the child after fork, before exec.
        unsafe {
            #[cfg(target_os = "macos")]
            let basegroup = gid as libc::c_int;
            #[cfg(not(target_os = "macos"))]
            let basegroup = gid as libc::gid_t;
            if libc::initgroups(cname.as_ptr(), basegroup) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    })
}

/// Apply the common login environment to a command builder.
fn login_env<'a>(home: &Path, shell: &Path, name: &str) -> [(&'a str, std::ffi::OsString); 5] {
    [
        ("HOME", home.into()),
        ("USER", name.into()),
        ("LOGNAME", name.into()),
        ("SHELL", shell.into()),
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ),
    ]
}

/// What a session runs and who it runs as: everything the two session paths
/// need beyond the channel itself.
struct SessionSpec {
    info: Arc<LoginInfo>,
    /// The `exec` command, or `None` for a login shell.
    command: Option<String>,
    env: Vec<(String, String)>,
    child_proc: ChildProc,
    origin: Origin,
}

/// Allocate a PTY, spawn the login shell (or `exec` command) as the requested
/// unix user, and pump bytes between the SSH channel and the PTY until the child
/// exits. Returns the child's exit code.
async fn run_pty_session(
    channel: Channel<Msg>,
    spec: SessionSpec,
    pty_req: PtyReq,
    mut resize_rx: mpsc::UnboundedReceiver<Size>,
) -> Result<Exit> {
    let SessionSpec {
        info,
        command,
        env,
        child_proc,
        origin,
    } = spec;
    let (pty, pts) = pty_process::open().context("opening pty")?;
    let _ = pty.resize(Size::new(pty_req.row, pty_req.col));
    let tty = tty_name(&pts);
    // Hold a terminal fd of our own for as long as the child runs. Reading the
    // master end returns EIO the instant the *last* slave fd closes, and a
    // child that closes and reopens its terminal while starting up (`login`
    // does, between the PAM session and the shell) hits exactly that window:
    // the read half would end there and the session would go silent with the
    // shell still running behind it. Dropped below, once the child is gone, so
    // the read half can finish.
    let keep_open = pts.as_fd().try_clone_to_owned().ok();

    // An interactive terminal with no command is a login, so hand it to
    // `login(1)` when this host has one: it owns the things a session gets
    // wrong when it is spawned directly. PAM (so a locked or expired account is
    // refused, and logind gives the session an XDG_RUNTIME_DIR and its
    // resource limits), the utmp/wtmp/lastlog records behind `who` and `last`,
    // `/etc/nologin`, and the motd. It is also what does the setuid, so this
    // branch keeps root and drops nothing itself.
    //
    // Not for root: `login` refuses a root session on a tty that is not in
    // `/etc/securetty` (a pts never is), and it refuses it by hanging with no
    // output rather than failing, which would leave `ssh root@host.ray` staring
    // at nothing. Root keeps the direct path.
    let handoff = (command.is_none() && info.uid != 0)
        .then(login_program)
        .flatten();
    let mut cmd = match &handoff {
        Some(login) => pty_process::Command::new(login)
            // Keep the environment we curated (login sets HOME/USER/SHELL/PATH
            // itself either way); record where the session came from; and log
            // the user in without asking for a password we cannot check.
            .arg("-p")
            .arg("-h")
            .arg(origin.client.ip().to_string())
            .arg("-f")
            .arg(&info.name),
        None => match &command {
            Some(c) => pty_process::Command::new(&info.shell).arg("-c").arg(c),
            None => pty_process::Command::new(&info.shell).arg("-l"),
        },
    };
    cmd = cmd
        .env_clear()
        .envs(login_env(&info.home, &info.shell, &info.name))
        .env("TERM", &pty_req.term)
        .envs(tty.map(|t| ("SSH_TTY".to_string(), t)))
        .envs(env);
    if handoff.is_none() {
        // `login` chdirs itself, and copes with a home directory that is gone;
        // spawning into a missing directory would just fail.
        cmd = cmd.current_dir(&info.home);
        let drop = drop_privs(info.uid, info.gid, &info.name)?;
        // SAFETY: drops privileges (initgroups+setgid+setuid) before exec; we do NOT
        // use `.uid()/.gid()` because std applies those *after* pre_exec, too late to
        // also drop supplementary groups.
        cmd = unsafe { cmd.pre_exec(drop) };
    }
    let mut child = cmd.spawn(pts).context("spawning login shell")?;
    // Publish the pid so `signal` requests reach it, and clear it again below
    // once it is reaped: a stale pid gets reused by an unrelated process.
    child_proc.pid.store(child.id().unwrap_or(0), Ordering::Relaxed);

    let stream = channel.into_stream();
    let (mut chan_read, mut chan_write) = tokio::io::split(stream);
    let (mut pty_read, mut pty_write) = pty.into_split();

    // Client -> PTY, interleaved with window resizes (both touch the write half).
    let c2p = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            tokio::select! {
                r = chan_read.read(&mut buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if pty_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                },
                Some(size) = resize_rx.recv() => {
                    let _ = pty_write.resize(size);
                }
            }
        }
    });

    // PTY -> client. Ends when the child exits and the master side EOFs.
    let p2c = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut pty_read, &mut chan_write).await;
        let _ = chan_write.shutdown().await;
    });

    let status = child.wait().await.context("waiting on child")?;
    child_proc.pid.store(0, Ordering::Relaxed);
    // The child is gone, so let the terminal go: with no slave fd left the
    // master reaches EIO and the reader below finishes instead of blocking.
    drop(keep_open);
    let _ = p2c.await;
    c2p.abort();
    Ok(Exit::from_status(status))
}

/// Run a command (or shell) with **pipes** instead of a PTY, for a non-`-t`
/// `ssh host cmd`. stdout goes to the channel's data stream and stderr to the
/// extended-data (code 1) stream, kept separate and untranslated, as a
/// conventional sshd delivers them, so piped/binary output isn't corrupted.
async fn run_pipe_session(
    channel: Channel<Msg>,
    handle: Handle,
    channel_id: ChannelId,
    spec: SessionSpec,
) -> Result<Exit> {
    let SessionSpec {
        info,
        command,
        env,
        child_proc,
        ..
    } = spec;
    let drop = drop_privs(info.uid, info.gid, &info.name)?;

    let mut cmd = tokio::process::Command::new(&info.shell);
    match &command {
        Some(c) => {
            cmd.arg("-c").arg(c);
        }
        None => {
            cmd.arg("-l");
        }
    }
    cmd.current_dir(&info.home)
        .env_clear()
        .envs(login_env(&info.home, &info.shell, &info.name))
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: drops privileges (initgroups+setgid+setuid) before exec.
    unsafe {
        cmd.pre_exec(drop);
    }
    let mut child = cmd.spawn().context("spawning command")?;
    child_proc.pid.store(child.id().unwrap_or(0), Ordering::Relaxed);
    let mut stdin = child.stdin.take().context("child stdin")?;
    let mut stdout = child.stdout.take().context("child stdout")?;
    let mut stderr = child.stderr.take().context("child stderr")?;

    // Output goes out via `handle.data`/`extended_data` (the stream can't emit
    // the separate stderr extended-data channel), so we only need the read half
    // for client stdin. Dropping the write half here is safe: `tokio::io::split`
    // keeps the underlying channel alive until *both* halves drop, and the
    // close-on-drop lives on the read half, which `stdin_task` holds open.
    let stream = channel.into_stream();
    let (mut chan_read, _chan_write) = tokio::io::split(stream);

    // client stdin -> child
    let stdin_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut chan_read, &mut stdin).await;
        // drop closes the child's stdin so commands reading to EOF finish.
    });
    // child stdout -> channel data
    let h_out = handle.clone();
    let out_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if h_out
                        .data(channel_id, Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    // child stderr -> channel extended data (code 1 = stderr)
    let h_err = handle.clone();
    let err_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if h_err
                        .extended_data(channel_id, 1, Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let status = child.wait().await.context("waiting on child")?;
    child_proc.pid.store(0, Ordering::Relaxed);
    let _ = out_task.await;
    let _ = err_task.await;
    stdin_task.abort();
    Ok(Exit::from_status(status))
}

/// Load the SSH host key the embedded server presents.
///
/// Prefers the machine's real OpenSSH ed25519 host key so a stock client that
/// already trusts the host keeps seeing the same fingerprint once the mesh SSH
/// NAT takes over `:22` (no `known_hosts` mismatch). Falls back to a persisted
/// generated key when no usable host key is found.
fn load_host_key() -> Result<PrivateKey> {
    if let Some((path, key)) = discover_host_ed25519_key() {
        info!(path = %path.display(), "mesh SSH: reusing host ed25519 key");
        return Ok(key);
    }
    let key = load_or_generate_host_key()?;
    // Loud, because the consequence lands on whoever connects, not here. With no
    // system sshd key to reuse (a container with no `/etc/ssh`, a host with no
    // sshd, an encrypted key) we present a key of our own, so a client that has
    // this host in `known_hosts` from a LAN or public-IP session sees a different
    // key for the same name and OpenSSH reports it as a possible MITM. Print the
    // fingerprint so the operator can compare and confirm the swap themselves.
    warn!(
        fingerprint = %key.public_key().fingerprint(Default::default()),
        "mesh SSH: no reusable system sshd host key found; serving a generated one. \
         Clients that already know this host by another address will see a host-key \
         change for the mesh name"
    );
    Ok(key)
}

/// Run `sshd -T` and return the first configured ed25519 host key that loads
/// unencrypted, together with its path. Best-effort: any failure (no `sshd`,
/// dump error, no ed25519 key, unreadable or encrypted key) yields `None`, so
/// the caller falls back to the generated key. The daemon is root, so it can
/// read the `0600` host key files.
fn discover_host_ed25519_key() -> Option<(PathBuf, PrivateKey)> {
    let dump = run_sshd_dump()?;
    for path in parse_hostkey_paths(&dump) {
        let Ok(pem) = std::fs::read_to_string(&path) else {
            continue;
        };
        match PrivateKey::from_openssh(&pem) {
            Ok(key) if !key.is_encrypted() && key.algorithm() == Algorithm::Ed25519 => {
                return Some((path, key));
            }
            _ => continue,
        }
    }
    None
}

/// Dump the effective sshd config (`sshd -T`). Tries `sshd` on `PATH` then the
/// common absolute locations, since the daemon's `PATH` may not include
/// `/usr/sbin`. Returns `None` if none run successfully.
fn run_sshd_dump() -> Option<String> {
    for bin in ["sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd"] {
        match std::process::Command::new(bin)
            .arg("-T")
            .stderr(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => return String::from_utf8(out.stdout).ok(),
            _ => continue,
        }
    }
    None
}

/// Extract the `hostkey <path>` entries from `sshd -T` output, in order. `sshd`
/// prints one lowercase directive per line; other directives are ignored.
fn parse_hostkey_paths(dump: &str) -> Vec<PathBuf> {
    dump.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let directive = parts.next()?;
            directive
                .eq_ignore_ascii_case("hostkey")
                .then(|| parts.next().map(PathBuf::from))
                .flatten()
        })
        .collect()
}

/// Where the OpenSSH sftp-server binary lives, per distribution. Used when the
/// host has no sshd to ask (a container, or a machine where mesh SSH *is* the
/// SSH server); all of these are shell-safe as written.
const SFTP_SERVER_PATHS: [&str; 5] = [
    "/usr/lib/openssh/sftp-server",     // Debian, Ubuntu
    "/usr/libexec/openssh/sftp-server", // Fedora, RHEL, SUSE
    "/usr/libexec/sftp-server",         // macOS, BSD
    "/usr/lib/ssh/sftp-server",         // Arch, Alpine
    "/usr/lib/sftp-server",             // last resort
];

/// The shell command that serves the `sftp` subsystem, or `None` when this host
/// has no sftp-server to run.
///
/// Prefers whatever the host's own sshd is configured to use, arguments and all
/// (`sshd -T` prints `subsystem sftp <command>`), so a non-default location or
/// an admin's logging flags are honoured. Falls back to the standard paths.
fn sftp_subsystem_command() -> Option<String> {
    if let Some(cmd) = run_sshd_dump().as_deref().and_then(parse_sftp_subsystem) {
        return Some(cmd);
    }
    SFTP_SERVER_PATHS
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_string())
}

/// Extract the `subsystem sftp <command>` entry from `sshd -T` output, keeping
/// any arguments. Rejects a command that isn't an absolute path: sshd's
/// `internal-sftp` is code inside sshd itself, not a binary we can spawn.
fn parse_sftp_subsystem(dump: &str) -> Option<String> {
    dump.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        if !parts.next()?.eq_ignore_ascii_case("subsystem") || parts.next()? != "sftp" {
            return None;
        }
        let rest = parts.collect::<Vec<_>>();
        let binary = Path::new(rest.first()?);
        (binary.is_absolute() && binary.is_file()).then(|| rest.join(" "))
    })
}

/// Load the persisted SSH host key, generating and persisting one on first use.
/// Stored as OpenSSH PEM at `<config_dir>/ssh_host_key`, mode 0600.
fn load_or_generate_host_key() -> Result<PrivateKey> {
    use russh::keys::ssh_key::LineEnding;

    let path = crate::config::config_dir()?.join("ssh_host_key");
    if path.exists() {
        let pem = std::fs::read_to_string(&path).context("reading ssh host key")?;
        return PrivateKey::from_openssh(&pem).context("parsing ssh host key");
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("generating ssh host key")?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .context("encoding ssh host key")?;
    crate::config::write_file(&path, pem.as_bytes(), true)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use russh::client;
    use russh::keys::ssh_key::PublicKey;
    use russh::{ChannelMsg, client::Msg as ClientMsg};
    use tokio::time::timeout;

    use super::*;

    fn id(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        iroh::SecretKey::from(b).public()
    }

    #[test]
    fn banner_tells_an_unauthorized_peer_why_and_how_to_fix_it() {
        // The whole point: without this the client only sees a password prompt
        // from the system sshd and reads the refusal as a network problem.
        let peer = id(7);
        let nets = [SmolStr::new("trade"), SmolStr::new("homelab")];
        let banner = auth_banner(&UserPolicy::default(), &peer, &nets)
            .expect("an unauthorized peer must be told");
        assert!(banner.contains("not authorized"));
        assert!(banner.contains(&peer.fmt_short().to_string()));
        assert!(banner.contains("ray firewall ssh allow homelab"));
        assert!(banner.contains("system sshd"));
    }

    #[test]
    fn banner_names_the_permitted_users_when_restricted() {
        let peer = id(8);
        let mut policy = UserPolicy::default();
        policy.add(&[]); // the default grant: any non-root user
        let banner = auth_banner(&policy, &peer, &[SmolStr::new("trade")])
            .expect("a restricted peer must be told what it may use");
        assert!(banner.contains("any user except root"));

        let mut named = UserPolicy::default();
        named.add(&["deploy".to_string(), "ci".to_string()]);
        let banner = auth_banner(&named, &peer, &[SmolStr::new("trade")]).expect("restricted");
        assert!(
            banner.contains("ci, deploy"),
            "users listed sorted: {banner}"
        );
    }

    #[test]
    fn no_banner_when_the_peer_may_log_in_as_anyone() {
        // Nothing to warn about, so don't nag on every successful connection.
        let mut policy = UserPolicy::default();
        policy.add(&["*".to_string()]);
        assert_eq!(auth_banner(&policy, &id(9), &[SmolStr::new("trade")]), None);
    }

    fn rule(peer: &str, users: &[&str]) -> crate::config::SshRule {
        crate::config::SshRule {
            peer: peer.to_string(),
            users: users.iter().map(|u| u.to_string()).collect(),
        }
    }

    #[test]
    fn authz_matches_identity_and_wildcard_per_network() {
        let alice = id(1);
        let bob = id(2);
        let authz = new_authz();
        let mut map = HashMap::new();
        // `net1` authorizes alice explicitly; `net2` authorizes any peer.
        map.insert("net1".to_string(), vec![rule(&alice.to_string(), &[])]);
        map.insert("net2".to_string(), vec![rule("*", &[])]);
        authz.store(Arc::new(map));

        let authorized = |u, nets: &[&str]| {
            let nets: Vec<SmolStr> = nets.iter().map(SmolStr::new).collect();
            resolve_user_policy(&authz, u, &nets).authorized()
        };
        // alice on net1 → allowed; bob on net1 → denied.
        assert!(authorized(&alice, &["net1"]));
        assert!(!authorized(&bob, &["net1"]));
        // wildcard on net2 → anyone allowed.
        assert!(authorized(&bob, &["net2"]));
        // a network with no allow list → denied.
        assert!(!authorized(&alice, &["net3"]));
        // union across shared networks: alice shares net3 (no rule) + net2 (*).
        assert!(authorized(&alice, &["net3", "net2"]));
    }

    #[test]
    fn parse_sftp_subsystem_keeps_the_command_and_its_arguments() {
        // `/bin/sh` stands in for sftp-server: the parser only requires an
        // absolute path that exists, and every unix host has this one.
        let dump = "permitrootlogin no\nsubsystem sftp /bin/sh -f AUTH -l INFO\n";
        assert_eq!(
            parse_sftp_subsystem(dump).as_deref(),
            Some("/bin/sh -f AUTH -l INFO")
        );
    }

    #[test]
    fn parse_sftp_subsystem_rejects_what_it_cannot_spawn() {
        // internal-sftp is code inside sshd, not a binary.
        assert_eq!(parse_sftp_subsystem("subsystem sftp internal-sftp\n"), None);
        // A path this host doesn't have (sshd config copied from elsewhere).
        assert_eq!(
            parse_sftp_subsystem("subsystem sftp /nonexistent/sftp-server\n"),
            None
        );
        // Another subsystem, and a bare directive, must not match.
        assert_eq!(parse_sftp_subsystem("subsystem netconf /bin/sh\n"), None);
        assert_eq!(parse_sftp_subsystem("subsystem\nsubsystem sftp\n"), None);
        assert_eq!(parse_sftp_subsystem(""), None);
    }

    #[test]
    fn parse_hostkey_paths_extracts_hostkey_lines() {
        // `sshd -T` prints one lowercase directive per line; only `hostkey`
        // lines carry a path, and there can be several. Other directives and
        // blank lines are ignored.
        let dump = "port 22\n\
            hostkey /etc/ssh/ssh_host_rsa_key\n\
            hostkey /etc/ssh/ssh_host_ecdsa_key\n\
            HostKey /etc/ssh/ssh_host_ed25519_key\n\
            hostkeyalgorithms ssh-ed25519\n\
            permitrootlogin no\n";
        let paths = parse_hostkey_paths(dump);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/etc/ssh/ssh_host_rsa_key"),
                PathBuf::from("/etc/ssh/ssh_host_ecdsa_key"),
                PathBuf::from("/etc/ssh/ssh_host_ed25519_key"),
            ]
        );
    }

    #[test]
    fn parse_hostkey_paths_empty_when_no_hostkey() {
        assert!(parse_hostkey_paths("port 22\npermitrootlogin no\n").is_empty());
    }

    #[test]
    fn user_policy_default_is_nonroot() {
        // An allow rule with no explicit users grants any non-root user but not
        // root, enforced by uid (so a uid-0 account under any name is blocked).
        let alice = id(1);
        let authz = new_authz();
        authz.store(Arc::new(HashMap::from([(
            "net".to_string(),
            vec![rule(&alice.to_string(), &[])],
        )])));
        let p = resolve_user_policy(&authz, &alice, &[SmolStr::new("net")]);
        assert!(p.permits("deploy", 1000), "non-root user allowed");
        assert!(!p.permits("root", 0), "root (uid 0) blocked by default");
        assert!(
            !p.permits("toor", 0),
            "any uid-0 account blocked, not just 'root'"
        );
    }

    /// Client side of the loopback tests: the host key is generated per test,
    /// so there is nothing to verify against. Channels the *server* opens back
    /// to us (reverse forwards, agent connections) are handed to whichever test
    /// asked to watch for them.
    struct AcceptAnyHost {
        opened: Option<mpsc::UnboundedSender<Channel<ClientMsg>>>,
    }

    impl client::Handler for AcceptAnyHost {
        type Error = russh::Error;

        async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn server_channel_open_forwarded_tcpip(
            &mut self,
            channel: Channel<ClientMsg>,
            _connected_address: &str,
            _connected_port: u32,
            _originator_address: &str,
            _originator_port: u32,
            _session: &mut client::Session,
        ) -> Result<(), Self::Error> {
            if let Some(tx) = &self.opened {
                let _ = tx.send(channel);
            }
            Ok(())
        }

        async fn server_channel_open_agent_forward(
            &mut self,
            channel: Channel<ClientMsg>,
            _session: &mut client::Session,
        ) -> Result<(), Self::Error> {
            if let Some(tx) = &self.opened {
                let _ = tx.send(channel);
            }
            Ok(())
        }
    }

    /// The account the tests log in as: the one running them, which is also the
    /// one the server runs as, so the session needs no privilege drop.
    fn test_account() -> String {
        let uid = uzers::get_effective_uid();
        uzers::get_user_by_uid(uid)
            .expect("these tests need a passwd entry for the uid running them")
            .name()
            .to_string_lossy()
            .to_string()
    }

    /// Serve the real [`SshHandler`] on loopback and return an authenticated
    /// client connection to it. The peer is authorized for any user, the same
    /// state a live mesh connection reaches before it opens a channel.
    async fn connect_to_test_server() -> client::Handle<AcceptAnyHost> {
        connect_watching_openings(None, test_account()).await
    }

    /// The same, plus the channels the server opens back to the client: what a
    /// reverse forward and agent forwarding deliver.
    async fn connect_and_watch_openings() -> (
        client::Handle<AcceptAnyHost>,
        mpsc::UnboundedReceiver<Channel<ClientMsg>>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        (connect_watching_openings(Some(tx), test_account()).await, rx)
    }

    async fn connect_watching_openings(
        opened: Option<mpsc::UnboundedSender<Channel<ClientMsg>>>,
        login_as: String,
    ) -> client::Handle<AcceptAnyHost> {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let config = Arc::new(Config {
            keys: vec![key],
            methods: MethodSet::from(&[MethodKind::None][..]),
            auth_rejection_time: Duration::ZERO,
            ..Default::default()
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        tokio::spawn(async move {
            let (stream, client) = listener.accept().await.expect("accept");
            let mut policy = UserPolicy::default();
            policy.add(&["*".to_string()]);
            // The same origin the live path builds: the client's real address,
            // and :22 for our side, which is where the client thinks it is.
            let origin = Origin {
                client,
                server: SocketAddr::new(addr.ip(), SSH_PORT),
            };
            let handler = SshHandler::new(policy, id(1), None, origin);
            if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                let _ = session.await;
            }
        });

        let mut handle = client::connect(
            Arc::new(client::Config::default()),
            addr,
            AcceptAnyHost { opened },
        )
        .await
        .expect("client connect");
        assert!(
            handle
                .authenticate_none(login_as)
                .await
                .expect("auth")
                .success(),
            "the `none` method is the mesh SSH auth gate"
        );
        handle
    }

    /// Drain one channel to its close, returning what the command wrote to
    /// stdout and the exit status it reported. Bounded: a channel that never
    /// finishes is exactly the bug under test, and it must fail, not hang.
    async fn drain(channel: &mut Channel<ClientMsg>) -> (String, Option<u32>) {
        let collect = async {
            let mut out = Vec::new();
            let mut code = None;
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { data } => out.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            (String::from_utf8_lossy(&out).to_string(), code)
        };
        timeout(Duration::from_secs(20), collect)
            .await
            .expect("the channel never finished: no output, no exit status, no close")
    }

    #[tokio::test]
    async fn every_channel_on_one_connection_runs_its_command() {
        // The `ssh -M` / ControlMaster case, and what Zed remote development
        // does: several commands in a row, each its own session channel on one
        // connection. Per-connection state used to be consumed by the first
        // channel, so every later one silently ran nothing and hung.
        let handle = connect_to_test_server().await;
        for n in 1..=3 {
            let mut channel = handle
                .channel_open_session()
                .await
                .expect("open session channel");
            channel
                .exec(true, format!("echo ran-{n}"))
                .await
                .expect("exec");
            let (out, code) = drain(&mut channel).await;
            assert!(
                out.contains(&format!("ran-{n}")),
                "channel {n} output: {out}"
            );
            assert_eq!(code, Some(0), "channel {n} exit status");
        }
    }

    #[tokio::test]
    async fn concurrent_channels_keep_their_own_output_and_pty() {
        // Both channels are open before either one starts a command, so a
        // single per-connection slot would let the second clobber the first.
        // `$TERM` is the tell: it is set only for a PTY session, so the pipe
        // channel seeing it would mean the PTY request leaked across channels.
        let handle = connect_to_test_server().await;
        let mut tty = handle
            .channel_open_session()
            .await
            .expect("open pty channel");
        let mut pipe = handle
            .channel_open_session()
            .await
            .expect("open pipe channel");

        tty.request_pty(true, "xterm-rayfish", 80, 24, 0, 0, &[])
            .await
            .expect("request pty");
        tty.exec(true, "echo on-tty term=$TERM")
            .await
            .expect("exec");
        pipe.exec(true, "echo on-pipe term=$TERM")
            .await
            .expect("exec");

        let (tty_out, tty_code) = drain(&mut tty).await;
        let (pipe_out, pipe_code) = drain(&mut pipe).await;

        assert!(tty_out.contains("on-tty"), "pty channel output: {tty_out}");
        assert!(!tty_out.contains("on-pipe"), "cross-talk: {tty_out}");
        assert!(
            tty_out.contains("term=xterm-rayfish"),
            "the pty channel gets its terminal: {tty_out}"
        );
        assert_eq!(tty_code, Some(0));

        assert!(
            pipe_out.contains("on-pipe"),
            "pipe channel output: {pipe_out}"
        );
        assert!(!pipe_out.contains("on-tty"), "cross-talk: {pipe_out}");
        assert!(
            !pipe_out.contains("xterm-rayfish"),
            "the pty must not leak onto the other channel: {pipe_out}"
        );
        assert!(
            !pipe_out.contains('\r'),
            "a pipe session is not line-translated: {pipe_out:?}"
        );
        assert_eq!(pipe_code, Some(0));
    }

    #[tokio::test]
    async fn direct_tcpip_channel_carries_a_forwarded_connection() {
        // `ssh -L`, `ssh -D` and `ProxyJump` all open this channel type. With
        // no handler for it russh refuses the open ("administratively
        // prohibited"), so every forward through a mesh host failed.
        let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo listener");
        let port = echo.local_addr().expect("echo address").port();
        tokio::spawn(async move {
            let (mut sock, _) = echo.accept().await.expect("accept forwarded connection");
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let handle = connect_to_test_server().await;
        let channel = handle
            .channel_open_direct_tcpip("127.0.0.1", port as u32, "127.0.0.1", 1234)
            .await
            .expect("open direct-tcpip channel");

        let mut stream = channel.into_stream();
        stream.write_all(b"ping").await.expect("write to forward");
        let mut buf = [0u8; 4];
        timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
            .await
            .expect("the forwarded connection never answered")
            .expect("read from forward");
        assert_eq!(&buf, b"ping", "bytes come back off the forwarded socket");
    }

    #[tokio::test]
    async fn direct_tcpip_channel_closes_when_the_target_refuses() {
        // Nothing listens on the port, so the channel must end instead of
        // hanging the client on a forward that will never carry data.
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind to claim a port");
        let port = dead.local_addr().expect("address").port();
        drop(dead);

        let handle = connect_to_test_server().await;
        let channel = handle
            .channel_open_direct_tcpip("127.0.0.1", port as u32, "127.0.0.1", 1234)
            .await
            .expect("open direct-tcpip channel");

        let mut stream = channel.into_stream();
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(20), stream.read(&mut buf))
            .await
            .expect("a forward to a refused port must not hang");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "the channel ends at EOF, not with data"
        );
    }

    #[tokio::test]
    async fn reverse_forward_carries_a_connection_back_to_the_client() {
        // `ssh -R`: this host listens, and each connection to the bound port
        // becomes a channel the *server* opens to the client.
        let (handle, mut opened) = connect_and_watch_openings().await;
        let port = handle
            .tcpip_forward("localhost", 0)
            .await
            .expect("reverse forward request");
        assert_ne!(port, 0, "a port-0 request must come back with the real one");

        let mut local = TcpStream::connect((Ipv4Addr::LOCALHOST, port as u16))
            .await
            .expect("connect to the reverse-forwarded port");
        let channel = timeout(Duration::from_secs(20), opened.recv())
            .await
            .expect("no forwarded channel arrived")
            .expect("the connection dropped");

        let mut stream = channel.into_stream();
        local.write_all(b"ping").await.expect("write on the socket");
        let mut buf = [0u8; 4];
        timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
            .await
            .expect("the forwarded bytes never arrived")
            .expect("read from the channel");
        assert_eq!(&buf, b"ping");

        stream.write_all(b"pong").await.expect("write back");
        timeout(Duration::from_secs(20), local.read_exact(&mut buf))
            .await
            .expect("nothing came back the other way")
            .expect("read from the socket");
        assert_eq!(&buf, b"pong", "the forward carries both directions");

        handle
            .cancel_tcpip_forward("localhost", port)
            .await
            .expect("cancel the forward");
        // The listener goes with the cancellation, so the port stops answering.
        let mut refused = false;
        for _ in 0..40 {
            if TcpStream::connect((Ipv4Addr::LOCALHOST, port as u16))
                .await
                .is_err()
            {
                refused = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(refused, "a cancelled forward must release its port");
    }

    #[tokio::test]
    async fn direct_streamlocal_channel_reaches_a_unix_socket() {
        // `ssh -L <port>:/path/to.sock`: docker, gpg-agent, database sockets.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("echo.sock");
        let echo = UnixListener::bind(&path).expect("bind echo socket");
        tokio::spawn(async move {
            let (mut sock, _) = echo.accept().await.expect("accept");
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let handle = connect_to_test_server().await;
        let channel = handle
            .channel_open_direct_streamlocal(path.display().to_string())
            .await
            .expect("open direct-streamlocal channel");

        let mut stream = channel.into_stream();
        stream.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
            .await
            .expect("the forwarded socket never answered")
            .expect("read");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn session_env_takes_locale_and_drops_the_rest() {
        // `SendEnv`/`SetEnv` may describe the client's locale, not steer the
        // login shell: a peer that could set LD_PRELOAD would be running its
        // own code inside every session.
        let handle = connect_to_test_server().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .expect("open session channel");
        channel
            .set_env(false, "LC_RAYFISH", "kept")
            .await
            .expect("set an accepted variable");
        channel
            .set_env(false, "LD_PRELOAD", "/tmp/evil.so")
            .await
            .expect("set a rejected variable");
        channel
            .exec(true, "echo env:$LC_RAYFISH:$LD_PRELOAD:")
            .await
            .expect("exec");
        let (out, code) = drain(&mut channel).await;
        assert!(out.contains("env:kept::"), "session environment: {out}");
        assert_eq!(code, Some(0));
    }

    #[tokio::test]
    async fn a_signal_request_reaches_the_session_process() {
        // The client asking to kill what it started, and the exit reported as
        // the signal it was rather than an invented status code.
        let handle = connect_to_test_server().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .expect("open session channel");
        channel.exec(true, "sleep 30").await.expect("exec");

        // The signal is repeated because it is only deliverable once the child
        // exists, and nothing on the wire says when that is.
        let mut signalled = None;
        for _ in 0..100 {
            let _ = channel.signal(Sig::TERM).await;
            match timeout(Duration::from_millis(200), channel.wait()).await {
                Ok(Some(ChannelMsg::ExitSignal { signal_name, .. })) => {
                    signalled = Some(format!("{signal_name:?}"));
                }
                Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
                Ok(Some(_)) => {}
                Err(_) => continue,
            }
        }
        assert_eq!(
            signalled.as_deref(),
            Some("TERM"),
            "the session must end reported as killed by SIGTERM"
        );
    }

    #[tokio::test]
    async fn agent_forwarding_hands_the_session_a_socket_that_reaches_the_client() {
        // `ssh -A`: the session gets an SSH_AUTH_SOCK whose other end is the
        // client's agent, so a key never has to live on this host.
        let (handle, mut opened) = connect_and_watch_openings().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .expect("open session channel");
        channel.agent_forward(true).await.expect("request an agent");
        channel
            .exec(true, "printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 5")
            .await
            .expect("exec");

        // Read the path the session was given, while it is still running (the
        // socket lives exactly as long as the channel).
        let mut path = String::new();
        for _ in 0..100 {
            match timeout(Duration::from_secs(20), channel.wait()).await {
                Ok(Some(ChannelMsg::Data { data })) => {
                    path.push_str(&String::from_utf8_lossy(&data));
                    if path.contains('\n') {
                        break;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let path = path.trim().to_string();
        assert!(
            path.contains("rayfish-ssh-agent"),
            "the session's SSH_AUTH_SOCK: {path:?}"
        );

        let mut sock = UnixStream::connect(&path)
            .await
            .expect("the session's agent socket must accept connections");
        let agent = timeout(Duration::from_secs(20), opened.recv())
            .await
            .expect("no agent channel reached the client")
            .expect("the connection dropped");

        // What the session writes to the socket comes out on the client's side
        // of the agent channel, which is where a real ssh-agent would answer.
        sock.write_all(b"ping").await.expect("write to the socket");
        let mut stream = agent.into_stream();
        let mut buf = [0u8; 4];
        timeout(Duration::from_secs(20), stream.read_exact(&mut buf))
            .await
            .expect("the agent bytes never arrived")
            .expect("read from the agent channel");
        assert_eq!(&buf, b"ping");
    }

    /// Kept out of the normal run: an interactive login shell depends on the
    /// host's shell and its rc files, and as root it goes through `login(1)`,
    /// which writes real utmp/wtmp records. Run it deliberately, as root, to
    /// exercise the login handoff:
    ///
    /// ```text
    /// cargo test --lib -- --ignored --exact ssh::tests::a_login_shell_runs_and_exits
    /// ```
    #[tokio::test]
    #[ignore]
    async fn a_login_shell_runs_and_exits() {
        // Reaching `login(1)` needs a root server and a non-root login, which
        // under `sudo` is the account that invoked it.
        let login_as = match uzers::get_effective_uid() {
            0 => std::env::var("SUDO_USER").unwrap_or_else(|_| test_account()),
            _ => test_account(),
        };
        let handle = connect_watching_openings(None, login_as).await;
        let mut channel = handle
            .channel_open_session()
            .await
            .expect("open session channel");
        channel
            .request_pty(true, "xterm-rayfish", 80, 24, 0, 0, &[])
            .await
            .expect("request pty");
        channel.request_shell(true).await.expect("request shell");
        // The quotes matter: the terminal echoes what we type, so the command
        // has to look different from its own output for the marker to mean the
        // shell ran it. And it is offered repeatedly because `login` flushes
        // the terminal before exec'ing the shell, so anything typed while it
        // was still printing the motd is gone.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut retype = tokio::time::Instant::now();
        let mut out = String::new();
        let mut ran = false;
        while tokio::time::Instant::now() < deadline {
            if !ran && tokio::time::Instant::now() >= retype {
                let _ = channel.data(&b"echo ray\"fish\"-marker\n"[..]).await;
                retype = tokio::time::Instant::now() + Duration::from_millis(500);
            }
            match timeout(Duration::from_millis(200), channel.wait()).await {
                Ok(Some(ChannelMsg::Data { data })) => {
                    out.push_str(&String::from_utf8_lossy(&data));
                    if !ran && out.contains("rayfish-marker") {
                        ran = true;
                        let _ = channel.data(&b"exit\n"[..]).await;
                    }
                }
                Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
                Ok(Some(_)) => {}
                Err(_) => continue,
            }
        }
        assert!(ran, "the login shell never ran our command: {out:?}");
    }

    #[tokio::test]
    async fn a_session_knows_it_is_remote() {
        // Prompts, `screen`, and any script that asks "am I over ssh" read
        // these. A session without them looks local.
        let handle = connect_to_test_server().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .expect("open session channel");
        channel
            .exec(true, "echo conn:$SSH_CONNECTION client:$SSH_CLIENT")
            .await
            .expect("exec");
        let (out, code) = drain(&mut channel).await;
        assert_eq!(code, Some(0));
        // "<client ip> <client port> <server ip> <server port>", and the server
        // port is the 22 the client dialled, not the internal listen port.
        let conn = out
            .split_whitespace()
            .find(|w| w.starts_with("conn:"))
            .map(|w| w.trim_start_matches("conn:").to_string())
            .expect("SSH_CONNECTION is set");
        assert_eq!(conn, "127.0.0.1", "SSH_CONNECTION starts at the client: {out}");
        assert!(
            out.contains(&format!(" {SSH_PORT} ")) || out.ends_with(&format!(" {SSH_PORT}")),
            "the server port is the one the client dialled: {out}"
        );
        assert!(out.contains("client:127.0.0.1"), "SSH_CLIENT is set: {out}");
    }

    #[tokio::test]
    async fn a_pty_reports_its_terminal() {
        // SSH_TTY names the pts the session runs on; `write`, `who` and
        // anything that talks to a terminal by path need it.
        let (_pty, pts) = pty_process::open().expect("open a pty");
        let name = tty_name(&pts).expect("the child end of a pty has a name");
        assert!(
            name.starts_with("/dev/"),
            "a terminal path, got {name:?}"
        );
    }

    #[test]
    fn reverse_forwards_bind_loopback_only() {
        // A reverse forward publishes the peer's service on this host, so a
        // wildcard bind is narrowed, like sshd's default `GatewayPorts no`.
        assert_eq!(
            reverse_bind_addr("localhost"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(reverse_bind_addr(""), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(reverse_bind_addr("::1"), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(reverse_bind_addr("*"), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(reverse_bind_addr("0.0.0.0"), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            reverse_bind_addr("10.0.0.1"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn accepted_env_is_locale_only() {
        assert!(env_accepted("LANG"));
        assert!(env_accepted("LC_ALL"));
        assert!(env_accepted("LC_CTYPE"));
        assert!(env_accepted("TZ"));
        assert!(env_accepted("TERM"));
        // The ones that would run the peer's code inside the session.
        assert!(!env_accepted("LD_PRELOAD"));
        assert!(!env_accepted("LD_LIBRARY_PATH"));
        assert!(!env_accepted("PATH"));
        assert!(!env_accepted("BASH_ENV"));
        assert!(!env_accepted("SSH_AUTH_SOCK"));
    }

    #[test]
    fn user_policy_explicit_and_wildcard() {
        let alice = id(1);
        let authz = new_authz();
        // net1: alice may only be `deploy`; net2: alice may be any user (`*`).
        authz.store(Arc::new(HashMap::from([
            (
                "net1".to_string(),
                vec![rule(&alice.to_string(), &["deploy"])],
            ),
            ("net2".to_string(), vec![rule(&alice.to_string(), &["*"])]),
        ])));

        // Only net1 shared → just `deploy`, root and others denied.
        let p = resolve_user_policy(&authz, &alice, &[SmolStr::new("net1")]);
        assert!(p.permits("deploy", 1000));
        assert!(!p.permits("ci", 1001));
        assert!(!p.permits("root", 0));

        // net2 shared → `*` wins, even root.
        let p = resolve_user_policy(&authz, &alice, &[SmolStr::new("net2")]);
        assert!(p.permits("root", 0));

        // Union: explicit `deploy` (net1) + `*` (net2) → `*` dominates.
        let p = resolve_user_policy(
            &authz,
            &alice,
            &[SmolStr::new("net1"), SmolStr::new("net2")],
        );
        assert!(p.permits("root", 0));
        assert!(p.permits("anyone", 1234));
    }
}
