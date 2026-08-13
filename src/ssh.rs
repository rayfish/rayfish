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
//! Authorization is evaluated once, when the connection is accepted, so
//! `ray firewall ssh allow/deny` changes apply to *new* sessions; an
//! already-established session is not torn down by a later `deny`.

use std::collections::HashMap;
use std::io::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use iroh::EndpointId;
use pty_process::Size;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
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
pub(crate) use crate::forward::SSH_LISTEN_PORT;

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
    let handler = SshHandler::new(policy, user_identity, banner);
    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            let _ = session.await;
        }
        Err(e) => debug!(error = %e, "mesh SSH session ended with error"),
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
}

impl SshHandler {
    fn new(policy: UserPolicy, user: EndpointId, banner: Option<String>) -> Self {
        Self {
            policy,
            user,
            banner,
            login_user: String::new(),
            login: None,
            channels: HashMap::new(),
        }
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
        let peer = self.user;
        let (resize_tx, resize_rx) = mpsc::unbounded_channel();
        state.resize_tx = Some(resize_tx);

        tokio::spawn(async move {
            // A PTY was requested -> interactive terminal. Otherwise (`ssh host
            // cmd` with no -t) use plain pipes so stdout/stderr aren't merged or
            // CRLF-translated, matching a conventional sshd.
            let result = match pty {
                Some(pty_req) => run_pty_session(channel, info, command, pty_req, resize_rx).await,
                None => run_pipe_session(channel, handle.clone(), channel_id, info, command).await,
            };
            let code = match result {
                Ok(c) => c,
                Err(e) => {
                    warn!(peer = %peer.fmt_short(), user = %login_name, error = %e, "mesh SSH session failed");
                    1
                }
            };
            let _ = handle.exit_status_request(channel_id, code).await;
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

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Either the client closed the channel or it is answering the close the
        // session task sent when the process exited. Either way this channel's
        // state is dead; the rest of the connection's channels carry on.
        self.channels.remove(&channel);
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

/// Allocate a PTY, spawn the login shell (or `exec` command) as the requested
/// unix user, and pump bytes between the SSH channel and the PTY until the child
/// exits. Returns the child's exit code.
async fn run_pty_session(
    channel: Channel<Msg>,
    info: Arc<LoginInfo>,
    command: Option<String>,
    pty_req: PtyReq,
    mut resize_rx: mpsc::UnboundedReceiver<Size>,
) -> Result<u32> {
    let drop = drop_privs(info.uid, info.gid, &info.name)?;

    let (pty, pts) = pty_process::open().context("opening pty")?;
    let _ = pty.resize(Size::new(pty_req.row, pty_req.col));

    let mut cmd = pty_process::Command::new(&info.shell);
    match &command {
        Some(c) => cmd = cmd.arg("-c").arg(c),
        None => cmd = cmd.arg("-l"),
    }
    cmd = cmd
        .current_dir(&info.home)
        .env_clear()
        .envs(login_env(&info.home, &info.shell, &info.name))
        .env("TERM", &pty_req.term);
    // SAFETY: drops privileges (initgroups+setgid+setuid) before exec; we do NOT
    // use `.uid()/.gid()` because std applies those *after* pre_exec, too late to
    // also drop supplementary groups.
    cmd = unsafe { cmd.pre_exec(drop) };
    let mut child = cmd.spawn(pts).context("spawning login shell")?;

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
    let _ = p2c.await;
    c2p.abort();
    Ok(status.code().unwrap_or(0) as u32)
}

/// Run a command (or shell) with **pipes** instead of a PTY, for a non-`-t`
/// `ssh host cmd`. stdout goes to the channel's data stream and stderr to the
/// extended-data (code 1) stream, kept separate and untranslated, as a
/// conventional sshd delivers them, so piped/binary output isn't corrupted.
async fn run_pipe_session(
    channel: Channel<Msg>,
    handle: Handle,
    channel_id: ChannelId,
    info: Arc<LoginInfo>,
    command: Option<String>,
) -> Result<u32> {
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: drops privileges (initgroups+setgid+setuid) before exec.
    unsafe {
        cmd.pre_exec(drop);
    }
    let mut child = cmd.spawn().context("spawning command")?;
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
    let _ = out_task.await;
    let _ = err_task.await;
    stdin_task.abort();
    Ok(status.code().unwrap_or(0) as u32)
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
    /// so there is nothing to verify against.
    struct AcceptAnyHost;

    impl client::Handler for AcceptAnyHost {
        type Error = russh::Error;

        async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
            Ok(true)
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
            let (stream, _) = listener.accept().await.expect("accept");
            let mut policy = UserPolicy::default();
            policy.add(&["*".to_string()]);
            let handler = SshHandler::new(policy, id(1), None);
            if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                let _ = session.await;
            }
        });

        let mut handle = client::connect(Arc::new(client::Config::default()), addr, AcceptAnyHost)
            .await
            .expect("client connect");
        assert!(
            handle
                .authenticate_none(test_account())
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
