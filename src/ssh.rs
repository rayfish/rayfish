#![cfg(unix)]

//! Embedded mesh SSH server (`ray firewall ssh on`), Tailscale-style.
//!
//! The daemon runs a small SSH server on each mesh IP's configured SSH port
//! (22 by default). A stock `ssh` client connecting to `<peer>.ray` (or the mesh IP)
//! lands here. There are no SSH keys: the connecting peer is already
//! cryptographically identified by the QUIC mesh link, and the kernel TCP stack
//! delivers the connection with the peer's mesh IP as the socket source (the
//! ingress anti-spoof check in [`crate::forward`] guarantees that IP is really
//! the peer's). We map that IP back to the peer identity via [`crate::peers::PeerTable`] and
//! admit the session iff the peer is in a shared network's `ssh_allow` list.
//! Grants are checked across verified memberships, not the network handles on
//! the current connection. Reconnecting through another network cannot hide a grant.
//!
//! Authorization is the only gate; SSH auth itself is the `none` method (the
//! identity is already proven). Which local accounts a peer may log in as comes
//! from its `SshRule.users` (see [`UserPolicy`]): empty grants any non-root
//! account, an explicit list grants exactly those, `*` grants any including root.
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
//! Forwarding runs in the daemon, which is root, so it must not be worth more
//! than a shell on the same host. A TCP forward goes anywhere the host can
//! reach (loopback services included), exactly like a shell would, and a
//! non-root account cannot reverse-forward a privileged port. Every unix-socket
//! connect, bind and cleanup (`-L`, `-R` and agent sockets) runs in a forked
//! child that has become the login account ([`as_user`]): there the
//! filesystem *is* the access control, and a listening service reads the
//! caller's uid from `SO_PEERCRED`. Forwards and connections are
//! capped so one peer cannot exhaust the daemon.
//!
//! Authorization is evaluated once, when the connection is accepted, so
//! `ray firewall ssh allow/deny` changes apply to *new* sessions; an
//! already-established session is not torn down by a later `deny`.
//!
//! Self-connections use a separate listener on the configured mesh SSH port.
//! The client socket's local UID authorizes login to that same account; root
//! may select any account. Mesh grants do not give local users extra privileges.
//! An IPv6 host sshd already occupying that port continues to handle self-SSH.

#[cfg(any(target_os = "macos", test))]
pub mod app_helper;
mod as_user;
mod authz;
mod host_keys;
mod local;
mod login;
mod session;
mod session_env;
mod slots;

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream as StdTcpStream};
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use pty_process::Size;
#[cfg(test)]
use russh::keys::Algorithm;
use russh::keys::PrivateKey;
use russh::server::{Auth, ChannelOpenHandle, Config, Handle, Handler, Msg, Session};
use russh::{
    Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Preferred, Sig, compression,
};
#[cfg(test)]
use smol_str::SmolStr;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
#[cfg(test)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, info, warn};

use crate::daemon::NetworkRegistry;
#[cfg(test)]
use authz::resolve_user_policy;
pub use authz::{SshAuthz, new_authz};
use authz::{UserPolicy, auth_banner, resolve_user_policy_with_hostnames};
#[cfg(test)]
use host_keys::{host_key_paths, parse_hostkey_paths, parse_sftp_subsystem};
use host_keys::{load_host_key, sftp_subsystem_command};
use login::{LoginInfo, resolve_login};
use session::{Exit, SessionSpec, run_pipe_session, run_pty_session, signal_number};
use session_env::env_accepted;
#[cfg(test)]
use session_env::{prepare_pts, tty_name};

// The port a stock `ssh` client targets (`ssh user@host.ray`) and the internal
// port the embedded server actually binds. Both live in `crate::forward` (the
// always-compiled core) because the userspace SSH NAT there rewrites the mesh SSH port
// <-> the listen port on every platform, including Android where this module is
// gated out. We can't bind `:22` directly: a host sshd on `0.0.0.0:22` makes the
// kernel reject a more-specific `<mesh-ip>:22` bind (EADDRINUSE), so the daemon
// binds `SSH_LISTEN_PORT` and translates the port in the forwarding path instead
// of an OS-firewall redirect. Re-exported here so the public path stays stable.
pub(crate) use crate::forward::SSH_LISTEN_PORT;
#[cfg(test)]
use crate::forward::SSH_PORT;

/// Reverse forwards (`ssh -R`, TCP and unix socket together) one connection
/// may hold at once.
const MAX_REVERSE_FORWARDS: usize = 32;

/// Forwarded connections (`ssh -L`, `-D`, `ProxyJump`, and connections
/// accepted on `-R` and agent sockets) one connection may carry at once. A
/// browser behind `-D` opens dozens, not hundreds.
const MAX_FORWARDED_CHANNELS: usize = 256;

/// SSH connections the server holds at once, across every peer and listener.
/// Past this, new connections are closed on accept.
const MAX_CONNECTIONS: usize = 256;

/// SSH connections one mesh peer, or one local account, may hold at once, so
/// a single source cannot fill [`MAX_CONNECTIONS`] for everyone else.
const MAX_CONNECTIONS_PER_SOURCE: usize = 16;

/// How long a `ssh -L` / `-D` forwarded connection may take to reach its target
/// before the channel is dropped. Short enough that a black-holed address fails
/// while the person who typed the command is still watching.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection has, from being accepted to completing authentication,
/// before it is dropped. Keepalives only establish that the peer is responsive;
/// without this deadline a peer could answer them forever without authenticating.
/// Generous next to a handshake that is a few round trips over a mesh link.
const LOGIN_GRACE: Duration = Duration::from_secs(60);

fn server_config(key: PrivateKey) -> Config {
    Config {
        keys: vec![key],
        // Mesh identity or the local socket owner authorizes `auth_none`.
        methods: MethodSet::from(&[MethodKind::None][..]),
        // Quiet sessions stay open while the client answers SSH keepalives.
        // This also refreshes the mesh firewall's idle TCP flow tracking.
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        // Russh sends three probes, then closes on the fourth tick: roughly
        // 60 seconds since the last received SSH packet, even with output flowing.
        keepalive_max: 3,
        auth_rejection_time: Duration::from_secs(1),
        // Offer "none" only. Russh's zlib is broken on the receive side: with
        // `zlib@openssh.com` negotiated, the second SSH_MSG_CHANNEL_DATA the
        // client sends fails to decompress and the connection dies with
        // `SshEncoding: length invalid`. A stock OpenSSH client picks zlib
        // whenever `Compression yes` is set in its config, so anyone with that
        // setting gets a session that drops the moment they type a second
        // command. Traffic on the mesh link is already small and latency-bound;
        // compressing it buys nothing worth that.
        preferred: Preferred {
            compression: Cow::Borrowed(&[compression::NONE]),
            ..Preferred::DEFAULT
        },
        ..Default::default()
    }
}

/// Handle to a running SSH server so the daemon can stop it on `ray down` /
/// `ssh off`. Dropping or cancelling the token tears down every listener.
pub struct SshServer {
    registry: Arc<NetworkRegistry>,
    authz: SshAuthz,
}

impl SshServer {
    pub(crate) fn new(registry: Arc<NetworkRegistry>, authz: SshAuthz) -> Self {
        Self { registry, authz }
    }

    /// Spawn a listener on each mesh address (at [`SSH_LISTEN_PORT`]). Runs until
    /// `token` is cancelled. The configured mesh SSH port is mapped to this port
    /// by the userspace NAT in `forward.rs`, with a separate listener for self-SSH.
    pub fn spawn(self, addrs: Vec<IpAddr>, token: CancellationToken) {
        session_env::warm_scope_tools();
        tokio::spawn(async move {
            let key = match load_host_key() {
                Ok(k) => k,
                Err(e) => {
                    warn!(error = %e, "mesh SSH: could not load host key; SSH disabled");
                    return;
                }
            };
            let config = Arc::new(server_config(key));
            let slots = Arc::new(slots::ConnectionSlots::new(
                MAX_CONNECTIONS,
                MAX_CONNECTIONS_PER_SOURCE,
            ));
            for addr in addrs {
                let listener = match crate::listener::bind_listener(addr, SSH_LISTEN_PORT) {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(%addr, port = SSH_LISTEN_PORT, error = %e, "mesh SSH: cannot bind listener; skipping");
                        continue;
                    }
                };
                let local_listener = match addr {
                    IpAddr::V6(address) => {
                        match local::bind_retry(address, crate::forward::ssh_port()).await {
                            Ok(listener) => Some(listener),
                            Err(error) => {
                                warn!(%error, "mesh SSH: cannot bind self-SSH port; a host sshd may already own it");
                                None
                            }
                        }
                    }
                    IpAddr::V4(_) => None,
                };
                info!(%addr, port = SSH_LISTEN_PORT, mesh_port = crate::forward::ssh_port(), "mesh SSH listening");
                let registry = Arc::clone(&self.registry);
                let authz = Arc::clone(&self.authz);
                let config = Arc::clone(&config);
                let token = token.clone();
                let slots = Arc::clone(&slots);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            accepted = local::accept(&listener, local_listener.as_ref()) => {
                                let (stream, peer) = match accepted {
                                    Ok(p) => p,
                                    Err(e) => { debug!(error = %e, "mesh SSH accept failed"); continue; }
                                };
                                let Some(slot) = slots.admit() else {
                                    warn!(%peer, "mesh SSH: refusing a connection past the connection limit");
                                    continue;
                                };
                                disable_nagle(&stream);
                                let conn = ConnContext {
                                    config: Arc::clone(&config),
                                    registry: Arc::clone(&registry),
                                    authz: Arc::clone(&authz),
                                    slots: Arc::clone(&slots),
                                };
                                tokio::spawn(async move {
                                    let _slot = slot;
                                    handle_conn(stream, peer, conn).await;
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

/// A slot under a connection's [`MAX_FORWARDED_CHANNELS`], shared by `-L` and
/// by connections accepted on its `-R` and agent sockets, or `None` at the
/// limit.
fn forwarded_slot(slots: &Arc<Semaphore>, peer: EndpointId) -> Option<OwnedSemaphorePermit> {
    let slot = Arc::clone(slots).try_acquire_owned().ok();
    if slot.is_none() {
        warn!(peer = %peer.fmt_short(), limit = MAX_FORWARDED_CHANNELS,
            "mesh SSH: refusing a forwarded connection past the limit");
    }
    slot
}

/// Turn off Nagle on an SSH-carrying socket.
///
/// SSH is a request/response protocol made of small writes. Nagle holds a small
/// write back waiting for more data to coalesce, while the peer's delayed ACK
/// holds the acknowledgement back waiting for a reply to piggyback on, and the
/// two wait for each other until a timer breaks the tie. That costs a stall per
/// exchange: opening a session channel over a 34 ms mesh link measured 117 ms
/// with Nagle on against 84 ms for OpenSSH over a slower transport, and ansible,
/// which opens one channel per task, paid it once per task.
///
/// russh has a `nodelay` config flag, but it only applies it inside its own
/// accept loop (`run_on_socket`), and we do our own accept and hand the stream
/// to `run_stream`. So it has to be set here, on every socket carrying SSH:
/// the session itself and both directions of port forwarding.
fn disable_nagle(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!(error = %e, "mesh SSH: could not set TCP_NODELAY");
    }
}

struct SshAuthorization {
    user_identity: EndpointId,
    policy: UserPolicy,
    banner: Option<String>,
}

/// What every accepted connection needs from the server.
struct ConnContext {
    config: Arc<Config>,
    registry: Arc<NetworkRegistry>,
    authz: SshAuthz,
    slots: Arc<slots::ConnectionSlots>,
}

/// Resolve the connecting peer, decide authorization, and run the SSH session.
async fn handle_conn(stream: TcpStream, peer: SocketAddr, conn: ConnContext) {
    let ConnContext {
        config,
        registry,
        authz,
        slots,
    } = conn;
    // The mesh listener only ever binds our own overlay address, so a session
    // arrives over IPv6 or it is not a mesh session at all.
    let IpAddr::V6(src) = peer.ip() else {
        debug!(peer = %peer.ip(), "mesh SSH: non-IPv6 source on the mesh listener, dropping");
        return;
    };
    let (
        source,
        SshAuthorization {
            user_identity,
            policy,
            banner,
        },
    ) = if src == registry.transport.identity.local_ipv6() {
        let Ok(server) = stream.local_addr() else {
            return;
        };
        let Some(uid) = local::uid(peer, server).await else {
            debug!(%src, "mesh SSH: cannot identify local socket owner, dropping");
            return;
        };
        let authorization = SshAuthorization {
            user_identity: registry.transport.identity.local_identity(),
            policy: UserPolicy::local(uid),
            banner: None,
        };
        (slots::Source::LocalUid(uid), authorization)
    } else {
        let Some(peer_id) = registry.peers.identity_for_ip(&src) else {
            debug!(%src, "mesh SSH: connection from unknown mesh IP, dropping");
            return;
        };
        let user_identity = registry.device_user_map.resolve(&peer_id);
        let networks = registry.authorization_networks(peer_id);
        let resolve = |network: &str, hostname: &str| {
            registry
                .resolve_peer_in_network(network, hostname)
                .map(|id| registry.device_user_map.resolve(&id))
        };
        let policy =
            resolve_user_policy_with_hostnames(&authz, &user_identity, &networks, &resolve);
        let banner = auth_banner(&policy, &user_identity, &networks);
        let authorization = SshAuthorization {
            user_identity,
            policy,
            banner,
        };
        (slots::Source::Peer(peer_id), authorization)
    };
    let Some(_source_slot) = slots.claim(source) else {
        warn!(%src, peer = %user_identity.fmt_short(), limit = MAX_CONNECTIONS_PER_SOURCE,
            "mesh SSH: refusing a connection past the per-source limit");
        return;
    };
    // Logged before the handshake, and with the source port, so a session that
    // stalls before it authenticates (and so logs nothing else) is still
    // visible here and can be matched to a socket in `ss` output.
    debug!(%src, port = peer.port(), peer = %user_identity.fmt_short(),
        authorized = policy.authorized(), "mesh SSH connection");
    // The address the client believes it reached, not the internal listen port
    // the SSH NAT sent it to: this is what the session reports in
    // `SSH_CONNECTION` and what `login` records as the origin.
    let server = stream
        .local_addr()
        .map(|a| SocketAddr::new(a.ip(), crate::forward::ssh_port()))
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V6(src), crate::forward::ssh_port()));
    let handler = SshHandler::new(
        policy,
        user_identity,
        banner,
        Origin {
            client: peer,
            server,
        },
    );
    serve(config, stream, handler, LOGIN_GRACE).await;
}

/// Run the SSH protocol on an accepted connection, dropping it if the peer has
/// not authenticated within `grace`.
///
/// The two halves of the handshake have to be bounded separately. russh reads
/// the client's version string inside `run_stream`, before there is a session
/// to speak of, so that half is bounded by dropping the future, which takes the
/// socket with it. Everything after it runs in a task russh spawns and owns,
/// and nothing here can cancel that task: what ends it is `shutdown(2)` on a
/// duplicate of the socket, which fails its next read, so it drops the handler
/// and with it the connection's channels, forwards and agent sockets.
async fn serve(config: Arc<Config>, stream: TcpStream, handler: SshHandler, grace: Duration) {
    let client = handler.origin.client;
    let (src, port) = (client.ip(), client.port());
    let peer = handler.user;
    let authenticated = handler.auth_flag();
    // A hangup handle. Never read from or written to: the session task owns the
    // socket for I/O, this only ever shuts it down.
    let hangup = match stream.as_fd().try_clone_to_owned().map(StdTcpStream::from) {
        Ok(h) => h,
        Err(e) => {
            warn!(%src, port, error = %e,
                "mesh SSH: cannot duplicate the connection socket; dropping");
            return;
        }
    };
    let deadline = Instant::now() + grace;
    let mut running =
        match timeout_at(deadline, russh::server::run_stream(config, stream, handler)).await {
            Ok(Ok(running)) => running,
            Ok(Err(e)) => {
                debug!(error = %e, "mesh SSH session ended with error");
                return;
            }
            Err(_) => {
                warn!(%src, port, peer = %peer.fmt_short(), secs = grace.as_secs(),
                "mesh SSH: no version string within the login grace; dropping");
                return;
            }
        };
    match timeout_at(deadline, &mut running).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!(error = %e, "mesh SSH session ended with error"),
        // Authenticated in time. From here the session runs as long as the
        // client remains responsive to SSH traffic or keepalives.
        Err(_) if authenticated.load(Ordering::Relaxed) => {
            if let Err(e) = running.await {
                debug!(error = %e, "mesh SSH session ended with error");
            }
        }
        Err(_) => {
            warn!(%src, port, peer = %peer.fmt_short(), secs = grace.as_secs(),
                "mesh SSH: no authentication within the login grace; dropping");
            let _ = hangup.shutdown(Shutdown::Both);
            let _ = running.await;
        }
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
    agent: Option<DropGuard>,
    /// The running child, for `signal` requests. Empty until the session starts.
    child: Option<ChildProc>,
    /// Cancelled before sending our close, since russh does not call
    /// `channel_close` for an acknowledgement of a server-initiated close.
    finished: CancellationToken,
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
    /// One permit per forwarded connection in flight, held by its task.
    forwarded: Arc<Semaphore>,
    /// Parent of every token above: cancelled when the handler drops, so a
    /// connection that goes away takes its listeners with it.
    token: CancellationToken,
    /// Where this connection came from, for the session environment and the
    /// login record.
    origin: Origin,
    /// Set once a peer is admitted, so the login grace can tell a connection
    /// that authenticated from one that is only holding the socket open.
    authenticated: Arc<AtomicBool>,
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
    fn new(policy: UserPolicy, user: EndpointId, banner: Option<String>, origin: Origin) -> Self {
        Self {
            policy,
            user,
            banner,
            login: None,
            channels: HashMap::new(),
            forwards: HashMap::new(),
            socket_forwards: HashMap::new(),
            forwarded: Arc::new(Semaphore::new(MAX_FORWARDED_CHANNELS)),
            token: CancellationToken::new(),
            origin,
            authenticated: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The flag [`Handler::auth_none`] sets once this peer is admitted. Taken
    /// before the handler is handed to russh, which owns it from then on.
    fn auth_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.authenticated)
    }

    /// A slot for one more forwarded connection, or `None` at the limit.
    fn forwarded_slot(&self) -> Option<OwnedSemaphorePermit> {
        forwarded_slot(&self.forwarded, self.user)
    }

    /// Whether this connection may open one more reverse forward. Replacing
    /// one it already holds (`replacing`) always fits.
    fn reverse_forward_room(&self, replacing: bool) -> bool {
        let room =
            replacing || self.forwards.len() + self.socket_forwards.len() < MAX_REVERSE_FORWARDS;
        if !room {
            warn!(peer = %self.user.fmt_short(), limit = MAX_REVERSE_FORWARDS,
                "mesh SSH: refusing a reverse forward past the limit");
        }
        room
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
        let finished = state.finished.clone();

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
            finished.cancel();
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
                self.authenticated.store(true, Ordering::Relaxed);
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
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels
            .retain(|_, state| !state.finished.is_cancelled());
        self.channels.insert(
            channel.id(),
            ChannelState {
                channel: Some(channel),
                ..Default::default()
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // `ssh -L`, `ssh -D` and `ProxyJump` all ride this channel type.
        // Dropping `reply` on an early return refuses the channel.
        if self.authorized_login().is_none() {
            return Ok(());
        }
        let Ok(port) = u16::try_from(port_to_connect) else {
            debug!(peer = %self.user.fmt_short(), port_to_connect,
                "mesh SSH: rejecting forward to an out-of-range port");
            return Ok(());
        };
        let Some(slot) = self.forwarded_slot() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        let target = format!("{host_to_connect}:{port}");
        let peer = self.user;
        let handle = session.handle();
        // Connect off the session task: it is shared by every channel on this
        // connection, so a slow or black-holed connect here would stall the
        // peer's shells and its other forwards. The open is answered once the
        // connect settles, so a failure reaches the client as "connect failed".
        tokio::spawn(async move {
            let _slot = slot;
            let connected = timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await;
            let upstream = match connected {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!(peer = %peer.fmt_short(), %target, error = %e,
                        "mesh SSH: forwarded connection failed");
                    reply.reject(ChannelOpenFailure::ConnectFailed).await;
                    return;
                }
                Err(_) => {
                    debug!(peer = %peer.fmt_short(), %target,
                        "mesh SSH: forwarded connection timed out");
                    reply.reject(ChannelOpenFailure::ConnectFailed).await;
                    return;
                }
            };
            disable_nagle(&upstream);
            debug!(peer = %peer.fmt_short(), %target, "mesh SSH: forwarding to");
            reply.accept().await;
            splice(channel, handle, upstream).await;
        });
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // `ssh -L <port>:/run/some.sock` and anything forwarding a unix socket
        // (docker, gpg-agent, a database's local socket).
        let Some(info) = self.authorized_login() else {
            return Ok(());
        };
        let Some(slot) = self.forwarded_slot() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        let path = PathBuf::from(socket_path);
        let peer = self.user;
        let handle = session.handle();
        tokio::spawn(async move {
            let _slot = slot;
            match timeout(CONNECT_TIMEOUT, as_user::connect(info, path.clone())).await {
                Ok(Ok(sock)) => {
                    debug!(peer = %peer.fmt_short(), socket = %path.display(),
                        "mesh SSH: forwarding to");
                    reply.accept().await;
                    splice(channel, handle, sock).await;
                }
                Ok(Err(e)) => {
                    debug!(peer = %peer.fmt_short(), socket = %path.display(), error = %e,
                        "mesh SSH: forwarded socket connection failed");
                    reply.reject(ChannelOpenFailure::ConnectFailed).await;
                }
                Err(_) => {
                    debug!(peer = %peer.fmt_short(), socket = %path.display(),
                        "mesh SSH: forwarded socket connection timed out");
                    reply.reject(ChannelOpenFailure::ConnectFailed).await;
                }
            }
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // `ssh -R`: this host listens, the peer's side answers.
        let Some(info) = self.authorized_login() else {
            return Ok(false);
        };
        if !self.reverse_forward_room(self.forwards.contains_key(&(address.to_string(), *port))) {
            return Ok(false);
        }
        let Ok(requested) = u16::try_from(*port) else {
            return Ok(false);
        };
        // The daemon binds as root; a privileged port stays root's, as in sshd.
        if requested != 0 && requested < 1024 && info.uid != 0 {
            warn!(peer = %self.user.fmt_short(), user = %info.name, port = requested,
                "mesh SSH: refusing a privileged reverse forward port");
            return Ok(false);
        }
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
        let slots = Arc::clone(&self.forwarded);
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
                let Some(slot) = forwarded_slot(&slots, peer) else {
                    continue;
                };
                disable_nagle(&sock);
                let handle = handle.clone();
                let advertised = advertised.clone();
                tokio::spawn(async move {
                    let _slot = slot;
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
        if !self.reverse_forward_room(self.socket_forwards.contains_key(socket_path)) {
            return Ok(false);
        }
        // Bound by the login account itself, so it lands only where that
        // account could have created it and belongs to it from the start. A
        // stale socket of the account's own at the path is replaced.
        let path = PathBuf::from(socket_path);
        let as_user::Bound { listener, file } = match as_user::listen(
            Arc::clone(&info),
            path.clone(),
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!(peer = %self.user.fmt_short(), socket = socket_path, error = %format!("{e:#}"),
                    "mesh SSH: cannot bind a reverse socket forward");
                return Ok(false);
            }
        };

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
        let slots = Arc::clone(&self.forwarded);
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
                let Some(slot) = forwarded_slot(&slots, peer) else {
                    continue;
                };
                let handle = handle.clone();
                let advertised = advertised.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    match handle.channel_open_forwarded_streamlocal(advertised).await {
                        Ok(channel) => splice(channel, handle, sock).await,
                        Err(e) => debug!(peer = %peer.fmt_short(), error = %e,
                            "mesh SSH: peer refused a reverse-forwarded socket connection"),
                    }
                });
            }
            // The listener holds the only reference to this path; take the
            // socket file with it so the next session can bind again.
            drop(listener);
            if let Err(e) = as_user::remove_socket(info, path.clone(), file).await {
                debug!(socket = %path.display(), error = %format!("{e:#}"),
                    "mesh SSH: cannot remove a reverse-forwarded socket");
            }
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
        let Some(state) = self.channels.get(&channel) else {
            return Ok(false);
        };
        let token = state.finished.child_token();
        let peer = self.user;
        let (agent_dir, as_user::Bound { listener, file }) =
            match open_agent_socket(Arc::clone(&info)).await {
                Ok(a) => a,
                Err(e) => {
                    warn!(peer = %peer.fmt_short(), error = %e,
                    "mesh SSH: cannot set up agent forwarding");
                    return Ok(false);
                }
            };
        let path = agent_dir.join(AGENT_SOCKET);
        let accept_token = token.clone();
        let socket = path.clone();
        let handle = session.handle();
        let slots = Arc::clone(&self.forwarded);
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
                let Some(slot) = forwarded_slot(&slots, peer) else {
                    continue;
                };
                let handle = handle.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    match handle.channel_open_agent().await {
                        Ok(channel) => splice(channel, handle, sock).await,
                        Err(e) => debug!(peer = %peer.fmt_short(), error = %e,
                            "mesh SSH: peer refused an agent connection"),
                    }
                });
            }
            drop(listener);
            remove_agent_dir(info, agent_dir, Some(file)).await;
            debug!(socket = %socket.display(), "mesh SSH: agent forwarding closed");
        });

        // Safe: the channel was there at the top of this method and `&mut self`
        // has not been released since.
        if let Some(state) = self.channels.get_mut(&channel) {
            state
                .env
                .push(("SSH_AUTH_SOCK".to_string(), path.display().to_string()));
            state.agent = Some(token.drop_guard());
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
        state
            .env
            .push((variable_name.to_string(), variable_value.to_string()));
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
        // The client closed the channel. Hang up anything still running under
        // it; the rest of the connection's channels carry on.
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
        // `sshd -T` behind it is a child process: keep it off the worker.
        let command = match tokio::task::spawn_blocking(sftp_subsystem_command).await {
            Ok(command) => command,
            Err(e) => {
                warn!(error = %e, "mesh SSH: sftp server lookup failed");
                None
            }
        };
        let Some(command) = command else {
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

/// File name of the agent-forwarding socket inside its private directory.
const AGENT_SOCKET: &str = "agent.sock";

/// Create the agent-forwarding socket for one session: a private directory
/// holding a single unix socket, both owned by the login account, so nothing
/// but that account can talk to the peer's ssh-agent through it. Returns the
/// directory and the bound listener; the socket the session's `SSH_AUTH_SOCK`
/// names is [`AGENT_SOCKET`] inside that directory.
///
/// Both are created by the login account itself, so root never chowns or
/// follows a path that account can change. The directory name is random and
/// created exclusively, so nothing can be waiting at the path.
async fn open_agent_socket(info: Arc<LoginInfo>) -> Result<(PathBuf, as_user::Bound)> {
    // `/tmp`, as sshd uses, not `temp_dir()`: on macOS that is the daemon's
    // own per-user directory, which the login account cannot enter.
    let dir =
        PathBuf::from("/tmp").join(format!("rayfish-ssh-agent.{:016x}", rand::random::<u64>()));
    as_user::create_dir(Arc::clone(&info), dir.clone())
        .await
        .context("creating the agent socket directory")?;
    match as_user::listen(Arc::clone(&info), dir.join(AGENT_SOCKET)).await {
        Ok(bound) => Ok((dir, bound)),
        Err(e) => {
            remove_agent_dir(info, dir, None).await;
            Err(e).context("binding the agent socket")
        }
    }
}

/// Remove an agent socket directory and the socket `file` in it, as the login
/// account.
async fn remove_agent_dir(info: Arc<LoginInfo>, dir: PathBuf, file: Option<as_user::SocketFile>) {
    let removed = match file {
        Some(file) => as_user::remove_socket(Arc::clone(&info), dir.join(AGENT_SOCKET), file).await,
        None => Ok(()),
    };
    let removed = match removed {
        Ok(()) => as_user::remove_dir(info, dir.clone()).await,
        Err(e) => Err(e),
    };
    if let Err(e) = removed {
        debug!(dir = %dir.display(), error = %format!("{e:#}"),
            "mesh SSH: cannot remove an agent socket directory");
    }
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

#[cfg(test)]
mod tests;
