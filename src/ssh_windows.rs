//! Embedded SSH over authenticated mesh addresses on Windows.
//!
//! Peer grants are shared with Unix. Windows sessions obtain their own account
//! token and run outside the service identity; local self-connections are refused
//! because a mesh address alone cannot identify a local Windows socket owner.

#[path = "ssh/authz.rs"]
mod authz;
#[path = "ssh_windows/host_firewall.rs"]
mod host_firewall;
#[path = "ssh/key_store.rs"]
mod key_store;
#[path = "ssh_windows/limits.rs"]
mod limits;
#[path = "ssh_windows/login.rs"]
mod login;
#[path = "ssh_windows/process.rs"]
mod process;
#[path = "ssh/protocol.rs"]
mod protocol;
#[path = "ssh/slots.rs"]
mod slots;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream as StdTcpStream};
use std::os::windows::io::AsSocket;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use russh::server::{Auth, ChannelOpenHandle, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty, Sig};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, warn};

use crate::daemon::NetworkRegistry;
use authz::{UserPolicy, resolve_user_policy_with_hostnames};
use limits::{SessionTasks, SshLimits};
use login::{LoginInfo, resolve_login};
use process::{SessionSpec, TerminalSize, run_session};
use protocol::server_config;

pub(crate) use crate::forward::SSH_LISTEN_PORT;
pub use authz::{SshAuthz, new_authz};

const MAX_CONNECTIONS: usize = 128;
const MAX_CONNECTIONS_PER_SOURCE: usize = 16;
const MAX_CHANNELS: usize = 32;
const MAX_FORWARDED: usize = 64;
const MAX_LOGONS: usize = 8;
const LOGIN_GRACE: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SshServer {
    registry: Arc<NetworkRegistry>,
    authz: SshAuthz,
}

impl SshServer {
    pub(crate) fn new(registry: Arc<NetworkRegistry>, authz: SshAuthz) -> Self {
        Self { registry, authz }
    }

    pub fn spawn(self, addrs: Vec<IpAddr>, cancel: CancellationToken) {
        tokio::spawn(async move {
            if let Err(error) = self.run(addrs, cancel).await {
                warn!(%error, "Windows mesh SSH server stopped");
            }
        });
    }

    async fn run(self, addrs: Vec<IpAddr>, cancel: CancellationToken) -> Result<()> {
        host_firewall::ensure_listener_access(&addrs).await?;
        let key = tokio::task::spawn_blocking(key_store::load_or_generate_host_key)
            .await
            .context("joining SSH host key loader")??;
        let config = Arc::new(server_config(key));
        let slots = Arc::new(slots::ConnectionSlots::new(
            MAX_CONNECTIONS,
            MAX_CONNECTIONS_PER_SOURCE,
        ));
        let limits = SshLimits::default();
        let bound = addrs
            .into_iter()
            .map(|addr| {
                crate::listener::bind_listener(addr, SSH_LISTEN_PORT)
                    .context("binding Windows mesh SSH listener")
            })
            .collect::<Result<Vec<_>>>()?;
        let mut listeners = JoinSet::new();
        for listener in bound {
            let context = ConnectionContext {
                config: Arc::clone(&config),
                registry: Arc::clone(&self.registry),
                authz: Arc::clone(&self.authz),
                slots: Arc::clone(&slots),
                limits: limits.clone(),
                cancel: cancel.child_token(),
            };
            listeners.spawn(accept_connections(listener, context));
        }
        while let Some(result) = listeners.join_next().await {
            if let Err(error) = result {
                warn!(%error, "Windows SSH listener task failed");
                cancel.cancel();
            }
        }
        Ok(())
    }
}

struct ConnectionContext {
    config: Arc<Config>,
    registry: Arc<NetworkRegistry>,
    authz: SshAuthz,
    slots: Arc<slots::ConnectionSlots>,
    limits: SshLimits,
    cancel: CancellationToken,
}

async fn accept_connections(listener: TcpListener, context: ConnectionContext) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = context.cancel.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed { warn!(%error, "Windows SSH connection task failed"); }
            }
            accepted = listener.accept() => {
                let (stream, source) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => { warn!(%error, "Windows SSH accept failed"); break; }
                };
                let Some(total) = context.slots.admit() else { continue };
                let IpAddr::V6(ip) = source.ip() else { continue };
                if ip == context.registry.transport.identity.local_ipv6() { continue; }
                let Some(peer) = context.registry.peers.identity_for_ip(&ip) else { continue };
                let networks = context.registry.authorization_networks(peer);
                if networks.is_empty() { continue; }
                let Some(slot) = context.slots.claim(slots::Source::Peer(peer)) else { continue };
                let user = context.registry.device_user_map.resolve(&peer);
                let resolve = |network: &str, hostname: &str| {
                    context.registry.resolve_peer_in_network(network, hostname)
                        .map(|id| context.registry.device_user_map.resolve(&id))
                };
                let policy = resolve_user_policy_with_hostnames(&context.authz, &user, &networks, &resolve);
                let config = Arc::clone(&context.config);
                let handler = SshHandler::new(policy, user, context.limits.clone(), context.cancel.child_token());
                connections.spawn(async move {
                    let (_total, _source) = (total, slot);
                    if let Err(error) = serve(config, stream, handler).await {
                        debug!(%error, "Windows SSH connection ended");
                    }
                });
            }
        }
    }
    context.cancel.cancel();
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            warn!(%error, "joining Windows SSH connection");
        }
    }
}

async fn serve(config: Arc<Config>, stream: TcpStream, mut handler: SshHandler) -> Result<()> {
    let cancel = handler.cancel.clone();
    // A completed protocol drops its handler and cancels channel work. Keep
    // owner cancellation separate so that drop cannot race the protocol result.
    handler.cancel = cancel.child_token();
    let tasks = handler.tasks.clone();
    let result = serve_protocol(config, stream, handler, cancel.clone()).await;
    cancel.cancel();
    tasks.close();
    tasks.wait().await;
    result
}

async fn serve_protocol(
    config: Arc<Config>,
    stream: TcpStream,
    handler: SshHandler,
    cancel: CancellationToken,
) -> Result<()> {
    stream.set_nodelay(true).context("configuring SSH socket")?;
    let hangup = StdTcpStream::from(
        stream
            .as_socket()
            .try_clone_to_owned()
            .context("duplicating SSH socket")?,
    );
    let authenticated = Arc::clone(&handler.authenticated);
    let deadline = Instant::now() + LOGIN_GRACE;
    let mut running = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = timeout_at(deadline, russh::server::run_stream(config, stream, handler)) => result.context("SSH version deadline")??,
    };
    tokio::select! {
        result = &mut running => return protocol_result(result, authenticated.load(Ordering::Acquire)),
        _ = cancel.cancelled() => {},
        _ = tokio::time::sleep_until(deadline) => {
            if authenticated.load(Ordering::Acquire) {
                tokio::select! {
                    result = &mut running => return protocol_result(result, authenticated.load(Ordering::Acquire)),
                    _ = cancel.cancelled() => {},
                }
            }
        }
    }
    cancel.cancel();
    // Shutdown wakes russh's owned protocol task, which drops the handler and
    // cancels every session and forward. The duplicate is never used for I/O.
    let shutdown = hangup.shutdown(Shutdown::Both);
    if let Err(error) = &shutdown
        && error.kind() != ErrorKind::NotConnected
    {
        warn!(%error, "SSH socket shutdown failed");
    }
    if let Err(error) = running.await {
        debug!(%error, "SSH protocol stopped after cancellation");
    }
    match shutdown {
        Err(error) if error.kind() != ErrorKind::NotConnected => {
            Err(error).context("closing SSH socket")
        }
        _ => Ok(()),
    }
}

fn protocol_result(result: Result<(), russh::Error>, authenticated: bool) -> Result<()> {
    // Clients close after none-auth rejection when no methods remain. Russh
    // reports that expected unauthenticated close as an I/O EOF.
    if !authenticated
        && matches!(&result, Err(russh::Error::IO(error)) if error.kind() == ErrorKind::UnexpectedEof)
    {
        return Ok(());
    }
    result.context("running SSH protocol")
}

struct ChannelState {
    channel: Option<Channel<Msg>>,
    terminal: Option<TerminalSize>,
    resize: watch::Sender<TerminalSize>,
    env: Vec<(String, String)>,
    cancel: CancellationToken,
}

struct SshHandler {
    policy: Arc<UserPolicy>,
    peer: EndpointId,
    login: Option<Arc<LoginInfo>>,
    channels: HashMap<ChannelId, ChannelState>,
    forwards: HashMap<(String, u32), CancellationToken>,
    forwarded: Arc<Semaphore>,
    logons: Arc<Semaphore>,
    sessions: SessionTasks,
    cancel: CancellationToken,
    authenticated: Arc<AtomicBool>,
    tasks: TaskTracker,
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl SshHandler {
    fn new(
        policy: UserPolicy,
        peer: EndpointId,
        limits: SshLimits,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            peer,
            logons: limits.logons,
            sessions: SessionTasks::new(limits.sessions, MAX_CHANNELS),
            cancel,
            login: None,
            channels: HashMap::new(),
            forwards: HashMap::new(),
            forwarded: Arc::new(Semaphore::new(MAX_FORWARDED)),
            authenticated: Arc::new(AtomicBool::new(false)),
            tasks: TaskTracker::new(),
        }
    }

    fn reap(&mut self) {
        self.channels
            .retain(|_, state| !state.cancel.is_cancelled());
    }

    fn start(
        &mut self,
        id: ChannelId,
        command: Option<String>,
        program: Option<PathBuf>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(login) = self.login.clone() else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let Some(state) = self.channels.get_mut(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let started = self.sessions.spawn(&self.tasks, || {
            let channel = state.channel.take()?;
            let spec = SessionSpec {
                login,
                command,
                program,
                terminal: state.terminal,
                env: std::mem::take(&mut state.env),
            };
            let resize = state.resize.subscribe();
            let cancel = state.cancel.clone();
            let handle = session.handle();
            Some(async move {
                let status = match run_session(channel, spec, resize, cancel.clone()).await {
                    Ok(status) => status,
                    Err(error) => {
                        warn!(error = %format!("{error:#}"), "Windows SSH shell failed");
                        if let Err(error) = handle
                            .extended_data(
                                id,
                                1,
                                b"Windows could not start the requested session.\r\n".as_slice(),
                            )
                            .await
                        {
                            debug!(?error, "reporting SSH session failure");
                        }
                        1
                    }
                };
                cancel.cancel();
                if let Err(error) = handle.exit_status_request(id, status).await {
                    debug!(?error, "reporting SSH process exit");
                }
                if let Err(error) = handle.eof(id).await {
                    debug!(?error, "ending SSH session output");
                }
                if let Err(error) = handle.close(id).await {
                    debug!(?error, "closing SSH session");
                }
            })
        });
        if started {
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(authz::auth_banner(&self.policy, &self.peer, &[]))
    }

    async fn auth_none(&mut self, name: &str) -> Result<Auth, Self::Error> {
        if !self.policy.authorized() || name.encode_utf16().count() > 256 || name.contains('\0') {
            return Ok(Auth::reject());
        }
        let Ok(permit) = Arc::clone(&self.logons).try_acquire_owned() else {
            return Ok(Auth::reject());
        };
        let name = name.to_owned();
        let policy = Arc::clone(&self.policy);
        let resolved = tokio::task::spawn_blocking(move || -> Result<Option<LoginInfo>> {
            let _permit = permit;
            let mut login = resolve_login(&name)?;
            let privileged = login.is_privileged()?;
            let allowed = policy.permits_account(privileged, |account| {
                match login.matches_account(account) {
                    Ok(matches) => matches,
                    Err(error) => {
                        debug!(%error, "Windows SSH grant does not resolve to an account");
                        false
                    }
                }
            });
            if !allowed {
                return Ok(None);
            }
            login.prepare_profile()?;
            Ok(Some(login))
        })
        .await;
        match resolved {
            Ok(Ok(Some(login))) => {
                self.login = Some(Arc::new(login));
                self.authenticated.store(true, Ordering::Release);
                return Ok(Auth::Accept);
            }
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                debug!(error = %format!("{error:#}"), peer = %self.peer.fmt_short(), "Windows SSH account logon rejected")
            }
            Err(error) => warn!(%error, "Windows SSH account task failed"),
        }
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reap();
        if self.login.is_none() || self.channels.len() >= MAX_CHANNELS {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }
        let (resize, _) = watch::channel(TerminalSize { cols: 80, rows: 24 });
        self.channels.insert(
            channel.id(),
            ChannelState {
                channel: Some(channel),
                terminal: None,
                resize,
                env: Vec::new(),
                cancel: self.cancel.child_token(),
            },
        );
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        id: ChannelId,
        _term: &str,
        cols: u32,
        rows: u32,
        _px: u32,
        _py: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = terminal_size(cols, rows);
        if let (Some(state), Some(size)) = (self.channels.get_mut(&id), size)
            && state.channel.is_some()
        {
            state.terminal = Some(size);
            state.resize.send_replace(size);
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        cols: u32,
        rows: u32,
        _px: u32,
        _py: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let (Some(state), Some(size)) = (self.channels.get(&id), terminal_size(cols, rows))
            && state.terminal.is_some()
        {
            state.resize.send_replace(size);
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Locale only. PATH, COMSPEC, PSModulePath and profile variables must
        // come from the target account, never from a connecting peer.
        if (name == "LANG" || name.starts_with("LC_"))
            && name.len() <= 64
            && value.len() <= 1024
            && !name.contains('\0')
            && !value.contains('\0')
            && let Some(state) = self.channels.get_mut(&id)
            && state.channel.is_some()
            && state.env.len() < 16
        {
            state.env.push((name.to_owned(), value.to_owned()));
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(id, None, None, session)
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Ok(command) = std::str::from_utf8(data)
            && command.len() <= 32_000
            && !command.contains('\0')
        {
            self.start(id, Some(command.to_owned()), None, session)
        } else {
            session.channel_failure(id)?;
            Ok(())
        }
    }

    async fn channel_close(
        &mut self,
        id: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.remove(&id) {
            state.cancel.cancel();
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        id: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(signal, Sig::KILL | Sig::TERM | Sig::HUP)
            && let Some(state) = self.channels.get(&id)
        {
            state.cancel.cancel();
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.login.is_none() || host.len() > 253 || host.contains('\0') {
            return Ok(());
        }
        let Ok(port) = u16::try_from(port) else {
            return Ok(());
        };
        let Ok(slot) = Arc::clone(&self.forwarded).try_acquire_owned() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        let host = host.to_owned();
        let cancel = self.cancel.child_token();
        let handle = session.handle();
        self.tasks.spawn(async move {
            let _slot = slot;
            let upstream = tokio::select! {
                _ = cancel.cancelled() => return,
                result = timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port))) => match result {
                    Ok(Ok(stream)) => stream,
                    _ => { reply.reject(ChannelOpenFailure::ConnectFailed).await; return; }
                }
            };
            reply.accept().await;
            forward_channel(channel, handle, upstream, cancel).await;
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.reap();
        self.forwards.retain(|_, cancel| !cancel.is_cancelled());
        let Some(login) = &self.login else {
            return Ok(false);
        };
        if self.forwards.len() >= 32 || address.len() > 253 {
            return Ok(false);
        }
        let Ok(requested) = u16::try_from(*port) else {
            return Ok(false);
        };
        if requested > 0 && requested < 1024 && !login.is_privileged().unwrap_or(false) {
            return Ok(false);
        }
        let ip = if address == "::1" {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let listener = match TcpListener::bind(SocketAddr::new(ip, requested)).await {
            Ok(listener) => listener,
            Err(error) => {
                debug!(%error, "binding Windows SSH reverse forward");
                return Ok(false);
            }
        };
        let bound = listener.local_addr().map_err(russh::Error::from)?.port();
        *port = u32::from(bound);
        let key = (address.to_owned(), *port);
        let cancel = self.cancel.child_token();
        if let Some(previous) = self.forwards.insert(key, cancel.clone()) {
            previous.cancel();
        }
        let tasks = self.tasks.clone();
        let slots = Arc::clone(&self.forwarded);
        let handle = session.handle();
        let address = address.to_owned();
        self.tasks.spawn(async move {
            loop {
                let (stream, origin) = tokio::select! {
                    _ = cancel.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(value) => value,
                        Err(error) => { debug!(%error, "Windows SSH reverse accept failed"); break; }
                    }
                };
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else { continue };
                let handle = handle.clone();
                let address = address.clone();
                let cancel = cancel.child_token();
                tasks.spawn(async move {
                    let _slot = slot;
                    let channel = tokio::select! {
                        _ = cancel.cancelled() => return,
                        result = timeout(CONNECT_TIMEOUT, handle.channel_open_forwarded_tcpip(address, u32::from(bound), origin.ip().to_string(), u32::from(origin.port()))) => match result {
                            Ok(Ok(channel)) => channel,
                            _ => return,
                        }
                    };
                    forward_channel(channel, handle, stream, cancel).await;
                });
            }
        });
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if let Some(cancel) = self.forwards.remove(&(address.to_owned(), port)) {
            cancel.cancel();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp"
            && self
                .channels
                .get(&id)
                .is_some_and(|state| state.terminal.is_none())
        {
            match login::sftp_server() {
                Ok(Some(program)) => return self.start(id, None, Some(program), session),
                Ok(None) => debug!("Windows OpenSSH SFTP helper is not installed"),
                Err(error) => warn!(%error, "finding Windows SFTP helper"),
            }
        }
        session.channel_failure(id)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn x11_request(
        &mut self,
        id: ChannelId,
        _single: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }
}

async fn forward_channel(
    channel: Channel<Msg>,
    handle: russh::server::Handle,
    mut socket: TcpStream,
    cancel: CancellationToken,
) {
    let id = channel.id();
    if let Err(error) = socket.set_nodelay(true) {
        debug!(%error, "configuring SSH forward socket");
    }
    let mut channel = channel.into_stream();
    tokio::select! {
        _ = cancel.cancelled() => return,
        result = copy_bidirectional(&mut channel, &mut socket) => {
            if let Err(error) = result { debug!(%error, "Windows SSH forward closed"); }
        }
    }
    if let Err(error) = handle.eof(id).await {
        debug!(?error, "ending SSH forward output");
    }
    if let Err(error) = handle.close(id).await {
        debug!(?error, "closing SSH forward");
    }
}

fn terminal_size(cols: u32, rows: u32) -> Option<TerminalSize> {
    let cols = u16::try_from(cols)
        .ok()
        .filter(|size| *size > 0 && *size <= i16::MAX as u16)?;
    let rows = u16::try_from(rows)
        .ok()
        .filter(|size| *size > 0 && *size <= i16::MAX as u16)?;
    Some(TerminalSize { cols, rows })
}

#[cfg(test)]
async fn serve_test_connection(
    stream: TcpStream,
    allowed_user: &str,
    authorized: bool,
    cancel: CancellationToken,
) -> Result<()> {
    use russh::keys::{Algorithm, PrivateKey};
    use std::sync::Once;
    static LOGGING: Once = Once::new();
    LOGGING.call_once(|| {
        // Other tests may have installed the process logger already.
        if tracing_subscriber::fmt()
            .with_env_filter("rayfish::ssh=debug")
            .with_test_writer()
            .try_init()
            .is_err()
        {
            debug!("SSH test logging is already configured");
        }
    });
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("generating test host key")?;
    let mut policy = UserPolicy::default();
    if authorized {
        policy.add(&[allowed_user.to_owned()]);
    }
    let peer = iroh::SecretKey::from([7; 32]).public();
    let handler = SshHandler::new(policy, peer, SshLimits::default(), cancel);
    serve(Arc::new(server_config(key)), stream, handler).await
}

#[cfg(test)]
#[path = "ssh_windows/tests.rs"]
mod tests;
