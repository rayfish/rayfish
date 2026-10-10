//! Host TCP services for the macOS app, outside NetworkExtension's socket policy.
//!
//! launchd owns a root-only Unix socket and starts the bundled CLI helper. The
//! packet tunnel supplies its mesh address and authorizes SSH connections using
//! its live peer registry. Bridged IPv4 connections pass its mesh firewall before
//! reaching the helper. No authorization snapshot is cached here.
//! Both ends check the Unix peer UID. The helper owns every TCP socket and login
//! process; EOF on the control stream closes listeners and sessions. This is a
//! private, versioned local protocol, not mesh or CLI IPC.

#[cfg(target_os = "macos")]
use std::ffi::{c_char, c_int};
use std::future::Future;
#[cfg(target_os = "macos")]
use std::net::IpAddr;
use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpStream as StdTcpStream};
use std::os::fd::AsFd;
#[cfg(target_os = "macos")]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(target_os = "macos")]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixListener as StdUnixListener;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use iroh::EndpointId;
use russh::keys::PrivateKey;
#[cfg(target_os = "macos")]
use russh::keys::ssh_key::LineEnding;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(target_os = "macos")]
use tokio::net::UnixListener;
use tokio::net::{TcpListener, UnixStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

use super::{
    Config, LOGIN_GRACE, Origin, SSH_LISTEN_PORT, SshHandler, UserPolicy, disable_nagle, local,
    serve, server_config,
};
#[cfg(target_os = "macos")]
use super::{SshAuthz, auth_banner, load_host_key, resolve_user_policy_with_hostnames};
#[cfg(target_os = "macos")]
use crate::daemon::NetworkRegistry;

#[cfg(target_os = "macos")]
const SOCKET: &str = "/var/run/com.rayfish.app.ssh.sock";
const VERSION: u32 = 4;
const MAX_FRAME: usize = 64 * 1024;
const MAX_SESSIONS: usize = 128;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct Hello {
    version: u32,
    address: Ipv6Addr,
    service: Service,
}

#[derive(Serialize, Deserialize)]
enum Service {
    // Sent only after authenticating the root helper. Discovery stays in the
    // provider to preserve its app-group fallback key, without touching the
    // standalone daemon's state. Never include this message in diagnostics.
    Ssh { host_key: Vec<u8>, mesh_port: u16 },
    V4Bridge { ssh_port: u16 },
}

#[derive(Serialize, Deserialize)]
struct Ready {
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct Authorize {
    client: SocketAddr,
    local_uid: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct Grant {
    user: EndpointId,
    policy: UserPolicy,
    banner: Option<String>,
    mesh_port: u16,
}

async fn send<T: Serialize>(writer: &mut (impl AsyncWrite + Unpin), value: &T) -> Result<()> {
    let bytes = rmp_serde::to_vec_named(value)?;
    ensure!(bytes.len() <= MAX_FRAME, "SSH helper frame too large");
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    Ok(())
}

async fn receive<T: DeserializeOwned>(reader: &mut (impl AsyncRead + Unpin)) -> Result<T> {
    let len = reader.read_u32().await? as usize;
    ensure!(len <= MAX_FRAME, "SSH helper frame too large");
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    Ok(rmp_serde::from_slice(&bytes)?)
}

fn require_root_peer(stream: &UnixStream) -> Result<()> {
    ensure!(
        stream.peer_cred()?.uid() == 0,
        "SSH helper requires a root peer"
    );
    Ok(())
}

fn validate_hello(hello: &Hello) -> Result<()> {
    ensure!(
        hello.version == VERSION,
        "SSH helper version mismatch; restart Rayfish"
    );
    ensure!(
        hello.address.segments()[0] & 0xfe00 == 0x0200,
        "SSH helper requires a mesh address"
    );
    Ok(())
}

/// Called only for an OS-owned macOS tunnel. The daemon keeps its own listener.
#[cfg(target_os = "macos")]
pub(crate) fn spawn(
    address: Ipv6Addr,
    registry: Arc<NetworkRegistry>,
    authz: SshAuthz,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        retry_service(token, || async {
            let result = authorize_connections(address, &registry, &authz).await;
            crate::forward::set_ssh_nat_active(false);
            if let Err(error) = result {
                tracing::warn!(%error, "macOS SSH helper unavailable; enable Rayfish in Login Items & Extensions");
            }
        })
        .await;
    });
}

async fn retry_service<F, Fut>(token: CancellationToken, mut attempt: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => return,
            _ = attempt() => {}
        }
        tokio::select! {
            biased;
            _ = token.cancelled() => return,
            _ = sleep(CONTROL_TIMEOUT) => {}
        }
    }
}

#[cfg(target_os = "macos")]
async fn authorize_connections(
    address: Ipv6Addr,
    registry: &NetworkRegistry,
    authz: &SshAuthz,
) -> Result<()> {
    let mut control = connect_service(
        address,
        Service::Ssh {
            host_key: load_host_key()?
                .to_openssh(LineEnding::LF)?
                .as_bytes()
                .to_vec(),
            mesh_port: crate::forward::ssh_port(),
        },
    )
    .await?;
    crate::forward::set_ssh_nat_active(true);
    tracing::info!(%address, "macOS app SSH helper ready");
    loop {
        let request: Authorize = receive(&mut control).await?;
        let grant = grant_for(request, address, registry, authz);
        timeout(CONTROL_TIMEOUT, send(&mut control, &grant)).await??;
    }
}

#[cfg(target_os = "macos")]
async fn connect_service(address: Ipv6Addr, service: Service) -> Result<UnixStream> {
    timeout(CONTROL_TIMEOUT, async {
        let meta = tokio::fs::symlink_metadata(SOCKET).await?;
        ensure!(
            meta.file_type().is_socket() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
            "SSH helper socket must be root-owned and private"
        );
        let mut stream = UnixStream::connect(SOCKET).await?;
        require_root_peer(&stream)?;
        send(
            &mut stream,
            &Hello {
                version: VERSION,
                address,
                service,
            },
        )
        .await?;
        let ready: Ready = receive(&mut stream).await?;
        ensure!(ready.version == VERSION, "SSH helper version mismatch");
        Ok::<_, anyhow::Error>(stream)
    })
    .await?
}

/// Keep the bridge in the helper while the external tunnel is attached.
#[cfg(target_os = "macos")]
pub(crate) fn spawn_v4_bridge(address: Ipv6Addr, token: CancellationToken) {
    tokio::spawn(async move {
        retry_service(token, || async {
            if let Err(error) = bridge_connections(address).await {
                tracing::warn!(%error, "macOS IPv4 bridge helper unavailable; enable Rayfish in Login Items & Extensions");
            }
        })
        .await;
    });
}

#[cfg(target_os = "macos")]
async fn bridge_connections(address: Ipv6Addr) -> Result<()> {
    let ssh_port = crate::config::load()?.ssh_port;
    let mut control = connect_service(address, Service::V4Bridge { ssh_port }).await?;
    tracing::info!("macOS app IPv4 bridge helper ready");
    let mut byte = [0];
    ensure!(
        control.read(&mut byte).await? == 0,
        "IPv4 bridge helper sent unexpected data"
    );
    bail!("IPv4 bridge helper control connection closed")
}

#[cfg(target_os = "macos")]
fn grant_for(
    request: Authorize,
    local: Ipv6Addr,
    registry: &NetworkRegistry,
    authz: &SshAuthz,
) -> Option<Grant> {
    let client = request.client;
    let IpAddr::V6(source) = client.ip() else {
        return None;
    };
    if source == local {
        return Some(Grant {
            user: registry.transport.identity.local_identity(),
            policy: UserPolicy::local(request.local_uid?),
            banner: None,
            mesh_port: crate::forward::ssh_port(),
        });
    }
    let peer = registry.peers.identity_for_ip(&source)?;
    let user = registry.device_user_map.resolve(&peer);
    let networks = registry.authorization_networks(peer);
    let resolve = |network: &str, hostname: &str| {
        registry
            .resolve_peer_in_network(network, hostname)
            .map(|id| registry.device_user_map.resolve(&id))
    };
    let policy = resolve_user_policy_with_hostnames(authz, &user, &networks, &resolve);
    let banner = auth_banner(&policy, &user, &networks);
    tracing::debug!(%client, peer = %user.fmt_short(), authorized = policy.authorized(),
        "macOS app SSH authorization");
    Some(Grant {
        user,
        policy,
        banner,
        mesh_port: crate::forward::ssh_port(),
    })
}

/// Entry point for the app's hidden CLI command, launched by SMAppService.
#[cfg(target_os = "macos")]
pub async fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "SSH helper must run as root through launchd"
    );
    let listener = activated_listener()?;
    let mut services = JoinSet::new();
    loop {
        let (control, _) = tokio::select! {
            result = services.join_next(), if !services.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(%error, "macOS app helper service failed");
                }
                // Let launchd start the current bundled helper on reconnect.
                if services.is_empty() {
                    return Ok(());
                }
                continue;
            }
            accepted = listener.accept(), if services.len() < 2 => accepted?,
        };
        if let Err(error) = require_root_peer(&control) {
            tracing::warn!(%error, "SSH helper refused control connection");
            continue;
        }
        services.spawn(async move {
            if let Err(error) = serve_control(control).await {
                tracing::warn!(%error, "macOS app helper service stopped");
            }
        });
    }
}

async fn serve_control(mut control: UnixStream) -> Result<()> {
    let hello: Hello = timeout(CONTROL_TIMEOUT, receive(&mut control)).await??;
    validate_hello(&hello)?;
    match hello.service {
        Service::Ssh {
            host_key,
            mesh_port,
        } => {
            // Identity-authorized sessions must not share a listener.
            let tcp = TcpListener::bind((hello.address, SSH_LISTEN_PORT)).await?;
            let config = Arc::new(server_config(PrivateKey::from_openssh(&host_key)?));
            let local_listener = match local::bind_retry(hello.address, mesh_port).await {
                Ok(listener) => Some(listener),
                Err(error) => {
                    tracing::warn!(%error, "mesh SSH: cannot bind self-SSH port; a host sshd may already own it");
                    None
                }
            };
            run_listener(control, tcp, local_listener, config).await
        }
        Service::V4Bridge { ssh_port } => {
            let token = CancellationToken::new();
            let _cancel = token.clone().drop_guard();
            crate::v4bridge::V4Bridge::new(hello.address)
                .with_ssh_port(ssh_port)
                .spawn(token);
            send(&mut control, &Ready { version: VERSION }).await?;
            let mut byte = [0];
            ensure!(
                control.read(&mut byte).await? == 0,
                "IPv4 bridge control sent unexpected data"
            );
            Ok(())
        }
    }
}

// A cloned socket is only a shutdown handle; the SSH session owns all I/O.
struct Hangup(StdTcpStream);

impl Drop for Hangup {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

async fn run_listener(
    mut control: UnixStream,
    listener: TcpListener,
    local_listener: Option<TcpListener>,
    config: Arc<Config>,
) -> Result<()> {
    timeout(
        CONTROL_TIMEOUT,
        send(&mut control, &Ready { version: VERSION }),
    )
    .await??;
    let mut sessions = JoinSet::new();
    loop {
        let mut unexpected = [0];
        let (stream, client) = tokio::select! {
            biased;
            // Outside a request/reply exchange, any input is EOF or a protocol
            // violation. Dropping the JoinSet also drops every Hangup guard.
            read = control.read(&mut unexpected) => {
                read?;
                bail!("SSH helper control connection closed or sent unexpected data");
            }
            _ = sessions.join_next(), if !sessions.is_empty() => continue,
            accepted = local::accept(&listener, local_listener.as_ref()), if sessions.len() < MAX_SESSIONS => accepted?,
        };
        let server = stream.local_addr()?;
        let local_uid = local::uid(client, server).await;
        let grant: Option<Grant> = timeout(CONTROL_TIMEOUT, async {
            send(&mut control, &Authorize { client, local_uid }).await?;
            receive(&mut control).await
        })
        .await??;
        let Some(grant) = grant else { continue };
        disable_nagle(&stream);
        let server = SocketAddr::new(stream.local_addr()?.ip(), grant.mesh_port);
        let hangup = Hangup(StdTcpStream::from(stream.as_fd().try_clone_to_owned()?));
        let handler = SshHandler::new(
            grant.policy,
            grant.user,
            grant.banner,
            Origin { client, server },
        );
        let config = Arc::clone(&config);
        sessions.spawn(async move {
            let _hangup = hangup;
            serve(config, stream, handler, LOGIN_GRACE).await;
        });
    }
}

#[cfg(target_os = "macos")]
fn activated_listener() -> Result<UnixListener> {
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const c_char,
            fds: *mut *mut c_int,
            count: *mut usize,
        ) -> c_int;
    }
    let mut fds = std::ptr::null_mut();
    let mut count = 0;
    let result = unsafe { launch_activate_socket(c"Control".as_ptr(), &mut fds, &mut count) };
    ensure!(
        result == 0,
        "SSH helper requires its launchd Control socket (error {result})"
    );
    if fds.is_null() || count == 0 {
        unsafe { libc::free(fds.cast()) };
        bail!("launchd supplied no SSH helper Control socket");
    }
    // launch_activate_socket transfers the descriptors and a malloc'd array.
    let sockets: Vec<OwnedFd> = unsafe {
        let sockets = std::slice::from_raw_parts(fds, count)
            .iter()
            .map(|fd| OwnedFd::from_raw_fd(*fd))
            .collect();
        libc::free(fds.cast());
        sockets
    };
    ensure!(sockets.len() == 1, "expected one SSH helper Control socket");
    let socket = StdUnixListener::from(
        sockets
            .into_iter()
            .next()
            .context("missing Control socket")?,
    );
    socket.set_nonblocking(true)?;
    Ok(UnixListener::from_std(socket)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client;
    use russh::keys::{Algorithm, PublicKey};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::Instant;

    struct AcceptTestKey;

    impl client::Handler for AcceptTestKey {
        type Error = russh::Error;

        async fn check_server_key(&mut self, _: &PublicKey) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn test_config() -> Result<Arc<Config>> {
        Ok(Arc::new(server_config(PrivateKey::random(
            &mut rand::rng(),
            Algorithm::Ed25519,
        )?)))
    }

    #[tokio::test]
    async fn retry_waits_before_reconnecting_and_cancellation_closes_control() -> Result<()> {
        let (control, mut peer) = UnixStream::pair()?;
        let (started, mut attempts) = unbounded_channel();
        let token = CancellationToken::new();
        let cancel = token.clone();
        let task = tokio::spawn(async move {
            let mut control = Some(control);
            let mut first = true;
            retry_service(token, || {
                let stream = if first {
                    first = false;
                    None
                } else {
                    control.take()
                };
                let started = started.clone();
                async move {
                    started
                        .send(Instant::now())
                        .expect("the test receives attempts");
                    if let Some(mut stream) = stream {
                        let mut byte = [0];
                        assert_eq!(
                            stream
                                .read(&mut byte)
                                .await
                                .expect("read the control socket"),
                            0
                        );
                    }
                }
            })
            .await;
        });
        let first_attempt = timeout(CONTROL_TIMEOUT, attempts.recv())
            .await?
            .context("the first attempt must start")?;
        let retry = timeout(CONTROL_TIMEOUT * 2, attempts.recv())
            .await?
            .context("the retry must start")?;
        // Tokio timers have millisecond precision.
        assert!(retry - first_attempt >= CONTROL_TIMEOUT - Duration::from_millis(1));
        cancel.cancel();
        timeout(CONTROL_TIMEOUT, task).await??;
        let mut byte = [0];
        assert_eq!(timeout(CONTROL_TIMEOUT, peer.read(&mut byte)).await??, 0);
        assert!(
            attempts.recv().await.is_none(),
            "cancellation stops retries"
        );
        Ok(())
    }

    #[tokio::test]
    async fn retry_cancellation_wins_before_an_attempt_and_during_backoff() -> Result<()> {
        let token = CancellationToken::new();
        token.cancel();
        retry_service(token, || async {
            panic!("a cancelled service must not run")
        })
        .await;

        let token = CancellationToken::new();
        let cancel = token.clone();
        let (started, mut attempts) = unbounded_channel();
        let task = tokio::spawn(async move {
            retry_service(token, || async {
                started.send(()).expect("the test receives attempts");
            })
            .await;
        });
        timeout(CONTROL_TIMEOUT, attempts.recv())
            .await?
            .context("the first attempt must start")?;
        cancel.cancel();
        timeout(CONTROL_TIMEOUT / 2, task).await??;
        assert!(
            attempts.recv().await.is_none(),
            "backoff must not reconnect"
        );
        Ok(())
    }

    #[test]
    fn refuses_non_mesh_addresses_and_other_versions() -> Result<()> {
        for address in [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            "fe80::1".parse()?,
        ] {
            assert!(
                validate_hello(&Hello {
                    version: VERSION,
                    address,
                    service: Service::Ssh {
                        host_key: Vec::new(),
                        mesh_port: 22,
                    },
                })
                .is_err()
            );
        }
        let address = "290::1".parse()?;
        assert!(
            validate_hello(&Hello {
                version: VERSION,
                address,
                service: Service::Ssh {
                    host_key: Vec::new(),
                    mesh_port: 22,
                },
            })
            .is_ok()
        );
        assert!(
            validate_hello(&Hello {
                version: VERSION + 1,
                address,
                service: Service::Ssh {
                    host_key: Vec::new(),
                    mesh_port: 22,
                },
            })
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn refuses_unprivileged_control_peers() -> Result<()> {
        let (control, _other) = UnixStream::pair()?;
        assert_eq!(
            require_root_peer(&control).is_ok(),
            unsafe { libc::geteuid() } == 0
        );
        Ok(())
    }

    #[tokio::test]
    async fn bridge_service_starts_without_ssh_and_stops_on_control_eof() -> Result<()> {
        let (control, mut provider) = UnixStream::pair()?;
        let task = tokio::spawn(serve_control(control));
        send(
            &mut provider,
            &Hello {
                version: VERSION,
                address: "200::beef".parse()?,
                service: Service::V4Bridge { ssh_port: 22 },
            },
        )
        .await?;
        let ready: Ready = timeout(CONTROL_TIMEOUT, receive(&mut provider)).await??;
        assert_eq!(ready.version, VERSION);
        assert!(!task.is_finished());
        drop(provider);
        timeout(CONTROL_TIMEOUT, task).await???;
        Ok(())
    }

    #[tokio::test]
    async fn oversized_control_frame_is_rejected_before_allocating_payload() -> Result<()> {
        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_u32(MAX_FRAME as u32 + 1).await?;
        assert!(
            receive::<Hello>(&mut receiver)
                .await
                .err()
                .context("oversized frame was accepted")?
                .to_string()
                .contains("too large")
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_peer_is_closed_and_control_eof_releases_listener() -> Result<()> {
        let tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let (control, mut provider) = UnixStream::pair()?;
        let task = tokio::spawn(run_listener(control, tcp, None, test_config()?));
        let _: Ready = receive(&mut provider).await?;
        let mut client = TcpStream::connect(address).await?;
        let request: Authorize = receive(&mut provider).await?;
        assert_eq!(request.client, client.local_addr()?);
        send(&mut provider, &None::<Grant>).await?;
        let mut byte = [0];
        assert_eq!(timeout(CONTROL_TIMEOUT, client.read(&mut byte)).await??, 0);
        drop(provider);
        assert!(timeout(CONTROL_TIMEOUT, task).await??.is_err());
        assert!(TcpListener::bind(address).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn control_eof_closes_a_session_waiting_for_ssh_handshake() -> Result<()> {
        let tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let (control, mut provider) = UnixStream::pair()?;
        let task = tokio::spawn(run_listener(control, tcp, None, test_config()?));
        let _: Ready = receive(&mut provider).await?;
        let mut client = TcpStream::connect(address).await?;
        let _: Authorize = receive(&mut provider).await?;
        let mut policy = UserPolicy::default();
        policy.add(&[]);
        send(
            &mut provider,
            &Some(Grant {
                user: iroh::SecretKey::generate().public(),
                policy,
                banner: None,
                mesh_port: 22,
            }),
        )
        .await?;
        let mut banner = [0; 128];
        let n = timeout(CONTROL_TIMEOUT, client.read(&mut banner)).await??;
        assert!(banner[..n].starts_with(b"SSH-2.0-"));
        drop(provider);
        assert!(timeout(CONTROL_TIMEOUT, task).await??.is_err());
        let mut remaining = Vec::new();
        timeout(CONTROL_TIMEOUT, client.read_to_end(&mut remaining)).await??;
        Ok(())
    }

    #[tokio::test]
    async fn helper_enforces_nonroot_policy_received_over_control_socket() -> Result<()> {
        let tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let (control, mut provider) = UnixStream::pair()?;
        let server = tokio::spawn(run_listener(control, tcp, None, test_config()?));
        let _: Ready = receive(&mut provider).await?;
        let client = tokio::spawn(async move {
            let mut connection =
                client::connect(Arc::new(client::Config::default()), address, AcceptTestKey)
                    .await?;
            Ok::<_, anyhow::Error>(connection.authenticate_none("root").await?.success())
        });
        let _: Authorize = receive(&mut provider).await?;
        let mut policy = UserPolicy::default();
        policy.add(&[]);
        send(
            &mut provider,
            &Some(Grant {
                user: iroh::SecretKey::generate().public(),
                policy,
                banner: None,
                mesh_port: 22,
            }),
        )
        .await?;
        assert!(!timeout(CONTROL_TIMEOUT, client).await???);
        drop(provider);
        assert!(timeout(CONTROL_TIMEOUT, server).await??.is_err());
        Ok(())
    }
}
