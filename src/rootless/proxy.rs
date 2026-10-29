//! Authenticated SOCKS5/HTTP proxies and explicit TCP forwarding. Each listener
//! owns its connection tasks; one semaphore bounds all proxy connections.

use std::fs::{OpenOptions, Permissions};
use std::future::Future;
use std::io::Write;
use std::net::{Ipv6Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, copy_bidirectional,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

use super::stack::Stack;
use super::{Expose, LocalForward, Options, Target};
use crate::daemon::Daemon;
use crate::instance::UserInstance;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 128;

// Deliberately has no Debug implementation, so logging a proxy cannot reveal credentials.
pub(super) struct Password(Vec<u8>);

impl Password {
    #[cfg(test)]
    pub(super) fn for_test(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    fn create(instance: &UserInstance) -> Result<Self> {
        let bytes: [u8; 32] = rand::random();
        let password = hex::encode(bytes);
        let path = instance.directory.join("proxy-password");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(Permissions::from_mode(0o600))?;
        file.write_all(password.as_bytes())?;
        file.sync_all()?;
        tracing::info!(path = %path.display(), username = "ray", "proxy password saved");
        Ok(Self(password.into_bytes()))
    }

    pub(super) fn matches(&self, candidate: &[u8]) -> bool {
        // Always compare the complete fixed-size token, even for a wrong length.
        let mut difference = self.0.len() ^ candidate.len();
        for (index, byte) in self.0.iter().enumerate() {
            difference |= usize::from(*byte ^ candidate.get(index).copied().unwrap_or(0));
        }
        difference == 0
    }
}

pub(crate) struct Proxy {
    socks: TcpListener,
    http: Option<TcpListener>,
    password: Arc<Password>,
    forwards: Vec<BoundForward>,
    expose: Vec<Expose>,
}
struct BoundForward {
    listener: TcpListener,
    target: Target,
}

impl Proxy {
    pub(crate) async fn bind(options: Options, instance: &UserInstance) -> Result<Self> {
        anyhow::ensure!(
            options.forwards.len() <= 16 && options.expose.len() <= 16,
            "at most 16 forwards and 16 exposed ports are supported"
        );
        anyhow::ensure!(
            options.socks5.ip().is_loopback(),
            "SOCKS5 must listen on loopback"
        );
        let socks = TcpListener::bind(options.socks5).await?;
        let http = if let Some(address) = options.http {
            anyhow::ensure!(
                address.ip().is_loopback(),
                "HTTP proxy must listen on loopback"
            );
            Some(TcpListener::bind(address).await?)
        } else {
            None
        };
        let mut forwards = Vec::new();
        for LocalForward { listen, target } in options.forwards {
            forwards.push(BoundForward {
                listener: TcpListener::bind(listen).await?,
                target,
            });
        }
        let password = Arc::new(Password::create(instance)?);
        tracing::info!(address = %socks.local_addr()?, "rootless SOCKS5 listening (authentication required)");
        if let Some(http) = &http {
            tracing::info!(address = %http.local_addr()?, "rootless HTTP proxy listening (authentication required)");
        }
        for forward in &forwards {
            tracing::info!(address = %forward.listener.local_addr()?, target = %forward.target, "local TCP forward listening (accessible to other local users)");
        }
        Ok(Self {
            socks,
            http,
            password,
            forwards,
            expose: options.expose,
        })
    }

    pub(crate) async fn print_instructions(&self, instance: &UserInstance) -> Result<()> {
        let socks = self.socks.local_addr()?;
        let mut text = format!(
            "\nRayfish rootless is ready. Keep this terminal open.\n\n\
             In another terminal (use the same RAYFISH_ROOTLESS_DIR if set):\n\
               ray join <network-key>\n\
               ray status\n\n\
             Proxy username: ray\n\
             Password file: {}\n\
             Read this file for the password when curl prompts.\n\n\
             SOCKS5 proxy: socks5h://{socks}\n\
               curl --proxy socks5h://{socks} --proxy-user ray http://peer.network.ray/\n",
            instance.directory.join("proxy-password").display()
        );
        if let Some(http) = &self.http {
            let http = http.local_addr()?;
            text.push_str(&format!(
                "\nHTTP proxy: http://{http} (HTTPS uses CONNECT)\n\
                   curl --proxy http://{http} --proxy-user ray http://peer.network.ray/\n"
            ));
        } else {
            text.push_str("\nTo enable HTTP/HTTPS proxying, restart with --http 127.0.0.1:0.\n");
        }
        text.push_str(
            "\nOnly applications using a proxy or TCP forward use the mesh.\n\
             Commands automatically use this instance while it is running.\n\
             Use ray --system status for the system daemon, or --rootless to select this instance explicitly.\n\
             Stop with Ctrl-C or ray stop.\n\n"
        );
        let mut stdout = tokio::io::stdout();
        stdout.write_all(text.as_bytes()).await?;
        stdout.flush().await?;
        Ok(())
    }

    pub(crate) fn ports(&self) -> Vec<u16> {
        self.expose.iter().map(|e| e.port.get()).collect()
    }

    pub(crate) async fn run(
        self,
        daemon: Arc<Daemon>,
        stack: Stack,
        listeners: Vec<super::stack::BoundListener>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = JoinSet::new();
        tasks.spawn(serve_local(
            self.socks,
            Protocol::Socks(Arc::clone(&self.password)),
            Arc::clone(&daemon),
            stack.clone(),
            Arc::clone(&slots),
        ));
        if let Some(http) = self.http {
            tasks.spawn(serve_local(
                http,
                Protocol::Http(self.password),
                Arc::clone(&daemon),
                stack.clone(),
                Arc::clone(&slots),
            ));
        }
        for forward in self.forwards {
            tasks.spawn(serve_local(
                forward.listener,
                Protocol::Forward(forward.target),
                Arc::clone(&daemon),
                stack.clone(),
                Arc::clone(&slots),
            ));
        }
        for listener in listeners {
            let target = self
                .expose
                .iter()
                .find(|e| e.port.get() == listener.port)
                .context("missing exposed port configuration")?
                .target;
            tasks.spawn(serve_inbound(listener.accepted, target, Arc::clone(&slots)));
        }
        let result = tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            result = tasks.join_next() => match result {
                Some(result) => result.context("rootless listener panicked")?,
                None => anyhow::bail!("rootless proxy has no listeners"),
            },
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}

#[derive(Clone)]
enum Protocol {
    Socks(Arc<Password>),
    Http(Arc<Password>),
    Forward(Target),
}

async fn serve_local(
    listener: TcpListener,
    protocol: Protocol,
    daemon: Arc<Daemon>,
    stack: Stack,
    slots: Arc<Semaphore>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => log_connection(result),
            accepted = listener.accept() => {
                let (mut client, _) = accepted?;
                let permit = match Arc::clone(&slots).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let protocol = protocol.clone();
                let daemon = Arc::clone(&daemon);
                let stack = stack.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    anyhow::ensure!(daemon.rootless_active(), "rootless data plane is on standby");
                    let mut remote = match protocol {
                        Protocol::Socks(password) => socks_connect(&mut client, &password, move |target: Target| async move {
                            stack.connect(target.resolve(&daemon).await?).await
                        }).await?,
                        Protocol::Forward(target) => stack.connect(target.resolve(&daemon).await?).await?,
                        Protocol::Http(password) => {
                            return super::http::serve(client, password, move |target: Target| {
                                let daemon = Arc::clone(&daemon);
                                let stack = stack.clone();
                                async move {
                                    anyhow::ensure!(daemon.rootless_active(), "rootless data plane is on standby");
                                    stack.connect(target.resolve(&daemon).await?).await
                                }
                            }).await;
                        }
                    };
                    copy_bidirectional(&mut client, &mut remote).await?;
                    Ok(())
                });
            }
        }
    }
}

async fn serve_inbound(
    mut accepted: mpsc::Receiver<DuplexStream>,
    target: SocketAddr,
    slots: Arc<Semaphore>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => log_connection(result),
            stream = accepted.recv() => {
                let mut stream = stream.context("userspace listener stopped")?;
                let permit = match Arc::clone(&slots).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut local = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(target)).await??;
                    copy_bidirectional(&mut stream, &mut local).await?;
                    Ok(())
                });
            }
        }
    }
}

fn log_connection(result: Option<Result<Result<()>, JoinError>>) {
    match result {
        Some(Ok(Err(error))) => tracing::debug!(%error, "rootless proxy connection ended"),
        Some(Err(error)) => tracing::error!(%error, "rootless proxy connection task failed"),
        _ => {}
    }
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    password: &Password,
) -> Result<()> {
    anyhow::ensure!(stream.read_u8().await? == 5, "expected SOCKS5");
    let count = stream.read_u8().await?;
    let mut methods = vec![0; usize::from(count)];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        stream.write_all(&[5, 255]).await?;
        anyhow::bail!("SOCKS5 username/password authentication is required");
    }
    stream.write_all(&[5, 2]).await?;
    anyhow::ensure!(
        stream.read_u8().await? == 1,
        "invalid SOCKS5 authentication version"
    );
    let length = stream.read_u8().await?;
    let mut username = vec![0; usize::from(length)];
    stream.read_exact(&mut username).await?;
    let length = stream.read_u8().await?;
    let mut candidate = vec![0; usize::from(length)];
    stream.read_exact(&mut candidate).await?;
    let valid = password.matches(&candidate) && username == b"ray";
    stream.write_all(&[1, u8::from(!valid)]).await?;
    anyhow::ensure!(valid, "SOCKS5 authentication failed");
    Ok(())
}

async fn socks_connect<S, D, F, R>(stream: &mut S, password: &Password, dial: D) -> Result<R>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: FnOnce(Target) -> F,
    F: Future<Output = Result<R>>,
{
    let target = tokio::time::timeout(HANDSHAKE_TIMEOUT, socks_target(stream, password))
        .await
        .context("SOCKS5 handshake timed out")??;
    let result = tokio::time::timeout(CONNECT_TIMEOUT, dial(target))
        .await
        .context("SOCKS5 mesh connection timed out")
        .flatten();
    match result {
        Ok(remote) => {
            reply(stream, 0).await?;
            Ok(remote)
        }
        Err(error) => {
            reply(stream, 4).await?;
            Err(error)
        }
    }
}

async fn socks_target<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    password: &Password,
) -> Result<Target> {
    authenticate(stream, password).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] != 1 || header[2] != 0 {
        reply(stream, 7).await?;
        anyhow::bail!("only SOCKS5 CONNECT is supported");
    }
    let target = match header[3] {
        4 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            Target::ipv6(Ipv6Addr::from(octets), stream.read_u16().await?)
        }
        3 => {
            let length = stream.read_u8().await?;
            let mut name = vec![0; usize::from(length)];
            stream.read_exact(&mut name).await?;
            let port = stream.read_u16().await?;
            std::str::from_utf8(&name)
                .context("invalid SOCKS5 hostname")
                .and_then(|name| format!("{name}:{port}").parse())
        }
        _ => {
            reply(stream, 8).await?;
            anyhow::bail!("SOCKS5 requires a mesh hostname or IPv6 address");
        }
    };
    match target {
        Ok(target) => Ok(target),
        Err(error) => {
            reply(stream, 8).await?;
            Err(error)
        }
    }
}

async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> Result<()> {
    // An IPv6 unspecified bind address, as the stream has no host socket address.
    let mut response = [0; 22];
    response[0] = 5;
    response[1] = code;
    response[3] = 4;
    stream.write_all(&response).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::duplex;

    async fn authenticate_client(client: &mut DuplexStream) {
        client.write_all(&[5, 1, 2]).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0x0502);
        client.write_all(b"\x01\x03ray\x08password").await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0x0100);
    }

    #[tokio::test(start_paused = true)]
    async fn socks_destination_timeout_returns_a_failure_reply() {
        let (mut client, mut server) = duplex(1024);
        let proxy = tokio::spawn(async move {
            socks_connect(&mut server, &Password(b"password".to_vec()), |target| {
                assert_eq!(target.to_string(), "[200::1]:443");
                pending::<Result<()>>()
            })
            .await
        });
        authenticate_client(&mut client).await;
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(&"200::1".parse::<Ipv6Addr>().unwrap().octets());
        request.extend_from_slice(&443u16.to_be_bytes());
        let started = tokio::time::Instant::now();
        client.write_all(&request).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0x0504);
        assert_eq!(started.elapsed(), CONNECT_TIMEOUT);
        assert!(proxy.await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_socks_authentication_keeps_the_handshake_deadline() {
        let (mut client, mut server) = duplex(1024);
        let proxy = tokio::spawn(async move {
            socks_connect(&mut server, &Password(b"password".to_vec()), |_| {
                pending::<Result<()>>()
            })
            .await
        });
        let started = tokio::time::Instant::now();
        client.write_all(&[5, 1, 2]).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0x0502);
        let mut remaining = Vec::new();
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT + Duration::from_secs(1),
            client.read_to_end(&mut remaining),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(remaining.is_empty());
        assert_eq!(started.elapsed(), HANDSHAKE_TIMEOUT);
        assert!(proxy.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn invalid_socks_targets_return_a_failure_before_dialling() {
        let mut zero_port = vec![5, 1, 0, 4];
        zero_port.extend_from_slice(&"200::1".parse::<Ipv6Addr>().unwrap().octets());
        zero_port.extend_from_slice(&0u16.to_be_bytes());
        let mut invalid_host = b"\x05\x01\x00\x03\x08bad/host".to_vec();
        invalid_host.extend_from_slice(&443u16.to_be_bytes());
        for request in [zero_port, invalid_host] {
            let (mut client, mut server) = duplex(1024);
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&attempts);
            let proxy = tokio::spawn(async move {
                socks_connect(&mut server, &Password(b"password".to_vec()), move |_| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                })
                .await
            });
            authenticate_client(&mut client).await;
            client.write_all(&request).await.unwrap();
            assert_eq!(client.read_u16().await.unwrap(), 0x0508);
            assert!(proxy.await.unwrap().is_err());
            assert_eq!(attempts.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn explicit_inbound_mapping_streams_to_a_loopback_service() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let target = listener.local_addr().unwrap();
            let service = tokio::spawn(async move {
                let (mut client, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                client.read_to_end(&mut request).await.unwrap();
                client.write_all(&request).await.unwrap();
            });
            let (accepted, receiver) = mpsc::channel(1);
            let bridge = tokio::spawn(serve_inbound(receiver, target, Arc::new(Semaphore::new(1))));
            let (mut remote, local) = duplex(1024);
            accepted.send(local).await.unwrap();
            remote.write_all(b"mesh service request").await.unwrap();
            remote.shutdown().await.unwrap();
            let mut response = Vec::new();
            remote.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"mesh service request");
            service.await.unwrap();
            drop(accepted);
            assert!(bridge.await.unwrap().is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn proxy_requires_authentication_even_on_loopback() {
        let (mut client, mut server) = duplex(1024);
        let task = tokio::spawn(async move {
            authenticate(&mut server, &Password(b"test-password".to_vec())).await
        });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 255]);
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn proxy_authentication_accepts_only_matching_credentials() {
        for (candidate, expected) in [(b"correct".as_slice(), true), (b"wrong".as_slice(), false)] {
            let (mut client, mut server) = duplex(1024);
            let task = tokio::spawn(async move {
                authenticate(&mut server, &Password(b"correct".to_vec())).await
            });
            client.write_all(&[5, 1, 2]).await.unwrap();
            assert_eq!(client.read_u16().await.unwrap(), 0x0502);
            client
                .write_all(&[
                    1,
                    3,
                    b'r',
                    b'a',
                    b'y',
                    u8::try_from(candidate.len()).unwrap(),
                ])
                .await
                .unwrap();
            client.write_all(candidate).await.unwrap();
            assert_eq!(
                client.read_u16().await.unwrap(),
                u16::from(!expected) | 0x0100
            );
            assert_eq!(task.await.unwrap().is_ok(), expected);
        }
    }
}
