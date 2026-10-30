use std::future::Future;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ray_proto::ipc::{self, IpcMessage, MsgpackCodec};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::{Builder, Runtime};
use tokio::time::{Instant, sleep, timeout};
use tokio_util::codec::Framed;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_GRACE: Duration = Duration::from_secs(3);

pub(super) struct Client {
    runtime: Runtime,
}

impl Client {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            runtime: Builder::new_current_thread()
                .enable_all()
                .build()
                .context("starting the daemon IPC client")?,
        })
    }

    pub(super) fn read(&self, request: IpcMessage, cancelled: &AtomicBool) -> Result<IpcMessage> {
        self.request(request, cancelled, READ_TIMEOUT)
    }

    pub(super) fn run(&self, request: IpcMessage, cancelled: &AtomicBool) -> Result<String> {
        if cancelled.load(Ordering::Acquire) {
            bail!("The operation was cancelled.");
        }
        #[cfg(windows)]
        {
            if matches!(&request, IpcMessage::Down) && crate::service::is_stopped()? {
                return Ok("Already disconnected.".into());
            }
            if matches!(&request, IpcMessage::Up { .. }) {
                crate::service::ensure_running()?;
            }
        }
        let request = with_download_directory(request, || {
            dirs::download_dir().or_else(|| dirs::home_dir().map(|home| home.join("Downloads")))
        })?;
        let duration = if matches!(request, IpcMessage::Down) {
            DISCONNECT_TIMEOUT
        } else {
            COMMAND_TIMEOUT
        };
        render(self.request(request, cancelled, duration)?)
    }

    fn request(
        &self,
        request: IpcMessage,
        cancelled: &AtomicBool,
        duration: Duration,
    ) -> Result<IpcMessage> {
        self.runtime.block_on(async {
            checked_request(
                async {
                    // connect() verifies that the Windows pipe belongs to LocalSystem.
                    let mut connection = if matches!(
                        &request,
                        IpcMessage::Status | IpcMessage::Up { .. } | IpcMessage::Down
                    ) {
                        connect_ready(ipc::connect).await?
                    } else {
                        ipc::connect().await?
                    };
                    exchange(&mut connection, request).await
                },
                cancelled,
                duration,
            )
            .await
        })
    }
}

fn with_download_directory(
    request: IpcMessage,
    download_directory: impl FnOnce() -> Option<PathBuf>,
) -> Result<IpcMessage> {
    match request {
        IpcMessage::AcceptFile { id, output: None } => {
            let directory =
                download_directory().context("Could not find your Downloads folder.")?;
            Ok(IpcMessage::AcceptFile {
                id,
                output: Some(directory.to_string_lossy().into_owned()),
            })
        }
        request => Ok(request),
    }
}

async fn connect_ready<T, F, Connection>(mut connect: F) -> Result<T>
where
    F: FnMut() -> Connection,
    Connection: Future<Output = Result<T>>,
{
    let deadline = Instant::now() + STARTUP_GRACE;
    loop {
        match connect().await {
            Err(error) if missing_service(&error) && Instant::now() < deadline => {
                sleep(Duration::from_millis(50)).await;
            }
            result => return result,
        }
    }
}

fn missing_service(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<IoError>()
            .is_some_and(|error| error.kind() == ErrorKind::NotFound)
    })
}

async fn checked_request(
    request: impl Future<Output = Result<IpcMessage>>,
    cancelled: &AtomicBool,
    duration: Duration,
) -> Result<IpcMessage> {
    if cancelled.load(Ordering::Acquire) {
        bail!("The operation was cancelled.");
    }
    tokio::select! {
        biased;
        _ = cancellation(cancelled) => bail!("The operation was cancelled."),
        response = timeout(duration, request) => response.context("The Rayfish service did not respond in time.")?,
    }
}

async fn cancellation(cancelled: &AtomicBool) {
    while !cancelled.load(Ordering::Acquire) {
        sleep(Duration::from_millis(25)).await;
    }
}

async fn exchange<S>(
    connection: &mut Framed<S, MsgpackCodec<IpcMessage>>,
    request: IpcMessage,
) -> Result<IpcMessage>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ipc::send(connection, request)
        .await
        .context("sending the request to the Rayfish service")?;
    match ipc::recv(connection)
        .await
        .context("reading the Rayfish service response")?
    {
        IpcMessage::Error { message } => bail!("{message}"),
        response => Ok(response),
    }
}

fn render(response: IpcMessage) -> Result<String> {
    match response {
        IpcMessage::Ok { message } => Ok(message),
        IpcMessage::Created { name, my_ipv6, .. } => {
            Ok(format!("Created {name}.\nAddress: {my_ipv6}"))
        }
        IpcMessage::Joined { name, my_ipv6 } => Ok(format!("Joined {name}.\nAddress: {my_ipv6}")),
        IpcMessage::InviteCreated { code, .. } => Ok(code),
        IpcMessage::FirewallPendingResponse { network, rules } => {
            let mut lines = vec![format!("Suggested firewall rules for {network}")];
            if rules.is_empty() {
                lines.push("No rules waiting for review.".into());
            }
            for rule in rules {
                lines.push(format!(
                    "{} {} {} {}, peer {}, network {}",
                    rule.direction, rule.action, rule.protocol, rule.port, rule.peer, rule.network
                ));
            }
            Ok(lines.join("\n"))
        }
        IpcMessage::FileList {
            files,
            outbox,
            transfers,
        } => {
            let mut lines = Vec::new();
            for file in files {
                lines.push(format!(
                    "Waiting: {} from {} ({} bytes)",
                    file.filename, file.from, file.size
                ));
            }
            for file in outbox {
                lines.push(format!(
                    "Queued: {} to {} ({} bytes)",
                    file.filename, file.peer, file.size
                ));
            }
            for transfer in transfers {
                lines.push(format!(
                    "{}: {} / {} bytes",
                    transfer.filename, transfer.transferred, transfer.size
                ));
            }
            if lines.is_empty() {
                lines.push("No file transfers.".into());
            }
            Ok(lines.join("\n"))
        }
        IpcMessage::Error { message } => bail!("{message}"),
        // Do not format an arbitrary reply with Debug: it may contain credentials.
        _ => bail!("The Rayfish service returned an unexpected response for this operation."),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use ray_proto::ipc::{InactiveNetwork, SshAllowView};
    use tokio::io::duplex;

    use crate::model::{SshRule, SshState, Status};

    use super::*;

    #[test]
    fn accepted_files_use_the_callers_downloads_directory_and_preserve_explicit_output() {
        let request = with_download_directory(
            IpcMessage::AcceptFile {
                id: 1,
                output: None,
            },
            || Some(PathBuf::from("/path/to/downloads")),
        )
        .unwrap();
        assert!(
            matches!(request, IpcMessage::AcceptFile { id: 1, output: Some(path) } if path == "/path/to/downloads")
        );
        let request = with_download_directory(
            IpcMessage::AcceptFile {
                id: 2,
                output: Some("/path/to/output".into()),
            },
            || panic!("An explicit output must not resolve another directory."),
        )
        .unwrap();
        assert!(
            matches!(request, IpcMessage::AcceptFile { id: 2, output: Some(path) } if path == "/path/to/output")
        );
        let missing = with_download_directory(
            IpcMessage::AcceptFile {
                id: 3,
                output: None,
            },
            || None,
        )
        .unwrap_err();
        assert!(missing.to_string().contains("Downloads folder"));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Requires installed test MSI service"]
    fn installed_service_smoke() {
        let client = Client::new().unwrap();
        let cancelled = AtomicBool::new(false);
        assert!(
            crate::service::is_stopped().unwrap(),
            "The installer smoke test starts with a stopped service."
        );
        {
            use super::super::{Work, Worker};
            use std::path::PathBuf;
            use std::sync::mpsc::sync_channel;

            let (ready, completion) = sync_channel(1);
            let mut worker =
                Worker::start(PathBuf::from("unused-ray.exe"), PathBuf::new(), move || {
                    ready.send(()).unwrap()
                })
                .unwrap();
            worker.interrupt(Work::Quit).unwrap();
            completion.recv_timeout(Duration::from_secs(15)).unwrap();
            let update = worker.take_update().unwrap().unwrap();
            assert!(
                update.quit,
                "Quit must succeed when SCM proves the service is stopped."
            );
            assert!(
                crate::service::is_stopped().unwrap(),
                "Quit must leave the stopped service stopped."
            );
        }
        crate::service::ensure_running().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "The installed service did not become ready within one minute."
            );
            match client.request(IpcMessage::Status, &cancelled, remaining.min(READ_TIMEOUT)) {
                Ok(response) => {
                    Status::from_response(response).unwrap();
                    break;
                }
                Err(error)
                    if missing_service(&error)
                        || error
                            .downcast_ref::<tokio::time::error::Elapsed>()
                            .is_some() =>
                {
                    assert!(
                        Instant::now() < deadline,
                        "The installed service did not become ready: {error:#}"
                    );
                }
                Err(error) => panic!("The installed service refused direct IPC: {error:#}"),
            }
        }
        let service_pid = crate::service::process_id().unwrap();
        assert!(
            service_pid != 0,
            "The ready service has no running process."
        );
        client.run(IpcMessage::Down, &cancelled).unwrap();
        let standby =
            Status::from_response(client.read(IpcMessage::Status, &cancelled).unwrap()).unwrap();
        assert!(
            !standby.active,
            "The installed service did not enter standby before Up."
        );
        assert!(
            crate::service::process_id().unwrap() == service_pid,
            "The service restarted while entering standby."
        );
        client
            .run(IpcMessage::Up { hostname: None }, &cancelled)
            .unwrap();
        let active =
            Status::from_response(client.read(IpcMessage::Status, &cancelled).unwrap()).unwrap();
        assert!(
            active.active,
            "Up did not activate the installed VPN service."
        );
        assert!(
            crate::service::process_id().unwrap() == service_pid,
            "The service restarted while activating the VPN."
        );
        client.run(IpcMessage::Down, &cancelled).unwrap();
        let inactive =
            Status::from_response(client.read(IpcMessage::Status, &cancelled).unwrap()).unwrap();
        assert!(
            !inactive.active,
            "Down did not put the installed VPN service on standby."
        );
        assert!(
            crate::service::process_id().unwrap() == service_pid,
            "The service restarted while disconnecting the VPN."
        );
        let refreshed =
            Status::from_response(client.read(IpcMessage::Status, &cancelled).unwrap()).unwrap();
        assert!(
            !refreshed.active,
            "A read-only status request reactivated the VPN."
        );
        assert!(
            crate::service::process_id().unwrap() == service_pid,
            "The service restarted after a read-only status request."
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_networks_arrive_as_shared_types_without_cli_json() {
        let mut snapshot = crate::preview::fixture(true);
        let network = snapshot.status.networks.remove(0);
        let endpoint_id = network.peers[0].endpoint_id;
        let mut saved = network.clone();
        saved.name = "saved-example".into();
        let response = IpcMessage::StatusResponse {
            endpoint_id,
            mdns_enabled: true,
            auto_update: true,
            active: true,
            identity: None,
            daemon_version: "0.0.0".into(),
            networks: vec![network],
            packets_rx: 0,
            packets_tx: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            pending_files: 0,
            pending_connects: 0,
            connection_errors: Vec::new(),
            pending_networks: vec!["waiting-example".into()],
            inactive_networks: vec![InactiveNetwork {
                name: saved.name.clone(),
                reason: None,
                saved: Some(saved),
            }],
            lan_peers: Vec::new(),
        };
        let (client, server) = duplex(8192);
        let daemon = async move {
            let mut connection = ipc::framed(server);
            assert!(matches!(
                ipc::recv(&mut connection).await.unwrap(),
                IpcMessage::Status
            ));
            ipc::send(&mut connection, response).await.unwrap();
        };
        let request = async move { exchange(&mut ipc::framed(client), IpcMessage::Status).await };
        let (response, ()) = tokio::join!(request, daemon);
        let status = Status::from_response(response.unwrap()).unwrap();
        assert_eq!(status.networks.len(), 1);
        assert_eq!(status.networks[0].name, "example");
        assert_eq!(status.networks[0].peers.len(), 6);
        assert_eq!(status.inactive_networks[0].name, "saved-example");
        assert_eq!(
            status.inactive_networks[0]
                .saved
                .as_ref()
                .unwrap()
                .peers
                .len(),
            6
        );
        assert_eq!(status.pending_networks, ["waiting-example"]);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn startup_retries_only_absent_pipe_connections_before_sending_a_request() {
        let attempts = AtomicUsize::new(0);
        let result = connect_ready(|| async {
            match attempts.fetch_add(1, Ordering::Relaxed) {
                0 => Err(IoError::from(ErrorKind::NotFound))
                    .context("The service pipe is not ready."),
                _ => Ok(()),
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn startup_does_not_retry_permission_or_owner_verification_failures() {
        let attempts = AtomicUsize::new(0);
        let denied = connect_ready(|| async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>(IoError::from(ErrorKind::PermissionDenied))
                .context("Cannot open the service pipe.")
        })
        .await;
        assert!(denied.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        let owner = connect_ready(|| async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>(anyhow::anyhow!("The pipe owner is not LocalSystem."))
        })
        .await;
        assert!(owner.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn startup_missing_pipe_retries_have_a_deadline() {
        let started = Instant::now();
        let absent = connect_ready(|| async {
            Err::<(), _>(IoError::from(ErrorKind::NotFound)).context("The service pipe is absent.")
        })
        .await;
        assert!(absent.unwrap_err().to_string().contains("absent"));
        assert!(started.elapsed() >= STARTUP_GRACE);
        assert!(started.elapsed() < STARTUP_GRACE + Duration::from_millis(100));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_requests_use_the_shared_msgpack_protocol_and_preserve_daemon_errors() {
        let (client, server) = duplex(4096);
        let daemon = async move {
            let mut connection = ipc::framed(server);
            assert!(matches!(
                ipc::recv(&mut connection).await.unwrap(),
                IpcMessage::Down
            ));
            ipc::send(
                &mut connection,
                IpcMessage::Error {
                    message: "Example disconnect refused.".into(),
                },
            )
            .await
            .unwrap();
        };
        let request = async move { exchange(&mut ipc::framed(client), IpcMessage::Down).await };
        let (result, ()) = tokio::join!(request, daemon);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Example disconnect refused."
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ssh_settings_read_uses_typed_ipc_and_preserves_rule_scope() {
        let (client, server) = duplex(4096);
        let daemon = async move {
            let mut connection = ipc::framed(server);
            assert!(matches!(
                ipc::recv(&mut connection).await.unwrap(),
                IpcMessage::FirewallSshShow
            ));
            ipc::send(
                &mut connection,
                IpcMessage::FirewallSshState {
                    enabled: true,
                    port: u16::MAX,
                    networks: vec![(
                        "example".into(),
                        vec![SshAllowView {
                            peer: "example-peer".into(),
                            users: vec!["example-user".into()],
                        }],
                    )],
                },
            )
            .await
            .unwrap();
        };
        let request =
            async move { exchange(&mut ipc::framed(client), IpcMessage::FirewallSshShow).await };
        let (response, ()) = tokio::join!(request, daemon);
        assert_eq!(
            SshState::from_response(response.unwrap()).unwrap(),
            SshState {
                enabled: true,
                port: u16::MAX,
                rules: vec![SshRule {
                    network: "example".into(),
                    peer: "example-peer".into(),
                    users: vec!["example-user".into()],
                }],
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_drops_an_inflight_ipc_request() {
        let (client, server) = duplex(4096);
        let cancelled = AtomicBool::new(false);
        let daemon = async {
            let mut connection = ipc::framed(server);
            assert!(matches!(
                ipc::recv(&mut connection).await.unwrap(),
                IpcMessage::Status
            ));
            cancelled.store(true, Ordering::Release);
            assert!(ipc::recv(&mut connection).await.is_err());
        };
        let request = async {
            let mut connection = ipc::framed(client);
            checked_request(
                exchange(&mut connection, IpcMessage::Status),
                &cancelled,
                Duration::from_secs(5),
            )
            .await
        };
        let (result, ()) = tokio::join!(request, daemon);
        assert!(result.unwrap_err().to_string().contains("cancelled"));
    }

    #[test]
    fn invite_result_is_the_code_without_cli_output_parsing() {
        assert_eq!(
            render(IpcMessage::InviteCreated {
                code: "example-invite".into(),
                id: "example".into(),
                expires_secs: 60
            })
            .unwrap(),
            "example-invite"
        );
    }

    #[test]
    fn unexpected_replies_do_not_print_credential_fields() {
        let error = render(IpcMessage::PairingTicket {
            ticket: "example-secret".into(),
        })
        .unwrap_err();
        assert!(!format!("{error:#}").contains("example-secret"));
    }
}
