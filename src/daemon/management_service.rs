//! Enrollment and direct management of machines controlled by this node.

use super::*;
use crate::management::{
    EnrollmentReceipt, EnrollmentSecret, ManagementAction, ManagementMsg, ManagementRequestId,
    ManagementResult, NetworkInvite,
};
use futures::future::join_all;
use iroh::EndpointAddr;
use iroh::endpoint::ConnectOptions;
use ray_proto::ipc::{
    ControllerSelector, EnrollmentCredentialSelector, MachineHostname, ManagedMachineSelector,
    NetworkName, UnixTimestampSecs,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

const MANAGEMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGEMENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MANAGEMENT_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGEMENT_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROLLER_HELLO_INTERVAL: Duration = Duration::from_secs(5 * 60);
const CONTROLLER_HELLO_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(test)]
mod compatibility_tests;
#[cfg(test)]
mod recovery_tests;

impl Daemon {
    /// Inventory for embedders, including machines outside the local networks.
    pub async fn list_managed_machines(&self, probe: bool) -> IpcMessage {
        self.management.list_machines(probe).await
    }
}

fn now() -> UnixTimestampSecs {
    UnixTimestampSecs::from_secs(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

fn enrollment_expiration(created_at: UnixTimestampSecs, expires_in: Duration) -> UnixTimestampSecs {
    created_at.saturating_add(expires_in)
}

/// Negotiate once, offering v1 for peers that have not upgraded. Recovery-only
/// messages check the selected ALPN before sending any application data.
async fn connect_management(
    endpoint: &Endpoint,
    address: EndpointAddr,
) -> anyhow::Result<Connection> {
    let options =
        ConnectOptions::new().with_additional_alpns(vec![crate::management::LEGACY_ALPN.to_vec()]);
    let connecting = endpoint
        .connect_with_opts(address, crate::management::ALPN, options)
        .await?;
    Ok(connecting.await?)
}

fn record_enrollment(
    settings: &mut config::AppConfig,
    machine: EndpointId,
    secret_hash: blake3::Hash,
    hostname: &MachineHostname,
    enrolled_at: UnixTimestampSecs,
) -> anyhow::Result<()> {
    let credential = settings
        .enrollment_credentials
        .iter_mut()
        .find(|credential| credential.secret_hash == secret_hash)
        .ok_or_else(|| anyhow::anyhow!("enrollment credential not found"))?;
    anyhow::ensure!(!credential.revoked, "enrollment credential revoked");
    anyhow::ensure!(
        credential.expires_at > enrolled_at,
        "enrollment credential expired"
    );
    anyhow::ensure!(
        credential.reusable
            || credential.enrolled_machines.is_empty()
            || credential.enrolled_machines.contains(&machine),
        "enrollment credential already used"
    );
    anyhow::ensure!(
        !settings
            .managed_machines
            .iter()
            .any(|entry| { entry.hostname == *hostname && entry.identity != machine }),
        "managed hostname '{hostname}' is already enrolled"
    );
    if !credential.enrolled_machines.contains(&machine) {
        credential.enrolled_machines.push(machine);
    }
    settings.forgotten_machines.retain(|id| *id != machine);
    record_machine(settings, machine, hostname, enrolled_at, enrolled_at)
}

fn record_machine(
    settings: &mut config::AppConfig,
    machine: EndpointId,
    hostname: &MachineHostname,
    enrolled_at: UnixTimestampSecs,
    seen_at: UnixTimestampSecs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !settings
            .managed_machines
            .iter()
            .any(|entry| entry.hostname == *hostname && entry.identity != machine),
        "managed hostname '{hostname}' is already enrolled"
    );
    if let Some(entry) = settings
        .managed_machines
        .iter_mut()
        .find(|entry| entry.identity == machine)
    {
        entry.hostname = hostname.clone();
        entry.last_seen = Some(seen_at);
    } else {
        settings.managed_machines.push(config::ManagedMachine {
            identity: machine,
            hostname: hostname.clone(),
            enrolled_at,
            last_seen: Some(seen_at),
        });
    }
    Ok(())
}

fn record_hello(
    settings: &mut config::AppConfig,
    controller: EndpointId,
    remote: EndpointId,
    receipt: &EnrollmentReceipt,
    hostname: &MachineHostname,
    seen_at: UnixTimestampSecs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        receipt.verify(controller, remote),
        "invalid enrollment receipt"
    );
    anyhow::ensure!(
        !settings.forgotten_machines.contains(&remote),
        "machine was explicitly forgotten; confirm or enroll it again"
    );
    record_machine(settings, remote, hostname, receipt.enrolled_at, seen_at)
}

fn forget_record(settings: &mut config::AppConfig, machine: EndpointId) {
    settings
        .managed_machines
        .retain(|entry| entry.identity != machine);
    if !settings.forgotten_machines.contains(&machine) {
        settings.forgotten_machines.push(machine);
    }
}

/// Confirmation can attach a receipt to an existing grant, never create a grant.
fn confirm_controller_grant(
    settings: &mut config::AppConfig,
    controller: EndpointId,
    machine: EndpointId,
    receipt: EnrollmentReceipt,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        receipt.verify(controller, machine),
        "invalid enrollment receipt"
    );
    let grant = settings
        .controllers
        .iter_mut()
        .find(|grant| grant.identity == controller)
        .ok_or_else(|| anyhow::anyhow!("controller is not authorized"))?;
    grant.receipt = Some(receipt);
    Ok(())
}

/// Handles enrollment, controller authorization, and delegated network actions.
pub(crate) struct ManagementService {
    transport: Arc<Transport>,
    registry: Arc<NetworkRegistry>,
    secret_key: SecretKey,
    /// Serializes controller authorization changes with remote actions. Once a
    /// local revoke returns, no request from that controller is still running.
    controller_gate: AsyncMutex<()>,
    hello_notify: Notify,
    hello_task: Mutex<Option<JoinHandle<()>>>,
}

impl ManagementService {
    /// Creates the management service for the process-wide transport and registry.
    pub(crate) fn new(
        transport: Arc<Transport>,
        registry: Arc<NetworkRegistry>,
        secret_key: SecretKey,
    ) -> Self {
        Self {
            transport,
            registry,
            secret_key,
            controller_gate: AsyncMutex::new(()),
            hello_notify: Notify::new(),
            hello_task: Mutex::new(None),
        }
    }

    /// Start immediately, retry while offline, and repeat to recover a controller
    /// that lost its inventory while the machine remained connected.
    pub(crate) fn start_announcements(self: &Arc<Self>, token: CancellationToken) {
        let service = Arc::clone(self);
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = token.cancelled() => {},
                _ = async {
                    let mut interval = tokio::time::interval(CONTROLLER_HELLO_INTERVAL);
                    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {},
                            _ = service.hello_notify.notified() => {},
                        }
                        if let Err(error) = service.announce_controllers().await {
                            tracing::debug!(%error, "controller announcement failed");
                        }
                    }
                } => {},
            }
        });
        *self.hello_task.lock().unwrap() = Some(task);
    }

    pub(crate) async fn stop_announcements(&self) {
        let task = self.hello_task.lock().unwrap().take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    /// A mesh reconnect is an opportunity to repair inventory immediately. The
    /// timer also covers controllers that share no network with this machine.
    pub(crate) fn connection_established(&self, peer: EndpointId) {
        if config::load().is_ok_and(|settings| {
            settings
                .controllers
                .iter()
                .any(|grant| grant.identity == peer && grant.receipt.is_some())
        }) {
            self.hello_notify.notify_one();
        }
    }

    async fn announce_controllers(&self) -> anyhow::Result<()> {
        let settings = config::load()?;
        if !settings
            .controllers
            .iter()
            .any(|grant| grant.receipt.is_some())
        {
            return Ok(());
        }
        let hostname = self.local_hostname()?;
        // Bound each exchange independently, so one offline controller cannot
        // prevent the others from learning about this machine.
        let machine = self.transport.endpoint.id();
        let receipts = settings.controllers.into_iter().filter_map(|grant| {
            grant
                .receipt
                .filter(|receipt| receipt.verify(grant.identity, machine))
        });
        join_all(receipts
            .map(|receipt| {
                let hostname = hostname.clone();
                async move {
                    let controller = receipt.controller;
                    let outcome = tokio::time::timeout(
                        CONTROLLER_HELLO_TIMEOUT, self.announce_controller(receipt, hostname)
                    ).await;
                    match outcome {
                        Ok(Ok(())) => {},
                        Ok(Err(error)) => tracing::debug!(peer = %controller.fmt_short(), %error, "controller hello failed"),
                        Err(_) => tracing::debug!(peer = %controller.fmt_short(), "controller hello timed out"),
                    }
                }
            })).await;
        Ok(())
    }

    async fn announce_controller(
        &self,
        receipt: EnrollmentReceipt,
        hostname: MachineHostname,
    ) -> anyhow::Result<()> {
        let controller = receipt.controller;
        let connection = self
            .transport
            .endpoint
            .connect(EndpointAddr::from(controller), crate::management::ALPN)
            .await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        {
            // Re-read under the revocation gate: a receipt captured before a
            // local revoke must not be sent afterwards. Release before waiting
            // for the reply so a slow controller does not block other hellos.
            let _guard = self.controller_gate.lock().await;
            let authorized = config::load()?.controllers.iter().any(|grant| {
                grant.identity == controller && grant.receipt.as_ref() == Some(&receipt)
            });
            if !authorized {
                return Ok(());
            }
            control::send_framed(
                &mut send,
                &ManagementMsg::ControllerHello { receipt, hostname },
            )
            .await?;
        }
        let reply = control::recv_framed::<ManagementMsg>(&mut recv).await?;
        connection.close(0u32.into(), b"hello received");
        match reply {
            ManagementMsg::HelloAccepted => Ok(()),
            ManagementMsg::HelloRejected { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("unexpected controller hello response"),
        }
    }

    /// Creates and persists a machine-enrollment credential.
    pub(crate) fn create_enrollment(&self, expires_in: Duration, reusable: bool) -> IpcMessage {
        let secret = EnrollmentSecret::generate();
        let secret_hash = secret.hash();
        let id = ipc::EnrollmentCredentialId::new(secret_hash.to_hex()[..12].to_string());
        let expires_at = enrollment_expiration(now(), expires_in);
        let credential = config::EnrollmentCredential {
            id: id.clone(),
            secret_hash,
            expires_at,
            reusable,
            enrolled_machines: Vec::new(),
            revoked: false,
        };
        if let Err(error) = config::update_settings(|settings| {
            settings.enrollment_credentials.push(credential);
            Ok(())
        }) {
            return ipc_err(format!("failed to save enrollment credential: {error}"));
        }
        IpcMessage::MachineEnrollmentCreated {
            id,
            ticket: ipc::EnrollmentTicket::new(self.transport.endpoint.addr(), secret.to_bytes()),
            expires_at,
            reusable,
        }
    }

    /// Lists enrollment credentials without exposing their secrets.
    pub(crate) fn list_enrollments(&self) -> IpcMessage {
        let now = now();
        match config::load() {
            Ok(settings) => IpcMessage::MachineEnrollments {
                enrollments: settings
                    .enrollment_credentials
                    .into_iter()
                    .map(|credential| ipc::MachineEnrollmentInfo {
                        id: credential.id,
                        expires_at: credential.expires_at,
                        reusable: credential.reusable,
                        uses: credential.enrolled_machines.len() as u64,
                        status: if credential.revoked {
                            ipc::MachineEnrollmentStatus::Revoked
                        } else if credential.expires_at <= now {
                            ipc::MachineEnrollmentStatus::Expired
                        } else if !credential.reusable && !credential.enrolled_machines.is_empty() {
                            ipc::MachineEnrollmentStatus::Used
                        } else {
                            ipc::MachineEnrollmentStatus::Pending
                        },
                    })
                    .collect(),
            },
            Err(error) => ipc_err(format!("failed to load enrollment credentials: {error}")),
        }
    }

    /// Revokes the unique enrollment credential matching `selector`.
    pub(crate) fn revoke_enrollment(&self, selector: &EnrollmentCredentialSelector) -> IpcMessage {
        let result = config::update_settings(|settings| {
            let matches: Vec<usize> = settings
                .enrollment_credentials
                .iter()
                .enumerate()
                .filter(|(_, credential)| credential.id.as_ref().starts_with(selector.as_ref()))
                .map(|(index, _)| index)
                .collect();
            anyhow::ensure!(!matches.is_empty(), "enrollment credential not found");
            anyhow::ensure!(matches.len() == 1, "enrollment credential id is ambiguous");
            settings.enrollment_credentials[matches[0]].revoked = true;
            Ok(())
        });
        match result {
            Ok(_) => IpcMessage::Ok {
                message: format!("revoked enrollment credential '{selector}'"),
            },
            Err(error) => ipc_err(error.to_string()),
        }
    }

    /// Enrolls this machine with the controller named by `ticket`.
    pub(crate) async fn enroll_with_ticket(&self, ticket: &ipc::EnrollmentTicket) -> IpcMessage {
        let controller = ticket.controller().id;
        let secret = EnrollmentSecret::from_bytes(*ticket.secret());
        if controller == self.transport.endpoint.id() {
            return ipc_err("a machine cannot control itself");
        }
        let hostname = match self.local_hostname() {
            Ok(hostname) => hostname,
            Err(error) => return ipc_err(format!("failed to choose machine hostname: {error}")),
        };
        let connection = match tokio::time::timeout(
            MANAGEMENT_CONNECT_TIMEOUT,
            connect_management(&self.transport.endpoint, ticket.controller().clone()),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return ipc_err(format!("failed to reach controller: {error}")),
            Err(_) => return ipc_err("timed out reaching controller"),
        };
        let legacy = connection.alpn() == crate::management::LEGACY_ALPN;
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(error) => return ipc_err(format!("failed to open controller stream: {error}")),
        };
        if let Err(error) = control::send_framed(
            &mut send,
            &ManagementMsg::Enroll {
                secret,
                hostname: hostname.clone(),
            },
        )
        .await
        {
            return ipc_err(format!("failed to send enrollment: {error}"));
        }
        let response = tokio::time::timeout(
            MANAGEMENT_RESPONSE_TIMEOUT,
            control::recv_framed::<ManagementMsg>(&mut recv),
        )
        .await;
        let receipt = match response {
            Err(_) => return ipc_err("timed out waiting for controller enrollment response"),
            Ok(Ok(ManagementMsg::Enrolled)) if legacy => None,
            Ok(Ok(ManagementMsg::EnrolledWithReceipt { receipt })) if !legacy => {
                if !receipt.verify(controller, self.transport.endpoint.id()) {
                    return ipc_err("controller returned an invalid enrollment receipt");
                }
                Some(receipt)
            }
            Ok(Ok(ManagementMsg::EnrollmentRejected { message }))
            | Ok(Ok(ManagementMsg::ProtocolError { message })) => return ipc_err(message),
            Ok(Ok(other)) => return ipc_err(format!("unexpected enrollment response: {other:?}")),
            Ok(Err(error)) => {
                return ipc_err(format!("failed to read enrollment response: {error}"));
            }
        };
        let _guard = self.controller_gate.lock().await;
        let saved = config::update_settings(|settings| {
            if let Some(grant) = settings
                .controllers
                .iter_mut()
                .find(|grant| grant.identity == controller)
            {
                if receipt.is_some() {
                    grant.receipt = receipt.clone();
                }
            } else {
                settings.controllers.push(config::ControllerGrant {
                    identity: controller,
                    enrolled_at: receipt
                        .as_ref()
                        .map_or_else(now, |receipt| receipt.enrolled_at),
                    receipt: receipt.clone(),
                });
            }
            Ok(())
        });
        match saved {
            Ok(_) => {
                self.hello_notify.notify_one();
                IpcMessage::Ok {
                    message: format!(
                        "enrolled '{hostname}' with controller {}",
                        controller.fmt_short()
                    ),
                }
            }
            Err(error) => ipc_err(format!("failed to save controller grant: {error}")),
        }
    }

    fn local_hostname(&self) -> anyhow::Result<MachineHostname> {
        let settings = config::load()?;
        if let Some(hostname) = settings.default_hostname {
            return Ok(hostname.parse()?);
        }
        let hostname =
            crate::hostname::system_hostname().unwrap_or_else(crate::hostname::generate_hostname);
        config::update_settings(|settings| {
            if settings.default_hostname.is_none() {
                settings.default_hostname = Some(hostname.clone());
            }
            Ok(())
        })?;
        Ok(hostname.parse()?)
    }

    /// Lists controllers authorized to manage this machine.
    pub(crate) fn list_controllers(&self) -> IpcMessage {
        match config::load() {
            Ok(settings) => IpcMessage::Controllers {
                controllers: settings
                    .controllers
                    .into_iter()
                    .map(|grant| ipc::ControllerInfo {
                        identity: grant.identity,
                        enrolled_at: grant.enrolled_at,
                    })
                    .collect(),
            },
            Err(error) => ipc_err(format!("failed to load controllers: {error}")),
        }
    }

    /// Revokes one matching controller, or every controller when no selector is given.
    pub(crate) async fn revoke_controller(
        &self,
        identity_prefix: Option<&ControllerSelector>,
    ) -> IpcMessage {
        let _guard = self.controller_gate.lock().await;
        let result = config::update_settings(|settings| {
            if let Some(selector) = identity_prefix {
                let prefix = selector.as_ref();
                let matches: Vec<EndpointId> = settings
                    .controllers
                    .iter()
                    .filter(|grant| {
                        grant.identity.to_string().starts_with(prefix)
                            || grant.identity.fmt_short().to_string().starts_with(prefix)
                    })
                    .map(|grant| grant.identity)
                    .collect();
                anyhow::ensure!(!matches.is_empty(), "controller not found");
                anyhow::ensure!(matches.len() == 1, "controller identity is ambiguous");
                settings
                    .controllers
                    .retain(|grant| grant.identity != matches[0]);
            } else {
                settings.controllers.clear();
            }
            Ok(())
        });
        match result {
            Ok(_) => IpcMessage::Ok {
                message: match identity_prefix {
                    Some(selector) => format!("revoked controller '{selector}'"),
                    None => "revoked all controllers".to_string(),
                },
            },
            Err(error) => ipc_err(error.to_string()),
        }
    }

    /// Lists enrolled machines and optionally probes their current status.
    pub(crate) async fn list_machines(&self, probe: bool) -> IpcMessage {
        let machines = match config::load() {
            Ok(settings) => settings.managed_machines,
            Err(error) => return ipc_err(format!("failed to load managed machines: {error}")),
        };
        if !probe {
            return IpcMessage::ManagedMachinesResponse {
                machines: machines
                    .into_iter()
                    .map(|machine| ipc::ManagedMachineInfo {
                        identity: machine.identity,
                        hostname: machine.hostname,
                        enrolled_at: machine.enrolled_at,
                        last_seen: machine.last_seen,
                        state: ipc::ManagedMachineState::Unknown,
                        networks: Vec::new(),
                    })
                    .collect(),
            };
        }
        let results = join_all(machines.into_iter().map(|machine| async move {
            let status = tokio::time::timeout(
                MANAGEMENT_STATUS_TIMEOUT,
                self.send_request(machine.identity, ManagementAction::Status),
            )
            .await;
            match status {
                Ok(Ok(ManagementResult::Status { networks, .. })) => ipc::ManagedMachineInfo {
                    identity: machine.identity,
                    hostname: machine.hostname,
                    enrolled_at: machine.enrolled_at,
                    last_seen: Some(now()),
                    state: ipc::ManagedMachineState::Online,
                    networks,
                },
                Ok(Ok(ManagementResult::Unauthorized)) => ipc::ManagedMachineInfo {
                    identity: machine.identity,
                    hostname: machine.hostname,
                    enrolled_at: machine.enrolled_at,
                    last_seen: Some(now()),
                    state: ipc::ManagedMachineState::Unauthorized,
                    networks: Vec::new(),
                },
                _ => ipc::ManagedMachineInfo {
                    identity: machine.identity,
                    hostname: machine.hostname,
                    enrolled_at: machine.enrolled_at,
                    last_seen: machine.last_seen,
                    state: ipc::ManagedMachineState::Offline,
                    networks: Vec::new(),
                },
            }
        }))
        .await;
        IpcMessage::ManagedMachinesResponse { machines: results }
    }

    /// Asks an enrolled machine to join a network controlled by this node.
    pub(crate) async fn delegated_join(
        &self,
        machine: &ManagedMachineSelector,
        network: &NetworkName,
        hostname: Option<MachineHostname>,
        auto_accept_firewall: bool,
        auto_accept_files: bool,
    ) -> IpcMessage {
        let target = match self.resolve_machine(machine) {
            Ok(target) => target,
            Err(error) => return ipc_err(error),
        };
        let network = match self.registry.active_network_name(network.as_ref()) {
            Some(name) => NetworkName::new(name),
            None => return ipc_err(format!("network '{network}' not active")),
        };
        let hostname = hostname.unwrap_or_else(|| target.hostname.clone());
        let invite = match self
            .registry
            .invite_create(
                network.as_ref(),
                7 * 24 * 60 * 60,
                Some(hostname.to_string()),
                false,
            )
            .await
        {
            IpcMessage::InviteCreated { code, .. } => code,
            IpcMessage::Error { message } => return ipc_err(message),
            other => return ipc_err(format!("unexpected invite response: {other:?}")),
        };
        match self
            .send_request(
                target.identity,
                ManagementAction::Join {
                    invite: NetworkInvite::new(invite),
                    network_name: network,
                    hostname,
                    auto_accept_firewall,
                    auto_accept_files,
                },
            )
            .await
        {
            Ok(ManagementResult::Applied { message }) => IpcMessage::Ok { message },
            Ok(ManagementResult::Unauthorized) => {
                ipc_err("managed machine has revoked this controller")
            }
            Ok(ManagementResult::Error { message }) => ipc_err(message),
            Ok(other) => ipc_err(format!("unexpected delegated join response: {other:?}")),
            Err(error) => ipc_err(error),
        }
    }

    /// Asks an enrolled machine to leave a network controlled by this node.
    pub(crate) async fn delegated_leave(
        &self,
        machine: &ManagedMachineSelector,
        network: &NetworkName,
    ) -> IpcMessage {
        let target = match self.resolve_machine(machine) {
            Ok(target) => target,
            Err(error) => return ipc_err(error),
        };
        let remote_result = self
            .send_request(
                target.identity,
                ManagementAction::Leave {
                    network_name: network.clone(),
                },
            )
            .await;

        match remote_result {
            Ok(ManagementResult::Applied { message }) => {
                // Make the controller-side roster converge even if the target's
                // best-effort LeaveNetwork notice was lost. Open networks and a
                // roster that already processed the notice may reject the kick;
                // the target's successful local leave is still authoritative.
                let _ = self
                    .registry
                    .kick_member(network.as_ref(), &target.identity.to_string(), true)
                    .await;
                IpcMessage::Ok { message }
            }
            // If the machine cannot be reached, a coordinator can still revoke
            // its network access immediately. Local cleanup will converge when
            // the target next sees the signed roster or accepts a request.
            Err(remote_error)
            | Ok(ManagementResult::Error {
                message: remote_error,
            }) => {
                match self
                    .registry
                    .kick_member(network.as_ref(), &target.identity.to_string(), true)
                    .await
                {
                    IpcMessage::Ok { .. } => IpcMessage::Ok {
                        message: format!(
                            "removed '{}' from '{}'; managed machine cleanup is pending",
                            target.hostname, network
                        ),
                    },
                    IpcMessage::Error {
                        message: kick_error,
                    } => ipc_err(format!(
                        "managed leave failed: {remote_error}; network removal failed: {kick_error}"
                    )),
                    other => ipc_err(format!(
                        "managed leave failed: {remote_error}; unexpected removal response: {other:?}"
                    )),
                }
            }
            Ok(ManagementResult::Unauthorized) => {
                ipc_err("managed machine has revoked this controller")
            }
            Ok(other) => ipc_err(format!("unexpected delegated leave response: {other:?}")),
        }
    }

    /// Removes an enrolled machine from this controller's local inventory.
    pub(crate) fn forget_machine(&self, machine: &ManagedMachineSelector) -> IpcMessage {
        let target = match self.resolve_machine(machine) {
            Ok(target) => target,
            Err(error) => return ipc_err(error),
        };
        match config::update_settings(|settings| {
            forget_record(settings, target.identity);
            Ok(())
        }) {
            Ok(_) => IpcMessage::Ok {
                message: format!("forgot managed machine '{}'", target.hostname),
            },
            Err(error) => ipc_err(format!("failed to forget managed machine: {error}")),
        }
    }

    /// Explicit operator confirmation for legacy grants, including machines whose
    /// controller-side entry was lost. The target must already trust our identity.
    pub(crate) async fn confirm_machine(&self, machine: EndpointId) -> IpcMessage {
        if machine == self.transport.endpoint.id() {
            return ipc_err("a machine cannot control itself");
        }
        let receipt = EnrollmentReceipt::issue(&self.secret_key, machine, now());
        match self
            .send_request(
                machine,
                ManagementAction::ConfirmEnrollment {
                    receipt: receipt.clone(),
                },
            )
            .await
        {
            Ok(ManagementResult::Status { hostname, .. }) => {
                let saved = config::update_settings(|settings| {
                    // A local confirmation is an explicit decision to restore a
                    // forgotten entry, unlike an unsolicited hello.
                    record_machine(settings, machine, &hostname, receipt.enrolled_at, now())?;
                    settings.forgotten_machines.retain(|id| *id != machine);
                    Ok(())
                });
                match saved {
                    Ok(_) => IpcMessage::Ok {
                        message: format!("confirmed '{hostname}'; inventory recovery enabled"),
                    },
                    Err(error) => ipc_err(format!("failed to save confirmed machine: {error}")),
                }
            }
            Ok(ManagementResult::Unauthorized) => {
                ipc_err("machine does not authorize this controller; enroll it with a ticket first")
            }
            Ok(ManagementResult::Error { message }) => ipc_err(message),
            Ok(_) => ipc_err("unexpected confirmation response"),
            Err(error) => ipc_err(error),
        }
    }

    fn resolve_machine(
        &self,
        selector: &ManagedMachineSelector,
    ) -> Result<config::ManagedMachine, String> {
        let name = selector.as_ref();
        let settings = config::load().map_err(|error| error.to_string())?;
        let matches: Vec<_> = settings
            .managed_machines
            .into_iter()
            .filter(|machine| {
                machine.hostname.as_ref() == name
                    || machine.identity.to_string().starts_with(name)
                    || machine.identity.fmt_short().to_string().starts_with(name)
            })
            .collect();
        match matches.len() {
            0 => Err(format!("managed machine '{name}' not found")),
            1 => Ok(matches.into_iter().next().expect("one match exists")),
            _ => Err(format!("managed machine '{name}' is ambiguous")),
        }
    }

    async fn send_request(
        &self,
        target: EndpointId,
        action: ManagementAction,
    ) -> Result<ManagementResult, String> {
        let connection = tokio::time::timeout(
            MANAGEMENT_CONNECT_TIMEOUT,
            connect_management(&self.transport.endpoint, EndpointAddr::from(target)),
        )
        .await
        .map_err(|_| "timed out reaching managed machine".to_string())?
        .map_err(|error| format!("failed to reach managed machine: {error}"))?;
        if connection.alpn() == crate::management::LEGACY_ALPN
            && matches!(action, ManagementAction::ConfirmEnrollment { .. })
        {
            connection.close(0u32.into(), b"management v2 required");
            return Err(
                "inventory recovery requires management v2; upgrade the managed machine first"
                    .to_string(),
            );
        }
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| format!("failed to open management stream: {error}"))?;
        let request_id = ManagementRequestId::generate();
        control::send_framed(&mut send, &ManagementMsg::Request { request_id, action })
            .await
            .map_err(|error| format!("failed to send management request: {error}"))?;
        match tokio::time::timeout(
            MANAGEMENT_RESPONSE_TIMEOUT,
            control::recv_framed::<ManagementMsg>(&mut recv),
        )
        .await
        {
            Ok(Ok(ManagementMsg::Response {
                request_id: response_id,
                result,
            })) if response_id == request_id => {
                let _ = config::update_settings(|settings| {
                    if let Some(machine) = settings
                        .managed_machines
                        .iter_mut()
                        .find(|machine| machine.identity == target)
                    {
                        machine.last_seen = Some(now());
                    }
                    Ok(())
                });
                Ok(result)
            }
            Ok(Ok(other)) => Err(format!("unexpected management response: {other:?}")),
            Ok(Err(error)) => Err(format!("failed to read management response: {error}")),
            Err(_) => Err("timed out waiting for managed machine response".to_string()),
        }
    }

    /// Handles one inbound enrollment or authenticated management request.
    pub(crate) async fn accept_connection(&self, connection: Connection) {
        let remote = connection.remote_id();
        let legacy = connection.alpn() == crate::management::LEGACY_ALPN;
        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
            return;
        };
        let message = match tokio::time::timeout(
            MANAGEMENT_FIRST_FRAME_TIMEOUT,
            control::recv_framed::<ManagementMsg>(&mut recv),
        )
        .await
        {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => {
                tracing::warn!(peer = %remote.fmt_short(), %error, "invalid management request");
                return;
            }
            Err(_) => {
                tracing::warn!(peer = %remote.fmt_short(), "management request timed out");
                return;
            }
        };
        let reply = if legacy && !message.supported_by_v1() {
            ManagementMsg::ProtocolError {
                message: "this operation requires management v2".to_string(),
            }
        } else {
            match message {
                ManagementMsg::Enroll { secret, hostname } => {
                    match self.accept_enrollment(remote, &secret, &hostname) {
                        Ok(_) if legacy => ManagementMsg::Enrolled,
                        Ok(receipt) => ManagementMsg::EnrolledWithReceipt { receipt },
                        Err(message) => ManagementMsg::EnrollmentRejected { message },
                    }
                }
                ManagementMsg::ControllerHello { receipt, hostname } => {
                    match config::update_settings(|settings| {
                        record_hello(
                            settings,
                            self.transport.endpoint.id(),
                            remote,
                            &receipt,
                            &hostname,
                            now(),
                        )
                    }) {
                        Ok(_) => ManagementMsg::HelloAccepted,
                        Err(error) => ManagementMsg::HelloRejected {
                            message: error.to_string(),
                        },
                    }
                }
                ManagementMsg::Request { request_id, action } => {
                    let _guard = self.controller_gate.lock().await;
                    let authorized = config::load().is_ok_and(|settings| {
                        settings
                            .controllers
                            .iter()
                            .any(|grant| grant.identity == remote)
                    });
                    let result = if authorized {
                        self.apply_action(remote, action).await
                    } else {
                        ManagementResult::Unauthorized
                    };
                    ManagementMsg::Response { request_id, result }
                }
                _ => ManagementMsg::ProtocolError {
                    message: "unexpected management message".to_string(),
                },
            }
        };
        if let Err(error) = control::send_framed(&mut send, &reply).await {
            tracing::warn!(peer = %remote.fmt_short(), %error, "failed to send management response");
            return;
        }
        // Keep the connection alive until the caller reads the reply. Returning
        // drops it and can reset the stream before the frame header arrives.
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
    }

    fn accept_enrollment(
        &self,
        machine: EndpointId,
        secret: &EnrollmentSecret,
        hostname: &MachineHostname,
    ) -> Result<EnrollmentReceipt, String> {
        let secret_hash = secret.hash();
        let enrolled_at = now();
        config::update_settings(|settings| {
            record_enrollment(settings, machine, secret_hash, hostname, enrolled_at)
        })
        .map(|settings| {
            let machine = settings
                .managed_machines
                .iter()
                .find(|entry| entry.identity == machine)
                .expect("enrollment recorded the machine");
            EnrollmentReceipt::issue(&self.secret_key, machine.identity, machine.enrolled_at)
        })
        .map_err(|error| error.to_string())
    }

    async fn apply_action(
        &self,
        controller: EndpointId,
        action: ManagementAction,
    ) -> ManagementResult {
        match action {
            ManagementAction::ConfirmEnrollment { receipt } => {
                // The caller holds controller_gate through this write and reply
                // construction, so a concurrent revoke cannot recreate a grant.
                let hostname = match self.local_hostname() {
                    Ok(hostname) => hostname,
                    Err(error) => {
                        return ManagementResult::Error {
                            message: error.to_string(),
                        };
                    }
                };
                match config::update_settings(|settings| {
                    confirm_controller_grant(
                        settings,
                        controller,
                        self.transport.endpoint.id(),
                        receipt,
                    )
                }) {
                    Ok(_) => {
                        self.hello_notify.notify_one();
                        ManagementResult::Status {
                            hostname,
                            networks: self
                                .registry
                                .networks
                                .iter()
                                .map(|entry| NetworkName::new(entry.key().clone()))
                                .collect(),
                        }
                    }
                    Err(error) => ManagementResult::Error {
                        message: error.to_string(),
                    },
                }
            }
            ManagementAction::Status => match self.local_hostname() {
                Ok(hostname) => ManagementResult::Status {
                    hostname,
                    networks: self
                        .registry
                        .networks
                        .iter()
                        .map(|entry| NetworkName::new(entry.key().clone()))
                        .collect(),
                },
                Err(error) => ManagementResult::Error {
                    message: format!("failed to read machine hostname: {error}"),
                },
            },
            ManagementAction::Join {
                invite,
                network_name,
                hostname,
                auto_accept_firewall,
                auto_accept_files,
            } => {
                let (network_key, coordinator, secret) =
                    match crate::invite::decode_invite_code(invite.expose()) {
                        Ok(decoded) => decoded,
                        Err(error) => {
                            return ManagementResult::Error {
                                message: error.to_string(),
                            };
                        }
                    };
                match self
                    .registry
                    .join_network(
                        &network_key.to_string(),
                        Some(network_name.as_ref()),
                        Some(hostname.into()),
                        Some(secret),
                        Some(coordinator),
                        auto_accept_firewall,
                        auto_accept_files,
                    )
                    .await
                {
                    IpcMessage::Joined { name, .. } => ManagementResult::Applied {
                        message: format!("managed machine joined '{name}'"),
                    },
                    IpcMessage::Ok { message } => ManagementResult::Applied { message },
                    IpcMessage::Error { message } => ManagementResult::Error { message },
                    other => ManagementResult::Error {
                        message: format!("unexpected join response: {other:?}"),
                    },
                }
            }
            ManagementAction::Leave { network_name } => {
                match self.registry.leave_network(network_name.as_ref()).await {
                    IpcMessage::Ok { message } => ManagementResult::Applied { message },
                    IpcMessage::Error { message } => ManagementResult::Error { message },
                    other => ManagementResult::Error {
                        message: format!("unexpected leave response: {other:?}"),
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn endpoint(seed: u8) -> EndpointId {
        let mut bytes = [0; 32];
        bytes[0] = seed;
        SecretKey::from(bytes).public()
    }

    fn settings_with_credential(reusable: bool) -> (config::AppConfig, blake3::Hash) {
        let secret_hash = blake3::hash(b"fabricated enrollment secret");
        let mut settings = config::AppConfig::default();
        settings
            .enrollment_credentials
            .push(config::EnrollmentCredential {
                id: ipc::EnrollmentCredentialId::new("abc123".to_string()),
                secret_hash,
                expires_at: UnixTimestampSecs::from_secs(200),
                reusable,
                enrolled_machines: Vec::new(),
                revoked: false,
            });
        (settings, secret_hash)
    }

    #[test]
    fn one_time_enrollment_allows_only_same_machine_to_retry() {
        let (mut settings, secret_hash) = settings_with_credential(false);
        let first = endpoint(1);
        let other = endpoint(2);
        let hostname: MachineHostname = "build-box".parse().unwrap();
        let at = UnixTimestampSecs::from_secs(100);

        record_enrollment(&mut settings, first, secret_hash, &hostname, at).unwrap();
        record_enrollment(&mut settings, first, secret_hash, &hostname, at).unwrap();
        let other_hostname = "gpu-box".parse().unwrap();
        let error =
            record_enrollment(&mut settings, other, secret_hash, &other_hostname, at).unwrap_err();
        assert!(error.to_string().contains("already used"));
        assert_eq!(
            settings.enrollment_credentials[0].enrolled_machines,
            [first]
        );
    }

    #[test]
    fn reusable_enrollment_accepts_distinct_machines() {
        let (mut settings, secret_hash) = settings_with_credential(true);
        let first = endpoint(1);
        let other = endpoint(2);
        let at = UnixTimestampSecs::from_secs(100);

        record_enrollment(
            &mut settings,
            first,
            secret_hash,
            &"build-box".parse().unwrap(),
            at,
        )
        .unwrap();
        record_enrollment(
            &mut settings,
            other,
            secret_hash,
            &"gpu-box".parse().unwrap(),
            at,
        )
        .unwrap();

        assert_eq!(
            settings.enrollment_credentials[0].enrolled_machines,
            [first, other]
        );
    }

    #[test]
    fn zero_enrollment_ttl_expires_immediately() {
        let created_at = UnixTimestampSecs::from_secs(100);
        assert_eq!(
            enrollment_expiration(created_at, Duration::ZERO),
            created_at
        );
    }

    #[test]
    fn signed_hello_recovers_inventory_without_an_enrollment_secret() {
        let key = SecretKey::generate();
        let machine = endpoint(2);
        let enrolled_at = UnixTimestampSecs::from_secs(100);
        let receipt = EnrollmentReceipt::issue(&key, machine, enrolled_at);
        let mut settings = config::AppConfig::default();
        for hostname in ["build-box", "renamed-box"] {
            record_hello(
                &mut settings,
                key.public(),
                machine,
                &receipt,
                &hostname.parse().unwrap(),
                UnixTimestampSecs::from_secs(200),
            )
            .unwrap();
        }
        assert_eq!(settings.managed_machines.len(), 1);
        assert_eq!(
            settings.managed_machines[0].hostname.as_ref(),
            "renamed-box"
        );
        assert_eq!(settings.managed_machines[0].enrolled_at, enrolled_at);
        assert!(settings.enrollment_credentials.is_empty());
        assert!(
            settings.controllers.is_empty(),
            "inventory recovery grants no authority"
        );
    }

    #[test]
    fn stolen_receipt_and_hostname_collision_cannot_replace_inventory() {
        let key = SecretKey::generate();
        let machine = endpoint(2);
        let other = endpoint(3);
        let at = UnixTimestampSecs::from_secs(100);
        let receipt = EnrollmentReceipt::issue(&key, machine, at);
        let hostname = "build-box".parse().unwrap();
        let mut settings = config::AppConfig::default();
        assert!(record_hello(&mut settings, key.public(), other, &receipt, &hostname, at).is_err());
        assert!(settings.managed_machines.is_empty());
        record_hello(
            &mut settings,
            key.public(),
            machine,
            &receipt,
            &hostname,
            at,
        )
        .unwrap();
        let other_receipt = EnrollmentReceipt::issue(&key, other, at);
        assert!(
            record_hello(
                &mut settings,
                key.public(),
                other,
                &other_receipt,
                &hostname,
                at
            )
            .is_err()
        );
        assert_eq!(settings.managed_machines.len(), 1);
        assert_eq!(settings.managed_machines[0].identity, machine);
    }

    #[test]
    fn forgotten_machine_stays_forgotten_until_explicit_reenrollment() {
        let key = SecretKey::generate();
        let machine = endpoint(2);
        let at = UnixTimestampSecs::from_secs(100);
        let hostname = "build-box".parse().unwrap();
        let receipt = EnrollmentReceipt::issue(&key, machine, at);
        let (mut settings, secret_hash) = settings_with_credential(false);
        record_enrollment(&mut settings, machine, secret_hash, &hostname, at).unwrap();
        forget_record(&mut settings, machine);
        forget_record(&mut settings, machine);
        assert_eq!(settings.forgotten_machines, [machine]);
        let mut settings: config::AppConfig =
            toml::from_str(&toml::to_string(&settings).unwrap()).unwrap();
        assert!(
            record_hello(
                &mut settings,
                key.public(),
                machine,
                &receipt,
                &hostname,
                at
            )
            .is_err()
        );
        assert!(settings.managed_machines.is_empty());
        record_enrollment(&mut settings, machine, secret_hash, &hostname, at).unwrap();
        assert!(settings.forgotten_machines.is_empty());
        record_hello(
            &mut settings,
            key.public(),
            machine,
            &receipt,
            &hostname,
            at,
        )
        .unwrap();
    }

    #[test]
    fn legacy_confirmation_requires_an_existing_grant_and_cannot_undo_revocation() {
        let key = SecretKey::generate();
        let machine = endpoint(2);
        let at = UnixTimestampSecs::from_secs(100);
        let receipt = EnrollmentReceipt::issue(&key, machine, at);
        let mut settings = config::AppConfig::default();
        assert!(
            confirm_controller_grant(&mut settings, key.public(), machine, receipt.clone())
                .is_err()
        );
        settings.controllers.push(config::ControllerGrant {
            identity: key.public(),
            enrolled_at: at,
            receipt: None,
        });
        assert!(
            confirm_controller_grant(&mut settings, endpoint(3), machine, receipt.clone()).is_err()
        );
        confirm_controller_grant(&mut settings, key.public(), machine, receipt.clone()).unwrap();
        assert_eq!(settings.controllers[0].receipt.as_ref(), Some(&receipt));
        settings.controllers.clear();
        assert!(confirm_controller_grant(&mut settings, key.public(), machine, receipt).is_err());
        assert!(settings.controllers.is_empty());
    }
}
