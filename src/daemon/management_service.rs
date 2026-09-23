//! Enrollment and direct management of machines controlled by this node.

use super::*;
use crate::management::{
    EnrollmentSecret, ManagementAction, ManagementMsg, ManagementRequestId, ManagementResult,
    NetworkInvite,
};
use futures::future::join_all;
use ray_proto::ipc::{
    ControllerSelector, EnrollmentCredentialSelector, MachineHostname, ManagedMachineSelector,
    NetworkName, UnixTimestampSecs,
};
use std::time::{SystemTime, UNIX_EPOCH};

const MANAGEMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGEMENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MANAGEMENT_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGEMENT_STATUS_TIMEOUT: Duration = Duration::from_secs(5);

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
    if let Some(entry) = settings
        .managed_machines
        .iter_mut()
        .find(|entry| entry.identity == machine)
    {
        entry.hostname = hostname.clone();
        entry.last_seen = Some(enrolled_at);
    } else {
        settings.managed_machines.push(config::ManagedMachine {
            identity: machine,
            hostname: hostname.clone(),
            enrolled_at,
            last_seen: Some(enrolled_at),
        });
    }
    Ok(())
}

/// Handles enrollment, controller authorization, and delegated network actions.
pub(crate) struct ManagementService {
    transport: Arc<Transport>,
    registry: Arc<NetworkRegistry>,
    /// Serializes controller authorization changes with remote actions. Once a
    /// local revoke returns, no request from that controller is still running.
    controller_gate: AsyncMutex<()>,
}

impl ManagementService {
    /// Creates the management service for the process-wide transport and registry.
    pub(crate) fn new(transport: Arc<Transport>, registry: Arc<NetworkRegistry>) -> Self {
        Self {
            transport,
            registry,
            controller_gate: AsyncMutex::new(()),
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
            self.transport
                .endpoint
                .connect(ticket.controller().clone(), crate::management::ALPN),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return ipc_err(format!("failed to reach controller: {error}")),
            Err(_) => return ipc_err("timed out reaching controller"),
        };
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
        match response {
            Err(_) => ipc_err("timed out waiting for controller enrollment response"),
            Ok(Ok(ManagementMsg::Enrolled)) => {
                let saved = config::update_settings(|settings| {
                    if !settings
                        .controllers
                        .iter()
                        .any(|grant| grant.identity == controller)
                    {
                        settings.controllers.push(config::ControllerGrant {
                            identity: controller,
                            enrolled_at: now(),
                        });
                    }
                    Ok(())
                });
                match saved {
                    Ok(_) => IpcMessage::Ok {
                        message: format!(
                            "enrolled '{hostname}' with controller {}",
                            controller.fmt_short()
                        ),
                    },
                    Err(error) => ipc_err(format!("failed to save controller grant: {error}")),
                }
            }
            Ok(Ok(ManagementMsg::EnrollmentRejected { message })) => ipc_err(message),
            Ok(Ok(ManagementMsg::ProtocolError { message })) => ipc_err(message),
            Ok(Ok(other)) => ipc_err(format!("unexpected enrollment response: {other:?}")),
            Ok(Err(error)) => ipc_err(format!("failed to read enrollment response: {error}")),
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
            settings
                .managed_machines
                .retain(|entry| entry.identity != target.identity);
            Ok(())
        }) {
            Ok(_) => IpcMessage::Ok {
                message: format!("forgot managed machine '{}'", target.hostname),
            },
            Err(error) => ipc_err(format!("failed to forget managed machine: {error}")),
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
            self.transport
                .endpoint
                .connect(iroh::EndpointAddr::from(target), crate::management::ALPN),
        )
        .await
        .map_err(|_| "timed out reaching managed machine".to_string())?
        .map_err(|error| format!("failed to reach managed machine: {error}"))?;
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
        let reply = match message {
            ManagementMsg::Enroll { secret, hostname } => {
                match self.accept_enrollment(remote, &secret, &hostname) {
                    Ok(()) => ManagementMsg::Enrolled,
                    Err(message) => ManagementMsg::EnrollmentRejected { message },
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
                    self.apply_action(action).await
                } else {
                    ManagementResult::Unauthorized
                };
                ManagementMsg::Response { request_id, result }
            }
            _ => ManagementMsg::ProtocolError {
                message: "unexpected management message".to_string(),
            },
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
    ) -> Result<(), String> {
        let secret_hash = secret.hash();
        let enrolled_at = now();
        config::update_settings(|settings| {
            record_enrollment(settings, machine, secret_hash, hostname, enrolled_at)
        })
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    async fn apply_action(&self, action: ManagementAction) -> ManagementResult {
        match action {
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
}
