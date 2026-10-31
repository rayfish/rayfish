//! Swift bindings for the Rayfish core running in an Apple packet tunnel.

#[cfg(target_os = "macos")]
mod logging;
mod migration;

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iroh::EndpointId;
use rayfish::config;
use rayfish::config::settings::GlobalKey;
use rayfish::config::{DnsMode, QuicEngine};
#[cfg(target_os = "macos")]
use rayfish::daemon::start_embedded_ipc;
use rayfish::daemon::{
    DaemonState, Done, FileQueues, FirewallView, OpError, OpResult, build_headless,
};
use rayfish::firewall::{Action, Direction, Protocol};
use rayfish::invite;
use rayfish::ipc::{self, ConnectionIssue, InvitationInfo, InvitationStatus, TransferFileState};
use rayfish::membership;
use rayfish::membership::GroupMode;
use thiserror::Error;
use tokio::runtime::{Builder, Runtime};
#[cfg(target_os = "macos")]
use tokio::task::JoinHandle;
use tokio::time::timeout;

uniffi::setup_scaffolding!();

const START_TIMEOUT: Duration = Duration::from_secs(45);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn connection_issue_priority(issue: ConnectionIssue) -> u8 {
    match issue {
        ConnectionIssue::HighLatency => 1,
        ConnectionIssue::PacketLoss => 2,
        ConnectionIssue::SendQueue => 3,
    }
}

#[derive(Debug, Error, uniffi::Error)]
pub enum AppleError {
    #[error("node not started")]
    NotStarted,
    #[error("the packet tunnel is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("the packet tunnel is already active")]
    AlreadyActive,
    #[error("state migration must run before the node starts")]
    AlreadyStarted,
    #[error("{0}")]
    Network(String),
}

impl From<OpError> for AppleError {
    fn from(error: OpError) -> Self {
        Self::Network(error.to_string())
    }
}

impl AppleError {
    fn network(error: impl Display) -> Self {
        Self::Network(error.to_string())
    }
}

#[derive(uniffi::Record)]
pub struct NodeStatus {
    pub mesh: NodeMeshStatus,
    pub requests: NodeRequestStatus,
    pub files: Vec<IncomingFile>,
    pub ssh: NodeSshStatus,
    pub services: NodeServiceStatus,
    pub connection_warning: Option<String>,
    pub file_auto_accept_peers: Vec<String>,
    pub inbound: NodeInboundStatus,
}

#[derive(uniffi::Record)]
pub struct NodeMeshStatus {
    pub active: bool,
    pub ipv6: String,
    pub networks: Vec<Network>,
}

#[derive(uniffi::Record)]
pub struct NodeRequestStatus {
    pub pending_requests: Vec<JoinRequest>,
    pub identity: Option<String>,
    pub connection_requests: Vec<ConnectionRequest>,
}

/// Who may ask this node for a connection, and what coordinators sent it.
#[derive(uniffi::Record)]
pub struct NodeInboundStatus {
    pub policy: InboundPolicy,
    pub blocked: Vec<String>,
    pub invitations: Vec<Invitation>,
}

/// Which strangers may send connect requests and invitations.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum InboundPolicy {
    Anyone,
    /// Only peers that share a network with this node.
    Known,
    Nobody,
}

impl From<config::InboundPolicy> for InboundPolicy {
    fn from(policy: config::InboundPolicy) -> Self {
        match policy {
            config::InboundPolicy::Anyone => Self::Anyone,
            config::InboundPolicy::Known => Self::Known,
            config::InboundPolicy::Nobody => Self::Nobody,
        }
    }
}

impl From<InboundPolicy> for config::InboundPolicy {
    fn from(policy: InboundPolicy) -> Self {
        match policy {
            InboundPolicy::Anyone => Self::Anyone,
            InboundPolicy::Known => Self::Known,
            InboundPolicy::Nobody => Self::Nobody,
        }
    }
}

#[derive(uniffi::Enum)]
pub enum InvitationState {
    Pending,
    Accepted,
    Declined,
}

impl From<InvitationStatus> for InvitationState {
    fn from(status: InvitationStatus) -> Self {
        match status {
            InvitationStatus::Pending => Self::Pending,
            InvitationStatus::Accepted => Self::Accepted,
            InvitationStatus::Declined => Self::Declined,
        }
    }
}

/// An invitation a coordinator delivered to this node. The code stays in the
/// node: accepting by `id` is all the app needs.
#[derive(uniffi::Record)]
pub struct Invitation {
    pub id: String,
    pub network: String,
    pub coordinator: String,
    pub received_secs: u64,
    pub state: InvitationState,
}

#[derive(uniffi::Record)]
pub struct NodeSshStatus {
    pub enabled: bool,
    pub rules: Vec<SshRule>,
}

#[derive(uniffi::Record)]
pub struct NodeServiceStatus {
    pub dns_enabled: bool,
    pub mdns_enabled: bool,
    pub mdns_active: bool,
    pub v4_bridge_enabled: bool,
    pub quic_fq_codel: bool,
}

#[derive(uniffi::Record)]
pub struct ManagedMachine {
    pub identity: String,
    pub hostname: String,
    pub ipv6: String,
    pub state: String,
    pub networks: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct ConnectionRequest {
    pub id: String,
    pub hostname: Option<String>,
    pub waiting_secs: u64,
}

#[derive(uniffi::Enum)]
pub enum IncomingFileState {
    Pending,
    Transferring,
    Received,
}

#[derive(uniffi::Record)]
pub struct IncomingFile {
    pub id: u64,
    pub peer: String,
    pub filename: String,
    pub size: u64,
    pub transferred: u64,
    pub state: IncomingFileState,
    pub destination: Option<String>,
}

#[derive(Clone, Copy, uniffi::Enum)]
pub enum GlobalSetting {
    Dns,
    Mdns,
    Ssh,
    /// On selects FQ-CoDel scheduling, off standalone forwarding.
    /// Applies when the endpoint next binds.
    QuicFqCodel,
}

impl From<GlobalSetting> for GlobalKey {
    fn from(setting: GlobalSetting) -> Self {
        match setting {
            GlobalSetting::Dns => Self::Dns,
            GlobalSetting::Mdns => Self::Mdns,
            GlobalSetting::Ssh => Self::Ssh,
            GlobalSetting::QuicFqCodel => Self::QuicEngine,
        }
    }
}

#[derive(uniffi::Record)]
pub struct Network {
    pub name: String,
    pub hostname: String,
    pub ipv6: String,
    pub role: String,
    pub peers: Vec<Peer>,
}

#[derive(uniffi::Record)]
pub struct Peer {
    pub identity: String,
    pub hostname: String,
    pub ipv6: String,
    pub state: String,
    pub latency_ms: Option<u32>,
    pub is_own_device: bool,
}

#[derive(uniffi::Record)]
pub struct SshRule {
    pub network: String,
    pub peer: String,
    pub users: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct JoinRequest {
    pub network: String,
    pub id: String,
    pub hostname: Option<String>,
    pub waiting_secs: u64,
}

#[derive(uniffi::Record)]
pub struct FirewallRule {
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub port: String,
    pub peer: String,
    pub network: String,
}

#[derive(uniffi::Record)]
pub struct FirewallState {
    pub default_inbound: String,
    pub default_outbound: String,
    pub disabled: bool,
    pub rules: Vec<FirewallRule>,
}

/// One Rayfish node hosted by a packet tunnel provider.
#[derive(uniffi::Object)]
pub struct Node {
    config_dir: PathBuf,
    runtime: Runtime,
    state: Mutex<Option<Arc<DaemonState>>>,
    #[cfg(target_os = "macos")]
    ipc_task: Mutex<Option<JoinHandle<()>>>,
    /// Serializes tunnel attach and detach.
    #[cfg(target_os = "macos")]
    tunnel_active: Mutex<bool>,
}

impl Node {
    fn state(&self) -> Result<Arc<DaemonState>, AppleError> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(AppleError::NotStarted)
    }

    fn edit_blocked(&self, peer: &str, remove: bool) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime
            .block_on(state.edit_peer_list(GlobalKey::Blocked, peer, remove))?;
        Ok(())
    }

    fn set_global(&self, key: GlobalKey, value: &str) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime.block_on(state.config_set(key, value))?;
        Ok(())
    }
}

#[uniffi::export]
impl Node {
    #[uniffi::constructor]
    pub fn new(config_dir: String) -> Arc<Self> {
        #[cfg(target_os = "macos")]
        logging::init();
        let config_dir = PathBuf::from(config_dir);
        config::set_config_dir_override(config_dir.clone());
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("creating the Apple bridge runtime must succeed");
        Arc::new(Self {
            config_dir,
            runtime,
            state: Mutex::new(None),
            #[cfg(target_os = "macos")]
            ipc_task: Mutex::new(None),
            #[cfg(target_os = "macos")]
            tunnel_active: Mutex::new(false),
        })
    }

    /// Start the control plane. This is safe to call more than once.
    pub fn start(&self, owner_uid: u32) -> Result<(), AppleError> {
        let mut slot = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        #[cfg(not(target_os = "macos"))]
        let _ = owner_uid;
        if slot.is_some() {
            return Ok(());
        }
        let state = self
            .runtime
            .block_on(async { timeout(START_TIMEOUT, build_headless(true)).await })
            .map_err(|_| AppleError::Network("node start timed out".to_owned()))?
            .map_err(AppleError::network)?;
        #[cfg(target_os = "macos")]
        {
            let task = match self.runtime.block_on(start_embedded_ipc(&state, owner_uid)) {
                Ok(task) => task,
                Err(error) => {
                    self.runtime.block_on(state.shutdown_and_close());
                    return Err(AppleError::network(error));
                }
            };
            *self.ipc_task.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
        }
        *slot = Some(state);
        Ok(())
    }

    /// Copy legacy launchd state before starting the extension-owned node.
    pub fn migrate_legacy_state(&self, source: String) -> Result<(), AppleError> {
        let slot = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_some() {
            return Err(AppleError::AlreadyStarted);
        }
        migration::copy_legacy_state(Path::new(&source), &self.config_dir)
            .map_err(AppleError::network)
    }

    /// The stable mesh address that the packet tunnel assigns to this device.
    pub fn ipv6_address(&self) -> Result<String, AppleError> {
        let state = self.state()?;
        Ok(membership::derive_ipv6(&state.status().endpoint_id).to_string())
    }

    /// A UI-ready snapshot of the running node.
    pub fn status(&self) -> Result<NodeStatus, AppleError> {
        let state = self.state()?;
        let ipc::NodeStatus {
            endpoint_id,
            active,
            networks,
            identity,
            mdns_enabled: mdns_active,
            ..
        } = state.status();
        let pending_requests = networks
            .iter()
            .filter(|network| network.pending_requests > 0)
            .flat_map(|network| {
                state
                    .list_requests(&network.name)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|request| JoinRequest {
                        network: network.name.clone(),
                        id: request.short_id,
                        hostname: request.hostname,
                        waiting_secs: request.waiting_secs,
                    })
            })
            .collect();
        let settings = config::load().map_err(AppleError::network)?;
        let connection_requests = state
            .list_connections()
            .into_iter()
            .map(|request| ConnectionRequest {
                id: request.short_id,
                hostname: request.hostname,
                waiting_secs: request.waiting_secs,
            })
            .collect();
        let requests = NodeRequestStatus {
            pending_requests,
            identity: identity.map(|id| id.to_string()),
            connection_requests,
        };
        let files = incoming_files(state.list_files());
        let inbound = NodeInboundStatus {
            policy: settings.inbound.into(),
            blocked: settings.blocked.iter().map(ToString::to_string).collect(),
            invitations: invitations(self.runtime.block_on(state.list_invitations())),
        };
        let rules = settings
            .networks
            .iter()
            .flat_map(|network| {
                network.ssh_allow.iter().map(|rule| SshRule {
                    network: network.name.clone(),
                    peer: rule.peer.clone(),
                    users: rule.users.clone(),
                })
            })
            .collect();
        let ssh = NodeSshStatus {
            enabled: settings.ssh_enabled,
            rules,
        };
        let services = NodeServiceStatus {
            dns_enabled: settings.dns_mode.enabled(),
            mdns_enabled: settings.mdns_enabled,
            mdns_active,
            v4_bridge_enabled: settings.v4_bridge,
            quic_fq_codel: settings.quic_engine == QuicEngine::FqCodel,
        };
        let ipv6 = membership::derive_ipv6(&endpoint_id).to_string();
        let connection_warning = networks
            .iter()
            .flat_map(|network| &network.peers)
            .filter_map(|peer| {
                peer.connection
                    .as_ref()
                    .and_then(|connection| connection.quality_issue)
                    .map(|issue| {
                        let name = peer
                            .hostname
                            .clone()
                            .unwrap_or_else(|| peer.endpoint_id.fmt_short().to_string());
                        let detail = match issue {
                            ConnectionIssue::HighLatency => "has high latency",
                            ConnectionIssue::PacketLoss => "is losing packets",
                            ConnectionIssue::SendQueue => "cannot accept traffic fast enough",
                        };
                        (
                            connection_issue_priority(issue),
                            format!(
                                "Connection to {name} {detail}. Rayfish traffic may be delayed."
                            ),
                        )
                    })
            })
            .max_by_key(|(priority, _)| *priority)
            .map(|(_, warning)| warning);
        let networks = networks
            .into_iter()
            .map(|network| Network {
                name: network.name,
                hostname: network.my_hostname.unwrap_or_default(),
                ipv6: network.my_ipv6.to_string(),
                role: network.role.to_string(),
                peers: network
                    .peers
                    .into_iter()
                    .map(|peer| Peer {
                        identity: peer.endpoint_id.to_string(),
                        hostname: peer
                            .hostname
                            .unwrap_or_else(|| peer.endpoint_id.to_string()),
                        ipv6: peer.ipv6.to_string(),
                        state: peer
                            .connection
                            .as_ref()
                            .map(|connection| connection.conn_type.to_string())
                            .unwrap_or_else(|| peer.state.to_string()),
                        latency_ms: peer
                            .connection
                            .and_then(|connection| connection.rtt_ms)
                            .map(|latency| latency.round() as u32),
                        is_own_device: peer.is_own_device,
                    })
                    .collect(),
            })
            .collect();
        let mesh = NodeMeshStatus {
            active,
            ipv6,
            networks,
        };
        Ok(NodeStatus {
            mesh,
            requests,
            files,
            ssh,
            services,
            connection_warning,
            file_auto_accept_peers: settings
                .file_auto_accept_peers
                .iter()
                .map(ToString::to_string)
                .collect(),
            inbound,
        })
    }

    /// Probe enrolled machines separately so an offline machine cannot delay status.
    pub fn machines(&self) -> Result<Vec<ManagedMachine>, AppleError> {
        let state = self.state()?;
        let machines = self.runtime.block_on(state.list_managed_machines(true))?;
        Ok(machines
            .into_iter()
            .map(|machine| ManagedMachine {
                identity: machine.identity.to_string(),
                hostname: machine.hostname.to_string(),
                ipv6: membership::derive_ipv6(&machine.identity).to_string(),
                state: <&str>::from(machine.state).to_owned(),
                networks: machine
                    .networks
                    .into_iter()
                    .map(|name| name.to_string())
                    .collect(),
            })
            .collect())
    }

    /// Persist an embedder-owned setting using the same keys as `ray config`.
    /// NetworkExtension applies DNS; mDNS changes on the running endpoint.
    pub fn set_setting(&self, key: GlobalSetting, enabled: bool) -> Result<(), AppleError> {
        let state = self.state()?;
        if matches!(key, GlobalSetting::Ssh) {
            return self.runtime.block_on(async {
                state.ssh_config_set(if enabled { "on" } else { "off" })?;
                Ok(())
            });
        }
        if matches!(key, GlobalSetting::Mdns) {
            return self
                .runtime
                .block_on(state.set_mdns_enabled(enabled))
                .map_err(AppleError::network);
        }
        let value = toggle_value(key, enabled);
        config::update_settings(|settings| config::config_set(settings, key.into(), value, false))
            .map(|_| ())
            .map_err(AppleError::network)
    }

    pub fn set_file_auto_accept(
        &self,
        peer: String,
        allow: bool,
        owner_uid: u32,
    ) -> Result<(), AppleError> {
        let state = self.state()?;
        if peer.trim().is_empty() || peer.contains(',') || peer.starts_with('-') {
            return Err(AppleError::Network(
                "a single peer name or identity is required".to_owned(),
            ));
        }
        if allow {
            if owner_uid == 0 {
                return Err(AppleError::Network(
                    "a non-root download owner is required".to_owned(),
                ));
            }
            config::update_settings(|settings| {
                if settings.download_dir.is_none()
                    && settings.download_user.is_none()
                    && settings.operator_uid.is_none()
                {
                    settings.download_user = Some(owner_uid);
                }
                Ok(())
            })
            .map_err(AppleError::network)?;
        }
        self.runtime
            .block_on(state.set_file_auto_accept(&peer, allow))?;
        Ok(())
    }

    pub fn set_ssh_rule(
        &self,
        network: String,
        peer: String,
        users: Vec<String>,
        allow: bool,
    ) -> Result<(), AppleError> {
        self.runtime.block_on(
            self.state()?
                .firewall_ssh_allow(&network, &peer, users, allow),
        )?;
        Ok(())
    }

    pub fn firewall_show(&self) -> Result<FirewallState, AppleError> {
        let FirewallView {
            default_inbound,
            default_outbound,
            disabled,
            rules,
            ..
        } = self.state()?.firewall_show();
        Ok(FirewallState {
            default_inbound: default_inbound.to_string(),
            default_outbound: default_outbound.to_string(),
            disabled,
            rules: rules
                .into_iter()
                .map(|rule| FirewallRule {
                    direction: rule.direction.to_string(),
                    action: rule.action.to_string(),
                    protocol: rule.protocol.to_string(),
                    port: rule.port,
                    peer: rule.peer,
                    network: rule.network,
                })
                .collect(),
        })
    }

    pub fn firewall_add(
        &self,
        direction: String,
        action: String,
        protocol: String,
        port: Option<String>,
        peer: Option<String>,
        network: Option<String>,
    ) -> Result<(), AppleError> {
        let direction: Direction = direction.parse().map_err(AppleError::network)?;
        let action: Action = action.parse().map_err(AppleError::network)?;
        let protocol: Protocol = protocol.parse().map_err(AppleError::network)?;
        let state = self.state()?;
        self.runtime.block_on(state.firewall_add(
            direction,
            action,
            protocol,
            port.as_deref(),
            peer.as_deref(),
            network.as_deref(),
        ))?;
        Ok(())
    }

    pub fn firewall_remove(&self, index: u32) -> Result<(), AppleError> {
        self.state()?.firewall_remove(index as usize)?;
        Ok(())
    }

    pub fn firewall_set_default_inbound(&self, action: String) -> Result<(), AppleError> {
        let action: Action = action.parse().map_err(AppleError::network)?;
        self.state()?.firewall_default(action)?;
        Ok(())
    }

    pub fn connect_peer(
        &self,
        peer: String,
        hostname: Option<String>,
    ) -> Result<String, AppleError> {
        let state = self.state()?;
        Ok(self
            .runtime
            .block_on(state.connect(&peer, hostname))?
            .summary())
    }

    pub fn approve_connection(&self, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime.block_on(state.approve_connection(&id))?;
        Ok(())
    }

    pub fn reject_connection(&self, id: String) -> Result<(), AppleError> {
        self.state()?.reject_connect(&id)?;
        Ok(())
    }

    /// Drop a pending connection request and block the requester.
    pub fn block_connection(&self, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime.block_on(state.deny_connection(&id))?;
        Ok(())
    }

    pub fn accept_invitation(&self, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime.block_on(state.accept_invitation(&id, None))?;
        Ok(())
    }

    pub fn decline_invitation(&self, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime.block_on(state.decline_invitation(&id))?;
        Ok(())
    }

    /// Deliver an invite for `network` to `recipient`'s identity. An offline
    /// recipient is not an error: the node retries until the invite expires.
    pub fn send_invite(&self, network: String, recipient: String) -> Result<String, AppleError> {
        let recipient: EndpointId = recipient.trim().parse().map_err(AppleError::network)?;
        let state = self.state()?;
        let Done(message) = self
            .runtime
            .block_on(state.deliver_invite(&network, recipient))?;
        Ok(message)
    }

    pub fn set_inbound_policy(&self, policy: InboundPolicy) -> Result<(), AppleError> {
        let value = config::InboundPolicy::from(policy);
        self.set_global(GlobalKey::Inbound, value.as_ref())
    }

    /// Block `peer` (an identity, or a hostname this node knows).
    pub fn block_peer(&self, peer: String) -> Result<(), AppleError> {
        self.edit_blocked(&peer, false)
    }

    pub fn unblock_peer(&self, peer: String) -> Result<(), AppleError> {
        self.edit_blocked(&peer, true)
    }

    /// Start receiving a file offer. Returns once the receive has started, not
    /// when the download ends; the app follows it in the status file list.
    pub fn accept_file(
        &self,
        id: u64,
        directory: String,
        uid: u32,
        gid: u32,
    ) -> Result<(), AppleError> {
        let state = self.state()?;
        // Inside the runtime: the receive runs in a task spawned on it.
        let _runtime = self.runtime.enter();
        state.start_accepting_file(id, Some(directory), Some((uid, gid)))?;
        Ok(())
    }

    pub fn reject_file(&self, id: u64) -> Result<(), AppleError> {
        self.state()?.reject_file(id)?;
        Ok(())
    }

    pub fn create_network(
        &self,
        name: Option<String>,
        hostname: Option<String>,
    ) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime
            .block_on(state.create_network(GroupMode::default(), name, hostname))?;
        Ok(())
    }

    pub fn join_network(&self, code: String, hostname: Option<String>) -> Result<(), AppleError> {
        let state = self.state()?;
        let (network_key, invite, coordinator) = match invite::decode_invite_code(&code) {
            Ok(decoded) => (
                decoded.network_key.to_string(),
                Some(decoded.secret),
                Some(decoded.coordinator),
            ),
            Err(_) => (code, None, None),
        };
        self.runtime.block_on(state.join_network(
            &network_key,
            None,
            hostname,
            invite,
            coordinator,
            false,
            true,
        ))?;
        Ok(())
    }

    /// Mint a single-use invite that expires after seven days.
    pub fn create_invite(&self, network: String) -> Result<String, AppleError> {
        let state = self.state()?;
        let invite =
            self.runtime
                .block_on(state.invite_create(&network, 7 * 24 * 60 * 60, None, false))?;
        Ok(invite.code)
    }

    pub fn leave_network(&self, network: String) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime.block_on(state.leave_network(&network))?;
        Ok(())
    }

    pub fn set_hostname(&self, network: String, hostname: String) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime
            .block_on(state.set_hostname(&network, &hostname))?;
        Ok(())
    }

    pub fn accept_request(&self, network: String, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        self.runtime.block_on(state.accept_request(&network, &id))?;
        Ok(())
    }

    pub fn deny_request(&self, network: String, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        state.deny_request(&network, &id)?;
        Ok(())
    }

    /// Attach the system packet tunnel and start forwarding packets.
    pub fn activate(&self) -> Result<(), AppleError> {
        #[cfg(not(target_os = "macos"))]
        {
            Err(AppleError::UnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            let state = self.state()?;
            let mut active = self
                .tunnel_active
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *active {
                return Err(AppleError::AlreadyActive);
            }
            // Swift calls this outside Tokio, but opening the async TUN needs its reactor.
            let _runtime = self.runtime.enter();
            let (reader, writer) =
                rayfish::tun::open_packet_tunnel().map_err(AppleError::network)?;
            self.runtime
                .block_on(state.attach_external_tun(reader, writer));
            *active = true;
            Ok(())
        }
    }

    /// Detach the packet flow but leave mesh control connections alive.
    pub fn deactivate(&self) -> Result<(), AppleError> {
        let state = self.state()?;
        #[cfg(target_os = "macos")]
        let mut active = self
            .tunnel_active
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.detach_tun();
        #[cfg(target_os = "macos")]
        {
            *active = false;
        }
        Ok(())
    }

    /// Stop the mesh node and release all persistent-store locks.
    pub fn stop(&self) {
        // Keep startup waiting until the old node releases its store locks.
        let mut slot = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = slot.take();
        #[cfg(target_os = "macos")]
        let mut active = self
            .tunnel_active
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(state) = &state {
            state.detach_tun();
        }
        #[cfg(target_os = "macos")]
        {
            *active = false;
        }
        #[cfg(target_os = "macos")]
        let ipc_task = self
            .ipc_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        // Swift calls from an ordinary host thread. Construct timers only after
        // entering the runtime, and let IPC drain alongside the mesh shutdown.
        self.runtime.block_on(async {
            let shutdown = async {
                if let Some(state) = state
                    && timeout(SHUTDOWN_TIMEOUT, state.shutdown_and_close())
                        .await
                        .is_err()
                {
                    tracing::warn!("Apple node shutdown exceeded its cleanup deadline");
                }
            };
            #[cfg(target_os = "macos")]
            {
                let drain_ipc = async {
                    if let Some(mut task) = ipc_task
                        && timeout(SHUTDOWN_TIMEOUT, &mut task).await.is_err()
                    {
                        tracing::warn!("Apple IPC shutdown exceeded its cleanup deadline");
                        task.abort();
                        let _ = task.await;
                    }
                };
                tokio::join!(shutdown, drain_ipc);
            }
            #[cfg(not(target_os = "macos"))]
            shutdown.await;
        });
    }
}

fn incoming_files(queues: FileQueues) -> Vec<IncomingFile> {
    queues
        .incoming
        .into_iter()
        .map(|file| IncomingFile {
            id: file.id,
            peer: file.from,
            filename: file.filename,
            size: file.size,
            transferred: 0,
            state: IncomingFileState::Pending,
            destination: None,
        })
        .chain(queues.transfers.into_iter().filter_map(|file| {
            (!file.outgoing
                && matches!(
                    file.state,
                    TransferFileState::Transferring | TransferFileState::Done
                ))
            .then_some(IncomingFile {
                id: file.id,
                peer: file.peer,
                filename: file.filename,
                size: file.size,
                transferred: file.transferred,
                state: if matches!(file.state, TransferFileState::Done) {
                    IncomingFileState::Received
                } else {
                    IncomingFileState::Transferring
                },
                destination: file
                    .destination
                    .map(|path| path.to_string_lossy().into_owned()),
            })
        }))
        .collect()
}

/// The invitations in a status snapshot. An unreadable inbox shows none
/// rather than failing the whole status, which would blank the app.
fn invitations(listed: OpResult<Vec<InvitationInfo>>) -> Vec<Invitation> {
    match listed {
        Ok(invitations) => invitations
            .into_iter()
            .map(|invitation| Invitation {
                id: invitation.id,
                network: invitation.network.into(),
                coordinator: invitation.coordinator.to_string(),
                received_secs: invitation.received,
                state: invitation.status.into(),
            })
            .collect(),
        Err(error) => {
            tracing::warn!(%error, "could not read invitations");
            Vec::new()
        }
    }
}

/// The `ray config` value a toggle writes for `key`.
fn toggle_value(key: GlobalSetting, enabled: bool) -> &'static str {
    match (key, enabled) {
        (GlobalSetting::QuicFqCodel, true) => QuicEngine::FqCodel.as_ref(),
        (GlobalSetting::QuicFqCodel, false) => QuicEngine::Standalone.as_ref(),
        // Enabling restores the default mode, not `on`, which would also turn
        // on short names the user never asked for.
        (GlobalSetting::Dns, true) => DnsMode::default().into(),
        (_, true) => "on",
        (_, false) => "off",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn dns_toggle_turns_on_the_default_mode() {
        assert_eq!(toggle_value(GlobalSetting::Dns, true), "partial");
        assert_eq!(toggle_value(GlobalSetting::Dns, false), "off");
    }

    #[test]
    fn unreadable_invitations_leave_the_status_usable() {
        let failed = Err(OpError::msg("parsing invitations.toml"));
        assert!(invitations(failed).is_empty());
    }

    #[test]
    fn command_errors_keep_the_daemon_message() {
        assert!(matches!(
            AppleError::from(OpError::msg("denied")),
            AppleError::Network(message) if message == "denied"
        ));
    }

    #[test]
    fn file_status_includes_offers_and_active_or_successful_receives() {
        use rayfish::ipc::{PendingFileInfo, TransferFileInfo};

        let files = incoming_files(FileQueues {
            incoming: vec![PendingFileInfo {
                id: 1,
                from: "sender".into(),
                filename: "offer.txt".into(),
                size: 8,
                mime_type: "text/plain".into(),
                own_device: false,
            }],
            outbox: Vec::new(),
            transfers: vec![
                TransferFileInfo {
                    error: None,
                    id: 2,
                    outgoing: false,
                    peer: "sender".into(),
                    filename: "received.txt".into(),
                    size: 8,
                    transferred: 8,
                    state: TransferFileState::Done,
                    destination: Some(PathBuf::from("/path/to/work/received.txt")),
                },
                TransferFileInfo {
                    error: None,
                    id: 5,
                    outgoing: false,
                    peer: "sender".into(),
                    filename: "moving.txt".into(),
                    size: 8,
                    transferred: 4,
                    state: TransferFileState::Transferring,
                    destination: None,
                },
                TransferFileInfo {
                    error: None,
                    id: 3,
                    outgoing: true,
                    peer: "receiver".into(),
                    filename: "sent.txt".into(),
                    size: 8,
                    transferred: 8,
                    state: TransferFileState::Done,
                    destination: None,
                },
                TransferFileInfo {
                    error: None,
                    id: 4,
                    outgoing: false,
                    peer: "sender".into(),
                    filename: "failed.txt".into(),
                    size: 8,
                    transferred: 0,
                    state: TransferFileState::Failed,
                    destination: None,
                },
            ],
        });
        assert_eq!(files.len(), 3);
        assert!(matches!(files[0].state, IncomingFileState::Pending));
        assert_eq!(files[1].filename, "received.txt");
        assert!(matches!(files[1].state, IncomingFileState::Received));
        assert_eq!(
            files[1].destination.as_deref(),
            Some("/path/to/work/received.txt")
        );
        assert_eq!(files[2].filename, "moving.txt");
        assert_eq!(files[2].transferred, 4);
        assert!(matches!(files[2].state, IncomingFileState::Transferring));
    }

    #[test]
    fn stop_from_host_thread_releases_state_and_allows_restart() {
        let directory = tempfile::tempdir().unwrap();
        let node = Node::new(directory.path().to_string_lossy().into_owned());
        // Build without binding the installed app's CLI socket on macOS.
        // The second build also checks that stop released the blob store lock.
        for iteration in 0..2 {
            let state = node.runtime.block_on(async {
                timeout(START_TIMEOUT, build_headless(false))
                    .await
                    .unwrap()
                    .unwrap()
            });
            *node.state.lock().unwrap() = Some(Arc::clone(&state));
            if iteration == 0 {
                let before = node.status().unwrap();
                assert!(before.mesh.networks.is_empty());
                assert!(before.requests.connection_requests.is_empty());
                assert!(before.requests.identity.is_some());
                node.set_setting(GlobalSetting::Dns, false).unwrap();
                node.set_setting(GlobalSetting::Mdns, false).unwrap();
                #[cfg(unix)]
                {
                    node.set_setting(GlobalSetting::Ssh, true).unwrap();
                    assert!(node.status().unwrap().ssh.enabled);
                    node.set_setting(GlobalSetting::Ssh, false).unwrap();
                    let mut network = config::NetworkConfig {
                        name: "ssh-test".into(),
                        ..Default::default()
                    };
                    network.ssh_allow.push(config::SshRule {
                        peer: "departed-peer".into(),
                        users: vec!["old-user".into()],
                    });
                    config::save_network(&network).unwrap();
                    node.set_ssh_rule(
                        "ssh-test".into(),
                        "departed-peer".into(),
                        vec!["test-user".into()],
                        true,
                    )
                    .unwrap();
                    let rules = node.status().unwrap().ssh.rules;
                    assert_eq!(rules[0].users, ["test-user"]);
                    node.set_ssh_rule("ssh-test".into(), "departed-peer".into(), Vec::new(), false)
                        .unwrap();
                    assert!(node.status().unwrap().ssh.rules.is_empty());
                }
                let trusted =
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_owned();
                assert!(node.set_file_auto_accept(trusted.clone(), true, 0).is_err());
                node.set_file_auto_accept(trusted.clone(), true, 1000)
                    .unwrap();
                assert_eq!(
                    node.status().unwrap().file_auto_accept_peers,
                    vec![trusted.clone()]
                );
                assert_eq!(config::load().unwrap().download_user, Some(1000));
                config::update_settings(|settings| {
                    settings.download_user = Some(1001);
                    Ok(())
                })
                .unwrap();
                node.set_file_auto_accept(trusted.clone(), true, 1000)
                    .unwrap();
                assert_eq!(config::load().unwrap().download_user, Some(1001));
                node.set_file_auto_accept(trusted, false, 1000).unwrap();
                assert!(node.status().unwrap().file_auto_accept_peers.is_empty());
                let after = node.status().unwrap();
                assert!(!after.services.dns_enabled);
                assert!(!after.services.mdns_enabled);
                assert!(!after.services.mdns_active);
                assert_eq!(after.mesh.ipv6, before.mesh.ipv6);
                assert_eq!(after.mesh.active, before.mesh.active);
                node.set_setting(GlobalSetting::Mdns, true).unwrap();
                let enabled = node.status().unwrap();
                assert!(enabled.services.mdns_active);
                assert_eq!(enabled.mesh.active, before.mesh.active);
                node.set_setting(GlobalSetting::Mdns, false).unwrap();
                let disabled = node.status().unwrap();
                assert!(!disabled.services.mdns_active);
                assert_eq!(disabled.mesh.active, before.mesh.active);
                node.set_setting(GlobalSetting::QuicFqCodel, true).unwrap();
                assert!(node.status().unwrap().services.quic_fq_codel);
                assert!(Arc::ptr_eq(&state, &node.state().unwrap()));
                assert!(matches!(
                    node.connect_peer("invalid identity".into(), None),
                    Err(AppleError::Network(_))
                ));
                assert!(node.approve_connection("missing".into()).is_err());
                assert!(node.reject_connection("missing".into()).is_err());

                // A self-dial fails immediately, providing an offline inventory
                // entry without relying on an external machine or a network.
                let endpoint_id = node.state().unwrap().status().endpoint_id;
                config::update_settings(|settings| {
                    settings.managed_machines.push(config::ManagedMachine {
                        identity: endpoint_id,
                        hostname: "managed-host".parse().unwrap(),
                        enrolled_at: rayfish::ipc::UnixTimestampSecs::from_secs(1),
                        last_seen: None,
                    });
                    Ok(())
                })
                .unwrap();
                let machines = node.machines().unwrap();
                assert_eq!(machines.len(), 1);
                assert_eq!(machines[0].hostname, "managed-host");
                assert_eq!(machines[0].identity, endpoint_id.to_string());
                assert_eq!(machines[0].ipv6, before.mesh.ipv6);
                assert_eq!(machines[0].state, "offline");
                assert!(machines[0].networks.is_empty());
            } else {
                let restarted = node.status().unwrap();
                assert!(!restarted.services.dns_enabled);
                assert!(!restarted.services.mdns_enabled);
                assert!(!restarted.services.mdns_active);
                assert!(restarted.services.quic_fq_codel);
            }
            let started = Instant::now();
            node.stop();
            eprintln!("host-thread stop took {:?}", started.elapsed());
            assert!(matches!(node.state(), Err(AppleError::NotStarted)));
        }
        node.stop();

        // The installed macOS socket is deliberately not used by this test.
        #[cfg(not(target_os = "macos"))]
        {
            use std::sync::Barrier;
            use std::thread;

            let ready = Barrier::new(2);
            thread::scope(|scope| {
                let start = || {
                    ready.wait();
                    node.start(1000).unwrap();
                    node.state().unwrap()
                };
                let first = scope.spawn(start);
                let second = scope.spawn(start);
                assert!(Arc::ptr_eq(&first.join().unwrap(), &second.join().unwrap()));
                assert_eq!(config::load().unwrap().operator_uid, None);
            });
            node.stop();
        }
    }
}
