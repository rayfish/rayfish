//! Swift bindings for the Rayfish core running in an Apple packet tunnel.

mod migration;

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rayfish::config;
use rayfish::config::settings::GlobalKey;
#[cfg(target_os = "macos")]
use rayfish::daemon::start_embedded_ipc;
use rayfish::daemon::{DaemonState, build_headless};
use rayfish::invite;
use rayfish::ipc::{IpcMessage, TransferFileState};
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

impl AppleError {
    fn network(error: impl Display) -> Self {
        Self::Network(error.to_string())
    }
}

#[derive(uniffi::Record)]
pub struct NodeStatus {
    pub active: bool,
    pub ipv6: String,
    pub networks: Vec<Network>,
    pub pending_requests: Vec<JoinRequest>,
    pub contact_id: Option<String>,
    pub connection_requests: Vec<ConnectionRequest>,
    pub files: Vec<IncomingFile>,
    pub ssh_enabled: bool,
    pub ssh_rules: Vec<SshRule>,
    pub dns_enabled: bool,
    pub mdns_enabled: bool,
    pub mdns_active: bool,
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
    Received,
}

#[derive(uniffi::Record)]
pub struct IncomingFile {
    pub id: u64,
    pub peer: String,
    pub filename: String,
    pub size: u64,
    pub state: IncomingFileState,
}

#[derive(uniffi::Enum)]
pub enum GlobalSetting {
    Dns,
    Mdns,
    Ssh,
}

impl From<GlobalSetting> for GlobalKey {
    fn from(setting: GlobalSetting) -> Self {
        match setting {
            GlobalSetting::Dns => Self::Dns,
            GlobalSetting::Mdns => Self::Mdns,
            GlobalSetting::Ssh => Self::Ssh,
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
}

#[uniffi::export]
impl Node {
    #[uniffi::constructor]
    pub fn new(config_dir: String) -> Arc<Self> {
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
        let IpcMessage::StatusResponse { endpoint_id, .. } = state.status() else {
            return Err(AppleError::Network(
                "node returned an invalid status response".to_owned(),
            ));
        };
        Ok(membership::derive_ipv6(&endpoint_id).to_string())
    }

    /// A UI-ready snapshot of the running node.
    pub fn status(&self) -> Result<NodeStatus, AppleError> {
        let state = self.state()?;
        let IpcMessage::StatusResponse {
            endpoint_id,
            active,
            networks,
            contact_id,
            mdns_enabled: mdns_active,
            ..
        } = state.status()
        else {
            return Err(AppleError::Network(
                "node returned an invalid status response".to_owned(),
            ));
        };
        let pending_requests = networks
            .iter()
            .filter(|network| network.pending_requests > 0)
            .flat_map(|network| match state.list_requests(&network.name) {
                IpcMessage::PendingRequests { requests } => requests
                    .into_iter()
                    .map(|request| JoinRequest {
                        network: network.name.clone(),
                        id: request.short_id,
                        hostname: request.hostname,
                        waiting_secs: request.waiting_secs,
                    })
                    .collect(),
                _ => Vec::new(),
            })
            .collect();
        let settings = config::load().map_err(AppleError::network)?;
        let connection_requests = match state.list_connections() {
            IpcMessage::PendingRequests { requests } => requests
                .into_iter()
                .map(|request| ConnectionRequest {
                    id: request.short_id,
                    hostname: request.hostname,
                    waiting_secs: request.waiting_secs,
                })
                .collect(),
            response => {
                expect_ok(response, "connection requests")?;
                Vec::new()
            }
        };
        Ok(NodeStatus {
            active,
            contact_id,
            connection_requests,
            files: incoming_files(state.list_files())?,
            ssh_enabled: settings.ssh_enabled,
            ssh_rules: settings
                .networks
                .iter()
                .flat_map(|network| {
                    network.ssh_allow.iter().map(|rule| SshRule {
                        network: network.name.clone(),
                        peer: rule.peer.clone(),
                        users: rule.users.clone(),
                    })
                })
                .collect(),
            dns_enabled: settings.dns_enabled,
            mdns_enabled: settings.mdns_enabled,
            mdns_active,
            ipv6: membership::derive_ipv6(&endpoint_id).to_string(),
            networks: networks
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
                .collect(),
            pending_requests,
        })
    }

    /// Probe enrolled machines separately so an offline machine cannot delay status.
    pub fn machines(&self) -> Result<Vec<ManagedMachine>, AppleError> {
        let state = self.state()?;
        match self.runtime.block_on(state.list_managed_machines(true)) {
            IpcMessage::ManagedMachinesResponse { machines } => Ok(machines
                .into_iter()
                .map(|machine| ManagedMachine {
                    identity: machine.identity.to_string(),
                    hostname: machine.hostname.to_string(),
                    ipv6: membership::derive_ipv6(&machine.identity).to_string(),
                    state: machine.state.as_str().to_owned(),
                    networks: machine
                        .networks
                        .into_iter()
                        .map(|name| name.to_string())
                        .collect(),
                })
                .collect()),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "invalid machine inventory response".to_owned(),
            )),
        }
    }

    /// Persist an embedder-owned setting using the same keys as `ray config`.
    /// NetworkExtension applies DNS; mDNS is rebuilt on the next connection.
    pub fn set_setting(&self, key: GlobalSetting, enabled: bool) -> Result<(), AppleError> {
        let state = self.state()?;
        if matches!(key, GlobalSetting::Ssh) {
            return self.runtime.block_on(async {
                expect_ok(
                    state.ssh_config_set(if enabled { "on" } else { "off" }),
                    "SSH setting",
                )
            });
        }
        config::update_settings(|settings| {
            config::config_set(
                settings,
                key.into(),
                if enabled { "on" } else { "off" },
                false,
            )
        })
        .map(|_| ())
        .map_err(AppleError::network)
    }

    pub fn set_ssh_rule(
        &self,
        network: String,
        peer: String,
        users: Vec<String>,
        allow: bool,
    ) -> Result<(), AppleError> {
        expect_ok(
            self.runtime.block_on(
                self.state()?
                    .firewall_ssh_allow(&network, &peer, users, allow),
            ),
            "SSH access",
        )
    }

    pub fn connect_peer(
        &self,
        contact_id: String,
        hostname: Option<String>,
    ) -> Result<String, AppleError> {
        let state = self.state()?;
        match self.runtime.block_on(state.connect(&contact_id, hostname)) {
            IpcMessage::Ok { message } => Ok(message),
            IpcMessage::Joined { name, .. } => Ok(format!("Connected on {name}")),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network("invalid connect response".to_owned())),
        }
    }

    pub fn approve_connection(&self, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        expect_ok(
            self.runtime.block_on(state.approve_connection(&id)),
            "connection approval",
        )
    }

    pub fn reject_connection(&self, id: String) -> Result<(), AppleError> {
        expect_ok(self.state()?.reject_connect(&id), "connection rejection")
    }

    pub fn accept_file(
        &self,
        id: u64,
        directory: String,
        uid: u32,
        gid: u32,
    ) -> Result<(), AppleError> {
        expect_ok(
            self.runtime.block_on(
                self.state()?
                    .accept_file(id, Some(directory), Some((uid, gid))),
            ),
            "file acceptance",
        )
    }

    pub fn reject_file(&self, id: u64) -> Result<(), AppleError> {
        expect_ok(self.state()?.reject_file(id), "file rejection")
    }

    pub fn create_network(
        &self,
        name: Option<String>,
        hostname: Option<String>,
    ) -> Result<(), AppleError> {
        let state = self.state()?;
        match self
            .runtime
            .block_on(state.create_network(GroupMode::default(), name, hostname))
        {
            IpcMessage::Created { .. } => Ok(()),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "node returned an invalid create response".to_owned(),
            )),
        }
    }

    pub fn join_network(&self, code: String, hostname: Option<String>) -> Result<(), AppleError> {
        let state = self.state()?;
        let (network_key, invite, coordinator) = match invite::decode_invite_code(&code) {
            Ok((network_key, coordinator, secret)) => {
                (network_key.to_string(), Some(secret), Some(coordinator))
            }
            Err(_) => (code, None, None),
        };
        match self.runtime.block_on(state.join_network(
            &network_key,
            None,
            hostname,
            invite,
            coordinator,
            false,
            true,
        )) {
            IpcMessage::Joined { .. } | IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "node returned an invalid join response".to_owned(),
            )),
        }
    }

    /// Mint a single-use invite that expires after seven days.
    pub fn create_invite(&self, network: String) -> Result<String, AppleError> {
        let state = self.state()?;
        match self
            .runtime
            .block_on(state.invite_create(&network, 7 * 24 * 60 * 60, None, false))
        {
            IpcMessage::InviteCreated { code, .. } => Ok(code),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "node returned an invalid invite response".to_owned(),
            )),
        }
    }

    pub fn leave_network(&self, network: String) -> Result<(), AppleError> {
        let state = self.state()?;
        expect_ok(
            self.runtime.block_on(state.leave_network(&network)),
            "leave",
        )
    }

    pub fn set_hostname(&self, network: String, hostname: String) -> Result<(), AppleError> {
        let state = self.state()?;
        expect_ok(
            self.runtime
                .block_on(state.set_hostname(&network, &hostname)),
            "hostname",
        )
    }

    pub fn accept_request(&self, network: String, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        expect_ok(
            self.runtime.block_on(state.accept_request(&network, &id)),
            "approval",
        )
    }

    pub fn deny_request(&self, network: String, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        expect_ok(state.deny_request(&network, &id), "denial")
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

fn incoming_files(response: IpcMessage) -> Result<Vec<IncomingFile>, AppleError> {
    let IpcMessage::FileList {
        files, transfers, ..
    } = response
    else {
        return Err(AppleError::Network("invalid file list response".into()));
    };
    Ok(files
        .into_iter()
        .map(|file| IncomingFile {
            id: file.id,
            peer: file.from,
            filename: file.filename,
            size: file.size,
            state: IncomingFileState::Pending,
        })
        .chain(transfers.into_iter().filter_map(|file| {
            (!file.outgoing && matches!(file.state, TransferFileState::Done)).then_some(
                IncomingFile {
                    id: file.id,
                    peer: file.peer,
                    filename: file.filename,
                    size: file.size,
                    state: IncomingFileState::Received,
                },
            )
        }))
        .collect())
}

fn expect_ok(response: IpcMessage, operation: &str) -> Result<(), AppleError> {
    match response {
        IpcMessage::Ok { .. } => Ok(()),
        IpcMessage::Error { message } => Err(AppleError::Network(message)),
        _ => Err(AppleError::Network(format!(
            "node returned an invalid {operation} response"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn command_results_preserve_daemon_errors_and_reject_other_responses() {
        assert!(
            expect_ok(
                IpcMessage::Ok {
                    message: "done".into()
                },
                "leave"
            )
            .is_ok()
        );
        assert!(matches!(
            expect_ok(IpcMessage::Error { message: "denied".into() }, "leave"),
            Err(AppleError::Network(message)) if message == "denied"
        ));
        assert!(matches!(
            expect_ok(IpcMessage::Status, "leave"),
            Err(AppleError::Network(message)) if message == "node returned an invalid leave response"
        ));
    }

    #[test]
    fn file_notifications_include_offers_and_successful_receives_only() {
        use rayfish::ipc::{PendingFileInfo, TransferFileInfo};

        let files = incoming_files(IpcMessage::FileList {
            files: vec![PendingFileInfo {
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
                    id: 2,
                    outgoing: false,
                    peer: "sender".into(),
                    filename: "received.txt".into(),
                    size: 8,
                    transferred: 8,
                    state: TransferFileState::Done,
                },
                TransferFileInfo {
                    id: 3,
                    outgoing: true,
                    peer: "receiver".into(),
                    filename: "sent.txt".into(),
                    size: 8,
                    transferred: 8,
                    state: TransferFileState::Done,
                },
                TransferFileInfo {
                    id: 4,
                    outgoing: false,
                    peer: "sender".into(),
                    filename: "failed.txt".into(),
                    size: 8,
                    transferred: 0,
                    state: TransferFileState::Failed,
                },
            ],
        })
        .unwrap();
        assert_eq!(files.len(), 2);
        assert!(matches!(files[0].state, IncomingFileState::Pending));
        assert_eq!(files[1].filename, "received.txt");
        assert!(matches!(files[1].state, IncomingFileState::Received));
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
            *node.state.lock().unwrap() = Some(state);
            if iteration == 0 {
                let before = node.status().unwrap();
                assert!(before.networks.is_empty());
                assert!(before.connection_requests.is_empty());
                assert!(before.contact_id.is_some());
                node.set_setting(GlobalSetting::Dns, false).unwrap();
                node.set_setting(GlobalSetting::Mdns, false).unwrap();
                #[cfg(unix)]
                {
                    node.set_setting(GlobalSetting::Ssh, true).unwrap();
                    assert!(node.status().unwrap().ssh_enabled);
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
                    let rules = node.status().unwrap().ssh_rules;
                    assert_eq!(rules[0].users, ["test-user"]);
                    node.set_ssh_rule("ssh-test".into(), "departed-peer".into(), Vec::new(), false)
                        .unwrap();
                    assert!(node.status().unwrap().ssh_rules.is_empty());
                }
                let after = node.status().unwrap();
                assert!(!after.dns_enabled);
                assert!(!after.mdns_enabled);
                assert!(after.mdns_active, "mDNS stays active until reconnect");
                assert!(matches!(
                    node.connect_peer("invalid contact id".into(), None),
                    Err(AppleError::Network(_))
                ));
                assert!(node.approve_connection("missing".into()).is_err());
                assert!(node.reject_connection("missing".into()).is_err());

                // A self-dial fails immediately, providing an offline inventory
                // entry without relying on an external machine or a network.
                let IpcMessage::StatusResponse { endpoint_id, .. } = node.state().unwrap().status()
                else {
                    panic!("expected node status");
                };
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
                assert_eq!(machines[0].ipv6, before.ipv6);
                assert_eq!(machines[0].state, "offline");
                assert!(machines[0].networks.is_empty());
            } else {
                let restarted = node.status().unwrap();
                assert!(!restarted.dns_enabled);
                assert!(!restarted.mdns_enabled);
                assert!(!restarted.mdns_active);
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
