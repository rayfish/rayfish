//! Swift bindings for the Rayfish core running in an Apple packet tunnel.

#[cfg(target_os = "macos")]
mod apple_tun;
mod migration;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rayfish::config;
#[cfg(target_os = "macos")]
use rayfish::daemon::start_embedded_ipc;
use rayfish::daemon::{DaemonState, build_headless};
use rayfish::invite;
use rayfish::ipc::IpcMessage;
use rayfish::membership;
use rayfish::membership::GroupMode;
use thiserror::Error;
use tokio::runtime::Runtime;
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
    #[error("packet queue is full")]
    PacketQueueFull,
    #[error("{0}")]
    Network(String),
}

#[derive(uniffi::Record)]
pub struct NodeStatus {
    pub active: bool,
    pub ipv6: String,
    pub networks: Vec<Network>,
    pub pending_requests: Vec<JoinRequest>,
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
    pub hostname: String,
    pub ipv6: String,
    pub state: String,
    pub latency_ms: Option<u32>,
    pub is_own_device: bool,
}

#[derive(uniffi::Record)]
pub struct JoinRequest {
    pub network: String,
    pub id: String,
    pub hostname: Option<String>,
    pub waiting_secs: u64,
}

#[uniffi::export(callback_interface)]
pub trait PacketFlow: Send + Sync {
    /// Write one packet received from a Rayfish peer into `NEPacketTunnelFlow`.
    fn write_packet(&self, packet: Vec<u8>);
}

/// One Rayfish node hosted by a packet tunnel provider.
#[derive(uniffi::Object)]
pub struct Node {
    config_dir: PathBuf,
    runtime: Runtime,
    state: Mutex<Option<Arc<DaemonState>>>,
    #[cfg(target_os = "macos")]
    ipc_task: Mutex<Option<JoinHandle<()>>>,
    #[cfg(target_os = "macos")]
    packet_tx: Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
}

impl Node {
    fn state(&self) -> Result<Arc<DaemonState>, AppleError> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or(AppleError::NotStarted)
    }
}

#[uniffi::export]
impl Node {
    #[uniffi::constructor]
    pub fn new(config_dir: String) -> Arc<Self> {
        let config_dir = PathBuf::from(config_dir);
        config::set_config_dir_override(config_dir.clone());
        let runtime = tokio::runtime::Builder::new_multi_thread()
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
            packet_tx: Mutex::new(None),
        })
    }

    /// Start the control plane. This is safe to call more than once.
    pub fn start(&self) -> Result<(), AppleError> {
        if self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(());
        }
        let state = self
            .runtime
            .block_on(async { timeout(START_TIMEOUT, build_headless(true)).await })
            .map_err(|_| AppleError::Network("node start timed out".to_owned()))?
            .map_err(|e| AppleError::Network(e.to_string()))?;
        #[cfg(target_os = "macos")]
        {
            let task = match self.runtime.block_on(start_embedded_ipc(&state)) {
                Ok(task) => task,
                Err(error) => {
                    self.runtime.block_on(state.shutdown_and_close());
                    return Err(AppleError::Network(error.to_string()));
                }
            };
            *self.ipc_task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        }
        let mut slot = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(state);
        }
        Ok(())
    }

    /// Copy legacy launchd state before starting the extension-owned node.
    pub fn migrate_legacy_state(&self, source: String) -> Result<(), AppleError> {
        if self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(AppleError::AlreadyStarted);
        }
        migration::copy_legacy_state(PathBuf::from(source).as_path(), &self.config_dir)
            .map_err(|error| AppleError::Network(error.to_string()))
    }

    /// The stable mesh address that the packet tunnel assigns to this device.
    pub fn ipv6_address(&self) -> Result<String, AppleError> {
        let state = self.state()?;
        let rayfish::ipc::IpcMessage::StatusResponse { endpoint_id, .. } = state.status() else {
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
        Ok(NodeStatus {
            active,
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
        match self.runtime.block_on(state.leave_network(&network)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "node returned an invalid leave response".to_owned(),
            )),
        }
    }

    pub fn set_hostname(&self, network: String, hostname: String) -> Result<(), AppleError> {
        let state = self.state()?;
        match self
            .runtime
            .block_on(state.set_hostname(&network, &hostname))
        {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "node returned an invalid hostname response".to_owned(),
            )),
        }
    }

    pub fn accept_request(&self, network: String, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        match self.runtime.block_on(state.accept_request(&network, &id)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "node returned an invalid approval response".to_owned(),
            )),
        }
    }

    pub fn deny_request(&self, network: String, id: String) -> Result<(), AppleError> {
        let state = self.state()?;
        match state.deny_request(&network, &id) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(AppleError::Network(message)),
            _ => Err(AppleError::Network(
                "node returned an invalid denial response".to_owned(),
            )),
        }
    }

    /// Attach the system packet flow and start forwarding packets.
    pub fn activate(&self, flow: Box<dyn PacketFlow>) -> Result<(), AppleError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = flow;
            Err(AppleError::UnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            let state = self.state()?;
            let mut packet_tx = self.packet_tx.lock().unwrap_or_else(|e| e.into_inner());
            if packet_tx.is_some() {
                return Err(AppleError::AlreadyActive);
            }
            let (tx, rx) = tokio::sync::mpsc::channel(apple_tun::PACKET_QUEUE_CAPACITY);
            let reader = apple_tun::AppleTunReader::new(rx);
            let writer = apple_tun::AppleTunWriter::new(flow);
            self.runtime.block_on(async {
                state.attach_external_tun(reader, writer).await;
            });
            *packet_tx = Some(tx);
            Ok(())
        }
    }

    /// Deliver packets read from `NEPacketTunnelFlow` to the mesh forwarder.
    pub fn receive_packets(&self, packets: Vec<Vec<u8>>) -> Result<(), AppleError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = packets;
            Err(AppleError::UnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            let sender = self
                .packet_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .ok_or(AppleError::NotStarted)?;
            for packet in packets {
                sender
                    .try_send(packet)
                    .map_err(|_| AppleError::PacketQueueFull)?;
            }
            Ok(())
        }
    }

    /// Detach the packet flow but leave mesh control connections alive.
    pub fn deactivate(&self) -> Result<(), AppleError> {
        let state = self.state()?;
        state.detach_tun();
        #[cfg(target_os = "macos")]
        self.packet_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Ok(())
    }

    /// Stop the mesh node and release all persistent-store locks.
    pub fn stop(&self) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner()).take();
        #[cfg(target_os = "macos")]
        self.packet_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(state) = &state {
            state.detach_tun();
        }
        #[cfg(target_os = "macos")]
        let ipc_task = self
            .ipc_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn stop_from_host_thread_releases_state_and_allows_restart() {
        let directory = tempfile::tempdir().unwrap();
        let node = Node::new(directory.path().to_string_lossy().into_owned());
        // Build without binding the installed app's CLI socket on macOS.
        // The second build also checks that stop released the blob store lock.
        for _ in 0..2 {
            let state = node.runtime.block_on(async {
                timeout(START_TIMEOUT, build_headless(false))
                    .await
                    .unwrap()
                    .unwrap()
            });
            *node.state.lock().unwrap() = Some(state);
            let started = Instant::now();
            node.stop();
            eprintln!("host-thread stop took {:?}", started.elapsed());
            assert!(matches!(node.state(), Err(AppleError::NotStarted)));
        }
        node.stop();
    }
}
