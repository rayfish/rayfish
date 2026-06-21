use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;

use anyhow::{Context, Result};
use iroh::address_lookup::PkarrRelayClient;
use iroh::endpoint::{Connection, Endpoint};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointId, SecretKey};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, HashAndFormat};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::acl;
use crate::config;
use crate::control::{self, ControlMsg};
use crate::dht;
use crate::dns;
use crate::dns_config;
use crate::firewall::{self, SharedFirewall};
use crate::forward;
use crate::identity;
use crate::ipc::{self, IpcMessage, NetworkRole, NetworkStatus, PeerStatus};
use crate::membership::{
    ApprovedEntry, ApprovedList, GroupMode, IdentityProvider, IrohIdentityProvider, Member,
    MemberList, MembershipPolicy, canonical_group_bytes, derive_ipv6, group_blob_hash,
    policy_for_mode, verify_group_blob,
};
use crate::network_name;
use crate::peers::PeerTable;
use crate::stats::ForwardMetrics;
use crate::transport;
use crate::tun::{self, check_cgnat_conflict};

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

struct CoordinatorAcceptState {
    endpoint: Endpoint,
    network_name: String,
    identity: IrohIdentityProvider,
    policy: Arc<dyn MembershipPolicy>,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
}

impl CoordinatorAcceptState {
    async fn handle_connection(&self, conn: Connection) {
        let remote_id = conn.remote_id();
        let peer_ip = self.identity.derive_ip(&remote_id);

        // Known member reconnecting
        let is_member = self.state.read().unwrap().members.is_member(&remote_id);
        if is_member {
            tracing::info!(ip = %peer_ip, "known member reconnecting");
            let members: Vec<Member> = self
                .state
                .read()
                .unwrap()
                .members
                .all()
                .into_iter()
                .cloned()
                .collect();
            crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
            let peer_ipv6 = derive_ipv6(&remote_id);
            self.peers.add(
                peer_ip,
                peer_ipv6,
                conn.clone(),
                remote_id,
                &self.network_name,
            );
            let token = self.token.clone();
            let stats = self.stats.clone();
            let tun_tx = self.tun_tx.clone();
            let disconnect_tx = self.disconnect_tx.clone();
            let local_id = self.endpoint.id();
            let network = self.network_name.clone();
            let shared_acl = self.shared_acl.clone();
            let firewall = self.firewall.clone();
            let state = self.state.clone();
            let hostname_table = self.hostname_table.clone();
            tokio::spawn(async move {
                send_member_sync(&conn, &members).await;
                spawn_coordinator_hello_reader(
                    conn.clone(),
                    remote_id,
                    peer_ip,
                    &network,
                    state,
                    hostname_table,
                )
                .await;
                forward::spawn_peer_reader(
                    conn,
                    remote_id,
                    peer_ip,
                    peer_ipv6,
                    local_id,
                    network,
                    shared_acl,
                    firewall,
                    tun_tx,
                    disconnect_tx,
                    token,
                    stats,
                );
            });
            return;
        }

        // Approved but not yet connected
        let is_approved = self.state.read().unwrap().approved.is_approved(&remote_id);
        if is_approved {
            tracing::info!(ip = %peer_ip, "approved peer connecting");
            let snap_bytes = {
                let mut s = self.state.write().unwrap();
                s.approved.remove(&remote_id);
                let new_member = Member {
                    identity: remote_id,
                    ip: peer_ip,
                    is_coordinator: false,
                    hostname: None,
                };
                s.members
                    .add(new_member)
                    .expect("was approved, no collision");
                s.refresh_snapshot();
                s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
            };
            if let Some(bytes) = snap_bytes {
                let _ = self.blob_store.blobs().add_slice(&bytes).await;
            }
            if let Some(notify) = &self.dht_notify {
                notify.notify_one();
            }
            let (members, approved) = {
                let s = self.state.read().unwrap();
                (
                    s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                    s.approved.all().into_iter().cloned().collect::<Vec<_>>(),
                )
            };
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(
                    &mut send,
                    &ControlMsg::Welcome {
                        members: members.clone(),
                        approved,
                    },
                )
                .await;
            }
            broadcast_member_sync(&self.peers, &members, Some(peer_ip)).await;
            let peer_ipv6 = derive_ipv6(&remote_id);
            self.peers.add(
                peer_ip,
                peer_ipv6,
                conn.clone(),
                remote_id,
                &self.network_name,
            );
            let token = self.token.clone();
            let stats = self.stats.clone();
            let tun_tx = self.tun_tx.clone();
            let disconnect_tx = self.disconnect_tx.clone();
            let local_id = self.endpoint.id();
            let network = self.network_name.clone();
            let shared_acl = self.shared_acl.clone();
            let firewall = self.firewall.clone();
            let state = self.state.clone();
            let hostname_table = self.hostname_table.clone();
            let dht_notify = self.dht_notify.clone();
            let blob_store = self.blob_store.clone();
            tokio::spawn(async move {
                spawn_coordinator_hello_reader(
                    conn.clone(),
                    remote_id,
                    peer_ip,
                    &network,
                    state.clone(),
                    hostname_table,
                )
                .await;
                update_snapshot_and_publish(&state, &blob_store, &dht_notify).await;
                forward::spawn_peer_reader(
                    conn,
                    remote_id,
                    peer_ip,
                    peer_ipv6,
                    local_id,
                    network,
                    shared_acl,
                    firewall,
                    tun_tx,
                    disconnect_tx,
                    token,
                    stats,
                );
            });
            return;
        }

        // Unknown peer — check policy
        let self_member = {
            let s = self.state.read().unwrap();
            s.members
                .get(&self.identity.local_identity())
                .cloned()
                .unwrap()
        };
        if !self.policy.can_authorize(&self_member) {
            tracing::warn!(peer = %remote_id, "not authorized to accept new members");
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(
                    &mut send,
                    &ControlMsg::JoinDenied {
                        reason: "not authorized".to_string(),
                    },
                )
                .await;
            }
            return;
        }

        // Check IP collision
        let collision_reason: Option<String> = {
            let s = self.state.read().unwrap();
            if let Some(existing) = s.members.get_by_ip(peer_ip)
                && existing.identity != remote_id
            {
                Some(format!("IP collision: {} already assigned", peer_ip))
            } else if let Some(existing) = s.approved.get_by_ip(peer_ip)
                && existing.identity != remote_id
            {
                Some(format!("IP collision: {} already assigned", peer_ip))
            } else {
                None
            }
        };
        if let Some(reason) = collision_reason {
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(&mut send, &ControlMsg::JoinDenied { reason }).await;
            }
            return;
        }

        // Broadcast MemberApproved (hostname will be updated after MeshHello)
        broadcast_control_msg(
            &self.peers,
            &ControlMsg::MemberApproved {
                identity: remote_id,
                ip: peer_ip,
                hostname: None,
            },
        )
        .await;

        // Promote to member
        let (add_collision, snap_bytes): (Option<String>, Option<Vec<u8>>) = {
            let mut s = self.state.write().unwrap();
            let result = s
                .members
                .add(Member {
                    identity: remote_id,
                    ip: peer_ip,
                    is_coordinator: false,
                    hostname: None,
                })
                .err()
                .map(|e| format!("IP collision: {e}"));
            if result.is_none() {
                s.refresh_snapshot();
            }
            let bytes = s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone());
            (result, bytes)
        };
        if add_collision.is_none()
            && let Some(bytes) = snap_bytes
        {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }
        if let Some(reason) = add_collision {
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(&mut send, &ControlMsg::JoinDenied { reason }).await;
            }
            return;
        }

        let (members, approved) = {
            let s = self.state.read().unwrap();
            (
                s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                s.approved.all().into_iter().cloned().collect::<Vec<_>>(),
            )
        };

        tracing::info!(ip = %peer_ip, "new member approved and joined");
        if let Some(notify) = &self.dht_notify {
            notify.notify_one();
        }

        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(
                &mut send,
                &ControlMsg::Welcome {
                    members: members.clone(),
                    approved,
                },
            )
            .await;
        }
        broadcast_member_sync(&self.peers, &members, Some(peer_ip)).await;
        let peer_ipv6 = derive_ipv6(&remote_id);
        self.peers.add(
            peer_ip,
            peer_ipv6,
            conn.clone(),
            remote_id,
            &self.network_name,
        );
        let token = self.token.clone();
        let stats = self.stats.clone();
        let tun_tx = self.tun_tx.clone();
        let disconnect_tx = self.disconnect_tx.clone();
        let local_id = self.endpoint.id();
        let network = self.network_name.clone();
        let shared_acl = self.shared_acl.clone();
        let firewall = self.firewall.clone();
        let state = self.state.clone();
        let hostname_table = self.hostname_table.clone();
        let dht_notify = self.dht_notify.clone();
        let blob_store = self.blob_store.clone();
        tokio::spawn(async move {
            spawn_coordinator_hello_reader(
                conn.clone(),
                remote_id,
                peer_ip,
                &network,
                state.clone(),
                hostname_table,
            )
            .await;
            update_snapshot_and_publish(&state, &blob_store, &dht_notify).await;
            forward::spawn_peer_reader(
                conn,
                remote_id,
                peer_ip,
                peer_ipv6,
                local_id,
                network,
                shared_acl,
                firewall,
                tun_tx,
                disconnect_tx,
                token,
                stats,
            );
        });
    }
}

struct MemberAcceptState {
    endpoint: Endpoint,
    network_name: String,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
}

impl MemberAcceptState {
    async fn handle_connection(&self, conn: Connection) {
        let Ok((_send, mut recv)) = conn.accept_bi().await else {
            return;
        };
        let transport_id = conn.remote_id();
        match control::recv_msg(&mut recv).await {
            Ok(ControlMsg::MeshHello {
                identity: peer_identity,
                ip,
                hostname,
            }) => {
                if peer_identity != transport_id {
                    return;
                }
                let (is_member, is_approved) = {
                    let s = self.state.read().unwrap();
                    (
                        s.members.is_member(&peer_identity),
                        s.approved.is_approved(&peer_identity),
                    )
                };
                // Resolve hostname collisions
                let final_hostname = if let Some(desired) = hostname {
                    let taken: Vec<String> = {
                        let s = self.state.read().unwrap();
                        s.members
                            .all()
                            .iter()
                            .filter(|m| m.identity != peer_identity)
                            .filter_map(|m| m.hostname.clone())
                            .collect()
                    };
                    let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
                    Some(crate::hostname::resolve_collision(&desired, &taken_refs))
                } else {
                    None
                };
                // Update DNS table
                if let Some(ref h) = final_hostname {
                    let mut table = self.hostname_table.write().await;
                    let network_hosts = table.entry(self.network_name.clone()).or_default();
                    network_hosts.insert(h.clone(), (ip, derive_ipv6(&peer_identity)));
                }
                if is_approved {
                    let snap_bytes = {
                        let mut s = self.state.write().unwrap();
                        s.approved.remove(&peer_identity);
                        let _ = s.members.add(Member {
                            identity: peer_identity,
                            ip,
                            is_coordinator: false,
                            hostname: final_hostname.clone(),
                        });
                        s.refresh_snapshot();
                        s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
                    };
                    if let Some(bytes) = snap_bytes {
                        let _ = self.blob_store.blobs().add_slice(&bytes).await;
                    }
                    let (members, approved_list) = {
                        let s = self.state.read().unwrap();
                        (
                            s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                            s.approved.all().into_iter().cloned().collect::<Vec<_>>(),
                        )
                    };
                    if let Ok((mut send, _)) = conn.open_bi().await {
                        let _ = control::send_msg(
                            &mut send,
                            &ControlMsg::Welcome {
                                members: members.clone(),
                                approved: approved_list,
                            },
                        )
                        .await;
                    }
                    let peer_ipv6 = derive_ipv6(&peer_identity);
                    self.peers.add(
                        ip,
                        peer_ipv6,
                        conn.clone(),
                        peer_identity,
                        &self.network_name,
                    );
                    forward::spawn_peer_reader(
                        conn,
                        peer_identity,
                        ip,
                        peer_ipv6,
                        self.endpoint.id(),
                        self.network_name.clone(),
                        self.shared_acl.clone(),
                        self.firewall.clone(),
                        self.tun_tx.clone(),
                        self.disconnect_tx.clone(),
                        self.token.clone(),
                        self.stats.clone(),
                    );
                    broadcast_member_sync(&self.peers, &members, Some(ip)).await;
                } else if is_member {
                    if final_hostname.is_some() {
                        let mut s = self.state.write().unwrap();
                        if let Some(m) = s.members.get_mut(&peer_identity) {
                            m.hostname = final_hostname;
                        }
                    }
                    let peer_ipv6 = derive_ipv6(&peer_identity);
                    self.peers.add(
                        ip,
                        peer_ipv6,
                        conn.clone(),
                        peer_identity,
                        &self.network_name,
                    );
                    forward::spawn_peer_reader(
                        conn,
                        peer_identity,
                        ip,
                        peer_ipv6,
                        self.endpoint.id(),
                        self.network_name.clone(),
                        self.shared_acl.clone(),
                        self.firewall.clone(),
                        self.tun_tx.clone(),
                        self.disconnect_tx.clone(),
                        self.token.clone(),
                        self.stats.clone(),
                    );
                }
            }
            Ok(ControlMsg::ReconnectRequest {
                identity: peer_identity,
                ip,
            }) => {
                if peer_identity != transport_id {
                    return;
                }
                let is_known = self.state.read().unwrap().members.is_member(&peer_identity);
                if is_known {
                    let peer_ipv6 = derive_ipv6(&peer_identity);
                    self.peers.add(
                        ip,
                        peer_ipv6,
                        conn.clone(),
                        peer_identity,
                        &self.network_name,
                    );
                    let current_members: Vec<Member> = self
                        .state
                        .read()
                        .unwrap()
                        .members
                        .all()
                        .into_iter()
                        .cloned()
                        .collect();
                    if let Ok((mut send, _)) = conn.open_bi().await {
                        let _ = control::send_msg(
                            &mut send,
                            &ControlMsg::MemberSync {
                                members: current_members,
                            },
                        )
                        .await;
                    }
                    forward::spawn_peer_reader(
                        conn,
                        peer_identity,
                        ip,
                        peer_ipv6,
                        self.endpoint.id(),
                        self.network_name.clone(),
                        self.shared_acl.clone(),
                        self.firewall.clone(),
                        self.tun_tx.clone(),
                        self.disconnect_tx.clone(),
                        self.token.clone(),
                        self.stats.clone(),
                    );
                }
            }
            _ => {}
        }
    }
}

enum AcceptHandler {
    Coordinator(Arc<CoordinatorAcceptState>),
    Member(Arc<MemberAcceptState>),
}

struct MeshProtocol {
    handler: AcceptHandler,
}

impl std::fmt::Debug for MeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshProtocol").finish()
    }
}

impl ProtocolHandler for MeshProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        match &self.handler {
            AcceptHandler::Coordinator(state) => state.handle_connection(conn).await,
            AcceptHandler::Member(state) => state.handle_connection(conn).await,
        }
        Ok(())
    }
}

struct PendingFile {
    id: u64,
    from: EndpointId,
    filename: String,
    size: u64,
    mime_type: String,
    blob_hash: blake3::Hash,
}

struct ProtocolRouter {
    blobs: BlobsProtocol,
    handlers: DashMap<Vec<u8>, Arc<MeshProtocol>>,
    pending_files: Arc<std::sync::Mutex<Vec<PendingFile>>>,
    file_id_counter: Arc<AtomicU64>,
}

impl ProtocolRouter {
    fn new(blobs: BlobsProtocol) -> Self {
        Self {
            blobs,
            handlers: DashMap::new(),
            pending_files: Arc::new(std::sync::Mutex::new(Vec::new())),
            file_id_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    fn register(&self, alpn: Vec<u8>, handler: AcceptHandler) {
        self.handlers
            .insert(alpn, Arc::new(MeshProtocol { handler }));
    }

    fn unregister(&self, alpn: &[u8]) {
        self.handlers.remove(alpn);
    }

    fn alpns(&self) -> Vec<Vec<u8>> {
        let mut alpns: Vec<Vec<u8>> = self.handlers.iter().map(|r| r.key().clone()).collect();
        alpns.push(iroh_blobs::protocol::ALPN.to_vec());
        alpns.push(transport::FILES_ALPN.to_vec());
        alpns
    }

    fn spawn_accept_loop(
        self: &Arc<Self>,
        endpoint: Endpoint,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let router = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { return };
                        let router = router.clone();
                        tokio::spawn(async move {
                            let conn = match incoming.await {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::debug!(error = ?e, "incoming handshake failed");
                                    return;
                                }
                            };
                            let alpn = conn.alpn().to_vec();
                            match alpn.as_slice() {
                                a if a == iroh_blobs::protocol::ALPN => {
                                    let _ = router.blobs.clone().accept(conn).await;
                                }
                                a if a == transport::FILES_ALPN => {
                                    let pending = router.pending_files.clone();
                                    let counter = router.file_id_counter.clone();
                                    let remote_id = conn.remote_id();
                                    match conn.accept_bi().await {
                                        Ok((_send, mut recv)) => {
                                            match control::recv_msg(&mut recv).await {
                                                Ok(control::ControlMsg::FileOffer { from, filename, size, mime_type, blob_hash }) => {
                                                    if from == remote_id {
                                                        let id = counter.fetch_add(1, Ordering::Relaxed);
                                                        tracing::info!(from = %from.fmt_short(), filename = %filename, size, "file offer received");
                                                        pending.lock().unwrap().push(PendingFile { id, from, filename, size, mime_type, blob_hash });
                                                    } else {
                                                        tracing::warn!(claimed = %from.fmt_short(), actual = %remote_id.fmt_short(), "file offer identity mismatch");
                                                    }
                                                }
                                                Ok(other) => {
                                                    tracing::warn!(msg = ?other, "unexpected control message on FILES_ALPN");
                                                }
                                                Err(e) => {
                                                    tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read file offer");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for file offer");
                                        }
                                    }
                                }
                                _ => {
                                    if let Some(handler) = router.handlers.get(&alpn).map(|r| r.clone()) {
                                        let _ = handler.accept(conn).await;
                                    } else {
                                        tracing::warn!(
                                            alpn = %String::from_utf8_lossy(&alpn),
                                            "no handler for ALPN"
                                        );
                                    }
                                }
                            }
                        });
                    }
                }
            }
        })
    }
}

#[derive(Clone)]
struct GroupSnapshot {
    hash: blake3::Hash,
    msgpack_bytes: Vec<u8>,
}

struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
    snapshot: Option<GroupSnapshot>,
    acl: acl::AclData,
    network_secret_key: Option<SecretKey>,
    network_public_key: EndpointId,
    network_name: Option<String>,
}

impl NetworkState {
    fn refresh_snapshot(&mut self) {
        let bytes = canonical_group_bytes(
            &self.members,
            &self.approved,
            &self.acl,
            self.network_name.as_deref(),
        );
        let hash = blake3::hash(&bytes);
        self.snapshot = Some(GroupSnapshot {
            hash,
            msgpack_bytes: bytes,
        });
    }
}

#[allow(dead_code)]
pub struct NetworkHandle {
    name: String,
    network_key: EndpointId,
    role: NetworkRole,
    my_ip: Ipv4Addr,
    state: Arc<std::sync::RwLock<NetworkState>>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

pub struct DaemonState {
    endpoint: Endpoint,
    identity: IrohIdentityProvider,
    peers: PeerTable,
    stats: Arc<ForwardMetrics>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    networks: Arc<DashMap<String, NetworkHandle>>,
    shutdown_token: CancellationToken,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    protocol_router: Arc<ProtocolRouter>,
    hostname_table: dns::HostnameTable,
    mdns_enabled: bool,
    tun_name: String,
}

impl DaemonState {
    fn refresh_alpns(&self) {
        let alpns = self.protocol_router.alpns();
        let alpn_strs: Vec<String> = alpns
            .iter()
            .map(|a| String::from_utf8_lossy(a).to_string())
            .collect();
        tracing::info!(alpns = ?alpn_strs, "refreshing ALPNs");
        self.endpoint.set_alpns(alpns);

        let network_names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        dns_config::update_search_domains(&network_names, &self.tun_name);
    }

    async fn handle_request(&self, req: IpcMessage, peer_cred: Option<(u32, u32)>) -> IpcMessage {
        match req {
            IpcMessage::Create {
                mode,
                name,
                hostname,
                transport: _,
            } => self.create_network(mode, name, hostname).await,
            IpcMessage::Join {
                network_key,
                name,
                hostname,
                transport: _,
            } => {
                self.join_network(&network_key, name.as_deref(), hostname)
                    .await
            }
            IpcMessage::Leave { name } => self.leave_network(&name).await,
            IpcMessage::Nuke { name, force } => self.nuke_network(&name, force).await,
            IpcMessage::Status => self.status(),
            IpcMessage::Shutdown => {
                self.shutdown_token.cancel();
                IpcMessage::Ok {
                    message: "shutting down".to_string(),
                }
            }
            IpcMessage::AclTag {
                network,
                tag,
                peer_ids,
            } => self.acl_tag(&network, &tag, &peer_ids).await,
            IpcMessage::AclUntag {
                network,
                tag,
                peer_id,
            } => self.acl_untag(&network, &tag, &peer_id).await,
            IpcMessage::AclAllow { network, src, dst } => {
                self.acl_allow(&network, &src, &dst).await
            }
            IpcMessage::AclRemove { network, index } => self.acl_remove(&network, index).await,
            IpcMessage::AclShow { network } => self.acl_show(&network),
            IpcMessage::AclApply { network } => self.acl_apply(&network).await,
            IpcMessage::FirewallAdd {
                direction,
                action,
                protocol,
                port,
                peer,
            } => self.firewall_add(
                &direction,
                &action,
                &protocol,
                port.as_deref(),
                peer.as_deref(),
            ),
            IpcMessage::FirewallRemove { index } => self.firewall_remove(index),
            IpcMessage::FirewallShow => self.firewall_show(),
            IpcMessage::FirewallDefault { action } => self.firewall_default(&action),
            IpcMessage::SetHostname { network, hostname } => {
                self.set_hostname(&network, &hostname).await
            }
            IpcMessage::SendFile { path, peer } => self.send_file(&path, &peer).await,
            IpcMessage::ListFiles => self.list_files(),
            IpcMessage::AcceptFile { id, output } => self.accept_file(id, output, peer_cred).await,
            other => IpcMessage::Error {
                message: format!("unexpected message: {:?}", other),
            },
        }
    }

    async fn create_network(
        &self,
        mode: GroupMode,
        name: Option<String>,
        hostname: Option<String>,
    ) -> IpcMessage {
        match self.create_network_inner(mode, name, hostname).await {
            Ok(resp) => resp,
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    async fn create_network_inner(
        &self,
        mode: GroupMode,
        custom_name: Option<String>,
        hostname: Option<String>,
    ) -> Result<IpcMessage> {
        let name = match custom_name {
            Some(n) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&n),
                    "invalid network name '{n}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                n
            }
            None => network_name::generate_name(),
        };

        // Generate per-network keypair
        let net_secret_key = SecretKey::generate();
        let net_public_key = net_secret_key.public();

        if self.networks.contains_key(&name) {
            return Ok(IpcMessage::Error {
                message: format!("network '{name}' already active"),
            });
        }

        let my_ip = self.identity.local_ip();
        let policy = policy_for_mode(mode);

        let my_hostname = match hostname {
            Some(h) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&h),
                    "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                h
            }
            None => crate::hostname::generate_hostname(),
        };

        let mut member_list = MemberList::new();
        member_list
            .add(Member {
                identity: self.identity.local_identity(),
                ip: my_ip,
                is_coordinator: true,
                hostname: Some(my_hostname.clone()),
            })
            .expect("self-add cannot collide");

        // Register in DNS hostname table
        {
            let mut table = self.hostname_table.write().await;
            let network_hosts = table.entry(name.clone()).or_default();
            network_hosts.insert(
                my_hostname.clone(),
                (my_ip, derive_ipv6(&self.identity.local_identity())),
            );
        }

        let mut net_state = NetworkState {
            members: member_list,
            approved: ApprovedList::new(),
            snapshot: None,
            acl: acl::AclData::empty(),
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_public_key,
            network_name: Some(name.clone()),
        };

        // Load ACL from file if it exists
        let acl_path = self.acl_file_path(&name);
        if acl_path.exists()
            && let Ok(content) = std::fs::read_to_string(&acl_path)
        {
            let resolver = |short: &str| -> Option<EndpointId> {
                net_state
                    .members
                    .all()
                    .iter()
                    .find(|m| m.identity.to_string().starts_with(short))
                    .map(|m| m.identity)
            };
            if let Ok(data) = acl::parse_acl_file(&content, &resolver) {
                tracing::info!(network = %name, "loaded ACL from file on create");
                net_state.acl = data;
            }
        }

        net_state.refresh_snapshot();
        if let Some(snap) = &net_state.snapshot {
            let _ = self.blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }

        // Publish single pkarr record
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            let blob_hash = net_state
                .snapshot
                .as_ref()
                .map(|s| s.hash)
                .expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                &net_secret_key,
                &blob_hash,
                &[self.endpoint.id()],
            )
            .await
            {
                tracing::warn!(error = %e, "failed to publish network record");
            }
        }

        // Save to config
        let member_entries = net_state
            .members
            .all()
            .into_iter()
            .map(|m| config::MemberEntry {
                identity: m.identity,
                ip: m.ip,
                is_coordinator: m.is_coordinator,
                hostname: m.hostname.clone(),
            })
            .collect();
        let approved_entries = net_state
            .approved
            .all()
            .into_iter()
            .map(|a| config::ApprovedConfigEntry {
                identity: a.identity,
                ip: a.ip,
                hostname: a.hostname.clone(),
            })
            .collect();
        let mut app_config = config::load()?;
        config::upsert_network(
            &mut app_config,
            config::NetworkConfig {
                name: name.clone(),
                group_mode: mode,
                my_ip: Some(my_ip),
                my_hostname: Some(my_hostname.clone()),
                members: member_entries,
                approved: approved_entries,
                network_secret_key: Some(net_secret_key.clone()),
                network_public_key: Some(net_public_key),
                transport: None,
            },
        );
        config::save(&app_config)?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let mut tasks = Vec::new();

        // Network publisher (single pkarr record: blob hash + seed peers)
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_network_publisher(
                pkarr_client,
                net_secret_key.clone(),
                state.clone(),
                self.endpoint.id(),
                self.peers.clone(),
                name.clone(),
                dht_notify.clone(),
                cancel.clone(),
            ));
        }

        // Disconnect handler (coordinator removes dead peers)
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(
            disconnect_rx,
            self.peers.clone(),
            cancel.clone(),
        ));

        // Register protocol handler for this network
        self.protocol_router.register(
            transport::network_alpn(&net_public_key),
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                endpoint: self.endpoint.clone(),
                network_name: name.clone(),
                identity: self.identity.clone(),
                policy: policy.into(),
                state: state.clone(),
                peers: self.peers.clone(),
                tun_tx: self.tun_tx.clone(),
                disconnect_tx,
                token: cancel.clone(),
                stats: self.stats.clone(),
                dht_notify: Some(dht_notify),
                blob_store: self.blob_store.clone(),
                shared_acl: self.shared_acl.clone(),
                firewall: self.firewall.clone(),
                hostname_table: self.hostname_table.clone(),
            })),
        );

        // Update ALPNs
        let handle = NetworkHandle {
            name: name.clone(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            cancel,
            tasks,
        };
        self.networks.insert(name.clone(), handle);
        self.refresh_alpns();

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network created");

        Ok(IpcMessage::Created {
            name,
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        })
    }

    async fn join_network(
        &self,
        network_key: &str,
        name: Option<&str>,
        hostname: Option<String>,
    ) -> IpcMessage {
        match self.join_network_inner(network_key, name, hostname).await {
            Ok(resp) => resp,
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    async fn join_network_inner(
        &self,
        network_key: &str,
        alias: Option<&str>,
        hostname: Option<String>,
    ) -> Result<IpcMessage> {
        let net_pubkey: EndpointId = network_key.parse().context("invalid network key")?;

        if let Some(a) = alias
            && self.networks.contains_key(a)
        {
            return Ok(IpcMessage::Error {
                message: format!("already in network '{a}'"),
            });
        }

        // Resolve single pkarr record → (blob_hash, seed_peers)
        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, peer_ids) = dht::resolve_network(&pkarr_client, net_pubkey)
            .await
            .context("failed to resolve network record")?;

        if peer_ids.is_empty() {
            return Ok(IpcMessage::Error {
                message: "no peers found in network record".to_string(),
            });
        }

        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        let mut group_blob = None;
        for peer_id in &peer_ids {
            match self.try_fetch_group_blob(*peer_id, blob_hash).await {
                Ok(data) => {
                    group_blob = Some(data);
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id.fmt_short(), error = %e, "failed to fetch blob");
                    continue;
                }
            }
        }

        let data = group_blob.context("could not fetch group blob from any peer")?;

        let alpn = transport::network_alpn(&net_pubkey);
        let my_ip = self.identity.local_ip();
        // Use coordinator's network name from GroupBlob, or user alias, or truncated key as fallback
        let blob_name = data
            .name
            .clone()
            .unwrap_or_else(|| network_key[..network_key.len().min(8)].to_string());
        let display_name_owned = alias.map(|a| a.to_string()).unwrap_or(blob_name);
        let display_name = display_name_owned.as_str();

        if self.networks.contains_key(display_name) {
            return Ok(IpcMessage::Error {
                message: format!("already in network '{display_name}'"),
            });
        }

        // Connect to the first reachable peer
        tracing::info!(alpn = %String::from_utf8_lossy(&alpn), peers = peer_ids.len(), "connecting to seed peers");
        let mut initial_conn = None;
        for peer_id in &peer_ids {
            if *peer_id == self.endpoint.id() {
                continue;
            }
            match transport::connect_to_peer_with_alpn(&self.endpoint, *peer_id, &alpn).await {
                Ok(conn) => {
                    initial_conn = Some(conn);
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id.fmt_short(), error = ?e, "failed to connect to seed peer");
                }
            }
        }

        // Fall back to known members from the group blob
        if initial_conn.is_none() {
            let my_identity = self.identity.local_identity();
            for member in &data.members {
                if member.identity == my_identity {
                    continue;
                }
                match transport::connect_to_peer_with_alpn(&self.endpoint, member.identity, &alpn)
                    .await
                {
                    Ok(conn) => {
                        initial_conn = Some(conn);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(peer = %member.identity.fmt_short(), error = %e, "failed to connect to member");
                    }
                }
            }
        }

        let conn = initial_conn.context("could not connect to any peer in the network")?;

        let my_hostname = match hostname {
            Some(h) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&h),
                    "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                h
            }
            None => crate::hostname::generate_hostname(),
        };

        let cancel = self.shutdown_token.child_token();
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

        let tasks = vec![spawn_reconnect_loop(
            disconnect_rx,
            self.endpoint.clone(),
            alpn.clone(),
            display_name.to_string(),
            self.identity.local_identity(),
            my_ip,
            Some(my_hostname.clone()),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
            self.stats.clone(),
            self.shared_acl.clone(),
            self.firewall.clone(),
        )];

        // Apply ACL from group blob
        self.shared_acl.set(display_name, data.acl.clone());

        let state = join_mesh_shared(
            conn,
            &self.endpoint,
            display_name,
            &self.identity,
            &alpn,
            Some(my_hostname.clone()),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
            self.stats.clone(),
            self.blob_store.clone(),
            self.shared_acl.clone(),
            self.firewall.clone(),
            net_pubkey,
        )
        .await?;

        self.protocol_router.register(
            alpn.clone(),
            AcceptHandler::Member(Arc::new(MemberAcceptState {
                endpoint: self.endpoint.clone(),
                network_name: display_name.to_string(),
                state: state.clone(),
                peers: self.peers.clone(),
                tun_tx: self.tun_tx.clone(),
                disconnect_tx,
                token: cancel.clone(),
                stats: self.stats.clone(),
                blob_store: self.blob_store.clone(),
                shared_acl: self.shared_acl.clone(),
                firewall: self.firewall.clone(),
                hostname_table: self.hostname_table.clone(),
            })),
        );

        // Set the network public key and ACL on the state
        {
            let mut s = state.write().unwrap();
            s.network_public_key = net_pubkey;
            s.acl = data.acl;
            s.refresh_snapshot();
        }
        let snap_bytes = state
            .read()
            .unwrap()
            .snapshot
            .as_ref()
            .map(|s| s.msgpack_bytes.clone());
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        // Save config with network public key (use display_name for config)
        if let Ok(mut app_config) = config::load() {
            if let Some(net) = app_config
                .networks
                .iter_mut()
                .find(|n| n.name == display_name)
            {
                net.network_public_key = Some(net_pubkey);
            }
            let _ = config::save(&app_config);
        }

        // Membership poller
        let mut tasks = tasks;
        if let Ok(poller_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_group_poller(
                poller_client,
                net_pubkey,
                state.clone(),
                self.endpoint.clone(),
                self.blob_store.clone(),
                self.peers.clone(),
                display_name.to_string(),
                self.shared_acl.clone(),
                cancel.clone(),
            ));
        }

        let handle = NetworkHandle {
            name: display_name.to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Member,
            my_ip,
            state,
            cancel,
            tasks,
        };
        self.networks.insert(display_name.to_string(), handle);
        self.refresh_alpns();

        // Register hostnames in DNS table
        {
            let mut table = self.hostname_table.write().await;
            let network_hosts = table.entry(display_name.to_string()).or_default();
            network_hosts.insert(
                my_hostname.clone(),
                (my_ip, derive_ipv6(&self.identity.local_identity())),
            );
            // Add any members with known hostnames
            for member in &data.members {
                if let Some(ref h) = member.hostname {
                    network_hosts.insert(h.clone(), (member.ip, derive_ipv6(&member.identity)));
                }
            }
        }

        tracing::info!(network = %display_name, key = %network_key, ip = %my_ip, "joined network");

        Ok(IpcMessage::Joined {
            name: display_name.to_string(),
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        })
    }

    async fn try_fetch_group_blob(
        &self,
        peer_id: EndpointId,
        blob_hash: iroh_blobs::Hash,
    ) -> Result<crate::membership::GroupBlob> {
        let conn = transport::connect_to_peer_with_alpn(
            &self.endpoint,
            peer_id,
            iroh_blobs::protocol::ALPN,
        )
        .await?;
        self.blob_store
            .remote()
            .fetch(conn, HashAndFormat::raw(blob_hash))
            .await
            .map_err(|e| anyhow::anyhow!("blob fetch failed: {e}"))?;
        let bytes = self
            .blob_store
            .blobs()
            .get_bytes(blob_hash)
            .await
            .map_err(|e| anyhow::anyhow!("blob read failed: {e}"))?;
        crate::membership::decode_group_blob(&bytes)
    }

    #[allow(dead_code)]
    async fn try_dht_fallback_join(
        &self,
        network_name: &str,
        net_pubkey: EndpointId,
        alpn: &[u8],
    ) -> Result<IpcMessage> {
        tracing::info!(network = %network_name, "trying DHT fallback");

        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, _peer_ids) = dht::resolve_network(&pkarr_client, net_pubkey).await?;

        let my_identity = self.identity.local_identity();
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        let app_config = config::load()?;
        let net_config = app_config
            .networks
            .iter()
            .find(|n| n.name == network_name)
            .context("network not in config")?;

        for member in &net_config.members {
            if member.identity == my_identity {
                continue;
            }

            let blobs_conn = match transport::connect_to_peer_with_alpn(
                &self.endpoint,
                member.identity,
                iroh_blobs::protocol::ALPN,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => continue,
            };

            if self
                .blob_store
                .remote()
                .fetch(blobs_conn, HashAndFormat::raw(blob_hash))
                .await
                .is_err()
            {
                continue;
            }

            let blob_bytes = match self.blob_store.blobs().get_bytes(blob_hash).await {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            let data = verify_group_blob(&blob_bytes, &expected_hash)?;
            tracing::info!(network = %network_name, members = data.members.len(), "group blob resolved via DHT fallback");

            let my_ip = self.identity.local_ip();
            let my_hostname = net_config.my_hostname.clone();
            let cancel = self.shutdown_token.child_token();
            let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

            let tasks = vec![spawn_reconnect_loop(
                disconnect_rx,
                self.endpoint.clone(),
                alpn.to_vec(),
                network_name.to_string(),
                my_identity,
                my_ip,
                my_hostname.clone(),
                self.peers.clone(),
                self.tun_tx.clone(),
                disconnect_tx.clone(),
                cancel.clone(),
                self.stats.clone(),
                self.shared_acl.clone(),
                self.firewall.clone(),
            )];

            self.shared_acl.set(network_name, data.acl.clone());

            for m in &data.members {
                if m.identity == my_identity {
                    continue;
                }
                if let Ok(peer_conn) =
                    transport::connect_to_peer_with_alpn(&self.endpoint, m.identity, alpn).await
                {
                    if let Ok((mut s, _)) = peer_conn.open_bi().await {
                        let _ = control::send_msg(
                            &mut s,
                            &ControlMsg::MeshHello {
                                identity: my_identity,
                                ip: my_ip,
                                hostname: my_hostname.clone(),
                            },
                        )
                        .await;
                    }
                    crate::spawn_path_logger(peer_conn.clone(), m.identity.fmt_short().to_string());
                    self.peers.add(
                        m.ip,
                        derive_ipv6(&m.identity),
                        peer_conn.clone(),
                        m.identity,
                        network_name,
                    );
                    forward::spawn_peer_reader(
                        peer_conn,
                        m.identity,
                        m.ip,
                        derive_ipv6(&m.identity),
                        self.endpoint.id(),
                        network_name.to_string(),
                        self.shared_acl.clone(),
                        self.firewall.clone(),
                        self.tun_tx.clone(),
                        disconnect_tx.clone(),
                        cancel.clone(),
                        self.stats.clone(),
                    );
                }
            }

            let mut ns = NetworkState {
                members: MemberList::from_members(data.members),
                approved: ApprovedList::from_entries(data.approved),
                snapshot: None,
                acl: data.acl,
                network_secret_key: None,
                network_public_key: net_pubkey,
                network_name: data.name.clone(),
            };
            ns.refresh_snapshot();
            let live_state = Arc::new(std::sync::RwLock::new(ns));

            let handle = NetworkHandle {
                name: network_name.to_string(),
                network_key: net_pubkey,
                role: NetworkRole::Member,
                my_ip,
                state: live_state,
                cancel,
                tasks,
            };
            self.networks.insert(network_name.to_string(), handle);
            self.refresh_alpns();

            return Ok(IpcMessage::Joined {
                name: network_name.to_string(),
                my_ip,
                my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
            });
        }

        anyhow::bail!("no peers reachable for DHT fallback")
    }

    /// Restores a coordinator network from saved config (uses the existing name).
    async fn restore_coordinator_network(
        &self,
        name: &str,
        mode: GroupMode,
    ) -> Result<IpcMessage> {
        {
            if self.networks.contains_key(name) {
                return Ok(IpcMessage::Error {
                    message: format!("network '{name}' already active"),
                });
            }
        }

        let my_ip = self.identity.local_ip();
        let policy = policy_for_mode(mode);

        // Load persisted network secret key from config
        let app_config = config::load()?;
        let net_config = app_config.networks.iter().find(|n| n.name == name);
        let net_secret_key = net_config
            .and_then(|nc| nc.network_secret_key.clone())
            .context("no network secret key in config — cannot restore as coordinator")?;
        let net_public_key = net_secret_key.public();
        let persisted_hostname = net_config.and_then(|nc| nc.my_hostname.clone());

        // Load persisted members and approved entries
        let mut member_list = MemberList::new();
        if let Some(nc) = net_config {
            for entry in &nc.members {
                let _ = member_list.add(Member {
                    identity: entry.identity,
                    ip: entry.ip,
                    is_coordinator: entry.is_coordinator,
                    hostname: entry.hostname.clone(),
                });
            }
        }
        if !member_list.is_member(&self.identity.local_identity()) {
            member_list
                .add(Member {
                    identity: self.identity.local_identity(),
                    ip: my_ip,
                    is_coordinator: true,
                    hostname: persisted_hostname.clone(),
                })
                .expect("self-add cannot collide");
        }

        let mut approved_list = ApprovedList::new();
        if let Some(nc) = net_config {
            for entry in &nc.approved {
                let ae = ApprovedEntry {
                    identity: entry.identity,
                    ip: entry.ip,
                    hostname: entry.hostname.clone(),
                };
                let _ = approved_list.approve(ae, &member_list);
            }
        }

        let mut net_state = NetworkState {
            members: member_list,
            approved: approved_list,
            snapshot: None,
            acl: acl::AclData::empty(),
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_public_key,
            network_name: Some(name.to_string()),
        };

        // Load persisted ACL file if it exists
        let acl_path = self.acl_file_path(name);
        if acl_path.exists()
            && let Ok(content) = std::fs::read_to_string(&acl_path)
        {
            let resolver = |short: &str| -> Option<EndpointId> {
                net_state
                    .members
                    .all()
                    .iter()
                    .find(|m| m.identity.to_string().starts_with(short))
                    .map(|m| m.identity)
            };
            match acl::parse_acl_file(&content, &resolver) {
                Ok(data) => {
                    tracing::info!(network = %name, "restored ACL from file");
                    net_state.acl = data;
                }
                Err(e) => tracing::warn!(error = %e, "failed to parse persisted ACL file"),
            }
        }

        net_state.refresh_snapshot();
        if let Some(snap) = &net_state.snapshot {
            let _ = self.blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }

        // Publish single pkarr record
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            let blob_hash = net_state
                .snapshot
                .as_ref()
                .map(|s| s.hash)
                .expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                &net_secret_key,
                &blob_hash,
                &[self.endpoint.id()],
            )
            .await
            {
                tracing::warn!(error = %e, "failed to publish network record on restore");
            }
        }

        // Update config
        let member_entries = net_state
            .members
            .all()
            .into_iter()
            .map(|m| config::MemberEntry {
                identity: m.identity,
                ip: m.ip,
                is_coordinator: m.is_coordinator,
                hostname: m.hostname.clone(),
            })
            .collect();
        let approved_entries = net_state
            .approved
            .all()
            .into_iter()
            .map(|a| config::ApprovedConfigEntry {
                identity: a.identity,
                ip: a.ip,
                hostname: a.hostname.clone(),
            })
            .collect();
        let mut app_config = config::load()?;
        config::upsert_network(
            &mut app_config,
            config::NetworkConfig {
                name: name.to_string(),
                group_mode: mode,
                my_ip: Some(my_ip),
                my_hostname: persisted_hostname.clone(),
                members: member_entries,
                approved: approved_entries,
                network_secret_key: Some(net_secret_key.clone()),
                network_public_key: Some(net_public_key),
                transport: None,
            },
        );
        config::save(&app_config)?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let mut tasks = Vec::new();

        let dht_notify = Arc::new(tokio::sync::Notify::new());
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_network_publisher(
                pkarr_client,
                net_secret_key.clone(),
                state.clone(),
                self.endpoint.id(),
                self.peers.clone(),
                name.to_string(),
                dht_notify.clone(),
                cancel.clone(),
            ));
        }

        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(
            disconnect_rx,
            self.peers.clone(),
            cancel.clone(),
        ));

        // Sync the restored ACL into the shared ACL state for enforcement
        {
            let s = state.read().unwrap();
            self.shared_acl.set(name, s.acl.clone());
        }

        self.protocol_router.register(
            transport::network_alpn(&net_public_key),
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                endpoint: self.endpoint.clone(),
                network_name: name.to_string(),
                identity: self.identity.clone(),
                policy: policy.into(),
                state: state.clone(),
                peers: self.peers.clone(),
                tun_tx: self.tun_tx.clone(),
                disconnect_tx,
                token: cancel.clone(),
                stats: self.stats.clone(),
                dht_notify: Some(dht_notify),
                blob_store: self.blob_store.clone(),
                shared_acl: self.shared_acl.clone(),
                firewall: self.firewall.clone(),
                hostname_table: self.hostname_table.clone(),
            })),
        );

        // Register hostnames in DNS table
        {
            let members_snapshot: Vec<_> = {
                let s = state.read().unwrap();
                s.members
                    .all()
                    .into_iter()
                    .filter_map(|m| {
                        m.hostname
                            .as_ref()
                            .map(|h| (h.clone(), m.ip, derive_ipv6(&m.identity)))
                    })
                    .collect()
            };
            let mut table = self.hostname_table.write().await;
            let network_hosts = table.entry(name.to_string()).or_default();
            for (hostname, ip, ipv6) in members_snapshot {
                network_hosts.insert(hostname, (ip, ipv6));
            }
        }

        let handle = NetworkHandle {
            name: name.to_string(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            cancel,
            tasks,
        };
        self.networks.insert(name.to_string(), handle);
        self.refresh_alpns();

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network restored (coordinator)");

        Ok(IpcMessage::Created {
            name: name.to_string(),
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        })
    }

    async fn nuke_network(&self, name: &str, force: bool) -> IpcMessage {
        // Check we're the coordinator and whether other members exist
        let (is_coordinator, has_other_members) = {
            let handle = match self.networks.get(name) {
                Some(h) => h,
                None => {
                    return IpcMessage::Error {
                        message: format!("not in network '{name}'"),
                    };
                }
            };
            let state = handle.state.read().unwrap();
            let my_id = self.endpoint.id();
            let is_coord = state
                .members
                .get(&my_id)
                .map(|m| m.is_coordinator)
                .unwrap_or(false);
            let others = state.members.all().len() > 1;
            (is_coord, others)
        };

        if !is_coordinator {
            return IpcMessage::Error {
                message: "only the coordinator can nuke a network".to_string(),
            };
        }

        if has_other_members && !force {
            return IpcMessage::Error {
                message: "network has other members — use --force to destroy, or transfer ownership first".to_string(),
            };
        }

        // Publish empty pkarr record
        let net_secret_key = {
            let handle = self.networks.get(name).unwrap();
            let state = handle.state.read().unwrap();
            state.network_secret_key.clone()
        };
        if let Some(key) = net_secret_key
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let empty_hash = group_blob_hash(
                &MemberList::new(),
                &ApprovedList::new(),
                &acl::AclData::empty(),
                None,
            );
            if let Err(e) = dht::publish_network(&client, &key, &empty_hash, &[]).await {
                tracing::warn!(error = %e, "failed to publish empty network record on nuke");
            }
        }

        // Remove the ACL file for this network
        let acl_path = self.acl_file_path(name);
        let _ = std::fs::remove_file(acl_path);

        // Leave the network (handles cleanup, config removal, etc.)
        self.leave_network(name).await
    }

    async fn leave_network(&self, name: &str) -> IpcMessage {
        let handle = self.networks.remove(name).map(|(_, v)| v);
        let was_active = handle.is_some();

        if let Some(handle) = handle {
            handle.cancel.cancel();
            for task in handle.tasks {
                let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
            }

            self.peers.remove_by_network(name);
            self.shared_acl.remove(name);
            self.protocol_router
                .unregister(&transport::network_alpn(&handle.network_key));
            self.refresh_alpns();
        }

        // Remove from config even if the network wasn't active
        let removed_from_config = if let Ok(mut app_config) = config::load()
            && config::remove_network(&mut app_config, name)
        {
            let _ = config::save(&app_config);
            true
        } else {
            false
        };

        if was_active || removed_from_config {
            tracing::info!(network = %name, "left network");
            IpcMessage::Ok {
                message: format!("left network '{}'", name),
            }
        } else {
            IpcMessage::Error {
                message: format!("network '{}' not found", name),
            }
        }
    }

    fn status(&self) -> IpcMessage {
        let hostname_snapshot = self.hostname_table.try_read().ok();
        let statuses: Vec<NetworkStatus> = self
            .networks
            .iter()
            .map(|h| {
                let peer_entries = self.peers.peers_for_network_with_conn(&h.name);
                let member_count = h.state.read().map(|s| s.members.all().len()).unwrap_or(0);
                let network_key = Some(h.network_key.to_string());
                let peers = peer_entries
                    .into_iter()
                    .map(|(eid, ip, conn)| {
                        let hostname = hostname_snapshot.as_ref().and_then(|table| {
                            table.get(&h.name).and_then(|hosts| {
                                hosts
                                    .iter()
                                    .find(|(_, v)| v.0 == ip)
                                    .map(|(k, _)| k.clone())
                            })
                        });
                        let connection = Self::gather_conn_info(&conn);
                        PeerStatus {
                            endpoint_id: eid,
                            ip,
                            ipv6: Some(derive_ipv6(&eid)),
                            hostname,
                            connection: Some(connection),
                        }
                    })
                    .collect();
                let my_hostname = hostname_snapshot.as_ref().and_then(|table| {
                    table.get(&h.name).and_then(|hosts| {
                        hosts
                            .iter()
                            .find(|(_, v)| v.0 == h.my_ip)
                            .map(|(k, _)| k.clone())
                    })
                });
                NetworkStatus {
                    name: h.name.clone(),
                    role: h.role.clone(),
                    my_ip: h.my_ip,
                    my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
                    my_hostname,
                    network_key,
                    member_count,
                    peers,
                }
            })
            .collect();

        IpcMessage::StatusResponse {
            endpoint_id: self.endpoint.id(),
            mdns_enabled: self.mdns_enabled,
            networks: statuses,
            packets_rx: self.stats.packets_rx.get(),
            packets_tx: self.stats.packets_tx.get(),
            bytes_rx: self.stats.bytes_rx.get(),
            bytes_tx: self.stats.bytes_tx.get(),
        }
    }

    fn gather_conn_info(conn: &iroh::endpoint::Connection) -> ipc::ConnectionInfo {
        let paths = conn.paths();
        let selected = paths.iter().find(|p| p.is_selected());

        let (conn_type, remote_addr, rtt_ms) = match selected {
            Some(path) => {
                let addr = path.remote_addr();
                let ct = if addr.is_relay() {
                    ipc::ConnType::Relay
                } else if addr.is_custom() {
                    ipc::ConnType::Tor
                } else {
                    ipc::ConnType::Direct
                };
                let rtt = path.rtt().as_secs_f64() * 1000.0;
                (ct, Some(addr.to_string()), Some(rtt))
            }
            None => (ipc::ConnType::Unknown, None, None),
        };

        let stats = conn.stats();
        ipc::ConnectionInfo {
            conn_type,
            remote_addr,
            rtt_ms,
            bytes_tx: stats.udp_tx.bytes,
            bytes_rx: stats.udp_rx.bytes,
            datagrams_tx: stats.udp_tx.datagrams,
            datagrams_rx: stats.udp_rx.datagrams,
            lost_packets: stats.lost_packets,
        }
    }

    // -----------------------------------------------------------------------
    // Hostname
    // -----------------------------------------------------------------------

    async fn set_hostname(&self, network: &str, hostname: &str) -> IpcMessage {
        use crate::hostname;

        if !hostname::is_valid_hostname(hostname) {
            return IpcMessage::Error {
                message: "invalid hostname (lowercase ASCII, 1-63 chars)".to_string(),
            };
        }

        let handle = match self.networks.get(network) {
            Some(h) => h,
            None => {
                return IpcMessage::Error {
                    message: format!("network '{}' not found", network),
                };
            }
        };

        let my_ip = handle.my_ip;
        let my_identity = self.endpoint.id();
        let new_hostname = hostname.to_string();

        // Update member list in memory
        if let Ok(mut state) = handle.state.write()
            && let Some(me) = state.members.get_mut(&my_identity)
        {
            me.hostname = Some(new_hostname.clone());
        }

        // Update DNS table: remove old entry for our IP, insert new one
        if let Ok(mut table) = self.hostname_table.try_write() {
            let hosts = table.entry(network.to_string()).or_default();
            hosts.retain(|_, addr| addr.0 != my_ip);
            hosts.insert(
                new_hostname.clone(),
                (my_ip, derive_ipv6(&self.identity.local_identity())),
            );
        }

        // Persist to config
        if let Ok(mut app_config) = config::load() {
            if let Some(net) = app_config.networks.iter_mut().find(|n| n.name == network) {
                net.my_hostname = Some(new_hostname.clone());
            }
            let _ = config::save(&app_config);
        }

        // Re-send MeshHello to all peers on this network
        let peers = self.peers.peers_for_network_with_conn(network);
        for (_peer_id, _peer_ip, conn) in &peers {
            if let Ok((mut send, _recv)) = conn.open_bi().await {
                let msg = ControlMsg::MeshHello {
                    identity: my_identity,
                    ip: my_ip,
                    hostname: Some(new_hostname.clone()),
                };
                let _ = control::send_msg(&mut send, &msg).await;
            }
        }

        let dns_name = format!("{}.{}.{}", new_hostname, network, crate::DNS_DOMAIN);
        IpcMessage::Ok {
            message: format!("hostname set to {} ({})", new_hostname, dns_name),
        }
    }

    // -----------------------------------------------------------------------
    // ACL helpers
    // -----------------------------------------------------------------------

    fn resolve_short_id(&self, network: &str, short: &str) -> Option<EndpointId> {
        if short == "self" {
            return Some(self.endpoint.id());
        }
        let handle = self.networks.get(network)?;
        let state = handle.state.read().unwrap();
        state
            .members
            .all()
            .iter()
            .find(|m| m.identity.to_string().starts_with(short))
            .map(|m| m.identity)
    }

    fn resolve_short_id_any_network(&self, short: &str) -> Option<EndpointId> {
        if short == "self" {
            return Some(self.endpoint.id());
        }
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(m) = state
                .members
                .all()
                .iter()
                .find(|m| m.identity.to_string().starts_with(short))
            {
                return Some(m.identity);
            }
        }
        None
    }

    fn acl_file_path(&self, network: &str) -> std::path::PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("pitopi")
            .join("acl")
            .join(format!("{network}.acl"))
    }

    fn persist_acl(&self, network: &str, data: &acl::AclData) {
        let path = self.acl_file_path(network);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let content = acl::format_acl_file(data, &short_id);
        if let Err(e) = std::fs::write(&path, content) {
            tracing::warn!(error = %e, "failed to persist ACL file");
        }
    }

    async fn publish_and_broadcast_acl(&self, network: &str, data: &acl::AclData) {
        self.shared_acl.set(network, data.clone());

        // Refresh the group blob snapshot and publish to DHT
        let (hash, net_key) = {
            if let Some(handle) = self.networks.get(network) {
                let mut state = handle.state.write().unwrap();
                state.acl = data.clone();
                state.refresh_snapshot();
                let h = state
                    .snapshot
                    .as_ref()
                    .map(|s| s.hash)
                    .expect("snapshot set");
                (h, state.network_secret_key.clone())
            } else {
                return;
            }
        };

        // Store updated blob
        let snap_bytes = {
            self.networks.get(network).and_then(|h| {
                h.state
                    .read()
                    .unwrap()
                    .snapshot
                    .as_ref()
                    .map(|s| s.msgpack_bytes.clone())
            })
        };
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        // Publish to pkarr if we have the secret key
        if let Some(key) = net_key
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let mut seed_peers: Vec<EndpointId> = self
                .peers
                .peers_for_network(network)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            seed_peers.push(self.endpoint.id());
            seed_peers.sort_by_key(|id| id.to_string());
            seed_peers.dedup();
            if let Err(e) = dht::publish_network(&client, &key, &hash, &seed_peers).await {
                tracing::warn!(error = %e, "failed to publish network record after ACL update");
            }
        }

        let msg = ControlMsg::BlobUpdated { hash };
        broadcast_control_msg(&self.peers, &msg).await;
    }

    async fn acl_tag(&self, network: &str, tag: &str, peer_ids: &[String]) -> IpcMessage {
        let mut resolved = Vec::new();
        for short in peer_ids {
            match self.resolve_short_id(network, short) {
                Some(id) => resolved.push(id),
                None => {
                    return IpcMessage::Error {
                        message: format!("unknown peer '{short}'"),
                    };
                }
            }
        }

        {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut state = handle.state.write().unwrap();
            if let Some(assignment) = state.acl.tags.iter_mut().find(|a| a.tag == tag) {
                for id in &resolved {
                    if !assignment.members.contains(id) {
                        assignment.members.push(*id);
                    }
                }
            } else {
                state.acl.tags.push(acl::TagAssignment {
                    tag: tag.to_string(),
                    members: resolved,
                });
            }
        }

        let acl = self
            .networks
            .get(network)
            .unwrap()
            .state
            .read()
            .unwrap()
            .acl
            .clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcMessage::Ok {
            message: format!("tagged '{tag}'"),
        }
    }

    async fn acl_untag(&self, network: &str, tag: &str, peer_id: &str) -> IpcMessage {
        let Some(id) = self.resolve_short_id(network, peer_id) else {
            return IpcMessage::Error {
                message: format!("unknown peer '{peer_id}'"),
            };
        };

        {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut state = handle.state.write().unwrap();
            if let Some(assignment) = state.acl.tags.iter_mut().find(|a| a.tag == tag) {
                assignment.members.retain(|m| m != &id);
            }
            state.acl.tags.retain(|a| !a.members.is_empty());
        }

        let acl = self
            .networks
            .get(network)
            .unwrap()
            .state
            .read()
            .unwrap()
            .acl
            .clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcMessage::Ok {
            message: format!("untagged '{peer_id}' from '{tag}'"),
        }
    }

    async fn acl_allow(&self, network: &str, src: &str, dst: &str) -> IpcMessage {
        let resolve = |s: &str| -> Option<acl::Target> {
            if s == "all" {
                return Some(acl::Target::All);
            }
            if let Some(id) = self.resolve_short_id(network, s) {
                return Some(acl::Target::Identity(id));
            }
            Some(acl::Target::Tag(s.to_string()))
        };

        let Some(src_target) = resolve(src) else {
            return IpcMessage::Error {
                message: format!("unknown src '{src}'"),
            };
        };
        let Some(dst_target) = resolve(dst) else {
            return IpcMessage::Error {
                message: format!("unknown dst '{dst}'"),
            };
        };

        {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut state = handle.state.write().unwrap();
            state.acl.rules.push(acl::AclRule {
                src: src_target,
                dst: dst_target,
            });
        }

        let acl = self
            .networks
            .get(network)
            .unwrap()
            .state
            .read()
            .unwrap()
            .acl
            .clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcMessage::Ok {
            message: format!("added allow {src} -> {dst}"),
        }
    }

    async fn acl_remove(&self, network: &str, index: usize) -> IpcMessage {
        {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut state = handle.state.write().unwrap();
            if index >= state.acl.rules.len() {
                return IpcMessage::Error {
                    message: format!("rule index {index} out of range"),
                };
            }
            state.acl.rules.remove(index);
        }

        let acl = self
            .networks
            .get(network)
            .unwrap()
            .state
            .read()
            .unwrap()
            .acl
            .clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcMessage::Ok {
            message: format!("removed rule {index}"),
        }
    }

    fn acl_show(&self, network: &str) -> IpcMessage {
        let Some(handle) = self.networks.get(network) else {
            return IpcMessage::Error {
                message: format!("network '{network}' not active"),
            };
        };
        let state = handle.state.read().unwrap();
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let display = acl::format_acl_show(&state.acl, &short_id);
        IpcMessage::AclState { display }
    }

    async fn acl_apply(&self, network: &str) -> IpcMessage {
        let path = self.acl_file_path(network);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to read {}: {e}", path.display()),
                };
            }
        };
        let network_str = network.to_string();
        let resolver =
            |short: &str| -> Option<EndpointId> { self.resolve_short_id(&network_str, short) };
        let data = match acl::parse_acl_file(&content, &resolver) {
            Ok(d) => d,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("parse error: {e}"),
                };
            }
        };

        {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut state = handle.state.write().unwrap();
            state.acl = data.clone();
        }

        self.publish_and_broadcast_acl(network, &data).await;
        IpcMessage::Ok {
            message: "ACL applied".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Firewall handlers
    // -----------------------------------------------------------------------

    fn firewall_add(
        &self,
        direction: &str,
        action: &str,
        protocol: &str,
        port: Option<&str>,
        peer: Option<&str>,
    ) -> IpcMessage {
        let direction = match firewall::parse_direction(direction) {
            Ok(d) => d,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let action = match firewall::parse_action(action) {
            Ok(a) => a,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let protocol = match firewall::parse_protocol(protocol) {
            Ok(p) => p,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let port = match port {
            Some(s) => match firewall::parse_port_range(s) {
                Ok(r) => Some(r),
                Err(e) => {
                    return IpcMessage::Error {
                        message: e.to_string(),
                    };
                }
            },
            None => None,
        };
        let peer = match peer {
            Some(s) => match self.resolve_short_id_any_network(s) {
                Some(id) => firewall::PeerFilter::Identity(id),
                None => {
                    return IpcMessage::Error {
                        message: format!("unknown peer '{s}'"),
                    };
                }
            },
            None => firewall::PeerFilter::Any,
        };

        let rule = firewall::FirewallRule {
            direction,
            action,
            protocol,
            port,
            peer,
        };
        let mut config = (*self.firewall.get_config()).clone();
        config.rules.push(rule);
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: "rule added".to_string(),
        }
    }

    fn firewall_remove(&self, index: usize) -> IpcMessage {
        let current = self.firewall.get_config();
        if index >= current.rules.len() {
            return IpcMessage::Error {
                message: format!(
                    "index {index} out of range (have {} rules)",
                    current.rules.len()
                ),
            };
        }
        let mut config = (*current).clone();
        config.rules.remove(index);
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: "rule removed".to_string(),
        }
    }

    fn firewall_show(&self) -> IpcMessage {
        let config = self.firewall.get_config();
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let display = firewall::format_firewall_show(&config, &short_id);
        IpcMessage::FirewallState { display }
    }

    fn firewall_default(&self, action: &str) -> IpcMessage {
        let action = match firewall::parse_action(action) {
            Ok(a) => a,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let mut config = (*self.firewall.get_config()).clone();
        config.default_action = action;
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: format!(
                "default set to {}",
                if action == firewall::Action::Allow {
                    "allow"
                } else {
                    "deny"
                }
            ),
        }
    }

    // -----------------------------------------------------------------------
    // File sharing
    // -----------------------------------------------------------------------

    async fn resolve_peer_name(&self, name: &str) -> Option<EndpointId> {
        let suffix = format!(".{}", crate::DNS_DOMAIN);
        let qualified = if name.ends_with(&suffix) {
            name.to_string()
        } else {
            format!("{name}{suffix}")
        };
        if let Some((ip, _)) = dns::resolve_name(&qualified, &suffix, &self.hostname_table).await {
            // Try connected peers first
            if let Some((_, eid, _)) = self.peers.lookup_v4(&ip) {
                return Some(eid);
            }
            // Fall back to member list (peer may be offline or it's us)
            for entry in self.networks.iter() {
                let state = entry.value().state.read().unwrap();
                if let Some(m) = state.members.all().iter().find(|m| m.ip == ip) {
                    return Some(m.identity);
                }
            }
        }
        self.resolve_short_id_any_network(name)
    }

    async fn send_file(&self, path: &str, peer: &str) -> IpcMessage {
        let peer_id = match self.resolve_peer_name(peer).await {
            Some(id) => id,
            None => {
                return IpcMessage::Error {
                    message: format!("unknown peer '{peer}'"),
                };
            }
        };

        let file_path = std::path::Path::new(path);
        let file_bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot read '{}': {e}", file_path.display()),
                };
            }
        };

        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let size = file_bytes.len() as u64;
        let mime_type = guess_mime_type(&filename);
        let hash = blake3::hash(&file_bytes);

        if let Err(e) = self.blob_store.blobs().add_slice(&file_bytes).await {
            return IpcMessage::Error {
                message: format!("blob store error: {e}"),
            };
        }

        let msg = control::ControlMsg::FileOffer {
            from: self.endpoint.id(),
            filename: filename.clone(),
            size,
            mime_type: mime_type.clone(),
            blob_hash: hash,
        };

        match transport::connect_to_peer_with_alpn(&self.endpoint, peer_id, transport::FILES_ALPN)
            .await
        {
            Ok(conn) => match conn.open_bi().await {
                Ok((mut send, _)) => {
                    if let Err(e) = control::send_msg(&mut send, &msg).await {
                        return IpcMessage::Error {
                            message: format!("failed to send offer: {e}"),
                        };
                    }
                    let _ = send.finish();
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                }
                Err(e) => {
                    return IpcMessage::Error {
                        message: format!("failed to open stream: {e}"),
                    };
                }
            },
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot reach peer '{peer}': {e}"),
                };
            }
        }

        IpcMessage::Ok {
            message: format!("offered {} ({}) to {}", filename, format_size(size), peer),
        }
    }

    fn list_files(&self) -> IpcMessage {
        let pending = self.protocol_router.pending_files.lock().unwrap();
        let files = pending
            .iter()
            .map(|f| ipc::PendingFileInfo {
                id: f.id,
                from: f.from.fmt_short().to_string(),
                filename: f.filename.clone(),
                size: f.size,
                mime_type: f.mime_type.clone(),
            })
            .collect();
        IpcMessage::FileList { files }
    }

    async fn accept_file(&self, id: u64, output: Option<String>, peer_cred: Option<(u32, u32)>) -> IpcMessage {
        let pending_file = {
            let mut pending = self.protocol_router.pending_files.lock().unwrap();
            let idx = pending.iter().position(|f| f.id == id);
            match idx {
                Some(i) => pending.remove(i),
                None => {
                    return IpcMessage::Error {
                        message: format!("no pending file with id {id}"),
                    };
                }
            }
        };

        let blob_hash = iroh_blobs::Hash::from_bytes(*pending_file.blob_hash.as_bytes());

        let conn = match transport::connect_to_peer_with_alpn(
            &self.endpoint,
            pending_file.from,
            iroh_blobs::protocol::ALPN,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot reach sender: {e}"),
                };
            }
        };

        if let Err(e) = self
            .blob_store
            .remote()
            .fetch(conn, iroh_blobs::HashAndFormat::raw(blob_hash))
            .await
        {
            return IpcMessage::Error {
                message: format!("blob fetch failed: {e}"),
            };
        }

        let bytes = match self.blob_store.blobs().get_bytes(blob_hash).await {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("blob read failed: {e}"),
                };
            }
        };

        let dir = match output {
            Some(ref p) => PathBuf::from(p),
            None => dirs::download_dir().unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("Downloads")
            }),
        };

        if let Err(e) = std::fs::create_dir_all(&dir) {
            return IpcMessage::Error {
                message: format!("cannot create directory '{}': {e}", dir.display()),
            };
        }

        let dest = dir.join(&pending_file.filename);
        if let Err(e) = std::fs::write(&dest, &bytes) {
            return IpcMessage::Error {
                message: format!("write failed: {e}"),
            };
        }

        if let Some((uid, gid)) = peer_cred {
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = std::ffi::CString::new(dest.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
            if let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
        }

        IpcMessage::Ok {
            message: format!("saved to {}", dest.display()),
        }
    }
}

fn guess_mime_type(filename: &str) -> String {
    mime_guess::from_path(filename)
        .first_or_octet_stream()
        .to_string()
}

fn format_size(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}

pub async fn run_daemon(token: CancellationToken, stats: Arc<ForwardMetrics>) -> Result<()> {
    // Check for CGNAT conflicts (e.g. Tailscale) before any setup
    check_cgnat_conflict()?;

    let key = identity::load_or_create()?;
    let public_key = key.public();
    let collision_index = identity::load_collision_index()?;
    let identity = IrohIdentityProvider::new(public_key, collision_index);
    let my_ip = identity.local_ip();

    // Load saved networks to determine initial ALPNs
    let app_config = config::load()?;
    let mut alpns: Vec<Vec<u8>> = app_config
        .networks
        .iter()
        .filter_map(|net| net.network_public_key.as_ref().map(transport::network_alpn))
        .collect();

    alpns.push(iroh_blobs::protocol::ALPN.to_vec());
    let use_tor = app_config
        .networks
        .iter()
        .any(|net| net.transport.as_ref().is_some_and(|t| t.is_tor()));
    let ep = transport::create_endpoint_with_alpns(key, alpns, use_tor).await?;

    let blobs_dir = dirs::config_dir()
        .context("no config directory")?
        .join("pitopi")
        .join("blobs");
    std::fs::create_dir_all(&blobs_dir)?;
    let blob_store = FsStore::load(&blobs_dir)
        .await
        .context("failed to open blob store")?;
    let blobs_proto = BlobsProtocol::new(&blob_store, None);

    // Single TUN for all networks
    let my_ipv6 = derive_ipv6(&identity.local_identity());
    let (tun_reader, tun_writer, tun_name) =
        tun::create(my_ip, my_ipv6).context("failed to create TUN device")?;
    let peers = PeerTable::new();
    let shared_acl = forward::SharedAcl::new();
    let fw_config = firewall::load_firewall().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load firewall config, using defaults");
        firewall::FirewallConfig::default()
    });
    let shared_firewall = SharedFirewall::new(fw_config);
    shared_firewall.clone().spawn_evictor(token.clone());
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);
    forward::spawn_tun_writer(tun_writer, tun_rx);
    tokio::spawn(forward::run_mesh(
        tun_reader,
        peers.clone(),
        public_key,
        shared_acl.clone(),
        shared_firewall.clone(),
        token.clone(),
        stats.clone(),
    ));

    let hostname_table = dns::new_hostname_table();

    // Start DNS resolver on 127.0.0.1:53
    let dns_table = hostname_table.clone();
    let dns_token = token.clone();
    tokio::spawn(async move {
        if let Err(e) = dns::spawn_dns_server(dns_table, dns_token).await {
            tracing::warn!(error = %e, "DNS server failed to start (Magic DNS disabled)");
        }
    });

    // Configure system DNS to route .pi queries to 127.0.0.1
    dns_config::restore_stale_backups();
    let dns_configurator = match dns_config::detect_and_configure(&tun_name) {
        Ok(c) => {
            tracing::info!(backend = c.name(), "system DNS configured for .pitopi");
            Some(c)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to configure system DNS (Magic DNS requires manual setup)");
            None
        }
    };

    // mDNS local peer discovery
    let mdns_enabled = app_config.mdns_enabled;
    if mdns_enabled {
        match iroh_mdns_address_lookup::MdnsAddressLookup::builder()
            .service_name("pitopi")
            .advertise(true)
            .build(ep.id())
        {
            Ok(mdns) => {
                if let Ok(lookups) = ep.address_lookup() {
                    lookups.add(mdns.clone());
                    tracing::info!("mDNS discovery enabled (advertising _pitopi._udp.local)");
                    let mdns_token = token.clone();
                    tokio::spawn(async move {
                        use futures::StreamExt;
                        let mut events = mdns.subscribe().await;
                        loop {
                            tokio::select! {
                                _ = mdns_token.cancelled() => break,
                                event = events.next() => {
                                    match event {
                                        Some(iroh_mdns_address_lookup::DiscoveryEvent::Discovered { endpoint_info, .. }) => {
                                            tracing::info!(
                                                peer = %endpoint_info.endpoint_id.fmt_short(),
                                                "mDNS: peer discovered on LAN"
                                            );
                                        }
                                        Some(iroh_mdns_address_lookup::DiscoveryEvent::Expired { endpoint_id }) => {
                                            tracing::info!(
                                                peer = %endpoint_id.fmt_short(),
                                                "mDNS: peer left LAN"
                                            );
                                        }
                                        None => break,
                                        _ => {}
                                    }
                                }
                            }
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to start mDNS discovery");
            }
        }
    } else {
        tracing::info!("mDNS discovery disabled");
    }

    let protocol_router = Arc::new(ProtocolRouter::new(blobs_proto));
    let daemon = Arc::new(DaemonState {
        endpoint: ep,
        identity,
        peers,
        stats: stats.clone(),
        tun_tx,
        networks: Arc::new(DashMap::new()),
        shutdown_token: token.clone(),
        blob_store,
        shared_acl,
        firewall: shared_firewall,
        protocol_router: protocol_router.clone(),
        hostname_table,
        mdns_enabled,
        tun_name: tun_name.clone(),
    });

    // Accept loop — dispatches connections via ProtocolHandler by ALPN
    protocol_router.spawn_accept_loop(daemon.endpoint.clone(), token.clone());

    // Metrics registry: pitopi counters + per-peer gauges + iroh endpoint metrics
    let mut registry = iroh_metrics::Registry::default();
    registry.register(stats.clone());
    let peer_metrics = Arc::new(crate::stats::PeerMetrics::default());
    registry.register(peer_metrics.clone());
    peer_metrics.spawn_collector(daemon.peers.clone(), token.clone());
    registry.register_all(daemon.endpoint.metrics());
    let metrics_addr: SocketAddr = ([0, 0, 0, 0], 9090).into();
    let registry = Arc::new(registry);
    let _metrics_server = match iroh_metrics::service::MetricsServer::spawn(metrics_addr, registry)
        .await
    {
        Ok(server) => {
            tracing::info!(addr = %server.local_addr(), "metrics server started");
            Some(server)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start metrics server (Prometheus export disabled)");
            None
        }
    };

    tracing::info!(ip = %my_ip, id = %daemon.endpoint.id().fmt_short(), "daemon started");

    // Restore saved networks
    for net in &app_config.networks {
        if net.network_secret_key.is_some() {
            // We have the secret key — restore as coordinator
            let name = net.name.clone();
            let mode = net.group_mode;
            let daemon_c = daemon.clone();
            tokio::spawn(async move {
                match daemon_c.restore_coordinator_network(&name, mode).await {
                    Ok(IpcMessage::Created { name, .. }) => {
                        tracing::info!(network = %name, "restored coordinator network");
                    }
                    Ok(IpcMessage::Error { message }) => {
                        tracing::warn!(network = %name, error = %message, "failed to restore network");
                    }
                    Err(e) => {
                        tracing::warn!(network = %name, error = %e, "failed to restore network");
                    }
                    _ => {}
                }
            });
        } else {
            // We're a member — rejoin via DHT lookup
            let name = net.name.clone();
            let persisted_hostname = net.my_hostname.clone();
            let net_pubkey = match &net.network_public_key {
                Some(k) => k.to_string(),
                None => {
                    tracing::warn!(network = %name, "no network public key in config, skipping restore");
                    continue;
                }
            };
            let daemon_c = daemon.clone();
            tokio::spawn(async move {
                match daemon_c
                    .join_network_inner(&net_pubkey, Some(&name), persisted_hostname)
                    .await
                {
                    Ok(IpcMessage::Joined { name, my_ip, .. }) => {
                        tracing::info!(network = %name, ip = %my_ip, "restored member network");
                    }
                    Ok(IpcMessage::Error { message }) => {
                        tracing::warn!(network = %name, error = %message, "failed to restore network");
                    }
                    Err(e) => {
                        tracing::warn!(network = %name, error = %e, "failed to restore network");
                    }
                    _ => {}
                }
            });
        }
    }

    // IPC server
    let socket_path = ipc::socket_path();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path).context("failed to bind IPC socket")?;
    set_socket_group_permissions(&socket_path);
    tracing::info!(path = %socket_path.display(), "IPC socket listening");

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!("daemon shutting down");
                if let Some(ref configurator) = dns_configurator
                    && let Err(e) = configurator.revert() {
                        tracing::warn!(error = %e, "failed to revert DNS configuration");
                    }
                dns_config::clear_search_domains(&tun_name);
                let _ = std::fs::remove_file(&socket_path);
                return Ok(());
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let daemon_c = daemon.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_ipc_client(stream, &daemon_c).await {
                                tracing::debug!(error = %e, "IPC client error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "IPC accept error");
                    }
                }
            }
        }
    }
}

fn set_socket_group_permissions(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return,
    };

    if cfg!(target_os = "macos") {
        unsafe { libc::chmod(c_path.as_ptr(), 0o666) };
        tracing::info!("socket mode 0666 (macOS — any user)");
        return;
    }

    let group_name = CString::new("pitopi").unwrap();
    let grp = unsafe { libc::getgrnam(group_name.as_ptr()) };
    if grp.is_null() {
        tracing::warn!("group 'pitopi' not found — socket only accessible by root");
        return;
    }
    let gid = unsafe { (*grp).gr_gid };
    unsafe { libc::chown(c_path.as_ptr(), 0, gid) };
    unsafe { libc::chmod(c_path.as_ptr(), 0o660) };
    tracing::info!("socket owned by root:pitopi (0660)");
}

async fn handle_ipc_client(stream: UnixStream, daemon: &DaemonState) -> Result<()> {
    let peer_cred = stream.peer_cred().ok().map(|c| (c.uid(), c.gid()));
    let mut framed = ipc::framed(stream);
    let req = ipc::recv(&mut framed).await?;
    let resp = daemon.handle_request(req, peer_cred).await;
    ipc::send(&mut framed, resp).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Network task helpers (extracted from main.rs patterns)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_network_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: Arc<std::sync::RwLock<NetworkState>>,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let hash = {
                let s = state.read().unwrap();
                s.snapshot
                    .as_ref()
                    .map(|snap| snap.hash)
                    .unwrap_or_else(|| {
                        group_blob_hash(&s.members, &s.approved, &s.acl, s.network_name.as_deref())
                    })
            };
            let mut seed_peers: Vec<EndpointId> = peers
                .peers_for_network(&network_name)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            seed_peers.push(endpoint_id);
            seed_peers.sort_by_key(|id| id.to_string());
            seed_peers.dedup();

            match dht::publish_network(&client, &net_secret_key, &hash, &seed_peers).await {
                Ok(()) => tracing::info!(peers = seed_peers.len(), "published network record"),
                Err(e) => tracing::warn!(error = %e, "failed to publish network record"),
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(300)) => {},
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_group_poller(
    client: PkarrRelayClient,
    net_pubkey: EndpointId,
    state: Arc<std::sync::RwLock<NetworkState>>,
    endpoint: Endpoint,
    blob_store: FsStore,
    peers: PeerTable,
    network_name: String,
    shared_acl: forward::SharedAcl,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(60)) => {},
            }

            let current_hash = {
                let s = state.read().unwrap();
                s.snapshot.as_ref().map(|snap| snap.hash)
            };

            let (remote_hash, _seed_peers) = match dht::resolve_network(&client, net_pubkey).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "group poll failed");
                    continue;
                }
            };

            if current_hash == Some(remote_hash) {
                continue;
            }

            tracing::info!(old = ?current_hash, new = %remote_hash, "group blob changed");

            let blob_hash = iroh_blobs::Hash::from_bytes(*remote_hash.as_bytes());

            let peer_ids: Vec<EndpointId> = peers
                .peers_for_network(&network_name)
                .into_iter()
                .map(|(id, _)| id)
                .collect();

            let mut new_data = None;
            for peer_id in &peer_ids {
                let conn = match transport::connect_to_peer_with_alpn(
                    &endpoint,
                    *peer_id,
                    iroh_blobs::protocol::ALPN,
                )
                .await
                {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if blob_store
                    .remote()
                    .fetch(conn, HashAndFormat::raw(blob_hash))
                    .await
                    .is_err()
                {
                    continue;
                }
                match blob_store.blobs().get_bytes(blob_hash).await {
                    Ok(bytes) => match crate::membership::decode_group_blob(&bytes) {
                        Ok(data) => {
                            new_data = Some(data);
                            break;
                        }
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                }
            }

            let Some(data) = new_data else {
                tracing::warn!("could not fetch updated group blob from any peer");
                continue;
            };

            // Reconcile: find removed peers
            let old_members: Vec<EndpointId> = {
                let s = state.read().unwrap();
                s.members.all().iter().map(|m| m.identity).collect()
            };
            let new_member_ids: std::collections::HashSet<EndpointId> =
                data.members.iter().map(|m| m.identity).collect();

            for old_id in &old_members {
                if !new_member_ids.contains(old_id) {
                    let s = state.read().unwrap();
                    if let Some(member) = s.members.get(old_id) {
                        peers.remove(&member.ip, &derive_ipv6(old_id));
                        tracing::info!(peer = %old_id.fmt_short(), "removed kicked peer");
                    }
                }
            }

            let my_id = endpoint.id();
            if !new_member_ids.contains(&my_id)
                && !data.approved.iter().any(|a| a.identity == my_id)
            {
                tracing::warn!("we have been removed from the network");
                break;
            }

            // Update state including ACL
            shared_acl.set(&network_name, data.acl.clone());
            {
                let mut s = state.write().unwrap();
                s.members = MemberList::from_members(data.members);
                s.approved = ApprovedList::from_entries(data.approved);
                s.acl = data.acl;
                s.refresh_snapshot();
            }
        }
    })
}

fn spawn_peer_cleanup(
    mut disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
    peers: PeerTable,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                event = disconnect_rx.recv() => {
                    match event {
                        Some(ev) => {
                            tracing::info!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, "removing dead peer");
                            peers.remove(&ev.ip, &ev.ipv6);
                        }
                        None => return,
                    }
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn spawn_coordinator_hello_reader(
    conn: Connection,
    remote_id: EndpointId,
    peer_ip: Ipv4Addr,
    network_name: &str,
    state: Arc<std::sync::RwLock<NetworkState>>,
    hostname_table: dns::HostnameTable,
) {
    let result: Result<()> = async {
        let (_send, mut recv) = tokio::time::timeout(
            Duration::from_secs(5),
            conn.accept_bi(),
        ).await.context("timeout waiting for MeshHello")?
        .context("accept bi for MeshHello")?;
        let msg = control::recv_msg(&mut recv).await?;
        if let ControlMsg::MeshHello { hostname: Some(desired), .. } = msg {
            let taken: Vec<String> = {
                let s = state.read().unwrap();
                s.members.all().iter()
                    .filter(|m| m.identity != remote_id)
                    .filter_map(|m| m.hostname.clone())
                    .collect()
            };
            let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
            let final_hostname = crate::hostname::resolve_collision(&desired, &taken_refs);
            tracing::info!(peer = %remote_id.fmt_short(), hostname = %final_hostname, "peer hostname via MeshHello");
            {
                let mut s = state.write().unwrap();
                if let Some(m) = s.members.get_mut(&remote_id) {
                    m.hostname = Some(final_hostname.clone());
                }
            }
            {
                let mut table = hostname_table.write().await;
                let network_hosts = table.entry(network_name.to_string()).or_default();
                network_hosts.insert(final_hostname, (peer_ip, derive_ipv6(&remote_id)));
            }
        }
        Ok(())
    }.await;
    if let Err(e) = result {
        tracing::debug!(peer = %remote_id.fmt_short(), error = %e, "failed to read MeshHello from peer");
    }
}

async fn update_snapshot_and_publish(
    state: &Arc<std::sync::RwLock<NetworkState>>,
    blob_store: &FsStore,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
) {
    let snap_bytes = {
        let mut s = state.write().unwrap();
        s.refresh_snapshot();
        s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
    };
    if let Some(bytes) = snap_bytes {
        let _ = blob_store.blobs().add_slice(&bytes).await;
    }
    if let Some(notify) = dht_notify {
        notify.notify_one();
    }
}

#[allow(clippy::too_many_arguments)]
async fn join_mesh_shared(
    initial_conn: Connection,
    ep: &Endpoint,
    network_name: &str,
    identity: &IrohIdentityProvider,
    alpn: &[u8],
    my_hostname: Option<String>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    net_pubkey: EndpointId,
) -> Result<Arc<std::sync::RwLock<NetworkState>>> {
    let my_identity = identity.local_identity();
    let my_ip = identity.local_ip();

    let (_send, mut recv) = initial_conn
        .accept_bi()
        .await
        .context("accept control stream")?;
    let msg = control::recv_msg(&mut recv).await?;
    let (members, approved) = match msg {
        ControlMsg::Welcome { members, approved } => {
            tracing::info!(network = %network_name, "welcomed to network");
            if let Some(existing) = members
                .iter()
                .find(|m| m.ip == my_ip && m.identity != my_identity)
            {
                anyhow::bail!(
                    "IP collision: {} is already assigned to {}",
                    my_ip,
                    existing.identity
                );
            }
            (members, approved)
        }
        ControlMsg::JoinApproved { your_ip, members } => {
            tracing::info!(ip = %your_ip, network = %network_name, "joined network (legacy)");
            (members, vec![])
        }
        ControlMsg::MemberSync { members } => {
            tracing::info!(network = %network_name, "reconnected via peer");
            (members, vec![])
        }
        ControlMsg::JoinDenied { reason } => {
            anyhow::bail!("join denied: {reason}");
        }
        other => {
            anyhow::bail!("expected Welcome or MemberSync, got {other:?}");
        }
    };

    // Save membership to config
    let member_entries: Vec<config::MemberEntry> = members
        .iter()
        .map(|m| config::MemberEntry {
            identity: m.identity,
            ip: m.ip,
            is_coordinator: m.is_coordinator,
            hostname: m.hostname.clone(),
        })
        .collect();
    let approved_config: Vec<config::ApprovedConfigEntry> = approved
        .iter()
        .map(|a| config::ApprovedConfigEntry {
            identity: a.identity,
            ip: a.ip,
            hostname: a.hostname.clone(),
        })
        .collect();
    let persisted_hostname = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone())
        .or(my_hostname.clone());
    let mut app_config = config::load()?;
    config::upsert_network(
        &mut app_config,
        config::NetworkConfig {
            name: network_name.to_string(),
            group_mode: GroupMode::Restricted,
            my_ip: Some(my_ip),
            my_hostname: persisted_hostname,
            members: member_entries,
            approved: approved_config,
            network_secret_key: None,
            network_public_key: Some(net_pubkey),
            transport: None,
        },
    );
    config::save(&app_config)?;

    // Send MeshHello to coordinator so it learns our hostname
    {
        let (mut send, _recv) = initial_conn.open_bi().await?;
        control::send_msg(
            &mut send,
            &ControlMsg::MeshHello {
                identity: my_identity,
                ip: my_ip,
                hostname: my_hostname.clone(),
            },
        )
        .await?;
    }

    // Add initial connection peer
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);
    crate::spawn_path_logger(initial_conn.clone(), remote_id.fmt_short().to_string());
    let remote_ipv6 = derive_ipv6(&remote_id);
    peers.add(
        remote_ip,
        remote_ipv6,
        initial_conn.clone(),
        remote_id,
        network_name,
    );
    forward::spawn_peer_reader(
        initial_conn.clone(),
        remote_id,
        remote_ip,
        remote_ipv6,
        ep.id(),
        network_name.to_string(),
        shared_acl.clone(),
        firewall.clone(),
        tun_tx.clone(),
        disconnect_tx.clone(),
        token.clone(),
        stats.clone(),
    );

    // Connect to other known members
    for member in &members {
        if member.identity == my_identity || member.identity == initial_conn.remote_id() {
            continue;
        }
        match transport::connect_to_peer_with_alpn(ep, member.identity, alpn).await {
            Ok(conn) => {
                let (mut send, _recv) = conn.open_bi().await?;
                control::send_msg(
                    &mut send,
                    &ControlMsg::MeshHello {
                        identity: my_identity,
                        ip: my_ip,
                        hostname: my_hostname.clone(),
                    },
                )
                .await?;
                let member_ipv6 = derive_ipv6(&member.identity);
                peers.add(
                    member.ip,
                    member_ipv6,
                    conn.clone(),
                    member.identity,
                    network_name,
                );
                forward::spawn_peer_reader(
                    conn,
                    member.identity,
                    member.ip,
                    member_ipv6,
                    ep.id(),
                    network_name.to_string(),
                    shared_acl.clone(),
                    firewall.clone(),
                    tun_tx.clone(),
                    disconnect_tx.clone(),
                    token.clone(),
                    stats.clone(),
                );
                tracing::info!(peer_ip = %member.ip, "connected to mesh peer");
            }
            Err(e) => {
                tracing::warn!(peer_ip = %member.ip, error = %e, "mesh peer unavailable");
            }
        }
    }

    let live_state = {
        let mut ns = NetworkState {
            members: MemberList::from_members(members.clone()),
            approved: ApprovedList::from_entries(approved),
            snapshot: None,
            acl: acl::AclData::empty(),
            network_secret_key: None,
            network_public_key: net_pubkey,
            network_name: Some(network_name.to_string()),
        };
        ns.refresh_snapshot();
        if let Some(snap) = &ns.snapshot {
            let _ = blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }
        Arc::new(std::sync::RwLock::new(ns))
    };

    // Control listener
    tokio::spawn({
        let initial_conn = initial_conn.clone();
        let token = token.clone();
        let live_state = live_state.clone();
        let network_name = network_name.to_string();
        let blob_store = blob_store.clone();
        let peers_c = peers.clone();
        let endpoint_c = ep.clone();
        let shared_acl_ctrl = shared_acl.clone();
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = initial_conn.accept_bi() => {
                        match result {
                            Ok((_send, mut recv)) => {
                                match control::recv_msg(&mut recv).await {
                                    Ok(ControlMsg::MemberApproved { identity, ip, hostname }) => {
                                        let entry = ApprovedEntry { identity, ip, hostname };
                                        let mut s = live_state.write().unwrap();
                                        let members = s.members.clone();
                                        let _ = s.approved.approve(entry, &members);
                                    }
                                    Ok(ControlMsg::MemberSync { members }) => {
                                        tracing::info!(count = members.len(), "member list updated");
                                        let snap_bytes = {
                                            let mut s = live_state.write().unwrap();
                                            s.members = MemberList::from_members(members);
                                            s.refresh_snapshot();
                                            s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
                                        };
                                        if let Some(bytes) = snap_bytes {
                                            let _ = blob_store.blobs().add_slice(&bytes).await;
                                        }
                                    }
                                    Ok(ControlMsg::BlobUpdated { hash }) => {
                                        tracing::info!(hash = %hash, "received blob update");
                                        let blob_hash = iroh_blobs::Hash::from_bytes(*hash.as_bytes());
                                        let peer_ids: Vec<EndpointId> = peers_c.peers_for_network(&network_name)
                                            .into_iter().map(|(id, _)| id).collect();
                                        let mut fetched = false;
                                        for pid in &peer_ids {
                                            if let Ok(conn) = transport::connect_to_peer_with_alpn(
                                                &endpoint_c, *pid, iroh_blobs::protocol::ALPN,
                                            ).await
                                                && blob_store.remote().fetch(
                                                    conn, HashAndFormat::raw(blob_hash),
                                                ).await.is_ok()
                                            {
                                                fetched = true;
                                                break;
                                            }
                                        }
                                        if fetched
                                            && let Ok(bytes) = blob_store.blobs().get_bytes(blob_hash).await
                                        {
                                            match crate::membership::verify_group_blob(&bytes, &hash) {
                                                Ok(data) => {
                                                    shared_acl_ctrl.set(&network_name, data.acl.clone());
                                                    let mut s = live_state.write().unwrap();
                                                    s.members = MemberList::from_members(data.members);
                                                    s.approved = ApprovedList::from_entries(data.approved);
                                                    s.acl = data.acl;
                                                    s.refresh_snapshot();
                                                    tracing::info!("group blob updated");
                                                }
                                                Err(e) => tracing::warn!(error = %e, "group blob verification failed"),
                                            }
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(_) => {}
                                }
                            }
                            Err(_) => return,
                        }
                    }
                }
            }
        }
    });

    Ok(live_state)
}

#[allow(clippy::too_many_arguments)]
fn spawn_reconnect_loop(
    mut disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
    ep: Endpoint,
    alpn: Vec<u8>,
    network_name: String,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    my_hostname: Option<String>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                _ = token.cancelled() => return,
                event = disconnect_rx.recv() => match event {
                    Some(ev) => ev,
                    None => return,
                },
            };
            let peer_id = event.endpoint_id;
            let peer_ip = event.ip;
            let peer_ipv6 = event.ipv6;
            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer disconnected, will reconnect");
            peers.remove(&peer_ip, &peer_ipv6);

            let ep = ep.clone();
            let alpn = alpn.clone();
            let network_name = network_name.clone();
            let peers = peers.clone();
            let tun_tx = tun_tx.clone();
            let disconnect_tx = disconnect_tx.clone();
            let token = token.clone();
            let stats = stats.clone();
            let shared_acl = shared_acl.clone();
            let firewall = firewall.clone();
            let my_hostname = my_hostname.clone();

            tokio::spawn(async move {
                let mut backoff = BACKOFF_INITIAL;
                loop {
                    if token.is_cancelled() {
                        return;
                    }
                    tracing::info!(peer = %peer_id.fmt_short(), secs = backoff.as_secs(), "reconnecting in");
                    tokio::select! {
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);

                    match transport::connect_to_peer_with_alpn(&ep, peer_id, &alpn).await {
                        Ok(conn) => {
                            let (mut send, _) = match conn.open_bi().await {
                                Ok(bi) => bi,
                                Err(e) => {
                                    tracing::warn!(error = %e, "reconnect handshake failed");
                                    continue;
                                }
                            };
                            if let Err(e) = control::send_msg(
                                &mut send,
                                &ControlMsg::MeshHello {
                                    identity: my_identity,
                                    ip: my_ip,
                                    hostname: my_hostname.clone(),
                                },
                            )
                            .await
                            {
                                tracing::warn!(error = %e, "reconnect MeshHello failed");
                                continue;
                            }
                            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "reconnected to peer");
                            peers.add(peer_ip, peer_ipv6, conn.clone(), peer_id, &network_name);
                            forward::spawn_peer_reader(
                                conn,
                                peer_id,
                                peer_ip,
                                peer_ipv6,
                                my_identity,
                                network_name,
                                shared_acl,
                                firewall,
                                tun_tx,
                                disconnect_tx,
                                token,
                                stats,
                            );
                            return;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "reconnect attempt failed");
                        }
                    }
                }
            });
        }
    })
}

// ---------------------------------------------------------------------------
// Broadcast helpers (same as main.rs but local to daemon)
// ---------------------------------------------------------------------------

async fn send_member_sync(conn: &Connection, members: &[Member]) {
    if let Ok((mut send, _)) = conn.open_bi().await {
        let _ = control::send_msg(
            &mut send,
            &ControlMsg::MemberSync {
                members: members.to_vec(),
            },
        )
        .await;
    }
}

async fn broadcast_member_sync(
    peers: &PeerTable,
    members: &[Member],
    exclude_ip: Option<Ipv4Addr>,
) {
    let msg = ControlMsg::MemberSync {
        members: members.to_vec(),
    };
    for (ip, conn) in peers.all_connections() {
        if Some(ip) == exclude_ip {
            continue;
        }
        if let Ok((mut send, _)) = conn.open_bi().await
            && let Err(e) = control::send_msg(&mut send, &msg).await
        {
            tracing::warn!(peer_ip = %ip, error = %e, "failed to sync members");
        }
    }
}

async fn broadcast_control_msg(peers: &PeerTable, msg: &ControlMsg) {
    for (_ip, conn) in peers.all_connections() {
        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(&mut send, msg).await;
        }
    }
}
