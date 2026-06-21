use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, Endpoint};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointId, SecretKey};
use iroh::address_lookup::PkarrRelayClient;
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
use crate::ipc::{self, IpcRequest, IpcResponse, NetworkRole, NetworkStatus, PeerStatus};
use crate::membership::{
    ApprovedEntry, ApprovedList, GroupMode, IdentityProvider, IrohIdentityProvider, Member,
    MemberList, MembershipPolicy, policy_for_mode, canonical_group_bytes,
    group_blob_hash, verify_group_blob,
};
use crate::network_name;
use crate::peers::PeerTable;
use crate::stats::Stats;
use crate::transport;
use crate::tun;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

struct MeshProtocol {
    tx: mpsc::Sender<Connection>,
}

impl std::fmt::Debug for MeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshProtocol").finish()
    }
}

impl ProtocolHandler for MeshProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.tx.send(conn).await.map_err(|_| {
            AcceptError::from_err(std::io::Error::other("network handler closed"))
        })
    }
}

struct ProtocolRouter {
    blobs: BlobsProtocol,
    handlers: DashMap<Vec<u8>, Arc<MeshProtocol>>,
}

impl ProtocolRouter {
    fn new(blobs: BlobsProtocol) -> Self {
        Self {
            blobs,
            handlers: DashMap::new(),
        }
    }

    fn register(&self, alpn: Vec<u8>) -> mpsc::Receiver<Connection> {
        let (tx, rx) = mpsc::channel(32);
        self.handlers.insert(alpn, Arc::new(MeshProtocol { tx }));
        rx
    }

    fn unregister(&self, alpn: &[u8]) {
        self.handlers.remove(alpn);
    }

    fn alpns(&self) -> Vec<Vec<u8>> {
        let mut alpns: Vec<Vec<u8>> = self.handlers.iter().map(|r| r.key().clone()).collect();
        alpns.push(iroh_blobs::protocol::ALPN.to_vec());
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
                            if alpn == iroh_blobs::protocol::ALPN {
                                let blobs = router.blobs.clone();
                                let _ = blobs.accept(conn).await;
                            } else {
                                let handler = router.handlers.get(&alpn).map(|r| r.clone());
                                if let Some(handler) = handler {
                                    let _ = handler.accept(conn).await;
                                } else {
                                    tracing::warn!(
                                        alpn = %String::from_utf8_lossy(&alpn),
                                        "no handler for ALPN"
                                    );
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
        let bytes = canonical_group_bytes(&self.members, &self.approved, &self.acl, self.network_name.as_deref());
        let hash = blake3::hash(&bytes);
        self.snapshot = Some(GroupSnapshot { hash, msgpack_bytes: bytes });
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
    stats: Arc<Stats>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    networks: Arc<DashMap<String, NetworkHandle>>,
    shutdown_token: CancellationToken,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    protocol_router: Arc<ProtocolRouter>,
    hostname_table: dns::HostnameTable,
}

impl DaemonState {
    fn refresh_alpns(&self) {
        let alpns = self.protocol_router.alpns();
        let alpn_strs: Vec<String> = alpns.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect();
        tracing::info!(alpns = ?alpn_strs, "refreshing ALPNs");
        self.endpoint.set_alpns(alpns);
    }

    async fn handle_request(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::Create { mode, hostname } => self.create_network(mode, hostname).await,
            IpcRequest::Join { network_key, name, hostname } => self.join_network(&network_key, name.as_deref(), hostname).await,
            IpcRequest::Leave { name } => self.leave_network(&name).await,
            IpcRequest::Nuke { name, force } => self.nuke_network(&name, force).await,
            IpcRequest::Status => self.status(),
            IpcRequest::Shutdown => {
                self.shutdown_token.cancel();
                IpcResponse::Ok { message: "shutting down".to_string() }
            }
            IpcRequest::AclTag { network, tag, peer_ids } => self.acl_tag(&network, &tag, &peer_ids).await,
            IpcRequest::AclUntag { network, tag, peer_id } => self.acl_untag(&network, &tag, &peer_id).await,
            IpcRequest::AclAllow { network, src, dst } => self.acl_allow(&network, &src, &dst).await,
            IpcRequest::AclRemove { network, index } => self.acl_remove(&network, index).await,
            IpcRequest::AclShow { network } => self.acl_show(&network),
            IpcRequest::AclApply { network } => self.acl_apply(&network).await,
            IpcRequest::FirewallAdd { direction, action, protocol, port, peer } => {
                self.firewall_add(&direction, &action, &protocol, port.as_deref(), peer.as_deref())
            }
            IpcRequest::FirewallRemove { index } => self.firewall_remove(index),
            IpcRequest::FirewallShow => self.firewall_show(),
            IpcRequest::FirewallDefault { action } => self.firewall_default(&action),
        }
    }

    async fn create_network(&self, mode: GroupMode, hostname: Option<String>) -> IpcResponse {
        match self.create_network_inner(mode, hostname).await {
            Ok(resp) => resp,
            Err(e) => IpcResponse::Error { message: format!("{e:#}") },
        }
    }

    async fn create_network_inner(&self, mode: GroupMode, hostname: Option<String>) -> Result<IpcResponse> {
        let name = network_name::generate_name();

        // Generate per-network keypair
        let net_secret_key = SecretKey::generate();
        let net_public_key = net_secret_key.public();

        if self.networks.contains_key(&name) {
            return Ok(IpcResponse::Error {
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
            network_hosts.insert(my_hostname.clone(), my_ip);
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
                net_state.members.all().iter()
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
            let blob_hash = net_state.snapshot.as_ref().map(|s| s.hash).expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                &net_secret_key,
                &blob_hash,
                &[self.endpoint.id()],
            ).await {
                tracing::warn!(error = %e, "failed to publish network record");
            }
        }

        // Save to config
        let member_entries = net_state.members.all().into_iter().map(|m| config::MemberEntry {
            identity: m.identity,
            ip: m.ip,
            is_coordinator: m.is_coordinator,
            hostname: m.hostname.clone(),
        }).collect();
        let approved_entries = net_state.approved.all().into_iter().map(|a| config::ApprovedConfigEntry {
            identity: a.identity,
            ip: a.ip,
            hostname: a.hostname.clone(),
        }).collect();
        let mut app_config = config::load()?;
        config::upsert_network(&mut app_config, config::NetworkConfig {
            name: name.clone(),
            group_mode: mode,
            my_ip: Some(my_ip),
            my_hostname: Some(my_hostname.clone()),
            members: member_entries,
            approved: approved_entries,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: Some(net_public_key),
        });
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
        tasks.push(spawn_peer_cleanup(disconnect_rx, self.peers.clone(), cancel.clone()));

        // Accept loop for this network
        let conn_rx = self.protocol_router.register(transport::network_alpn(&net_public_key));
        let accept_handle = spawn_coordinator_accept(
            self.endpoint.clone(),
            name.clone(),
            conn_rx,
            self.identity.clone(),
            policy,
            state.clone(),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx,
            cancel.clone(),
            self.stats.clone(),
            Some(dht_notify),
            self.blob_store.clone(),
            self.shared_acl.clone(),
            self.firewall.clone(),
            self.hostname_table.clone(),
        );
        tasks.push(accept_handle);

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

        Ok(IpcResponse::Created {
            name,
            network_key: net_public_key,
            my_ip,
        })
    }

    async fn join_network(&self, network_key: &str, name: Option<&str>, hostname: Option<String>) -> IpcResponse {
        match self.join_network_inner(network_key, name, hostname).await {
            Ok(resp) => resp,
            Err(e) => IpcResponse::Error { message: format!("{e:#}") },
        }
    }

    async fn join_network_inner(&self, network_key: &str, alias: Option<&str>, hostname: Option<String>) -> Result<IpcResponse> {
        let net_pubkey: EndpointId = network_key.parse()
            .context("invalid network key")?;

        if let Some(a) = alias
            && self.networks.contains_key(a)
        {
            return Ok(IpcResponse::Error {
                message: format!("already in network '{a}'"),
            });
        }

        // Resolve single pkarr record → (blob_hash, seed_peers)
        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, peer_ids) = dht::resolve_network(&pkarr_client, net_pubkey).await
            .context("failed to resolve network record")?;

        if peer_ids.is_empty() {
            return Ok(IpcResponse::Error {
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
        let blob_name = data.name.clone().unwrap_or_else(|| network_key[..network_key.len().min(8)].to_string());
        let display_name_owned = alias.map(|a| a.to_string()).unwrap_or(blob_name);
        let display_name = display_name_owned.as_str();

        if self.networks.contains_key(display_name) {
            return Ok(IpcResponse::Error {
                message: format!("already in network '{display_name}'"),
            });
        }

        // Connect to the first reachable peer
        tracing::info!(alpn = %String::from_utf8_lossy(&alpn), peers = peer_ids.len(), "connecting to seed peers");
        let mut initial_conn = None;
        for peer_id in &peer_ids {
            if *peer_id == self.endpoint.id() { continue; }
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
                if member.identity == my_identity { continue; }
                match transport::connect_to_peer_with_alpn(&self.endpoint, member.identity, &alpn).await {
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

        let conn_rx = self.protocol_router.register(alpn.clone());
        let state = join_mesh_shared(
            conn,
            &self.endpoint,
            display_name,
            &self.identity,
            &alpn,
            Some(my_hostname.clone()),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx,
            cancel.clone(),
            self.stats.clone(),
            self.blob_store.clone(),
            self.shared_acl.clone(),
            self.firewall.clone(),
            net_pubkey,
            conn_rx,
            self.hostname_table.clone(),
        ).await?;

        // Set the network public key and ACL on the state
        {
            let mut s = state.write().unwrap();
            s.network_public_key = net_pubkey;
            s.acl = data.acl;
            s.refresh_snapshot();
        }
        let snap_bytes = state.read().unwrap().snapshot.as_ref().map(|s| s.msgpack_bytes.clone());
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        // Save config with network public key (use display_name for config)
        if let Ok(mut app_config) = config::load() {
            if let Some(net) = app_config.networks.iter_mut().find(|n| n.name == display_name) {
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
            network_hosts.insert(my_hostname.clone(), my_ip);
            // Add any members with known hostnames
            for member in &data.members {
                if let Some(ref h) = member.hostname {
                    network_hosts.insert(h.clone(), member.ip);
                }
            }
        }

        tracing::info!(network = %display_name, key = %network_key, ip = %my_ip, "joined network");

        Ok(IpcResponse::Joined {
            name: display_name.to_string(),
            my_ip,
        })
    }

    async fn try_fetch_group_blob(
        &self,
        peer_id: EndpointId,
        blob_hash: iroh_blobs::Hash,
    ) -> Result<crate::membership::GroupBlob> {
        let conn = transport::connect_to_peer_with_alpn(
            &self.endpoint, peer_id, iroh_blobs::protocol::ALPN,
        ).await?;
        self.blob_store.remote().fetch(
            conn, HashAndFormat::raw(blob_hash),
        ).await.map_err(|e| anyhow::anyhow!("blob fetch failed: {e}"))?;
        let bytes = self.blob_store.blobs().get_bytes(blob_hash).await
            .map_err(|e| anyhow::anyhow!("blob read failed: {e}"))?;
        crate::membership::decode_group_blob(&bytes)
    }

    #[allow(dead_code)]
    async fn try_dht_fallback_join(&self, network_name: &str, net_pubkey: EndpointId, alpn: &[u8]) -> Result<IpcResponse> {
        tracing::info!(network = %network_name, "trying DHT fallback");

        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, _peer_ids) = dht::resolve_network(&pkarr_client, net_pubkey).await?;

        let my_identity = self.identity.local_identity();
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        let app_config = config::load()?;
        let net_config = app_config.networks.iter()
            .find(|n| n.name == network_name)
            .context("network not in config")?;

        for member in &net_config.members {
            if member.identity == my_identity { continue; }

            let blobs_conn = match transport::connect_to_peer_with_alpn(
                &self.endpoint, member.identity, iroh_blobs::protocol::ALPN,
            ).await {
                Ok(c) => c,
                Err(_) => continue,
            };

            if self.blob_store.remote().fetch(blobs_conn, HashAndFormat::raw(blob_hash)).await.is_err() {
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
                if m.identity == my_identity { continue; }
                if let Ok(peer_conn) = transport::connect_to_peer_with_alpn(&self.endpoint, m.identity, alpn).await {
                    if let Ok((mut s, _)) = peer_conn.open_bi().await {
                        let _ = control::send_msg(&mut s, &ControlMsg::MeshHello { identity: my_identity, ip: my_ip, hostname: my_hostname.clone() }).await;
                    }
                    crate::spawn_path_logger(peer_conn.clone(), m.identity.fmt_short().to_string());
                    self.peers.add(m.ip, peer_conn.clone(), m.identity, network_name);
                    forward::spawn_peer_reader(peer_conn, m.identity, m.ip, self.endpoint.id(), network_name.to_string(), self.shared_acl.clone(), self.firewall.clone(), self.tun_tx.clone(), disconnect_tx.clone(), cancel.clone(), self.stats.clone());
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

            return Ok(IpcResponse::Joined {
                name: network_name.to_string(),
                my_ip,
            });
        }

        anyhow::bail!("no peers reachable for DHT fallback")
    }

    /// Restores a coordinator network from saved config (uses the existing name).
    async fn restore_coordinator_network(&self, name: &str, mode: GroupMode) -> Result<IpcResponse> {
        {
            
            if self.networks.contains_key(name) {
                return Ok(IpcResponse::Error {
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
                let ae = ApprovedEntry { identity: entry.identity, ip: entry.ip, hostname: entry.hostname.clone() };
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
                net_state.members.all().iter()
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
            let blob_hash = net_state.snapshot.as_ref().map(|s| s.hash).expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                &net_secret_key,
                &blob_hash,
                &[self.endpoint.id()],
            ).await {
                tracing::warn!(error = %e, "failed to publish network record on restore");
            }
        }

        // Update config
        let member_entries = net_state.members.all().into_iter().map(|m| config::MemberEntry {
            identity: m.identity,
            ip: m.ip,
            is_coordinator: m.is_coordinator,
            hostname: m.hostname.clone(),
        }).collect();
        let approved_entries = net_state.approved.all().into_iter().map(|a| config::ApprovedConfigEntry {
            identity: a.identity,
            ip: a.ip,
            hostname: a.hostname.clone(),
        }).collect();
        let mut app_config = config::load()?;
        config::upsert_network(&mut app_config, config::NetworkConfig {
            name: name.to_string(),
            group_mode: mode,
            my_ip: Some(my_ip),
            my_hostname: persisted_hostname.clone(),
            members: member_entries,
            approved: approved_entries,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: Some(net_public_key),
        });
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
        tasks.push(spawn_peer_cleanup(disconnect_rx, self.peers.clone(), cancel.clone()));

        // Sync the restored ACL into the shared ACL state for enforcement
        {
            let s = state.read().unwrap();
            self.shared_acl.set(name, s.acl.clone());
        }

        let conn_rx = self.protocol_router.register(transport::network_alpn(&net_public_key));
        let accept_handle = spawn_coordinator_accept(
            self.endpoint.clone(),
            name.to_string(),
            conn_rx,
            self.identity.clone(),
            policy,
            state.clone(),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx,
            cancel.clone(),
            self.stats.clone(),
            Some(dht_notify),
            self.blob_store.clone(),
            self.shared_acl.clone(),
            self.firewall.clone(),
            self.hostname_table.clone(),
        );
        tasks.push(accept_handle);

        // Register hostnames in DNS table
        {
            let members_snapshot: Vec<_> = {
                let s = state.read().unwrap();
                s.members.all().into_iter().filter_map(|m| {
                    m.hostname.as_ref().map(|h| (h.clone(), m.ip))
                }).collect()
            };
            let mut table = self.hostname_table.write().await;
            let network_hosts = table.entry(name.to_string()).or_default();
            for (hostname, ip) in members_snapshot {
                network_hosts.insert(hostname, ip);
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

        Ok(IpcResponse::Created {
            name: name.to_string(),
            network_key: net_public_key,
            my_ip,
        })
    }

    async fn nuke_network(&self, name: &str, force: bool) -> IpcResponse {
        // Check we're the coordinator and whether other members exist
        let (is_coordinator, has_other_members) = {
            
            let handle = match self.networks.get(name) {
                Some(h) => h,
                None => return IpcResponse::Error {
                    message: format!("not in network '{name}'"),
                },
            };
            let state = handle.state.read().unwrap();
            let my_id = self.endpoint.id();
            let is_coord = state.members.get(&my_id)
                .map(|m| m.is_coordinator)
                .unwrap_or(false);
            let others = state.members.all().len() > 1;
            (is_coord, others)
        };

        if !is_coordinator {
            return IpcResponse::Error {
                message: "only the coordinator can nuke a network".to_string(),
            };
        }

        if has_other_members && !force {
            return IpcResponse::Error {
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
            let empty_hash = group_blob_hash(&MemberList::new(), &ApprovedList::new(), &acl::AclData::empty(), None);
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

    async fn leave_network(&self, name: &str) -> IpcResponse {
        let handle = self.networks.remove(name).map(|(_, v)| v);
        let Some(handle) = handle else {
            return IpcResponse::Error {
                message: format!("network '{}' not active", name),
            };
        };

        handle.cancel.cancel();
        for task in handle.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }

        self.peers.remove_by_network(name);
        self.shared_acl.remove(name);
        self.protocol_router.unregister(&transport::network_alpn(&handle.network_key));
        self.refresh_alpns();

        // Remove from config
        if let Ok(mut app_config) = config::load()
            && config::remove_network(&mut app_config, name)
        {
            let _ = config::save(&app_config);
        }

        tracing::info!(network = %name, "left network");
        IpcResponse::Ok { message: format!("left network '{}'", name) }
    }

    fn status(&self) -> IpcResponse {
        let hostname_snapshot = self.hostname_table.try_read().ok();
        let statuses: Vec<NetworkStatus> = self.networks.iter().map(|h| {
            let peer_entries = self.peers.peers_for_network_with_conn(&h.name);
            let member_count = h.state.read().map(|s| s.members.all().len()).unwrap_or(0);
            let network_key = Some(h.network_key.to_string());
            let peers = peer_entries.into_iter().map(|(eid, ip, conn)| {
                let hostname = hostname_snapshot.as_ref().and_then(|table| {
                    table.get(&h.name).and_then(|hosts| {
                        hosts.iter().find(|(_, v)| **v == ip).map(|(k, _)| k.clone())
                    })
                });
                let connection = Self::gather_conn_info(&conn);
                PeerStatus { endpoint_id: eid, ip, hostname, connection: Some(connection) }
            }).collect();
            let my_hostname = hostname_snapshot.as_ref().and_then(|table| {
                table.get(&h.name).and_then(|hosts| {
                    hosts.iter().find(|(_, v)| **v == h.my_ip).map(|(k, _)| k.clone())
                })
            });
            NetworkStatus {
                name: h.name.clone(),
                role: h.role.clone(),
                my_ip: h.my_ip,
                my_hostname,
                network_key,
                member_count,
                peers,
            }
        }).collect();

        IpcResponse::Status {
            endpoint_id: self.endpoint.id(),
            networks: statuses,
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
    // ACL helpers
    // -----------------------------------------------------------------------

    fn resolve_short_id(&self, network: &str, short: &str) -> Option<EndpointId> {
        if short == "self" {
            return Some(self.endpoint.id());
        }
        let handle = self.networks.get(network)?;
        let state = handle.state.read().unwrap();
        state.members.all().iter()
            .find(|m| m.identity.to_string().starts_with(short))
            .map(|m| m.identity)
    }

    fn resolve_short_id_any_network(&self, short: &str) -> Option<EndpointId> {
        if short == "self" {
            return Some(self.endpoint.id());
        }
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(m) = state.members.all().iter().find(|m| m.identity.to_string().starts_with(short)) {
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
                let h = state.snapshot.as_ref().map(|s| s.hash).expect("snapshot set");
                (h, state.network_secret_key.clone())
            } else {
                return;
            }
        };

        // Store updated blob
        let snap_bytes = {
            
            self.networks.get(network).and_then(|h| {
                h.state.read().unwrap().snapshot.as_ref().map(|s| s.msgpack_bytes.clone())
            })
        };
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        // Publish to pkarr if we have the secret key
        if let Some(key) = net_key
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let mut seed_peers: Vec<EndpointId> = self.peers
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

    async fn acl_tag(&self, network: &str, tag: &str, peer_ids: &[String]) -> IpcResponse {
        let mut resolved = Vec::new();
        for short in peer_ids {
            match self.resolve_short_id(network, short) {
                Some(id) => resolved.push(id),
                None => return IpcResponse::Error {
                    message: format!("unknown peer '{short}'"),
                },
            }
        }

        {
            
            let Some(handle) = self.networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
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

        let acl = self.networks.get(network).unwrap()
            .state.read().unwrap().acl.clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcResponse::Ok { message: format!("tagged '{tag}'") }
    }

    async fn acl_untag(&self, network: &str, tag: &str, peer_id: &str) -> IpcResponse {
        let Some(id) = self.resolve_short_id(network, peer_id) else {
            return IpcResponse::Error { message: format!("unknown peer '{peer_id}'") };
        };

        {
            
            let Some(handle) = self.networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            if let Some(assignment) = state.acl.tags.iter_mut().find(|a| a.tag == tag) {
                assignment.members.retain(|m| m != &id);
            }
            state.acl.tags.retain(|a| !a.members.is_empty());
        }

        let acl = self.networks.get(network).unwrap()
            .state.read().unwrap().acl.clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcResponse::Ok { message: format!("untagged '{peer_id}' from '{tag}'") }
    }

    async fn acl_allow(&self, network: &str, src: &str, dst: &str) -> IpcResponse {
        let resolve = |s: &str| -> Option<acl::Target> {
            if s == "all" { return Some(acl::Target::All); }
            if let Some(id) = self.resolve_short_id(network, s) {
                return Some(acl::Target::Identity(id));
            }
            Some(acl::Target::Tag(s.to_string()))
        };

        let Some(src_target) = resolve(src) else {
            return IpcResponse::Error { message: format!("unknown src '{src}'") };
        };
        let Some(dst_target) = resolve(dst) else {
            return IpcResponse::Error { message: format!("unknown dst '{dst}'") };
        };

        {
            
            let Some(handle) = self.networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            state.acl.rules.push(acl::AclRule { src: src_target, dst: dst_target });
        }

        let acl = self.networks.get(network).unwrap()
            .state.read().unwrap().acl.clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcResponse::Ok { message: format!("added allow {src} -> {dst}") }
    }

    async fn acl_remove(&self, network: &str, index: usize) -> IpcResponse {
        {
            
            let Some(handle) = self.networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            if index >= state.acl.rules.len() {
                return IpcResponse::Error { message: format!("rule index {index} out of range") };
            }
            state.acl.rules.remove(index);
        }

        let acl = self.networks.get(network).unwrap()
            .state.read().unwrap().acl.clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcResponse::Ok { message: format!("removed rule {index}") }
    }

    fn acl_show(&self, network: &str) -> IpcResponse {
        let Some(handle) = self.networks.get(network) else {
            return IpcResponse::Error { message: format!("network '{network}' not active") };
        };
        let state = handle.state.read().unwrap();
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let display = acl::format_acl_show(&state.acl, &short_id);
        IpcResponse::AclState { display }
    }

    async fn acl_apply(&self, network: &str) -> IpcResponse {
        let path = self.acl_file_path(network);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => return IpcResponse::Error {
                message: format!("failed to read {}: {e}", path.display()),
            },
        };
        let network_str = network.to_string();
        let resolver = |short: &str| -> Option<EndpointId> {
            self.resolve_short_id(&network_str, short)
        };
        let data = match acl::parse_acl_file(&content, &resolver) {
            Ok(d) => d,
            Err(e) => return IpcResponse::Error { message: format!("parse error: {e}") },
        };

        {
            
            let Some(handle) = self.networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            state.acl = data.clone();
        }

        self.publish_and_broadcast_acl(network, &data).await;
        IpcResponse::Ok { message: "ACL applied".to_string() }
    }

    // -----------------------------------------------------------------------
    // Firewall handlers
    // -----------------------------------------------------------------------

    fn firewall_add(&self, direction: &str, action: &str, protocol: &str, port: Option<&str>, peer: Option<&str>) -> IpcResponse {
        let direction = match firewall::parse_direction(direction) {
            Ok(d) => d,
            Err(e) => return IpcResponse::Error { message: e.to_string() },
        };
        let action = match firewall::parse_action(action) {
            Ok(a) => a,
            Err(e) => return IpcResponse::Error { message: e.to_string() },
        };
        let protocol = match firewall::parse_protocol(protocol) {
            Ok(p) => p,
            Err(e) => return IpcResponse::Error { message: e.to_string() },
        };
        let port = match port {
            Some(s) => match firewall::parse_port_range(s) {
                Ok(r) => Some(r),
                Err(e) => return IpcResponse::Error { message: e.to_string() },
            },
            None => None,
        };
        let peer = match peer {
            Some(s) => match self.resolve_short_id_any_network(s) {
                Some(id) => firewall::PeerFilter::Identity(id),
                None => return IpcResponse::Error { message: format!("unknown peer '{s}'") },
            },
            None => firewall::PeerFilter::Any,
        };

        let rule = firewall::FirewallRule { direction, action, protocol, port, peer };
        let mut config = self.firewall.get_config();
        config.rules.push(rule);
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcResponse::Ok { message: "rule added".to_string() }
    }

    fn firewall_remove(&self, index: usize) -> IpcResponse {
        let mut config = self.firewall.get_config();
        if index >= config.rules.len() {
            return IpcResponse::Error { message: format!("index {index} out of range (have {} rules)", config.rules.len()) };
        }
        config.rules.remove(index);
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcResponse::Ok { message: "rule removed".to_string() }
    }

    fn firewall_show(&self) -> IpcResponse {
        let config = self.firewall.get_config();
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let display = firewall::format_firewall_show(&config, &short_id);
        IpcResponse::FirewallState { display }
    }

    fn firewall_default(&self, action: &str) -> IpcResponse {
        let action = match firewall::parse_action(action) {
            Ok(a) => a,
            Err(e) => return IpcResponse::Error { message: e.to_string() },
        };
        let mut config = self.firewall.get_config();
        config.default_action = action;
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcResponse::Ok { message: format!("default set to {}", if action == firewall::Action::Allow { "allow" } else { "deny" }) }
    }
}

pub async fn run_daemon(token: CancellationToken, stats: Arc<Stats>) -> Result<()> {
    let key = identity::load_or_create()?;
    let public_key = key.public();
    let identity = IrohIdentityProvider::new(public_key);
    let my_ip = identity.local_ip();

    // Load saved networks to determine initial ALPNs
    let app_config = config::load()?;
    let mut alpns: Vec<Vec<u8>> = app_config
        .networks
        .iter()
        .filter_map(|net| net.network_public_key.as_ref()
            .map(transport::network_alpn))
        .collect();

    alpns.push(iroh_blobs::protocol::ALPN.to_vec());
    let ep = transport::create_endpoint_with_alpns(key, alpns).await?;

    let blobs_dir = dirs::config_dir()
        .context("no config directory")?
        .join("pitopi")
        .join("blobs");
    std::fs::create_dir_all(&blobs_dir)?;
    let blob_store = FsStore::load(&blobs_dir).await
        .context("failed to open blob store")?;
    let blobs_proto = BlobsProtocol::new(&blob_store, None);

    // Check for CGNAT conflicts (e.g. Tailscale) before creating our TUN
    tun::check_cgnat_conflict()?;

    // Single TUN for all networks
    let (tun_reader, tun_writer) = tun::create(my_ip).context("failed to create TUN device")?;
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
    let dns_configurator = match dns_config::detect_and_configure() {
        Ok(c) => {
            tracing::info!(backend = c.name(), "system DNS configured for .pitopi");
            Some(c)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to configure system DNS (Magic DNS requires manual setup)");
            None
        }
    };

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
    });

    // Accept loop — dispatches connections via ProtocolHandler by ALPN
    protocol_router.spawn_accept_loop(daemon.endpoint.clone(), token.clone());

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
                    Ok(IpcResponse::Created { name, .. }) => {
                        tracing::info!(network = %name, "restored coordinator network");
                    }
                    Ok(IpcResponse::Error { message }) => {
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
                match daemon_c.join_network_inner(&net_pubkey, Some(&name), persisted_hostname).await {
                    Ok(IpcResponse::Joined { name, my_ip }) => {
                        tracing::info!(network = %name, ip = %my_ip, "restored member network");
                    }
                    Ok(IpcResponse::Error { message }) => {
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
    let listener = UnixListener::bind(&socket_path)
        .context("failed to bind IPC socket")?;
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

async fn handle_ipc_client(mut stream: UnixStream, daemon: &DaemonState) -> Result<()> {
    let req: IpcRequest = ipc::recv_msg(&mut stream).await?;
    let resp = daemon.handle_request(req).await;
    ipc::send_msg(&mut stream, &resp).await?;
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
                s.snapshot.as_ref().map(|snap| snap.hash)
                    .unwrap_or_else(|| group_blob_hash(&s.members, &s.approved, &s.acl, s.network_name.as_deref()))
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
                    &endpoint, *peer_id, iroh_blobs::protocol::ALPN,
                ).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if blob_store.remote().fetch(
                    conn, HashAndFormat::raw(blob_hash),
                ).await.is_err() {
                    continue;
                }
                match blob_store.blobs().get_bytes(blob_hash).await {
                    Ok(bytes) => {
                        match crate::membership::decode_group_blob(&bytes) {
                            Ok(data) => { new_data = Some(data); break; }
                            Err(_) => continue,
                        }
                    }
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
                        peers.remove(&member.ip);
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
                            peers.remove(&ev.ip);
                        }
                        None => return,
                    }
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_coordinator_accept(
    ep: Endpoint,
    network_name: String,
    conn_rx: mpsc::Receiver<Connection>,
    identity: IrohIdentityProvider,
    policy: Box<dyn MembershipPolicy>,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<Stats>,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_accept_loop(
            &ep,
            &network_name,
            conn_rx,
            &identity,
            &*policy,
            state,
            peers,
            tun_tx,
            disconnect_tx,
            token,
            stats,
            dht_notify,
            blob_store,
            shared_acl,
            firewall,
            hostname_table,
        ).await {
            tracing::warn!(network = %network_name, error = %e, "accept loop stopped");
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_accept_loop(
    ep: &Endpoint,
    network_name: &str,
    mut conn_rx: mpsc::Receiver<Connection>,
    identity: &IrohIdentityProvider,
    policy: &dyn MembershipPolicy,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<Stats>,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
) -> Result<()> {
    let self_member = {
        let s = state.read().unwrap();
        s.members.get(&identity.local_identity()).cloned().unwrap()
    };

    loop {
        tracing::info!(network = %network_name, "waiting for peers...");

        let conn = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            msg = conn_rx.recv() => {
                match msg {
                    Some(conn) => conn,
                    None => return Ok(()),
                }
            }
        };

        let remote_id = conn.remote_id();
        let peer_ip = identity.derive_ip(&remote_id);

        // Known member reconnecting
        let is_member = state.read().unwrap().members.is_member(&remote_id);
        if is_member {
            tracing::info!(ip = %peer_ip, "known member reconnecting");
            let members: Vec<Member> = state.read().unwrap().members.all().into_iter().cloned().collect();
            crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
            peers.add(peer_ip, conn.clone(), remote_id, network_name);
            let token_c = token.clone();
            let stats_c = stats.clone();
            let tun_tx_c = tun_tx.clone();
            let disconnect_tx_c = disconnect_tx.clone();
            let local_id = ep.id();
            let network_c = network_name.to_string();
            let shared_acl_c = shared_acl.clone();
            let firewall_c = firewall.clone();
            let state_c = state.clone();
            let hostname_table_c = hostname_table.clone();
            let network_name_c = network_name.to_string();
            tokio::spawn(async move {
                send_member_sync(&conn, &members).await;
                spawn_coordinator_hello_reader(conn.clone(), remote_id, peer_ip, &network_name_c, state_c, hostname_table_c).await;
                forward::spawn_peer_reader(conn, remote_id, peer_ip, local_id, network_c, shared_acl_c, firewall_c, tun_tx_c, disconnect_tx_c, token_c, stats_c);
            });
            continue;
        }

        // Approved but not yet connected
        let is_approved = state.read().unwrap().approved.is_approved(&remote_id);
        if is_approved {
            tracing::info!(ip = %peer_ip, "approved peer connecting");
            let snap_bytes = {
                let mut s = state.write().unwrap();
                s.approved.remove(&remote_id);
                let new_member = Member { identity: remote_id, ip: peer_ip, is_coordinator: false, hostname: None };
                s.members.add(new_member).expect("was approved, no collision");
                s.refresh_snapshot();
                s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
            };
            if let Some(bytes) = snap_bytes {
                let _ = blob_store.blobs().add_slice(&bytes).await;
            }
            if let Some(notify) = &dht_notify { notify.notify_one(); }
            let (members, approved) = {
                let s = state.read().unwrap();
                (s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                 s.approved.all().into_iter().cloned().collect::<Vec<_>>())
            };
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(&mut send, &ControlMsg::Welcome {
                    members: members.clone(), approved,
                }).await;
            }
            broadcast_member_sync(&peers, &members, Some(peer_ip)).await;
            peers.add(peer_ip, conn.clone(), remote_id, network_name);
            let token_c = token.clone();
            let stats_c = stats.clone();
            let tun_tx_c = tun_tx.clone();
            let disconnect_tx_c = disconnect_tx.clone();
            let local_id = ep.id();
            let network_c = network_name.to_string();
            let shared_acl_c = shared_acl.clone();
            let firewall_c = firewall.clone();
            let state_c = state.clone();
            let hostname_table_c = hostname_table.clone();
            let dht_notify_c = dht_notify.clone();
            let blob_store_c = blob_store.clone();
            let network_name_c = network_name.to_string();
            tokio::spawn(async move {
                spawn_coordinator_hello_reader(conn.clone(), remote_id, peer_ip, &network_name_c, state_c.clone(), hostname_table_c).await;
                update_snapshot_and_publish(&state_c, &blob_store_c, &dht_notify_c).await;
                forward::spawn_peer_reader(conn, remote_id, peer_ip, local_id, network_c, shared_acl_c, firewall_c, tun_tx_c, disconnect_tx_c, token_c, stats_c);
            });
            continue;
        }

        // Unknown peer — check policy
        if !policy.can_authorize(&self_member) {
            tracing::warn!(peer = %remote_id, "not authorized to accept new members");
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(&mut send, &ControlMsg::JoinDenied {
                    reason: "not authorized".to_string(),
                }).await;
            }
            continue;
        }

        // Check IP collision
        let collision_reason: Option<String> = {
            let s = state.read().unwrap();
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
            continue;
        }

        // Broadcast MemberApproved (hostname will be updated after MeshHello)
        broadcast_control_msg(&peers, &ControlMsg::MemberApproved { identity: remote_id, ip: peer_ip, hostname: None }).await;

        // Promote to member
        let (add_collision, snap_bytes): (Option<String>, Option<Vec<u8>>) = {
            let mut s = state.write().unwrap();
            let result = s.members.add(Member { identity: remote_id, ip: peer_ip, is_coordinator: false, hostname: None })
                .err().map(|e| format!("IP collision: {e}"));
            if result.is_none() {
                s.refresh_snapshot();
            }
            let bytes = s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone());
            (result, bytes)
        };
        if add_collision.is_none()
            && let Some(bytes) = snap_bytes
        {
            let _ = blob_store.blobs().add_slice(&bytes).await;
        }
        if let Some(reason) = add_collision {
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(&mut send, &ControlMsg::JoinDenied { reason }).await;
            }
            continue;
        }

        let (members, approved) = {
            let s = state.read().unwrap();
            (s.members.all().into_iter().cloned().collect::<Vec<_>>(),
             s.approved.all().into_iter().cloned().collect::<Vec<_>>())
        };

        tracing::info!(ip = %peer_ip, "new member approved and joined");
        if let Some(notify) = &dht_notify { notify.notify_one(); }

        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(&mut send, &ControlMsg::Welcome {
                members: members.clone(), approved,
            }).await;
        }
        broadcast_member_sync(&peers, &members, Some(peer_ip)).await;
        peers.add(peer_ip, conn.clone(), remote_id, network_name);
        let token_c = token.clone();
        let stats_c = stats.clone();
        let tun_tx_c = tun_tx.clone();
        let disconnect_tx_c = disconnect_tx.clone();
        let local_id = ep.id();
        let network_c = network_name.to_string();
        let shared_acl_c = shared_acl.clone();
        let firewall_c = firewall.clone();
        let state_c = state.clone();
        let hostname_table_c = hostname_table.clone();
        let dht_notify_c = dht_notify.clone();
        let blob_store_c = blob_store.clone();
        let network_name_c = network_name.to_string();
        tokio::spawn(async move {
            spawn_coordinator_hello_reader(conn.clone(), remote_id, peer_ip, &network_name_c, state_c.clone(), hostname_table_c).await;
            update_snapshot_and_publish(&state_c, &blob_store_c, &dht_notify_c).await;
            forward::spawn_peer_reader(conn, remote_id, peer_ip, local_id, network_c, shared_acl_c, firewall_c, tun_tx_c, disconnect_tx_c, token_c, stats_c);
        });
    }
}

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
            std::time::Duration::from_secs(5),
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
                network_hosts.insert(final_hostname, peer_ip);
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
    if let Some(notify) = dht_notify { notify.notify_one(); }
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
    stats: Arc<Stats>,
    blob_store: FsStore,
    shared_acl: forward::SharedAcl,
    firewall: SharedFirewall,
    net_pubkey: EndpointId,
    conn_rx: mpsc::Receiver<Connection>,
    hostname_table: dns::HostnameTable,
) -> Result<Arc<std::sync::RwLock<NetworkState>>> {
    let my_identity = identity.local_identity();
    let my_ip = identity.local_ip();

    let (_send, mut recv) = initial_conn.accept_bi().await.context("accept control stream")?;
    let msg = control::recv_msg(&mut recv).await?;
    let (members, approved) = match msg {
        ControlMsg::Welcome { members, approved } => {
            tracing::info!(network = %network_name, "welcomed to network");
            if let Some(existing) = members.iter().find(|m| m.ip == my_ip && m.identity != my_identity) {
                anyhow::bail!("IP collision: {} is already assigned to {}", my_ip, existing.identity);
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
    let member_entries: Vec<config::MemberEntry> = members.iter().map(|m| config::MemberEntry {
        identity: m.identity, ip: m.ip, is_coordinator: m.is_coordinator, hostname: m.hostname.clone(),
    }).collect();
    let approved_config: Vec<config::ApprovedConfigEntry> = approved.iter().map(|a| config::ApprovedConfigEntry {
        identity: a.identity, ip: a.ip, hostname: a.hostname.clone(),
    }).collect();
    let persisted_hostname = members.iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone())
        .or(my_hostname.clone());
    let mut app_config = config::load()?;
    config::upsert_network(&mut app_config, config::NetworkConfig {
        name: network_name.to_string(),
        group_mode: GroupMode::Restricted,
        my_ip: Some(my_ip),
        my_hostname: persisted_hostname,
        members: member_entries,
        approved: approved_config,
        network_secret_key: None,
        network_public_key: Some(net_pubkey),
    });
    config::save(&app_config)?;

    // Send MeshHello to coordinator so it learns our hostname
    {
        let (mut send, _recv) = initial_conn.open_bi().await?;
        control::send_msg(&mut send, &ControlMsg::MeshHello { identity: my_identity, ip: my_ip, hostname: my_hostname.clone() }).await?;
    }

    // Add initial connection peer
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);
    crate::spawn_path_logger(initial_conn.clone(), remote_id.fmt_short().to_string());
    peers.add(remote_ip, initial_conn.clone(), remote_id, network_name);
    forward::spawn_peer_reader(
        initial_conn.clone(), remote_id, remote_ip,
        ep.id(), network_name.to_string(), shared_acl.clone(), firewall.clone(),
        tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone(),
    );

    // Connect to other known members
    for member in &members {
        if member.identity == my_identity || member.identity == initial_conn.remote_id() {
            continue;
        }
        match transport::connect_to_peer_with_alpn(ep, member.identity, alpn).await {
            Ok(conn) => {
                let (mut send, _recv) = conn.open_bi().await?;
                control::send_msg(&mut send, &ControlMsg::MeshHello { identity: my_identity, ip: my_ip, hostname: my_hostname.clone() }).await?;
                peers.add(member.ip, conn.clone(), member.identity, network_name);
                forward::spawn_peer_reader(conn, member.identity, member.ip, ep.id(), network_name.to_string(), shared_acl.clone(), firewall.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
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

    // Mesh acceptor
    tokio::spawn({
        let ep = ep.clone();
        let peers = peers.clone();
        let token = token.clone();
        let stats = stats.clone();
        let tun_tx = tun_tx.clone();
        let disconnect_tx = disconnect_tx.clone();
        let live_state = live_state.clone();
        let network_name = network_name.to_string();
        let blob_store = blob_store.clone();
        let shared_acl = shared_acl.clone();
        let hostname_table = hostname_table.clone();
        let mut conn_rx = conn_rx;
        async move {
            loop {
                let conn = tokio::select! {
                    _ = token.cancelled() => return,
                    msg = conn_rx.recv() => {
                        match msg {
                            Some(c) => c,
                            None => return,
                        }
                    }
                };
                if let Ok((_send, mut recv)) = conn.accept_bi().await {
                    let transport_id = conn.remote_id();
                    match control::recv_msg(&mut recv).await {
                        Ok(ControlMsg::MeshHello { identity: peer_identity, ip, hostname }) => {
                            if peer_identity != transport_id { continue; }
                            let (is_member, is_approved) = {
                                let s = live_state.read().unwrap();
                                (s.members.is_member(&peer_identity), s.approved.is_approved(&peer_identity))
                            };
                            // Resolve hostname collisions
                            let final_hostname = if let Some(desired) = hostname {
                                let taken: Vec<String> = {
                                    let s = live_state.read().unwrap();
                                    s.members.all().iter()
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
                                let mut table = hostname_table.write().await;
                                let network_hosts = table.entry(network_name.clone()).or_default();
                                network_hosts.insert(h.clone(), ip);
                            }
                            if is_approved {
                                let snap_bytes = {
                                    let mut s = live_state.write().unwrap();
                                    s.approved.remove(&peer_identity);
                                    let _ = s.members.add(Member { identity: peer_identity, ip, is_coordinator: false, hostname: final_hostname.clone() });
                                    s.refresh_snapshot();
                                    s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
                                };
                                if let Some(bytes) = snap_bytes {
                                    let _ = blob_store.blobs().add_slice(&bytes).await;
                                }
                                let (members, approved_list) = {
                                    let s = live_state.read().unwrap();
                                    (s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                                     s.approved.all().into_iter().cloned().collect::<Vec<_>>())
                                };
                                if let Ok((mut send, _)) = conn.open_bi().await {
                                    let _ = control::send_msg(&mut send, &ControlMsg::Welcome {
                                        members: members.clone(), approved: approved_list,
                                    }).await;
                                }
                                peers.add(ip, conn.clone(), peer_identity, &network_name);
                                forward::spawn_peer_reader(conn, peer_identity, ip, ep.id(), network_name.clone(), shared_acl.clone(), firewall.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                                broadcast_member_sync(&peers, &members, Some(ip)).await;
                            } else if is_member {
                                // Update hostname for existing member
                                if final_hostname.is_some() {
                                    let mut s = live_state.write().unwrap();
                                    if let Some(m) = s.members.get_mut(&peer_identity) {
                                        m.hostname = final_hostname;
                                    }
                                }
                                peers.add(ip, conn.clone(), peer_identity, &network_name);
                                forward::spawn_peer_reader(conn, peer_identity, ip, ep.id(), network_name.clone(), shared_acl.clone(), firewall.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                            }
                        }
                        Ok(ControlMsg::ReconnectRequest { identity: peer_identity, ip }) => {
                            if peer_identity != transport_id { continue; }
                            let is_known = live_state.read().unwrap().members.is_member(&peer_identity);
                            if is_known {
                                peers.add(ip, conn.clone(), peer_identity, &network_name);
                                let current_members: Vec<Member> = live_state.read().unwrap().members.all().into_iter().cloned().collect();
                                if let Ok((mut send, _)) = conn.open_bi().await {
                                    let _ = control::send_msg(&mut send, &ControlMsg::MemberSync { members: current_members }).await;
                                }
                                forward::spawn_peer_reader(conn, peer_identity, ip, ep.id(), network_name.clone(), shared_acl.clone(), firewall.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                            }
                        }
                        _ => {}
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
    stats: Arc<Stats>,
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
            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer disconnected, will reconnect");
            peers.remove(&peer_ip);

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
                    if token.is_cancelled() { return; }
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
                                Err(e) => { tracing::warn!(error = %e, "reconnect handshake failed"); continue; }
                            };
                            if let Err(e) = control::send_msg(&mut send, &ControlMsg::MeshHello { identity: my_identity, ip: my_ip, hostname: my_hostname.clone() }).await {
                                tracing::warn!(error = %e, "reconnect MeshHello failed");
                                continue;
                            }
                            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "reconnected to peer");
                            peers.add(peer_ip, conn.clone(), peer_id, &network_name);
                            forward::spawn_peer_reader(conn, peer_id, peer_ip, my_identity, network_name, shared_acl, firewall, tun_tx, disconnect_tx, token, stats);
                            return;
                        }
                        Err(e) => { tracing::debug!(error = %e, "reconnect attempt failed"); }
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
        let _ = control::send_msg(&mut send, &ControlMsg::MemberSync { members: members.to_vec() }).await;
    }
}

async fn broadcast_member_sync(peers: &PeerTable, members: &[Member], exclude_ip: Option<Ipv4Addr>) {
    let msg = ControlMsg::MemberSync { members: members.to_vec() };
    for (ip, conn) in peers.all_connections() {
        if Some(ip) == exclude_ip { continue; }
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
