use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, Endpoint};
use iroh::protocol::ProtocolHandler;
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
use crate::forward;
use crate::identity;
use crate::ipc::{self, IpcRequest, IpcResponse, NetworkRole, NetworkStatus, PeerStatus};
use crate::membership::{
    ApprovedEntry, ApprovedList, GroupMode, IdentityProvider, IrohIdentityProvider, Member,
    MemberList, MembershipPolicy, policy_for_mode, canonical_membership_bytes_with_secrets,
    membership_hash, verify_membership_data,
};
use crate::network_name;
use crate::peers::PeerTable;
use crate::stats::Stats;
use crate::transport;
use crate::tun;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct MembershipSnapshot {
    hash: String,
    msgpack_bytes: Vec<u8>,
}

struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
    snapshot: Option<MembershipSnapshot>,
    network_secret: [u8; 32],
    membership_signing_key: [u8; 32],
    acl: acl::AclData,
}

impl NetworkState {
    fn refresh_snapshot(&mut self) {
        let bytes = canonical_membership_bytes_with_secrets(
            &self.members, &self.approved,
            &self.network_secret, &self.membership_signing_key,
        );
        let hash = blake3::hash(&bytes).to_hex().to_string();
        self.snapshot = Some(MembershipSnapshot { hash, msgpack_bytes: bytes });
    }
}

#[allow(dead_code)]
pub struct NetworkHandle {
    name: String,
    role: NetworkRole,
    my_ip: Ipv4Addr,
    state: Arc<std::sync::RwLock<NetworkState>>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

pub struct DaemonState {
    endpoint: Endpoint,
    secret_key: SecretKey,
    identity: IrohIdentityProvider,
    peers: PeerTable,
    stats: Arc<Stats>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    networks: Arc<std::sync::RwLock<HashMap<String, NetworkHandle>>>,
    shutdown_token: CancellationToken,
    blob_store: FsStore,
    blobs_proto: BlobsProtocol,
    shared_acl: forward::SharedAcl,
}

impl DaemonState {
    fn refresh_alpns(&self) {
        let networks = self.networks.read().unwrap();
        let mut alpns: Vec<Vec<u8>> = networks
            .keys()
            .map(|n| transport::network_alpn(n))
            .collect();
        alpns.push(iroh_blobs::protocol::ALPN.to_vec());
        self.endpoint.set_alpns(alpns);
    }

    async fn handle_request(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::Create { mode } => self.create_network(mode).await,
            IpcRequest::Join { name } => self.join_network(&name).await,
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
        }
    }

    async fn create_network(&self, mode: GroupMode) -> IpcResponse {
        match self.create_network_inner(mode).await {
            Ok(resp) => resp,
            Err(e) => IpcResponse::Error { message: format!("{e:#}") },
        }
    }

    async fn create_network_inner(&self, mode: GroupMode) -> Result<IpcResponse> {
        let name = network_name::generate_name();

        {
            let networks = self.networks.read().unwrap();
            if networks.contains_key(&name) {
                return Ok(IpcResponse::Error {
                    message: format!("network '{name}' already active"),
                });
            }
        }

        // Generate network secret (for seed list publishing)
        let network_secret: [u8; 32] = rand::random();
        let network_secret_key = SecretKey::from_bytes(&network_secret);

        // Derive membership signing key
        let membership_key = dht::derive_membership_key(&self.secret_key, &name);
        let membership_signing_key = membership_key.to_bytes();
        let dht_id = dht::membership_dht_id(&self.secret_key, &name).to_string();
        let my_ip = self.identity.local_ip();
        let policy = policy_for_mode(mode);

        let mut member_list = MemberList::new();
        member_list
            .add(Member {
                identity: self.identity.local_identity(),
                ip: my_ip,
                is_coordinator: true,
            })
            .expect("self-add cannot collide");

        let mut net_state = NetworkState {
            members: member_list,
            approved: ApprovedList::new(),
            snapshot: None,
            network_secret,
            membership_signing_key,
            acl: acl::AclData::empty(),
        };

        // Load ACL from file if it exists.
        // Note: network is not yet registered, so resolve short IDs directly from net_state.members.
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

        // Publish directory and seed list to DHT
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            let dir_key = dht::derive_directory_key(&name);
            if let Err(e) = dht::publish_directory(
                &pkarr_client,
                &dir_key,
                &network_secret_key.public(),
                &membership_key.public(),
            ).await {
                tracing::warn!(error = %e, "failed to publish directory record");
            }

            if let Err(e) = dht::publish_seed_list(
                &pkarr_client,
                &SecretKey::from_bytes(&network_secret),
                &[self.endpoint.id()],
            ).await {
                tracing::warn!(error = %e, "failed to publish seed list");
            }

            // Publish ACL to DHT if non-empty
            if !net_state.acl.tags.is_empty() || !net_state.acl.rules.is_empty() {
                let acl_bytes = acl::canonical_acl_bytes(&net_state.acl);
                let acl_hash = acl::acl_hash(&net_state.acl);
                let _ = self.blob_store.blobs().add_slice(&acl_bytes).await;
                let acl_key = dht::derive_acl_key(&self.secret_key, &name);
                if let Err(e) = dht::publish_acl(&pkarr_client, &acl_key, &acl_hash).await {
                    tracing::warn!(error = %e, "failed to publish ACL on create");
                }
            }
        }

        // Save to config
        let member_entries = net_state.members.all().into_iter().map(|m| config::MemberEntry {
            identity: m.identity,
            ip: m.ip,
            is_coordinator: m.is_coordinator,
        }).collect();
        let approved_entries = net_state.approved.all().into_iter().map(|a| config::ApprovedConfigEntry {
            identity: a.identity,
            ip: a.ip,
        }).collect();
        let mut app_config = config::load()?;
        config::upsert_network(&mut app_config, config::NetworkConfig {
            name: name.clone(),
            group_mode: mode,
            my_ip: Some(my_ip),
            members: member_entries,
            approved: approved_entries,
            membership_dht_id: Some(dht_id.clone()),
            network_pkarr_pubkey: Some(network_secret_key.public().to_string()),
            membership_dht_pubkey: Some(membership_key.public().to_string()),
        });
        config::save(&app_config)?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let mut tasks = Vec::new();

        // DHT publisher
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_dht_publisher(
                pkarr_client.clone(),
                membership_key,
                state.clone(),
                dht_notify.clone(),
                cancel.clone(),
            ));

            // Seed list publisher
            let seed_notify = Arc::new(tokio::sync::Notify::new());
            tasks.push(spawn_seed_list_publisher(
                pkarr_client,
                network_secret,
                self.endpoint.id(),
                self.peers.clone(),
                name.clone(),
                seed_notify,
                cancel.clone(),
            ));
        }

        // Disconnect handler (coordinator removes dead peers)
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(disconnect_rx, self.peers.clone(), cancel.clone()));

        // Accept loop for this network
        let acl_dht_id_str = Some(dht::acl_dht_id(&self.secret_key, &name).to_string());
        let accept_handle = spawn_coordinator_accept(
            self.endpoint.clone(),
            name.clone(),
            self.identity.clone(),
            policy,
            state.clone(),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx,
            cancel.clone(),
            self.stats.clone(),
            Some(dht_notify),
            Some(dht_id),
            acl_dht_id_str,
            self.blob_store.clone(),
            self.blobs_proto.clone(),
            self.shared_acl.clone(),
        );
        tasks.push(accept_handle);

        // Update ALPNs
        let handle = NetworkHandle {
            name: name.clone(),
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            cancel,
            tasks,
        };
        self.networks.write().unwrap().insert(name.clone(), handle);
        self.refresh_alpns();

        tracing::info!(name = %name, ip = %my_ip, "network created");

        Ok(IpcResponse::Created {
            name,
            my_ip,
        })
    }

    async fn join_network(&self, name: &str) -> IpcResponse {
        match self.join_network_inner(name).await {
            Ok(resp) => resp,
            Err(e) => IpcResponse::Error { message: format!("{e:#}") },
        }
    }

    async fn join_network_inner(&self, name: &str) -> Result<IpcResponse> {
        {
            let networks = self.networks.read().unwrap();
            if networks.contains_key(name) {
                return Ok(IpcResponse::Error {
                    message: format!("already in network '{name}'"),
                });
            }
        }

        // Step 1: Resolve directory record (name → network pkarr pubkey + membership DHT pubkey)
        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (network_pkarr_pubkey, membership_dht_pubkey) =
            dht::resolve_directory(&pkarr_client, name).await
                .context("failed to resolve network directory")?;

        // Step 2: Resolve seed list and membership hash in parallel
        let (seed_result, hash_result) = tokio::join!(
            dht::resolve_seed_list(&pkarr_client, network_pkarr_pubkey),
            dht::resolve_membership_hash(&pkarr_client, membership_dht_pubkey),
        );

        let peer_ids = seed_result.context("failed to resolve seed list")?;
        let expected_hash = hash_result.context("failed to resolve membership hash")?;

        if peer_ids.is_empty() {
            return Ok(IpcResponse::Error {
                message: "no peers found in seed list".to_string(),
            });
        }

        // Step 3: Connect to a peer and fetch membership blob
        let blob_hash = {
            let b3_hash: blake3::Hash = expected_hash.parse()
                .context("invalid membership hash from DHT")?;
            iroh_blobs::Hash::from_bytes(*b3_hash.as_bytes())
        };

        let mut membership_data = None;
        for peer_id in &peer_ids {
            match self.try_fetch_blob_from_peer(*peer_id, blob_hash).await {
                Ok(data) => {
                    membership_data = Some(data);
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id.fmt_short(), error = %e, "failed to fetch blob");
                    continue;
                }
            }
        }

        let data = membership_data.context("could not fetch membership from any peer")?;

        let alpn = transport::network_alpn(name);
        let my_ip = self.identity.local_ip();

        // Try to connect to the first reachable peer via the network ALPN
        let mut initial_conn = None;
        for peer_id in &peer_ids {
            if *peer_id == self.endpoint.id() { continue; }
            match transport::connect_to_peer_with_alpn(&self.endpoint, *peer_id, &alpn).await {
                Ok(conn) => {
                    initial_conn = Some(conn);
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id.fmt_short(), error = %e, "failed to connect to seed peer");
                }
            }
        }

        // Fall back to connecting to known members from the membership data
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

        let cancel = self.shutdown_token.child_token();
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

        // Reconnect loop
        let tasks = vec![spawn_reconnect_loop(
            disconnect_rx,
            self.endpoint.clone(),
            alpn.clone(),
            name.to_string(),
            self.identity.local_identity(),
            my_ip,
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
            self.stats.clone(),
            self.shared_acl.clone(),
        )];

        // Join mesh via the connected peer
        let state = join_mesh_shared(
            conn,
            &self.endpoint,
            name,
            &self.identity,
            &alpn,
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx,
            cancel.clone(),
            self.stats.clone(),
            self.blob_store.clone(),
            self.blobs_proto.clone(),
            self.shared_acl.clone(),
        ).await?;

        // Store the secrets from the fetched membership data and refresh snapshot
        // so the blob store has a hash that matches what the DHT publishes.
        {
            let mut s = state.write().unwrap();
            s.network_secret = data.network_secret;
            s.membership_signing_key = data.membership_signing_key;
            s.refresh_snapshot();
        }
        let snap_bytes = state.read().unwrap().snapshot.as_ref().map(|s| s.msgpack_bytes.clone());
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        // Save config with the DHT pubkeys
        if let Ok(mut app_config) = config::load() {
            if let Some(net) = app_config.networks.iter_mut().find(|n| n.name == name) {
                net.network_pkarr_pubkey = Some(network_pkarr_pubkey.to_string());
                net.membership_dht_pubkey = Some(membership_dht_pubkey.to_string());
            }
            let _ = config::save(&app_config);
        }

        // Membership poller — periodically checks for membership changes via DHT
        let mut tasks = tasks;
        if let Ok(poller_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_membership_poller(
                poller_client,
                membership_dht_pubkey,
                state.clone(),
                self.endpoint.clone(),
                self.blob_store.clone(),
                self.peers.clone(),
                name.to_string(),
                cancel.clone(),
            ));
        }

        let handle = NetworkHandle {
            name: name.to_string(),
            role: NetworkRole::Member,
            my_ip,
            state,
            cancel,
            tasks,
        };
        self.networks.write().unwrap().insert(name.to_string(), handle);
        self.refresh_alpns();

        tracing::info!(network = %name, ip = %my_ip, "joined network");

        Ok(IpcResponse::Joined {
            name: name.to_string(),
            my_ip,
        })
    }

    async fn try_fetch_blob_from_peer(
        &self,
        peer_id: EndpointId,
        blob_hash: iroh_blobs::Hash,
    ) -> Result<crate::membership::MembershipData> {
        let conn = transport::connect_to_peer_with_alpn(
            &self.endpoint, peer_id, iroh_blobs::protocol::ALPN,
        ).await?;
        self.blob_store.remote().fetch(
            conn, HashAndFormat::raw(blob_hash),
        ).await.map_err(|e| anyhow::anyhow!("blob fetch failed: {e}"))?;
        let bytes = self.blob_store.blobs().get_bytes(blob_hash).await
            .map_err(|e| anyhow::anyhow!("blob read failed: {e}"))?;
        rmp_serde::from_slice(&bytes).context("invalid membership data")
    }

    #[allow(dead_code)]
    async fn try_dht_fallback_join(&self, network_name: &str, alpn: &[u8]) -> Result<IpcResponse> {
        let app_config = config::load()?;
        let net_config = app_config.networks.iter()
            .find(|n| n.name == network_name)
            .context("network not in config")?;
        let dht_id_str = net_config.membership_dht_id.as_ref()
            .context("no DHT ID known for this network")?;
        let dht_id: EndpointId = dht_id_str.parse()
            .context("invalid DHT ID in config")?;

        tracing::info!(network = %network_name, "coordinator unreachable, trying DHT fallback");

        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let expected_hash = dht::resolve_membership_hash(&pkarr_client, dht_id).await?;

        // Try connecting to known members from config to fetch membership blob
        let my_identity = self.identity.local_identity();
        let blob_hash = {
            let b3_hash: blake3::Hash = expected_hash.parse()
                .context("invalid membership hash from DHT")?;
            iroh_blobs::Hash::from_bytes(*b3_hash.as_bytes())
        };

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

            let data = verify_membership_data(&blob_bytes, &expected_hash)?;
            tracing::info!(network = %network_name, members = data.members.len(), "membership resolved via DHT fallback");

            let my_ip = self.identity.local_ip();
            let cancel = self.shutdown_token.child_token();
            let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

            let tasks = vec![spawn_reconnect_loop(
                disconnect_rx,
                self.endpoint.clone(),
                alpn.to_vec(),
                network_name.to_string(),
                my_identity,
                my_ip,
                self.peers.clone(),
                self.tun_tx.clone(),
                disconnect_tx.clone(),
                cancel.clone(),
                self.stats.clone(),
                self.shared_acl.clone(),
            )];

            // Connect to the same peer via network ALPN for mesh data
            for m in &data.members {
                if m.identity == my_identity { continue; }
                if let Ok(peer_conn) = transport::connect_to_peer_with_alpn(&self.endpoint, m.identity, alpn).await {
                    if let Ok((mut s, _)) = peer_conn.open_bi().await {
                        let _ = control::send_msg(&mut s, &ControlMsg::MeshHello { identity: my_identity, ip: my_ip }).await;
                    }
                    crate::spawn_path_logger(peer_conn.clone(), m.identity.fmt_short().to_string());
                    self.peers.add(m.ip, peer_conn.clone(), m.identity, network_name);
                    forward::spawn_peer_reader(peer_conn, m.identity, m.ip, self.endpoint.id(), network_name.to_string(), self.shared_acl.clone(), self.tun_tx.clone(), disconnect_tx.clone(), cancel.clone(), self.stats.clone());
                }
            }

            let mut ns = NetworkState {
                members: MemberList::from_members(data.members),
                approved: ApprovedList::from_entries(data.approved),
                snapshot: None,
                network_secret: data.network_secret,
                membership_signing_key: data.membership_signing_key,
                acl: acl::AclData::empty(),
            };
            ns.refresh_snapshot();
            let live_state = Arc::new(std::sync::RwLock::new(ns));

            let handle = NetworkHandle {
                name: network_name.to_string(),
                role: NetworkRole::Member,
                my_ip,
                state: live_state,
                cancel,
                tasks,
            };
            self.networks.write().unwrap().insert(network_name.to_string(), handle);
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
            let networks = self.networks.read().unwrap();
            if networks.contains_key(name) {
                return Ok(IpcResponse::Error {
                    message: format!("network '{name}' already active"),
                });
            }
        }

        let membership_key = dht::derive_membership_key(&self.secret_key, name);
        let membership_signing_key = membership_key.to_bytes();
        let dht_id = dht::membership_dht_id(&self.secret_key, name).to_string();
        let my_ip = self.identity.local_ip();
        let policy = policy_for_mode(mode);

        // The network secret was originally random; on restore we generate a fresh one
        // and re-publish the seed list / directory with the new key.
        let network_secret: [u8; 32] = rand::random();
        let network_secret_key = SecretKey::from_bytes(&network_secret);

        // Load persisted members and approved entries from config so we restore
        // the full membership state, not just the coordinator.
        let app_config = config::load()?;
        let net_config = app_config.networks.iter().find(|n| n.name == name);

        let mut member_list = MemberList::new();
        if let Some(nc) = net_config {
            for entry in &nc.members {
                let _ = member_list.add(Member {
                    identity: entry.identity,
                    ip: entry.ip,
                    is_coordinator: entry.is_coordinator,
                });
            }
        }
        // Ensure the coordinator is always present (in case config is missing or incomplete).
        if !member_list.is_member(&self.identity.local_identity()) {
            member_list
                .add(Member {
                    identity: self.identity.local_identity(),
                    ip: my_ip,
                    is_coordinator: true,
                })
                .expect("self-add cannot collide");
        }

        let mut approved_list = ApprovedList::new();
        if let Some(nc) = net_config {
            for entry in &nc.approved {
                let ae = ApprovedEntry { identity: entry.identity, ip: entry.ip };
                let _ = approved_list.approve(ae, &member_list);
            }
        }

        let mut net_state = NetworkState {
            members: member_list,
            approved: approved_list,
            snapshot: None,
            network_secret,
            membership_signing_key,
            acl: acl::AclData::empty(),
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

        // Re-publish directory and seed list
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            let dir_key = dht::derive_directory_key(name);
            if let Err(e) = dht::publish_directory(
                &pkarr_client,
                &dir_key,
                &network_secret_key.public(),
                &membership_key.public(),
            ).await {
                tracing::warn!(error = %e, "failed to publish directory record on restore");
            }

            if let Err(e) = dht::publish_seed_list(
                &pkarr_client,
                &SecretKey::from_bytes(&network_secret),
                &[self.endpoint.id()],
            ).await {
                tracing::warn!(error = %e, "failed to publish seed list on restore");
            }

            // Publish ACL to DHT if non-empty
            if !net_state.acl.tags.is_empty() || !net_state.acl.rules.is_empty() {
                let acl_bytes = acl::canonical_acl_bytes(&net_state.acl);
                let _ = self.blob_store.blobs().add_slice(&acl_bytes).await;
                let acl_key = dht::derive_acl_key(&self.secret_key, name);
                let hash = acl::acl_hash(&net_state.acl);
                if let Err(e) = dht::publish_acl(&pkarr_client, &acl_key, &hash).await {
                    tracing::warn!(error = %e, "failed to publish ACL on restore");
                }
            }
        }

        // Update config with refreshed secrets (members/approved are unchanged).
        let member_entries = net_state.members.all().into_iter().map(|m| config::MemberEntry {
            identity: m.identity,
            ip: m.ip,
            is_coordinator: m.is_coordinator,
        }).collect();
        let approved_entries = net_state.approved.all().into_iter().map(|a| config::ApprovedConfigEntry {
            identity: a.identity,
            ip: a.ip,
        }).collect();
        let mut app_config = config::load()?;
        config::upsert_network(&mut app_config, config::NetworkConfig {
            name: name.to_string(),
            group_mode: mode,
            my_ip: Some(my_ip),
            members: member_entries,
            approved: approved_entries,
            membership_dht_id: Some(dht_id.clone()),
            network_pkarr_pubkey: Some(network_secret_key.public().to_string()),
            membership_dht_pubkey: Some(membership_key.public().to_string()),
        });
        config::save(&app_config)?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let mut tasks = Vec::new();

        let dht_notify = Arc::new(tokio::sync::Notify::new());
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_dht_publisher(
                pkarr_client,
                membership_key,
                state.clone(),
                dht_notify.clone(),
                cancel.clone(),
            ));
        }

        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(disconnect_rx, self.peers.clone(), cancel.clone()));

        let acl_dht_id_str = Some(dht::acl_dht_id(&self.secret_key, name).to_string());

        // Sync the restored ACL into the shared ACL state for enforcement
        {
            let s = state.read().unwrap();
            self.shared_acl.set(name, s.acl.clone());
        }

        let accept_handle = spawn_coordinator_accept(
            self.endpoint.clone(),
            name.to_string(),
            self.identity.clone(),
            policy,
            state.clone(),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx,
            cancel.clone(),
            self.stats.clone(),
            Some(dht_notify),
            Some(dht_id),
            acl_dht_id_str,
            self.blob_store.clone(),
            self.blobs_proto.clone(),
            self.shared_acl.clone(),
        );
        tasks.push(accept_handle);

        let handle = NetworkHandle {
            name: name.to_string(),
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            cancel,
            tasks,
        };
        self.networks.write().unwrap().insert(name.to_string(), handle);
        self.refresh_alpns();

        tracing::info!(name = %name, ip = %my_ip, "network restored (coordinator)");

        Ok(IpcResponse::Created {
            name: name.to_string(),
            my_ip,
        })
    }

    async fn nuke_network(&self, name: &str, force: bool) -> IpcResponse {
        // Check we're the coordinator and whether other members exist
        let (is_coordinator, has_other_members) = {
            let networks = self.networks.read().unwrap();
            let handle = match networks.get(name) {
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

        // Publish empty membership and empty seed list to DHT
        if let Ok(client) = dht::create_pkarr_client(&self.endpoint) {
            let membership_key = dht::derive_membership_key(&self.secret_key, name);

            // Publish empty membership hash
            let empty_members = MemberList::new();
            let empty_approved = ApprovedList::new();
            let empty_hash = membership_hash(&empty_members, &empty_approved);
            if let Err(e) = dht::publish_membership(&client, &membership_key, &empty_hash).await {
                tracing::warn!(error = %e, "failed to publish empty membership on nuke");
            }

            // Publish empty seed list
            let network_secret = {
                let networks = self.networks.read().unwrap();
                let handle = networks.get(name).unwrap();
                let state = handle.state.read().unwrap();
                state.network_secret
            };
            let seed_key = SecretKey::from_bytes(&network_secret);
            if let Err(e) = dht::publish_seed_list(&client, &seed_key, &[]).await {
                tracing::warn!(error = %e, "failed to publish empty seed list on nuke");
            }

            // Publish empty ACL
            let acl_key = dht::derive_acl_key(&self.secret_key, name);
            let empty_acl = acl::AclData::empty();
            let empty_acl_hash = acl::acl_hash(&empty_acl);
            if let Err(e) = dht::publish_acl(&client, &acl_key, &empty_acl_hash).await {
                tracing::warn!(error = %e, "failed to publish empty ACL on nuke");
            }
        }

        // Remove the ACL file for this network
        let acl_path = self.acl_file_path(name);
        let _ = std::fs::remove_file(acl_path);

        // Leave the network (handles cleanup, config removal, etc.)
        self.leave_network(name).await
    }

    async fn leave_network(&self, name: &str) -> IpcResponse {
        let handle = {
            self.networks.write().unwrap().remove(name)
        };
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
        let networks = self.networks.read().unwrap();
        let statuses: Vec<NetworkStatus> = networks.values().map(|h| {
            let peer_entries = self.peers.peers_for_network(&h.name);
            let peers = peer_entries.into_iter().map(|(eid, ip)| PeerStatus {
                endpoint_id: eid.to_string(),
                ip,
            }).collect();
            NetworkStatus {
                name: h.name.clone(),
                role: h.role.clone(),
                my_ip: h.my_ip,
                peers,
            }
        }).collect();

        IpcResponse::Status {
            endpoint_id: self.endpoint.id().to_string(),
            networks: statuses,
        }
    }

    // -----------------------------------------------------------------------
    // ACL helpers
    // -----------------------------------------------------------------------

    fn resolve_short_id(&self, network: &str, short: &str) -> Option<EndpointId> {
        let networks = self.networks.read().unwrap();
        let handle = networks.get(network)?;
        let state = handle.state.read().unwrap();
        state.members.all().iter()
            .find(|m| m.identity.to_string().starts_with(short))
            .map(|m| m.identity)
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
        // Sync into the shared ACL used by the forwarding layer
        self.shared_acl.set(network, data.clone());

        let hash = acl::acl_hash(data);
        let bytes = acl::canonical_acl_bytes(data);
        let _ = self.blob_store.blobs().add_slice(&bytes).await;

        if let Ok(client) = dht::create_pkarr_client(&self.endpoint) {
            let acl_key = dht::derive_acl_key(&self.secret_key, network);
            if let Err(e) = dht::publish_acl(&client, &acl_key, &hash).await {
                tracing::warn!(error = %e, "failed to publish ACL to DHT");
            }
        }

        let msg = ControlMsg::AclUpdated { acl_hash: hash };
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
            let networks = self.networks.read().unwrap();
            let Some(handle) = networks.get(network) else {
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

        let acl = self.networks.read().unwrap().get(network).unwrap()
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
            let networks = self.networks.read().unwrap();
            let Some(handle) = networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            if let Some(assignment) = state.acl.tags.iter_mut().find(|a| a.tag == tag) {
                assignment.members.retain(|m| m != &id);
            }
            state.acl.tags.retain(|a| !a.members.is_empty());
        }

        let acl = self.networks.read().unwrap().get(network).unwrap()
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
            let networks = self.networks.read().unwrap();
            let Some(handle) = networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            state.acl.rules.push(acl::AclRule { src: src_target, dst: dst_target });
        }

        let acl = self.networks.read().unwrap().get(network).unwrap()
            .state.read().unwrap().acl.clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcResponse::Ok { message: format!("added allow {src} -> {dst}") }
    }

    async fn acl_remove(&self, network: &str, index: usize) -> IpcResponse {
        {
            let networks = self.networks.read().unwrap();
            let Some(handle) = networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            if index >= state.acl.rules.len() {
                return IpcResponse::Error { message: format!("rule index {index} out of range") };
            }
            state.acl.rules.remove(index);
        }

        let acl = self.networks.read().unwrap().get(network).unwrap()
            .state.read().unwrap().acl.clone();
        self.persist_acl(network, &acl);
        self.publish_and_broadcast_acl(network, &acl).await;
        IpcResponse::Ok { message: format!("removed rule {index}") }
    }

    fn acl_show(&self, network: &str) -> IpcResponse {
        let networks = self.networks.read().unwrap();
        let Some(handle) = networks.get(network) else {
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
            let networks = self.networks.read().unwrap();
            let Some(handle) = networks.get(network) else {
                return IpcResponse::Error { message: format!("network '{network}' not active") };
            };
            let mut state = handle.state.write().unwrap();
            state.acl = data.clone();
        }

        self.publish_and_broadcast_acl(network, &data).await;
        IpcResponse::Ok { message: "ACL applied".to_string() }
    }
}

pub async fn run_daemon(token: CancellationToken, stats: Arc<Stats>) -> Result<()> {
    let key = identity::load_or_create()?;
    let public_key = key.public();
    let secret_key = key.clone();
    let identity = IrohIdentityProvider::new(public_key);
    let my_ip = identity.local_ip();

    // Load saved networks to determine initial ALPNs
    let app_config = config::load()?;
    let mut alpns: Vec<Vec<u8>> = app_config
        .networks
        .iter()
        .map(|net| transport::network_alpn(&net.name))
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
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);
    forward::spawn_tun_writer(tun_writer, tun_rx);
    tokio::spawn(forward::run_mesh(
        tun_reader,
        peers.clone(),
        public_key,
        shared_acl.clone(),
        token.clone(),
        stats.clone(),
    ));

    let daemon = Arc::new(DaemonState {
        endpoint: ep,
        secret_key,
        identity,
        peers,
        stats: stats.clone(),
        tun_tx,
        networks: Arc::new(std::sync::RwLock::new(HashMap::new())),
        shutdown_token: token.clone(),
        blob_store,
        blobs_proto,
        shared_acl,
    });

    tracing::info!(ip = %my_ip, id = %daemon.endpoint.id().fmt_short(), "daemon started");

    // Restore saved networks
    for net in &app_config.networks {
        if net.my_ip.is_some() {
            // We're a member — rejoin via DHT name lookup
            let name = net.name.clone();
            let daemon_c = daemon.clone();
            tokio::spawn(async move {
                match daemon_c.join_network_inner(&name).await {
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
        } else {
            // We're the coordinator — restore with existing name
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

fn spawn_dht_publisher(
    client: PkarrRelayClient,
    membership_key: SecretKey,
    state: Arc<std::sync::RwLock<NetworkState>>,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let hash = {
                let s = state.read().unwrap();
                s.snapshot.as_ref().map(|snap| snap.hash.clone())
                    .unwrap_or_else(|| membership_hash(&s.members, &s.approved))
            };
            match dht::publish_membership(&client, &membership_key, &hash).await {
                Ok(()) => tracing::info!("published membership hash to DHT"),
                Err(e) => tracing::warn!(error = %e, "failed to publish membership to DHT"),
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(300)) => {},
            }
        }
    })
}

fn spawn_seed_list_publisher(
    client: PkarrRelayClient,
    network_secret: [u8; 32],
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let key = SecretKey::from_bytes(&network_secret);
        loop {
            let mut peer_ids: Vec<EndpointId> = peers
                .peers_for_network(&network_name)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            peer_ids.push(endpoint_id);
            peer_ids.sort_by_key(|id| id.to_string());
            peer_ids.dedup();

            match dht::publish_seed_list(&client, &key, &peer_ids).await {
                Ok(()) => tracing::info!(count = peer_ids.len(), "published seed list"),
                Err(e) => tracing::warn!(error = %e, "failed to publish seed list"),
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
fn spawn_membership_poller(
    client: PkarrRelayClient,
    membership_dht_pubkey: EndpointId,
    state: Arc<std::sync::RwLock<NetworkState>>,
    endpoint: Endpoint,
    blob_store: FsStore,
    peers: PeerTable,
    network_name: String,
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
                s.snapshot.as_ref().map(|snap| snap.hash.clone())
            };

            let remote_hash = match dht::resolve_membership_hash(&client, membership_dht_pubkey).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!(error = %e, "membership poll failed");
                    continue;
                }
            };

            if current_hash.as_deref() == Some(remote_hash.as_str()) {
                continue;
            }

            tracing::info!(old = ?current_hash, new = %remote_hash, "membership changed");

            let blob_hash = match remote_hash.parse::<blake3::Hash>() {
                Ok(h) => iroh_blobs::Hash::from_bytes(*h.as_bytes()),
                Err(e) => {
                    tracing::warn!(error = %e, "invalid membership hash");
                    continue;
                }
            };

            // Try fetching from any connected peer
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
                        match rmp_serde::from_slice::<crate::membership::MembershipData>(&bytes) {
                            Ok(data) => { new_data = Some(data); break; }
                            Err(_) => continue,
                        }
                    }
                    Err(_) => continue,
                }
            }

            let Some(data) = new_data else {
                tracing::warn!("could not fetch updated membership from any peer");
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

            // Check if we were removed
            let my_id = endpoint.id();
            if !new_member_ids.contains(&my_id)
                && !data.approved.iter().any(|a| a.identity == my_id)
            {
                tracing::warn!("we have been removed from the network");
                break;
            }

            // Update state
            {
                let mut s = state.write().unwrap();
                s.members = MemberList::from_members(data.members);
                s.approved = ApprovedList::from_entries(data.approved);
                s.network_secret = data.network_secret;
                s.membership_signing_key = data.membership_signing_key;
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
    identity: IrohIdentityProvider,
    policy: Box<dyn MembershipPolicy>,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<Stats>,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    dht_id: Option<String>,
    acl_dht_id: Option<String>,
    blob_store: FsStore,
    blobs_proto: BlobsProtocol,
    shared_acl: forward::SharedAcl,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_accept_loop(
            &ep,
            &transport::network_alpn(&network_name),
            &network_name,
            &identity,
            &*policy,
            state,
            peers,
            tun_tx,
            disconnect_tx,
            token,
            stats,
            dht_notify,
            dht_id,
            acl_dht_id,
            blob_store,
            blobs_proto,
            shared_acl,
        ).await {
            tracing::warn!(network = %network_name, error = %e, "accept loop stopped");
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_accept_loop(
    ep: &Endpoint,
    alpn: &[u8],
    network_name: &str,
    identity: &IrohIdentityProvider,
    policy: &dyn MembershipPolicy,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<Stats>,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    dht_id: Option<String>,
    acl_dht_id: Option<String>,
    blob_store: FsStore,
    blobs_proto: BlobsProtocol,
    shared_acl: forward::SharedAcl,
) -> Result<()> {
    let self_member = {
        let s = state.read().unwrap();
        s.members.get(&identity.local_identity()).cloned().unwrap()
    };

    loop {
        tracing::info!(network = %network_name, "waiting for peers...");

        let conn = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = transport::accept_connection_with_alpn(ep) => {
                match result {
                    Ok((conn, conn_alpn)) => {
                        if conn_alpn == iroh_blobs::protocol::ALPN {
                            let proto = blobs_proto.clone();
                            tokio::spawn(async move { let _ = proto.accept(conn).await; });
                            continue;
                        }
                        if conn_alpn != alpn {
                            continue;
                        }
                        conn
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to accept connection");
                        continue;
                    }
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
            let dht_id_c = dht_id.clone();
            let local_id = ep.id();
            let network_c = network_name.to_string();
            let shared_acl_c = shared_acl.clone();
            tokio::spawn(async move {
                send_member_sync(&conn, &members, dht_id_c).await;
                forward::spawn_peer_reader(conn, remote_id, peer_ip, local_id, network_c, shared_acl_c, tun_tx_c, disconnect_tx_c, token_c, stats_c);
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
                let new_member = Member { identity: remote_id, ip: peer_ip, is_coordinator: false };
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
                    members: members.clone(), approved, membership_dht_id: dht_id.clone(), acl_dht_id: acl_dht_id.clone(),
                }).await;
            }
            broadcast_member_sync(&peers, &members, Some(peer_ip), dht_id.clone()).await;
            peers.add(peer_ip, conn.clone(), remote_id, network_name);
            let token_c = token.clone();
            let stats_c = stats.clone();
            let tun_tx_c = tun_tx.clone();
            let disconnect_tx_c = disconnect_tx.clone();
            let local_id = ep.id();
            let network_c = network_name.to_string();
            let shared_acl_c = shared_acl.clone();
            tokio::spawn(async move {
                forward::spawn_peer_reader(conn, remote_id, peer_ip, local_id, network_c, shared_acl_c, tun_tx_c, disconnect_tx_c, token_c, stats_c);
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

        // Broadcast MemberApproved
        broadcast_control_msg(&peers, &ControlMsg::MemberApproved { identity: remote_id, ip: peer_ip }).await;

        // Promote to member
        let (add_collision, snap_bytes): (Option<String>, Option<Vec<u8>>) = {
            let mut s = state.write().unwrap();
            let result = s.members.add(Member { identity: remote_id, ip: peer_ip, is_coordinator: false })
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
                members: members.clone(), approved, membership_dht_id: dht_id.clone(), acl_dht_id: acl_dht_id.clone(),
            }).await;
        }
        broadcast_member_sync(&peers, &members, Some(peer_ip), dht_id.clone()).await;
        peers.add(peer_ip, conn.clone(), remote_id, network_name);
        let token_c = token.clone();
        let stats_c = stats.clone();
        let tun_tx_c = tun_tx.clone();
        let disconnect_tx_c = disconnect_tx.clone();
        let local_id = ep.id();
        let network_c = network_name.to_string();
        let shared_acl_c = shared_acl.clone();
        tokio::spawn(async move {
            forward::spawn_peer_reader(conn, remote_id, peer_ip, local_id, network_c, shared_acl_c, tun_tx_c, disconnect_tx_c, token_c, stats_c);
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn join_mesh_shared(
    initial_conn: Connection,
    ep: &Endpoint,
    network_name: &str,
    identity: &IrohIdentityProvider,
    alpn: &[u8],
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<Stats>,
    blob_store: FsStore,
    blobs_proto: BlobsProtocol,
    shared_acl: forward::SharedAcl,
) -> Result<Arc<std::sync::RwLock<NetworkState>>> {
    let my_identity = identity.local_identity();
    let my_ip = identity.local_ip();

    let (_send, mut recv) = initial_conn.accept_bi().await.context("accept control stream")?;
    let msg = control::recv_msg(&mut recv).await?;
    let (members, approved, received_dht_id, received_acl_dht_id) = match msg {
        ControlMsg::Welcome { members, approved, membership_dht_id, acl_dht_id } => {
            tracing::info!(network = %network_name, "welcomed to network");
            if let Some(existing) = members.iter().find(|m| m.ip == my_ip && m.identity != my_identity) {
                anyhow::bail!("IP collision: {} is already assigned to {}", my_ip, existing.identity);
            }
            (members, approved, membership_dht_id, acl_dht_id)
        }
        ControlMsg::JoinApproved { your_ip, members } => {
            tracing::info!(ip = %your_ip, network = %network_name, "joined network (legacy)");
            (members, vec![], None, None)
        }
        ControlMsg::MemberSync { members, membership_dht_id } => {
            tracing::info!(network = %network_name, "reconnected via peer");
            (members, vec![], membership_dht_id, None)
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
        identity: m.identity, ip: m.ip, is_coordinator: m.is_coordinator,
    }).collect();
    let approved_config: Vec<config::ApprovedConfigEntry> = approved.iter().map(|a| config::ApprovedConfigEntry {
        identity: a.identity, ip: a.ip,
    }).collect();
    let mut app_config = config::load()?;
    let dht_id_to_save = received_dht_id.clone().or_else(|| {
        app_config.networks.iter().find(|n| n.name == network_name).and_then(|n| n.membership_dht_id.clone())
    });
    config::upsert_network(&mut app_config, config::NetworkConfig {
        name: network_name.to_string(),
        group_mode: GroupMode::Restricted,
        my_ip: Some(my_ip),
        members: member_entries,
        approved: approved_config,
        membership_dht_id: dht_id_to_save,
        network_pkarr_pubkey: None,
        membership_dht_pubkey: None,
    });
    config::save(&app_config)?;

    // Add initial connection peer
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);
    crate::spawn_path_logger(initial_conn.clone(), remote_id.fmt_short().to_string());
    peers.add(remote_ip, initial_conn.clone(), remote_id, network_name);
    forward::spawn_peer_reader(
        initial_conn.clone(), remote_id, remote_ip,
        ep.id(), network_name.to_string(), shared_acl.clone(),
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
                control::send_msg(&mut send, &ControlMsg::MeshHello { identity: my_identity, ip: my_ip }).await?;
                peers.add(member.ip, conn.clone(), member.identity, network_name);
                forward::spawn_peer_reader(conn, member.identity, member.ip, ep.id(), network_name.to_string(), shared_acl.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
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
            network_secret: [0u8; 32],
            membership_signing_key: [0u8; 32],
            acl: acl::AclData::empty(),
        };
        ns.refresh_snapshot();
        if let Some(snap) = &ns.snapshot {
            let _ = blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }
        Arc::new(std::sync::RwLock::new(ns))
    };

    // Fetch ACL from DHT if coordinator provided an ACL DHT ID
    if let Some(acl_id_str) = received_acl_dht_id
        && let Ok(acl_dht_id_parsed) = acl_id_str.parse::<EndpointId>()
        && let Ok(pkarr_client) = dht::create_pkarr_client(ep)
    {
            match dht::resolve_acl_hash(&pkarr_client, acl_dht_id_parsed).await {
                Ok(acl_hash) => {
                    match acl_hash.parse::<blake3::Hash>() {
                        Ok(b3_hash) => {
                            let blob_hash = iroh_blobs::Hash::from_bytes(*b3_hash.as_bytes());
                            let peer_ids: Vec<EndpointId> = peers
                                .peers_for_network(network_name)
                                .into_iter()
                                .map(|(id, _)| id)
                                .collect();
                            let mut fetched = false;
                            for pid in &peer_ids {
                                if let Ok(conn) = transport::connect_to_peer_with_alpn(
                                    ep, *pid, iroh_blobs::protocol::ALPN,
                                ).await
                                    && blob_store.remote().fetch(
                                        conn, HashAndFormat::raw(blob_hash),
                                    ).await.is_ok()
                                {
                                    fetched = true;
                                    break;
                                }
                            }
                            if fetched {
                                if let Ok(bytes) = blob_store.blobs().get_bytes(blob_hash).await {
                                    match acl::verify_acl_data(&bytes, &acl_hash) {
                                        Ok(data) => {
                                            shared_acl.set(network_name, data.clone());
                                            live_state.write().unwrap().acl = data;
                                            tracing::info!(network = %network_name, "ACL loaded from DHT on join");
                                        }
                                        Err(e) => tracing::warn!(error = %e, "ACL verification failed on join"),
                                    }
                                }
                            } else {
                                tracing::warn!(network = %network_name, "could not fetch ACL blob from any peer on join");
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "invalid ACL hash from DHT"),
                    }
                }
                Err(e) => tracing::warn!(error = %e, "failed to resolve ACL hash from DHT on join"),
            }
    }

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
                                    Ok(ControlMsg::MemberApproved { identity, ip }) => {
                                        let entry = ApprovedEntry { identity, ip };
                                        let mut s = live_state.write().unwrap();
                                        let members = s.members.clone();
                                        let _ = s.approved.approve(entry, &members);
                                    }
                                    Ok(ControlMsg::MemberSync { members, membership_dht_id }) => {
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
                                        if membership_dht_id.is_some()
                                            && let Ok(mut cfg) = config::load()
                                            && let Some(net) = cfg.networks.iter_mut().find(|n| n.name == network_name)
                                        {
                                            net.membership_dht_id = membership_dht_id;
                                            let _ = config::save(&cfg);
                                        }
                                    }
                                    Ok(ControlMsg::AclUpdated { acl_hash }) => {
                                        tracing::info!(hash = %acl_hash, "received ACL update");
                                        let blob_hash = match acl_hash.parse::<blake3::Hash>() {
                                            Ok(h) => iroh_blobs::Hash::from_bytes(*h.as_bytes()),
                                            Err(_) => continue,
                                        };
                                        // Fetch from any connected peer
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
                                            match acl::verify_acl_data(&bytes, &acl_hash) {
                                                Ok(data) => {
                                                    shared_acl_ctrl.set(&network_name, data.clone());
                                                    live_state.write().unwrap().acl = data;
                                                    tracing::info!("ACL updated");
                                                }
                                                Err(e) => tracing::warn!(error = %e, "ACL verification failed"),
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
        let expected_alpn = alpn.to_vec();
        let live_state = live_state.clone();
        let network_name = network_name.to_string();
        let blob_store = blob_store.clone();
        let blobs_proto = blobs_proto.clone();
        let shared_acl = shared_acl.clone();
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = transport::accept_connection_with_alpn(&ep) => {
                        if let Ok((conn, conn_alpn)) = result {
                            if conn_alpn == iroh_blobs::protocol::ALPN {
                                let proto = blobs_proto.clone();
                                tokio::spawn(async move { let _ = proto.accept(conn).await; });
                                continue;
                            }
                            if conn_alpn != expected_alpn { continue; }
                            if let Ok((_send, mut recv)) = conn.accept_bi().await {
                                let transport_id = conn.remote_id();
                                match control::recv_msg(&mut recv).await {
                                    Ok(ControlMsg::MeshHello { identity: peer_identity, ip }) => {
                                        if peer_identity != transport_id { continue; }
                                        let (is_member, is_approved) = {
                                            let s = live_state.read().unwrap();
                                            (s.members.is_member(&peer_identity), s.approved.is_approved(&peer_identity))
                                        };
                                        if is_approved {
                                            let snap_bytes = {
                                                let mut s = live_state.write().unwrap();
                                                s.approved.remove(&peer_identity);
                                                let _ = s.members.add(Member { identity: peer_identity, ip, is_coordinator: false });
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
                                                    members: members.clone(), approved: approved_list, membership_dht_id: None, acl_dht_id: None,
                                                }).await;
                                            }
                                            peers.add(ip, conn.clone(), peer_identity, &network_name);
                                            forward::spawn_peer_reader(conn, peer_identity, ip, ep.id(), network_name.clone(), shared_acl.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                                            broadcast_member_sync(&peers, &members, Some(ip), None).await;
                                        } else if is_member {
                                            peers.add(ip, conn.clone(), peer_identity, &network_name);
                                            forward::spawn_peer_reader(conn, peer_identity, ip, ep.id(), network_name.clone(), shared_acl.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                                        }
                                    }
                                    Ok(ControlMsg::ReconnectRequest { identity: peer_identity, ip }) => {
                                        if peer_identity != transport_id { continue; }
                                        let is_known = live_state.read().unwrap().members.is_member(&peer_identity);
                                        if is_known {
                                            peers.add(ip, conn.clone(), peer_identity, &network_name);
                                            let current_members: Vec<Member> = live_state.read().unwrap().members.all().into_iter().cloned().collect();
                                            if let Ok((mut send, _)) = conn.open_bi().await {
                                                let _ = control::send_msg(&mut send, &ControlMsg::MemberSync { members: current_members, membership_dht_id: None }).await;
                                            }
                                            forward::spawn_peer_reader(conn, peer_identity, ip, ep.id(), network_name.clone(), shared_acl.clone(), tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                                        }
                                    }
                                    _ => {}
                                }
                            }
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
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<Stats>,
    shared_acl: forward::SharedAcl,
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
                            if let Err(e) = control::send_msg(&mut send, &ControlMsg::MeshHello { identity: my_identity, ip: my_ip }).await {
                                tracing::warn!(error = %e, "reconnect MeshHello failed");
                                continue;
                            }
                            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "reconnected to peer");
                            peers.add(peer_ip, conn.clone(), peer_id, &network_name);
                            forward::spawn_peer_reader(conn, peer_id, peer_ip, my_identity, network_name, shared_acl, tun_tx, disconnect_tx, token, stats);
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

async fn send_member_sync(conn: &Connection, members: &[Member], dht_id: Option<String>) {
    if let Ok((mut send, _)) = conn.open_bi().await {
        let _ = control::send_msg(&mut send, &ControlMsg::MemberSync { members: members.to_vec(), membership_dht_id: dht_id }).await;
    }
}

async fn broadcast_member_sync(peers: &PeerTable, members: &[Member], exclude_ip: Option<Ipv4Addr>, dht_id: Option<String>) {
    let msg = ControlMsg::MemberSync { members: members.to_vec(), membership_dht_id: dht_id };
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
