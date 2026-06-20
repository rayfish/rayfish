use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, Endpoint};
use iroh::{EndpointId, SecretKey};
use iroh::address_lookup::PkarrRelayClient;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::control::{self, ControlMsg};
use crate::dht;
use crate::forward;
use crate::identity;
use crate::ipc::{self, IpcRequest, IpcResponse, NetworkRole, NetworkStatus, PeerStatus};
use crate::membership::{
    ApprovedEntry, ApprovedList, GroupMode, IdentityProvider, IrohIdentityProvider, Member,
    MemberList, MembershipPolicy, policy_for_mode,
};
use crate::peers::PeerTable;
use crate::room_code;
use crate::stats::Stats;
use crate::transport;
use crate::tun;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
}

#[allow(dead_code)]
pub struct NetworkHandle {
    name: String,
    role: NetworkRole,
    my_ip: Ipv4Addr,
    state: Arc<std::sync::RwLock<NetworkState>>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    room_code: Option<String>,
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
}

impl DaemonState {
    fn refresh_alpns(&self) {
        let networks = self.networks.read().unwrap();
        let alpns: Vec<Vec<u8>> = networks
            .keys()
            .map(|n| transport::network_alpn(n))
            .collect();
        self.endpoint.set_alpns(alpns);
    }

    async fn handle_request(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::Create { name, mode } => self.create_network(&name, mode).await,
            IpcRequest::Join { node_id, name } => self.join_network(&node_id, name.as_deref()).await,
            IpcRequest::Leave { name } => self.leave_network(&name).await,
            IpcRequest::Status => self.status(),
            IpcRequest::Shutdown => {
                self.shutdown_token.cancel();
                IpcResponse::Ok { message: "shutting down".to_string() }
            }
        }
    }

    async fn create_network(&self, name: &str, mode: GroupMode) -> IpcResponse {
        {
            let networks = self.networks.read().unwrap();
            if networks.contains_key(name) {
                return IpcResponse::Error {
                    message: format!("network '{}' already active", name),
                };
            }
        }

        match self.create_network_inner(name, mode).await {
            Ok(resp) => resp,
            Err(e) => IpcResponse::Error { message: format!("{e:#}") },
        }
    }

    async fn create_network_inner(&self, name: &str, mode: GroupMode) -> Result<IpcResponse> {
        let membership_key = dht::derive_membership_key(&self.secret_key, name);
        let dht_id = dht::membership_dht_id(&self.secret_key, name).to_string();
        let my_ip = self.identity.local_ip();
        let room_code = room_code::encode(name, &self.endpoint.id());
        let policy = policy_for_mode(mode);

        let mut member_list = MemberList::new();
        member_list
            .add(Member {
                identity: self.identity.local_identity(),
                ip: my_ip,
                is_coordinator: true,
            })
            .expect("self-add cannot collide");

        let net_state = NetworkState {
            members: member_list,
            approved: ApprovedList::new(),
        };

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
            name: name.to_string(),
            coordinator_id: self.endpoint.id(),
            group_mode: mode,
            my_ip: Some(my_ip),
            members: member_entries,
            approved: approved_entries,
            membership_dht_id: Some(dht_id.clone()),
        });
        config::save(&app_config)?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let mut tasks = Vec::new();

        // DHT publisher
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

        // Disconnect handler (coordinator removes dead peers)
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(disconnect_rx, self.peers.clone(), cancel.clone()));

        // Accept loop for this network
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
        );
        tasks.push(accept_handle);

        // Update ALPNs
        let handle = NetworkHandle {
            name: name.to_string(),
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            cancel,
            tasks,
            room_code: Some(room_code.clone()),
        };
        self.networks.write().unwrap().insert(name.to_string(), handle);
        self.refresh_alpns();

        tracing::info!(name, ip = %my_ip, room_code = %room_code, "network created");

        Ok(IpcResponse::Created {
            name: name.to_string(),
            room_code,
            my_ip,
        })
    }

    async fn join_network(&self, node_id_str: &str, name_override: Option<&str>) -> IpcResponse {
        match self.join_network_inner(node_id_str, name_override).await {
            Ok(resp) => resp,
            Err(e) => IpcResponse::Error { message: format!("{e:#}") },
        }
    }

    async fn join_network_inner(&self, node_id_str: &str, name_override: Option<&str>) -> Result<IpcResponse> {
        let parsed = room_code::parse_input(node_id_str).context("invalid node ID or room code")?;
        let network_name = name_override.unwrap_or_else(|| {
            if parsed.network_name.is_empty() { "default" } else { &parsed.network_name }
        }).to_string();

        {
            let networks = self.networks.read().unwrap();
            if networks.contains_key(&network_name) {
                return Ok(IpcResponse::Error {
                    message: format!("network '{}' already active", network_name),
                });
            }
        }

        let alpn = transport::network_alpn(&network_name);
        let my_ip = self.identity.local_ip();

        // Connect to coordinator
        let conn = transport::connect_to_peer_with_alpn(
            &self.endpoint,
            parsed.endpoint_id,
            &alpn,
        ).await.context("could not reach coordinator")?;

        let cancel = self.shutdown_token.child_token();
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

        // Reconnect loop
        let tasks = vec![spawn_reconnect_loop(
            disconnect_rx,
            self.endpoint.clone(),
            alpn.clone(),
            network_name.clone(),
            self.identity.local_identity(),
            my_ip,
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
            self.stats.clone(),
        )];

        // Join mesh
        let state = join_mesh_shared(
            conn,
            &self.endpoint,
            &network_name,
            &self.identity,
            &alpn,
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx,
            cancel.clone(),
            self.stats.clone(),
        ).await?;

        let handle = NetworkHandle {
            name: network_name.clone(),
            role: NetworkRole::Member,
            my_ip,
            state,
            cancel,
            tasks,
            room_code: None,
        };
        self.networks.write().unwrap().insert(network_name.clone(), handle);
        self.refresh_alpns();

        tracing::info!(network = %network_name, ip = %my_ip, "joined network");

        Ok(IpcResponse::Joined {
            name: network_name,
            my_ip,
        })
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
}

pub async fn run_daemon(token: CancellationToken, stats: Arc<Stats>) -> Result<()> {
    let key = identity::load_or_create()?;
    let public_key = key.public();
    let secret_key = key.clone();
    let identity = IrohIdentityProvider::new(public_key);
    let my_ip = identity.local_ip();

    // Load saved networks to determine initial ALPNs
    let app_config = config::load()?;
    let alpns: Vec<Vec<u8>> = app_config
        .networks
        .iter()
        .map(|net| transport::network_alpn(&net.name))
        .collect();

    let ep = transport::create_endpoint_with_alpns(key, alpns).await?;

    // Single TUN for all networks
    let (tun_reader, tun_writer) = tun::create(my_ip).context("failed to create TUN device")?;
    let peers = PeerTable::new();
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);
    forward::spawn_tun_writer(tun_writer, tun_rx);
    tokio::spawn(forward::run_mesh(
        tun_reader,
        peers.clone(),
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
    });

    tracing::info!(ip = %my_ip, id = %daemon.endpoint.id().fmt_short(), "daemon started");

    // Restore saved networks
    for net in &app_config.networks {
        if net.my_ip.is_some() {
            // We're a member — join
            let node_id_str = net.coordinator_id.to_string();
            let name = net.name.clone();
            let daemon_c = daemon.clone();
            tokio::spawn(async move {
                match daemon_c.join_network_inner(&node_id_str, Some(&name)).await {
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
            // We're the coordinator — create
            let name = net.name.clone();
            let mode = net.group_mode;
            let daemon_c = daemon.clone();
            tokio::spawn(async move {
                match daemon_c.create_network_inner(&name, mode).await {
                    Ok(IpcResponse::Created { name, room_code, .. }) => {
                        tracing::info!(network = %name, room_code = %room_code, "restored coordinator network");
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
            let (members_snapshot, approved_snapshot) = {
                let s = state.read().unwrap();
                (s.members.clone(), s.approved.clone())
            };
            match dht::publish_membership(&client, &membership_key, &members_snapshot, &approved_snapshot).await {
                Ok(()) => tracing::info!("published membership to DHT"),
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
            tokio::spawn(async move {
                send_member_sync(&conn, &members, dht_id_c).await;
                forward::spawn_peer_reader(conn, remote_id, peer_ip, tun_tx_c, disconnect_tx_c, token_c, stats_c);
            });
            continue;
        }

        // Approved but not yet connected
        let is_approved = state.read().unwrap().approved.is_approved(&remote_id);
        if is_approved {
            tracing::info!(ip = %peer_ip, "approved peer connecting");
            {
                let mut s = state.write().unwrap();
                s.approved.remove(&remote_id);
                let new_member = Member { identity: remote_id, ip: peer_ip, is_coordinator: false };
                s.members.add(new_member).expect("was approved, no collision");
            }
            if let Some(notify) = &dht_notify { notify.notify_one(); }
            let (members, approved) = {
                let s = state.read().unwrap();
                (s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                 s.approved.all().into_iter().cloned().collect::<Vec<_>>())
            };
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(&mut send, &ControlMsg::Welcome {
                    members: members.clone(), approved, membership_dht_id: dht_id.clone(),
                }).await;
            }
            broadcast_member_sync(&peers, &members, Some(peer_ip), dht_id.clone()).await;
            peers.add(peer_ip, conn.clone(), remote_id, network_name);
            let token_c = token.clone();
            let stats_c = stats.clone();
            let tun_tx_c = tun_tx.clone();
            let disconnect_tx_c = disconnect_tx.clone();
            tokio::spawn(async move {
                forward::spawn_peer_reader(conn, remote_id, peer_ip, tun_tx_c, disconnect_tx_c, token_c, stats_c);
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
        let add_collision: Option<String> = {
            let mut s = state.write().unwrap();
            s.members.add(Member { identity: remote_id, ip: peer_ip, is_coordinator: false })
                .err().map(|e| format!("IP collision: {e}"))
        };
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
                members: members.clone(), approved, membership_dht_id: dht_id.clone(),
            }).await;
        }
        broadcast_member_sync(&peers, &members, Some(peer_ip), dht_id.clone()).await;
        peers.add(peer_ip, conn.clone(), remote_id, network_name);
        let token_c = token.clone();
        let stats_c = stats.clone();
        let tun_tx_c = tun_tx.clone();
        let disconnect_tx_c = disconnect_tx.clone();
        tokio::spawn(async move {
            forward::spawn_peer_reader(conn, remote_id, peer_ip, tun_tx_c, disconnect_tx_c, token_c, stats_c);
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
) -> Result<Arc<std::sync::RwLock<NetworkState>>> {
    let my_identity = identity.local_identity();
    let my_ip = identity.local_ip();

    let (_send, mut recv) = initial_conn.accept_bi().await.context("accept control stream")?;
    let msg = control::recv_msg(&mut recv).await?;
    let (members, approved, received_dht_id) = match msg {
        ControlMsg::Welcome { members, approved, membership_dht_id } => {
            tracing::info!(network = %network_name, "welcomed to network");
            if let Some(existing) = members.iter().find(|m| m.ip == my_ip && m.identity != my_identity) {
                anyhow::bail!("IP collision: {} is already assigned to {}", my_ip, existing.identity);
            }
            (members, approved, membership_dht_id)
        }
        ControlMsg::JoinApproved { your_ip, members } => {
            tracing::info!(ip = %your_ip, network = %network_name, "joined network (legacy)");
            (members, vec![], None)
        }
        ControlMsg::MemberSync { members, membership_dht_id } => {
            tracing::info!(network = %network_name, "reconnected via peer");
            (members, vec![], membership_dht_id)
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
        coordinator_id: initial_conn.remote_id(),
        group_mode: GroupMode::Restricted,
        my_ip: Some(my_ip),
        members: member_entries,
        approved: approved_config,
        membership_dht_id: dht_id_to_save,
    });
    config::save(&app_config)?;

    // Add initial connection peer
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);
    crate::spawn_path_logger(initial_conn.clone(), remote_id.fmt_short().to_string());
    peers.add(remote_ip, initial_conn.clone(), remote_id, network_name);
    forward::spawn_peer_reader(
        initial_conn.clone(), remote_id, remote_ip,
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
                forward::spawn_peer_reader(conn, member.identity, member.ip, tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                tracing::info!(peer_ip = %member.ip, "connected to mesh peer");
            }
            Err(e) => {
                tracing::warn!(peer_ip = %member.ip, error = %e, "mesh peer unavailable");
            }
        }
    }

    let live_state = Arc::new(std::sync::RwLock::new(NetworkState {
        members: MemberList::from_members(members.clone()),
        approved: ApprovedList::from_entries(approved),
    }));

    // Control listener
    tokio::spawn({
        let initial_conn = initial_conn.clone();
        let token = token.clone();
        let live_state = live_state.clone();
        let network_name = network_name.to_string();
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
                                        live_state.write().unwrap().members = MemberList::from_members(members);
                                        if membership_dht_id.is_some()
                                            && let Ok(mut cfg) = config::load()
                                            && let Some(net) = cfg.networks.iter_mut().find(|n| n.name == network_name)
                                        {
                                            net.membership_dht_id = membership_dht_id;
                                            let _ = config::save(&cfg);
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
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = transport::accept_connection_with_alpn(&ep) => {
                        match result {
                            Ok((conn, conn_alpn)) => {
                                if conn_alpn != expected_alpn { continue; }
                                match conn.accept_bi().await {
                                    Ok((_send, mut recv)) => {
                                        let transport_id = conn.remote_id();
                                        match control::recv_msg(&mut recv).await {
                                            Ok(ControlMsg::MeshHello { identity: peer_identity, ip }) => {
                                                if peer_identity != transport_id { continue; }
                                                let (is_member, is_approved) = {
                                                    let s = live_state.read().unwrap();
                                                    (s.members.is_member(&peer_identity), s.approved.is_approved(&peer_identity))
                                                };
                                                if is_approved {
                                                    {
                                                        let mut s = live_state.write().unwrap();
                                                        s.approved.remove(&peer_identity);
                                                        let _ = s.members.add(Member { identity: peer_identity, ip, is_coordinator: false });
                                                    }
                                                    let (members, approved_list) = {
                                                        let s = live_state.read().unwrap();
                                                        (s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                                                         s.approved.all().into_iter().cloned().collect::<Vec<_>>())
                                                    };
                                                    if let Ok((mut send, _)) = conn.open_bi().await {
                                                        let _ = control::send_msg(&mut send, &ControlMsg::Welcome {
                                                            members: members.clone(), approved: approved_list, membership_dht_id: None,
                                                        }).await;
                                                    }
                                                    peers.add(ip, conn.clone(), peer_identity, &network_name);
                                                    forward::spawn_peer_reader(conn, peer_identity, ip, tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                                                    broadcast_member_sync(&peers, &members, Some(ip), None).await;
                                                } else if is_member {
                                                    peers.add(ip, conn.clone(), peer_identity, &network_name);
                                                    forward::spawn_peer_reader(conn, peer_identity, ip, tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
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
                                                    forward::spawn_peer_reader(conn, peer_identity, ip, tun_tx.clone(), disconnect_tx.clone(), token.clone(), stats.clone());
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
    });

    Ok(live_state)
}

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
                            forward::spawn_peer_reader(conn, peer_id, peer_ip, tun_tx, disconnect_tx, token, stats);
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
