mod acl;
mod audit;
mod dht;
mod config;
mod control;
mod forward;
mod identity;
mod membership;
mod peers;
mod room_code;
mod shutdown;
mod stats;
mod transport;
mod tun;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use iroh::EndpointId;
use iroh::SecretKey;
use iroh::address_lookup::PkarrRelayClient;
use iroh::endpoint::Endpoint;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use control::ControlMsg;
use membership::{
    ApprovedEntry, ApprovedList, GroupMode, IdentityProvider, IrohIdentityProvider, Member,
    MemberList, MembershipPolicy, policy_for_mode,
};
use peers::PeerTable;
use stats::Stats;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
}

#[derive(Parser)]
#[command(name = "pitopi", about = "P2P mesh VPN powered by iroh")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new network and wait for peers
    Create {
        /// Network name (defaults to "default")
        #[arg(long, default_value = "default")]
        name: String,
        /// Membership mode: open or restricted
        #[arg(long, default_value = "restricted")]
        mode: GroupMode,
    },
    /// Join an existing network using a node ID or room code
    Join {
        /// The endpoint ID or room code of the network creator
        node_id: String,
        /// Network name (override the name from room code)
        #[arg(long)]
        name: Option<String>,
    },
    /// List saved networks
    List,
    /// Leave a network (remove from saved config)
    Leave {
        /// Name of the network to leave
        name: String,
    },
    /// Show status of active networks
    Status,
    /// Connect to all saved networks
    Up,
    /// Disconnect from all networks
    Down,
    /// Install system service (systemd on Linux, launchd on macOS)
    InstallService,
    /// Uninstall system service
    UninstallService,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
}

fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("pitopi requires root privileges to create TUN devices. Run with sudo.");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    match cli.command {
        Command::List => cmd_list(),
        Command::Leave { name } => cmd_leave(&name),
        Command::Create { name, mode } => {
            check_root();
            let token = shutdown::token();
            let stats = stats::Stats::new();
            stats.spawn_logger(token.clone());
            cmd_create(&name, mode, token, stats).await
        }
        Command::Join { node_id, name } => {
            check_root();
            let parsed = room_code::parse_input(&node_id).context("invalid node ID or room code")?;
            let network_name = name.unwrap_or_else(|| {
                if parsed.network_name.is_empty() {
                    "default".to_string()
                } else {
                    parsed.network_name.clone()
                }
            });
            let token = shutdown::token();
            let stats = stats::Stats::new();
            stats.spawn_logger(token.clone());
            cmd_join(parsed.endpoint_id, &network_name, token, stats).await
        }
        Command::Status => cmd_status(),
        Command::Up => {
            check_root();
            let token = shutdown::token();
            let stats = stats::Stats::new();
            stats.spawn_logger(token.clone());
            cmd_up(token, stats).await
        }
        Command::Down => cmd_down(),
        Command::InstallService => cmd_install_service(),
        Command::UninstallService => cmd_uninstall_service(),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "pitopi", &mut std::io::stdout());
            Ok(())
        }
    }
}

fn spawn_dht_publisher(
    client: PkarrRelayClient,
    membership_key: SecretKey,
    state: Arc<std::sync::RwLock<NetworkState>>,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            // Read current state and publish
            let (members_snapshot, approved_snapshot) = {
                let s = state.read().unwrap();
                (s.members.clone(), s.approved.clone())
            };
            match dht::publish_membership(
                &client, &membership_key, &members_snapshot, &approved_snapshot,
            )
            .await
            {
                Ok(()) => tracing::info!("published membership to DHT"),
                Err(e) => tracing::warn!(error = %e, "failed to publish membership to DHT"),
            }

            // Wait for notification or periodic republish (5 min)
            tokio::select! {
                _ = token.cancelled() => break,
                _ = notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(300)) => {},
            }
        }
    });
}

async fn cmd_create(
    name: &str,
    mode: GroupMode,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let key = identity::load_or_create()?;
    let public_key = key.public();
    // Derive membership key and DHT ID before key is consumed by endpoint builder
    let membership_key = dht::derive_membership_key(&key, name);
    let dht_id = dht::membership_dht_id(&key, name).to_string();
    let alpn = transport::network_alpn(name);
    let ep = transport::create_endpoint_with_alpns(key, vec![alpn.clone()]).await?;

    let identity = IrohIdentityProvider::new(public_key);
    let my_ip = identity.local_ip();
    let room_code = room_code::encode(name, &ep.id());
    let policy = policy_for_mode(mode);

    tracing::info!(name = %name, mode = ?mode, "network created");
    tracing::info!(ip = %my_ip, "your virtual IP");
    tracing::info!(room_code = %room_code, "share this room code");
    tracing::info!(dht_id = %dht_id, "membership DHT ID");

    let mut member_list = MemberList::new();
    member_list
        .add(Member {
            identity: identity.local_identity(),
            ip: my_ip,
            is_coordinator: true,
        })
        .expect("self-add cannot collide");

    let state = NetworkState {
        members: member_list,
        approved: ApprovedList::new(),
    };

    let mut app_config = config::load()?;
    save_network_config(&mut app_config, name, &ep, mode, Some(my_ip), &state, Some(dht_id.clone()))?;

    let tun_dev = tun::TunDevice::create(my_ip).context("failed to create TUN device")?;

    let peers = PeerTable::new();
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);

    forward::spawn_tun_writer(tun_dev.share(), tun_rx);
    tokio::spawn(forward::run_mesh(
        tun_dev,
        peers.clone(),
        tun_tx.clone(),
        token.clone(),
        stats.clone(),
    ));

    let state = Arc::new(std::sync::RwLock::new(state));

    let pkarr_client = dht::create_pkarr_client(&ep)?;
    let dht_notify = Arc::new(tokio::sync::Notify::new());

    spawn_dht_publisher(
        pkarr_client,
        membership_key,
        state.clone(),
        dht_notify.clone(),
        token.clone(),
    );

    run_accept_loop(
        &ep, &alpn, &identity, &*policy, state, peers, tun_tx, token, stats,
        Some(dht_notify), Some(dht_id),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_accept_loop(
    ep: &Endpoint,
    alpn: &[u8],
    identity: &IrohIdentityProvider,
    policy: &dyn MembershipPolicy,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
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
        tracing::info!("waiting for peers...");

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

        // Case 1: Known member reconnecting
        let is_member = state.read().unwrap().members.is_member(&remote_id);
        if is_member {
            tracing::info!(ip = %peer_ip, "known member reconnecting");
            let members: Vec<Member> = state
                .read()
                .unwrap()
                .members
                .all()
                .into_iter()
                .cloned()
                .collect();
            peers.add(peer_ip, conn.clone(), remote_id);
            let token_c = token.clone();
            let stats_c = stats.clone();
            let tun_tx_c = tun_tx.clone();
            let dht_id_c = dht_id.clone();
            tokio::spawn(async move {
                send_member_sync(&conn, &members, dht_id_c).await;
                forward::spawn_peer_reader(conn, tun_tx_c, token_c, stats_c);
            });
            continue;
        }

        // Case 2: Approved but not yet connected as member
        let is_approved = state.read().unwrap().approved.is_approved(&remote_id);
        if is_approved {
            tracing::info!(ip = %peer_ip, "approved peer connecting");

            // Promote from approved to member
            {
                let mut s = state.write().unwrap();
                s.approved.remove(&remote_id);
                let new_member = Member {
                    identity: remote_id,
                    ip: peer_ip,
                    is_coordinator: false,
                };
                s.members
                    .add(new_member)
                    .expect("was approved, no collision");
            }

            if let Some(notify) = &dht_notify {
                notify.notify_one();
            }

            let (members, approved) = {
                let s = state.read().unwrap();
                let m: Vec<Member> = s.members.all().into_iter().cloned().collect();
                let a: Vec<ApprovedEntry> = s.approved.all().into_iter().cloned().collect();
                (m, a)
            };

            // Send Welcome to new peer
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(
                    &mut send,
                    &ControlMsg::Welcome {
                        members: members.clone(),
                        approved,
                        membership_dht_id: dht_id.clone(),
                    },
                )
                .await;
            }

            // Broadcast MemberSync to existing peers
            broadcast_member_sync(&peers, &members, Some(peer_ip), dht_id.clone()).await;

            peers.add(peer_ip, conn.clone(), remote_id);
            let token_c = token.clone();
            let stats_c = stats.clone();
            let tun_tx_c = tun_tx.clone();
            tokio::spawn(async move {
                forward::spawn_peer_reader(conn, tun_tx_c, token_c, stats_c);
            });
            continue;
        }

        // Case 3: Unknown peer — check policy and approve
        if !policy.can_authorize(&self_member) {
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
            continue;
        }

        // Check IP collision before broadcasting approval (drop lock before any await)
        let collision_reason: Option<String> = {
            let s = state.read().unwrap();
            if let Some(existing) = s.members.get_by_ip(peer_ip)
                && existing.identity != remote_id
            {
                tracing::warn!(ip = %peer_ip, existing = %existing.identity.fmt_short(), new = %remote_id.fmt_short(), "IP collision");
                Some(format!("IP collision: {} already assigned", peer_ip))
            } else if let Some(existing) = s.approved.get_by_ip(peer_ip)
                && existing.identity != remote_id
            {
                tracing::warn!(ip = %peer_ip, existing = %existing.identity.fmt_short(), new = %remote_id.fmt_short(), "IP collision (approved list)");
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

        // Broadcast MemberApproved to existing peers
        broadcast_control_msg(
            &peers,
            &ControlMsg::MemberApproved {
                identity: remote_id,
                ip: peer_ip,
            },
        )
        .await;

        // Immediately promote (peer is connected right now); collision shouldn't happen
        // after the check above, but handle defensively
        let add_collision: Option<String> = {
            let mut s = state.write().unwrap();
            let new_member = Member {
                identity: remote_id,
                ip: peer_ip,
                is_coordinator: false,
            };
            s.members.add(new_member).err().map(|e| {
                tracing::warn!(error = %e, "IP collision adding member after broadcast");
                format!("IP collision: {} already assigned", peer_ip)
            })
        };
        if let Some(reason) = add_collision {
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(&mut send, &ControlMsg::JoinDenied { reason }).await;
            }
            continue;
        }

        let (members, approved) = {
            let s = state.read().unwrap();
            let m: Vec<Member> = s.members.all().into_iter().cloned().collect();
            let a: Vec<ApprovedEntry> = s.approved.all().into_iter().cloned().collect();
            (m, a)
        };

        tracing::info!(ip = %peer_ip, "new member approved and joined");

        if let Some(notify) = &dht_notify {
            notify.notify_one();
        }

        // Send Welcome to new peer
        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(
                &mut send,
                &ControlMsg::Welcome {
                    members: members.clone(),
                    approved,
                    membership_dht_id: dht_id.clone(),
                },
            )
            .await;
        }

        // Broadcast MemberSync to existing peers
        broadcast_member_sync(&peers, &members, Some(peer_ip), dht_id.clone()).await;

        peers.add(peer_ip, conn.clone(), remote_id);
        let token_c = token.clone();
        let stats_c = stats.clone();
        let tun_tx_c = tun_tx.clone();
        tokio::spawn(async move {
            forward::spawn_peer_reader(conn, tun_tx_c, token_c, stats_c);
        });
    }
}

async fn send_member_sync(
    conn: &iroh::endpoint::Connection,
    members: &[Member],
    dht_id: Option<String>,
) {
    if let Ok((mut send, _)) = conn.open_bi().await {
        let _ = control::send_msg(
            &mut send,
            &ControlMsg::MemberSync {
                members: members.to_vec(),
                membership_dht_id: dht_id,
            },
        )
        .await;
    }
}

async fn broadcast_member_sync(
    peers: &PeerTable,
    members: &[Member],
    exclude_ip: Option<Ipv4Addr>,
    dht_id: Option<String>,
) {
    let msg = ControlMsg::MemberSync {
        members: members.to_vec(),
        membership_dht_id: dht_id,
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

async fn cmd_join(
    node_id: EndpointId,
    name: &str,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let key = identity::load_or_create()?;
    let public_key = key.public();
    let alpn = transport::network_alpn(name);
    let ep = transport::create_endpoint_with_alpns(key, vec![alpn.clone()]).await?;

    let identity = IrohIdentityProvider::new(public_key);
    let mut backoff = BACKOFF_INITIAL;

    loop {
        tracing::info!(network = %name, "connecting to network...");

        // Try coordinator first
        let conn = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = transport::connect_to_peer_with_alpn(&ep, node_id, &alpn) => {
                match result {
                    Ok(conn) => {
                        backoff = BACKOFF_INITIAL;
                        conn
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "coordinator unavailable, trying known peers...");

                        // Try known peers from config
                        if let Some(conn) = try_reconnect_to_known_peers(
                            &ep, name, &alpn, &identity, &token,
                        ).await {
                            conn
                        } else {
                            backoff_sleep(&token, &mut backoff).await;
                            continue;
                        }
                    }
                }
            }
        };

        match enter_mesh(
            conn,
            &ep,
            name,
            &identity,
            &alpn,
            token.clone(),
            stats.clone(),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                if token.is_cancelled() {
                    return Ok(());
                }
                tracing::warn!(error = %e, "connection lost, reconnecting...");
                backoff_sleep(&token, &mut backoff).await;
            }
        }
    }
}

async fn try_reconnect_to_known_peers(
    ep: &Endpoint,
    network_name: &str,
    alpn: &[u8],
    identity: &IrohIdentityProvider,
    token: &CancellationToken,
) -> Option<iroh::endpoint::Connection> {
    let app_config = config::load().ok()?;
    let net = app_config
        .networks
        .iter()
        .find(|n| n.name == network_name)?;

    // Best-effort: try DHT resolution first for a potentially fresher member list
    if let Some(dht_id_str) = &net.membership_dht_id
        && let Ok(dht_id) = dht_id_str.parse::<EndpointId>()
    {
        match dht::create_pkarr_client(ep) {
            Ok(client) => {
                match dht::resolve_membership(&client, dht_id).await {
                    Ok((dht_members, _)) => {
                        tracing::info!(count = dht_members.len(), "resolved membership from DHT");
                        for member in &dht_members {
                            if member.identity == identity.local_identity() {
                                continue;
                            }
                            if token.is_cancelled() {
                                return None;
                            }
                            match transport::connect_to_peer_with_alpn(ep, member.identity, alpn).await {
                                Ok(conn) => {
                                    tracing::info!(peer_ip = %member.ip, "connected to DHT-resolved peer for reconnection");
                                    return Some(conn);
                                }
                                Err(e) => {
                                    tracing::debug!(peer = %member.identity.fmt_short(), error = %e, "DHT-resolved peer unavailable");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "DHT membership resolution failed, falling back to local config");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to create pkarr client for reconnection");
            }
        }
    }

    // Fall back to local config members
    for member in &net.members {
        if member.identity == identity.local_identity() {
            continue; // skip self
        }
        if token.is_cancelled() {
            return None;
        }
        match transport::connect_to_peer_with_alpn(ep, member.identity, alpn).await {
            Ok(conn) => {
                tracing::info!(peer_ip = %member.ip, "connected to known peer for reconnection");
                return Some(conn);
            }
            Err(e) => {
                tracing::debug!(peer = %member.identity.fmt_short(), error = %e, "known peer unavailable");
            }
        }
    }
    None
}

/// Shared join logic: handshake + peer connections + listeners.
/// Does NOT create a TUN device or run the forwarding loop.
/// Returns Ok(()) once setup is complete; background tasks run until `token` is cancelled.
#[allow(clippy::too_many_arguments)]
async fn join_mesh_shared(
    initial_conn: iroh::endpoint::Connection,
    ep: &Endpoint,
    network_name: &str,
    identity: &IrohIdentityProvider,
    alpn: &[u8],
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let my_identity = identity.local_identity();
    let my_ip = identity.local_ip();

    // Receive initial control message (Welcome, JoinApproved, MemberSync, or JoinDenied)
    let (_send, mut recv) = initial_conn
        .accept_bi()
        .await
        .context("accept control stream")?;

    let msg = control::recv_msg(&mut recv).await?;
    let (members, approved, received_dht_id) = match msg {
        ControlMsg::Welcome { members, approved, membership_dht_id } => {
            tracing::info!(network = %network_name, "welcomed to network");
            // Joiner-side collision check
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
            (members, approved, membership_dht_id)
        }
        ControlMsg::JoinApproved { your_ip, members } => {
            // Backward compat: old coordinators still send JoinApproved
            tracing::info!(ip = %your_ip, network = %network_name, "joined network (legacy)");
            if your_ip != my_ip {
                tracing::warn!(
                    expected = %my_ip,
                    got = %your_ip,
                    "coordinator assigned different IP than identity-derived"
                );
            }
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

    // Save membership to config, including membership_dht_id if received
    let member_entries: Vec<config::MemberEntry> = members
        .iter()
        .map(|m| config::MemberEntry {
            identity: m.identity.clone(),
            ip: m.ip,
            is_coordinator: m.is_coordinator,
        })
        .collect();
    let approved_config: Vec<config::ApprovedConfigEntry> = approved
        .iter()
        .map(|a| config::ApprovedConfigEntry {
            identity: a.identity.clone(),
            ip: a.ip,
        })
        .collect();
    let mut app_config = config::load()?;
    // Preserve an existing dht_id if we didn't get a new one
    let dht_id_to_save = received_dht_id.clone().or_else(|| {
        app_config.networks.iter()
            .find(|n| n.name == network_name)
            .and_then(|n| n.membership_dht_id.clone())
    });
    config::upsert_network(
        &mut app_config,
        config::NetworkConfig {
            name: network_name.to_string(),
            coordinator_id: initial_conn.remote_id(),
            group_mode: GroupMode::Restricted,
            my_ip: Some(my_ip),
            members: member_entries,
            approved: approved_config,
            membership_dht_id: dht_id_to_save,
        },
    );
    config::save(&app_config)?;

    // Add the initial connection peer to routing table
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);
    peers.add(remote_ip, initial_conn.clone(), remote_id);
    forward::spawn_peer_reader(
        initial_conn.clone(),
        tun_tx.clone(),
        token.clone(),
        stats.clone(),
    );

    // Connect to all other known members
    for member in &members {
        if member.identity == my_identity {
            continue;
        }
        if member.identity == initial_conn.remote_id() {
            continue; // already connected
        }
        match transport::connect_to_peer_with_alpn(ep, member.identity, alpn).await {
            Ok(conn) => {
                let (mut send, _recv) = conn.open_bi().await?;
                control::send_msg(
                    &mut send,
                    &ControlMsg::MeshHello {
                        identity: my_identity.clone(),
                        ip: my_ip,
                    },
                )
                .await?;

                peers.add(member.ip, conn.clone(), member.identity.clone());
                forward::spawn_peer_reader(conn, tun_tx.clone(), token.clone(), stats.clone());
                tracing::info!(peer_ip = %member.ip, "connected to mesh peer");
            }
            Err(e) => {
                tracing::warn!(peer_ip = %member.ip, error = %e, "mesh peer unavailable");
            }
        }
    }

    // Shared live state for mesh_acceptor and control_listener
    let live_state = Arc::new(std::sync::RwLock::new(NetworkState {
        members: MemberList::from_members(members.clone()),
        approved: ApprovedList::from_entries(approved),
    }));

    // Listen for control messages from initial connection
    let _control_listener = tokio::spawn({
        let initial_conn = initial_conn.clone();
        let token = token.clone();
        let live_state = live_state.clone();
        let network_name_owned = network_name.to_string();
        async move {
            let network_name = network_name_owned;
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = initial_conn.accept_bi() => {
                        match result {
                            Ok((_send, mut recv)) => {
                                match control::recv_msg(&mut recv).await {
                                    Ok(ControlMsg::MemberApproved { identity, ip }) => {
                                        tracing::info!(peer = %identity, ip = %ip, "peer approved by coordinator");
                                        let entry = ApprovedEntry { identity, ip };
                                        let mut s = live_state.write().unwrap();
                                        let members = s.members.clone();
                                        let _ = s.approved.approve(entry, &members);
                                    }
                                    Ok(ControlMsg::MemberSync { members, membership_dht_id }) => {
                                        tracing::info!(count = members.len(), "member list updated");
                                        live_state.write().unwrap().members = MemberList::from_members(members);
                                        // Persist updated DHT ID if newly received
                                        if membership_dht_id.is_some()
                                            && let Ok(mut cfg) = config::load()
                                            && let Some(net) = cfg.networks.iter_mut().find(|n| n.name == network_name)
                                        {
                                            net.membership_dht_id = membership_dht_id;
                                            let _ = config::save(&cfg);
                                        }
                                    }
                                    Ok(other) => {
                                        tracing::debug!(?other, "unhandled control message");
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "control message error");
                                    }
                                }
                            }
                            Err(_) => return,
                        }
                    }
                }
            }
        }
    });

    // Accept incoming mesh connections (MeshHello + ReconnectRequest)
    let _mesh_acceptor = tokio::spawn({
        let ep = ep.clone();
        let peers = peers.clone();
        let token = token.clone();
        let stats = stats.clone();
        let tun_tx = tun_tx.clone();
        let expected_alpn = alpn.to_vec();
        let live_state = live_state.clone();
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = transport::accept_connection_with_alpn(&ep) => {
                        match result {
                            Ok((conn, conn_alpn)) => {
                                if conn_alpn != expected_alpn {
                                    continue;
                                }
                                match conn.accept_bi().await {
                                    Ok((_send, mut recv)) => {
                                        let transport_id = conn.remote_id();
                                        match control::recv_msg(&mut recv).await {
                                            Ok(ControlMsg::MeshHello { identity: peer_identity, ip }) => {
                                                if peer_identity != transport_id {
                                                    tracing::warn!(claimed = %peer_identity.fmt_short(), actual = %transport_id.fmt_short(), "identity mismatch in MeshHello");
                                                    continue;
                                                }

                                                let (is_member, is_approved) = {
                                                    let s = live_state.read().unwrap();
                                                    (s.members.is_member(&peer_identity), s.approved.is_approved(&peer_identity))
                                                };

                                                if is_approved {
                                                    // Welcome the approved peer
                                                    tracing::info!(peer_ip = %ip, "welcoming approved peer");
                                                    {
                                                        let mut s = live_state.write().unwrap();
                                                        s.approved.remove(&peer_identity);
                                                        let _ = s.members.add(Member {
                                                            identity: peer_identity.clone(),
                                                            ip,
                                                            is_coordinator: false,
                                                        });
                                                    }
                                                    let (members, approved_list) = {
                                                        let s = live_state.read().unwrap();
                                                        let m: Vec<Member> = s.members.all().into_iter().cloned().collect();
                                                        let a: Vec<ApprovedEntry> = s.approved.all().into_iter().cloned().collect();
                                                        (m, a)
                                                    };
                                                    if let Ok((mut send, _)) = conn.open_bi().await {
                                                        let _ = control::send_msg(
                                                            &mut send,
                                                            &ControlMsg::Welcome {
                                                                members: members.clone(),
                                                                approved: approved_list,
                                                                membership_dht_id: None,
                                                            },
                                                        ).await;
                                                    }
                                                    peers.add(ip, conn.clone(), peer_identity);
                                                    forward::spawn_peer_reader(conn, tun_tx.clone(), token.clone(), stats.clone());
                                                    // Broadcast updated member list
                                                    broadcast_member_sync(&peers, &members, Some(ip), None).await;
                                                } else if is_member {
                                                    tracing::info!(peer_ip = %ip, "known peer reconnecting via mesh");
                                                    peers.add(ip, conn.clone(), peer_identity);
                                                    forward::spawn_peer_reader(conn, tun_tx.clone(), token.clone(), stats.clone());
                                                } else {
                                                    tracing::warn!(peer = %peer_identity.fmt_short(), "unknown peer, not approved — rejecting");
                                                }
                                            }
                                            Ok(ControlMsg::ReconnectRequest { identity: peer_identity, ip }) => {
                                                if peer_identity != transport_id {
                                                    tracing::warn!(claimed = %peer_identity.fmt_short(), actual = %transport_id.fmt_short(), "identity mismatch in ReconnectRequest");
                                                    continue;
                                                }
                                                let is_known = live_state.read().unwrap().members.is_member(&peer_identity);
                                                if is_known {
                                                    tracing::info!(peer_ip = %ip, "known peer reconnecting");
                                                    peers.add(ip, conn.clone(), peer_identity);

                                                    let current_members: Vec<Member> = live_state
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
                                                            &ControlMsg::MemberSync { members: current_members, membership_dht_id: None },
                                                        ).await;
                                                    }

                                                    forward::spawn_peer_reader(conn, tun_tx.clone(), token.clone(), stats.clone());
                                                } else {
                                                    tracing::warn!(peer = %peer_identity, "unknown peer reconnect attempt");
                                                }
                                            }
                                            Ok(other) => {
                                                tracing::debug!(?other, "unexpected mesh message");
                                            }
                                            Err(e) => {
                                                tracing::warn!(error = %e, "mesh handshake failed");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "mesh accept failed");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to accept mesh connection");
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

async fn enter_mesh(
    initial_conn: iroh::endpoint::Connection,
    ep: &Endpoint,
    network_name: &str,
    identity: &IrohIdentityProvider,
    alpn: &[u8],
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let my_ip = identity.local_ip();

    let tun_dev = tun::TunDevice::create(my_ip).context("failed to create TUN device")?;
    let peers = PeerTable::new();
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);
    forward::spawn_tun_writer(tun_dev.share(), tun_rx);

    join_mesh_shared(
        initial_conn,
        ep,
        network_name,
        identity,
        alpn,
        peers.clone(),
        tun_tx.clone(),
        token.clone(),
        stats.clone(),
    )
    .await?;

    forward::run_mesh(tun_dev, peers, tun_tx, token, stats).await
}

fn save_network_config(
    app_config: &mut config::AppConfig,
    name: &str,
    ep: &Endpoint,
    mode: GroupMode,
    my_ip: Option<Ipv4Addr>,
    state: &NetworkState,
    dht_id: Option<String>,
) -> Result<()> {
    let member_entries: Vec<config::MemberEntry> = state
        .members
        .all()
        .into_iter()
        .map(|m| config::MemberEntry {
            identity: m.identity.clone(),
            ip: m.ip,
            is_coordinator: m.is_coordinator,
        })
        .collect();

    let approved_entries: Vec<config::ApprovedConfigEntry> = state
        .approved
        .all()
        .into_iter()
        .map(|a| config::ApprovedConfigEntry {
            identity: a.identity.clone(),
            ip: a.ip,
        })
        .collect();

    config::upsert_network(
        app_config,
        config::NetworkConfig {
            name: name.to_string(),
            coordinator_id: ep.id(),
            group_mode: mode,
            my_ip,
            members: member_entries,
            approved: approved_entries,
            membership_dht_id: dht_id,
        },
    );
    config::save(app_config)
}

fn cmd_list() -> Result<()> {
    let app_config = config::load()?;
    if app_config.networks.is_empty() {
        println!("No saved networks.");
        return Ok(());
    }
    for net in &app_config.networks {
        let ip_str = net
            .my_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "coordinator".to_string());
        println!(
            "{} (coordinator: {}, ip: {}, members: {}, mode: {:?})",
            net.name,
            net.coordinator_id,
            ip_str,
            net.members.len(),
            net.group_mode,
        );
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    let app_config = config::load()?;
    if app_config.networks.is_empty() {
        println!("No networks configured.");
        return Ok(());
    }
    println!("Networks:");
    for net in &app_config.networks {
        let role = if net.my_ip.is_none() {
            "coordinator"
        } else {
            "member"
        };
        let ip_str = net
            .my_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "pending".to_string());
        println!("  {} [{}] ({})", net.name, role, net.group_mode);
        println!("    IP: {}", ip_str);
        println!("    Coordinator: {}", net.coordinator_id);
        if !net.members.is_empty() {
            println!("    Members:");
            for member in &net.members {
                let role_tag = if member.is_coordinator {
                    " [coord]"
                } else {
                    ""
                };
                println!("      {} ({}){}", member.ip, member.identity, role_tag);
            }
        }
    }
    Ok(())
}

fn cmd_leave(name: &str) -> Result<()> {
    let mut app_config = config::load()?;
    if config::remove_network(&mut app_config, name) {
        config::save(&app_config)?;
        println!("Left network '{}'.", name);
    } else {
        println!("Network '{}' not found.", name);
    }
    Ok(())
}

async fn cmd_up(token: CancellationToken, stats: Arc<Stats>) -> Result<()> {
    let app_config = config::load()?;
    if app_config.networks.is_empty() {
        println!("No saved networks. Use 'pitopi create' or 'pitopi join' first.");
        return Ok(());
    }

    let key = identity::load_or_create()?;
    let public_key = key.public();
    // Clone key before it is consumed by the endpoint builder; needed for DHT derivation
    let key_for_dht = key.clone();

    let alpns: Vec<Vec<u8>> = app_config
        .networks
        .iter()
        .map(|net| transport::network_alpn(&net.name))
        .collect();

    let ep = transport::create_endpoint_with_alpns(key, alpns).await?;

    // Single TUN for all networks
    let identity = IrohIdentityProvider::new(public_key);
    let my_ip = identity.local_ip();
    let tun_dev = tun::TunDevice::create(my_ip).context("failed to create TUN device")?;
    let peers = PeerTable::new();
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);
    forward::spawn_tun_writer(tun_dev.share(), tun_rx);
    tokio::spawn(forward::run_mesh(
        tun_dev,
        peers.clone(),
        tun_tx.clone(),
        token.clone(),
        stats.clone(),
    ));

    let mut handles = Vec::new();
    for net in &app_config.networks {
        let alpn = transport::network_alpn(&net.name);

        if net.my_ip.is_some() {
            // We're a member — join using the shared TUN/peers
            let coordinator_id: EndpointId = net.coordinator_id;
            let name = net.name.clone();
            let membership_dht_id = net.membership_dht_id.clone();
            let ep = ep.clone();
            let identity = identity.clone();
            let peers = peers.clone();
            let tun_tx = tun_tx.clone();
            let token = token.clone();
            let stats = stats.clone();
            handles.push(tokio::spawn(async move {
                tracing::info!(network = %name, "connecting...");

                // Best-effort: try DHT resolution to get a fresh member list before connecting
                if let Some(dht_id_str) = &membership_dht_id
                    && let Ok(dht_id) = dht_id_str.parse::<EndpointId>()
                {
                    match dht::create_pkarr_client(&ep) {
                        Ok(client) => {
                            match dht::resolve_membership(&client, dht_id).await {
                                Ok((dht_members, _)) => {
                                    tracing::info!(
                                        network = %name,
                                        count = dht_members.len(),
                                        "refreshed membership from DHT"
                                    );
                                    // Try connecting to DHT-resolved members directly
                                    for member in &dht_members {
                                        if member.identity == identity.local_identity() {
                                            continue;
                                        }
                                        if token.is_cancelled() {
                                            return;
                                        }
                                        match transport::connect_to_peer_with_alpn(&ep, member.identity, &alpn).await {
                                            Ok(conn) => {
                                                tracing::info!(network = %name, peer_ip = %member.ip, "connected via DHT-resolved peer");
                                                if let Err(e) = join_mesh_shared(
                                                    conn, &ep, &name, &identity, &alpn, peers, tun_tx, token, stats,
                                                ).await {
                                                    tracing::warn!(network = %name, error = %e, "join_mesh_shared failed (DHT path)");
                                                }
                                                return;
                                            }
                                            Err(e) => {
                                                tracing::debug!(peer_ip = %member.ip, error = %e, "DHT-resolved peer unavailable");
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(network = %name, error = %e, "DHT resolution failed, falling back to coordinator");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(network = %name, error = %e, "failed to create pkarr client for cmd_up");
                        }
                    }
                }

                match transport::connect_to_peer_with_alpn(&ep, coordinator_id, &alpn).await {
                    Ok(conn) => {
                        tracing::info!(network = %name, "connected");
                        if let Err(e) = join_mesh_shared(
                            conn, &ep, &name, &identity, &alpn, peers, tun_tx, token, stats,
                        )
                        .await
                        {
                            tracing::warn!(network = %name, error = %e, "join_mesh_shared failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(network = %name, error = %e, "failed to connect");
                    }
                }
            }));
        } else {
            // We're the coordinator
            let name = net.name.clone();
            let mode = net.group_mode;
            let ep = ep.clone();
            let token = token.clone();
            let stats = stats.clone();
            let peers = peers.clone();
            let tun_tx = tun_tx.clone();
            let identity = IrohIdentityProvider::new(ep.id());
            // Derive membership key and DHT ID for this network
            let membership_key = dht::derive_membership_key(&key_for_dht, &name);
            let dht_id = dht::membership_dht_id(&key_for_dht, &name).to_string();
            handles.push(tokio::spawn(async move {
                tracing::info!(network = %name, "starting coordinator...");
                let policy = policy_for_mode(mode);
                let mut member_list = MemberList::new();
                member_list
                    .add(Member {
                        identity: identity.local_identity(),
                        ip: identity.local_ip(),
                        is_coordinator: true,
                    })
                    .unwrap();
                let state = Arc::new(std::sync::RwLock::new(NetworkState {
                    members: member_list,
                    approved: ApprovedList::new(),
                }));
                let alpn = transport::network_alpn(&name);

                let dht_notify = Arc::new(tokio::sync::Notify::new());
                match dht::create_pkarr_client(&ep) {
                    Ok(pkarr_client) => {
                        spawn_dht_publisher(
                            pkarr_client,
                            membership_key,
                            state.clone(),
                            dht_notify.clone(),
                            token.clone(),
                        );
                    }
                    Err(e) => {
                        tracing::warn!(network = %name, error = %e, "failed to create pkarr client, DHT publishing disabled");
                    }
                }

                if let Err(e) = run_accept_loop(
                    &ep, &alpn, &identity, &*policy, state, peers, tun_tx, token, stats,
                    Some(dht_notify), Some(dht_id),
                )
                .await
                {
                    tracing::warn!(network = %name, error = %e, "coordinator stopped");
                }
            }));
        }
    }

    tokio::select! {
        _ = token.cancelled() => {}
        _ = futures::future::join_all(handles) => {}
    }

    Ok(())
}

fn cmd_down() -> Result<()> {
    println!("Stopping all networks. Send SIGTERM to the running pitopi process.");
    Ok(())
}

fn cmd_install_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let service = include_str!("../contrib/pitopi.service");
        let path = std::path::Path::new("/etc/systemd/system/pitopi.service");
        std::fs::write(path, service)?;
        println!("Installed systemd service to {}", path.display());
        println!("Run: sudo systemctl enable --now pitopi");
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let plist = include_str!("../contrib/com.pitopi.vpn.plist");
        let path = std::path::Path::new("/Library/LaunchDaemons/com.pitopi.vpn.plist");
        std::fs::write(path, plist)?;
        println!("Installed launchd daemon to {}", path.display());
        println!("Run: sudo launchctl load {}", path.display());
        return Ok(());
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("service installation not supported on this platform");
    }
}

fn cmd_uninstall_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = std::path::Path::new("/etc/systemd/system/pitopi.service");
        if path.exists() {
            std::fs::remove_file(path)?;
            println!("Removed systemd service.");
            println!("Run: sudo systemctl daemon-reload");
        } else {
            println!("Service not installed.");
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let path = std::path::Path::new("/Library/LaunchDaemons/com.pitopi.vpn.plist");
        if path.exists() {
            println!("Run: sudo launchctl unload {}", path.display());
            std::fs::remove_file(path)?;
            println!("Removed launchd daemon.");
        } else {
            println!("Service not installed.");
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("service uninstallation not supported on this platform");
    }
}

async fn backoff_sleep(token: &CancellationToken, backoff: &mut Duration) {
    tracing::info!(secs = backoff.as_secs(), "retrying in");
    tokio::select! {
        _ = token.cancelled() => {}
        _ = tokio::time::sleep(*backoff) => {}
    }
    *backoff = (*backoff * 2).min(BACKOFF_MAX);
}
