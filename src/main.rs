mod acl;
mod audit;
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
use iroh::endpoint::Endpoint;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use control::ControlMsg;
use membership::{
    GroupMode, IdentityProvider, IrohIdentityProvider, Member, MemberList, MembershipPolicy,
    policy_for_mode,
};
use peers::PeerTable;
use stats::Stats;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

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
        /// Network name (defaults to "default")
        #[arg(long, default_value = "default")]
        name: String,
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
        .with_max_level(tracing::Level::INFO)
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
            let node_id =
                room_code::parse_node_id(&node_id).context("invalid node ID or room code")?;
            let token = shutdown::token();
            let stats = stats::Stats::new();
            stats.spawn_logger(token.clone());
            cmd_join(node_id, &name, token, stats).await
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

async fn cmd_create(
    name: &str,
    mode: GroupMode,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let key = identity::load_or_create()?;
    let public_key = key.public();
    let alpn = transport::network_alpn(name);
    let ep = transport::create_endpoint_with_alpns(key, vec![alpn.clone()]).await?;

    let identity = IrohIdentityProvider::new(public_key);
    let my_ip = identity.local_ip();
    let room_code = room_code::encode(&ep.id());
    let policy = policy_for_mode(mode);

    tracing::info!(name = %name, mode = ?mode, "network created");
    tracing::info!(ip = %my_ip, "your virtual IP");
    tracing::info!(room_code = %room_code, "share this room code");

    let mut member_list = MemberList::new();
    member_list
        .add(Member {
            identity: identity.local_identity(),
            ip: my_ip,
            is_coordinator: true,
        })
        .expect("self-add cannot collide");

    let mut app_config = config::load()?;
    save_network_config(&mut app_config, name, &ep, mode, Some(my_ip), &member_list)?;

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

    let member_list = Arc::new(std::sync::RwLock::new(member_list));

    run_accept_loop(
        &ep, &alpn, &identity, &*policy, member_list, peers, tun_tx, token, stats,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_accept_loop(
    ep: &Endpoint,
    alpn: &[u8],
    identity: &IrohIdentityProvider,
    policy: &dyn MembershipPolicy,
    member_list: Arc<std::sync::RwLock<MemberList>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let self_member = {
        let list = member_list.read().unwrap();
        list.get(&identity.local_identity()).cloned().unwrap()
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

        let remote_id = conn.remote_id().to_string();
        let peer_ip = identity.derive_ip(&remote_id);

        // Check if this is a known member reconnecting
        let is_known = member_list.read().unwrap().is_member(&remote_id);

        if is_known {
            tracing::info!(ip = %peer_ip, "known member reconnecting");
            let members = member_list
                .read()
                .unwrap()
                .all()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
            peers.add(peer_ip, conn.clone(), remote_id);

            let token_clone = token.clone();
            let stats_clone = stats.clone();
            let tun_tx_clone = tun_tx.clone();
            tokio::spawn(async move {
                send_member_sync(&conn, &members).await;
                forward::spawn_peer_reader(conn, tun_tx_clone, token_clone, stats_clone);
            });
            continue;
        }

        // New join — check policy
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

        // Check IP collision
        let has_collision = {
            let list = member_list.read().unwrap();
            if let Some(existing) = list.get_by_ip(peer_ip) {
                existing.identity != remote_id
            } else {
                false
            }
        };
        if has_collision {
            tracing::warn!(ip = %peer_ip, "IP collision, rejecting");
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(
                    &mut send,
                    &ControlMsg::JoinDenied {
                        reason: "IP collision".to_string(),
                    },
                )
                .await;
            }
            continue;
        }

        // Accept the new member
        let new_member = Member {
            identity: remote_id.clone(),
            ip: peer_ip,
            is_coordinator: false,
        };
        member_list
            .write()
            .unwrap()
            .add(new_member)
            .expect("checked above");

        let members: Vec<Member> = member_list
            .read()
            .unwrap()
            .all()
            .into_iter()
            .cloned()
            .collect();
        peers.add(peer_ip, conn.clone(), remote_id);
        tracing::info!(ip = %peer_ip, "new member joined");

        // Send JoinApproved to new peer
        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(
                &mut send,
                &ControlMsg::JoinApproved {
                    your_ip: peer_ip,
                    members: members.clone(),
                },
            )
            .await;
        }

        // Broadcast MemberSync to existing peers
        broadcast_member_sync(&peers, &members, Some(peer_ip)).await;

        let tun_tx_clone = tun_tx.clone();
        let token_clone = token.clone();
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            forward::spawn_peer_reader(conn, tun_tx_clone, token_clone, stats_clone);
        });
    }
}

async fn send_member_sync(conn: &iroh::endpoint::Connection, members: &[Member]) {
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

        match enter_mesh(conn, &ep, name, &identity, &alpn, token.clone(), stats.clone()).await {
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

    for member in &net.members {
        if member.identity == identity.local_identity() {
            continue; // skip self
        }
        let peer_id: EndpointId = match member.identity.parse() {
            Ok(id) => id,
            Err(_) => continue,
        };
        if token.is_cancelled() {
            return None;
        }
        match transport::connect_to_peer_with_alpn(ep, peer_id, alpn).await {
            Ok(conn) => {
                tracing::info!(peer_ip = %member.ip, "connected to known peer for reconnection");
                return Some(conn);
            }
            Err(e) => {
                tracing::debug!(peer = %member.identity, error = %e, "known peer unavailable");
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

    // Receive initial control message (JoinApproved, MemberSync, or JoinDenied)
    let (_send, mut recv) = initial_conn
        .accept_bi()
        .await
        .context("accept control stream")?;

    let msg = control::recv_msg(&mut recv).await?;
    let members = match msg {
        ControlMsg::JoinApproved { your_ip, members } => {
            tracing::info!(ip = %your_ip, network = %network_name, "joined network");
            if your_ip != my_ip {
                tracing::warn!(
                    expected = %my_ip,
                    got = %your_ip,
                    "coordinator assigned different IP than identity-derived"
                );
            }
            members
        }
        ControlMsg::MemberSync { members } => {
            tracing::info!(network = %network_name, "reconnected via peer");
            members
        }
        ControlMsg::JoinDenied { reason } => {
            anyhow::bail!("join denied: {reason}");
        }
        other => {
            anyhow::bail!("expected JoinApproved or MemberSync, got {other:?}");
        }
    };

    // Save membership to config
    let member_entries: Vec<config::MemberEntry> = members
        .iter()
        .map(|m| config::MemberEntry {
            identity: m.identity.clone(),
            ip: m.ip,
            is_coordinator: m.is_coordinator,
        })
        .collect();
    let mut app_config = config::load()?;
    config::upsert_network(
        &mut app_config,
        config::NetworkConfig {
            name: network_name.to_string(),
            coordinator_id: initial_conn.remote_id().to_string(),
            group_mode: GroupMode::Restricted,
            my_ip: Some(my_ip),
            members: member_entries,
            approved: vec![],
        },
    );
    config::save(&app_config)?;

    // Add the initial connection peer to routing table
    let remote_id = initial_conn.remote_id().to_string();
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
        if member.identity == initial_conn.remote_id().to_string() {
            continue; // already connected
        }
        let peer_id: EndpointId = match member.identity.parse() {
            Ok(id) => id,
            Err(_) => continue,
        };
        match transport::connect_to_peer_with_alpn(ep, peer_id, alpn).await {
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

    // Shared live member list for mesh_acceptor (updated on ReconnectRequest)
    let live_members = Arc::new(std::sync::RwLock::new(members.clone()));

    // Listen for control messages from initial connection
    let _control_listener = tokio::spawn({
        let initial_conn = initial_conn.clone();
        let token = token.clone();
        let live_members = live_members.clone();
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = initial_conn.accept_bi() => {
                        match result {
                            Ok((_send, mut recv)) => {
                                match control::recv_msg(&mut recv).await {
                                    Ok(ControlMsg::MemberSync { members }) => {
                                        tracing::info!(count = members.len(), "member list updated");
                                        *live_members.write().unwrap() = members;
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
        let live_members = live_members.clone();
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
                                        let transport_id = conn.remote_id().to_string();
                                        match control::recv_msg(&mut recv).await {
                                            Ok(ControlMsg::MeshHello { identity: peer_identity, ip }) => {
                                                if peer_identity != transport_id {
                                                    tracing::warn!(claimed = %peer_identity, actual = %transport_id, "identity mismatch in MeshHello");
                                                    continue;
                                                }
                                                tracing::info!(peer_ip = %ip, "mesh peer connected");
                                                peers.add(ip, conn.clone(), peer_identity);
                                                forward::spawn_peer_reader(conn, tun_tx.clone(), token.clone(), stats.clone());
                                            }
                                            Ok(ControlMsg::ReconnectRequest { identity: peer_identity, ip }) => {
                                                if peer_identity != transport_id {
                                                    tracing::warn!(claimed = %peer_identity, actual = %transport_id, "identity mismatch in ReconnectRequest");
                                                    continue;
                                                }
                                                let is_known = live_members.read().unwrap().iter().any(|m| m.identity == peer_identity);
                                                if is_known {
                                                    tracing::info!(peer_ip = %ip, "known peer reconnecting");
                                                    peers.add(ip, conn.clone(), peer_identity);

                                                    let current_members = live_members.read().unwrap().clone();
                                                    if let Ok((mut send, _)) = conn.open_bi().await {
                                                        let _ = control::send_msg(
                                                            &mut send,
                                                            &ControlMsg::MemberSync { members: current_members },
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
    member_list: &MemberList,
) -> Result<()> {
    let member_entries: Vec<config::MemberEntry> = member_list
        .all()
        .into_iter()
        .map(|m| config::MemberEntry {
            identity: m.identity.clone(),
            ip: m.ip,
            is_coordinator: m.is_coordinator,
        })
        .collect();

    config::upsert_network(
        app_config,
        config::NetworkConfig {
            name: name.to_string(),
            coordinator_id: ep.id().to_string(),
            group_mode: mode,
            my_ip,
            members: member_entries,
            approved: vec![],
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
                let role_tag = if member.is_coordinator { " [coord]" } else { "" };
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
            let coordinator_id: EndpointId = net
                .coordinator_id
                .parse()
                .context("invalid coordinator id in config")?;
            let name = net.name.clone();
            let ep = ep.clone();
            let identity = identity.clone();
            let peers = peers.clone();
            let tun_tx = tun_tx.clone();
            let token = token.clone();
            let stats = stats.clone();
            handles.push(tokio::spawn(async move {
                tracing::info!(network = %name, "connecting...");
                match transport::connect_to_peer_with_alpn(&ep, coordinator_id, &alpn).await {
                    Ok(conn) => {
                        tracing::info!(network = %name, "connected");
                        if let Err(e) = join_mesh_shared(
                            conn,
                            &ep,
                            &name,
                            &identity,
                            &alpn,
                            peers,
                            tun_tx,
                            token,
                            stats,
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
                let member_list = Arc::new(std::sync::RwLock::new(member_list));
                let alpn = transport::network_alpn(&name);
                if let Err(e) = run_accept_loop(
                    &ep, &alpn, &identity, &*policy, member_list, peers, tun_tx, token, stats,
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
