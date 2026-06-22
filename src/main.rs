mod acl;
mod config;
mod control;
mod daemon;
mod dht;
mod dns;
mod dns_config;
mod firewall;
mod forward;
mod hostname;
mod identity;
mod ipc;
mod membership;
mod network_name;
mod peers;

mod shutdown;
mod stats;
mod transport;
mod tun;

pub const APP_NAME: &str = "pitopi";
pub const DNS_DOMAIN: &str = "pi";

use std::sync::Arc;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

use futures::StreamExt;
use iroh::endpoint::{Connection as IrohConnection, PathEvent};

use membership::GroupMode;

/// Logs iroh path events (opened, closed, selected) for a peer connection.
pub(crate) fn spawn_path_logger(conn: IrohConnection, label: String) {
    let paths = conn.paths();
    for path in paths.iter() {
        tracing::info!(
            peer = %label,
            addr = ?path.remote_addr(),
            rtt = ?path.rtt(),
            selected = path.is_selected(),
            "existing path"
        );
    }

    tokio::spawn(async move {
        let mut events = conn.path_events();
        while let Some(event) = events.next().await {
            match event {
                PathEvent::Opened { remote_addr, .. } => {
                    tracing::info!(peer = %label, addr = ?remote_addr, "path opened");
                }
                PathEvent::Closed { remote_addr, .. } => {
                    tracing::info!(peer = %label, addr = ?remote_addr, "path closed");
                }
                PathEvent::Selected { remote_addr, .. } => {
                    tracing::info!(peer = %label, addr = ?remote_addr, "path selected");
                }
                PathEvent::Lagged { missed, .. } => {
                    tracing::warn!(peer = %label, missed, "path events lagged");
                }
                _ => {}
            }
        }
    });
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
        /// Membership mode: open or restricted
        #[arg(long, default_value = "restricted")]
        mode: GroupMode,
        /// Network name used in DNS (e.g. "gaming" → alice.gaming.pi). Random if not set
        #[arg(long)]
        name: Option<String>,
        /// Your hostname within the network (e.g. "alice" → alice.gaming.pi). Random if not set
        #[arg(long)]
        hostname: Option<String>,
        /// Route traffic through Tor (requires running Tor daemon with ControlPort 9051)
        #[arg(long)]
        tor: bool,
    },
    /// Join an existing network using its public key
    Join {
        /// The network public key (join code)
        network_key: String,
        /// Optional local alias for the network
        #[arg(long)]
        name: Option<String>,
        /// Your hostname within the network (e.g. "bob" → bob.gaming.pi). Random if not set
        #[arg(long)]
        hostname: Option<String>,
        /// Route traffic through Tor (requires running Tor daemon with ControlPort 9051)
        #[arg(long)]
        tor: bool,
    },
    /// Leave a network (remove from saved config)
    Leave {
        /// Three-word network name
        name: String,
    },
    /// Destroy a network (coordinator only)
    Nuke {
        /// Three-word network name
        name: String,
        /// Force destroy even if other members exist
        #[arg(long)]
        force: bool,
    },
    /// Show status of all networks (active + saved)
    Status,
    /// Start the daemon (manages all networks, listens for IPC commands)
    Daemon,
    /// Connect to all saved networks (alias for daemon)
    Up,
    /// Disconnect from all networks (signals daemon to shut down)
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
    /// Manage ACL rules for a network
    Acl {
        /// Three-word network name
        network: String,
        #[command(subcommand)]
        action: AclAction,
    },
    /// Manage local device firewall rules
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },
    /// Change your hostname on a network
    Hostname {
        /// Network name
        network: String,
        /// New hostname (e.g. "alice" → alice.network.pi)
        name: String,
    },
    /// Enable or disable mDNS local peer discovery
    Mdns {
        /// "on" or "off"
        state: String,
    },
    /// Send a file to a peer
    Send {
        /// File path to send
        file: String,
        /// Peer hostname or short ID
        peer: String,
    },
    /// Manage incoming file transfers
    Files {
        #[command(subcommand)]
        action: Option<FilesAction>,
    },
    /// Pair this device with another device (share user identity)
    Pair {
        #[command(subcommand)]
        action: Option<PairAction>,
        /// Pairing ticket from the primary device (shorthand for `pitopi pair accept <ticket>`)
        ticket: Option<String>,
    },
}

#[derive(Subcommand)]
enum PairAction {
    /// Accept a pairing ticket from the primary device
    Accept {
        /// The pairing ticket
        ticket: String,
    },
    /// Export an encrypted backup of the signing key
    Backup,
    /// Restore a signing key from an encrypted backup
    Restore {
        /// The encrypted backup string
        backup: String,
    },
}

#[derive(Subcommand)]
enum AclAction {
    /// Assign a tag to peers
    Tag {
        /// Tag name
        tag: String,
        /// Peer ID short hex prefixes
        peer_ids: Vec<String>,
    },
    /// Remove a tag from a peer
    Untag {
        /// Tag name
        tag: String,
        /// Peer ID short hex prefix
        peer_id: String,
    },
    /// Add an allow rule
    Allow {
        /// Source (tag name, peer ID, or "all")
        src: String,
        /// Destination (tag name, peer ID, or "all")
        dst: String,
    },
    /// Remove a rule by index
    Remove {
        /// Rule index (from 'acl show')
        index: usize,
    },
    /// Show current ACL rules and tags
    Show,
    /// Apply ACL rules from the config file
    Apply,
}

#[derive(Subcommand)]
enum FirewallAction {
    /// Add a firewall rule
    Add {
        /// Direction: in or out
        direction: String,
        /// Action: allow or deny
        action: String,
        /// Protocol: tcp, udp, icmp, any
        #[arg(long, short = 'p', default_value = "any")]
        proto: String,
        /// Port or port range (e.g. 22, 80-443)
        #[arg(long, short = 'P')]
        port: Option<String>,
        /// Peer short ID (omit for any peer)
        #[arg(long)]
        peer: Option<String>,
    },
    /// Remove a rule by index
    Remove {
        /// Rule index (from 'firewall show')
        index: usize,
    },
    /// Show current firewall rules
    Show,
    /// Set default policy (allow or deny)
    Default {
        /// Default action: allow or deny
        action: String,
    },
}

#[derive(Subcommand)]
enum FilesAction {
    /// Accept a pending file transfer
    Accept {
        /// Transfer ID (from 'pitopi files')
        id: u64,
        /// Output directory (default: ~/Downloads)
        #[arg(long, short)]
        output: Option<String>,
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
        Command::Leave { name } => ipc_leave(&name).await,
        Command::Create {
            mode,
            name,
            hostname,
            tor,
        } => ipc_create(mode, name, hostname, tor).await,
        Command::Join {
            network_key,
            name,
            hostname,
            tor,
        } => ipc_join(&network_key, name.as_deref(), hostname, tor).await,
        Command::Nuke { name, force } => ipc_nuke(&name, force).await,
        Command::Status => ipc_status().await,
        Command::Daemon | Command::Up => {
            check_root();
            let token = shutdown::token();
            let stats = Arc::new(stats::ForwardMetrics::default());
            stats.spawn_logger(token.clone());
            daemon::run_daemon(token, stats).await
        }
        Command::Down => ipc_down().await,
        Command::InstallService => cmd_install_service(),
        Command::UninstallService => cmd_uninstall_service(),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "pitopi", &mut std::io::stdout());
            Ok(())
        }
        Command::Acl { network, action } => ipc_acl(&network, action).await,
        Command::Firewall { action } => ipc_firewall(action).await,
        Command::Hostname { network, name } => ipc_set_hostname(&network, &name).await,
        Command::Mdns { state } => cmd_mdns(&state),
        Command::Send { file, peer } => ipc_send_file(&file, &peer).await,
        Command::Files { action } => ipc_files(action).await,
        Command::Pair { action, ticket } => cmd_pair(action, ticket).await,
    }
}

// ---------------------------------------------------------------------------
// Client-side commands (daemon optional)
// ---------------------------------------------------------------------------

fn cmd_mdns(state: &str) -> Result<()> {
    let enabled = match state {
        "on" => true,
        "off" => false,
        _ => {
            eprintln!("Usage: pitopi mdns <on|off>");
            std::process::exit(1);
        }
    };
    let mut app_config = config::load()?;
    app_config.mdns_enabled = enabled;
    config::save(&app_config)?;
    println!(
        "mDNS discovery {}. Restart the daemon for changes to take effect.",
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// IPC client commands (require daemon running)
// ---------------------------------------------------------------------------

async fn ipc_create(
    mode: GroupMode,
    name: Option<String>,
    hostname: Option<String>,
    tor: bool,
) -> Result<()> {
    let transport = if tor {
        Some(config::TransportMode::Tor)
    } else {
        None
    };
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Create {
            mode,
            name,
            hostname,
            transport,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Created {
            name,
            network_key,
            my_ip,
            my_ipv6,
        } => {
            println!("Network created: {}", name);
            println!("  IPv4: {}", my_ip);
            if let Some(v6) = my_ipv6 {
                println!("  IPv6: {}", v6);
            }
            println!("  Join code: {}", network_key);
            println!("  Share this join code to invite others");
        }
        ipc::IpcMessage::Error { message } => {
            eprintln!("Error: {}", message);
        }
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_join(
    network_key: &str,
    name: Option<&str>,
    hostname: Option<String>,
    tor: bool,
) -> Result<()> {
    let transport = if tor {
        Some(config::TransportMode::Tor)
    } else {
        None
    };
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Join {
            network_key: network_key.to_string(),
            name: name.map(|s| s.to_string()),
            hostname,
            transport,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Joined {
            name,
            my_ip,
            my_ipv6,
        } => {
            println!("Joined network '{}'.", name);
            println!("  IPv4: {}", my_ip);
            if let Some(v6) = my_ipv6 {
                println!("  IPv6: {}", v6);
            }
        }
        ipc::IpcMessage::Error { message } => {
            eprintln!("Error: {}", message);
        }
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_nuke(name: &str, force: bool) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Nuke {
            name: name.to_string(),
            force,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_leave(name: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Leave {
            name: name.to_string(),
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_status() -> Result<()> {
    let Ok(mut stream) = ipc::connect().await else {
        // Daemon not running — show saved config
        let app_config = config::load()?;
        if app_config.networks.is_empty() {
            println!("Daemon not running. No saved networks.");
            return Ok(());
        }
        println!("Daemon not running. Saved networks:");
        for net in &app_config.networks {
            let ip_str = net
                .my_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!("  {} (ip: {}, members: {})", net.name, ip_str, net.members.len());
        }
        return Ok(());
    };

    ipc::send(&mut stream, ipc::IpcMessage::Status).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::StatusResponse {
            endpoint_id,
            mdns_enabled,
            networks,
            packets_rx,
            packets_tx,
            bytes_rx,
            bytes_tx,
        } => {
            println!("Endpoint: {}", endpoint_id);
            println!("  mDNS: {}", if mdns_enabled { "enabled" } else { "disabled" });
            if networks.is_empty() {
                println!("No active networks.");
            } else {
                for net in &networks {
                    let role = match &net.role {
                        ipc::NetworkRole::Coordinator => "coordinator",
                        ipc::NetworkRole::Member => "member",
                    };
                    let dns_name = net
                        .my_hostname
                        .as_ref()
                        .map(|h| format!("{}.{}.{}", h, net.name, DNS_DOMAIN));
                    print!("  {} [{}]", net.name, role);
                    if let Some(ref dns) = dns_name {
                        print!(" — {}", dns);
                    }
                    println!("  ({})", net.my_ip);
                    if let Some(ref key) = net.network_key {
                        println!(
                            "    Key: {}…{}",
                            &key[..8.min(key.len())],
                            &key[key.len().saturating_sub(4)..]
                        );
                    }
                    println!(
                        "    Members: {}/{} online",
                        net.peers.len() + 1,
                        net.member_count
                    );
                    if !net.peers.is_empty() {
                        println!("    Peers:");
                        for peer in &net.peers {
                            let name = if let Some(ref h) = peer.hostname {
                                format!("{}.{}.{}", h, net.name, DNS_DOMAIN)
                            } else {
                                peer.ip.to_string()
                            };
                            print!("      {} ({})", name, peer.endpoint_id.fmt_short());
                            if let Some(ref uid) = peer.user_identity {
                                print!(" user:{}", uid.fmt_short());
                            }
                            if let Some(ref ci) = peer.connection {
                                let conn_type = match ci.conn_type {
                                    ipc::ConnType::Direct => "direct",
                                    ipc::ConnType::Relay => "relay",
                                    ipc::ConnType::Tor => "tor",
                                    ipc::ConnType::Unknown => "?",
                                };
                                print!(" [{conn_type}");
                                if let Some(rtt) = ci.rtt_ms {
                                    print!(", {:.1}ms", rtt);
                                }
                                print!("]");
                                print!("  tx:{} rx:{}", ci.bytes_tx, ci.bytes_rx);
                                if ci.lost_packets > 0 {
                                    print!(" lost:{}", ci.lost_packets);
                                }
                            }
                            println!();
                        }
                    }
                }
            }

            // Show inactive networks from config that the daemon didn't restore
            let active_names: std::collections::HashSet<&str> =
                networks.iter().map(|n| n.name.as_str()).collect();
            if let Ok(app_config) = config::load() {
                let inactive: Vec<_> = app_config
                    .networks
                    .iter()
                    .filter(|n| !active_names.contains(n.name.as_str()))
                    .collect();
                for net in &inactive {
                    println!("  {} [inactive]", net.name);
                }
            }

            fn format_bytes(b: u64) -> String {
                if b >= 1_073_741_824 {
                    format!("{:.1} GB", b as f64 / 1_073_741_824.0)
                } else if b >= 1_048_576 {
                    format!("{:.1} MB", b as f64 / 1_048_576.0)
                } else if b >= 1024 {
                    format!("{:.1} KB", b as f64 / 1024.0)
                } else {
                    format!("{} B", b)
                }
            }
            println!(
                "  Traffic: rx:{} tx:{} ({})",
                packets_rx,
                packets_tx,
                format_bytes(bytes_rx + bytes_tx)
            );
        }
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_down() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream,ipc::IpcMessage::Shutdown).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_set_hostname(network: &str, hostname: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::SetHostname {
            network: network.to_string(),
            hostname: hostname.to_string(),
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_acl(network: &str, action: AclAction) -> Result<()> {
    let mut stream = ipc::connect().await?;
    let req = match action {
        AclAction::Tag { tag, peer_ids } => ipc::IpcMessage::AclTag {
            network: network.to_string(),
            tag,
            peer_ids,
        },
        AclAction::Untag { tag, peer_id } => ipc::IpcMessage::AclUntag {
            network: network.to_string(),
            tag,
            peer_id,
        },
        AclAction::Allow { src, dst } => ipc::IpcMessage::AclAllow {
            network: network.to_string(),
            src,
            dst,
        },
        AclAction::Remove { index } => ipc::IpcMessage::AclRemove {
            network: network.to_string(),
            index,
        },
        AclAction::Show => ipc::IpcMessage::AclShow {
            network: network.to_string(),
        },
        AclAction::Apply => ipc::IpcMessage::AclApply {
            network: network.to_string(),
        },
    };
    ipc::send(&mut stream,req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::AclState { display } => print!("{}", display),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_firewall(action: FirewallAction) -> Result<()> {
    let mut stream = ipc::connect().await?;
    let req = match action {
        FirewallAction::Add {
            direction,
            action,
            proto,
            port,
            peer,
        } => ipc::IpcMessage::FirewallAdd {
            direction,
            action,
            protocol: proto,
            port,
            peer,
        },
        FirewallAction::Remove { index } => ipc::IpcMessage::FirewallRemove { index },
        FirewallAction::Show => ipc::IpcMessage::FirewallShow,
        FirewallAction::Default { action } => ipc::IpcMessage::FirewallDefault { action },
    };
    ipc::send(&mut stream,req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::FirewallState { display } => print!("{}", display),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_send_file(file: &str, peer: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::SendFile {
            path: file.to_string(),
            peer: peer.to_string(),
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_files(action: Option<FilesAction>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    match action {
        None => {
            ipc::send(&mut stream,ipc::IpcMessage::ListFiles).await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::FileList { files } => {
                    if files.is_empty() {
                        println!("No pending file transfers.");
                    } else {
                        println!("Pending file transfers:");
                        for f in &files {
                            println!(
                                "  {}  {} ({})  {}  {}",
                                f.id, f.from, f.mime_type, f.filename, format_size(f.size),
                            );
                        }
                        println!();
                        println!("Accept with: pitopi files accept <id>");
                    }
                }
                ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
                other => eprintln!("Unexpected response: {:?}", other),
            }
        }
        Some(FilesAction::Accept { id, output }) => {
            let output = output.or_else(|| {
                dirs::download_dir()
                    .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
                    .map(|p| p.to_string_lossy().to_string())
            });
            ipc::send(
                &mut stream,
                ipc::IpcMessage::AcceptFile { id, output },
            )
            .await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::Ok { message } => println!("{}", message),
                ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
                other => eprintln!("Unexpected response: {:?}", other),
            }
        }
    }
    Ok(())
}

fn format_size(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}

// ---------------------------------------------------------------------------
// Device pairing
// ---------------------------------------------------------------------------

async fn cmd_pair(action: Option<PairAction>, ticket: Option<String>) -> Result<()> {
    match (action, ticket) {
        // `pitopi pair <ticket>` shorthand
        (None, Some(ticket)) | (Some(PairAction::Accept { ticket }), _) => {
            ipc_pair_accept(&ticket).await
        }
        // `pitopi pair` — start pairing on primary device
        (None, None) => ipc_pair_start().await,
        // `pitopi pair backup`
        (Some(PairAction::Backup), _) => cmd_pair_backup(),
        // `pitopi pair restore <backup>`
        (Some(PairAction::Restore { backup }), _) => cmd_pair_restore(&backup),
    }
}

async fn ipc_pair_start() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::StartPairing).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::PairingTicket { ticket } => {
            println!("Pairing ticket: {}", ticket);
            println!();
            qr2term::print_qr(&ticket).ok();
            println!();
            println!("On the other device, run:");
            println!("  pitopi pair {}", ticket);
            println!();
            println!("Waiting for device to connect...");
            // The daemon handles the pairing asynchronously via the accept loop.
            // We could poll for completion, but the daemon logs when it happens.
            // For now, just tell the user it's ready.
        }
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_pair_accept(ticket: &str) -> Result<()> {
    let ticket_bytes = bs58::decode(ticket)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid pairing ticket: {e}"))?;
    if ticket_bytes.len() != 64 {
        anyhow::bail!(
            "invalid pairing ticket: expected 64 bytes, got {}",
            ticket_bytes.len()
        );
    }
    let endpoint_id = iroh::EndpointId::from_bytes(&ticket_bytes[..32].try_into().unwrap())
        .map_err(|e| anyhow::anyhow!("invalid endpoint ID in ticket: {e}"))?;
    let secret = ticket_bytes[32..].to_vec();

    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::PairWithDevice {
            endpoint_id,
            secret,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::PairingComplete { user_identity } => {
            println!("Paired successfully!");
            println!("  User identity: {}", user_identity);
            println!("  Device certificate stored.");
            println!();
            println!("This device will present its certificate when joining networks.");
        }
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

fn cmd_pair_backup() -> Result<()> {
    use argon2::Argon2;
    use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead, KeyInit};

    let key = identity::load_or_create()?;
    let password = rpassword::prompt_password("Enter backup password: ")?;
    if password.is_empty() {
        anyhow::bail!("password cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("passwords do not match");
    }

    let salt: [u8; 16] = rand::random();
    let mut derived_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;

    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let nonce_bytes: [u8; 24] = rand::random();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, key.to_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    // Format: "enc1" (4) || salt (16) || nonce (24) || ciphertext (32 + 16 tag)
    let mut backup_bytes = Vec::with_capacity(4 + 16 + 24 + ciphertext.len());
    backup_bytes.extend_from_slice(b"enc1");
    backup_bytes.extend_from_slice(&salt);
    backup_bytes.extend_from_slice(&nonce_bytes);
    backup_bytes.extend_from_slice(&ciphertext);

    let backup = bs58::encode(&backup_bytes).into_string();
    println!("Backup code: {}", backup);
    println!();
    println!("Store this safely. To restore on a new device:");
    println!("  pitopi pair restore {}", backup);
    Ok(())
}

fn cmd_pair_restore(backup: &str) -> Result<()> {
    use argon2::Argon2;
    use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead, KeyInit};

    let backup_bytes = bs58::decode(backup)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid backup code: {e}"))?;
    if backup_bytes.len() < 4 + 16 + 24 + 32 {
        anyhow::bail!("invalid backup code: too short");
    }
    if &backup_bytes[..4] != b"enc1" {
        anyhow::bail!("invalid backup code: unknown format");
    }
    let salt = &backup_bytes[4..20];
    let nonce_bytes = &backup_bytes[20..44];
    let ciphertext = &backup_bytes[44..];

    let password = rpassword::prompt_password("Enter backup password: ")?;
    let mut derived_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;

    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed: wrong password or corrupted backup"))?;

    let key_bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid key data"))?;
    let key = iroh::SecretKey::from_bytes(&key_bytes);

    // Check if a key already exists
    let existing = identity::load_or_create()?;
    if existing.public() == key.public() {
        println!("This device already has this identity.");
        return Ok(());
    }

    // Write the restored key
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine config directory"))?
        .join("pitopi");
    std::fs::create_dir_all(&config_dir)?;
    std::fs::write(config_dir.join("secret_key"), key.to_bytes())?;

    println!("Restored user identity: {}", key.public());
    println!("Restart the daemon for changes to take effect.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Service install/uninstall
// ---------------------------------------------------------------------------

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
