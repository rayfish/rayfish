mod acl;
mod daemon;
mod dht;
mod dns;
mod dns_config;
mod config;
mod control;
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


use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

use futures::StreamExt;
use iroh::endpoint::{PathEvent, Connection as IrohConnection};

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
    },
    /// List networks (queries daemon if running, falls back to saved config)
    List,
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
    /// Show status of active networks
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
        Command::List => cmd_list().await,
        Command::Leave { name } => ipc_leave(&name).await,
        Command::Create { mode, name, hostname } => ipc_create(mode, name, hostname).await,
        Command::Join { network_key, name, hostname } => ipc_join(&network_key, name.as_deref(), hostname).await,
        Command::Nuke { name, force } => ipc_nuke(&name, force).await,
        Command::Status => ipc_status().await,
        Command::Daemon | Command::Up => {
            check_root();
            let token = shutdown::token();
            let stats = std::sync::Arc::new(stats::ForwardMetrics::default());
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
    }
}

// ---------------------------------------------------------------------------
// Client-side commands (daemon optional)
// ---------------------------------------------------------------------------

async fn cmd_list() -> Result<()> {
    if let Ok(mut stream) = ipc::connect().await {
        ipc::send_msg(&mut stream, &ipc::IpcRequest::Status).await?;
        let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
        match resp {
            ipc::IpcResponse::Status { networks, .. } => {
                if networks.is_empty() {
                    println!("No active networks.");
                } else {
                    for net in &networks {
                        let role = match &net.role {
                            ipc::NetworkRole::Coordinator => "coordinator",
                            ipc::NetworkRole::Member => "member",
                        };
                        if let Some(ref h) = net.my_hostname {
                            println!(
                                "{} (role: {}, dns: {}.{}.{}, peers: {})",
                                net.name, role, h, net.name, DNS_DOMAIN, net.peers.len(),
                            );
                        } else {
                            println!(
                                "{} (role: {}, ip: {}, peers: {})",
                                net.name, role, net.my_ip, net.peers.len(),
                            );
                        }
                    }
                }
            }
            ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
            other => eprintln!("Unexpected response: {:?}", other),
        }
        return Ok(());
    }

    let app_config = config::load()?;
    if app_config.networks.is_empty() {
        println!("No saved networks.");
        return Ok(());
    }
    for net in &app_config.networks {
        let ip_str = net
            .my_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "?".to_string());
        println!(
            "{} (ip: {}, members: {}, mode: {:?})",
            net.name, ip_str, net.members.len(), net.group_mode,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IPC client commands (require daemon running)
// ---------------------------------------------------------------------------

async fn ipc_create(mode: GroupMode, name: Option<String>, hostname: Option<String>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send_msg(&mut stream, &ipc::IpcRequest::Create { mode, name, hostname }).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Created { name, network_key, my_ip } => {
            println!("Network created: {}", name);
            println!("  IP: {}", my_ip);
            println!("  Join code: {}", network_key);
            println!("  Share this join code to invite others");
        }
        ipc::IpcResponse::Error { message } => {
            eprintln!("Error: {}", message);
        }
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_join(network_key: &str, name: Option<&str>, hostname: Option<String>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send_msg(&mut stream, &ipc::IpcRequest::Join {
        network_key: network_key.to_string(),
        name: name.map(|s| s.to_string()),
        hostname,
    }).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Joined { name, my_ip } => {
            println!("Joined network '{}'.", name);
            println!("  IP: {}", my_ip);
        }
        ipc::IpcResponse::Error { message } => {
            eprintln!("Error: {}", message);
        }
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_nuke(name: &str, force: bool) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send_msg(&mut stream, &ipc::IpcRequest::Nuke {
        name: name.to_string(),
        force,
    }).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Ok { message } => println!("{}", message),
        ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_leave(name: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send_msg(&mut stream, &ipc::IpcRequest::Leave {
        name: name.to_string(),
    }).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Ok { message } => println!("{}", message),
        ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_status() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send_msg(&mut stream, &ipc::IpcRequest::Status).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Status { endpoint_id, networks, packets_rx, packets_tx, bytes_rx, bytes_tx } => {
            println!("Endpoint: {}", endpoint_id);
            if networks.is_empty() {
                println!("No active networks.");
            } else {
                for net in &networks {
                    let role = match &net.role {
                        ipc::NetworkRole::Coordinator => "coordinator",
                        ipc::NetworkRole::Member => "member",
                    };
                    let dns_name = net.my_hostname.as_ref()
                        .map(|h| format!("{}.{}.{}", h, net.name, DNS_DOMAIN));
                    print!("  {} [{}]", net.name, role);
                    if let Some(ref dns) = dns_name {
                        print!(" — {}", dns);
                    }
                    println!("  ({})", net.my_ip);
                    if let Some(ref key) = net.network_key {
                        println!("    Key: {}…{}", &key[..8.min(key.len())], &key[key.len().saturating_sub(4)..]);
                    }
                    println!("    Members: {}/{} online", net.peers.len() + 1, net.member_count);
                    if !net.peers.is_empty() {
                        println!("    Peers:");
                        for peer in &net.peers {
                            let name = if let Some(ref h) = peer.hostname {
                                format!("{}.{}.{}", h, net.name, DNS_DOMAIN)
                            } else {
                                peer.ip.to_string()
                            };
                            print!("      {} ({})", name, peer.endpoint_id.fmt_short());
                            if let Some(ref ci) = peer.connection {
                                let conn_type = match ci.conn_type {
                                    ipc::ConnType::Direct => "direct",
                                    ipc::ConnType::Relay => "relay",
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
            println!("  Traffic: rx:{} tx:{} ({})",
                packets_rx, packets_tx, format_bytes(bytes_rx + bytes_tx));
        }
        ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_down() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send_msg(&mut stream, &ipc::IpcRequest::Shutdown).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Ok { message } => println!("{}", message),
        ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_set_hostname(network: &str, hostname: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send_msg(&mut stream, &ipc::IpcRequest::SetHostname {
        network: network.to_string(),
        hostname: hostname.to_string(),
    }).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Ok { message } => println!("{}", message),
        ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_acl(network: &str, action: AclAction) -> Result<()> {
    let mut stream = ipc::connect().await?;
    let req = match action {
        AclAction::Tag { tag, peer_ids } => ipc::IpcRequest::AclTag {
            network: network.to_string(), tag, peer_ids,
        },
        AclAction::Untag { tag, peer_id } => ipc::IpcRequest::AclUntag {
            network: network.to_string(), tag, peer_id,
        },
        AclAction::Allow { src, dst } => ipc::IpcRequest::AclAllow {
            network: network.to_string(), src, dst,
        },
        AclAction::Remove { index } => ipc::IpcRequest::AclRemove {
            network: network.to_string(), index,
        },
        AclAction::Show => ipc::IpcRequest::AclShow {
            network: network.to_string(),
        },
        AclAction::Apply => ipc::IpcRequest::AclApply {
            network: network.to_string(),
        },
    };
    ipc::send_msg(&mut stream, &req).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Ok { message } => println!("{}", message),
        ipc::IpcResponse::AclState { display } => print!("{}", display),
        ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_firewall(action: FirewallAction) -> Result<()> {
    let mut stream = ipc::connect().await?;
    let req = match action {
        FirewallAction::Add { direction, action, proto, port, peer } => ipc::IpcRequest::FirewallAdd {
            direction, action, protocol: proto, port, peer,
        },
        FirewallAction::Remove { index } => ipc::IpcRequest::FirewallRemove { index },
        FirewallAction::Show => ipc::IpcRequest::FirewallShow,
        FirewallAction::Default { action } => ipc::IpcRequest::FirewallDefault { action },
    };
    ipc::send_msg(&mut stream, &req).await?;
    let resp: ipc::IpcResponse = ipc::recv_msg(&mut stream).await?;
    match resp {
        ipc::IpcResponse::Ok { message } => println!("{}", message),
        ipc::IpcResponse::FirewallState { display } => print!("{}", display),
        ipc::IpcResponse::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
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
