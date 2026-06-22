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
mod style;
mod transport;
mod tun;

pub const APP_NAME: &str = "ray";
pub const DNS_DOMAIN: &str = "ray";

use std::sync::Arc;

use anyhow::{Context, Result};
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
#[command(name = "ray", about = "P2P mesh VPN powered by iroh")]
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
        /// Network name used in DNS (e.g. "gaming" → alice.gaming.ray). Random if not set
        #[arg(long)]
        name: Option<String>,
        /// Your hostname within the network (e.g. "alice" → alice.gaming.ray). Random if not set
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
        /// Your hostname within the network (e.g. "bob" → bob.gaming.ray). Random if not set
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
    /// Run the daemon in the foreground (invoked by the system service)
    #[command(hide = true)]
    Daemon,
    /// Install the system service if needed and start it
    Up,
    /// Disconnect from all networks (signals daemon to shut down)
    Down,
    /// Uninstall system service
    Uninstall,
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
        /// New hostname (e.g. "alice" → alice.network.ray)
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
        /// Pairing ticket from the primary device (shorthand for `rayfish pair accept <ticket>`)
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
        /// Transfer ID (from 'rayfish files')
        id: u64,
        /// Output directory (default: ~/Downloads)
        #[arg(long, short)]
        output: Option<String>,
    },
}

fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("rayfish requires root privileges to create TUN devices. Run with sudo.");
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
        Command::Daemon => {
            check_root();
            let token = shutdown::token();
            let stats = Arc::new(stats::ForwardMetrics::default());
            stats.spawn_logger(token.clone());
            daemon::run_daemon(token, stats).await
        }
        Command::Up => cmd_up().await,
        Command::Down => ipc_down().await,
        Command::Uninstall => cmd_uninstall_service(),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "ray", &mut std::io::stdout());
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
            eprintln!("Usage: rayfish mdns <on|off>");
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
            let key_str = network_key.to_string();
            let short = if key_str.len() > 12 {
                format!("{}…{}", &key_str[..4], &key_str[key_str.len() - 4..])
            } else {
                key_str.clone()
            };
            println!();
            println!(
                "{} {}",
                style::green("✓ network created"),
                style::bold(&name)
            );
            println!(
                "  {}  {}",
                style::label("IPv4"),
                style::value(&my_ip.to_string())
            );
            if let Some(v6) = my_ipv6 {
                println!(
                    "  {}  {}",
                    style::label("IPv6"),
                    style::value(&v6.to_string())
                );
            }
            println!("  {}  {}", style::label("join"), style::rose(&short));
            println!(
                "  {}  {}",
                style::faint(&format!("ray join {network_key}")),
                style::faint("# share this command to invite")
            );
            println!();
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
            println!();
            println!("{} {}", style::green("✓ joined"), style::bold(&name));
            println!(
                "  {}  {}",
                style::label("IPv4"),
                style::value(&my_ip.to_string())
            );
            if let Some(v6) = my_ipv6 {
                println!(
                    "  {}  {}",
                    style::label("IPv6"),
                    style::value(&v6.to_string())
                );
            }
            println!();
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
        println!();
        println!("  {}", style::red("✗ daemon not running"));
        if app_config.networks.is_empty() {
            println!("  {}", style::faint("no saved networks"));
            println!();
            return Ok(());
        }
        println!("  {}", style::faint("saved networks:"));
        for net in &app_config.networks {
            let ip_str = net
                .my_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!(
                "    {} {}  {}",
                style::value(&net.name),
                style::faint(&format!("({ip_str})")),
                style::faint(&format!("{} members", net.members.len()))
            );
        }
        println!();
        return Ok(());
    };

    ipc::send(&mut stream, ipc::IpcMessage::Status).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::StatusResponse {
            endpoint_id,
            mdns_enabled,
            active,
            networks,
            packets_rx,
            packets_tx,
            bytes_rx,
            bytes_tx,
        } => {
            println!();
            println!(
                "  {} {}",
                style::label("endpoint"),
                style::value(&endpoint_id.to_string())
            );
            println!(
                "  {} {}",
                style::label("state   "),
                if active {
                    style::green("up")
                } else {
                    style::faint("standby (ray up to activate)")
                }
            );
            println!(
                "  {} {}",
                style::label("mDNS    "),
                if mdns_enabled {
                    style::green("on")
                } else {
                    style::faint("off")
                }
            );
            if networks.is_empty() {
                println!();
                println!("  {}", style::faint("no active networks"));
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
                    println!();
                    print!(
                        "  {} {}",
                        style::bold(&net.name),
                        style::faint(&format!("[{role}]"))
                    );
                    if let Some(ref dns) = dns_name {
                        print!("  {}", style::value(dns));
                    }
                    println!("  {}", style::faint(&format!("({})", net.my_ip)));
                    if let Some(ref key) = net.network_key {
                        println!("    {}  {}", style::label("join   "), style::rose(key));
                    }
                    println!(
                        "    {}  {}",
                        style::label("members"),
                        style::value(&format!(
                            "{}/{} online",
                            net.peers.len() + 1,
                            net.member_count
                        ))
                    );
                    for peer in &net.peers {
                        let name = if let Some(ref h) = peer.hostname {
                            format!("{}.{}.{}", h, net.name, DNS_DOMAIN)
                        } else {
                            peer.ip.to_string()
                        };
                        print!(
                            "    {} {}  {}",
                            style::dot_online(),
                            style::value(&name),
                            style::faint(&format!("{}", peer.endpoint_id.fmt_short()))
                        );
                        if let Some(ref uid) = peer.user_identity {
                            print!(" {}", style::faint(&format!("user:{}", uid.fmt_short())));
                        }
                        if let Some(ref ci) = peer.connection {
                            let conn_type = match ci.conn_type {
                                ipc::ConnType::Direct => "direct",
                                ipc::ConnType::Relay => "relay",
                                ipc::ConnType::Tor => "tor",
                                ipc::ConnType::Unknown => "?",
                            };
                            print!("  {}", style::faint(conn_type));
                            if let Some(rtt) = ci.rtt_ms {
                                print!("  {}", style::latency(rtt));
                            }
                            if ci.lost_packets > 0 {
                                print!("  {}", style::red(&format!("lost:{}", ci.lost_packets)));
                            }
                        }
                        println!();
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
                    println!();
                    println!(
                        "  {} {}",
                        style::faint(&net.name),
                        style::faint("[inactive]")
                    );
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
            println!();
            println!(
                "  {} {}",
                style::label("traffic"),
                style::value(&format!(
                    "{} rx · {} tx · {}",
                    packets_rx,
                    packets_tx,
                    format_bytes(bytes_rx + bytes_tx)
                ))
            );
            println!();
        }
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// `ray down`: put the daemon on standby (tear down the TUN, revert DNS, drop
/// connections) while leaving the daemon process running so `ray up` can
/// reactivate it without root.
async fn ipc_down() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Down).await?;
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
    ipc::send(&mut stream, req).await?;
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
    ipc::send(&mut stream, req).await?;
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
            ipc::send(&mut stream, ipc::IpcMessage::ListFiles).await?;
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
                                f.id,
                                f.from,
                                f.mime_type,
                                f.filename,
                                format_size(f.size),
                            );
                        }
                        println!();
                        println!("Accept with: rayfish files accept <id>");
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
            ipc::send(&mut stream, ipc::IpcMessage::AcceptFile { id, output }).await?;
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
        // `rayfish pair <ticket>` shorthand
        (None, Some(ticket)) | (Some(PairAction::Accept { ticket }), _) => {
            ipc_pair_accept(&ticket).await
        }
        // `rayfish pair` — start pairing on primary device
        (None, None) => ipc_pair_start().await,
        // `rayfish pair backup`
        (Some(PairAction::Backup), _) => cmd_pair_backup(),
        // `rayfish pair restore <backup>`
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
            println!("  rayfish pair {}", ticket);
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
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

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
    println!("  rayfish pair restore {}", backup);
    Ok(())
}

fn cmd_pair_restore(backup: &str) -> Result<()> {
    use argon2::Argon2;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

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
        .join("rayfish");
    std::fs::create_dir_all(&config_dir)?;
    std::fs::write(config_dir.join("secret_key"), key.to_bytes())?;

    println!("Restored user identity: {}", key.public());
    println!("Restart the daemon for changes to take effect.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Service install/uninstall
// ---------------------------------------------------------------------------

/// Write the system service unit/plist, substituting the path of the binary
/// currently running so the service execs the same `ray` the user invoked
/// (rather than a hardcoded /usr/local/bin/ray). Idempotent — safe to call on
/// every `ray up`, keeping the exec path fresh if the binary moves.
#[allow(unused_variables)]
fn ensure_service_installed() -> Result<()> {
    let exe = std::env::current_exe()
        .context("failed to determine current executable path")?
        .to_string_lossy()
        .into_owned();

    #[cfg(target_os = "linux")]
    {
        let path = std::path::Path::new("/etc/systemd/system/rayfish.service");
        let service =
            include_str!("../contrib/rayfish.service").replace("/usr/local/bin/ray", &exe);
        std::fs::write(path, service)
            .with_context(|| format!("failed to write {}", path.display()))?;
        run_cmd("systemctl", &["daemon-reload"]);
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let path = std::path::Path::new("/Library/LaunchDaemons/com.rayfish.vpn.plist");
        let plist =
            include_str!("../contrib/com.rayfish.vpn.plist").replace("/usr/local/bin/ray", &exe);
        std::fs::write(path, plist)
            .with_context(|| format!("failed to write {}", path.display()))?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("system service not supported on this platform");
    }
}

/// `ray up`: activate the VPN.
///
/// If the daemon is already running (the common case — the system service
/// starts it at boot), this is just an unprivileged IPC call asking the daemon
/// to bring the TUN up, configure DNS, and reconnect networks. Only when no
/// daemon is reachable do we fall back to installing/starting the system
/// service, which requires root.
async fn cmd_up() -> Result<()> {
    if let Ok(mut stream) = ipc::connect().await {
        ipc::send(&mut stream, ipc::IpcMessage::Up).await?;
        match ipc::recv(&mut stream).await? {
            ipc::IpcMessage::Ok { message } => println!("{message}"),
            ipc::IpcMessage::Error { message } => eprintln!("Error: {message}"),
            other => eprintln!("Unexpected response: {other:?}"),
        }
        return Ok(());
    }

    // No daemon reachable — install and start the system service (needs root).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "rayfish service is not running. Start it with: sudo ray up\n\
             (the daemon needs root to install the system service and create the TUN device)"
        );
        std::process::exit(1);
    }
    install_and_start_service()
}

/// Install/refresh the system service and (re)start it. Requires root.
fn install_and_start_service() -> Result<()> {
    ensure_service_installed()?;

    #[cfg(target_os = "linux")]
    {
        run_cmd("systemctl", &["enable", "rayfish"]);
        run_cmd("systemctl", &["restart", "rayfish"]);
        println!("rayfish service started. Check `ray status`.");
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let path = "/Library/LaunchDaemons/com.rayfish.vpn.plist";
        // Tear down any previously loaded job (e.g. one pointing at a stale
        // binary path) before loading the freshly written plist.
        run_cmd_quiet("launchctl", &["unload", path]);
        run_cmd("launchctl", &["load", "-w", path]);
        println!("rayfish service started. Check `ray status`.");
        return Ok(());
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("system service not supported on this platform");
    }
}

#[allow(dead_code)]
fn run_cmd(program: &str, args: &[&str]) {
    match std::process::Command::new(program).args(args).status() {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("warning: `{program}` exited with {status}"),
        Err(e) => eprintln!("warning: failed to run `{program}`: {e}"),
    }
}

/// Run a command, ignoring its exit status (used for best-effort teardown).
#[allow(dead_code)]
fn run_cmd_quiet(program: &str, args: &[&str]) {
    let _ = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn cmd_uninstall_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = std::path::Path::new("/etc/systemd/system/rayfish.service");
        if path.exists() {
            run_cmd("systemctl", &["disable", "--now", "rayfish"]);
            std::fs::remove_file(path)?;
            run_cmd("systemctl", &["daemon-reload"]);
            println!("Removed systemd service.");
        } else {
            println!("Service not installed.");
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let path = std::path::Path::new("/Library/LaunchDaemons/com.rayfish.vpn.plist");
        if path.exists() {
            run_cmd("launchctl", &["unload", "-w", &path.to_string_lossy()]);
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
