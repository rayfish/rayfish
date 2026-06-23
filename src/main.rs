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
mod invite;
mod ipc;
mod logdir;
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
        /// Make the network public: anyone with the room id can join directly.
        /// Without this flag the network is closed (gated by approval/invites).
        #[arg(long, conflicts_with = "closed")]
        open: bool,
        /// Explicitly create a closed (gated) network. This is the default.
        #[arg(long)]
        closed: bool,
        /// Network name used in DNS (e.g. "gaming" → alice.gaming.ray). Random if not set
        #[arg(long)]
        name: Option<String>,
        /// Your hostname within the network (e.g. "alice" → alice.gaming.ray). Random if not set
        #[arg(long)]
        hostname: Option<String>,
        /// Route traffic through Tor (requires running Tor daemon with ControlPort 9051)
        #[arg(long)]
        tor: bool,
        /// Trusted network: as coordinator you may suggest firewall rules to
        /// members (`ray firewall suggest` / `ray apply`), distributed in the
        /// signed blob and taken by members that opt in with `--allow-trusted`.
        #[arg(long)]
        trusted: bool,
    },
    /// Join an existing network using its room id or an invite code
    Join {
        /// The network public key (room id) or a one-time invite code
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
        /// Auto-take coordinator-suggested firewall rules on this network without
        /// a manual review queue (managed node).
        #[arg(long)]
        allow_trusted: bool,
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
    /// Collect diagnostics (logs + metrics) and open a pre-filled GitHub issue
    Report,
    /// Run the daemon in the foreground (invoked by the system service)
    #[command(hide = true)]
    Daemon,
    /// Install the system service if needed and start it
    Up {
        /// Set your default hostname for future networks (e.g. "dario"). Used
        /// when create/join don't specify one; doesn't rename existing networks
        #[arg(long)]
        hostname: Option<String>,
        /// Opt every saved network into auto-taking coordinator-suggested
        /// firewall rules (persisted; applies to trusted networks).
        #[arg(long)]
        allow_trusted: bool,
    },
    /// Disconnect from all networks (signals daemon to shut down)
    Down,
    /// Uninstall system service
    Uninstall,
    /// Install or refresh the system service and start it (requires root)
    Install,
    /// Restart the system service (requires root)
    Restart,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Mint and manage one-time invite codes for a network (coordinator only)
    Invite {
        /// Network name to issue/manage invites for
        network: String,
        #[command(subcommand)]
        action: Option<InviteAction>,
    },
    /// List peers awaiting approval on a closed network (coordinator only)
    Requests {
        /// Network name
        network: String,
    },
    /// Admit a peer waiting for approval (coordinator only)
    Accept {
        /// Network name
        network: String,
        /// Short id of the pending peer (from `ray requests`)
        id: String,
    },
    /// Reject a peer waiting for approval (coordinator only)
    Deny {
        /// Network name
        network: String,
        /// Short id of the pending peer (from `ray requests`)
        id: String,
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
    /// Authorize a user to run ray without sudo (requires root)
    SetOperator {
        /// Username or numeric UID to grant operator access
        user: String,
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
enum InviteAction {
    /// Mint a new one-time invite code (default action)
    Create {
        /// How long the invite stays valid, e.g. 24h, 7d, 30m (default 7d)
        #[arg(long, default_value = "7d")]
        expires: String,
        /// Hostname the coordinator assigns on redemption (trusted networks).
        /// The holder joins with no `--hostname`.
        #[arg(long)]
        hostname: Option<String>,
    },
    /// List issued invites and their status
    List,
    /// Revoke an unused invite by id
    Revoke {
        /// Invite id (from `ray invite <network> list`)
        id: String,
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
        /// Restrict to a network (omit to match any network the peer is reached through)
        #[arg(long)]
        network: Option<String>,
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
    /// Coordinator-only: suggest firewall rules for a subject host on a trusted
    /// network. Distributed in the signed blob; members take them per consent.
    Suggest {
        /// Network name
        network: String,
        /// Subject host (the hostname the rules protect)
        #[arg(long)]
        subject: String,
        /// Allow a peer on ports, e.g. `--allow earn01:9000,8123` (repeatable)
        #[arg(long, value_name = "PEER:PORTS")]
        allow: Vec<String>,
        /// Deny a peer on ports (repeatable)
        #[arg(long, value_name = "PEER:PORTS")]
        deny: Vec<String>,
        /// Default action for the subject on this network: allow or deny
        #[arg(long)]
        default: Option<String>,
    },
    /// Show suggested rules queued for manual review on a trusted network
    /// (a member that did not join with `--allow-trusted`).
    Pending {
        /// Network name
        network: String,
    },
    /// Accept and install a network's queued suggested rules
    Accept {
        /// Network name
        network: String,
    },
    /// Discard a network's queued suggested rules without installing them
    Deny {
        /// Network name
        network: String,
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

/// Guards that must outlive the process: the file appender's `WorkerGuard`
/// (flushes buffered log lines) and, under the `otel` feature, the OpenTelemetry
/// tracer provider (flushed on drop so in-flight spans are exported).
#[derive(Default)]
struct LogGuard {
    _appender: Option<tracing_appender::non_blocking::WorkerGuard>,
    #[cfg(feature = "otel")]
    otel_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.otel_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

/// Build the tracing subscriber. The console layer (stdout) is always present;
/// the daemon additionally gets a rolling daily file layer under [`logdir::log_dir`]
/// so that `ray report` has on-disk logs to bundle. With the `otel` feature and an
/// OTLP endpoint configured, spans are also exported to an OpenTelemetry collector.
/// The returned [`LogGuard`] must be kept alive for the lifetime of the process.
fn init_tracing(to_file: bool) -> LogGuard {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Console layer — unchanged behavior (human text on stdout).
    let console_layer = tracing_subscriber::fmt::layer();

    // File layer — daemon only, human text with ANSI stripped, rotated daily.
    let (file_layer, appender_guard) = if to_file {
        match std::fs::create_dir_all(logdir::log_dir()) {
            Ok(()) => {
                let appender = tracing_appender::rolling::daily(logdir::log_dir(), "rayfish.log");
                let (writer, guard) = tracing_appender::non_blocking(appender);
                let layer = tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(writer);
                (Some(layer), Some(guard))
            }
            Err(e) => {
                eprintln!(
                    "warning: cannot create log directory {}: {e} (file logging disabled)",
                    logdir::log_dir().display()
                );
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let mut guard = LogGuard {
        _appender: appender_guard,
        #[cfg(feature = "otel")]
        otel_provider: None,
    };

    // OTLP span export layer — only built when the feature is on AND an endpoint
    // is configured. Type-erased to `Box<dyn Layer>` so the `None` case has a
    // concrete type; the daemon flushes the provider on shutdown via `LogGuard`.
    let otel_layer = build_otel_layer(&mut guard);

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .with(otel_layer)
        .init();
    guard
}

#[cfg(feature = "otel")]
fn build_otel_layer<S>(
    guard: &mut LogGuard,
) -> Option<Box<dyn tracing_subscriber::Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a> + Send + Sync,
{
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::Layer as _;

    // Respect the standard OTLP env vars: do nothing unless an endpoint is set.
    if std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_none()
        && std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_none()
    {
        return None;
    }

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("otel: failed to build OTLP exporter: {e}");
            return None;
        }
    };

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name("rayfish")
        .build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let tracer = provider.tracer("rayfish");
    guard.otel_provider = Some(provider);

    tracing::info!("OpenTelemetry OTLP span export enabled");
    Some(tracing_opentelemetry::layer().with_tracer(tracer).boxed())
}

/// No-op when the `otel` feature is disabled; the registry sees an inert layer.
#[cfg(not(feature = "otel"))]
fn build_otel_layer(_guard: &mut LogGuard) -> Option<tracing_subscriber::layer::Identity> {
    None
}

/// Install a fail-fast panic hook (daemon only). On any panic — including in a
/// spawned tokio task, which the runtime would otherwise swallow — it records the
/// crash (message, location, thread, backtrace) via `tracing::error!` (rolling file
/// log + any OTLP exporter) and synchronously appends it to `panic.log` in the log
/// dir, then **aborts the process**.
///
/// Rationale: a panic is an invariant violation. For a VPN daemon, limping on with
/// a dead subsystem (e.g. a stalled forwarding loop) is worse than a clean restart —
/// and a live-but-broken process won't trip the service manager's restart. Aborting
/// lets systemd/launchd restart from known-good state; peers then reconnect. The
/// crash is captured (durably in `panic.log`) and bundled by `ray report`.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());

        tracing::error!(
            location = %location,
            thread = %thread,
            "panic: {message}\n{backtrace}"
        );
        // Durable, synchronous capture — survives even though abort() skips the
        // async log appender's flush.
        if let Err(e) = append_panic_log(&location, &thread, &message, &backtrace) {
            eprintln!("failed to write panic log: {e}");
        }

        // Print the standard panic message to stderr (journal), then fail fast so
        // the service manager restarts the daemon cleanly.
        default_hook(info);
        std::process::abort();
    }));
}

/// Append a panic record to `<log_dir>/panic.log`. Best-effort durability in case
/// the tracing pipeline itself is implicated in the crash.
fn append_panic_log(
    location: &str,
    thread: &str,
    message: &str,
    backtrace: &std::backtrace::Backtrace,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = logdir::log_dir();
    std::fs::create_dir_all(&dir)?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("panic.log"))?;
    writeln!(f, "=== panic @ unix {ts} ===")?;
    writeln!(f, "thread:   {thread}")?;
    writeln!(f, "location: {location}")?;
    writeln!(f, "message:  {message}")?;
    writeln!(f, "backtrace:\n{backtrace}\n")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Keep the appender guard alive for the whole process so file logs flush.
    let _log_guard = init_tracing(matches!(cli.command, Command::Daemon));

    match cli.command {
        Command::Leave { name } => ipc_leave(&name).await,
        Command::Create {
            open,
            closed: _,
            name,
            hostname,
            tor,
            trusted,
        } => {
            let mode = if open {
                GroupMode::Open
            } else {
                GroupMode::Restricted
            };
            ipc_create(mode, name, hostname, tor, trusted).await
        }
        Command::Join {
            network_key,
            name,
            hostname,
            tor,
            allow_trusted,
        } => ipc_join(&network_key, name.as_deref(), hostname, tor, allow_trusted).await,
        Command::Nuke { name, force } => ipc_nuke(&name, force).await,
        Command::Status => ipc_status().await,
        Command::Report => ipc_report().await,
        Command::Daemon => {
            check_root();
            install_panic_hook();
            let token = shutdown::token();
            let stats = Arc::new(stats::ForwardMetrics::default());
            stats.spawn_logger(token.clone());
            daemon::run_daemon(token, stats).await
        }
        Command::Up {
            hostname,
            allow_trusted,
        } => cmd_up(hostname, allow_trusted).await,
        Command::Down => ipc_down().await,
        Command::Uninstall => cmd_uninstall_service(),
        Command::Install => cmd_install().await,
        Command::Restart => cmd_restart().await,
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "ray", &mut std::io::stdout());
            Ok(())
        }
        Command::Invite { network, action } => ipc_invite(&network, action).await,
        Command::Requests { network } => ipc_requests(&network).await,
        Command::Accept { network, id } => ipc_accept_request(&network, &id).await,
        Command::Deny { network, id } => ipc_deny_request(&network, &id).await,
        Command::Firewall { action } => ipc_firewall(action).await,
        Command::Hostname { network, name } => ipc_set_hostname(&network, &name).await,
        Command::Mdns { state } => cmd_mdns(&state),
        Command::SetOperator { user } => cmd_set_operator(&user).await,
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

/// Resolve a username to its UID, falling back to parsing a numeric UID.
fn uid_for_user(user: &str) -> Option<u32> {
    use std::ffi::CString;
    let cname = CString::new(user).ok()?;
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if !pw.is_null() {
        return Some(unsafe { (*pw).pw_uid });
    }
    user.parse::<u32>().ok()
}

/// `ray set-operator <user>`: authorize a local user to run mutating ray
/// commands without sudo (Tailscale's `--operator` model). The daemon enforces
/// that this call itself comes from root.
async fn cmd_set_operator(user: &str) -> Result<()> {
    let uid = uid_for_user(user)
        .ok_or_else(|| anyhow::anyhow!("unknown user '{user}' (pass a valid username or UID)"))?;
    let mut stream = ipc::connect()
        .await
        .context("rayfish daemon is not running; start it with: sudo ray up")?;
    ipc::send(&mut stream, ipc::IpcMessage::SetOperator { uid }).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("Unexpected response: {other:?}"),
    }
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
    trusted: bool,
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
            trusted,
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
    allow_trusted: bool,
) -> Result<()> {
    let transport = if tor {
        Some(config::TransportMode::Tor)
    } else {
        None
    };
    // `ray join <arg>` accepts either a bare room id (the network public key) or
    // a self-contained invite code. An invite decodes to the network key plus the
    // coordinator to dial and a one-time secret to present.
    let (network_key, invite, coordinator) = match invite::decode_invite_code(network_key) {
        Ok((net_pubkey, coord, secret)) => (net_pubkey.to_string(), Some(secret), Some(coord)),
        Err(_) => (network_key.to_string(), None, None),
    };
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Join {
            network_key,
            name: name.map(|s| s.to_string()),
            hostname,
            transport,
            invite,
            coordinator,
            allow_trusted,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => {
            println!("{}", message);
        }
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

/// Base repository for `ray report`. Swap this for a managed upload endpoint
/// once the diagnostics service exists; the rest of the flow stays the same.
const REPORT_REPO_URL: &str = "https://github.com/rayfish/rayfish";

/// Ask the daemon to build a diagnostic bundle, then open a pre-filled GitHub
/// issue so the user can attach it. The bundle is built daemon-side (logs are
/// root-owned) and written to a path owned by the invoking user.
async fn ipc_report() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Report).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::ReportBundle {
            path,
            issue_title,
            issue_body,
        } => {
            println!("Diagnostic bundle written to:\n  {path}\n");
            println!(
                "Review it before sharing — it contains your logs, virtual IPs, and peer IDs,\n\
                 but no private keys."
            );
            let url = url::Url::parse_with_params(
                &format!("{REPORT_REPO_URL}/issues/new"),
                &[
                    ("title", issue_title.as_str()),
                    ("body", issue_body.as_str()),
                ],
            )?;
            println!("\nOpening a pre-filled GitHub issue — attach the bundle above.");
            if !open_url(url.as_str()) {
                println!("\nCouldn't open a browser. Open this URL manually:\n{url}");
            }
        }
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Best-effort: open `url` in the user's default browser. Returns false if no
/// opener is available (e.g. headless), so the caller can print it instead.
fn open_url(url: &str) -> bool {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(url)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

/// Parse a duration like `30m`, `24h`, `7d`, `90s` into seconds.
fn parse_duration_secs(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(rest) = s.strip_suffix('s') {
        (rest, 1u64)
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = s.strip_suffix('h') {
        (rest, 3600)
    } else if let Some(rest) = s.strip_suffix('d') {
        (rest, 86400)
    } else {
        (s, 1)
    };
    let value: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{s}': use e.g. 30m, 24h, 7d"))?;
    Ok(value * mult)
}

async fn ipc_invite(network: &str, action: Option<InviteAction>) -> Result<()> {
    let action = action.unwrap_or(InviteAction::Create {
        expires: "7d".to_string(),
        hostname: None,
    });
    let hostname_opt = match &action {
        InviteAction::Create { hostname, .. } => hostname.clone(),
        _ => None,
    };
    let req = match action {
        InviteAction::Create { expires, hostname } => ipc::IpcMessage::InviteCreate {
            network: network.to_string(),
            expires_secs: parse_duration_secs(&expires)?,
            hostname,
        },
        InviteAction::List => ipc::IpcMessage::InviteList {
            network: network.to_string(),
        },
        InviteAction::Revoke { id } => ipc::IpcMessage::InviteRevoke {
            network: network.to_string(),
            id,
        },
    };
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::InviteCreated {
            code,
            id,
            expires_secs,
        } => {
            println!();
            println!("{} {}", style::green("✓ invite"), style::faint(&id));
            println!();
            println!("  {}", style::bold(&code));
            println!();
            qr2term::print_qr(&code).ok();
            println!(
                "\n  share this code; the holder joins with: {}",
                style::faint(&format!("ray join {code}"))
            );
            let days = expires_secs / 86400;
            let hours = (expires_secs % 86400) / 3600;
            let ttl = if days > 0 {
                format!("{days}d")
            } else if hours > 0 {
                format!("{hours}h")
            } else {
                format!("{}m", expires_secs / 60)
            };
            println!("  single-use, expires in {ttl}");
            if let Some(h) = &hostname_opt {
                println!("  binds hostname: {}", style::bold(h));
            }
        }
        ipc::IpcMessage::InviteListResponse { invites } => {
            if invites.is_empty() {
                println!("No invites.");
            } else {
                for inv in invites {
                    let who = inv.redeemer.map(|r| format!(" by {r}")).unwrap_or_default();
                    let host = inv
                        .hostname
                        .as_deref()
                        .map(|h| format!("  host={h}"))
                        .unwrap_or_default();
                    println!("  {}  {}{}{}", style::rose(&inv.id), inv.status, who, host);
                }
            }
        }
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_requests(network: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Requests {
            network: network.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PendingRequests { requests } => {
            if requests.is_empty() {
                println!("No pending join requests.");
            } else {
                println!("Pending join requests:");
                for r in requests {
                    let host = r.hostname.unwrap_or_else(|| "—".to_string());
                    println!(
                        "  {}  {}  waiting {}s",
                        style::rose(&r.short_id),
                        host,
                        r.waiting_secs
                    );
                }
                println!("\nAdmit with: ray accept {network} <id>");
            }
        }
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_accept_request(network: &str, id: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::AcceptRequest {
            network: network.to_string(),
            id: id.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_deny_request(network: &str, id: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::DenyRequest {
            network: network.to_string(),
            id: id.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_firewall(action: FirewallAction) -> Result<()> {
    if let FirewallAction::Suggest {
        network,
        subject,
        allow,
        deny,
        default,
    } = action
    {
        return ipc_firewall_suggest(&network, &subject, allow, deny, default).await;
    }
    let mut stream = ipc::connect().await?;
    let req = match action {
        FirewallAction::Add {
            direction,
            action,
            proto,
            port,
            peer,
            network,
        } => ipc::IpcMessage::FirewallAdd {
            direction,
            action,
            protocol: proto,
            port,
            peer,
            network,
        },
        FirewallAction::Remove { index } => ipc::IpcMessage::FirewallRemove { index },
        FirewallAction::Show => ipc::IpcMessage::FirewallShow,
        FirewallAction::Default { action } => ipc::IpcMessage::FirewallDefault { action },
        FirewallAction::Pending { network } => ipc::IpcMessage::FirewallPending { network },
        FirewallAction::Accept { network } => ipc::IpcMessage::FirewallAccept { network },
        FirewallAction::Deny { network } => ipc::IpcMessage::FirewallDeny { network },
        // Handled above by early return (needs a read-modify-write round trip).
        FirewallAction::Suggest { .. } => unreachable!(),
    };
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::FirewallState { display } => print!("{}", display),
        ipc::IpcMessage::FirewallPendingResponse { display } => print!("{}", display),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {}", message),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// `ray firewall suggest`: read the network's current suggestions, merge the
/// requested subject edits, and publish the updated set (coordinator-only).
async fn ipc_firewall_suggest(
    network: &str,
    subject: &str,
    allow: Vec<String>,
    deny: Vec<String>,
    default: Option<String>,
) -> Result<()> {
    use ray_proto::HostSuggestions;

    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallSuggestions {
            network: network.to_string(),
        },
    )
    .await?;
    let mut suggestions = match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::FirewallSuggestionsResponse { suggestions } => suggestions,
        ipc::IpcMessage::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
        other => {
            eprintln!("Unexpected response: {other:?}");
            std::process::exit(1);
        }
    };

    let parse = |spec: &str, flag: &str| -> Result<(String, String)> {
        let (peer, ports) = spec
            .split_once(':')
            .with_context(|| format!("{flag} expects PEER:PORTS, got '{spec}'"))?;
        anyhow::ensure!(
            !peer.is_empty() && !ports.is_empty(),
            "{flag} expects PEER:PORTS, got '{spec}'"
        );
        Ok((peer.to_string(), ports.to_string()))
    };

    let entry = suggestions.entry(subject.to_string()).or_default();
    if let Some(d) = default {
        entry.default = Some(d);
    }
    for a in &allow {
        let (peer, ports) = parse(a, "--allow")?;
        entry.allows.insert(peer, ports);
    }
    for d in &deny {
        let (peer, ports) = parse(d, "--deny")?;
        entry.denies.insert(peer, ports);
    }
    // Drop a now-empty subject so removing all of a host's rules clears it.
    if entry == &HostSuggestions::default() {
        suggestions.remove(subject);
    }

    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallSuggest {
            network: network.to_string(),
            suggestions,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::Error { message } => eprintln!("Error: {message}"),
        other => eprintln!("Unexpected response: {other:?}"),
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
async fn cmd_up(hostname: Option<String>, allow_trusted: bool) -> Result<()> {
    if let Ok(mut stream) = ipc::connect().await {
        ipc::send(
            &mut stream,
            ipc::IpcMessage::Up {
                hostname,
                allow_trusted,
            },
        )
        .await?;
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
    install_and_start_service(hostname, allow_trusted).await
}

/// Install/refresh the system service and (re)start it. Requires root.
///
/// Starting the service is fire-and-forget at the OS level, so we then wait for
/// the daemon to actually accept an IPC connection before declaring success. If
/// it never comes up (e.g. it crashed on a port/route conflict with another
/// VPN), we surface the tail of its log so the user knows what went wrong
/// instead of seeing a cheerful "started" followed by a dead `ray status`.
async fn install_and_start_service(hostname: Option<String>, allow_trusted: bool) -> Result<()> {
    ensure_service_installed()?;

    #[cfg(target_os = "linux")]
    {
        run_cmd("systemctl", &["enable", "rayfish"]);
        run_cmd("systemctl", &["restart", "rayfish"]);
    }

    #[cfg(target_os = "macos")]
    {
        let path = "/Library/LaunchDaemons/com.rayfish.vpn.plist";
        // Tear down any previously loaded job (e.g. one pointing at a stale
        // binary path) before loading the freshly written plist.
        run_cmd_quiet("launchctl", &["unload", path]);
        run_cmd("launchctl", &["load", "-w", path]);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("system service not supported on this platform");
    }

    // Wait for the freshly started daemon to accept IPC, then activate the VPN.
    match wait_for_daemon(std::time::Duration::from_secs(8)).await {
        Some(mut stream) => {
            ipc::send(
                &mut stream,
                ipc::IpcMessage::Up {
                    hostname,
                    allow_trusted,
                },
            )
            .await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => println!("rayfish service started. {message}"),
                ipc::IpcMessage::Error { message } => eprintln!("Error: {message}"),
                other => eprintln!("Unexpected response: {other:?}"),
            }
            // We're root here (installing the service). Grant the invoking user
            // operator access so they can run `ray` without sudo from now on,
            // the way `tailscale up --operator=$USER` does.
            grant_operator_to_invoking_user().await;
            Ok(())
        }
        None => {
            eprintln!(
                "rayfish service was started but the daemon never became reachable.\n\
                 It likely crashed on startup — a common cause is another VPN (e.g. Tailscale)\n\
                 already using the 100.64.0.0/10 range, DNS port 53, or a conflicting route."
            );
            print_daemon_log_tail();
            std::process::exit(1);
        }
    }
}

/// When the service is (re)installed under `sudo`, grant the invoking user
/// (`$SUDO_USER`) operator access so subsequent `ray` commands work without
/// root. Best-effort: silent if there is no `$SUDO_USER` or the daemon refuses.
async fn grant_operator_to_invoking_user() {
    let Ok(user) = std::env::var("SUDO_USER") else {
        return;
    };
    if user == "root" {
        return;
    }
    let Some(uid) = uid_for_user(&user) else {
        return;
    };
    if let Ok(mut stream) = ipc::connect().await {
        let _ = ipc::send(&mut stream, ipc::IpcMessage::SetOperator { uid }).await;
        if let Ok(ipc::IpcMessage::Ok { .. }) = ipc::recv(&mut stream).await {
            println!("granted operator access to '{user}' — run ray without sudo");
        }
    }
}

/// Ensure the process is running as root for service-manager operations.
/// Prints a clear `sudo` hint and exits non-zero otherwise.
fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "this command manages the system service and needs root.\n\
             Re-run with: sudo ray <command>"
        );
        std::process::exit(1);
    }
    Ok(())
}

/// `ray install`: install the system service if needed (or refresh an existing
/// install), then start it and verify the daemon comes up. Requires root.
async fn cmd_install() -> Result<()> {
    require_root()?;
    install_and_start_service(None, false).await
}

/// `ray restart`: restart the already-installed system service via the OS
/// service manager (does not rewrite the unit file). Requires root. The daemon
/// comes back up active.
async fn cmd_restart() -> Result<()> {
    require_root()?;

    #[cfg(target_os = "linux")]
    {
        let unit = std::path::Path::new("/etc/systemd/system/rayfish.service");
        if !unit.exists() {
            eprintln!("rayfish service is not installed. Run: sudo ray up");
            std::process::exit(1);
        }
        run_cmd("systemctl", &["restart", "rayfish"]);
    }

    #[cfg(target_os = "macos")]
    {
        let plist = std::path::Path::new("/Library/LaunchDaemons/com.rayfish.vpn.plist");
        if !plist.exists() {
            eprintln!("rayfish service is not installed. Run: sudo ray up");
            std::process::exit(1);
        }
        run_cmd("launchctl", &["kickstart", "-k", "system/com.rayfish.vpn"]);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("system service not supported on this platform");
    }

    // Confirm the daemon came back, mirroring `up`/`install` diagnostics.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match wait_for_daemon(std::time::Duration::from_secs(8)).await {
        Some(_) => {
            println!("rayfish service restarted.");
            Ok(())
        }
        None => {
            eprintln!("rayfish service was restarted but the daemon never became reachable.");
            print_daemon_log_tail();
            std::process::exit(1);
        }
    }
}

/// Poll the IPC socket until the daemon answers or the deadline passes.
async fn wait_for_daemon(timeout: std::time::Duration) -> Option<ipc::IpcFramed> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(stream) = ipc::connect().await {
            return Some(stream);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Print the last few lines of the daemon log so a failed startup is diagnosable.
fn print_daemon_log_tail() {
    #[cfg(target_os = "macos")]
    {
        let path = "/var/log/rayfish.log";
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let tail: Vec<&str> = contents.lines().rev().take(15).collect();
                if tail.is_empty() {
                    eprintln!("\n(daemon log {path} is empty)");
                } else {
                    eprintln!("\nLast lines of {path}:");
                    for line in tail.into_iter().rev() {
                        eprintln!("  {line}");
                    }
                }
            }
            Err(e) => eprintln!("\n(could not read daemon log {path}: {e})"),
        }
    }

    #[cfg(target_os = "linux")]
    {
        eprintln!("\nRecent daemon log (journalctl -u rayfish):");
        run_cmd("journalctl", &["-u", "rayfish", "-n", "15", "--no-pager"]);
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
