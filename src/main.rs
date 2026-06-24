// The daemon's modules live in the `rayfish` library crate (`src/lib.rs`) so
// integration tests and benchmarks can reach them; this binary is the CLI/IPC
// client built on top.
use rayfish::{
    DNS_DOMAIN, apply, config, daemon, firewall, identity, invite, ipc, layout, logdir, membership,
    onepassword, picker, progress, shutdown, stats, style,
};

use std::sync::{Arc, atomic};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use membership::GroupMode;

#[derive(Parser)]
#[command(name = "ray", about = "P2P mesh VPN powered by iroh")]
struct Cli {
    /// Emit machine-readable JSON instead of styled text (disables color and
    /// spinners). Supported by `status`, `firewall show`, `files`, and other
    /// list commands.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

static JSON_FLAG: atomic::AtomicBool = atomic::AtomicBool::new(false);

/// Whether `--json` output mode is active (set once in `main`).
fn json_enabled() -> bool {
    JSON_FLAG.load(atomic::Ordering::Relaxed)
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
        /// Auto-install coordinator-suggested firewall rules on this network
        /// without a manual review queue (managed node, e.g. a server). Without
        /// it, suggestions queue for `ray firewall accept`.
        #[arg(long)]
        auto_accept_firewall: bool,
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
    /// Request a direct 2-peer connection to someone by their contact id. They
    /// approve it with `ray connections approve`, forming a private 2-peer
    /// network — no room id or invite code needed.
    Connect {
        /// The peer's contact id (from their `ray contact id` / `ray status`)
        contact_id: String,
        /// Your hostname on the resulting network (defaults to your set name)
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Review and approve incoming direct-connection requests (`ray connect`)
    Connections {
        #[command(subcommand)]
        action: Option<ConnectionsAction>,
    },
    /// Show or rotate your contact id (shared so others can `ray connect` you)
    Contact {
        #[command(subcommand)]
        action: Option<ContactAction>,
    },
    /// Grant the network key to a member (coordinator only). The grantee becomes
    /// a co-coordinator: it can publish the signed blob and suggest firewall
    /// rules. Trusted-network multi-admin.
    Admin {
        /// Network name
        network: String,
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Manage local device firewall rules
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },
    /// Reconcile trusted networks against a deploy spec file (Phase B). Creates
    /// missing trusted networks, publishes idempotent firewall suggestions, and
    /// reports the membership gap (expected vs joined hosts). Never joins.
    Apply {
        /// Path to a TOML spec file (see `ray apply --example`).
        spec: Option<String>,
        /// Drop suggested-firewall subjects that are no longer in the spec.
        #[arg(long)]
        prune: bool,
        /// Show what would change without applying it.
        #[arg(long)]
        dry_run: bool,
        /// Mint one-time invites for hosts the spec expects but that haven't
        /// joined yet (hostname-bound). Without this flag, the commands are
        /// only printed.
        #[arg(long)]
        invite_missing: bool,
        /// Print an example spec file and exit.
        #[arg(long, conflicts_with_all = ["spec", "prune", "dry_run", "invite_missing"])]
        example: bool,
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
    /// Mint a new invite code (default action). Single-use by default; `--reusable`
    /// mints a multi-use key for unattended fleets.
    Create {
        /// How long the invite stays valid, e.g. 24h, 7d, 30m (default 7d;
        /// 30d for `--reusable`).
        #[arg(long)]
        expires: Option<String>,
        /// Hostname the coordinator assigns authoritatively on redemption
        /// (single-use only). The holder joins with no `--hostname`.
        #[arg(long, conflicts_with = "reusable")]
        hostname: Option<String>,
        /// Mint a reusable (multi-use, expiring) key that rides the signed blob,
        /// so any network-key holder can admit. Ideal for `ray join <key>
        /// --hostname <h> --auto-accept-firewall` in deploy scripts. Revoke with
        /// `ray invite <net> revoke <id>`.
        #[arg(long)]
        reusable: bool,
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
    Backup {
        /// Store the backup in 1Password (via the `op` CLI) instead of printing it
        #[arg(long = "1password", alias = "op")]
        onepassword: bool,
        /// 1Password vault (defaults to your default vault)
        #[arg(long)]
        vault: Option<String>,
        /// 1Password item title
        #[arg(long, default_value = "Rayfish Identity")]
        item: String,
    },
    /// Restore a signing key from an encrypted backup
    Restore {
        /// The encrypted backup string (omit when using --1password)
        backup: Option<String>,
        /// Read the backup from 1Password (via the `op` CLI)
        #[arg(long = "1password", alias = "op")]
        onepassword: bool,
        /// 1Password vault (defaults to your default vault)
        #[arg(long)]
        vault: Option<String>,
        /// 1Password item title
        #[arg(long, default_value = "Rayfish Identity")]
        item: String,
    },
}

#[derive(Subcommand)]
enum AdminAction {
    /// Grant the network key to a member (coordinator only)
    Add {
        /// Short id of the member to promote (from `ray status`)
        identity: String,
    },
    /// List this network's key-holders (the local node + granted members)
    List,
}

#[derive(Subcommand)]
enum ConnectionsAction {
    /// List pending incoming connection requests (default)
    List,
    /// Approve a pending request, forming the direct 2-peer network
    Approve {
        /// Short id of the requester (from `ray connections`)
        id: String,
    },
}

#[derive(Subcommand)]
enum ContactAction {
    /// Print your contact id (default)
    Id,
    /// Rotate your contact key (invalidates the old contact id)
    Rotate,
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
        /// Port or port range (e.g. 22, 80-443, or * for all)
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
    /// Coordinator-only: suggest firewall rules for a subject host on a network.
    /// Distributed in the signed blob; each node takes them per its own consent.
    Suggest {
        /// Network name
        network: String,
        /// Subject host (the hostname the rules protect). Use `*` to target every
        /// node on the network (e.g. "everyone opens this port").
        #[arg(long)]
        subject: String,
        /// Allow a peer, e.g. `--allow earn01:tcp:9000,tcp:8123` or `--allow earn01:icmp`
        /// (repeatable). Token grammar: `proto:ports` or bare proto (`icmp`, `any`, `tcp`).
        #[arg(long, value_name = "PEER:SPEC")]
        allow: Vec<String>,
        /// Deny a peer, e.g. `--deny earn01:tcp:443` or `--deny earn01:icmp` (repeatable).
        /// Same token grammar as `--allow`.
        #[arg(long, value_name = "PEER:SPEC")]
        deny: Vec<String>,
    },
    /// Show suggested rules queued for manual review on a network
    /// (a node that did not join with `--auto-accept-firewall`).
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
    /// Toggle auto-accepting this network's suggested firewall rules on this node
    /// (`on` installs the current queue; `off` stops future auto-install).
    AutoAccept {
        /// Network name
        network: String,
        /// `on` or `off`
        state: String,
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
    if cli.json {
        JSON_FLAG.store(true, atomic::Ordering::Relaxed);
        // JSON output must never be colorized or interrupted by spinners.
        style::set_plain(true);
    }
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
        } => {
            let mode = if open {
                GroupMode::Open
            } else {
                GroupMode::Restricted
            };
            ipc_create(mode, name, hostname, tor).await
        }
        Command::Join {
            network_key,
            name,
            hostname,
            tor,
            auto_accept_firewall,
        } => {
            ipc_join(
                &network_key,
                name.as_deref(),
                hostname,
                tor,
                auto_accept_firewall,
            )
            .await
        }
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
        Command::Up { hostname } => cmd_up(hostname).await,
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
        Command::Connect {
            contact_id,
            hostname,
        } => ipc_connect(&contact_id, hostname).await,
        Command::Connections { action } => ipc_connections(action).await,
        Command::Contact { action } => ipc_contact(action).await,
        Command::Admin { network, action } => ipc_admin(&network, action).await,
        Command::Firewall { action } => ipc_firewall(action).await,
        Command::Apply {
            spec,
            prune,
            dry_run,
            invite_missing,
            example,
        } => ipc_apply(spec, prune, dry_run, invite_missing, example).await,
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
            print_error("error", &message, None);
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
            let _ = my_ipv6;
            println!();
            println!(
                "  {} {} {}",
                style::check(),
                style::value("created"),
                style::bold(&name)
            );
            println!(
                "    {}   {}   {}  {}",
                style::label("address"),
                style::value(&my_ip.to_string()),
                style::faint("·"),
                style::rose(&short),
            );
            let join = format!("ray join {network_key}");
            print_next(&[
                (&join, "share this to invite peers"),
                ("ray up", "activate the VPN"),
            ]);
            println!();
        }
        ipc::IpcMessage::Error { message } => print_error("create failed", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_join(
    network_key: &str,
    name: Option<&str>,
    hostname: Option<String>,
    tor: bool,
    auto_accept_firewall: bool,
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
            auto_accept_firewall,
        },
    )
    .await?;
    // Joining dials the coordinator and runs the handshake daemon-side, so this
    // can take a few seconds — show a spinner while we wait.
    let spinner = progress::spinner("joining…");
    let resp = ipc::recv(&mut stream).await?;
    spinner.finish_and_clear();
    match resp {
        ipc::IpcMessage::Ok { message } => {
            println!("{}", message);
        }
        ipc::IpcMessage::Joined {
            name,
            my_ip,
            my_ipv6,
        } => {
            let _ = my_ipv6;
            let dns = format!("{name}.{DNS_DOMAIN}");
            println!();
            println!(
                "  {} {} {}",
                style::check(),
                style::value("joined"),
                style::bold(&name)
            );
            println!(
                "    {}   {}   {}  {}",
                style::label("address"),
                style::value(&my_ip.to_string()),
                style::faint("·"),
                style::value(&dns),
            );
            print_next(&[
                ("ray status", "see who's online"),
                ("ray up", "activate the VPN"),
            ]);
            println!();
        }
        ipc::IpcMessage::Error { message } => print_error("join failed", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Human-readable byte size (GiB/MiB/KiB/B) for traffic and transfer counters.
fn format_bytes(b: u64) -> String {
    bytesize::ByteSize(b).to_string()
}

/// Render a styled error block to stderr:
/// ```text
///   ✗ <title>
///     <detail>
///     hint  <hint>
/// ```
/// When `hint` is `None`, a hint is inferred from common daemon error strings.
fn print_error(title: &str, detail: &str, hint: Option<&str>) {
    eprintln!("  {} {}", style::cross(), style::bold(title));
    if !detail.is_empty() {
        eprintln!("    {}", style::value(detail));
    }
    let hint = hint.map(str::to_string).or_else(|| infer_hint(detail));
    if let Some(h) = hint {
        eprintln!("    {}  {}", style::label("hint"), style::faint(&h));
    }
}

/// Map a daemon error message to an actionable hint, best-effort.
fn infer_hint(message: &str) -> Option<String> {
    let m = message.to_lowercase();
    if m.contains("daemon") && (m.contains("not running") || m.contains("connect")) {
        Some("start the service: sudo ray up".into())
    } else if m.contains("expired") || m.contains("invite") {
        Some("ask the coordinator for a fresh code: ray invite <net>".into())
    } else if m.contains("root") || m.contains("permission") || m.contains("operator") {
        Some("run with sudo, or `sudo ray set-operator <you>` once".into())
    } else if m.contains("hostname") && m.contains("collision") {
        Some("pick another name: --hostname <name>".into())
    } else {
        None
    }
}

/// Render a "next steps" footer: an aligned list of suggested commands.
/// ```text
///     next  ray status   see who's online
///           ray up       activate the VPN
/// ```
fn print_next(steps: &[(&str, &str)]) {
    let rows: Vec<Vec<layout::Cell>> = steps
        .iter()
        .enumerate()
        .map(|(i, (cmd, blurb))| {
            let label = if i == 0 { "next" } else { "" };
            vec![
                layout::Cell::new(label, style::label(label)),
                layout::Cell::new(*cmd, style::rose(cmd)),
                layout::Cell::new(*blurb, style::faint(blurb)),
            ]
        })
        .collect();
    print!("{}", indent(&layout::columns(&rows, 2), 4));
}

/// Standard borderless table: a faint header row over `rows`, aligned via
/// [`layout::columns`] and indented `pad` spaces. Headers are styled here (so
/// `layout` stays presentation-free) and every list command shares this shape.
fn table(headers: &[&str], rows: Vec<Vec<layout::Cell>>, pad: usize) -> String {
    let header: Vec<layout::Cell> = headers
        .iter()
        .map(|h| layout::Cell::new(*h, style::faint(h)))
        .collect();
    let mut all = Vec::with_capacity(rows.len() + 1);
    all.push(header);
    all.extend(rows);
    indent(&layout::columns(&all, 2), pad)
}

/// Prefix every line of `block` with `indent` spaces (for nested table output).
fn indent(block: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    block
        .lines()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
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
            contact_id,
            networks,
            packets_rx,
            packets_tx,
            bytes_rx,
            bytes_tx,
        } => {
            if json_enabled() {
                print_json(&serde_json::json!({
                    "endpoint": endpoint_id.to_string(),
                    "mdns": mdns_enabled,
                    "active": active,
                    "contact_id": contact_id,
                    "networks": networks,
                    "traffic": {
                        "packets_rx": packets_rx, "packets_tx": packets_tx,
                        "bytes_rx": bytes_rx, "bytes_tx": bytes_tx,
                    },
                }));
                return Ok(());
            }
            let _ = (packets_rx, packets_tx, bytes_rx, bytes_tx);
            // Header: rayfish ● up    mDNS on    endpoint k7f2…9qx4
            let state = if active {
                format!("{} {}", style::dot_online(), style::value("up"))
            } else {
                format!("{} {}", style::dot_offline(), style::faint("standby"))
            };
            let mdns = if mdns_enabled {
                format!("{} {}", style::label("mDNS"), style::green("on"))
            } else {
                format!("{} {}", style::label("mDNS"), style::faint("off"))
            };
            println!();
            println!(
                "  {}  {}      {}      {} {}",
                style::bold("rayfish"),
                state,
                mdns,
                style::label("endpoint"),
                style::value(&endpoint_id.fmt_short().to_string()),
            );
            if !active {
                println!("  {}", style::faint("run `ray up` to activate"));
            }
            if let Some(ref cid) = contact_id {
                println!("  {} {}", style::label("contact"), style::rose(cid),);
            }

            if networks.is_empty() {
                println!();
                println!("  {}", style::faint("no active networks"));
            } else {
                for net in &networks {
                    let role = net.role.to_string();
                    let dns_name = net
                        .my_hostname
                        .as_ref()
                        .map(|h| format!("{}.{}.{}", h, net.name, DNS_DOMAIN));
                    println!();
                    print!("  {}  {}", style::bold(&net.name), style::marker(&role));
                    if let Some(ref dns) = dns_name {
                        print!("   {}", style::value(dns));
                    }
                    println!("   {}", style::faint(&net.my_ip.to_string()));

                    // Peer rows as aligned columns: glyph · host · ipv4 · via · rtt · traffic
                    let online = net.peers.iter().filter(|p| p.connection.is_some()).count();
                    let mut rows: Vec<Vec<layout::Cell>> = Vec::new();
                    for peer in &net.peers {
                        let host = peer
                            .hostname
                            .as_ref()
                            .map(|h| format!("{h}.{}.{}", net.name, DNS_DOMAIN))
                            .unwrap_or_else(|| peer.ip.to_string());
                        match &peer.connection {
                            Some(ci) => {
                                let via = match ci.conn_type {
                                    ipc::ConnType::Direct => "direct",
                                    ipc::ConnType::Relay => "relay",
                                    ipc::ConnType::Tor => "tor",
                                    ipc::ConnType::Unknown => "?",
                                };
                                let (rtt_plain, rtt_styled) = match ci.rtt_ms {
                                    Some(ms) => (format!("{ms:.0}ms"), style::latency(ms)),
                                    None => ("—".into(), style::faint("—")),
                                };
                                let traffic_plain = format!(
                                    "↑ {}  ↓ {}",
                                    format_bytes(ci.bytes_tx),
                                    format_bytes(ci.bytes_rx)
                                );
                                rows.push(vec![
                                    layout::Cell::new("●", style::dot_online()),
                                    layout::Cell::new(host.clone(), style::value(&host)),
                                    layout::Cell::new(
                                        peer.ip.to_string(),
                                        style::faint(&peer.ip.to_string()),
                                    ),
                                    layout::Cell::new(via, style::faint(via)),
                                    layout::Cell::right(rtt_plain, rtt_styled),
                                    layout::Cell::new(
                                        traffic_plain.clone(),
                                        style::faint(&traffic_plain),
                                    ),
                                ]);
                            }
                            None => {
                                rows.push(vec![
                                    layout::Cell::new("○", style::dot_offline()),
                                    layout::Cell::new(host.clone(), style::faint(&host)),
                                    layout::Cell::new(
                                        peer.ip.to_string(),
                                        style::faint(&peer.ip.to_string()),
                                    ),
                                    layout::Cell::new("—", style::faint("—")),
                                    layout::Cell::right("offline", style::faint("offline")),
                                    layout::Cell::plain(""),
                                ]);
                            }
                        }
                    }
                    if rows.is_empty() {
                        println!("    {}", style::faint("(no other members)"));
                    } else {
                        print!("{}", indent(&layout::columns(&rows, 3), 4));
                    }

                    // join code + members (self excluded from the count). Direct
                    // (`ray connect`) networks have no shareable room id, so the
                    // join code is suppressed for them.
                    print!("    ");
                    if let Some(ref key) = net.network_key
                        && !net.role.is_direct()
                    {
                        print!("{} {}    ", style::label("join"), style::rose(key));
                    }
                    println!(
                        "{} {}",
                        style::label("members"),
                        style::value(&format!("{online}/{}", net.peers.len())),
                    );
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
                        "  {}  {}",
                        style::faint(&net.name),
                        style::marker("inactive")
                    );
                }
            }
            println!();
        }
        ipc::IpcMessage::Error { message } => print_error("status failed", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        expires: None,
        hostname: None,
        reusable: false,
    });
    let hostname_opt = match &action {
        InviteAction::Create { hostname, .. } => hostname.clone(),
        _ => None,
    };
    let reusable_requested = matches!(&action, InviteAction::Create { reusable: true, .. });
    let req = match action {
        InviteAction::Create {
            expires,
            hostname,
            reusable,
        } => {
            // Reusable keys default to a longer 30d TTL; single-use to 7d.
            let ttl = expires.unwrap_or_else(|| {
                if reusable {
                    "30d".to_string()
                } else {
                    "7d".to_string()
                }
            });
            ipc::IpcMessage::InviteCreate {
                network: network.to_string(),
                expires_secs: parse_duration_secs(&ttl)?,
                hostname,
                reusable,
            }
        }
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
            println!(
                "  {} {} {}",
                style::check(),
                style::value("invite"),
                style::faint(&id)
            );
            println!();
            println!("  {}", style::bold(&code));
            println!();
            qr2term::print_qr(&code).ok();
            print_next(&[(&format!("ray join {code}"), "the holder runs this to join")]);
            println!();
            let days = expires_secs / 86400;
            let hours = (expires_secs % 86400) / 3600;
            let ttl = if days > 0 {
                format!("{days}d")
            } else if hours > 0 {
                format!("{hours}h")
            } else {
                format!("{}m", expires_secs / 60)
            };
            if reusable_requested {
                println!("  reusable (multi-use), expires in {ttl}");
                println!(
                    "  servers join unattended with: {}",
                    style::faint(&format!(
                        "ray join {code} --hostname <h> --auto-accept-firewall"
                    ))
                );
            } else {
                println!("  single-use, expires in {ttl}");
            }
            if let Some(h) = &hostname_opt {
                println!("  binds hostname: {}", style::bold(h));
            }
        }
        ipc::IpcMessage::InviteListResponse { invites } => {
            if json_enabled() {
                print_json(&serde_json::json!(
                    invites
                        .iter()
                        .map(|i| serde_json::json!({
                            "id": i.id, "status": i.status, "redeemer": i.redeemer,
                            "hostname": i.hostname, "reusable": i.reusable,
                            "created": i.created, "expires": i.expires,
                        }))
                        .collect::<Vec<_>>()
                ));
            } else if invites.is_empty() {
                println!("\n  {}\n", style::faint("no invites"));
            } else {
                let rows = invites
                    .iter()
                    .map(|inv| {
                        let kind = if inv.reusable {
                            "reusable"
                        } else {
                            "single-use"
                        };
                        let host = inv.hostname.clone().unwrap_or_else(|| "—".to_string());
                        let who = inv.redeemer.clone().unwrap_or_else(|| "—".to_string());
                        vec![
                            layout::Cell::new(inv.id.clone(), style::rose(&inv.id)),
                            layout::Cell::new(inv.status.clone(), style::value(&inv.status)),
                            layout::Cell::new(kind, style::faint(kind)),
                            layout::Cell::new(host.clone(), style::faint(&host)),
                            layout::Cell::new(who.clone(), style::faint(&who)),
                        ]
                    })
                    .collect();
                println!();
                print!(
                    "{}",
                    table(&["id", "status", "kind", "host", "redeemer"], rows, 2)
                );
                println!();
            }
        }
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
            if json_enabled() {
                print_json(&serde_json::json!(requests
                    .iter()
                    .map(|r| serde_json::json!({
                        "id": r.short_id, "hostname": r.hostname, "waiting_secs": r.waiting_secs,
                    }))
                    .collect::<Vec<_>>()));
            } else if requests.is_empty() {
                println!("\n  {}\n", style::faint("no pending join requests"));
            } else {
                let rows = requests
                    .iter()
                    .map(|r| {
                        let host = r.hostname.clone().unwrap_or_else(|| "—".to_string());
                        let wait = format!("{}s", r.waiting_secs);
                        vec![
                            layout::Cell::new(r.short_id.clone(), style::rose(&r.short_id)),
                            layout::Cell::new(host.clone(), style::value(&host)),
                            layout::Cell::right(wait.clone(), style::faint(&wait)),
                        ]
                    })
                    .collect();
                println!();
                print!("{}", table(&["id", "host", "waiting"], rows, 2));
                println!(
                    "\n  {}",
                    style::faint(&format!("admit with: ray accept {network} <id>"))
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_connect(contact_id: &str, hostname: Option<String>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Connect {
            contact_id: contact_id.to_string(),
            hostname,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Joined { name, my_ip, .. } => {
            println!(
                "  {} connected — direct network {} ({})",
                style::green("✓"),
                style::value(&name),
                style::faint(&my_ip.to_string()),
            );
        }
        ipc::IpcMessage::Error { message } => print_error("connect failed", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_connections(action: Option<ConnectionsAction>) -> Result<()> {
    match action.unwrap_or(ConnectionsAction::List) {
        ConnectionsAction::List => ipc_connections_list().await,
        ConnectionsAction::Approve { id } => ipc_connections_approve(&id).await,
    }
}

async fn ipc_connections_list() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Connections).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PendingRequests { requests } => {
            if json_enabled() {
                print_json(&serde_json::json!(requests
                    .iter()
                    .map(|r| serde_json::json!({
                        "id": r.short_id, "hostname": r.hostname, "waiting_secs": r.waiting_secs,
                    }))
                    .collect::<Vec<_>>()));
            } else if requests.is_empty() {
                println!("\n  {}\n", style::faint("no pending connection requests"));
            } else {
                let rows = requests
                    .iter()
                    .map(|r| {
                        let host = r.hostname.clone().unwrap_or_else(|| "—".to_string());
                        let wait = format!("{}s", r.waiting_secs);
                        vec![
                            layout::Cell::new(r.short_id.clone(), style::rose(&r.short_id)),
                            layout::Cell::new(host.clone(), style::value(&host)),
                            layout::Cell::right(wait.clone(), style::faint(&wait)),
                        ]
                    })
                    .collect();
                println!();
                print!("{}", table(&["id", "host", "waiting"], rows, 2));
                println!(
                    "\n  {}",
                    style::faint("approve with: ray connections approve <id>")
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_connections_approve(id: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::ApproveConnection { id: id.to_string() },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_contact(action: Option<ContactAction>) -> Result<()> {
    let req = match action.unwrap_or(ContactAction::Id) {
        ContactAction::Id => ipc::IpcMessage::ContactId,
        ContactAction::Rotate => ipc::IpcMessage::RotateContact,
    };
    let rotating = matches!(req, ipc::IpcMessage::RotateContact);
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::ContactIdResponse { contact_id } => {
            if json_enabled() {
                print_json(&serde_json::json!({ "contact_id": contact_id }));
            } else {
                if rotating {
                    println!("  {} contact id rotated", style::green("✓"));
                }
                println!("{}", contact_id);
                println!(
                    "  {}",
                    style::faint("share this so others can: ray connect <contact-id>")
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn ipc_admin(network: &str, action: AdminAction) -> Result<()> {
    let req = match action {
        AdminAction::Add { identity } => ipc::IpcMessage::AdminAdd {
            network: network.to_string(),
            identity,
        },
        AdminAction::List => ipc::IpcMessage::AdminList {
            network: network.to_string(),
        },
    };
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::AdminListResponse { admins } => {
            if json_enabled() {
                print_json(&serde_json::json!(
                    admins
                        .iter()
                        .map(|a| serde_json::json!({ "id": a.short_id, "self": a.self_node }))
                        .collect::<Vec<_>>()
                ));
            } else if admins.is_empty() {
                println!("\n  {}\n", style::faint("no admins recorded"));
            } else {
                println!();
                let mut rows = Vec::new();
                for a in &admins {
                    let (glyph, tag) = if a.self_node {
                        (style::dot_online(), style::marker("this device"))
                    } else {
                        (style::dot_offline(), String::new())
                    };
                    rows.push(vec![
                        layout::Cell::new("●", glyph),
                        layout::Cell::new(a.short_id.clone(), style::value(&a.short_id)),
                        layout::Cell::new(if a.self_node { "this device" } else { "" }, tag),
                    ]);
                }
                print!("{}", indent(&layout::columns(&rows, 2), 2));
                println!();
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
    } = action
    {
        return ipc_firewall_suggest(&network, &subject, allow, deny).await;
    }
    if let FirewallAction::Pending { network } = action {
        return ipc_firewall_pending(&network).await;
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
            direction: direction.parse().map_err(anyhow::Error::msg)?,
            action: action.parse().map_err(anyhow::Error::msg)?,
            protocol: proto.parse().map_err(anyhow::Error::msg)?,
            port,
            peer,
            network,
        },
        FirewallAction::Remove { index } => ipc::IpcMessage::FirewallRemove { index },
        FirewallAction::Show => ipc::IpcMessage::FirewallShow,
        FirewallAction::Default { action } => ipc::IpcMessage::FirewallDefault {
            action: action.parse().map_err(anyhow::Error::msg)?,
        },
        FirewallAction::Accept { network } => ipc::IpcMessage::FirewallAccept { network },
        FirewallAction::Deny { network } => ipc::IpcMessage::FirewallDeny { network },
        FirewallAction::AutoAccept { network, state } => {
            let enabled = match state.to_ascii_lowercase().as_str() {
                "on" | "true" | "yes" => true,
                "off" | "false" | "no" => false,
                other => anyhow::bail!("expected `on` or `off`, got '{other}'"),
            };
            ipc::IpcMessage::FirewallAutoAccept { network, enabled }
        }
        // Handled above by early return (need extra round trips / interaction).
        FirewallAction::Suggest { .. } | FirewallAction::Pending { .. } => unreachable!(),
    };
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::FirewallState { default, rules } => {
            if json_enabled() {
                print_json(&serde_json::json!({ "default": default, "rules": rules }));
            } else {
                print!("{}", render_firewall_rules(Some(default), &rules));
            }
        }
        ipc::IpcMessage::Error { message } => print_error("firewall", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Print a JSON value as one compact line to stdout (jq-friendly).
fn print_json(value: &serde_json::Value) {
    println!("{value}");
}

/// Render a firewall rule table as aligned columns. `default` is the catch-all
/// action shown as a header (omitted for the pending-suggestions list).
fn render_firewall_rules(
    default: Option<firewall::Action>,
    rules: &[ipc::FirewallRuleView],
) -> String {
    let mut out = String::from("\n");
    if let Some(d) = default {
        let s = d.to_string();
        let styled = if d.is_deny() {
            style::red(&s)
        } else {
            style::green(&s)
        };
        out.push_str(&format!("  {}  {}\n\n", style::label("default"), styled));
    }
    if rules.is_empty() {
        out.push_str(&format!("  {}\n", style::faint("(no rules)")));
        return out;
    }
    let rows = rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let direction = r.direction.to_string();
            let protocol = r.protocol.to_string();
            let action_s = r.action.to_string();
            let action = if r.action.is_deny() {
                style::red(&action_s)
            } else {
                style::green(&action_s)
            };
            let sugg = r
                .suggested_by
                .as_ref()
                .map(|s| style::marker(&format!("suggested by {s}")))
                .unwrap_or_default();
            let sugg_plain = r
                .suggested_by
                .as_ref()
                .map(|s| format!("·suggested by {s}·"))
                .unwrap_or_default();
            vec![
                layout::Cell::new(i.to_string(), style::faint(&i.to_string())),
                layout::Cell::new(direction.clone(), style::value(&direction)),
                layout::Cell::new(action_s.clone(), action),
                layout::Cell::new(protocol.clone(), style::value(&protocol)),
                layout::Cell::right(r.port.clone(), style::value(&r.port)),
                layout::Cell::new(r.peer.clone(), style::value(&r.peer)),
                layout::Cell::new(r.network.clone(), style::faint(&r.network)),
                layout::Cell::new(sugg_plain, sugg),
            ]
        })
        .collect();
    out.push_str(&table(
        &["#", "dir", "action", "proto", "port", "peer", "network", ""],
        rows,
        4,
    ));
    out.push('\n');
    out
}

/// `ray firewall pending`: fetch the queued suggestions, then either run the
/// interactive picker (TTY) or print a static table (piped / `--json`).
async fn ipc_firewall_pending(network: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallPending {
            network: network.to_string(),
        },
    )
    .await?;
    let rules = match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::FirewallPendingResponse { rules, .. } => rules,
        ipc::IpcMessage::Error { message } => {
            print_error("firewall pending", &message, None);
            return Ok(());
        }
        other => {
            eprintln!("Unexpected response: {other:?}");
            return Ok(());
        }
    };

    if json_enabled() {
        print_json(&serde_json::json!({ "network": network, "rules": rules }));
        return Ok(());
    }
    if rules.is_empty() {
        println!("\n  {}\n", style::faint("no pending suggested rules"));
        return Ok(());
    }
    // Non-interactive (piped / NO_COLOR): print the static table and stop.
    if !style::is_enabled() {
        print!("{}", render_firewall_rules(None, &rules));
        return Ok(());
    }

    // Interactive picker → resolve the user's per-rule decisions.
    let Some(resolution) = picker::run(network, &rules)? else {
        // Ctrl-C: leave the queue untouched.
        return Ok(());
    };
    if resolution.accept.is_empty() && resolution.deny.is_empty() {
        println!("  {}", style::faint("no changes"));
        return Ok(());
    }
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallResolveSuggestions {
            network: network.to_string(),
            accept: resolution.accept,
            deny: resolution.deny,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => {
            println!("  {} {}", style::check(), style::value(&message));
        }
        ipc::IpcMessage::Error { message } => print_error("firewall pending", &message, None),
        other => eprintln!("Unexpected response: {other:?}"),
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
            print_error("error", &message, None);
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
            .with_context(|| format!("{flag} expects PEER:SPEC, got '{spec}'"))?;
        anyhow::ensure!(
            !peer.is_empty() && !ports.is_empty(),
            "{flag} expects PEER:SPEC, got '{spec}'"
        );
        Ok((peer.to_string(), ports.to_string()))
    };

    let entry = suggestions.entry(subject.to_string()).or_default();
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {other:?}"),
    }
    Ok(())
}

/// `ray apply <spec>`: reconcile trusted networks against a deploy spec.
///
/// B2 — orchestrator: for each network in the spec, `Create { trusted }` if it
/// isn't active, then publish the spec's `firewall` block as suggestions
/// (idempotent — always replaces the live set). `--prune` limits the published
/// set to subjects present in the spec, dropping any live suggestions for
/// hosts no longer mentioned. Never joins.
///
/// B3 — membership diff: expected hosts = union of hostnames in the spec's
/// `firewall:` blocks; joined hosts = hostnames from `Status` (this node +
/// peers). Reports the gap and prints hostname-bound invite commands; with
/// `--invite-missing` mints them via IPC.
async fn ipc_apply(
    spec_path: Option<String>,
    prune: bool,
    dry_run: bool,
    invite_missing: bool,
    example: bool,
) -> Result<()> {
    if example {
        print!("{}", apply::EXAMPLE_SPEC);
        return Ok(());
    }
    let Some(spec_path) = spec_path else {
        anyhow::bail!("a spec file path is required (or use --example to print a template)");
    };
    let spec = apply::load(std::path::Path::new(&spec_path))?;
    if spec.networks.is_empty() {
        anyhow::bail!("spec contains no networks");
    }
    if dry_run {
        println!("{}", style::bold("Spec (normalized):"));
        print!("{}", apply::to_yaml(&spec)?);
        println!("{}", style::faint("(dry-run; no changes applied)"));
        return Ok(());
    }

    // Fetch live state once: status gives active networks + joined hostnames.
    let status_networks = ipc_status_networks().await?;
    let active_names: std::collections::HashSet<&str> =
        status_networks.iter().map(|n| n.name.as_str()).collect();

    let mut missing_hosts: Vec<(String, String)> = Vec::new(); // (network, hostname)

    for (net_name, net_firewall) in &spec.networks {
        let is_active = active_names.contains(net_name.as_str());
        // Create-if-absent (always a closed network).
        if !is_active {
            println!(
                "{} {}: creating closed network",
                style::label("apply"),
                style::bold(net_name),
            );
            if let Err(e) = ipc_apply_create(net_name).await {
                eprintln!("{}  create failed: {e}", style::red("  !"));
                continue;
            }
        } else {
            println!(
                "{} {}: already active",
                style::label("apply"),
                style::bold(net_name)
            );
        }

        // Publish suggestions (idempotent). With --prune, publish exactly the
        // spec's set; without it, merge into the live set (so `apply` never
        // silently drops subjects authored out-of-band — use --prune for that).
        let to_publish = if prune {
            net_firewall.clone()
        } else {
            let mut live = ipc_firewall_suggestions_get(net_name)
                .await
                .unwrap_or_default();
            // Merge spec subjects over live (spec wins on conflict).
            for (subj, rules) in net_firewall {
                live.insert(subj.clone(), rules.clone());
            }
            live
        };
        match ipc_firewall_suggest_set(net_name, to_publish).await {
            Ok(msg) => println!("{}   {msg}", style::faint("→")),
            Err(e) => eprintln!("{}   suggest failed: {e}", style::red("  !")),
        }

        // B3 — membership diff for this network.
        let joined = joined_hostnames(&status_networks, net_name);
        for host in apply::expected_hosts(&spec) {
            if !joined.iter().any(|j| j == &host) {
                missing_hosts.push((net_name.clone(), host));
            }
        }
    }

    // B3 — report the membership gap.
    if missing_hosts.is_empty() {
        println!("{}", style::green("All expected hosts have joined."));
    } else {
        println!(
            "\n{} Missing hosts (spec expects them):",
            style::label("diff")
        );
        for (net, host) in &missing_hosts {
            let cmd = format!("ray invite {net} --hostname {host}");
            if invite_missing {
                match ipc_invite_mint(net, Some(host.clone())).await {
                    Ok(code) => println!(
                        "  {}  {}  {}",
                        style::bold(host),
                        cmd,
                        style::faint(&format!("→ {code}"))
                    ),
                    Err(e) => eprintln!(
                        "  {}  {cmd}  {}",
                        style::red(host),
                        style::red(&e.to_string())
                    ),
                }
            } else {
                println!("  {}  {cmd}", style::bold(host));
            }
        }
        if !invite_missing {
            println!(
                "\n{} re-run with --invite-missing to mint these invites.",
                style::faint("tip:")
            );
        }
    }
    Ok(())
}

/// Joined hostnames on `network` (this node's hostname + every peer's hostname).
fn joined_hostnames(networks: &[ipc::NetworkStatus], network: &str) -> Vec<String> {
    let Some(net) = networks.iter().find(|n| n.name == network) else {
        return Vec::new();
    };
    let mut hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Some(h) = &net.my_hostname {
        hosts.insert(h.clone());
    }
    for p in &net.peers {
        if let Some(h) = &p.hostname {
            hosts.insert(h.clone());
        }
    }
    hosts.into_iter().collect()
}

async fn ipc_status_networks() -> Result<Vec<ipc::NetworkStatus>> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Status).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::StatusResponse { networks, .. } => Ok(networks),
        other => anyhow::bail!("unexpected status response: {other:?}"),
    }
}

async fn ipc_apply_create(name: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Create {
            mode: ray_proto::GroupMode::Restricted,
            name: Some(name.to_string()),
            hostname: None,
            transport: None,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Created { name: n, .. } => {
            println!("{}   created '{n}'", style::faint("→"));
            Ok(())
        }
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected create response: {other:?}"),
    }
}

async fn ipc_firewall_suggestions_get(network: &str) -> Result<ray_proto::SuggestedFirewall> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallSuggestions {
            network: network.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::FirewallSuggestionsResponse { suggestions } => Ok(suggestions),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected suggestions response: {other:?}"),
    }
}

async fn ipc_firewall_suggest_set(
    network: &str,
    suggestions: ray_proto::SuggestedFirewall,
) -> Result<String> {
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
        ipc::IpcMessage::Ok { message } => Ok(message),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected suggest response: {other:?}"),
    }
}

async fn ipc_invite_mint(network: &str, hostname: Option<String>) -> Result<String> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::InviteCreate {
            network: network.to_string(),
            expires_secs: 7 * 24 * 3600,
            hostname,
            reusable: false,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::InviteCreated { code, .. } => Ok(code),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected invite response: {other:?}"),
    }
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
                    if json_enabled() {
                        let arr: Vec<_> = files
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "id": f.id, "from": f.from, "filename": f.filename,
                                    "size": f.size, "mime_type": f.mime_type,
                                })
                            })
                            .collect();
                        print_json(&serde_json::json!(arr));
                    } else if files.is_empty() {
                        println!("\n  {}\n", style::faint("no pending file transfers"));
                    } else {
                        let rows = files
                            .iter()
                            .map(|f| {
                                let accept = format!("ray files accept {}", f.id);
                                vec![
                                    layout::Cell::new(
                                        f.id.to_string(),
                                        style::rose(&f.id.to_string()),
                                    ),
                                    layout::Cell::new(f.from.clone(), style::value(&f.from)),
                                    layout::Cell::right(
                                        format_size(f.size),
                                        style::faint(&format_size(f.size)),
                                    ),
                                    layout::Cell::new(
                                        f.filename.clone(),
                                        style::value(&f.filename),
                                    ),
                                    layout::Cell::new(accept.clone(), style::faint(&accept)),
                                ]
                            })
                            .collect();
                        println!();
                        print!("{}", table(&["id", "from", "size", "file", ""], rows, 2));
                        println!();
                    }
                }
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
            // The blob is fetched daemon-side without progress events, so show an
            // indeterminate spinner rather than a determinate bar.
            let spinner = progress::spinner("downloading…");
            let resp = ipc::recv(&mut stream).await?;
            spinner.finish_and_clear();
            match resp {
                ipc::IpcMessage::Ok { message } => {
                    println!("  {} {}", style::check(), style::value(&message));
                }
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        (
            Some(PairAction::Backup {
                onepassword,
                vault,
                item,
            }),
            _,
        ) => cmd_pair_backup(onepassword, vault.as_deref(), &item),
        // `rayfish pair restore <backup>`
        (
            Some(PairAction::Restore {
                backup,
                onepassword,
                vault,
                item,
            }),
            _,
        ) => cmd_pair_restore(backup.as_deref(), onepassword, vault.as_deref(), &item),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Produce the encrypted `enc1…` backup blob for the local identity, prompting
/// for (and confirming) a backup password. Returns the blob and the identity's
/// public key string.
fn make_backup_blob() -> Result<(String, String)> {
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
    Ok((backup, key.public().to_string()))
}

fn cmd_pair_backup(onepassword: bool, vault: Option<&str>, item: &str) -> Result<()> {
    // Fail fast if `op` is missing before prompting for a password.
    if onepassword {
        onepassword::op_available()?;
    }

    let (backup, public_key) = make_backup_blob()?;

    if onepassword {
        onepassword::store(vault, item, &backup, &public_key)?;
        println!("Stored encrypted backup in 1Password item \"{}\".", item);
        println!();
        println!("To restore on a new device:");
        println!("  rayfish pair restore --1password");
        return Ok(());
    }

    println!("Backup code: {}", backup);
    println!();
    println!("Store this safely. To restore on a new device:");
    println!("  rayfish pair restore {}", backup);
    Ok(())
}

fn cmd_pair_restore(
    backup: Option<&str>,
    onepassword: bool,
    vault: Option<&str>,
    item: &str,
) -> Result<()> {
    use argon2::Argon2;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

    let backup = if onepassword {
        if backup.is_some() {
            anyhow::bail!("provide either a backup code or --1password, not both");
        }
        onepassword::op_available()?;
        onepassword::read(vault, item)?
    } else {
        backup
            .map(|b| b.to_string())
            .context("provide a backup code, or use --1password to read it from 1Password")?
    };

    let backup_bytes = bs58::decode(&backup)
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
async fn cmd_up(hostname: Option<String>) -> Result<()> {
    if let Ok(mut stream) = ipc::connect().await {
        ipc::send(&mut stream, ipc::IpcMessage::Up { hostname }).await?;
        match ipc::recv(&mut stream).await? {
            ipc::IpcMessage::Ok { message } => println!("{message}"),
            ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
    install_and_start_service(hostname).await
}

/// Install/refresh the system service and (re)start it. Requires root.
///
/// Starting the service is fire-and-forget at the OS level, so we then wait for
/// the daemon to actually accept an IPC connection before declaring success. If
/// it never comes up (e.g. it crashed on a port/route conflict with another
/// VPN), we surface the tail of its log so the user knows what went wrong
/// instead of seeing a cheerful "started" followed by a dead `ray status`.
async fn install_and_start_service(hostname: Option<String>) -> Result<()> {
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
    let spinner = progress::spinner("starting service…");
    let daemon = wait_for_daemon(std::time::Duration::from_secs(8)).await;
    spinner.finish_and_clear();
    match daemon {
        Some(mut stream) => {
            ipc::send(&mut stream, ipc::IpcMessage::Up { hostname }).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => println!("rayfish service started. {message}"),
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
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
    install_and_start_service(None).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::FirewallRuleView;

    fn view(
        dir: &str,
        action: &str,
        proto: &str,
        port: &str,
        peer: &str,
        net: &str,
        sugg: Option<&str>,
    ) -> FirewallRuleView {
        FirewallRuleView {
            direction: dir.parse().unwrap(),
            action: action.parse().unwrap(),
            protocol: proto.parse().unwrap(),
            port: port.into(),
            peer: peer.into(),
            network: net.into(),
            suggested_by: sugg.map(str::to_string),
        }
    }

    #[test]
    fn firewall_table_aligns_without_color() {
        style::set_plain(true);
        let rules = vec![
            view("in", "allow", "tcp", "443", "any", "any", None),
            view(
                "out",
                "deny",
                "udp",
                "53",
                "abc1",
                "homelab",
                Some("homelab"),
            ),
        ];
        let out = render_firewall_rules(Some(firewall::Action::Allow), &rules);
        assert!(out.contains("default  allow"));
        // Header present, columns aligned: the "action" column header and the
        // two action values start at the same offset on their lines.
        let lines: Vec<&str> = out
            .lines()
            .filter(|l| l.contains("allow") || l.contains("deny"))
            .collect();
        assert!(out.contains("·suggested by homelab·"));
        // No ANSI escapes in plain mode.
        assert!(!out.contains('\u{1b}'));
        assert!(lines.iter().any(|l| l.contains("443")));
    }

    #[test]
    fn empty_firewall_says_no_rules() {
        style::set_plain(true);
        let out = render_firewall_rules(Some(firewall::Action::Deny), &[]);
        assert!(out.contains("default  deny"));
        assert!(out.contains("(no rules)"));
    }
}
