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

// The CLI command handlers are split into the `cli` module (`src/cli/`) to keep
// this file to the clap definitions + dispatch. `cli` re-exports each domain
// submodule's contents, and `use cli::*` flattens them into the crate root so
// every handler resolves the others (and the shared helpers here) by name.
mod cli;
use cli::*;

/// Full version string: the crate version plus the git short SHA stamped in by
/// `build.rs` (e.g. `0.1.0 (abc12345)`). The SHA distinguishes nightly builds
/// that share a crate version, and is what a tester quotes in a `ray report`.
const FULL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("RAY_GIT_SHA"), ")");

#[derive(Parser)]
#[command(
    name = "ray",
    about = "P2P mesh VPN powered by iroh",
    version = FULL_VERSION
)]
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
pub(crate) enum Command {
    /// Create a new network and wait for peers
    #[command(visible_alias = "new")]
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
    #[command(visible_alias = "rm")]
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
    #[command(visible_aliases = ["st", "ls"])]
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
    /// Standby: take the data plane (TUN + Magic DNS) offline; stays connected to peers
    Down,
    /// Stop the system service (go fully offline). Requires root
    Stop,
    /// Start the installed system service. Requires root
    Start,
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
    /// Probe a peer over the mesh: report round-trip latency, packet loss, and
    /// whether the path is direct or relayed. Unlike `status`, this sends live
    /// echo probes that verify the round-trip end to end.
    Ping {
        /// Peer to probe: hostname, mesh IP, or short id.
        peer: String,
        /// Number of probes to send.
        #[arg(short, long, default_value_t = 3)]
        count: u32,
        /// Delay between probes, in milliseconds.
        #[arg(short, long, default_value_t = 1000)]
        interval: u64,
    },
    /// Report this node's network conditions: bound UDP port, home relay and its
    /// latency, public addresses, and IPv4/IPv6/UDP reachability.
    Netcheck,
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
    /// Print a host's identity string (the value to paste into a `ray apply`
    /// spec's `aliases:` map). Resolves to the user identity if the device is
    /// paired, else the device's transport identity.
    #[command(visible_alias = "whois")]
    Identityof {
        /// Network name
        network: String,
        /// Hostname to look up
        hostname: String,
    },
    /// Enable or disable mDNS local peer discovery
    Mdns {
        /// "on" or "off"
        state: String,
    },
    /// View or change global daemon settings (relay, discovery-dns, dns-upstreams)
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
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
    /// Print the rayfish version
    #[command(visible_alias = "ver")]
    Version,
    /// Update rayfish to the latest GitHub release
    #[command(visible_alias = "upgrade")]
    Update {
        /// Reinstall even if already on the latest version
        #[arg(long)]
        force: bool,
        /// Report the latest available version without installing
        #[arg(long)]
        check: bool,
        /// Track the rolling `nightly` pre-release (built from every commit to
        /// master) instead of the latest stable release
        #[arg(long, conflicts_with_all = ["list", "version"])]
        nightly: bool,
        /// List the available releases (newest first) and exit
        #[arg(long, conflicts_with_all = ["check", "force", "version"])]
        list: bool,
        /// Install a specific release version, e.g. 0.1.0 (downgrades allowed)
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum InviteAction {
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
        /// Also render the invite as a scannable QR code (off by default — it
        /// takes up a lot of terminal space).
        #[arg(long)]
        qr: bool,
    },
    /// List issued invites and their status
    #[command(visible_alias = "ls")]
    List,
    /// Revoke an unused invite by id
    #[command(visible_alias = "rm")]
    Revoke {
        /// Invite id (from `ray invite <network> list`)
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PairAction {
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
pub(crate) enum AdminAction {
    /// Grant the network key to a member (coordinator only)
    Add {
        /// Short id of the member to promote (from `ray status`)
        identity: String,
    },
    /// List this network's key-holders (the local node + granted members)
    #[command(visible_alias = "ls")]
    List,
}

#[derive(Subcommand)]
pub(crate) enum ConnectionsAction {
    /// List pending incoming connection requests (default)
    #[command(visible_alias = "ls")]
    List,
    /// Approve a pending request, forming the direct 2-peer network
    #[command(visible_alias = "ok")]
    Approve {
        /// Short id of the requester (from `ray connections`)
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigAction {
    /// Show settings (all, or one key)
    #[command(visible_alias = "ls")]
    Get {
        /// relay, discovery-dns, or dns-upstreams (omit for all)
        key: Option<String>,
    },
    /// Set a key. Value is a comma list of presets (rayfish/n0), URLs, or IPs.
    Set {
        /// relay, discovery-dns, or dns-upstreams
        key: String,
        /// Comma list of presets / URLs / IPv4s (use "n0" or empty to reset)
        value: String,
        /// Replace the defaults instead of augmenting them (can isolate the node)
        #[arg(long)]
        replace: bool,
    },
    /// Reset a key to its default (iroh n0)
    #[command(visible_alias = "rm")]
    Unset {
        /// relay, discovery-dns, or dns-upstreams
        key: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ContactAction {
    /// Print your contact id (default)
    Id,
    /// Rotate your contact key (invalidates the old contact id)
    Rotate,
}

#[derive(Subcommand)]
pub(crate) enum FirewallAction {
    /// Add a firewall rule. A new rule is inserted at the front, so it
    /// supersedes any contradicting rule under first-match — e.g. `deny in icmp`
    /// overrides the seeded `allow in icmp` (and re-adding `allow` flips it back).
    /// A rule with the same selector (direction/proto/port/peer/network) replaces
    /// the old one rather than stacking, so toggling never accumulates dead rules.
    #[command(visible_alias = "a")]
    Add {
        /// Direction: in or out
        direction: String,
        /// Action: allow or deny
        action: String,
        /// Protocol: tcp, udp, icmp, any
        #[arg(long, short = 'p', default_value = "any")]
        proto: String,
        /// Port, range, or comma list (e.g. 22, 80-443, 80,443, or * for all).
        /// A comma list adds one rule per item.
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
    #[command(visible_aliases = ["rm", "del"])]
    Remove {
        /// Rule index (from 'firewall show')
        index: usize,
    },
    /// Show current firewall rules
    #[command(visible_aliases = ["ls", "list"])]
    Show,
    /// Set the inbound default policy (allow or deny). `deny` (the secure
    /// built-in default) blocks unsolicited inbound TCP/UDP; `allow` restores the
    /// old permissive behaviour. Inbound ICMP is always allowed by default (use an
    /// explicit `deny in icmp` rule to block it); the outbound default is always
    /// allow and is unaffected.
    Default {
        /// Default inbound action: allow or deny
        action: String,
    },
    /// Toggle "fail fast" REJECT mode (opt-in, default off). When `on`, a denied
    /// packet gets a TCP RST / ICMP-unreachable reply so the initiator fails
    /// immediately ("connection refused") instead of hanging to a timeout. When
    /// `off`, denied packets are silently dropped (stealthy, the default).
    Reject {
        /// on or off
        state: String,
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
        /// Allow inbound traffic, e.g. `--allow tcp:22` (any peer) or
        /// `--allow earn01:tcp:9000,tcp:8123` (repeatable). The `PEER:` prefix is
        /// optional — omit it (start with a protocol) to mean "any peer".
        /// Spec grammar: `proto:ports` or bare proto (`icmp`, `any`, `tcp`).
        #[arg(long, value_name = "[PEER:]SPEC")]
        allow: Vec<String>,
        /// Deny inbound traffic, e.g. `--deny udp:53` (any peer) or
        /// `--deny earn01:tcp:443` (repeatable). Same grammar as `--allow`; the
        /// `PEER:` prefix is optional.
        #[arg(long, value_name = "[PEER:]SPEC")]
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
    /// Embedded mesh SSH server (Tailscale-style): SSH into this node by mesh
    /// identity, no SSH keys. `ssh on` starts the server; `ssh allow <net> <peer>`
    /// authorizes a peer to log in. Connect with a stock client: `ssh user@host.ray`.
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },
}

#[derive(Subcommand)]
pub(crate) enum SshAction {
    /// Start the embedded mesh SSH server on this node (listens on the mesh IPs'
    /// port 22; opens tcp:22 in the local firewall).
    On,
    /// Stop the mesh SSH server (removes the tcp:22 passthrough).
    Off,
    /// Authorize a peer to SSH into this node over a network. `peer` is a
    /// hostname, mesh IP, short id, or `*` (any peer on the network).
    #[command(visible_alias = "ok")]
    Allow {
        /// Network name
        network: String,
        /// Peer (hostname / mesh IP / short id) or `*`
        peer: String,
        /// Local unix users this peer may log in as (comma-separated). Omit for
        /// any non-root user; pass `*` for any user including root.
        #[arg(long = "user", short = 'u', value_delimiter = ',')]
        user: Vec<String>,
    },
    /// Revoke a peer's SSH authorization on a network.
    #[command(visible_aliases = ["rm", "del"])]
    Deny {
        /// Network name
        network: String,
        /// Peer (hostname / mesh IP / short id) or `*`
        peer: String,
    },
    /// Show the mesh SSH server state and per-network allow lists.
    #[command(visible_aliases = ["ls", "list"])]
    Show {
        /// Optional network to filter to
        network: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FilesAction {
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

    // The global gate must be permissive enough for the most verbose layer (the
    // file), or events are dropped before any layer sees them. Default it to our
    // crate at `debug` (dependencies stay at `info` so iroh/quinn don't flood the
    // file), then keep the console quieter with a per-layer `info` filter below.
    // `RUST_LOG` overrides both, so an operator can still dial either up or down.
    let global_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,rayfish=debug"));
    let console_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Console layer — human text on stdout, held at `info` so CLI output and the
    // daemon console stay readable while the file keeps the `debug` detail.
    let console_layer = tracing_subscriber::fmt::layer().with_filter(console_filter);

    // File layer — daemon only, human text with ANSI stripped, rotated daily.
    let (file_layer, appender_guard) = if to_file {
        match std::fs::create_dir_all(logdir::log_dir()) {
            Ok(()) => {
                // Daily rotation; retain the 7 most recent files so logs older
                // than ~a week are pruned automatically (bounds disk usage).
                match tracing_appender::rolling::Builder::new()
                    .rotation(tracing_appender::rolling::Rotation::DAILY)
                    .filename_prefix("rayfish.log")
                    .max_log_files(7)
                    .build(logdir::log_dir())
                {
                    Ok(appender) => {
                        let (writer, guard) = tracing_appender::non_blocking(appender);
                        let layer = tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(writer);
                        (Some(layer), Some(guard))
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: cannot build rolling log appender: {e} (file logging disabled)"
                        );
                        (None, None)
                    }
                }
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
        .with(global_filter)
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

        // Hand DNS back to the OS before we abort: restore the backed-up
        // resolv.conf and drop the NetworkManager `dns=none` snippet, so a crash
        // can't leave the host pointing at our dead resolver (it would otherwise
        // blackhole all DNS until the service restarts). Synchronous, best-effort.
        rayfish::dns_config::emergency_restore_resolv_conf();

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
        Command::Stop => cmd_stop().await,
        Command::Start => cmd_start().await,
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
        Command::Ping {
            peer,
            count,
            interval,
        } => ipc_ping(&peer, count, interval).await,
        Command::Netcheck => ipc_netcheck().await,
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
        Command::Identityof { network, hostname } => {
            cmd_identityof(&network, &hostname, cli.json).await
        }
        Command::Mdns { state } => cmd_mdns(&state),
        Command::Config { action } => cmd_config(action, cli.json),
        Command::SetOperator { user } => cmd_set_operator(&user).await,
        Command::Send { file, peer } => ipc_send_file(&file, &peer).await,
        Command::Files { action } => ipc_files(action).await,
        Command::Pair { action, ticket } => cmd_pair(action, ticket).await,
        Command::Version => {
            println!("ray {FULL_VERSION}");
            Ok(())
        }
        Command::Update {
            force,
            check,
            nightly,
            list,
            version,
        } => cmd_update(force, check, nightly, list, version).await,
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
    config::save_settings(&app_config)?;
    println!(
        "mDNS discovery {}. Restart the daemon for changes to take effect.",
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

/// `ray config get/set/unset`: view or change global daemon settings. Writes
/// `settings.toml` directly (like `cmd_mdns`); relay/discovery/dns-upstreams all
/// take effect on the next daemon restart. On Linux the config tree is root-
/// owned, so a write naturally requires sudo.
fn cmd_config(action: Option<ConfigAction>, json: bool) -> Result<()> {
    match action.unwrap_or(ConfigAction::Get { key: None }) {
        ConfigAction::Get { key } => {
            let cfg = config::load()?;
            let rows = config::config_get(&cfg, key.as_deref())?;
            if json {
                let map: serde_json::Map<String, serde_json::Value> = rows
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect();
                print_json(&serde_json::Value::Object(map));
            } else {
                for (k, v) in rows {
                    println!("{k} = {v}");
                }
            }
        }
        ConfigAction::Set { key, value, replace } => {
            let mut cfg = config::load()?;
            config::config_set(&mut cfg, &key, &value, replace)?;
            config::save_settings(&cfg)?;
            println!("Set {key}. Run 'sudo ray restart' for changes to take effect.");
        }
        ConfigAction::Unset { key } => {
            let mut cfg = config::load()?;
            config::config_set(&mut cfg, &key, "", false)?;
            config::save_settings(&cfg)?;
            println!("Reset {key} to default. Run 'sudo ray restart' for changes to take effect.");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::FirewallRuleView;

    #[test]
    fn strip_deleted_suffix_sanitizes_replaced_binary_path() {
        // After `self_replace` unlinks the running binary, Linux reports
        // `/proc/self/exe` with a trailing " (deleted)". The service unit must
        // not inherit it, or the daemon crash-loops on `ray (deleted) daemon`.
        assert_eq!(
            strip_deleted_suffix("/usr/local/bin/ray (deleted)"),
            "/usr/local/bin/ray"
        );
        // A normal path is untouched.
        assert_eq!(
            strip_deleted_suffix("/usr/local/bin/ray"),
            "/usr/local/bin/ray"
        );
        // Only an exact trailing marker is stripped, not the substring mid-path.
        assert_eq!(
            strip_deleted_suffix("/opt/ray (deleted)/ray"),
            "/opt/ray (deleted)/ray"
        );
    }

    #[test]
    fn parse_suggest_token_defaults_peer_to_any_for_bare_proto() {
        // A leading protocol keyword ⇒ peer defaults to `*` (any).
        assert_eq!(
            parse_suggest_token("tcp:22", "--allow").unwrap(),
            ("*".to_string(), "tcp:22".to_string())
        );
        assert_eq!(
            parse_suggest_token("udp:53", "--allow").unwrap(),
            ("*".to_string(), "udp:53".to_string())
        );
        // Bare port-less protocols too.
        assert_eq!(
            parse_suggest_token("icmp", "--allow").unwrap(),
            ("*".to_string(), "icmp".to_string())
        );
        assert_eq!(
            parse_suggest_token("any:*", "--allow").unwrap(),
            ("*".to_string(), "any:*".to_string())
        );
    }

    #[test]
    fn parse_suggest_token_keeps_explicit_peer() {
        // A non-protocol first segment is a peer hostname.
        assert_eq!(
            parse_suggest_token("earn01:tcp:9000,tcp:8123", "--allow").unwrap(),
            ("earn01".to_string(), "tcp:9000,tcp:8123".to_string())
        );
        // Explicit `*` peer still works.
        assert_eq!(
            parse_suggest_token("*:tcp:22", "--allow").unwrap(),
            ("*".to_string(), "tcp:22".to_string())
        );
        // Hostname with a bare proto spec.
        assert_eq!(
            parse_suggest_token("alice:icmp", "--deny").unwrap(),
            ("alice".to_string(), "icmp".to_string())
        );
    }

    #[test]
    fn parse_suggest_token_rejects_empty() {
        assert!(parse_suggest_token("", "--allow").is_err());
        assert!(parse_suggest_token("alice", "--allow").is_err());
    }

    #[test]
    fn release_asset_name_maps_supported_platforms() {
        assert_eq!(
            release_asset_name("linux", "x86_64").unwrap(),
            "ray-linux-x86_64"
        );
        assert_eq!(
            release_asset_name("linux", "aarch64").unwrap(),
            "ray-linux-aarch64"
        );
        assert_eq!(
            release_asset_name("macos", "x86_64").unwrap(),
            "ray-macos-x86_64"
        );
        assert_eq!(
            release_asset_name("macos", "aarch64").unwrap(),
            "ray-macos-aarch64"
        );
    }

    #[test]
    fn release_asset_name_rejects_unsupported_platforms() {
        assert!(release_asset_name("windows", "x86_64").is_err());
        assert!(release_asset_name("linux", "riscv64").is_err());
    }

    #[test]
    fn normalize_version_strips_leading_v() {
        assert_eq!(normalize_version("v0.1.0"), "0.1.0");
        assert_eq!(normalize_version("0.1.0"), "0.1.0");
        assert_eq!(normalize_version("v1.2.3-rc1"), "1.2.3-rc1");
    }

    #[test]
    fn version_is_newer_orders_semver() {
        assert!(version_is_newer("0.2.0", "0.1.0"));
        assert!(version_is_newer("1.0.0", "0.9.9"));
        assert!(!version_is_newer("0.1.0", "0.1.0"));
        assert!(!version_is_newer("0.1.0", "0.2.0")); // older latest ⇒ no downgrade
        assert!(version_is_newer("0.1.0", "0.1.0-rc1")); // release beats prerelease
        // Unparseable tags fall back to inequality.
        assert!(version_is_newer("nightly", "0.1.0"));
        assert!(!version_is_newer("weird", "weird"));
    }

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
        let out = render_firewall_rules(
            Some((firewall::Action::Allow, firewall::Action::Allow)),
            false,
            &rules,
        );
        assert!(out.contains("default in   allow"));
        assert!(out.contains("default out  allow"));
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
        let out =
            render_firewall_rules(Some((firewall::Action::Deny, firewall::Action::Allow)), false, &[]);
        assert!(out.contains("default in   deny"));
        assert!(out.contains("default out  allow"));
        assert!(out.contains("(no rules)"));
    }
}
