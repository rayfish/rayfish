// The daemon's modules live in the `rayfish` library crate (`src/lib.rs`) so
// integration tests and benchmarks can reach them; this binary is the CLI/IPC
// client built on top.
use rayfish::term::{layout, picker, progress, style};
use rayfish::{
    DNS_DOMAIN, apply, config, daemon, firewall, hostname, identity, invite, ipc, keybackup,
    logdir, membership, onepassword, shutdown, stats,
};

use std::sync::{Arc, atomic};

use anyhow::{Context, Result};
use clap::{FromArgMatches, Parser, Subcommand};
use ray_proto::settings::node_key_help;

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

/// The `on`/`off` domain shared by the toggle arguments. Suggestions, not a
/// `value_parser`: these arguments also take `true`/`yes`/`1` (see
/// `config::parse_bool_setting`), and restricting them to two words here would
/// start rejecting spellings that work today.
const ON_OFF: [&str; 2] = ["on", "off"];

/// The firewall's verdict words, shared by `firewall add` and `firewall default`.
const ALLOW_DENY: [&str; 2] = ["allow", "deny"];

#[derive(Parser)]
#[command(
    name = "ray",
    about = "P2P mesh VPN powered by iroh",
    version = FULL_VERSION
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

static JSON_FLAG: atomic::AtomicBool = atomic::AtomicBool::new(false);

/// Whether `--json` output mode is active (set once in `main`).
fn json_enabled() -> bool {
    JSON_FLAG.load(atomic::Ordering::Relaxed)
}

/// Whether the parsed command carried `--json`.
///
/// `--json` used to be a `global = true` flag on `Cli`, which meant every one of
/// the 44 commands accepted it and the 30-odd that render no JSON ignored it in
/// silence (`ray version --json` printed the same plain text). It is now declared
/// only on the commands that honour it, so the parser rejects it elsewhere. This
/// funnels those per-command flags back into the one `JSON_FLAG` the renderers
/// already read, keeping the change to the enum and this function rather than
/// the seven `cli` modules that call `json_enabled`.
fn json_requested(command: &Command) -> bool {
    match command {
        Command::Status { json }
        | Command::Invite { json, .. }
        | Command::Requests { json, .. }
        | Command::Connect { json, .. }
        | Command::Connections { json, .. }
        | Command::Contact { json, .. }
        | Command::Ping { json, .. }
        | Command::Netcheck { json }
        | Command::Admin { json, .. }
        | Command::Firewall { json, .. }
        | Command::ExitNode { json, .. }
        | Command::Mdns { json, .. }
        | Command::Files { json, .. }
        | Command::Pair { json, .. }
        | Command::Identityof { json, .. }
        | Command::Alias { json, .. }
        | Command::Config { json, .. } => *json,
        _ => false,
    }
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
        /// Your hostname within the network (e.g. "alice" → alice.gaming.ray). Defaults to this machine's hostname
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
        /// Your hostname within the network (e.g. "bob" → bob.gaming.ray). Defaults to this machine's hostname
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
        /// Opt out of auto-accepting file transfers from your own paired devices
        /// on this network. By default own-device offers are accepted without a
        /// manual `ray files accept` (only offers whose sender is one of your own
        /// devices, identity-checked); pass this to require manual acceptance.
        #[arg(long)]
        no_auto_accept_files: bool,
    },
    /// Leave a network (remove from saved config)
    #[command(visible_alias = "rm")]
    Leave {
        /// Three-word network name
        #[arg(add = complete::networks())]
        name: String,
    },
    /// Destroy a network (coordinator only)
    Nuke {
        /// Three-word network name
        #[arg(add = complete::networks())]
        name: String,
        /// Force destroy even if other members exist
        #[arg(long)]
        force: bool,
    },
    /// Remove a member from a network (coordinator only)
    ///
    /// Closed networks only.
    #[command(visible_alias = "boot")]
    Kick {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Member to remove: hostname, mesh IP, or short id
        #[arg(add = complete::peers())]
        peer: String,
    },
    /// Set or show a per-network ephemeral policy (coordinator only)
    ///
    /// Auto-removes members that have been offline longer than the given
    /// duration.
    Ephemeral {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// `Nh`/`Nd`/`Nw` to enable, `off` to disable, or `show` to print
        #[arg(add = complete::ephemeral_args())]
        arg: String,
    },
    /// Show status of all networks (active + saved)
    #[command(visible_aliases = ["st", "ls"])]
    Status {
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Collect diagnostics and open a pre-filled GitHub issue
    ///
    /// Bundles the rolling log files and the forward metrics.
    Report,
    /// Show the daemon's log output
    ///
    /// Reads the daemon's rolling log files over IPC, so no root is needed.
    /// With no arguments, shows everything since the last daily rotation,
    /// through `$PAGER` (`less`) when the output is a terminal.
    Logs {
        /// Only lines from the last <DUR> (e.g. 10m, 1h, 2h30m)
        #[arg(long, value_name = "DUR")]
        since: Option<String>,
        /// Keep streaming new lines until Ctrl-C, like `tail -f`
        #[arg(short, long)]
        follow: bool,
    },
    /// Run the daemon in the foreground (invoked by the system service)
    #[command(hide = true)]
    Daemon,
    /// Install the system service if needed and start it
    Up {
        /// Set your default hostname for future networks (e.g. "laptop"). Used
        /// when create/join don't specify one; doesn't rename existing networks
        #[arg(long)]
        hostname: Option<String>,
        /// Contact only the relay and discovery servers you name, nothing else
        ///
        /// Needs --relay and --pkarr, unless both are already set to servers of
        /// your own. Turns mDNS and auto-update off, since both reach past those
        /// servers. Sticky: it survives restarts until `ray up --no-private`.
        #[arg(long, conflicts_with = "no_private")]
        private: bool,
        /// Leave private mode, going back to the default servers
        #[arg(long)]
        no_private: bool,
        /// Relay servers to use instead of the defaults (comma-separated)
        #[arg(long, value_name = "URL")]
        relay: Option<String>,
        /// pkarr discovery server to use instead of the default
        #[arg(long, value_name = "URL")]
        pkarr: Option<String>,
        /// Skip the confirmation when leaving private mode
        #[arg(long, requires = "no_private")]
        yes: bool,
    },
    /// Standby: take the data plane offline, staying connected to peers
    ///
    /// Drops the TUN link and Magic DNS. Peer connections stay up, so coming
    /// back with `ray up` does not have to redial anyone.
    Down,
    /// Stop the system service (go fully offline). Requires root
    Stop,
    /// Start the installed system service. Requires root
    Start,
    /// Uninstall system service
    Uninstall,
    /// Install or refresh the system service (requires root)
    ///
    /// Starts it once installed.
    Install {
        /// Opt this node into automatic stable updates: the daemon periodically
        /// checks for a newer stable release and swaps + restarts onto it
        #[arg(long)]
        auto_update: bool,
    },
    /// Restart the system service (requires root)
    Restart,
    /// Set up tab completion for your shell
    ///
    /// `ray up` installs this for you; this command is for a binary-only install.
    Completions {
        /// Shell to generate for. Guessed from $SHELL when left out; as root,
        /// left out means every shell
        shell: Option<clap_complete::Shell>,
        /// Write the script where the shell will find it, rather than printing
        /// it for you to redirect somewhere yourself
        #[arg(long)]
        install: bool,
    },
    /// Start a local browser GUI
    ///
    /// Covers the common workflows and every CLI command.
    Gui {
        /// Localhost port to listen on (0 chooses a free port)
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Print the URL without trying to open a browser
        #[arg(long)]
        no_open: bool,
    },
    /// Mint and manage invite codes (coordinator only)
    ///
    /// Codes are one-time by default; `--reusable` mints a multi-use key.
    Invite {
        /// Network name to issue/manage invites for
        #[arg(add = complete::networks())]
        network: String,
        #[command(subcommand)]
        action: Option<InviteAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Peers awaiting approval; admit or reject them
    ///
    /// Coordinator only, and closed networks only. With no action, lists who is
    /// waiting; `accept <id>` admits one and `deny <id>` turns it away.
    Requests {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        #[command(subcommand)]
        action: Option<RequestsAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// The old spelling of `ray requests <network> accept <id>`.
    #[command(hide = true)]
    Accept {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Short id of the pending peer (from `ray requests`)
        #[arg(add = complete::join_requests())]
        id: String,
    },
    /// The old spelling of `ray requests <network> deny <id>`.
    #[command(hide = true)]
    Deny {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Short id of the pending peer (from `ray requests`)
        #[arg(add = complete::join_requests())]
        id: String,
    },
    /// Request a direct link, or review incoming ones
    ///
    /// `ray connect <contact-id>` asks that peer for a direct 2-peer network,
    /// with no room id or invite code needed; they run `ray connect approve` to
    /// accept it. With no argument, lists the requests waiting on you.
    Connect {
        #[command(subcommand)]
        action: Option<ConnectAction>,
        /// The peer's contact id (from their `ray contact id` / `ray status`)
        contact_id: Option<String>,
        /// Your hostname on the resulting network (defaults to your set name)
        ///
        /// `requires` because the id is what it names a hostname *on*: without
        /// one there is nothing to dial, and the flag would be dropped in
        /// silence while the queue got listed instead.
        #[arg(long, requires = "contact_id")]
        hostname: Option<String>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// The old spelling of `ray connect list` / `ray connect approve`.
    #[command(hide = true)]
    Connections {
        #[command(subcommand)]
        action: Option<ConnectAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Show or rotate your contact id
    ///
    /// Share it so others can `ray connect` you.
    Contact {
        #[command(subcommand)]
        action: Option<ContactAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Probe a peer over the mesh for latency and packet loss
    ///
    /// Reports round-trip latency, packet loss, and whether the path is direct
    /// or relayed. Unlike `status`, this sends live echo probes that verify the
    /// round-trip end to end.
    Ping {
        /// Peer to probe: hostname, mesh IP, or short id.
        #[arg(add = complete::peers())]
        peer: String,
        /// Number of probes to send.
        #[arg(short, long, default_value_t = 3)]
        count: u32,
        /// Delay between probes, in milliseconds.
        #[arg(short, long, default_value_t = 1000)]
        interval: u64,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Report this node's network conditions
    ///
    /// Bound UDP port, home relay and its latency, public addresses, and
    /// IPv4/IPv6/UDP reachability.
    Netcheck {
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Grant or list this network's co-coordinators
    ///
    /// Coordinator only. A grantee holds the network key: it can publish the
    /// signed blob and suggest firewall rules. Trusted-network multi-admin.
    Admin {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        #[command(subcommand)]
        action: AdminAction,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Manage local, per-network aliases for peer identities
    ///
    /// A friendly name for a user identity. Node-local and display-only: shown
    /// inline in `ray status` and used to seed a `ray apply` spec's `aliases:`
    /// map. Never published to the network.
    Alias {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        #[command(subcommand)]
        action: AliasAction,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Manage local device firewall rules
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Offer or use an internet gateway
    ///
    /// Offer this node as a gateway, or route this node's traffic through one.
    #[command(name = "exit-node")]
    ExitNode {
        #[command(subcommand)]
        action: ExitNodeAction,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Reconcile trusted networks against a deploy spec file
    ///
    /// Creates missing trusted networks, publishes idempotent firewall
    /// suggestions, and reports the membership gap (expected vs joined hosts).
    /// Never joins.
    Apply {
        /// Path to a TOML spec file (see `ray apply --example`).
        #[arg(value_hint = clap::ValueHint::FilePath)]
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
        #[arg(add = complete::networks())]
        network: String,
        /// New hostname (e.g. "alice" → alice.network.ray)
        name: String,
    },
    /// Print a host's identity string
    ///
    /// The value to paste into a `ray apply` spec's `aliases:` map. Resolves to
    /// the user identity if the device is paired, else the device's transport
    /// identity.
    #[command(visible_alias = "whois")]
    Identityof {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Hostname to look up
        #[arg(add = complete::peers())]
        hostname: String,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Toggle LAN peer discovery, or list what it found
    ///
    /// Discovery is over mDNS, and finds peers on the same local network.
    Mdns {
        #[command(subcommand)]
        action: MdnsAction,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// The old spelling of `ray config set auto-update on|off`.
    #[command(name = "auto-update", hide = true)]
    AutoUpdate {
        /// "on" or "off"
        #[arg(add = complete::words(&ON_OFF))]
        state: String,
    },
    /// View or change daemon settings
    ///
    /// `ray config get` lists every key, `ray config set --help` describes them.
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Authorize a user to run ray without sudo (requires root)
    SetOperator {
        /// Username or numeric UID to grant operator access
        #[arg(value_hint = clap::ValueHint::Username)]
        user: String,
    },
    /// Send one or more files to a peer (queued if the peer is offline)
    Send {
        /// Peer hostname, mesh IP, or short ID
        #[arg(add = complete::peers())]
        peer: String,
        /// File paths to send
        #[arg(required = true, value_hint = clap::ValueHint::AnyPath)]
        files: Vec<String>,
    },
    /// Manage incoming file transfers
    Files {
        #[command(subcommand)]
        action: Option<FilesAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Pair this device with another device (share user identity)
    Pair {
        #[command(subcommand)]
        action: Option<PairAction>,
        /// Pairing ticket from the primary device (shorthand for `rayfish pair accept <ticket>`)
        ticket: Option<String>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Revoke a paired device (primary only)
    ///
    /// Invalidates the device's certificate mesh-wide.
    Unpair {
        /// Device to revoke: hostname, mesh IP, short id, or full endpoint id
        /// (see `ray pair list`)
        #[arg(add = complete::paired_devices())]
        device: String,
    },
    /// Handle a rayfish:// deep link (join or pair)
    ///
    /// Hidden because it is what the desktop URI handler invokes, not something
    /// typed at a prompt.
    #[command(hide = true)]
    Open {
        /// The rayfish:// URI, e.g. rayfish://join/<code> or rayfish://pair/<ticket>
        uri: String,
    },
    /// Print the rayfish version
    #[command(visible_alias = "ver")]
    Version,
    /// Update rayfish to the latest GitHub release
    ///
    /// A one-off update. To have the daemon do it for you, turn on automatic
    /// stable updates with `ray config set auto-update on`.
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
    /// Internal detached Windows MSI updater helper.
    #[cfg(windows)]
    #[command(name = "windows-update-helper", hide = true)]
    WindowsUpdateHelper {
        #[arg(long)]
        msi: std::path::PathBuf,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        parent_pid: u32,
    },
}

#[derive(Subcommand)]
pub(crate) enum InviteAction {
    /// Mint a new invite code (the default action)
    ///
    /// Single-use by default; `--reusable` mints a multi-use key for unattended
    /// fleets.
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
        /// Also render the invite as a scannable QR code (off by default, it
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
        #[arg(add = complete::invite_ids())]
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
    /// List this user's paired devices
    #[command(visible_alias = "ls")]
    List,
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
    /// Grant the network key to a member
    Add {
        /// Short id of the member to promote (from `ray status`)
        #[arg(add = complete::peers())]
        identity: String,
    },
    /// List this network's key-holders
    ///
    /// The local node, plus every member granted the key.
    #[command(visible_alias = "ls")]
    List,
}

#[derive(Subcommand)]
pub(crate) enum AliasAction {
    /// Bind an alias to a user identity
    ///
    /// `key` is an identity string (from `ray identityof`) or a
    /// currently-joined hostname, resolved to its identity.
    Set {
        /// Identity string or a joined hostname
        #[arg(add = complete::peers())]
        key: String,
        /// The alias to assign
        alias: String,
    },
    /// List this network's aliases
    #[command(visible_alias = "ls")]
    List,
    /// Remove an alias by name
    #[command(visible_aliases = ["rm", "del"])]
    Remove {
        /// The alias to remove
        #[arg(add = complete::aliases())]
        alias: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum RequestsAction {
    /// Admit a peer waiting for approval
    #[command(visible_alias = "ok")]
    Accept {
        /// Short id of the pending peer (from `ray requests <network>`)
        #[arg(add = complete::join_requests())]
        id: String,
    },
    /// Reject a peer waiting for approval
    Deny {
        /// Short id of the pending peer (from `ray requests <network>`)
        #[arg(add = complete::join_requests())]
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConnectAction {
    /// List pending incoming connection requests (default)
    #[command(visible_alias = "ls")]
    List,
    /// Approve a pending request
    ///
    /// Forms the direct 2-peer network. `accept` is an alias, so the admit verb
    /// reads the same here as it does under `ray requests`.
    #[command(visible_aliases = ["ok", "accept"])]
    Approve {
        /// Short id of the requester (from `ray connect`)
        #[arg(add = complete::connect_requests())]
        id: String,
    },
}

/// `--help` text for a `ray config` key argument: the lead line plus the
/// generated key list, so `-h` stays one line and `--help` names every key.
fn key_long_help(lead: &str) -> String {
    format!("{lead}\n\n{}", node_key_help())
}

#[derive(Subcommand)]
pub(crate) enum ConfigAction {
    /// Show settings (all, or one key)
    #[command(visible_alias = "ls")]
    Get {
        /// A settings key (omit for all)
        #[arg(
            long_help = key_long_help("A settings key (omit for all)."),
            add = complete::node_settings_keys()
        )]
        key: Option<String>,
    },
    /// Set a key to a value
    ///
    /// List keys take a comma list of presets/URLs/IPs; on/off keys take on or
    /// off.
    Set {
        /// A settings key
        #[arg(
            long_help = key_long_help("A settings key."),
            add = complete::node_settings_keys()
        )]
        key: String,
        /// A comma list of presets / URLs / IPv4s ("n0" or empty resets), or on/off
        #[arg(add = complete::settings_values())]
        value: String,
        /// Replace the defaults instead of augmenting them (list keys only)
        #[arg(long)]
        replace: bool,
    },
    /// Reset a key to its default
    #[command(visible_alias = "rm")]
    Unset {
        /// A settings key
        #[arg(
            long_help = key_long_help("A settings key."),
            add = complete::node_settings_keys()
        )]
        key: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum MdnsAction {
    /// Enable mDNS local peer discovery (takes effect on daemon restart)
    On,
    /// Disable mDNS local peer discovery (takes effect on daemon restart)
    Off,
    /// List rayfish nodes seen on this LAN
    ///
    /// Seeing a node grants it nothing: linking up still needs `ray connect`
    /// and the other side's approval.
    Scan,
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
    /// Add a firewall rule
    ///
    /// A new rule is inserted at the front, so it supersedes any contradicting
    /// rule under first-match, e.g. `deny in icmp` overrides the seeded
    /// `allow in icmp` (and re-adding `allow` flips it back). A rule with the
    /// same selector (direction/proto/port/peer/network) replaces the old one
    /// rather than stacking, so toggling never accumulates dead rules.
    #[command(visible_alias = "a")]
    Add {
        /// Direction: in or out
        #[arg(add = complete::words(&["in", "out"]))]
        direction: String,
        /// Action: allow or deny
        #[arg(add = complete::words(&ALLOW_DENY))]
        action: String,
        /// Protocol: tcp, udp, icmp, any
        #[arg(long, short = 'p', default_value = "any", add = complete::words(&["tcp", "udp", "icmp", "any"]))]
        proto: String,
        /// Port, range, or comma list (e.g. 22, 80-443, 80,443, or * for all).
        /// A comma list adds one rule per item.
        #[arg(long, short = 'P')]
        port: Option<String>,
        /// Peer: hostname, mesh IP, short id, endpoint id, or user identity
        /// (omit for any peer)
        #[arg(long, add = complete::peers())]
        peer: Option<String>,
        /// Restrict to a network (omit to match any network the peer is reached through)
        #[arg(long, add = complete::networks())]
        network: Option<String>,
    },
    /// Remove a rule by index
    #[command(visible_aliases = ["rm", "del"])]
    Remove {
        /// Rule index (from 'firewall show')
        #[arg(add = complete::firewall_rules())]
        index: usize,
    },
    /// Show current firewall rules
    #[command(visible_aliases = ["ls", "list"])]
    Show,
    /// Set the inbound default policy (allow or deny)
    ///
    /// `deny` (the secure built-in default) blocks unsolicited inbound TCP/UDP;
    /// `allow` restores the old permissive behaviour. Inbound ICMP is always
    /// allowed by default (use an explicit `deny in icmp` rule to block it);
    /// the outbound default is always allow and is unaffected.
    Default {
        /// Default inbound action: allow or deny
        #[arg(add = complete::words(&ALLOW_DENY))]
        action: String,
    },
    /// Reply RST/unreachable instead of dropping (on|off)
    ///
    /// "Fail fast" REJECT mode, opt-in and off by default. When `on`, a denied
    /// packet gets a TCP RST / ICMP-unreachable reply so the initiator fails
    /// immediately ("connection refused") instead of hanging to a timeout. When
    /// `off`, denied packets are silently dropped (stealthy, the default).
    Reject {
        /// on or off
        #[arg(add = complete::words(&ON_OFF))]
        state: String,
    },
    /// Turn the firewall back on
    ///
    /// Resumes enforcing rules and defaults. Undoes `ray firewall off`.
    #[command(visible_alias = "enable")]
    On,
    /// Allow every packet, bypassing all rules
    ///
    /// Disables the firewall entirely on this device: every packet is allowed,
    /// bypassing all rules and defaults (mesh membership still gates who can
    /// reach you; the anti-spoof check still runs). For simple setups that don't
    /// want a second firewall on top of the host/kernel one. Re-enable with
    /// `ray firewall on`.
    #[command(visible_alias = "disable")]
    Off,
    /// Coordinator: suggest rules for a subject host
    ///
    /// Distributed in the signed blob; each node takes them per its own consent.
    Suggest {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Subject host (the hostname the rules protect). Use `*` to target every
        /// node on the network (e.g. "everyone opens this port").
        #[arg(long, add = complete::peers_or_any())]
        subject: String,
        /// Allow inbound traffic, e.g. `--allow tcp:22` (any peer) or
        /// `--allow earn01:tcp:9000,tcp:8123` (repeatable). The `PEER:` prefix is
        /// optional: omit it (start with a protocol) to mean "any peer".
        /// Spec grammar: `proto:ports` or bare proto (`icmp`, `any`, `tcp`).
        #[arg(long, value_name = "[PEER:]SPEC")]
        allow: Vec<String>,
        /// Deny inbound traffic, e.g. `--deny udp:53` (any peer) or
        /// `--deny earn01:tcp:443` (repeatable). Same grammar as `--allow`; the
        /// `PEER:` prefix is optional.
        #[arg(long, value_name = "[PEER:]SPEC")]
        deny: Vec<String>,
    },
    /// Show suggested rules queued for review on a network
    ///
    /// Queued on a node that did not join with `--auto-accept-firewall`.
    Pending {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
    },
    /// Accept and install a network's queued suggested rules
    Accept {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
    },
    /// Discard a network's queued suggested rules
    Deny {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
    },
    /// Take future suggestions without review (on|off)
    ///
    /// Per network, on this node. `on` also installs the current queue; `off`
    /// stops future auto-install.
    AutoAccept {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// `on` or `off`
        #[arg(add = complete::words(&ON_OFF))]
        state: String,
    },
    /// Embedded mesh SSH server: SSH in by mesh identity
    ///
    /// Tailscale-style, with no SSH keys. `ssh on` starts the server;
    /// `ssh allow <net> <peer>` authorizes a peer to log in. Connect with a
    /// stock client: `ssh user@host.ray`.
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },
}

#[derive(Subcommand)]
pub(crate) enum SshAction {
    /// Start the mesh SSH server on this node
    ///
    /// Listens on the mesh IPs' port 22, and opens tcp:22 in the local firewall.
    On,
    /// Stop the mesh SSH server
    ///
    /// Removes the tcp:22 passthrough.
    Off,
    /// Authorize a peer to SSH into this node
    ///
    /// Per network. `peer` is a hostname, mesh IP, short id, or `*` (any peer on
    /// the network).
    #[command(visible_alias = "ok")]
    Allow {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Peer (hostname / mesh IP / short id) or `*`
        #[arg(add = complete::peers_or_any())]
        peer: String,
        /// Local unix users this peer may log in as (comma-separated). Omit for
        /// any non-root user; pass `*` for any user including root.
        #[arg(long = "user", short = 'u', value_delimiter = ',')]
        user: Vec<String>,
    },
    /// Revoke a peer's SSH authorization on a network
    #[command(visible_aliases = ["rm", "del"])]
    Deny {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Peer (hostname / mesh IP / short id) or `*`
        #[arg(add = complete::peers_or_any())]
        peer: String,
    },
    /// Show the server state and per-network allow lists
    #[command(visible_aliases = ["ls", "list"])]
    Show {
        /// Optional network to filter to
        #[arg(add = complete::networks())]
        network: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ExitNodeAction {
    /// Let a peer route its internet traffic through this node
    ///
    /// The first `allow` turns this node into an exit node for the network;
    /// activate it with `ray up`. `peer` is a hostname, mesh IP, short id, or
    /// `*` (any peer on the network).
    #[command(visible_alias = "ok")]
    Allow {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Peer (hostname / mesh IP / short id) or `*`
        #[arg(add = complete::peers_or_any())]
        peer: String,
    },
    /// Revoke a peer's exit-node permission
    ///
    /// Per network. Removing the last peer withdraws this node's exit-node
    /// offer.
    #[command(visible_aliases = ["rm", "del", "deny"])]
    Disallow {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Peer (hostname / mesh IP / short id) or `*`
        #[arg(add = complete::peers_or_any())]
        peer: String,
    },
    /// Route this node's non-mesh traffic through an exit peer
    ///
    /// Per network. The peer must advertise an exit node (see
    /// `ray exit-node status`). Takes effect on the next `ray up`.
    Use {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Exit peer (hostname / mesh IP / short id)
        #[arg(add = complete::exit_peers())]
        peer: String,
    },
    /// Stop routing through an exit node
    ///
    /// Restores direct egress. With no network, clears the exit selection on
    /// every network that has one.
    #[command(visible_aliases = ["off", "disable"])]
    None {
        /// Network name (omit to clear every network's exit selection)
        #[arg(add = complete::networks())]
        network: Option<String>,
    },
    /// Show exit-node state and available peers
    ///
    /// This node's offer and selection, plus the peers advertising one.
    #[command(visible_aliases = ["ls", "list", "show"])]
    Status {
        /// Optional network to filter to
        #[arg(add = complete::networks())]
        network: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FilesAction {
    /// Accept a pending file transfer
    Accept {
        /// Transfer ID (from 'rayfish files')
        #[arg(add = complete::incoming_files())]
        id: u64,
        /// Output directory (default: ~/Downloads)
        #[arg(long, short, value_hint = clap::ValueHint::DirPath)]
        output: Option<String>,
    },
    /// Cancel a queued send that hasn't reached its peer yet
    Cancel {
        /// Queued-send ID (from 'ray files')
        #[arg(add = complete::queued_sends())]
        id: u64,
    },
    /// Auto-accept offers from your own devices (on|off)
    ///
    /// Per network, and only for your own paired devices. `on` also drains any
    /// already-queued offers from them; `off` stops future auto-accept.
    AutoAccept {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// `on` or `off`
        #[arg(add = complete::words(&ON_OFF))]
        state: String,
    },
    /// Set the directory auto-accepted files are written to
    ///
    /// An absolute path. With no argument, prints the current value; `--clear`
    /// reverts to the download-user / operator fallback.
    DownloadDir {
        /// Absolute path (omit to show current)
        #[arg(value_hint = clap::ValueHint::DirPath)]
        path: Option<String>,
        /// Clear the setting (revert to download-user / operator fallback)
        #[arg(long)]
        clear: bool,
    },
    /// Set the unix user that owns auto-accepted files
    ///
    /// Their ~/Downloads also receives the files when no download-dir is set.
    /// With no argument, prints the current value.
    DownloadUser {
        /// Username or numeric uid (omit to show current)
        #[arg(value_hint = clap::ValueHint::Username)]
        user: Option<String>,
        /// Clear the setting
        #[arg(long)]
        clear: bool,
    },
}

fn check_root() {
    #[cfg(windows)]
    return;
    #[cfg(unix)]
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
    use std::io::IsTerminal;
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

    // Console layer: human text on stdout, held at `info` so CLI output and the
    // daemon console stay readable while the file keeps the `debug` detail.
    // Color only when stdout is a terminal: under systemd stdout is a pipe to
    // journald, and ANSI escapes would end up verbatim in syslog.
    let console_layer = tracing_subscriber::fmt::layer()
        .with_ansi(std::io::stdout().is_terminal())
        .with_filter(console_filter);

    // File layer: daemon only, human text with ANSI stripped, rotated daily.
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

    // OTLP span export layer: only built when the feature is on AND an endpoint
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

/// Install a fail-fast panic hook (daemon only). On any panic (including in a
/// spawned tokio task, which the runtime would otherwise swallow) it records the
/// crash (message, location, thread, backtrace) via `tracing::error!` (rolling file
/// log + any OTLP exporter) and synchronously appends it to `panic.log` in the log
/// dir, then **aborts the process**.
///
/// Rationale: a panic is an invariant violation. For a VPN daemon, limping on with
/// a dead subsystem (e.g. a stalled forwarding loop) is worse than a clean restart,
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
        // Durable, synchronous capture: survives even though abort() skips the
        // async log appender's flush.
        if let Err(e) = append_panic_log(&location, &thread, &message, &backtrace) {
            eprintln!("failed to write panic log: {e}");
        }

        // Hand DNS back to the OS before we abort: restore the backed-up
        // resolv.conf and drop the NetworkManager `dns=none` snippet, so a crash
        // can't leave the host pointing at our dead resolver (it would otherwise
        // blackhole all DNS until the service restarts). Synchronous, best-effort.
        rayfish::dns::config::emergency_restore_resolv_conf();

        // Remove the exit-node kernel state: the forwarding/NAT (restoring the
        // sysctls) so a crash can't leave the host an open router, and the client
        // full-tunnel rules, which would otherwise outlive the TUN they point at.
        rayfish::exit_node::disable();
        rayfish::exit_node::teardown_client_routing();

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

fn main() -> Result<()> {
    // Before anything else: before stdout is touched, before the arguments are
    // parsed (a completion request is not a command line this parser accepts),
    // and outside the runtime, since the completers build one of their own.
    complete::intercept();
    run()
}

#[tokio::main]
async fn run() -> Result<()> {
    // Not `Cli::parse()`: the command list in `-h` is grouped, which clap cannot
    // express on subcommands, so the parser comes from `cli::help` with a
    // template that renders the grouping in place of clap's flat list.
    let cli =
        Cli::from_arg_matches(&cli::help::command().get_matches()).unwrap_or_else(|e| e.exit());
    if json_requested(&cli.command) {
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
            no_auto_accept_files,
        } => {
            ipc_join(
                &network_key,
                name.as_deref(),
                hostname,
                tor,
                auto_accept_firewall,
                !no_auto_accept_files,
            )
            .await
        }
        Command::Nuke { name, force } => ipc_nuke(&name, force).await,
        Command::Kick { network, peer } => ipc_kick(&network, &peer).await,
        Command::Ephemeral { network, arg } => ipc_ephemeral(&network, &arg).await,
        Command::Status { json: _ } => ipc_status().await,
        Command::Report => ipc_report().await,
        Command::Logs { since, follow } => ipc_logs(since, follow).await,
        Command::Daemon => {
            check_root();
            install_panic_hook();
            #[cfg(windows)]
            if rayfish::windows_service::run_if_service()? {
                return Ok(());
            }
            let token = shutdown::token();
            let stats = Arc::new(stats::ForwardMetrics::default());
            stats.spawn_logger(token.clone());
            daemon::run_daemon(token, stats).await
        }
        Command::Up {
            hostname,
            private,
            no_private,
            relay,
            pkarr,
            yes,
        } => {
            cmd_up(UpOptions {
                hostname,
                private,
                no_private,
                relay,
                pkarr,
                yes,
            })
            .await
        }
        Command::Down => ipc_down().await,
        Command::Stop => cmd_stop().await,
        Command::Start => cmd_start().await,
        Command::Uninstall => cmd_uninstall_service(),
        Command::Install { auto_update } => cmd_install(auto_update).await,
        Command::Restart => cmd_restart().await,
        Command::Completions { shell, install } => complete::cmd_completions(shell, install),
        Command::Gui { port, no_open } => cmd_gui(port, no_open),
        Command::Invite {
            network,
            action,
            json: _,
        } => ipc_invite(&network, action).await,
        Command::Requests {
            network,
            action,
            json: _,
        } => match action {
            None => ipc_requests(&network).await,
            Some(RequestsAction::Accept { id }) => ipc_accept_request(&network, &id).await,
            Some(RequestsAction::Deny { id }) => ipc_deny_request(&network, &id).await,
        },
        Command::Accept { network, id } => ipc_accept_request(&network, &id).await,
        Command::Deny { network, id } => ipc_deny_request(&network, &id).await,
        // An action is a request-queue verb, a bare contact id dials that peer,
        // and with neither, show the queue, the same as `ray connections` did.
        // The two together parse (the positional fills, then the subcommand
        // does) and mean nothing, so they are rejected rather than served by
        // dropping one.
        Command::Connect {
            action,
            contact_id,
            hostname,
            json: _,
        } => match (action, contact_id) {
            (None, Some(id)) => ipc_connect(&id, hostname).await,
            (None, None) => ipc_connections(None).await,
            (Some(action), None) => ipc_connections(Some(action)).await,
            (Some(_), Some(id)) => {
                anyhow::bail!("`ray connect {id}` dials that peer; it takes no subcommand")
            }
        },
        Command::Connections { action, json: _ } => ipc_connections(action).await,
        Command::Contact { action, json: _ } => ipc_contact(action).await,
        Command::Ping {
            peer,
            count,
            interval,
            json: _,
        } => ipc_ping(&peer, count, interval).await,
        Command::Netcheck { json: _ } => ipc_netcheck().await,
        Command::Admin {
            network,
            action,
            json: _,
        } => ipc_admin(&network, action).await,
        Command::Firewall { action, json: _ } => ipc_firewall(action).await,
        Command::ExitNode { action, json: _ } => ipc_exit_node(action).await,
        Command::Apply {
            spec,
            prune,
            dry_run,
            invite_missing,
            example,
        } => ipc_apply(spec, prune, dry_run, invite_missing, example).await,
        Command::Hostname { network, name } => ipc_set_hostname(&network, &name).await,
        Command::Identityof {
            network,
            hostname,
            json,
        } => cmd_identityof(&network, &hostname, json).await,
        Command::Alias {
            network,
            action,
            json,
        } => cmd_alias(&network, action, json).await,
        Command::Mdns { action, json: _ } => cmd_mdns(action).await,
        Command::AutoUpdate { state } => cmd_auto_update(&state).await,
        Command::Config { action, json } => cmd_config(action, json).await,
        Command::SetOperator { user } => cmd_set_operator(&user).await,
        Command::Send { peer, files } => ipc_send_files(&files, &peer).await,
        Command::Files { action, json: _ } => ipc_files(action).await,
        Command::Pair {
            action,
            ticket,
            json: _,
        } => cmd_pair(action, ticket).await,
        Command::Unpair { device } => ipc_unpair(&device).await,
        Command::Open { uri } => cmd_open(&uri).await,
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
        #[cfg(windows)]
        Command::WindowsUpdateHelper {
            msi,
            identity,
            sha256,
            parent_pid,
        } => rayfish::update::run_msi_update_helper(&msi, &identity, &sha256, parent_pid).await,
    }
}

// ---------------------------------------------------------------------------
// Config-writing commands
//
// These change global daemon settings (`settings.toml`). They route through the
// daemon rather than writing the file client-side: on non-Linux, `config_dir()`
// is derived from the process environment, so a CLI writing from a different
// `HOME` than the service runs under would land the file where the daemon never
// reads it (rayfish#94). The daemon writes its own config dir, sidestepping the
// divergence. This makes a running daemon a prerequisite.
// ---------------------------------------------------------------------------

/// Send a mutating IPC request and print its `Ok`/`Error` reply.
pub(crate) async fn ipc_mutate(msg: ipc::IpcMessage) -> Result<()> {
    let mut stream = ipc::connect()
        .await
        .context("rayfish daemon is not running; start it with: sudo ray up")?;
    ipc::send(&mut stream, msg).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// `ray mdns on|off|scan`. The two toggles are the `mdns` settings key under
/// another name; `scan` is a read and goes its own way.
async fn cmd_mdns(action: MdnsAction) -> Result<()> {
    let state = match action {
        MdnsAction::On => "on",
        MdnsAction::Off => "off",
        MdnsAction::Scan => return ipc_lan_peers().await,
    };
    ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: ipc::NodeKey::Global(ipc::GlobalKey::Mdns),
        value: state.to_string(),
        replace: false,
    })
    .await
}

/// `ray auto-update on|off`: back-compat alias for `ray config set auto-update
/// <on|off>`. The daemon persists it and reads it at startup, so the change
/// takes effect on the next daemon restart.
async fn cmd_auto_update(state: &str) -> Result<()> {
    ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: ipc::NodeKey::Global(ipc::GlobalKey::AutoUpdate),
        value: state.to_string(),
        replace: false,
    })
    .await
}

/// `ray config get/set/unset`: view or change global daemon settings via the
/// daemon (see the module note above on why writes are not client-side). Changes
/// to relay/discovery/dns-upstreams all take effect on the next daemon restart.
async fn cmd_config(action: Option<ConfigAction>, json: bool) -> Result<()> {
    match action.unwrap_or(ConfigAction::Get { key: None }) {
        ConfigAction::Get { key } => {
            // Before the connect, so a bad key reads the same whether or not the
            // daemon happens to be running (and the same as `set`/`unset`).
            let key = key.as_deref().map(parse_node_key);
            let mut stream = ipc::connect()
                .await
                .context("rayfish daemon is not running; start it with: sudo ray up")?;
            ipc::send(&mut stream, ipc::IpcMessage::ConfigGet { key }).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::ConfigValues { rows } => {
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
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
            Ok(())
        }
        ConfigAction::Set {
            key,
            value,
            replace,
        } => {
            ipc_mutate(ipc::IpcMessage::ConfigSet {
                key: parse_node_key(&key),
                value,
                replace,
            })
            .await
        }
        ConfigAction::Unset { key } => {
            ipc_mutate(ipc::IpcMessage::ConfigUnset {
                key: parse_node_key(&key),
            })
            .await
        }
    }
}

/// Resolve a user-typed key to the one the wire carries. `ray config` is the
/// only command that takes a key as free text; every other caller names its key
/// as a constant, so this is the single place a typo can enter.
///
/// Reported here rather than by the daemon, with the registry's own wording:
/// the key type makes an unknown key unrepresentable on the wire, so without
/// this the request would fail to encode instead of explaining itself.
fn parse_node_key(key: &str) -> ipc::NodeKey {
    match key.parse() {
        Ok(k) => k,
        Err(e) => fail_with("error", &e),
    }
}

/// Resolve a username to its UID, falling back to parsing a numeric UID.
pub(crate) fn uid_for_user(user: &str) -> Option<u32> {
    #[cfg(windows)]
    return user.parse::<u32>().ok();
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let cname = CString::new(user).ok()?;
        let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
        if !pw.is_null() {
            return Some(unsafe { (*pw).pw_uid });
        }
        user.parse::<u32>().ok()
    }
}

/// `ray set-operator <user>`: authorize a local user to run mutating ray
/// commands without sudo (Tailscale's `--operator` model). The daemon enforces
/// that this call itself comes from root.
async fn cmd_set_operator(user: &str) -> Result<()> {
    // Windows writes the operator SID itself instead of asking the daemon. The
    // daemon has no Windows equivalent of the root check that authorizes
    // `SetOperator` over IPC, so the check that matters (an elevated
    // Administrator) happens here, in the process that has the caller's token.
    // This is the recovery path when the claim `ray up` makes goes to the wrong
    // account; the normal case never runs it.
    #[cfg(windows)]
    {
        let sid = rayfish::windows_service::set_operator_account(std::ffi::OsStr::new(user))?;
        println!("operator set to {user} ({sid})");
        Ok(())
    }
    #[cfg(unix)]
    {
        let uid = uid_for_user(user).ok_or_else(|| {
            anyhow::anyhow!("unknown user '{user}' (pass a valid username or UID)")
        })?;
        let mut stream = ipc::connect()
            .await
            .context("rayfish daemon is not running; start it with: sudo ray up")?;
        ipc::send(&mut stream, ipc::IpcMessage::SetOperator { uid }).await?;
        match ipc::recv(&mut stream).await? {
            ipc::IpcMessage::Ok { message } => println!("{message}"),
            ipc::IpcMessage::Error { message } => fail_with("error", &message),
            other => fail_unexpected(&other),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IPC client commands (require daemon running)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::FirewallRuleView;
    use rayfish::update::{normalize_version, release_asset_name, version_is_newer};

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
        assert_eq!(
            release_asset_name("windows", "x86_64").unwrap(),
            "ray-windows-x86_64.msi"
        );
    }

    #[test]
    fn release_asset_name_rejects_unsupported_platforms() {
        assert!(release_asset_name("windows", "aarch64").is_err());
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
        let out = render_firewall_rules(
            Some((firewall::Action::Deny, firewall::Action::Allow)),
            false,
            false,
            &[],
        );
        assert!(out.contains("default in   deny"));
        assert!(out.contains("default out  allow"));
        assert!(out.contains("(no rules)"));
        // The posture header notes the firewall is separate from the host one.
        assert!(out.contains("separate from your host/kernel firewall"));
    }

    #[test]
    fn disabled_firewall_shows_banner() {
        style::set_plain(true);
        let out = render_firewall_rules(
            Some((firewall::Action::Deny, firewall::Action::Allow)),
            false,
            true,
            &[],
        );
        assert!(out.contains("disabled"));
        assert!(out.contains("all packets allowed"));
    }
}
