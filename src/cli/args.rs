//! The clap definitions for every `ray` command.

use crate::*;

/// Full version string: the crate version plus the git short SHA stamped in by
/// `build.rs` (e.g. `0.1.0 (abc12345)`). The SHA distinguishes nightly builds
/// that share a crate version, and is what a tester quotes in a `ray report`.
pub(crate) const FULL_VERSION: &str =
    concat!(env!("CARGO_PKG_VERSION"), " (", env!("RAY_GIT_SHA"), ")");

/// The `on`/`off` domain shared by the toggle arguments. Suggestions, not a
/// `value_parser`: these arguments also take `true`/`yes`/`1` (see
/// `config::parse_bool_setting`), and restricting them to two words here would
/// start rejecting spellings that work today.
pub(crate) const ON_OFF: [&str; 2] = ["on", "off"];

/// The firewall's verdict words, shared by `firewall add` and `firewall default`.
pub(crate) const ALLOW_DENY: [&str; 2] = ["allow", "deny"];

#[derive(Parser)]
#[command(
    name = "ray",
    about = "P2P mesh VPN powered by iroh",
    version = FULL_VERSION
)]
pub(crate) struct Cli {
    /// Use your private rootless instance
    #[cfg(target_os = "linux")]
    #[arg(long, global = true)]
    pub(crate) rootless: bool,
    /// Use the system daemon
    #[cfg(target_os = "linux")]
    #[arg(long, global = true, conflicts_with = "rootless")]
    pub(crate) system: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
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
        /// Network public key, invite code, or local network name with --delegate
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
        /// Run the join on an enrolled machine instead of this one.
        #[arg(long)]
        delegate: Option<ipc::ManagedMachineSelector>,
    },
    /// Leave a network (remove from saved config)
    #[command(visible_alias = "rm")]
    Leave {
        /// Three-word network name
        #[arg(add = complete::networks())]
        name: String,
        /// Run the leave on an enrolled machine instead of this one.
        #[arg(long)]
        delegate: Option<ipc::ManagedMachineSelector>,
    },
    /// Leave a network, destroying it if the last coordinator
    Nuke {
        /// Three-word network name
        #[arg(add = complete::networks())]
        name: String,
        /// Proceed even if other members exist
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
        /// Skip the confirmation when the member holds more than one device
        #[arg(long, short = 'y')]
        yes: bool,
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
    /// Show status of all networks
    ///
    /// Covers the networks the daemon has registered and the saved ones it has
    /// not brought up yet.
    #[command(visible_aliases = ["s", "st", "ls"])]
    Status {
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
        /// Include managed machines in the status output
        #[arg(long)]
        machines: bool,
        /// Include IP addresses in the text output
        #[arg(long, visible_alias = "ips")]
        with_ips: bool,
    },
    /// Collect diagnostics and open a pre-filled GitHub issue
    ///
    /// Bundles the rolling log files and the forward metrics.
    Report,
    /// Show Rayfish logs
    ///
    /// Reads daemon log files over IPC, or unified app and core logs on macOS.
    /// No root is needed. With no arguments, shows today's logs through
    /// `$PAGER` (`less`) when the output is a terminal. The macOS app's bundled
    /// CLI can read logs even while the VPN is disconnected.
    Logs {
        /// Only lines from the last <DUR> (e.g. 10m, 1h, 2h30m)
        #[arg(long, value_name = "DUR")]
        since: Option<String>,
        /// Keep streaming new lines until Ctrl-C, like `tail -f`
        #[arg(short, long)]
        follow: bool,
    },
    /// Run a rootless mesh with authenticated SOCKS5 and HTTP proxies
    #[cfg(target_os = "linux")]
    Rootless {
        /// SOCKS5 loopback address (default: an automatically assigned port)
        #[arg(long, default_value = "127.0.0.1:0", value_parser = rayfish::rootless::loopback_listener)]
        socks5: SocketAddr,
        /// HTTP proxy loopback address, including HTTPS through CONNECT
        #[arg(long, value_parser = rayfish::rootless::loopback_listener)]
        http: Option<SocketAddr>,
        /// Forward a local TCP port to PEER:PORT (other local users can connect)
        #[arg(long, value_name = "LOCAL_PORT=PEER:PORT")]
        forward: Vec<LocalForward>,
        /// Expose a loopback service at a mesh port
        #[arg(long, value_name = "MESH_PORT=LOOPBACK_ADDRESS:PORT")]
        expose: Vec<Expose>,
    },
    /// Run the daemon in the foreground (invoked by the system service)
    #[command(hide = true)]
    Daemon {
        /// Undo DNS and exit-node changes a dead daemon left behind, then exit
        /// (run by the service manager after the daemon stops)
        #[arg(long)]
        cleanup: bool,
    },
    /// Serve macOS app SSH sessions (started only by launchd).
    #[cfg(all(target_os = "macos", feature = "macos-app"))]
    #[command(hide = true)]
    AppSshHelper,
    /// Install the system service if needed and start it
    Up {
        /// Set your default hostname for future networks (e.g. "laptop"). Used
        /// when create/join don't specify one; doesn't rename existing networks
        #[arg(long)]
        hostname: Option<String>,
        /// Enable and persist mesh SSH when bringing the node up
        #[arg(long)]
        enable_ssh: bool,
        /// Persist a setting after startup (repeatable; a bare key means on)
        #[arg(
            long = "set",
            visible_alias = "enable",
            value_name = "KEY[=VALUE]",
            long_help = key_long_help(
                "Persist a setting after startup. Repeat for multiple settings; a bare key means on.\n\
                 Uses the same values and restart requirements as `ray config set`.\n\
                 Settings are applied in order; a failure leaves earlier settings applied."
            ),
            add = complete::node_settings_keys()
        )]
        settings: Vec<UpSetting>,
        /// Enroll this machine with a controller after bringing the daemon up.
        #[arg(long)]
        controller: Option<ipc::EnrollmentTicket>,
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
    #[cfg(not(all(target_os = "macos", feature = "macos-app")))]
    Gui {
        /// Localhost port to listen on (0 chooses a free port)
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Print the URL without trying to open a browser
        #[arg(long)]
        no_open: bool,
    },
    /// Review and answer private network invitations
    ///
    /// Coordinators send these with `ray apply --invite-missing`. Nothing joins
    /// until you accept; declining also blocks the sender.
    Invitations {
        #[command(subcommand)]
        action: Option<InvitationAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
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
    /// waiting; `accept <name>` admits one and `deny <name>` turns it away.
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
    /// The old spelling of `ray requests <network> accept <name>`.
    #[command(hide = true)]
    Accept {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Hostname or short id of the pending peer
        #[arg(add = complete::join_requests())]
        id: String,
    },
    /// The old spelling of `ray requests <network> deny <name>`.
    #[command(hide = true)]
    Deny {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// Hostname or short id of the pending peer
        #[arg(add = complete::join_requests())]
        id: String,
    },
    /// Request a direct link, or review incoming ones
    ///
    /// `ray connect <identity>` asks that peer for a direct 2-peer network,
    /// with no room id or invite code needed; they run `ray connect approve` to
    /// accept it. Share yours from `ray status`. With no argument, lists the
    /// requests waiting on you.
    Connect {
        #[command(subcommand)]
        action: Option<ConnectAction>,
        /// The peer's identity (from their `ray status` or `ray identityof`)
        peer: Option<String>,
        /// Your hostname on the resulting network (defaults to your set name)
        ///
        /// `requires` because the id is what it names a hostname *on*: without
        /// one there is nothing to dial, and the flag would be dropped in
        /// silence while the queue got listed instead.
        #[arg(long, requires = "peer")]
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
    /// Refuse a peer's connect requests and invitations
    ///
    /// The peer gets no reply, so it cannot tell a block from a full queue,
    /// though it can see you are online. Blocking a paired user's identity
    /// also covers their devices that appear in your networks. Membership of
    /// shared networks is unaffected; `ray kick` removes a member.
    Block {
        /// Identity or hostname of the peer
        #[arg(add = complete::peers())]
        peer: String,
    },
    /// Let a blocked peer reach you again
    Unblock {
        /// Identity or hostname of the peer
        #[arg(add = complete::peers())]
        peer: String,
    },
    /// List blocked peers
    Blocked {
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
    #[command(visible_alias = "fw")]
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Manage the embedded mesh SSH server and access rules
    Ssh {
        #[command(subcommand)]
        action: SshAction,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Offer or use an internet gateway
    ///
    /// Offer this node as a gateway, or route this node's traffic through one.
    #[command(name = "exit-node", visible_alias = "e")]
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
    /// suggestions, SSH grants, and enrolled machines by hostname.
    Apply {
        /// Path to a YAML spec file (see `ray apply --example`).
        #[arg(value_hint = clap::ValueHint::FilePath)]
        spec: Option<String>,
        /// Drop suggested-firewall subjects that are no longer in the spec.
        #[arg(long)]
        prune: bool,
        /// Show what would change without applying it.
        #[arg(long)]
        dry_run: bool,
        /// Mint one-time invites for hosts the spec expects but that haven't
        /// joined yet (hostname-bound), and privately invite aliases that have
        /// no joined device. Without this flag, they are only listed.
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
    /// Rename a network on this machine only
    ///
    /// The name is what `ray` commands and Magic DNS use for the network here:
    /// its hosts resolve as `<host>.<new-name>.ray` afterwards. Other members keep
    /// their own name for it. A live network reconnects under the new name.
    Rename {
        /// Network name
        #[arg(add = complete::networks())]
        network: String,
        /// New name (e.g. "lab" → alice.lab.ray)
        new_name: String,
    },
    /// Print a host's identity string
    ///
    /// The value to paste into a `ray apply` spec's `aliases:` map. Resolves to
    /// the user identity if the device is paired, else the device's transport
    /// identity. Searches all networks; different identities sharing a name
    /// are listed in a table. The older `identityof <network> <hostname>` form
    /// limits the lookup to one network. The identity is also what `ray
    /// connect` takes. Requires a running daemon.
    #[command(visible_alias = "whois")]
    Identityof {
        /// Hostname to look up across all networks
        #[arg(add = complete::peers())]
        peer: String,
        /// Hostname for a scoped lookup, treating PEER as the network name
        #[arg(add = complete::peers())]
        hostname: Option<String>,
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
    /// Configure Magic DNS system integration
    Dns {
        #[command(subcommand)]
        action: DnsAction,
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
    #[cfg(not(all(target_os = "macos", feature = "macos-app")))]
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
        /// Pairing ticket from the primary device (shorthand for `ray pair accept <ticket>`)
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
    /// List and enroll machines controlled by this node
    Machines {
        #[command(subcommand)]
        action: Option<MachinesAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
    },
    /// Manage controllers authorized by this machine
    Controller {
        #[command(subcommand)]
        action: Option<ControllerAction>,
        /// Emit machine-readable JSON instead of styled text
        #[arg(long, global = true)]
        json: bool,
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
pub(crate) enum InvitationAction {
    /// Join the invitation's network
    Accept {
        /// Invitation id, or an unambiguous prefix
        id: String,
        /// Your hostname on the network (defaults to your set name)
        #[arg(long)]
        hostname: Option<ipc::MachineHostname>,
    },
    /// Refuse it and block the sender
    Decline {
        /// Invitation id, or an unambiguous prefix
        id: String,
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
        /// Store the backup in 1Password instead of printing it
        #[arg(long = "1p", aliases = ["1password", "op"])]
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
        /// The encrypted backup string (omit when using --1p)
        backup: Option<String>,
        /// Read the backup from 1Password
        #[arg(long = "1p", aliases = ["1password", "op"])]
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
pub(crate) enum MachinesAction {
    /// Mint a machine-enrollment ticket
    Enroll {
        /// Allow this ticket to enroll more than one machine
        #[arg(long)]
        reusable: bool,
        /// How long the ticket remains valid, such as 30m or 7d
        #[arg(long)]
        expires: Option<String>,
    },
    /// List enrollment tickets and their status
    Enrollments,
    /// Revoke an enrollment ticket
    RevokeEnrollment {
        credential: ipc::EnrollmentCredentialSelector,
    },
    /// Forget an enrolled machine from this controller
    Forget {
        machine: ipc::ManagedMachineSelector,
    },
    /// Confirm an existing machine for inventory recovery
    Confirm {
        /// Full endpoint ID of a machine that already trusts this controller
        machine: EndpointId,
    },
}

#[derive(Subcommand)]
pub(crate) enum ControllerAction {
    /// Enroll this machine using a controller ticket
    Add { ticket: ipc::EnrollmentTicket },
    /// List authorized controllers
    List,
    /// Revoke one controller, or all controllers with --all
    Revoke {
        identity: Option<ipc::ControllerSelector>,
        #[arg(long, conflicts_with = "identity")]
        all: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum AdminAction {
    /// Grant the network key to a member
    Add {
        /// Member hostname, mesh IP, short id, or full identity
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
        /// Hostname or short id of the pending peer
        #[arg(add = complete::join_requests())]
        id: String,
    },
    /// Reject a peer waiting for approval
    Deny {
        /// Hostname or short id of the pending peer
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
        /// Hostname or short id of the requester
        #[arg(add = complete::connect_requests())]
        id: String,
    },
    /// Refuse a pending request and block the requester
    #[command(visible_alias = "reject")]
    Deny {
        /// Hostname or short id of the requester
        #[arg(add = complete::connect_requests())]
        id: String,
    },
}

/// `--help` text for a `ray config` key argument: the lead line plus the
/// generated key list, so `-h` stays one line and `--help` names every key.
pub(crate) fn key_long_help(lead: &str) -> String {
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

#[derive(Subcommand, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum MdnsAction {
    /// Enable mDNS local peer discovery
    On,
    /// Disable mDNS local peer discovery
    Off,
    /// List rayfish nodes seen on this LAN
    ///
    /// Seeing a node grants it nothing: linking up still needs `ray connect`
    /// and the other side's approval.
    Scan,
}

#[derive(Subcommand, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum DnsAction {
    /// Configure the system resolver for .ray names
    On,
    /// Resolve only explicit .ray names, without short-name search domains
    Partial,
    /// Remove Rayfish's system DNS configuration
    Off,
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
    /// Check whether the firewall would let a packet through
    ///
    /// Runs the rules and defaults the data path enforces against one packet
    /// and names what decides it, without sending anything: by default a new
    /// packet from the peer, with `--direction out` one to it.
    Test {
        /// Peer: hostname, mesh IP, short id, endpoint id, or user identity
        #[arg(add = complete::peers())]
        peer: String,
        /// Packet to check: tcp:<port>, udp:<port>, or icmp
        #[arg(value_name = "PROTO[:PORT]")]
        spec: String,
        /// Direction: in (from the peer) or out (to the peer)
        #[arg(long, default_value = "in", add = complete::words(&["in", "out"]))]
        direction: String,
        /// Look the peer up on this network only
        #[arg(long, add = complete::networks())]
        network: Option<String>,
    },
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
    /// stock client: `ssh user@host.ray` (or `ssh -p <port>` after setting
    /// `ray config set ssh-port <port>` on the server).
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },
}

#[derive(Subcommand)]
pub(crate) enum SshAction {
    /// Start the mesh SSH server on this node
    ///
    /// Listens on the configured mesh SSH port (22 by default).
    On,
    /// Stop the mesh SSH server
    ///
    /// Removes the configured port's passthrough.
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
        /// Local accounts this peer may log in as (comma-separated). Omit for
        /// any unprivileged account; pass `*` for any account including administrators.
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
        /// Transfer ID (from 'ray files')
        #[arg(add = complete::incoming_files())]
        id: u64,
        /// Output directory (default: ~/Downloads)
        #[arg(long, short, value_hint = clap::ValueHint::DirPath)]
        output: Option<String>,
    },
    /// Decline a pending file transfer
    ///
    /// Drops the offer from the queue without fetching it. The sender is not
    /// told: their offer is simply never pulled.
    Reject {
        /// Transfer ID (from 'ray files')
        #[arg(add = complete::incoming_files())]
        id: u64,
    },
    /// Cancel a queued send that hasn't reached its peer yet
    Cancel {
        /// Queued-send ID (from 'ray files')
        #[arg(add = complete::queued_sends())]
        id: u64,
    },
    /// Cancel a transfer in progress
    ///
    /// Cancels an outgoing transfer that has been offered or started, or stops
    /// an incoming one, including one waiting to resume. A stopped incoming
    /// file goes back to the queue with what was downloaded.
    CancelTransfer {
        /// Transfer ID (from 'ray files')
        id: u64,
    },
    /// Auto-accept files from trusted peers or your own devices
    ///
    /// Use add/remove/list for exact peers, or <network> on|off for your own
    /// paired devices. Enabling also accepts already-pending offers.
    #[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]
    AutoAccept {
        #[command(subcommand)]
        action: Option<FilesAutoAcceptAction>,
        /// Network name (own devices only)
        #[arg(required = true, add = complete::networks())]
        network: Option<String>,
        /// `on` or `off`
        #[arg(required = true, add = complete::words(&ON_OFF))]
        state: Option<String>,
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

#[derive(Subcommand)]
pub(crate) enum FilesAutoAcceptAction {
    /// Trust this exact peer to send files without approval
    Add {
        #[arg(add = complete::peers())]
        peer: String,
    },
    /// Remove this peer from the trusted senders
    Remove {
        #[arg(add = complete::peers())]
        peer: String,
    },
    /// List trusted sender identities
    #[command(visible_alias = "ls")]
    List,
}
