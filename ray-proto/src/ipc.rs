use std::collections::BTreeMap;
use std::io::{IoSlice, IoSliceMut};
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use iroh::EndpointId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::Interest;
use tokio::net::UnixStream;
use tokio_util::codec::{Decoder, Encoder, Framed, LengthDelimitedCodec};

use crate::{Action, Direction, GroupMode, Protocol, SuggestedFirewall, TransportMode};

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcMessage {
    // Requests
    Create {
        mode: GroupMode,
        name: Option<String>,
        hostname: Option<String>,
        transport: Option<TransportMode>,
    },
    Join {
        network_key: String,
        name: Option<String>,
        hostname: Option<String>,
        transport: Option<TransportMode>,
        /// One-time invite secret to present for invite-gated admission. When set,
        /// `coordinator` is dialed directly (no pkarr lookup).
        #[serde(default)]
        invite: Option<Vec<u8>>,
        /// Coordinator endpoint id to dial directly when joining via an invite.
        #[serde(default)]
        coordinator: Option<EndpointId>,
        /// Auto-install coordinator-suggested firewall rules on this network
        /// without a manual review queue (`--auto-accept-firewall`).
        #[serde(default, alias = "allow_trusted")]
        auto_accept_firewall: bool,
        /// Auto-accept incoming file offers from our own paired devices on this
        /// network (`--auto-accept-files`).
        #[serde(default)]
        auto_accept_files: bool,
    },
    Leave {
        name: String,
    },
    Nuke {
        name: String,
        force: bool,
    },
    /// Coordinator-only: remove a member from a closed network. Prunes it from the
    /// roster + approved list, republishes the signed blob, and disconnects it
    /// mesh-wide. `peer` is a hostname / mesh IP / short id of a current member.
    Kick {
        network: String,
        peer: String,
    },
    /// Coordinator-local: set (or clear) the per-network ephemeral policy — the
    /// TTL after which an offline member is auto-removed. `ttl_secs = None`
    /// disables it. Mutation (root/operator).
    SetEphemeral {
        network: String,
        ttl_secs: Option<u64>,
    },
    /// Read the per-network ephemeral TTL (open read). Answered with
    /// `EphemeralStatus`.
    GetEphemeral {
        network: String,
    },
    /// Response to `GetEphemeral`: the network's current TTL (`None` = off).
    EphemeralStatus {
        network: String,
        ttl_secs: Option<u64>,
    },
    Status,
    /// Build a diagnostic bundle (logs + metrics + sanitized status) on disk and
    /// return its path plus a pre-filled GitHub issue title/body. Open to any
    /// local user, like `Status`.
    Report,
    Shutdown,
    /// Activate the VPN: bring the TUN interface up, configure system DNS, and
    /// reconnect all saved networks. Handled by the already-running daemon, so
    /// no root privileges are needed on the client. An optional `hostname` sets
    /// the personal default hostname used for future creates/joins.
    Up {
        #[serde(default)]
        hostname: Option<String>,
    },
    /// Put the daemon on standby: tear down active network connections, revert
    /// system DNS, and bring the TUN interface down. The daemon process keeps
    /// running so it can be reactivated with `Up`.
    Down,
    FirewallAdd {
        direction: Direction,
        action: Action,
        protocol: Protocol,
        port: Option<String>,
        peer: Option<String>,
        #[serde(default)]
        network: Option<String>,
    },
    FirewallRemove {
        index: usize,
    },
    FirewallShow,
    FirewallDefault {
        action: Action,
    },
    /// Toggle "fail fast" REJECT mode (opt-in, default off): when on, a denied
    /// packet gets a TCP RST / ICMP-unreachable reply instead of a silent drop.
    FirewallReject {
        enabled: bool,
    },
    /// Global firewall kill switch (`ray firewall on|off`). When `enabled` is
    /// false the firewall stops enforcing and allows every packet.
    FirewallSetEnabled {
        enabled: bool,
    },
    /// Coordinator-only: replace the network's suggested firewall rules and
    /// republish the signed blob. Authority comes from holding the network's
    /// secret key; works on any network (suggestions are advisory).
    FirewallSuggest {
        network: String,
        suggestions: SuggestedFirewall,
    },
    /// Read the current suggested firewall rules for a network (open, like other
    /// reads). Used by `ray firewall suggest` (read-modify-write) and `ray apply`.
    FirewallSuggestions {
        network: String,
    },
    /// Read the suggested rules queued for manual review on a network (a node that
    /// did not opt into `--auto-accept-firewall`). Open read, like `FirewallShow`.
    FirewallPending {
        network: String,
    },
    /// Toggle per-network auto-accept of coordinator-suggested firewall rules.
    /// `on` immediately installs the queued set; `off` stops future auto-install.
    FirewallAutoAccept {
        network: String,
        enabled: bool,
    },
    /// Toggle per-network auto-accept of incoming file offers from our own
    /// paired devices. `on` also drains any already-queued offers from own
    /// devices; `off` stops future auto-accept.
    FilesAutoAccept {
        network: String,
        enabled: bool,
    },
    /// Accept the queued suggested rules for a network: install them (replacing
    /// the prior `Network(net)` set) and clear the queue.
    FirewallAccept {
        network: String,
    },
    /// Discard the queued suggested rules for a network without installing them.
    FirewallDeny {
        network: String,
    },
    /// Resolve individual queued suggestions (from the interactive picker):
    /// install the `accept` views and drop both `accept`+`deny` from the queue.
    /// Matching is by view value, so it's robust to queue reordering.
    FirewallResolveSuggestions {
        network: String,
        accept: Vec<FirewallRuleView>,
        deny: Vec<FirewallRuleView>,
    },
    /// Toggle the embedded mesh SSH server (`ray firewall ssh on|off`). When on,
    /// the daemon listens on each mesh IP's port 22 and admits peers authorized
    /// per-network; off stops the listeners and removes the tcp:22 passthrough.
    FirewallSshSet {
        enabled: bool,
    },
    /// Add (`allow=true`) or remove (`allow=false`) a peer from a network's SSH
    /// allow list. `peer` is a resolved peer EndpointId (hex) or `"*"` (any peer
    /// on the network). `users` are the local accounts the peer may log in as on
    /// allow (empty = any non-root user, `"*"` = any incl. root); ignored on
    /// deny, which drops the peer's rule. `ray firewall ssh allow|deny <net> <peer>`.
    FirewallSshAllow {
        network: String,
        peer: String,
        #[serde(default)]
        users: Vec<String>,
        allow: bool,
    },
    /// Read the SSH server state + per-network allow lists (open read).
    FirewallSshShow,
    /// Add (`allow=true`) or remove (`allow=false`) a peer from a network's
    /// exit-node allow list (`ray exit-node allow|disallow <net> <peer>`). `peer`
    /// is a resolved peer identity (hex) or `"*"` (any member). A non-empty list
    /// makes this node offer itself as an exit node and gates real forwarding;
    /// the daemon also advertises the offer in the signed blob. Mutating.
    ExitNodeAllow {
        network: String,
        peer: String,
        allow: bool,
    },
    /// Select (`peer = Some`) or clear (`peer = None`) the exit node this node
    /// routes all non-mesh traffic through (`ray exit-node use|none <net>`).
    /// `peer` is a hostname / mesh IP / short id, validated against the roster
    /// (must advertise `exit_node`). Mutating; takes effect on the next `ray up`.
    ExitNodeUse {
        network: String,
        peer: Option<String>,
    },
    /// Read exit-node state: this node's own offer (allow list) and selection per
    /// network, plus which roster peers advertise `exit_node` (open read).
    ExitNodeStatus {
        network: Option<String>,
    },
    SetHostname {
        network: String,
        hostname: String,
    },
    /// Bind a local, per-network alias to a user/device identity (`ray alias set`).
    /// Node-local only: never rides the signed blob. `identity` is already
    /// canonicalized to the string `ray identityof` prints. Mutating (root/operator).
    AliasSet {
        network: String,
        identity: String,
        alias: String,
    },
    /// Remove a local alias by its name (`ray alias rm`). Mutating.
    AliasRemove {
        network: String,
        alias: String,
    },
    /// List a network's local aliases (`ray alias list`). Open read.
    AliasList {
        network: String,
    },
    /// Response to `AliasList`: `alias name -> identity string`.
    AliasListResponse {
        aliases: BTreeMap<String, String>,
    },
    SendFile {
        path: String,
        peer: String,
    },
    /// Send a file to a peer, passing the already-open file as an SCM_RIGHTS
    /// descriptor on the same connection (see [`send_with_fd`]). The client
    /// opens the file with its own privileges, so filesystem permissions and
    /// macOS TCC grants apply to the caller, not to the root daemon. `SendFile`
    /// stays for frontends that cannot pass descriptors.
    SendFileFd {
        filename: String,
        peer: String,
    },
    ListFiles,
    /// Cancel a queued outbound send (`ray files cancel <id>`). Only reaches
    /// sends still waiting in the outbox; a delivered offer is the peer's now.
    CancelSend {
        id: u64,
    },
    AcceptFile {
        id: u64,
        output: Option<String>,
    },
    StartPairing,
    PairWithDevice {
        endpoint_id: EndpointId,
        secret: Vec<u8>,
    },
    /// List this user's paired devices (enumerated from the network rosters).
    /// Reply: [`IpcMessage::PairedDevices`].
    ListPairedDevices,
    /// Revoke one of this user's paired devices (`ray unpair`). Primary-only.
    /// Publishes a signed revocation record, drops the device locally, severs it
    /// from networks this node coordinates, and best-effort signals the device to
    /// wipe its own cert. Reply: [`IpcMessage::Ok`] / [`IpcMessage::Error`].
    Unpair {
        /// Device identifier: hostname, mesh IP, short id, or full endpoint id.
        device: String,
    },
    /// Authorize a local user (by UID) to control the daemon without root, the
    /// way `tailscale up --operator` does. Root-only.
    SetOperator {
        uid: u32,
    },
    /// Mint an invite for a closed network (coordinator / network-key holder only).
    InviteCreate {
        network: String,
        expires_secs: u64,
        /// Hostname the coordinator assigns authoritatively on redemption
        /// (single-use only; rejected together with `reusable`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        /// Mint a reusable (multi-use, expiring) key that rides the signed blob,
        /// so any network-key holder can admit. Hostname is not authoritative.
        #[serde(default)]
        reusable: bool,
    },
    /// List invites for a network (coordinator-only).
    InviteList {
        network: String,
    },
    /// Revoke an unused invite by id (coordinator-only).
    InviteRevoke {
        network: String,
        id: String,
    },
    /// List peers awaiting live approval on a closed network (coordinator-only).
    Requests {
        network: String,
    },
    /// Admit a pending peer by short id (coordinator-only).
    AcceptRequest {
        network: String,
        id: String,
    },
    /// Drop a pending peer's join request by short id (coordinator-only).
    DenyRequest {
        network: String,
        id: String,
    },
    /// Coordinator-only: grant the per-network secret key to a member, making it
    /// a co-coordinator (can publish / suggest firewall rules).
    AdminAdd {
        network: String,
        identity: String,
    },
    /// List the identities this coordinator has granted the network key to
    /// (plus itself). Open read.
    AdminList {
        network: String,
    },
    /// `ray connect <contact-id>`: request a direct 2-peer connection by the
    /// recipient's contact id. Resolves the contact id to an endpoint, dials the
    /// connect ALPN, and waits (recipient-only approval).
    Connect {
        contact_id: String,
        hostname: Option<String>,
    },
    /// `ray connections`: list pending incoming connect requests. Open read.
    Connections,
    /// `ray connections approve <id>`: approve a pending connect request by short
    /// id, minting a 2-peer network with the requester pre-approved.
    ApproveConnection {
        id: String,
    },
    /// `ray contact id`: print this node's contact id. Open read.
    ContactId,
    /// `ray contact rotate`: rotate this node's contact key (old id stops
    /// resolving once its pkarr record expires).
    RotateContact,
    /// `ray ping <peer>`: active liveness probe. Resolves `peer`, sends `count`
    /// echo probes over the mesh connection, and returns per-probe RTTs. Open
    /// read, like `Status`.
    Ping {
        peer: String,
        count: u32,
        interval_ms: u64,
    },
    /// `ray netcheck`: local endpoint diagnostics (bound port, home relay,
    /// reachability). Open read.
    Netcheck,
    /// Persist the mDNS discovery toggle (`ray mdns on|off`). Routed through the
    /// daemon (not written client-side) so the setting always lands in the config
    /// dir the daemon reads: on non-Linux, `config_dir()` is derived from the
    /// process environment, so a client-side write from a different `HOME` than
    /// the service's would silently miss the daemon's config. The daemon reads
    /// this at startup, so it takes effect on restart. Mutation (root/operator).
    SetMdns {
        enabled: bool,
    },
    /// Set a global config key (`ray config set`, `ray auto-update on|off`). The
    /// daemon applies it to its own config and persists it. `value` uses the same
    /// grammar as `config::config_set`. Same routing rationale as `SetMdns`.
    /// Mutation.
    ConfigSet {
        key: String,
        value: String,
        #[serde(default)]
        replace: bool,
    },
    /// Reset a global config key to its default (`ray config unset`). Mutation.
    ConfigUnset {
        key: String,
    },
    /// Read global config keys (`ray config get`), answered with `ConfigValues`.
    /// `key = None` returns every key. Open read, like `Status` — routed through
    /// the daemon so reads and writes agree on which config dir is authoritative.
    ConfigGet {
        key: Option<String>,
    },
    /// Set (or clear, with `None`) the directory accepted files land in
    /// (`ray files download-dir`). Same daemon-writes-its-own-config rationale as
    /// `SetMdns`; the path is validated absolute on the client. Mutation.
    SetDownloadDir {
        path: Option<String>,
    },
    /// Set (or clear, with `None`) the local UID that owns accepted files
    /// (`ray files download-user`). The client resolves the username to a UID
    /// (as it does for `SetOperator`) before sending. Mutation.
    SetDownloadUser {
        uid: Option<u32>,
    },
    /// Read the file-download settings (`ray files download-dir`/`download-user`
    /// with no argument), answered with `DownloadSettings`. Open read.
    GetDownloadSettings,

    // Responses
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
    Created {
        name: String,
        network_key: EndpointId,
        my_ip: Ipv4Addr,
        my_ipv6: Option<Ipv6Addr>,
    },
    Joined {
        name: String,
        my_ip: Ipv4Addr,
        my_ipv6: Option<Ipv6Addr>,
    },
    StatusResponse {
        endpoint_id: EndpointId,
        mdns_enabled: bool,
        /// Whether this node opted into automatic stable updates. Reflects the
        /// running daemon's setting (which can differ from on-disk config until a
        /// restart). Defaulted so an older CLI/daemon pair still deserializes.
        #[serde(default)]
        auto_update: bool,
        /// Whether the VPN is active (TUN up, networks connected) or on standby.
        active: bool,
        /// This node's contact id (`ray connect`), shown at the top of status.
        /// `None` if the daemon has not generated one yet.
        #[serde(default)]
        contact_id: Option<String>,
        /// The running daemon's compiled version (`CARGO_PKG_VERSION`). The CLI
        /// compares it to its own version and hints `ray update` on a mismatch
        /// — e.g. after a self-update where the daemon never restarted onto the
        /// new binary. Empty when talking to a daemon predating this field.
        #[serde(default)]
        daemon_version: String,
        networks: Vec<NetworkStatus>,
        packets_rx: u64,
        packets_tx: u64,
        bytes_rx: u64,
        bytes_tx: u64,
        /// Incoming file offers awaiting `ray files accept` (global, not
        /// per-network). Shown in the status "pending" summary.
        #[serde(default)]
        pending_files: usize,
        /// Incoming `ray connect` requests awaiting `ray connections approve`
        /// (global). Shown in the status "pending" summary.
        #[serde(default)]
        pending_connects: usize,
        /// Networks this node has asked to join but has not yet been admitted
        /// to (persisted `AppConfig.pending_joins`), minus any that are now
        /// active. Shown in the UI as "waiting for approval".
        #[serde(default)]
        pending_networks: Vec<String>,
    },
    /// Reply to `Ping`. `probes` holds one entry per probe in send order: the
    /// measured round-trip in milliseconds, or `None` if that probe timed out.
    PingResponse {
        /// Resolved display name for the peer (hostname if known, else short id).
        peer_name: String,
        conn_type: ConnType,
        remote_addr: Option<String>,
        /// Network whose connection the probes traversed.
        network: String,
        probes: Vec<Option<f64>>,
    },
    /// Reply to `Netcheck`. Local endpoint diagnostics. Fields the underlying
    /// iroh API does not reliably expose are left `None` rather than guessed.
    NetcheckResponse {
        /// Bound UDP port of the shared endpoint.
        bound_port: u16,
        /// True when the bound port is the fixed `RAYFISH_LISTEN_PORT` (manually
        /// forwardable); false when the daemon fell back to an ephemeral port.
        port_is_fixed: bool,
        /// Home relay URL the endpoint currently prefers.
        home_relay: Option<String>,
        /// Round-trip to the home relay, if measurable.
        relay_latency_ms: Option<f64>,
        /// Observed public IPv4 / mapped address, if known.
        public_ipv4: Option<String>,
        /// Observed public IPv6 address, if known.
        public_ipv6: Option<String>,
        /// Whether UDP appears to work (the endpoint has a usable direct path).
        udp: bool,
    },
    /// The device's local firewall (reply to `FirewallShow`). Structured so the
    /// CLI renders it with color on the *user's* TTY and serializes it for
    /// `--json`.
    FirewallState {
        /// Default action for inbound traffic that matches no explicit rule.
        /// (Inbound ICMP is always allowed-by-default regardless of this.)
        default_inbound: Action,
        /// Default action for outbound traffic that matches no explicit rule.
        default_outbound: Action,
        /// "Fail fast" REJECT mode (opt-in, default off): when on, denied packets
        /// get a TCP RST / ICMP-unreachable reply instead of a silent drop.
        #[serde(default)]
        reject: bool,
        /// Global kill switch (`ray firewall off`). When true the firewall is not
        /// enforcing: every packet is allowed regardless of rules/defaults.
        #[serde(default)]
        disabled: bool,
        rules: Vec<FirewallRuleView>,
    },
    /// Current suggested firewall rules for a network (reply to
    /// `FirewallSuggestions`).
    FirewallSuggestionsResponse {
        suggestions: SuggestedFirewall,
    },
    /// Materialized suggested rules queued for manual review on a network (reply
    /// to `FirewallPending`). The CLI renders these as an interactive picker on a
    /// TTY, or a static table otherwise.
    FirewallPendingResponse {
        network: String,
        rules: Vec<FirewallRuleView>,
    },
    /// Embedded mesh SSH state (reply to `FirewallSshShow`): whether the server
    /// is enabled, and each network's allow list.
    FirewallSshState {
        enabled: bool,
        /// `(network, allow-entries)` for networks with at least one rule.
        networks: Vec<(String, Vec<SshAllowView>)>,
    },
    /// Exit-node state (reply to `ExitNodeStatus`): one entry per network.
    ExitNodeState {
        networks: Vec<ExitNodeStatusView>,
    },
    FileList {
        files: Vec<PendingFileInfo>,
        /// Outbound sends queued for delivery (peer offline). Absent on daemons
        /// that predate queued sends.
        #[serde(default)]
        outbox: Vec<OutboxFileInfo>,
    },
    PairingTicket {
        ticket: String,
    },
    PairingComplete {
        user_identity: EndpointId,
    },
    /// This user's paired devices (reply to `ListPairedDevices`).
    PairedDevices {
        devices: Vec<PairedDeviceInfo>,
    },
    /// A diagnostic bundle was written to `path` (a `.tgz`, owned by the caller).
    /// `issue_title`/`issue_body` pre-fill a GitHub issue; the user attaches the
    /// bundle file manually.
    ReportBundle {
        path: String,
        issue_title: String,
        issue_body: String,
    },
    /// An invite was minted; `code` is the shareable invite string.
    InviteCreated {
        code: String,
        id: String,
        expires_secs: u64,
    },
    /// The list of invites for a network.
    InviteListResponse {
        invites: Vec<InviteInfo>,
    },
    /// The list of peers awaiting live approval.
    PendingRequests {
        requests: Vec<PendingRequestInfo>,
    },
    /// The list of network key-holders (reply to `AdminList`): the local node
    /// plus every identity it has granted the key to.
    AdminListResponse {
        admins: Vec<AdminInfo>,
    },
    /// This node's contact id (reply to `ContactId`/`RotateContact`).
    ContactIdResponse {
        contact_id: String,
    },
    /// Reply to `ConfigGet`: `(key, value)` rows as `config::config_get` renders.
    ConfigValues {
        rows: Vec<(String, String)>,
    },
    /// Reply to `GetDownloadSettings`: the daemon's current file-download config.
    DownloadSettings {
        dir: Option<String>,
        uid: Option<u32>,
    },
}

/// A display-oriented view of one firewall rule, sent over IPC so the CLI can
/// render (with color) and serialize (`--json`) without depending on the
/// daemon-side `firewall::FirewallRule` type. All fields are pre-stringified;
/// `PartialEq`/`Eq`/`Hash` let the daemon value-match views back to queued rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FirewallRuleView {
    pub direction: Direction,
    pub action: Action,
    pub protocol: Protocol,
    /// Port or range: `"443"`, `"8000-9000"`, or `"*"`.
    pub port: String,
    /// `"any"` or a peer's short id.
    pub peer: String,
    /// `"any"` or a network name.
    pub network: String,
    /// `Some(net)` if this rule was suggested by network `net`; `None` if local.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_by: Option<String>,
}

/// One mesh-SSH allow entry as shown by `ray firewall ssh show`. `peer` is `"*"`
/// or a peer identity (hex); `users` is the permitted login accounts (empty =
/// any non-root user, `"*"` = any incl. root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshAllowView {
    pub peer: String,
    pub users: Vec<String>,
}

/// Exit-node state for one network as shown by `ray exit-node status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitNodeStatusView {
    pub network: String,
    /// This node's own allow list (`ray exit-node allow`): `"*"` or peer
    /// identities. Non-empty means this node offers itself as an exit node.
    pub allow: Vec<String>,
    /// The exit peer this node routes non-mesh traffic through (`ray exit-node
    /// use`), as a display string, or `None` for direct egress.
    pub using: Option<String>,
    /// Roster peers advertising `exit_node` (display strings: hostname or short
    /// id), so the user can see who is available to route through.
    pub available: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminInfo {
    /// Short id of the key-holder.
    pub short_id: String,
    /// `true` if this is the local node.
    pub self_node: bool,
}

/// One of this user's paired secondary devices (reply to `ListPairedDevices`),
/// enumerated from the network rosters as members whose `user_identity` is ours
/// but whose device id is not.
#[derive(Debug, Serialize, Deserialize)]
pub struct PairedDeviceInfo {
    /// The device's transport endpoint id (what `ray unpair` revokes).
    pub device_id: EndpointId,
    /// Short id form for display.
    pub short_id: String,
    /// The device's hostname if known from any roster.
    pub hostname: Option<String>,
    /// Networks this device is currently a member of.
    pub networks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteInfo {
    pub id: String,
    /// One of `pending`, `redeemed`, `revoked`, `expired`.
    pub status: String,
    pub created: u64,
    pub expires: u64,
    pub redeemer: Option<String>,
    /// Hostname assigned authoritatively on redemption (single-use invites only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// True for a reusable (multi-use) key; false for a single-use invite.
    #[serde(default)]
    pub reusable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingRequestInfo {
    pub short_id: String,
    pub hostname: Option<String>,
    pub waiting_secs: u64,
}

/// An outbound send waiting in the daemon's outbox for its peer to come online.
#[derive(Debug, Serialize, Deserialize)]
pub struct OutboxFileInfo {
    pub id: u64,
    /// The peer name as given to `ray send` (hostname or short id).
    pub peer: String,
    pub filename: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingFileInfo {
    pub id: u64,
    pub from: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
    /// True when the sender resolves to one of the recipient's own paired
    /// devices (used by the mobile UI to auto-accept own-device offers).
    #[serde(default)]
    pub own_device: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub name: String,
    pub role: NetworkRole,
    pub my_ip: Ipv4Addr,
    pub my_ipv6: Option<Ipv6Addr>,
    pub my_hostname: Option<String>,
    pub network_key: Option<String>,
    pub member_count: usize,
    pub peers: Vec<PeerStatus>,
    /// Suggested firewall rules queued for review on this node for this network
    /// (`ray firewall pending <net>`). Surfaced in the status summary.
    #[serde(default)]
    pub pending_suggestions: usize,
    /// Peers awaiting live approval on this network — coordinator-only
    /// (`ray requests <net>` / `ray accept`). Surfaced in the status summary.
    #[serde(default)]
    pub pending_requests: usize,
    /// Node-local aliases for this network (`alias name -> identity string`,
    /// set via `ray alias`). Display-only and never in the signed blob; also
    /// seeds `ray apply`'s `aliases:` map.
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
    /// Per-network ephemeral auto-kick TTL in seconds, if the policy is on
    /// (`ray ephemeral <net> <dur>`). `None` = off. Shown on the network line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_ttl_secs: Option<u64>,
    /// The exit peer this node routes non-mesh traffic through on this network
    /// (`ray exit-node use`), as a display string, or `None` for direct egress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub my_exit_node: Option<String>,
    /// True when this node offers itself as an exit node on this network (its
    /// `exit_allow` list is non-empty). Without it, `ray status` would show every
    /// peer's exit offer but never your own.
    #[serde(default)]
    pub exit_offering: bool,
}

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, derive_more::IsVariant, derive_more::Display,
)]
pub enum NetworkRole {
    #[display("coordinator")]
    Coordinator,
    #[display("member")]
    Member,
    /// An auto-minted 2-peer direct connection (`ray connect`). Display-only: the
    /// node is structurally still the coordinator or a member, but `ray status`
    /// surfaces these as `direct` and hides the (non-shareable) room id.
    #[display("direct")]
    Direct,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub endpoint_id: EndpointId,
    pub ip: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub hostname: Option<String>,
    pub user_identity: Option<EndpointId>,
    /// True when this peer is another of the local user's own paired devices
    /// (its resolved user identity equals ours).
    #[serde(default)]
    pub is_own_device: bool,
    /// True when a mesh dial to this peer last failed because it speaks an
    /// incompatible mesh protocol version (the ALPN gate rejected it). Such a
    /// peer can't connect and would otherwise look identical to a plain offline
    /// peer; status flags it so the user knows to run `ray update`. Cleared on any
    /// successful (re)connection.
    #[serde(default)]
    pub incompatible: bool,
    pub connection: Option<ConnectionInfo>,
    /// Coarse liveness for the three-state display (Tailscale-style). `Active`
    /// when a live connection exists; `Offline` only after an actual reach attempt
    /// failed and no later success cleared it; `Idle` otherwise (a known roster
    /// member we simply have no live link to). On-demand nodes hold no connections
    /// when idle, so a bare `connection.is_none()` must read as `Idle`, not offline.
    #[serde(default)]
    pub state: PeerState,
    /// True when this peer advertises itself as an exit node on this network
    /// (`Member.exit_node` in the signed roster). Shown as a badge in status.
    #[serde(default)]
    pub exit_node: bool,
    /// True when this is the peer we currently route our internet traffic through
    /// (`ray exit-node use`). Distinguishes the one exit node actually carrying our
    /// traffic from the others that merely offer.
    #[serde(default)]
    pub exit_in_use: bool,
}

/// Three-state peer liveness for `ray status`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, derive_more::IsVariant,
)]
pub enum PeerState {
    /// A live mesh connection to the peer exists right now.
    Active,
    /// No live connection, but no failed reach either: presumed reachable (dialed
    /// lazily on demand). The optimistic default for a freshly booted node.
    #[default]
    Idle,
    /// A recent reach attempt failed and wasn't cleared by a later success.
    Offline,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub conn_type: ConnType,
    pub remote_addr: Option<String>,
    pub rtt_ms: Option<f64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub datagrams_tx: u64,
    pub datagrams_rx: u64,
    pub lost_packets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, derive_more::IsVariant)]
pub enum ConnType {
    Direct,
    Relay,
    Tor,
    Unknown,
}

/// Maximum IPC frame size (body). Matches the previous hand-rolled guard;
/// `LengthDelimitedCodec` rejects anything larger so a malformed/hostile peer
/// can't make us allocate an unbounded buffer.
const MAX_FRAME_LEN: usize = 1_048_576;

/// A codec that frames msgpack-serialized `T`s using tokio's
/// [`LengthDelimitedCodec`] (a 4-byte big-endian length prefix — the wire format
/// is unchanged, so this stays compatible with the previous hand-rolled
/// framing). Framing is delegated to the battle-tested tokio codec; this layer
/// only does the msgpack (de)serialization on top of each length-delimited
/// frame.
///
/// Structs are serialized with `to_vec_named` (field-name maps, not positional
/// arrays) — required for correctness when a struct uses `skip_serializing_if`:
/// with positional arrays, skipping a field shifts later fields into the wrong
/// slot on decode (e.g. `HostSuggestions` with `default: None` + non-empty
/// `allows` misaligns and fails with "invalid type: map, expected a string").
/// The decoder (`from_slice`) handles both named and unnamed representations,
/// so it's forward-compatible with older peers.
pub struct MsgpackCodec<T> {
    framed: LengthDelimitedCodec,
    _t: PhantomData<T>,
}

impl<T> MsgpackCodec<T> {
    pub fn new() -> Self {
        Self {
            framed: LengthDelimitedCodec::builder()
                .length_field_length(4)
                .max_frame_length(MAX_FRAME_LEN)
                .new_codec(),
            _t: PhantomData,
        }
    }
}

impl<T> Default for MsgpackCodec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Serialize> Encoder<T> for MsgpackCodec<T> {
    type Error = anyhow::Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<()> {
        let body = rmp_serde::to_vec_named(&item).context("serialize IPC message")?;
        self.framed
            .encode(Bytes::from(body), dst)
            .context("frame IPC message")?;
        Ok(())
    }
}

impl<T: DeserializeOwned> Decoder for MsgpackCodec<T> {
    type Item = T;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<T>> {
        match self.framed.decode(src).context("frame IPC message")? {
            Some(frame) => Ok(Some(
                rmp_serde::from_slice(&frame).context("decode IPC message")?,
            )),
            None => Ok(None),
        }
    }
}

pub type IpcFramed = Framed<UnixStream, MsgpackCodec<IpcMessage>>;

pub fn socket_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/rayfish.sock")
    } else {
        PathBuf::from("/var/run/rayfish/rayfish.sock")
    }
}

pub async fn connect() -> Result<IpcFramed> {
    let path = socket_path();
    let stream = UnixStream::connect(&path)
        .await
        .context("daemon not running — start it with: sudo rayfish daemon")?;
    Ok(Framed::new(stream, MsgpackCodec::new()))
}

pub fn framed(stream: UnixStream) -> IpcFramed {
    Framed::new(stream, MsgpackCodec::new())
}

pub async fn send(framed: &mut IpcFramed, msg: IpcMessage) -> Result<()> {
    use futures::SinkExt;
    framed.send(msg).await
}

pub async fn recv(framed: &mut IpcFramed) -> Result<IpcMessage> {
    use futures::StreamExt;
    framed.next().await.context("connection closed")?
}

/// Cap on SCM_RIGHTS descriptors accepted per request. One is all any message
/// uses today; the cap keeps a hostile client from stuffing the daemon's fd
/// table through a single connection.
pub const MAX_IPC_FDS: usize = 4;

/// Send `msg` as a normal length-prefixed frame with `fd` attached to its
/// first byte as SCM_RIGHTS ancillary data. The receiver must read with
/// [`recv_with_fds`]: a plain `read()` consumes the bytes but silently drops
/// the descriptor.
pub async fn send_with_fd(stream: &UnixStream, msg: &IpcMessage, fd: BorrowedFd<'_>) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let body = rmp_serde::to_vec_named(msg).context("serialize IPC message")?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
    frame.extend_from_slice(&body);

    let mut sent = 0;
    let mut fd_sent = false;
    while sent < frame.len() {
        let n = stream
            .async_io(Interest::WRITABLE, || {
                let iov = [IoSlice::new(&frame[sent..])];
                let fds = [fd.as_raw_fd()];
                // The descriptor rides the first sendmsg that accepts bytes;
                // continuation writes after a partial send carry no ancillary.
                let cmsgs: &[ControlMessage] = if fd_sent {
                    &[]
                } else {
                    &[ControlMessage::ScmRights(&fds)]
                };
                sendmsg::<()>(stream.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None)
                    .map_err(std::io::Error::from)
            })
            .await?;
        fd_sent = true;
        sent += n;
    }
    Ok(())
}

/// Read one request frame, capturing any SCM_RIGHTS descriptors delivered
/// with it. The daemon reads every request through this (not through the
/// framed codec) because ancillary data is only surfaced by `recvmsg` with a
/// control buffer; any other read on the socket would drop the descriptors.
pub async fn recv_with_fds(stream: &UnixStream) -> Result<(IpcMessage, Vec<OwnedFd>)> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

    let mut buf: Vec<u8> = Vec::new();
    let mut fds: Vec<OwnedFd> = Vec::new();
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            if len > MAX_FRAME_LEN {
                anyhow::bail!("IPC frame too large ({len} bytes)");
            }
            if buf.len() >= 4 + len {
                let msg = rmp_serde::from_slice(&buf[4..4 + len]).context("decode IPC message")?;
                return Ok((msg, fds));
            }
        }

        let mut chunk = [0u8; 8192];
        let (n, mut got) = stream
            .async_io(Interest::READABLE, || {
                let mut iov = [IoSliceMut::new(&mut chunk)];
                let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_IPC_FDS]);
                // CLOEXEC on Linux/Android so a received fd never leaks into a
                // spawned child; macOS has no MSG_CMSG_CLOEXEC.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                let flags = MsgFlags::MSG_CMSG_CLOEXEC;
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                let flags = MsgFlags::empty();
                let msg = recvmsg::<()>(stream.as_raw_fd(), &mut iov, Some(&mut cmsg_buf), flags)
                    .map_err(std::io::Error::from)?;
                let mut received = Vec::new();
                for cmsg in msg.cmsgs().map_err(std::io::Error::from)? {
                    if let ControlMessageOwned::ScmRights(raw) = cmsg {
                        // SAFETY: the kernel just installed these descriptors in
                        // our fd table for this process; we are their sole owner.
                        received.extend(raw.iter().map(|&r| unsafe { OwnedFd::from_raw_fd(r) }));
                    }
                }
                Ok((msg.bytes, received))
            })
            .await?;
        if n == 0 {
            anyhow::bail!("connection closed mid-frame");
        }
        buf.extend_from_slice(&chunk[..n]);
        fds.append(&mut got);
        if fds.len() > MAX_IPC_FDS {
            // Dropping the OwnedFds closes everything the client pushed.
            anyhow::bail!("too many file descriptors in IPC request");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let req = IpcMessage::Create {
            mode: GroupMode::Open,
            name: None,
            hostname: None,
            transport: None,
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::Create { mode, .. } => {
                assert_eq!(mode, GroupMode::Open);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn send_file_fd_roundtrip() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsFd;

        let (client, server) = UnixStream::pair().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"payload bytes").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let msg = IpcMessage::SendFileFd {
            filename: "report.pdf".to_string(),
            peer: "peer1".to_string(),
        };
        send_with_fd(&client, &msg, file.as_fd()).await.unwrap();

        let (decoded, fds) = recv_with_fds(&server).await.unwrap();
        match decoded {
            IpcMessage::SendFileFd { filename, peer } => {
                assert_eq!(filename, "report.pdf");
                assert_eq!(peer, "peer1");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(fds.len(), 1);

        let mut received = std::fs::File::from(fds.into_iter().next().unwrap());
        let mut contents = String::new();
        received.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "payload bytes");
    }

    #[tokio::test]
    async fn recv_with_fds_handles_plain_frames() {
        use futures::SinkExt;

        let (client, server) = UnixStream::pair().unwrap();
        let mut framed = framed(client);
        framed.send(IpcMessage::Status).await.unwrap();

        let (decoded, fds) = recv_with_fds(&server).await.unwrap();
        assert!(matches!(decoded, IpcMessage::Status));
        assert!(fds.is_empty());
    }

    #[tokio::test]
    async fn send_file_fd_survives_multi_chunk_frames() {
        use std::os::fd::AsFd;

        let (client, server) = UnixStream::pair().unwrap();
        let file = tempfile::tempfile().unwrap();

        // A frame much larger than the 8 KiB recv chunk, so the descriptor
        // (attached to the first bytes) must survive a multi-read assembly.
        let msg = IpcMessage::SendFileFd {
            filename: "x".repeat(100 * 1024),
            peer: "peer1".to_string(),
        };
        let send = send_with_fd(&client, &msg, file.as_fd());
        let recv = recv_with_fds(&server);
        let (sent, received) = tokio::join!(send, recv);
        sent.unwrap();
        let (decoded, fds) = received.unwrap();
        match decoded {
            IpcMessage::SendFileFd { filename, .. } => assert_eq!(filename.len(), 100 * 1024),
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(fds.len(), 1);
    }

    #[test]
    fn exit_node_requests_roundtrip() {
        for req in [
            IpcMessage::ExitNodeAllow {
                network: "n".into(),
                peer: "*".into(),
                allow: true,
            },
            IpcMessage::ExitNodeUse {
                network: "n".into(),
                peer: Some("host".into()),
            },
            IpcMessage::ExitNodeUse {
                network: "n".into(),
                peer: None,
            },
            IpcMessage::ExitNodeStatus { network: None },
        ] {
            let bytes = rmp_serde::to_vec_named(&req).unwrap();
            let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(format!("{req:?}"), format!("{decoded:?}"));
        }
    }

    #[test]
    fn exit_node_state_roundtrips() {
        let resp = IpcMessage::ExitNodeState {
            networks: vec![ExitNodeStatusView {
                network: "n".into(),
                allow: vec!["*".into()],
                using: Some("gw".into()),
                available: vec!["gw".into()],
            }],
        };
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::ExitNodeState { networks } => {
                assert_eq!(networks.len(), 1);
                assert_eq!(networks[0].using.as_deref(), Some("gw"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn firewall_suggest_roundtrips_through_named_codec() {
        // Regression: with positional-array (`to_vec`) serialization, a
        // `HostSuggestions` whose `default` is `None` (skipped) but whose
        // `allows` is non-empty misaligns on decode and fails with
        // "invalid type: map, expected a string". The codec must serialize
        // structs as named maps so `skip_serializing_if` is safe.
        use crate::policy::HostSuggestions;
        use std::collections::BTreeMap;

        let mut fw: SuggestedFirewall = BTreeMap::new();
        fw.insert(
            "alpha".to_string(),
            HostSuggestions {
                allows: [("beta".to_string(), "22".to_string())].into(),
                denies: BTreeMap::new(),
            },
        );
        fw.insert(
            "gamma".to_string(),
            HostSuggestions {
                allows: [("alpha".to_string(), "8080".to_string())].into(),
                denies: BTreeMap::new(),
            },
        );
        let msg = IpcMessage::FirewallSuggest {
            network: "net1".to_string(),
            suggestions: fw,
        };

        let mut codec = MsgpackCodec::<IpcMessage>::new();
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().expect("frame not complete");
        match decoded {
            IpcMessage::FirewallSuggest {
                network,
                suggestions,
            } => {
                assert_eq!(network, "net1");
                assert_eq!(suggestions.len(), 2);
                let gamma = suggestions.get("gamma").unwrap();
                assert_eq!(gamma.allows.get("alpha").map(|s| s.as_str()), Some("8080"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let key = iroh::SecretKey::generate().public();
        let resp = IpcMessage::Created {
            name: "test".to_string(),
            network_key: key,
            my_ip: Ipv4Addr::new(100, 64, 10, 5),
            my_ipv6: None,
        };
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::Created {
                name,
                network_key,
                my_ip,
                ..
            } => {
                assert_eq!(name, "test");
                assert_eq!(network_key, key);
                assert_eq!(my_ip, Ipv4Addr::new(100, 64, 10, 5));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_report_bundle_roundtrip() {
        let resp = IpcMessage::ReportBundle {
            path: "/tmp/rayfish-report-123.tgz".to_string(),
            issue_title: "[report] diagnostics".to_string(),
            issue_body: "body".to_string(),
        };
        let bytes = rmp_serde::to_vec(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::ReportBundle { path, .. } => {
                assert!(path.ends_with(".tgz"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_invite_create_roundtrip() {
        let req = IpcMessage::InviteCreate {
            network: "gaming".to_string(),
            expires_secs: 604_800,
            hostname: None,
            reusable: true,
        };
        // The IPC codec uses `to_vec_named`; positional encoding can't survive a
        // `skip_serializing_if` field followed by another field.
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::InviteCreate {
                network,
                expires_secs,
                hostname: _,
                reusable,
            } => {
                assert_eq!(network, "gaming");
                assert_eq!(expires_secs, 604_800);
                assert!(reusable);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_invite_list_response_roundtrip() {
        let resp = IpcMessage::InviteListResponse {
            invites: vec![InviteInfo {
                id: "ab3f9c01".to_string(),
                status: "pending".to_string(),
                created: 1000,
                expires: 2000,
                redeemer: None,
                hostname: None,
                reusable: false,
            }],
        };
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::InviteListResponse { invites } => {
                assert_eq!(invites.len(), 1);
                assert_eq!(invites[0].status, "pending");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_join_with_invite_roundtrip() {
        let coord = iroh::SecretKey::generate().public();
        let req = IpcMessage::Join {
            network_key: "abc".to_string(),
            name: None,
            hostname: None,
            transport: None,
            invite: Some(vec![1, 2, 3]),
            coordinator: Some(coord),
            auto_accept_firewall: false,
            auto_accept_files: false,
        };
        let bytes = rmp_serde::to_vec(&req).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::Join {
                invite,
                coordinator,
                ..
            } => {
                assert_eq!(invite, Some(vec![1, 2, 3]));
                assert_eq!(coordinator, Some(coord));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_connect_roundtrip() {
        let req = IpcMessage::Connect {
            contact_id: "contactabc".to_string(),
            hostname: Some("dario".to_string()),
        };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::Connect {
                contact_id,
                hostname,
            } => {
                assert_eq!(contact_id, "contactabc");
                assert_eq!(hostname.as_deref(), Some("dario"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn config_mutation_messages_roundtrip() {
        // `ray mdns off` / `ray config set` route through the daemon; the wire
        // types must survive the named-map codec.
        for msg in [
            IpcMessage::SetMdns { enabled: false },
            IpcMessage::ConfigSet {
                key: "auto-update".to_string(),
                value: "off".to_string(),
                replace: false,
            },
            IpcMessage::ConfigUnset {
                key: "relay".to_string(),
            },
            IpcMessage::ConfigGet { key: None },
            IpcMessage::SetDownloadDir {
                path: Some("/srv/dl".to_string()),
            },
            IpcMessage::SetDownloadUser { uid: Some(501) },
            IpcMessage::GetDownloadSettings,
            IpcMessage::DownloadSettings {
                dir: None,
                uid: None,
            },
        ] {
            let bytes = rmp_serde::to_vec_named(&msg).unwrap();
            let _: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        }

        let resp = IpcMessage::ConfigValues {
            rows: vec![("auto-update".to_string(), "off".to_string())],
        };
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        match rmp_serde::from_slice::<IpcMessage>(&bytes).unwrap() {
            IpcMessage::ConfigValues { rows } => {
                assert_eq!(rows, vec![("auto-update".to_string(), "off".to_string())]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_contact_id_response_roundtrip() {
        let resp = IpcMessage::ContactIdResponse {
            contact_id: "abc123".to_string(),
        };
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::ContactIdResponse { contact_id } => assert_eq!(contact_id, "abc123"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_status_response_roundtrip() {
        let ep_id = iroh::SecretKey::generate().public();
        let peer_id = iroh::SecretKey::generate().public();
        let resp = IpcMessage::StatusResponse {
            endpoint_id: ep_id,
            mdns_enabled: true,
            auto_update: false,
            active: true,
            contact_id: Some("contact123".to_string()),
            daemon_version: "0.1.0".to_string(),
            networks: vec![NetworkStatus {
                name: "gaming".to_string(),
                role: NetworkRole::Coordinator,
                my_ip: Ipv4Addr::new(100, 64, 10, 5),
                my_ipv6: None,
                my_hostname: Some("alice".to_string()),
                network_key: Some("abc123".to_string()),
                member_count: 2,
                peers: vec![PeerStatus {
                    endpoint_id: peer_id,
                    ip: Ipv4Addr::new(100, 64, 10, 6),
                    ipv6: None,
                    hostname: None,
                    user_identity: None,
                    is_own_device: false,
                    incompatible: false,
                    connection: None,
                    state: PeerState::Idle,
                    exit_node: false,
                    exit_in_use: false,
                }],
                pending_suggestions: 0,
                pending_requests: 0,
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                my_exit_node: None,
                exit_offering: false,
            }],
            packets_rx: 0,
            packets_tx: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            pending_files: 0,
            pending_connects: 0,
            pending_networks: vec![],
        };
        // The IPC codec uses `to_vec_named`; positional encoding can't survive
        // NetworkStatus's `skip_serializing_if` fields (ephemeral_ttl_secs,
        // my_exit_node) sitting ahead of exit_offering.
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::StatusResponse {
                endpoint_id,
                networks,
                ..
            } => {
                assert_eq!(endpoint_id, ep_id);
                assert_eq!(networks.len(), 1);
                assert_eq!(networks[0].peers[0].endpoint_id, peer_id);
            }
            _ => panic!("wrong variant"),
        }
    }
}
