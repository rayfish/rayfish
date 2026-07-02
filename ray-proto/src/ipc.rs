use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use iroh::EndpointId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
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
    ListFiles,
    AcceptFile {
        id: u64,
        output: Option<String>,
    },
    StartPairing,
    PairWithDevice {
        endpoint_id: EndpointId,
        secret: Vec<u8>,
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
    FileList {
        files: Vec<PendingFileInfo>,
    },
    PairingTicket {
        ticket: String,
    },
    PairingComplete {
        user_identity: EndpointId,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminInfo {
    /// Short id of the key-holder.
    pub short_id: String,
    /// `true` if this is the local node.
    pub self_node: bool,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingFileInfo {
    pub id: u64,
    pub from: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
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
    pub connection: Option<ConnectionInfo>,
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
                    connection: None,
                }],
                pending_suggestions: 0,
                pending_requests: 0,
                aliases: BTreeMap::new(),
            }],
            packets_rx: 0,
            packets_tx: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            pending_files: 0,
            pending_connects: 0,
        };
        let bytes = rmp_serde::to_vec(&resp).unwrap();
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
