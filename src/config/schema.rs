//! The shape of the persisted config: per-network and global entries, the
//! enums they hold, and the helpers that resolve their relay, discovery and
//! DNS overrides.

use super::*;

/// How Rayfish integrates its resolver with the host.
///
/// - [`On`](Self::On): `.ray` routes to us and the `<network>.ray` and `ray`
///   search domains are installed, so bare `host` and `host.<network>` resolve.
/// - [`Partial`](Self::Partial), the default: `.ray` routes to us and nothing
///   else. No search domains, so the host's own search path is left alone.
/// - [`Off`](Self::Off): the host's resolver is not touched.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    strum::AsRefStr,
    strum::EnumString,
    strum::IntoStaticStr,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum DnsMode {
    On,
    #[default]
    Partial,
    Off,
}

impl DnsMode {
    pub fn enabled(self) -> bool {
        self != Self::Off
    }

    /// Whether names outside `.ray` are answered. Only [`On`](Self::On)
    /// installs the search domains that make them meaningful.
    pub fn short_names(self) -> bool {
        self == Self::On
    }
}

/// Who may reach this node on the connect channel (`ray connect` requests and
/// invitations). "Known" means sharing a network with this node.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    strum::AsRefStr,
    strum::EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum InboundPolicy {
    #[default]
    Anyone,
    Known,
    #[serde(rename = "none")]
    #[strum(serialize = "none")]
    Nobody,
}

/// Packet forwarding engine, selected when the endpoint binds. Both engines
/// use loss-tolerant QUIC congestion control.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, strum::AsRefStr, strum::EnumString,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum QuicEngine {
    /// Send packets directly to QUIC without per-flow scheduling.
    #[default]
    Standalone,
    /// FQ-CoDel scheduling of inner IP flows. Experimental.
    FqCodel,
}

/// Accept legacy saved controller choices while writing only the engine name.
pub(super) fn deserialize_quic_engine<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<QuicEngine, D::Error> {
    let value = String::deserialize(deserializer)?;
    if matches!(value.trim(), "cubic" | "loss-tolerant") {
        return Ok(QuicEngine::Standalone);
    }
    Ok(value.trim().parse().unwrap_or_else(|_| {
        tracing::warn!(%value, "unknown quic_engine in settings.toml; using default engine");
        QuicEngine::default()
    }))
}

pub(super) fn deserialize_dns_mode<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DnsMode, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SavedMode {
        Legacy(bool),
        Named(String),
    }
    use serde::de::Error;
    match SavedMode::deserialize(deserializer)? {
        SavedMode::Legacy(true) => Ok(DnsMode::On),
        SavedMode::Legacy(false) => Ok(DnsMode::Off),
        SavedMode::Named(value) => value
            .trim()
            .parse()
            .map_err(|_| Error::custom("DNS mode must be on, partial, or off")),
    }
}

pub(super) mod secret_key_hex {
    use iroh::SecretKey;
    use serde::{self, Serializer};

    pub fn serialize<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.to_bytes()))
    }
}

pub(super) mod option_secret_key_hex {
    use iroh::SecretKey;
    use serde::de::Error;
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(key: &Option<SecretKey>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match key {
            Some(k) => super::secret_key_hex::serialize(k, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SecretKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = serde::Deserialize::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes: [u8; 32] = hex::decode(&s)
                    .map_err(Error::custom)?
                    .try_into()
                    .map_err(|_| Error::custom("secret key must be 32 bytes"))?;
                Ok(Some(SecretKey::from(bytes)))
            }
            None => Ok(None),
        }
    }
}

/// Info about a member in a saved network config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEntry {
    pub identity: EndpointId,
    #[serde(default)]
    pub is_coordinator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// A pre-approved peer that hasn't connected yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedConfigEntry {
    pub identity: EndpointId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// A single saved network membership.
///
/// `Default` is for tests that care about two or three fields: the struct has
/// twenty, and spelling them all out buries what a case is actually about.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Human-friendly network alias (local only, not used for discovery).
    pub name: String,
    /// Membership mode: open or restricted.
    #[serde(default)]
    pub group_mode: GroupMode,
    /// Our hostname in this network (persisted so it survives daemon restarts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub my_hostname: Option<String>,
    /// A locally-requested rename not yet confirmed by the signed blob. Set by
    /// `ray hostname` on a member; the durable "deliver this rename to the
    /// coordinator" intent. Survives daemon restarts and is *not* clobbered when
    /// a reconverge applies a stale blob (unlike `my_hostname`), so the rename
    /// keeps being re-sent until the coordinator publishes it. Cleared once the
    /// blob reflects the new name (`rename_satisfied`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_hostname: Option<String>,
    /// Known members in this network.
    #[serde(default)]
    pub members: Vec<MemberEntry>,
    /// Pre-approved peers that haven't connected yet.
    #[serde(default)]
    pub approved: Vec<ApprovedConfigEntry>,
    #[serde(default, with = "option_secret_key_hex")]
    pub network_secret_key: Option<SecretKey>,
    #[serde(default)]
    pub network_public_key: Option<EndpointId>,
    /// The primary whose certificate was presented on this device's first join.
    /// Absent for networks created or joined independently, including configs
    /// saved before this field existed. Reconnects must not change this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_certificate_issuer: Option<EndpointId>,
    /// Devices that were already members when this coordinator paired them.
    /// Revoking their certificate must keep their independent membership.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub independent_paired_devices: Vec<EndpointId>,
    /// Hash of the last complete GroupBlob this node verified or authored.
    /// Coordinator restore uses it only when the signed pkarr record is
    /// unreachable, so an expired record can be republished without rebuilding
    /// the roster from the deliberately lossy `members` config projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_group_hash: Option<blake3::Hash>,
    /// Whether `last_group_hash` has been confirmed published. `false` marks a
    /// locally authored generation durably stored before its pkarr write; restore
    /// must prefer that hash over an older live record after a crash. Existing
    /// configs default to `true` because their pointers predate this marker and
    /// were written only by already-running publishers/reconvergence.
    #[serde(default = "default_true")]
    pub last_group_hash_published: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportMode>,
    /// This node auto-installs coordinator-suggested firewall rules without a
    /// manual review queue. Set per-network by `ray join --auto-accept-firewall`
    /// or toggled later with `ray firewall auto-accept <net> on|off`.
    #[serde(default, alias = "allow_trusted")]
    pub auto_accept_firewall: bool,
    /// Auto-accept incoming file offers from our own paired devices on this
    /// network (no manual `ray files accept`). Own-devices-only (the sender's
    /// user identity must match ours), so it is safe on by default. Opt out per
    /// network with `ray join --no-auto-accept-files` or `ray files auto-accept
    /// <net> off`.
    #[serde(default = "default_true")]
    pub auto_accept_files: bool,
    /// Identities this coordinator has granted the per-network secret key to
    /// (`ray admin add`). Local tracking only: the key is shared and not
    /// attributable, so this is the coordinator's record of grants, not a
    /// verifiable roster. Never published in the GroupBlob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<EndpointId>,
    /// This is an auto-minted 2-peer "direct connection" network (`ray connect`),
    /// not a user-created mesh. Tagged so `ray status` can label it `[direct]`
    /// and suppress its (non-shareable) room id.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub direct: bool,
    /// The one peer this direct network was minted for, recorded at
    /// `ray connect approve` time.
    ///
    /// Admission hands the network *secret key* to a pre-approved peer on a
    /// direct network, because a direct link is symmetric and both ends
    /// coordinate it. `direct` alone is a property of the network, so that rule
    /// read as "any peer ever approved here becomes a co-coordinator", and a
    /// later `ray requests accept` on the same network would silently give away
    /// the key.
    /// Naming the peer keeps the grant to the link it was meant for.
    ///
    /// `None` on networks minted before this field existed. See the fallback in
    /// `admit_peer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_peer: Option<EndpointId>,
    /// Peers authorized to SSH into this node over this network's mesh link
    /// (`ray firewall ssh allow <net> <peer>`). Only consulted when the global
    /// `ssh_enabled` toggle is on. Empty = no peer may SSH in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_allow: Vec<SshRule>,
    /// SSH grants installed by a controller's deploy spec. Local grants remain
    /// separate so a later apply cannot remove them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_ssh_allow: Vec<SshRule>,
    /// Node-local, per-network aliases (`alias name -> identity string`), set via
    /// `ray alias`. Display-only convenience: shown inline in `ray status` and
    /// used to seed `ray apply`'s `aliases:` map. Never published in the
    /// GroupBlob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, String>,
    /// Coordinator-local ephemeral policy: auto-remove a member offline
    /// longer than this many seconds. `None` = off (default). The 1-hour floor
    /// is enforced by the settings registry (`settings::apply_network`), so it
    /// binds every writer; the CLI's duration parser rejects it earlier only to
    /// give a nicer message. Local only (only the coordinator enforces);
    /// never rides the signed blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_ttl_secs: Option<u64>,
    /// Users permitted to route their internet-bound traffic out through this
    /// node as an exit node (`ray exit-node allow <net> <user|*>`). Each entry
    /// is a peer's user-identity (hex [`EndpointId`]) or `"*"` (any member).
    /// A non-empty list means this node offers itself as an exit node on this
    /// network and is what gates real forwarding; the offer is also advertised
    /// in the signed blob (`Member.exit_node`) so peers can discover it. Local
    /// policy, never published as an allow-list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_allow: Vec<String>,
    /// The peer this node routes all non-mesh traffic through as an exit node
    /// (`ray exit-node use <net> <peer>`), stored as the peer's user-identity or
    /// endpoint-id string. `None` = direct egress (default). Local only; drives
    /// default-route install and forward-loop routing on `ray up`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node_use: Option<String>,
}

/// One mesh-SSH authorization entry: a peer and the local unix users it may log
/// in as. `peer` is a peer's user-identity (hex [`EndpointId`]) or `"*"` (any
/// peer on the network). `users` lists the permitted login accounts; an **empty
/// list means any non-root user** (the secure default), and `"*"` in the list
/// means any user including root. Setting a peer's rule replaces its `users`
/// (last write wins); the SSH server folds rules across shared networks at
/// login (see [`crate::ssh`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshRule {
    pub peer: String,
    #[serde(default)]
    pub users: Vec<String>,
}

pub(super) fn default_true() -> bool {
    true
}

pub(crate) const fn default_ssh_port() -> u16 {
    22
}

/// In-memory aggregate of the on-disk config. Reads assemble this from
/// `settings.toml` (globals) + one `networks/<name>.toml` per network; writes
/// are targeted (`update_settings` / `save_network` / `delete_network`) so a
/// write to one network can never clobber another. See the storage section
/// below.
/// A global server override (relay / discovery-DNS / DNS-upstreams). `servers`
/// holds preset keywords (`rayfish`, `n0`) or literal URLs/IPs as the user typed
/// them; an empty list means unset (use the iroh n0 defaults). `replace` swaps
/// the defaults out instead of augmenting them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerOverride {
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub replace: bool,
}

impl ServerOverride {
    pub fn is_unset(&self) -> bool {
        self.servers.is_empty()
    }
}

/// Preset URL for the rayfish-operated iroh transport relay.
pub const RELAY_PRESET_RAYFISH: &str = "http://relay.iroh.rayfish.xyz:3340";
/// Preset URL for the rayfish-operated discovery-DNS / pkarr server.
pub const DISCOVERY_PRESET_RAYFISH: &str = "http://dns.iroh.rayfish.xyz:8080";

/// Default idle timeout for on-demand nodes: no data-plane or control traffic for
/// this long closes a peer connection so the node returns to zero connections.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;

pub(super) fn validate_http_url(s: &str) -> Result<()> {
    let u = url::Url::parse(s).with_context(|| format!("invalid URL: {s}"))?;
    anyhow::ensure!(
        matches!(u.scheme(), "http" | "https"),
        "URL must be http or https: {s}"
    );
    Ok(())
}

/// Resolve one relay/discovery entry: the `rayfish` keyword maps to `preset`,
/// anything else must be a valid http(s) URL (returned as-is).
pub(crate) fn resolve_url_entry(entry: &str, preset: &str) -> Result<String> {
    match entry {
        "rayfish" => Ok(preset.to_string()),
        other => {
            validate_http_url(other)?;
            Ok(other.to_string())
        }
    }
}

/// Resolve the relay override to concrete URL strings (presets expanded,
/// validated). Empty when unset.
pub fn relay_urls(o: &ServerOverride) -> Result<Vec<String>> {
    o.servers
        .iter()
        .map(|e| resolve_url_entry(e, RELAY_PRESET_RAYFISH))
        .collect()
}

/// Resolve the discovery-DNS override to concrete URL strings. Empty when unset.
pub fn discovery_urls(o: &ServerOverride) -> Result<Vec<String>> {
    o.servers
        .iter()
        .map(|e| resolve_url_entry(e, DISCOVERY_PRESET_RAYFISH))
        .collect()
}

/// Merge configured DNS upstreams with the system-captured ones. `replace`
/// drops the captured set; otherwise custom upstreams are tried first, then the
/// captured ones. When present, Tailscale's Magic DNS resolver is preferred over
/// every other upstream. Unset returns the captured set unchanged.
///
/// Both families: configured IPv6 addresses are retained so an overlay peer
/// running a resolver can receive ordinary DNS queries over the mesh, and a
/// host's own IPv6 servers are captured like its IPv4 ones. A captured server
/// the operator also named is listed once.
pub fn resolve_upstreams(o: &ServerOverride, captured: Vec<IpAddr>) -> Vec<IpAddr> {
    let upstreams = if o.servers.is_empty() {
        captured
    } else {
        let mut custom: Vec<IpAddr> = o.servers.iter().filter_map(|s| s.parse().ok()).collect();
        if !o.replace {
            for ip in captured {
                if !custom.contains(&ip) {
                    custom.push(ip);
                }
            }
        }
        custom
    };
    prefer_tailscale_dns(upstreams)
}

/// Tailscale's Magic DNS resolver owns its split-DNS rules. Keep it first when
/// present while Rayfish intercepts `.ray` queries and forwards other names.
pub(super) fn prefer_tailscale_dns(mut upstreams: Vec<IpAddr>) -> Vec<IpAddr> {
    let tailscale = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100));
    if let Some(index) = upstreams.iter().position(|ip| *ip == tailscale) {
        let resolver = upstreams.remove(index);
        upstreams.insert(0, resolver);
    }
    upstreams
}

/// Whether `o` contributes anything to [`resolve_upstreams`], i.e. names at least
/// one server the captured-upstream path can actually use.
///
/// Beside `resolve_upstreams` because it has to narrow the same way: this is what
/// lets an operator's setting waive the refusal to take over `/etc/resolv.conf`
/// with no verified upstream (`DnsConfigurator::operator_upstreams`), and waiving
/// it on entries that then get filtered out would take the host's DNS down
/// instead of saving it. A bare `!servers.is_empty()` was exactly that bug once
/// `dns_upstreams` started accepting IPv6.
pub fn has_usable_upstream(o: &ServerOverride) -> bool {
    o.servers.iter().any(|s| s.parse::<IpAddr>().is_ok())
}

/// Parse a comma list of entries (trimmed, empties dropped).
pub(crate) fn parse_entries(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// A minimal saved network, for tests that need a `NetworkConfig` to apply
/// settings to or render messages from. Every field is at its default; only the
/// name is meaningful.
#[cfg(test)]
pub(crate) fn empty_network_config(name: &str) -> NetworkConfig {
    NetworkConfig {
        name: name.to_string(),
        group_mode: GroupMode::Open,
        my_hostname: None,
        pending_hostname: None,
        members: vec![],
        approved: vec![],
        network_secret_key: None,
        network_public_key: None,
        join_certificate_issuer: None,
        independent_paired_devices: vec![],
        last_group_hash: None,
        last_group_hash_published: true,
        transport: None,
        auto_accept_firewall: false,
        auto_accept_files: true,
        admins: vec![],
        direct: false,
        direct_peer: None,
        ssh_allow: vec![],
        managed_ssh_allow: vec![],
        aliases: BTreeMap::new(),
        ephemeral_ttl_secs: None,
        exit_allow: vec![],
        exit_node_use: None,
    }
}

/// Apply a `ray config set`/`unset` to the in-memory config. Delegates to the
/// settings registry; kept as a thin wrapper so existing callers don't need to
/// know about `settings::apply_global`.
pub fn config_set(
    cfg: &mut AppConfig,
    key: settings::GlobalKey,
    value: &str,
    replace: bool,
) -> Result<()> {
    settings::apply_global(cfg, key, value, replace)
}

pub(crate) fn render_override(o: &ServerOverride) -> String {
    if o.is_unset() {
        "<default>".to_string()
    } else {
        let mode = if o.replace { "replace" } else { "augment" };
        format!("{} ({mode})", o.servers.join(","))
    }
}

/// Render global settings as `(key, value)` rows for `ray config get`. With a
/// key, returns just that one; without, every global key. Driven off
/// `GlobalKey::ALL` rather than a hand-kept list, so a new key shows up here
/// the moment it exists instead of being silently unlistable.
pub fn config_get(cfg: &AppConfig, key: Option<settings::GlobalKey>) -> Vec<(String, String)> {
    use settings::GlobalKey;
    let row = |k: GlobalKey| (k.name().to_string(), settings::render_global(cfg, k));
    match key {
        Some(k) => vec![row(k)],
        None => GlobalKey::ALL.iter().copied().map(row).collect(),
    }
}

/// A closed-network join that was queued for coordinator approval and has not
/// yet been admitted. Persisted so the background retry survives a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingJoinEntry {
    /// The network public key (bare room id) we asked to join.
    pub network_key: String,
    /// The local display name to use once admitted, if the user gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The transport asked for (`ray join --tor`), saved on the network once
    /// admitted. Absent in entries written before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportMode>,
}

/// An unpair of this device from its primary that has not finished. See
/// [`AppConfig::pending_unpairs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUnpair {
    /// The certificate given up. Kept after the stored copy is deleted: the
    /// primary checks the request against it.
    pub cert: DeviceCert,
    pub phase: UnpairPhase,
}

/// How far a [`PendingUnpair`] got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnpairPhase {
    /// The local cleanup has not finished: networks joined with the
    /// certificate, and the stored certificate itself, may remain.
    Cleanup,
    /// The cleanup is saved. The primary has not yet confirmed that it
    /// recorded the revocation.
    Request,
}

/// A device `ray unpair` revoked that has yet to confirm its cleanup. See
/// [`AppConfig::pending_unpair_notices`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUnpairNotice {
    pub device: EndpointId,
    /// The generation of the pairing revoked, which the notice names.
    pub generation: u64,
}

/// A primary's pairings with one device. See
/// [`AppConfig::device_generations`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGeneration {
    pub device: EndpointId,
    /// The generation of the latest certificate signed for it.
    pub issued: u64,
    /// The generation of the latest certificate it confirmed it saved
    /// (`PairMsg::CertificateSaved`), if it confirmed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<u64>,
}

/// A controller this machine has explicitly authorized to issue management
/// requests. Authority is bound to the controller's transport endpoint id,
/// which iroh authenticates during the QUIC handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerGrant {
    pub identity: EndpointId,
    pub enrolled_at: UnixTimestampSecs,
    /// Missing on enrollments made before management protocol v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<EnrollmentReceipt>,
}

/// A machine enrolled with this controller. `hostname` is the stable name used
/// by delegated commands and by `ray apply` when matching a missing host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedMachine {
    pub identity: EndpointId,
    pub hostname: MachineHostname,
    pub enrolled_at: UnixTimestampSecs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<UnixTimestampSecs>,
}

/// A controller-side enrollment credential. Only its hash is persisted.
/// Reusable credentials may enroll multiple machines until revoked or expired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentCredential {
    pub id: ray_proto::ipc::EnrollmentCredentialId,
    pub secret_hash: blake3::Hash,
    pub expires_at: UnixTimestampSecs,
    pub reusable: bool,
    #[serde(default)]
    pub enrolled_machines: Vec<EndpointId>,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,
    /// Local UID authorized to control the daemon without root (Tailscale's
    /// `--operator` model). `None` means root-only for mutating commands.
    #[serde(default)]
    pub operator_uid: Option<u32>,
    /// Personal default hostname used when creating/joining a network without an
    /// explicit `--hostname`. Set via `ray up --hostname <name>`. `None` falls
    /// back to a random generated name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_hostname: Option<String>,
    /// Custom iroh transport relay servers (NAT-traversal fallback).
    #[serde(default)]
    pub relay: ServerOverride,
    /// Custom iroh discovery-DNS / pkarr server (endpoint resolution + record
    /// publish). Also redirects the `dht.rs` pkarr client.
    #[serde(default)]
    pub discovery_dns: ServerOverride,
    /// Custom Magic DNS upstream forwarders for non-`.ray` queries (IPv4 only).
    #[serde(default)]
    pub dns_upstreams: ServerOverride,
    /// Whether Magic DNS resolves short names, only `.ray` names, or nothing.
    #[serde(
        default,
        alias = "dns_enabled",
        deserialize_with = "deserialize_dns_mode"
    )]
    pub dns_mode: DnsMode,
    /// QUIC forwarding engine (`ray config set quic-engine`).
    #[serde(
        default,
        alias = "quic_congestion",
        deserialize_with = "deserialize_quic_engine"
    )]
    pub quic_engine: QuicEngine,
    /// Recently successful peer transport paths.  These are only connection
    /// hints: iroh still authenticates the endpoint identity in TLS and falls
    /// back to its normal discovery services when a hint is stale.  Keeping
    /// them lets a restart try a known LAN/direct path or relay immediately,
    /// before a pkarr lookup completes.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "endpoint_hints::deserialize"
    )]
    pub endpoint_hints: Vec<EndpointHint>,
    /// Global toggle for the embedded mesh SSH server (`ray firewall ssh on`).
    /// When on, the daemon listens on each mesh IP's configured SSH port and admits peers
    /// authorized in a network's local or managed SSH allow list. Off by default.
    #[serde(default)]
    pub ssh_enabled: bool,
    /// Port peers use to reach the embedded SSH server over the mesh.
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// Global toggle for bridging this host's IPv4-only listeners onto the mesh
    /// address (`ray config set v4-bridge off`). On by default: the mesh
    /// firewall still denies inbound by default, so the only ports it changes
    /// are ones a rule already opened and which silently did not answer. See
    /// `crate::v4bridge`.
    #[serde(default = "default_true")]
    pub v4_bridge: bool,
    /// macOS only: load a pf anchor that passes traffic on the mesh interface
    /// (`ray config set pf-passthrough off`). On by default. Another VPN's kill
    /// switch ends in a catch-all block and its allow-list names private ranges
    /// the overlay is not in, so without this the mesh dies the moment that VPN
    /// connects. See `crate::hostfw`.
    #[serde(default = "default_true")]
    pub pf_passthrough: bool,
    /// On-demand connection mode (battery-minimizing, Tailscale-style). When on,
    /// the node does not eagerly dial peers at startup: it restores memberships and
    /// the roster locally, dials a peer lazily on the first outgoing packet that
    /// needs it, and tears down connections idle past [`idle_timeout_secs`].
    ///
    /// On by default; a latency-sensitive server or always-push coordinator can turn
    /// it off (`ray config set on-demand off`) to stay eagerly connected.
    #[serde(default = "default_true")]
    pub on_demand: bool,
    /// Seconds of no traffic before an on-demand node closes a peer connection.
    /// `None` uses [`DEFAULT_IDLE_TIMEOUT_SECS`]. Only consulted when `on_demand`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
    /// Opt-in automatic updates: when on, the daemon periodically checks for a
    /// newer stable release, swaps the binary, and restarts itself onto it. Off
    /// by default; enable via `ray install --auto-update` or `ray config set auto-update on`.
    #[serde(default)]
    pub auto_update: bool,
    /// Last release tag the auto-updater attempted (e.g. `v0.2.0`). Persisted so a
    /// swapped binary that keeps mis-reporting its version can't tight-loop: the
    /// same target is retried at most once per backoff window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update_last_target: Option<String>,
    /// Unix seconds of the last auto-update attempt, paired with
    /// `auto_update_last_target` for the backoff guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update_last_attempt: Option<i64>,
    /// Exact device identities allowed to send files without approval.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_auto_accept_peers: Vec<EndpointId>,
    /// Who may send connect requests and invitations.
    #[serde(default)]
    pub inbound: InboundPolicy,
    /// Refused on the connect channel. Shared networks are unaffected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<EndpointId>,
    /// Absolute directory where auto-accepted files are written.
    /// `None` falls back to `download_user`, then the operator's ~/Downloads.
    /// Set via `ray files download-dir <path>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_dir: Option<String>,
    /// Unix uid that owns auto-accepted files (and whose ~/Downloads receives
    /// them when `download_dir` is unset). Set via `ray files download-user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_user: Option<u32>,
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    /// Closed-network joins queued for coordinator approval, awaiting
    /// admission. See [`PendingJoinEntry`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_joins: Vec<PendingJoinEntry>,
    /// The generation certificates carried before pairings were numbered, left
    /// from an earlier revocation scheme and normally `0`. A device paired
    /// before then still holds it, so it counts as that device's generation
    /// until the device pairs again. Nothing raises it now.
    #[serde(default)]
    pub cert_generation: u64,
    /// This primary's pairings with each device: the generation of the latest
    /// certificate signed for it, and of the latest one it confirmed it saved.
    /// A pairing is issued one above the device's last (or above
    /// `cert_generation`) and saved here before the device gets the
    /// certificate, so a notice or request about an earlier pairing of it is
    /// told apart from the current one. Only a confirmed pairing makes a
    /// request about an earlier one obsolete: the reply carrying a certificate
    /// can be lost. Kept after an unpair, so a later pairing still numbers
    /// above it. See `daemon::mesh::unpair`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_generations: Vec<DeviceGeneration>,
    /// Device keys this user has nullified (hex `EndpointId`), by `ray unpair` or
    /// at a paired device's own request (`PairMsg::UnpairRequest`). The
    /// coordinator's durable nullifier seed: it survives a restart and is unioned
    /// into every coordinated network's signed blob (`GroupBlob.nullifiers`) at seal
    /// time, so a listed device's cert is rejected mesh-wide. A device is removed
    /// here when it re-pairs (re-auth). See `Daemon::unpair`/`reauth_device_locked`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_devices: Vec<String>,
    /// This device's unpairs from a primary that have not finished, each saved
    /// before any of its work so that a restart resumes it. An entry holds the
    /// certificate given up and how far the unpair got: the local cleanup first,
    /// then the request asking the primary to record the revocation. It is
    /// complete, and removed, only once the primary confirms the revocation is
    /// saved (`PairMsg::UnpairRecorded`), or once a new pairing with that primary
    /// is saved, which cancels it. See `daemon::mesh::unpair`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_unpairs: Vec<PendingUnpair>,
    /// Devices `ray unpair` revoked that have not yet confirmed their cleanup,
    /// each with the generation of the pairing revoked. Saved with the
    /// revocation, before the device is told (`ControlMsg::PairingRevoked`).
    /// The notice is repeated, after a restart too, until the device confirms
    /// by asking this primary to record its unpair (`PairMsg::UnpairRequest`),
    /// or until it pairs here again. See `daemon::mesh::unpair`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_unpair_notices: Vec<PendingUnpairNotice>,
    /// Remote controllers authorized by this machine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub controllers: Vec<ControllerGrant>,
    /// Machines that enrolled with this node as their controller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_machines: Vec<ManagedMachine>,
    /// Prevent a signed hello from restoring an explicitly forgotten machine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forgotten_machines: Vec<EndpointId>,
    /// Pending and reusable machine-enrollment credentials minted here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrollment_credentials: Vec<EnrollmentCredential>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mdns_enabled: true,
            operator_uid: None,
            default_hostname: None,
            relay: ServerOverride::default(),
            discovery_dns: ServerOverride::default(),
            dns_upstreams: ServerOverride::default(),
            dns_mode: DnsMode::default(),
            quic_engine: QuicEngine::default(),
            endpoint_hints: Vec::new(),
            ssh_enabled: false,
            ssh_port: default_ssh_port(),
            v4_bridge: true,
            pf_passthrough: true,
            on_demand: true,
            idle_timeout_secs: None,
            auto_update: false,
            auto_update_last_target: None,
            auto_update_last_attempt: None,
            file_auto_accept_peers: Vec::new(),
            inbound: InboundPolicy::default(),
            blocked: Vec::new(),
            download_dir: None,
            download_user: None,
            networks: Vec::new(),
            pending_joins: Vec::new(),
            cert_generation: 0,
            device_generations: Vec::new(),
            revoked_devices: Vec::new(),
            pending_unpairs: Vec::new(),
            pending_unpair_notices: Vec::new(),
            controllers: Vec::new(),
            managed_machines: Vec::new(),
            forgotten_machines: Vec::new(),
            enrollment_credentials: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Idle timeout for on-demand teardown, falling back to
    /// [`DEFAULT_IDLE_TIMEOUT_SECS`] when unset.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS))
    }
}

/// Parse the persisted revoked device keys (`revoked_devices`) into
/// `EndpointId`s, skipping any malformed entry.
pub fn revoked_device_ids(config: &AppConfig) -> Vec<EndpointId> {
    config
        .revoked_devices
        .iter()
        .filter_map(|s| s.parse::<EndpointId>().ok())
        .collect()
}
