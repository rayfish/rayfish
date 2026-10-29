use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs::Permissions;
#[cfg(any(target_os = "linux", all(test, unix)))]
use std::fs::{self, File};
#[cfg(any(target_os = "linux", all(test, unix)))]
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
// Only the test-only `CONFIG_ENV_LOCK` holds one.
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::{EndpointId, SecretKey};
use ray_proto::ipc::{MachineHostname, UnixTimestampSecs};
use serde::{Deserialize, Deserializer, Serialize};

use crate::control::DeviceCert;
use crate::endpoint_hints::{self, EndpointHint};
use crate::management::EnrollmentReceipt;
use crate::membership::GroupMode;

/// Per-network transport preference. Defined in `ray-proto` (shared with GUI
/// frontends); re-exported here so existing `crate::config::TransportMode` paths work.
pub use ray_proto::TransportMode;

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
fn deserialize_quic_engine<'de, D: Deserializer<'de>>(
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

fn deserialize_dns_mode<'de, D: Deserializer<'de>>(deserializer: D) -> Result<DnsMode, D::Error> {
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

mod secret_key_hex {
    use iroh::SecretKey;
    use serde::{self, Serializer};

    pub fn serialize<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.to_bytes()))
    }
}

mod option_secret_key_hex {
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

pub(crate) mod destruction;
mod write;

pub use write::{restrict_perms, write_file};
use write::{sync_dir, sync_file_and_parent, write_atomic};

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

fn default_true() -> bool {
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

fn validate_http_url(s: &str) -> Result<()> {
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
fn prefer_tailscale_dns(mut upstreams: Vec<IpAddr>) -> Vec<IpAddr> {
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

pub mod settings;

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

// ---- Storage layout -------------------------------------------------------
//
// Config is sharded so a write to one network can never clobber another:
//
//   <config_dir>/settings.toml          globals (mdns, operator, default
//                                        hostname), owner-only
//   <config_dir>/networks/<name>.toml   one NetworkConfig each, secret-bearing
//
// All writes go through `write_atomic` (temp file in the same dir + rename), so
// a concurrent reader never observes a torn file. This replaces the old single
// `networks.toml` whose non-atomic full-file rewrites raced under concurrent
// load-modify-save and silently dropped networks.
//
// Linux stores the tree under /etc/rayfish owned root:rayfish (see
// `config_dir`); secret-bearing files are 0600 root:root, dirs 0750
// root:rayfish.

const LEGACY_FILE: &str = "networks.toml";
const SETTINGS_FILE: &str = "settings.toml";
const NETWORKS_SUBDIR: &str = "networks";

/// Process-wide transaction boundary for network shards. Public per-network
/// reads take a shared guard; save, update, migration, and delete take an
/// exclusive guard so a stale whole-file write cannot overwrite another task's
/// fields or resurrect a deleted network.
static NETWORK_CONFIG_LOCK: RwLock<()> = RwLock::new(());

thread_local! {
    /// Tripwire for the non-reentrant update callback contract. The process
    /// lock deliberately remains the real transaction boundary.
    static IN_NETWORK_CONFIG_UPDATE: Cell<bool> = const { Cell::new(false) };
}

struct NetworkUpdateScope;

impl NetworkUpdateScope {
    fn enter() -> Result<Self> {
        ensure_not_in_network_update()?;
        IN_NETWORK_CONFIG_UPDATE.with(|active| active.set(true));
        Ok(Self)
    }
}

impl Drop for NetworkUpdateScope {
    fn drop(&mut self) {
        IN_NETWORK_CONFIG_UPDATE.with(|active| active.set(false));
    }
}

fn ensure_not_in_network_update() -> Result<()> {
    IN_NETWORK_CONFIG_UPDATE.with(|active| {
        anyhow::ensure!(
            !active.get(),
            "network config update callbacks must not call network config APIs"
        );
        Ok(())
    })
}

/// Globals persisted to `settings.toml` (everything in [`AppConfig`] except the
/// per-network entries, which live in their own files).
///
/// `Default` gives every field its type-default (so `mdns_enabled` is `false`);
/// the fresh-install defaults are built at the `load_in` site with explicit
/// overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Settings {
    #[serde(default = "default_true")]
    mdns_enabled: bool,
    #[serde(default)]
    operator_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_hostname: Option<String>,
    #[serde(default)]
    relay: ServerOverride,
    #[serde(default)]
    discovery_dns: ServerOverride,
    #[serde(default)]
    dns_upstreams: ServerOverride,
    #[serde(
        default,
        alias = "dns_enabled",
        deserialize_with = "deserialize_dns_mode"
    )]
    dns_mode: DnsMode,
    #[serde(
        default,
        alias = "quic_congestion",
        deserialize_with = "deserialize_quic_engine"
    )]
    quic_engine: QuicEngine,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "endpoint_hints::deserialize"
    )]
    endpoint_hints: Vec<EndpointHint>,
    #[serde(default)]
    ssh_enabled: bool,
    #[serde(default = "default_ssh_port")]
    ssh_port: u16,
    #[serde(default = "default_true")]
    v4_bridge: bool,
    #[serde(default = "default_true")]
    pf_passthrough: bool,
    #[serde(default = "default_true")]
    on_demand: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    auto_update: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_update_last_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_update_last_attempt: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    download_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    file_auto_accept_peers: Vec<EndpointId>,
    #[serde(default)]
    inbound: InboundPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    blocked: Vec<EndpointId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    download_user: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_joins: Vec<PendingJoinEntry>,
    #[serde(default)]
    cert_generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    device_generations: Vec<DeviceGeneration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revoked_devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_unpairs: Vec<PendingUnpair>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_unpair_notices: Vec<PendingUnpairNotice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    controllers: Vec<ControllerGrant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    managed_machines: Vec<ManagedMachine>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    forgotten_machines: Vec<EndpointId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    enrollment_credentials: Vec<EnrollmentCredential>,
}

/// Look up the `rayfish` group's gid (Linux), if the group exists.
#[cfg(target_os = "linux")]
fn rayfish_gid() -> Option<u32> {
    use std::{ffi::CString, mem::zeroed, ptr::null_mut};
    let name = CString::new("rayfish").ok()?;
    // getgrnam_r, never getgrnam: the legacy call returns a pointer into a
    // process-wide buffer that any concurrent getgr*/getpw* call is allowed
    // to move or free. Config saves run on many threads at once, and on musl
    // that race corrupted the heap and took the daemon down with SIGSEGV.
    // The reentrant variant copies into our own buffer, which is the whole
    // reason it exists.
    let mut buf_len = 4096;
    loop {
        let mut buf = vec![0u8; buf_len];
        let mut grbuf: libc::group = unsafe { zeroed() };
        let mut result: *mut libc::group = null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut grbuf,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        return Some(unsafe { (*result).gr_gid });
    }
}

/// The group a config path is owned by: `rayfish` for a non-secret path when the
/// group exists, otherwise root.
#[cfg(target_os = "linux")]
fn owner_gid(secret: bool) -> u32 {
    if secret {
        0
    } else {
        rayfish_gid().unwrap_or(0)
    }
}

/// Best-effort `chown` to root, with group `rayfish` for non-secret paths (or
/// root for secret ones). No-op off Linux. Silent on failure so the daemon
/// still starts if the group is missing.
#[cfg(target_os = "linux")]
fn set_owner(path: &Path, secret: bool) {
    if crate::instance::is_rootless() {
        return;
    }
    if let Err(e) = std::os::unix::fs::chown(path, Some(0), Some(owner_gid(secret))) {
        tracing::debug!(path = %path.display(), error = %e, "chown failed (non-fatal)");
    }
}

/// Unit tests use caller-owned temporary directories and must not replace their
/// inherited ACL with the service-only ProgramData ACL.
#[cfg(all(windows, test))]
fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
}

#[cfg(all(windows, not(test)))]
fn ensure_dir(dir: &Path) -> Result<()> {
    crate::windows_security::ensure_protected_dir(dir)
}

/// Create `dir` (and parents) with restrictive perms: 0750 root:rayfish on
/// Unix. Idempotent.
#[cfg(not(windows))]
fn ensure_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Some(instance) = crate::instance::user_instance() {
        return crate::instance::ensure_private_dir(dir, instance.owner_uid);
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::set_permissions(dir, Permissions::from_mode(0o750));
        set_owner(dir, false);
    }
    Ok(())
}

/// Resolve the `RAYFISH_CONFIG_DIR` override from its raw environment value. An
/// unset *or empty* var means "no override": an exported-but-empty var is a
/// common shell accident and must not resolve the config tree to the current
/// directory. Split out from [`config_dir`] so it is testable without touching
/// the real platform path.
fn config_dir_override(raw: Option<OsString>) -> Option<PathBuf> {
    raw.filter(|d| !d.is_empty()).map(PathBuf::from)
}

/// Config directory published by an embedder rather than by the environment.
///
/// `ray-mobile`'s `Node::new` passes Android's `Context.getFilesDir()` here. It
/// used to write that path into `RAYFISH_CONFIG_DIR` instead, which is a
/// mutation of the process environment: undefined behaviour once any other
/// thread is running, and in the lib tests it redirected a concurrent test's
/// config reads between its own write and read. The directory is fixed for the
/// life of the process, so a process-wide cell holds it without threading a
/// handle through every [`config_dir`] caller (as `dht::PKARR_OVERRIDE` does
/// for the discovery server).
static CONFIG_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Point every config read at `dir`, ahead of `RAYFISH_CONFIG_DIR`.
///
/// For embedders that know their config location at startup; the CLI and the
/// daemon use the environment variable. Must run before any config or identity
/// read, and takes precedence because the environment write it replaces did.
pub fn set_config_dir_override(dir: PathBuf) {
    *CONFIG_DIR_OVERRIDE
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(dir);
}

/// Pick between the two override sources: the embedder's first, then the
/// environment's. `None` means the platform default applies, and an empty path
/// from either source is "no override" rather than the current directory.
///
/// Split out from [`effective_override`], the way [`config_dir_override`] is
/// split out of [`config_dir`], so the precedence is testable without mutating
/// the process environment (which is what this whole override exists to avoid).
fn resolve_override(embedder: Option<PathBuf>, env: Option<OsString>) -> Option<PathBuf> {
    embedder
        .filter(|d| !d.as_os_str().is_empty())
        .or_else(|| config_dir_override(env))
}

#[cfg(test)]
thread_local! {
    /// A config tree for this thread alone, ahead of both overrides. The other
    /// two are process-wide, so a test running two daemons at once gives each a
    /// runtime whose threads set this to its own tree.
    static THREAD_CONFIG_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Point this thread's config reads at `dir`. See [`THREAD_CONFIG_DIR`].
#[cfg(test)]
pub(crate) fn set_thread_config_dir(dir: PathBuf) {
    THREAD_CONFIG_DIR.with(|cell| *cell.borrow_mut() = Some(dir));
}

/// The rootless instance directory, or the embedder's [`set_config_dir_override`]
/// followed by `RAYFISH_CONFIG_DIR`. Tests can override these per thread.
/// `None` means the platform default applies.
fn effective_override() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = THREAD_CONFIG_DIR.with(|cell| cell.borrow().clone()) {
        return Some(dir);
    }
    if let Some(instance) = crate::instance::user_instance() {
        return Some(instance.directory.clone());
    }
    resolve_override(
        CONFIG_DIR_OVERRIDE
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone(),
        std::env::var_os("RAYFISH_CONFIG_DIR"),
    )
}

/// The platform's config location, before the `RAYFISH_CONFIG_DIR` override and
/// without creating anything.
///
/// This is always the *daemon's* directory, never the calling process's. macOS
/// is where the difference bites: the daemon runs as root under launchd, so its
/// config lives under `/var/root`, and resolving `dirs::config_dir()` in an
/// unprivileged `ray` would name an empty directory in that user's home instead
/// (and, through [`config_dir`], create it).
fn platform_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    let dir = PathBuf::from("/etc/rayfish");
    #[cfg(target_os = "freebsd")]
    let dir = PathBuf::from("/usr/local/etc/rayfish");
    // Android without the override falls back to a fixed app-private path so the
    // library still compiles/runs standalone.
    #[cfg(target_os = "android")]
    let dir = PathBuf::from("/data/local/tmp/rayfish");
    #[cfg(target_os = "macos")]
    let dir = PathBuf::from("/var/root/Library/Application Support/rayfish");
    // Machine-wide, for the same reason macOS is: the daemon is a LocalSystem
    // service, and `dirs::config_dir()` would name that account's roaming
    // profile under `C:\Windows\system32\config\systemprofile` for the daemon
    // and the operator's own `%APPDATA%` for `ray`.
    #[cfg(target_os = "windows")]
    let dir = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("rayfish");
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "windows"
    )))]
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("rayfish");
    Ok(dir)
}

/// Base directory for all rayfish config + state. Created if missing.
///
/// `RAYFISH_CONFIG_DIR` overrides the platform default on every platform. The
/// daemon and the CLI must agree on it, so setting it for one and not the other
/// points them at different trees: export it in the service unit (or the daemon's
/// environment) as well as the shell you run `ray` from.
///
/// Platform defaults: Linux `/etc/rayfish` (system service location,
/// root:rayfish), FreeBSD `/usr/local/etc/rayfish`, macOS the daemon's
/// `/var/root/Library/Application Support/rayfish` (root-only; under launchd
/// root's home is `/var/root`, not the home of whoever ran `sudo`), Android the
/// app's `Context.getFilesDir()` (passed by `ray-mobile`'s `Node::new` through
/// [`set_config_dir_override`], which outranks the variable).
///
/// Use [`config_dir_for_read`] from anything that only reads: creating the tree
/// is the daemon's job, and a reader that does it can end up reporting the
/// directory it just made as the daemon's config.
pub fn config_dir() -> Result<PathBuf> {
    let dir = match effective_override() {
        Some(dir) => dir,
        None => platform_config_dir()?,
    };
    ensure_dir(&dir)?;
    Ok(dir)
}

/// Where the daemon keeps its content-addressed blob store: membership
/// snapshots and file transfers in flight. Created if missing.
///
/// On Linux it lives under `/var/lib/rayfish`, not the config tree: transfers
/// can be large, `/etc` is often on a small or read-only root filesystem, and
/// the store is state, not configuration. A store left in `/etc/rayfish/blobs`
/// by an older release is moved on first start. Elsewhere, and whenever
/// `RAYFISH_CONFIG_DIR` is set, it stays inside the config directory.
pub fn blobs_dir() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if effective_override().is_none() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        let old = config_dir()?.join("blobs");
        let state = Path::new(LINUX_STATE_DIR);
        let dir = match DirBuilder::new().recursive(true).mode(0o700).create(state) {
            Ok(()) => migrate_blobs(&old, &state.join("blobs")),
            Err(error) => {
                tracing::warn!(dir = LINUX_STATE_DIR, %error, "cannot create the state directory; keeping blobs in the config directory");
                old
            }
        };
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        return Ok(dir);
    }
    let dir = config_dir()?.join("blobs");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

#[cfg(target_os = "linux")]
const LINUX_STATE_DIR: &str = "/var/lib/rayfish";

/// Move a blob store from `old` to `new` and return the one to use. Across
/// filesystems (a separate `/var`) the store is copied next to `new`, checked,
/// and only then renamed into place, so a half-finished copy is never used. On
/// any failure the old location stays in use.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn migrate_blobs(old: &Path, new: &Path) -> PathBuf {
    if !old.is_dir() {
        return new.to_path_buf();
    }
    if new.exists() {
        tracing::warn!(
            old = %old.display(),
            new = %new.display(),
            "both blob store locations exist; using the new one and leaving the old one alone"
        );
        return new.to_path_buf();
    }
    match std::fs::rename(old, new) {
        Ok(()) => {
            tracing::info!(old = %old.display(), new = %new.display(), "moved the blob store");
            new.to_path_buf()
        }
        Err(error) if error.kind() == ErrorKind::CrossesDevices => {
            match copy_blob_store(old, new) {
                Ok(()) => {
                    tracing::info!(old = %old.display(), new = %new.display(), "copied the blob store to the state directory");
                    if let Err(error) = fs::remove_dir_all(old) {
                        tracing::warn!(old = %old.display(), %error, "copied the blob store but could not remove the old one");
                    }
                    new.to_path_buf()
                }
                Err(error) => {
                    tracing::warn!(
                        old = %old.display(),
                        new = %new.display(),
                        %error,
                        "could not copy the blob store; it stays where it is"
                    );
                    old.to_path_buf()
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                old = %old.display(),
                new = %new.display(),
                %error,
                "could not move the blob store; it stays where it is"
            );
            old.to_path_buf()
        }
    }
}

/// Copy the store at `old` to `new`, which must not exist, through a staging
/// directory beside `new`. Every file and directory is synced and the copy's
/// file list and sizes are compared with the original before the rename that
/// makes it visible. `old` is left untouched.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn copy_blob_store(old: &Path, new: &Path) -> io::Result<()> {
    let parent = new
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "blob store path has no parent"))?;
    let staging = parent.join(".blobs.migrating");
    // A leftover from an attempt that was interrupted; never in use.
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    let result = (|| {
        fs::create_dir(&staging)?;
        copy_tree(old, &staging)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        }
        File::open(&staging)?.sync_all()?;
        let mut original = Vec::new();
        list_tree(old, Path::new(""), &mut original)?;
        let mut check = Vec::new();
        list_tree(&staging, Path::new(""), &mut check)?;
        original.sort();
        check.sort();
        if original != check {
            return Err(io::Error::other(
                "copied blob store does not match the original",
            ));
        }
        fs::rename(&staging, new)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// One regular file in a blob store, by path relative to the store and size.
#[cfg(any(target_os = "linux", all(test, unix)))]
type StoreEntry = (PathBuf, u64);

/// Copy the tree under `from` into the existing directory `to`, syncing each
/// file and directory.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&dst)?;
            copy_tree(&src, &dst)?;
            fs::set_permissions(&dst, fs::metadata(&src)?.permissions())?;
        } else if kind.is_file() {
            fs::copy(&src, &dst)?;
            File::open(&dst)?.sync_all()?;
        } else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                format!("{} is not a file or directory", src.display()),
            ));
        }
    }
    File::open(to)?.sync_all()
}

/// Every regular file under `dir`, with its size.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn list_tree(dir: &Path, rel: &Path, out: &mut Vec<StoreEntry>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let rel = rel.join(entry.file_name());
        if metadata.is_dir() {
            list_tree(&entry.path(), &rel, out)?;
        } else {
            out.push((rel, metadata.len()));
        }
    }
    Ok(())
}

/// [`config_dir`] for a reader: same directory, never created.
///
/// A missing directory is not an error here — it reads as an empty config, which
/// is what a reader wants to say about a daemon that has saved nothing.
pub fn config_dir_for_read() -> Result<PathBuf> {
    match effective_override() {
        Some(dir) => Ok(dir),
        None => platform_config_dir(),
    }
}

#[cfg(windows)]
const OPERATOR_SID_FILE: &str = "operator.sid";

#[cfg(windows)]
const OPERATOR_LOCK_FILE: &str = "operator.sid.lock";

#[cfg(windows)]
fn operator_sid_at(path: &Path) -> Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect operator SID"),
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "operator SID is a reparse point"
    );
    use std::io::Read;
    #[cfg(not(test))]
    let mut file = crate::windows_security::open_protected_file_no_follow(path)?;
    #[cfg(test)]
    let mut file = std::fs::File::open(path)?;
    let mut sid = String::new();
    file.read_to_string(&mut sid)?;
    let sid = sid.trim().to_string();
    Ok((!sid.is_empty()).then_some(sid))
}

#[cfg(windows)]
fn lock_operator(dir: &Path) -> Result<crate::windows_security::OperatorFileLock> {
    crate::windows_security::lock_operator_file(&dir.join(OPERATOR_LOCK_FILE))
}

#[cfg(windows)]
pub fn operator_sid() -> Result<Option<String>> {
    let path = config_dir()?.join(OPERATOR_SID_FILE);
    operator_sid_at(&path)
}

#[cfg(windows)]
pub fn set_operator_sid(sid: &str) -> Result<()> {
    crate::windows_security::pipe_descriptor(Some(sid))?;
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    write_atomic(&path, &format!("{sid}\n"), true)
}

/// Atomically record the first Windows operator without replacing an existing
/// non-empty SID. Returns `true` only to the process that won the claim.
#[cfg(windows)]
pub fn claim_operator_sid(sid: &str) -> Result<bool> {
    crate::windows_security::pipe_descriptor(Some(sid))?;
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    if operator_sid_at(&path)?.is_some() {
        return Ok(false);
    }
    if path.exists() && std::fs::metadata(&path)?.len() == 0 {
        std::fs::remove_file(&path).context("remove incomplete operator SID claim")?;
    }
    let tmp = windows_config_stage_path(&dir, OPERATOR_SID_FILE);
    let result = (|| -> Result<bool> {
        use std::io::Write;
        let mut file = create_windows_config_stage(&tmp)?;
        writeln!(file, "{sid}").context("write operator SID claim")?;
        file.sync_all().context("flush operator SID claim")?;
        drop(file);
        crate::windows_security::move_no_replace(&tmp, &path)
    })();
    if tmp.exists() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Compensate only the exact claim made by this process. A concurrent explicit
/// recovery that changed the operator is never removed.
#[cfg(windows)]
pub fn remove_operator_sid_if_matches(sid: &str) -> Result<bool> {
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    if operator_sid_at(&path)?.as_deref() != Some(sid) {
        return Ok(false);
    }
    std::fs::remove_file(path).context("remove failed operator SID claim")?;
    Ok(true)
}

/// Restore an operator value only if nobody replaced the value being
/// compensated. Used by service-restart recovery to avoid stale rollback.
#[cfg(windows)]
pub fn replace_operator_sid_if_matches(expected: &str, replacement: Option<&str>) -> Result<bool> {
    if let Some(sid) = replacement {
        crate::windows_security::pipe_descriptor(Some(sid))?;
    }
    let dir = config_dir()?;
    let _lock = lock_operator(&dir)?;
    let path = dir.join(OPERATOR_SID_FILE);
    if operator_sid_at(&path)?.as_deref() != Some(expected) {
        return Ok(false);
    }
    match replacement {
        Some(sid) => write_atomic(&path, &format!("{sid}\n"), true)?,
        None => std::fs::remove_file(&path).context("remove compensated operator SID")?,
    }
    Ok(true)
}

/// Reject a network name that can't be a safe single path component (defence in
/// depth, names are already validated as hostnames elsewhere).
fn validate_net_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        anyhow::bail!("invalid network name for config file: {name:?}");
    }
    Ok(())
}

#[cfg(windows)]
fn windows_config_stage_path(dir: &Path, filename: &str) -> PathBuf {
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    dir.join(format!(".{filename}.tmp.{nonce}"))
}

#[cfg(windows)]
fn create_windows_config_stage(path: &Path) -> Result<std::fs::File> {
    #[cfg(not(test))]
    {
        crate::windows_security::create_protected_new_file(path)
    }
    #[cfg(test)]
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating unique config stage {}", path.display()))
}

#[cfg(all(windows, not(test)))]
fn validate_existing_windows_config_child(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => drop(crate::windows_security::open_protected_file_no_follow(
            path,
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    }
    Ok(())
}

/// Linux-only: relocate a pre-`/etc` config tree into `/etc/rayfish` on first
/// start after the upgrade that moved the location. Earlier Linux builds stored
/// everything under the daemon's `~/.config/rayfish` (i.e. `/root/.config`); this
/// moves `secret_key`, `networks.toml`, `firewall.toml`, `invites/`, etc. over so
/// the node keeps its identity and networks. No-op on macOS (location unchanged)
/// and once `/etc/rayfish` is populated, and skipped entirely when the config
/// location is set explicitly. Must run before any config/identity read
/// (called at the top of `build_daemon`).
pub fn migrate_location() {
    #[cfg(target_os = "linux")]
    {
        // An explicit config location (env var or embedder) is deliberate, not
        // an upgrade in progress: never pull `/root/.config/rayfish` into it.
        if effective_override().is_some() {
            return;
        }
        let Ok(new) = config_dir() else { return };
        // Already populated → nothing to relocate.
        if new.join("secret_key").exists()
            || new.join(SETTINGS_FILE).exists()
            || new.join(LEGACY_FILE).exists()
            || new.join(NETWORKS_SUBDIR).is_dir()
        {
            return;
        }
        let Some(old) = dirs::config_dir().map(|d| d.join("rayfish")) else {
            return;
        };
        if old == new || !old.is_dir() {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&old) else {
            return;
        };
        let mut moved = 0;
        for e in entries.flatten() {
            let dest = new.join(e.file_name());
            // Same-filesystem rename is atomic; if it fails (e.g. EXDEV across
            // mounts) the entry is left in place and the daemon starts fresh,
            // logged so the operator can move it by hand.
            match std::fs::rename(e.path(), &dest) {
                Ok(()) => moved += 1,
                Err(err) => {
                    tracing::warn!(entry = ?e.path(), error = %err, "could not relocate config entry into /etc/rayfish")
                }
            }
        }
        if moved > 0 {
            // Lock the relocated tree down: secrets keep old, possibly-loose perms
            // (older builds wrote the key without restricting it). Be conservative
            // by using 0600 everything; later targeted writes relax non-secret files.
            if let Ok(entries) = std::fs::read_dir(&new) {
                for e in entries.flatten() {
                    if e.path().is_file() {
                        restrict_perms(&e.path(), true);
                    }
                }
            }
            tracing::info!(from = %old.display(), to = %new.display(), entries = moved, "relocated config tree to /etc/rayfish");
        }
    }
}

/// One-time migration: split a legacy single `networks.toml` into the sharded
/// layout, keeping the original as `networks.toml.bak` (never deleted).
fn migrate_legacy(dir: &Path) -> Result<()> {
    let legacy = dir.join(LEGACY_FILE);
    if !legacy.exists() {
        return Ok(());
    }
    let contents = std::fs::read_to_string(&legacy).context("reading legacy networks.toml")?;
    let old: AppConfig = toml::from_str(&contents).context("parsing legacy networks.toml")?;

    save_settings_in(dir, &old)?;
    for net in &old.networks {
        save_network_unlocked(dir, net)?;
    }

    let bak = dir.join("networks.toml.bak");
    std::fs::rename(&legacy, &bak)
        .with_context(|| format!("renaming legacy config to {}", bak.display()))?;
    tracing::info!(backup = %bak.display(), networks = old.networks.len(), "migrated legacy config to per-network files");
    Ok(())
}

/// Load the full config, assembling it from `settings.toml` + `networks/*.toml`.
/// Returns a default config if nothing is stored yet. Runs the legacy migration
/// on first call after an upgrade.
pub fn load() -> Result<AppConfig> {
    ensure_not_in_network_update()?;
    let dir = config_dir()?;
    {
        let _guard = NETWORK_CONFIG_LOCK
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        migrate_legacy(&dir)?;
    }
    let _guard = NETWORK_CONFIG_LOCK
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    load_in(&dir)
}

/// The two settings the connect channel checks on every inbound dial.
#[derive(Debug, Clone, Default)]
pub struct InboundSettings {
    pub inbound: InboundPolicy,
    pub blocked: Vec<EndpointId>,
}

/// [`InboundSettings`] from `settings.toml` alone. It runs on every inbound
/// connect dial, strangers included, so it skips the network files and the
/// legacy migration [`load`] performs.
pub fn load_inbound() -> Result<InboundSettings> {
    ensure_not_in_network_update()?;
    let path = config_dir()?.join(SETTINGS_FILE);
    let _guard = NETWORK_CONFIG_LOCK
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !path.exists() {
        return Ok(InboundSettings::default());
    }
    let contents = std::fs::read_to_string(&path).context("reading settings.toml")?;
    let settings: Settings = toml::from_str(&contents).context("parsing settings.toml")?;
    Ok(InboundSettings {
        inbound: settings.inbound,
        blocked: settings.blocked,
    })
}

/// [`load`] for a process that only reads the daemon's config (the CLI when the
/// daemon is down). Creates nothing and runs no migration; a config tree that
/// isn't there, or isn't readable by this user, reads as an empty config.
pub fn load_for_read() -> Result<AppConfig> {
    ensure_not_in_network_update()?;
    let _guard = NETWORK_CONFIG_LOCK
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    load_in(&config_dir_for_read()?)
}

fn load_in(dir: &Path) -> Result<AppConfig> {
    let settings_path = dir.join(SETTINGS_FILE);
    let settings: Settings = if settings_path.exists() {
        let s = std::fs::read_to_string(&settings_path).context("reading settings.toml")?;
        toml::from_str(&s).context("parsing settings.toml")?
    } else {
        // Fresh install: discovery, `.ray`-only Magic DNS, on-demand and the pf
        // passthrough are on, and mesh SSH uses port 22, matching the serde
        // field defaults.
        Settings {
            mdns_enabled: true,
            dns_mode: DnsMode::default(),
            ssh_port: default_ssh_port(),
            v4_bridge: true,
            pf_passthrough: true,
            on_demand: true,
            ..Default::default()
        }
    };

    let mut networks = Vec::new();
    let ndir = dir.join(NETWORKS_SUBDIR);
    if ndir.is_dir() {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&ndir)
            .with_context(|| format!("reading {}", ndir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "toml").unwrap_or(false))
            .collect();
        paths.sort();
        for p in paths {
            let s =
                std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            // Atomic writes make a torn file unreachable, but be defensive: skip
            // an unparseable network rather than failing the whole load.
            match toml::from_str::<NetworkConfig>(&s) {
                Ok(nc) => networks.push(nc),
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "skipping unreadable network config")
                }
            }
        }
    }

    Ok(AppConfig {
        mdns_enabled: settings.mdns_enabled,
        operator_uid: settings.operator_uid,
        default_hostname: settings.default_hostname,
        relay: settings.relay,
        discovery_dns: settings.discovery_dns,
        dns_upstreams: settings.dns_upstreams,
        dns_mode: settings.dns_mode,
        quic_engine: settings.quic_engine,
        endpoint_hints: settings.endpoint_hints,
        ssh_enabled: settings.ssh_enabled,
        ssh_port: settings.ssh_port,
        v4_bridge: settings.v4_bridge,
        pf_passthrough: settings.pf_passthrough,
        on_demand: settings.on_demand,
        idle_timeout_secs: settings.idle_timeout_secs,
        auto_update: settings.auto_update,
        auto_update_last_target: settings.auto_update_last_target,
        auto_update_last_attempt: settings.auto_update_last_attempt,
        file_auto_accept_peers: settings.file_auto_accept_peers,
        inbound: settings.inbound,
        blocked: settings.blocked,
        download_dir: settings.download_dir,
        download_user: settings.download_user,
        networks,
        pending_joins: settings.pending_joins,
        cert_generation: settings.cert_generation,
        device_generations: settings.device_generations,
        revoked_devices: settings.revoked_devices,
        pending_unpairs: settings.pending_unpairs,
        pending_unpair_notices: settings.pending_unpair_notices,
        controllers: settings.controllers,
        managed_machines: settings.managed_machines,
        forgotten_machines: settings.forgotten_machines,
        enrollment_credentials: settings.enrollment_credentials,
    })
}

/// Atomically load, synchronously mutate, and save the globals. The read and the
/// write happen under one exclusive guard, so two tasks changing different
/// globals cannot lose each other's field the way a `load` + `save_settings`
/// pair does. Returns the saved config.
///
/// Same contract as [`update_network`]: the callback must not call another
/// config API, and the guard is deliberately never held across an await.
pub fn update_settings(update: impl FnOnce(&mut AppConfig) -> Result<()>) -> Result<AppConfig> {
    update_settings_in(&config_dir()?, update)
}

fn update_settings_in(
    dir: &Path,
    update: impl FnOnce(&mut AppConfig) -> Result<()>,
) -> Result<AppConfig> {
    ensure_not_in_network_update()?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut config = load_in(dir)?;
    let before = settings_toml(&config)?;
    let update_scope = NetworkUpdateScope::enter()?;
    let applied = update(&mut config);
    drop(update_scope);
    applied?;
    // A callback that decided there was nothing to do must not cost a write:
    // every save fsyncs the file and its directory entry.
    if settings_toml(&config)? != before {
        save_settings_in(dir, &config)?;
    }
    Ok(config)
}

fn save_settings_in(dir: &Path, config: &AppConfig) -> Result<()> {
    let path = dir.join(SETTINGS_FILE);
    let contents = settings_toml(config)?;
    // Owner-only: it names the operator and trusted peers.
    write_atomic(&path, &contents, true)
}

/// The `settings.toml` projection of `config`, serialized. Also the change
/// detector for [`update_settings`]: identical text means nothing to write.
fn settings_toml(config: &AppConfig) -> Result<String> {
    let settings = Settings {
        mdns_enabled: config.mdns_enabled,
        operator_uid: config.operator_uid,
        default_hostname: config.default_hostname.clone(),
        relay: config.relay.clone(),
        discovery_dns: config.discovery_dns.clone(),
        dns_upstreams: config.dns_upstreams.clone(),
        dns_mode: config.dns_mode,
        quic_engine: config.quic_engine,
        endpoint_hints: config.endpoint_hints.clone(),
        ssh_enabled: config.ssh_enabled,
        ssh_port: config.ssh_port,
        v4_bridge: config.v4_bridge,
        pf_passthrough: config.pf_passthrough,
        on_demand: config.on_demand,
        idle_timeout_secs: config.idle_timeout_secs,
        auto_update: config.auto_update,
        auto_update_last_target: config.auto_update_last_target.clone(),
        auto_update_last_attempt: config.auto_update_last_attempt,
        file_auto_accept_peers: config.file_auto_accept_peers.clone(),
        inbound: config.inbound,
        blocked: config.blocked.clone(),
        download_dir: config.download_dir.clone(),
        download_user: config.download_user,
        pending_joins: config.pending_joins.clone(),
        cert_generation: config.cert_generation,
        device_generations: config.device_generations.clone(),
        revoked_devices: config.revoked_devices.clone(),
        pending_unpairs: config.pending_unpairs.clone(),
        pending_unpair_notices: config.pending_unpair_notices.clone(),
        controllers: config.controllers.clone(),
        managed_machines: config.managed_machines.clone(),
        forgotten_machines: config.forgotten_machines.clone(),
        enrollment_credentials: config.enrollment_credentials.clone(),
    };
    toml::to_string_pretty(&settings).context("serializing settings")
}

/// Record a queued join so its background retry survives a daemon restart.
/// Idempotent: a second call with the same key updates the stored name and
/// transport but does not duplicate the entry.
pub fn add_pending_join(entry: PendingJoinEntry) -> Result<()> {
    add_pending_join_in(&config_dir()?, entry)
}

fn add_pending_join_in(dir: &Path, entry: PendingJoinEntry) -> Result<()> {
    update_settings_in(dir, |cfg| {
        if let Some(existing) = cfg
            .pending_joins
            .iter_mut()
            .find(|e| e.network_key == entry.network_key)
        {
            existing.name = entry.name;
            existing.transport = entry.transport;
        } else {
            cfg.pending_joins.push(entry);
        }
        Ok(())
    })?;
    Ok(())
}

/// Drop a pending-join marker once the network is admitted (or abandoned).
pub fn remove_pending_join(network_key: &str) -> Result<()> {
    remove_pending_join_in(&config_dir()?, network_key)
}

fn remove_pending_join_in(dir: &Path, network_key: &str) -> Result<()> {
    update_settings_in(dir, |cfg| {
        cfg.pending_joins.retain(|e| e.network_key != network_key);
        Ok(())
    })?;
    Ok(())
}

/// Persist a single network to `networks/<name>.toml`. Direct full-record
/// writes share the same transaction boundary as updates and deletes.
pub fn save_network(net: &NetworkConfig) -> Result<()> {
    ensure_not_in_network_update()?;
    let dir = config_dir()?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    save_network_unlocked(&dir, net)
}

/// Caller holds [`NETWORK_CONFIG_LOCK`] when this runs in production.
fn save_network_unlocked(dir: &Path, net: &NetworkConfig) -> Result<()> {
    validate_net_name(&net.name)?;
    if let Some(key) = net
        .network_public_key
        .or_else(|| net.network_secret_key.as_ref().map(SecretKey::public))
    {
        anyhow::ensure!(
            destruction::load_in(dir, key)?.is_none(),
            "network has been destroyed"
        );
    }
    let ndir = dir.join(NETWORKS_SUBDIR);
    let path = ndir.join(format!("{}.toml", net.name));
    let contents = toml::to_string_pretty(net).context("serializing network config")?;
    // Secret-bearing: holds the per-network coordinator secret key.
    write_atomic(&path, &contents, true)
}

/// Load a single network's config, if present.
pub fn load_network(name: &str) -> Result<Option<NetworkConfig>> {
    ensure_not_in_network_update()?;
    let dir = config_dir()?;
    let _guard = NETWORK_CONFIG_LOCK
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    load_network_unlocked(&dir, name)
}

/// Caller holds [`NETWORK_CONFIG_LOCK`] when this runs in production.
fn load_network_unlocked(dir: &Path, name: &str) -> Result<Option<NetworkConfig>> {
    validate_net_name(name)?;
    let path = dir.join(NETWORKS_SUBDIR).join(format!("{name}.toml"));
    if !path.exists() {
        return Ok(None);
    }
    let s =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(
        toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))?,
    ))
}

/// Atomically load, synchronously mutate, and save an existing network's latest
/// config. The callback must not call another network-config API; the lock is
/// deliberately never held across an await. Returns `None` when the network was
/// deleted or never existed.
pub fn update_network(
    name: &str,
    update: impl FnOnce(&mut NetworkConfig) -> Result<()>,
) -> Result<Option<NetworkConfig>> {
    update_network_in(&config_dir()?, name, update)
}

fn update_network_in(
    dir: &Path,
    name: &str,
    update: impl FnOnce(&mut NetworkConfig) -> Result<()>,
) -> Result<Option<NetworkConfig>> {
    ensure_not_in_network_update()?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(mut net) = load_network_unlocked(dir, name)? else {
        return Ok(None);
    };
    if apply_network_update(name, &mut net, update)? {
        save_network_unlocked(dir, &net)?;
    } else {
        // A prior atomic write may have installed this exact file and then
        // reported an ambiguous parent-directory sync failure. A no-op retry is
        // still a durability barrier, not merely a serialization optimization.
        let path = dir.join(NETWORKS_SUBDIR).join(format!("{name}.toml"));
        sync_file_and_parent(&path)?;
    }
    Ok(Some(net))
}

/// Run one network update callback against `net`, which was loaded for `name`.
/// Refuses a stored record or an update that names a different network, and
/// returns whether the callback changed the serialized record.
fn apply_network_update(
    name: &str,
    net: &mut NetworkConfig,
    update: impl FnOnce(&mut NetworkConfig) -> Result<()>,
) -> Result<bool> {
    anyhow::ensure!(
        net.name == name,
        "network config {name:?} contains mismatched name {:?}",
        net.name
    );
    let before = toml::to_string(net).context("serializing network config")?;
    let update_scope = NetworkUpdateScope::enter()?;
    update(net)?;
    drop(update_scope);
    anyhow::ensure!(
        net.name == name,
        "network update cannot rename {name:?} to {:?}",
        net.name
    );
    let after = toml::to_string(net).context("serializing network config")?;
    Ok(after != before)
}

/// Atomically update the latest network config, inserting `initial` only when
/// the network is absent. This is the fresh-join counterpart to
/// [`update_network`]; existing node-local fields remain available to `update`.
pub fn update_network_or_insert(
    name: &str,
    initial: NetworkConfig,
    update: impl FnOnce(&mut NetworkConfig) -> Result<()>,
) -> Result<NetworkConfig> {
    update_network_or_insert_in(&config_dir()?, name, initial, update)
}

fn update_network_or_insert_in(
    dir: &Path,
    name: &str,
    initial: NetworkConfig,
    update: impl FnOnce(&mut NetworkConfig) -> Result<()>,
) -> Result<NetworkConfig> {
    ensure_not_in_network_update()?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let existing = load_network_unlocked(dir, name)?;
    let inserting = existing.is_none();
    let mut net = existing.unwrap_or(initial);
    let changed = apply_network_update(name, &mut net, update)?;
    if inserting || changed {
        save_network_unlocked(dir, &net)?;
    }
    Ok(net)
}

/// Delete a single network's config file. Returns true if it existed.
pub fn delete_network(name: &str) -> Result<bool> {
    ensure_not_in_network_update()?;
    let dir = config_dir()?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    delete_network_unlocked(&dir, name)
}

/// Make the deletions made so far in the config tree durable, which removing a
/// file is not until its directory is synced. An unpair confirms its cleanup
/// only once the networks and certificate it deleted stay deleted.
pub fn sync_deletions() -> Result<()> {
    let dir = config_dir()?;
    let networks = dir.join(NETWORKS_SUBDIR);
    if networks.is_dir() {
        sync_dir(&networks)?;
    }
    sync_dir(&dir)
}

/// Caller holds [`NETWORK_CONFIG_LOCK`] when this runs in production.
fn delete_network_unlocked(dir: &Path, name: &str) -> Result<bool> {
    validate_net_name(name)?;
    let path = dir.join(NETWORKS_SUBDIR).join(format!("{name}.toml"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// A `ray rename` in progress, saved before the network's file moves. See
/// [`rename_network`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameIntent {
    pub from: String,
    pub to: String,
}

const RENAME_INTENT_FILE: &str = "rename-intent.toml";

/// Save a network's config under a new local name: `networks/<from>.toml`
/// becomes `networks/<to>.toml`, the name inside it follows, and so does the
/// network's invite ledger (`invites/<from>.toml`), without which its
/// single-use invites could no longer be redeemed, listed or revoked. Returns
/// the renamed config, or `None` when no network is saved as `from`, and
/// refuses a `to` that is taken.
///
/// The move and the rewrite after it are two steps, and between them the file
/// lists the network under a name it cannot be loaded by, so neither name
/// restores it. A [`RenameIntent`] is saved first, and from then on the rename
/// is committed: a start that finds the intent completes it with
/// [`finish_rename`] before restoring any network. The intent also covers what
/// the caller renames after this returns (the firewall rules that name the
/// network), so the caller clears it with [`clear_rename_intent`] once those
/// are saved too. While it stands, another rename is refused.
///
/// The file is moved, not copied and then deleted: a crash between a copy and
/// the delete would leave the network saved twice, under two names that would
/// both restore it.
pub fn rename_network(from: &str, to: &str) -> Result<Option<NetworkConfig>> {
    rename_network_in(&config_dir()?, from, to)
}

fn rename_network_in(dir: &Path, from: &str, to: &str) -> Result<Option<NetworkConfig>> {
    ensure_not_in_network_update()?;
    validate_net_name(to)?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pending) = load_rename_intent(dir)? {
        anyhow::bail!(
            "renaming network {:?} to {:?} has not finished; restart the daemon to finish it",
            pending.from,
            pending.to
        );
    }
    let Some(net) = load_network_unlocked(dir, from)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        net.name == from,
        "network config {from:?} contains mismatched name {:?}",
        net.name
    );
    let target = dir.join(NETWORKS_SUBDIR).join(format!("{to}.toml"));
    anyhow::ensure!(!target.exists(), "a network is already saved as {to:?}");
    let intent = RenameIntent {
        from: from.to_string(),
        to: to.to_string(),
    };
    let contents = toml::to_string(&intent).context("serializing rename intent")?;
    write_atomic(&dir.join(RENAME_INTENT_FILE), &contents, false)?;
    finish_rename_unlocked(dir, &intent)
}

/// The rename that has not finished, if one is saved.
pub fn rename_intent() -> Result<Option<RenameIntent>> {
    ensure_not_in_network_update()?;
    let dir = config_dir()?;
    let _guard = NETWORK_CONFIG_LOCK
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    load_rename_intent(&dir)
}

fn load_rename_intent(dir: &Path) -> Result<Option<RenameIntent>> {
    let path = dir.join(RENAME_INTENT_FILE);
    let s = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    Ok(Some(
        toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))?,
    ))
}

/// Complete the config half of a saved rename: move the network's file if it
/// has not moved yet, then its invite ledger, then rewrite the name inside it if
/// that is still the old one. Safe to repeat. Returns the renamed config, or `None` when there is
/// nothing to rename: the network is gone, or another file was saved under the
/// new name by hand, which the daemon itself never does while the intent stands.
pub fn finish_rename(intent: &RenameIntent) -> Result<Option<NetworkConfig>> {
    finish_rename_in(&config_dir()?, intent)
}

fn finish_rename_in(dir: &Path, intent: &RenameIntent) -> Result<Option<NetworkConfig>> {
    ensure_not_in_network_update()?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    finish_rename_unlocked(dir, intent)
}

/// Caller holds [`NETWORK_CONFIG_LOCK`] when this runs in production.
fn finish_rename_unlocked(dir: &Path, intent: &RenameIntent) -> Result<Option<NetworkConfig>> {
    let RenameIntent { from, to } = intent;
    validate_net_name(from)?;
    validate_net_name(to)?;
    let ndir = dir.join(NETWORKS_SUBDIR);
    let source = ndir.join(format!("{from}.toml"));
    let target = ndir.join(format!("{to}.toml"));
    if source.exists() {
        if target.exists() {
            return Ok(None);
        }
        std::fs::rename(&source, &target)
            .with_context(|| format!("renaming network config {from:?} to {to:?}"))?;
        sync_dir(&ndir)?;
    }
    let Some(mut net) = load_network_unlocked(dir, to)? else {
        return Ok(None);
    };
    // Moved over any ledger left under the new name by a network saved there
    // before, whose invites no longer name a network here.
    let ledger = crate::invite::ledger_path_in(dir, from);
    if ledger.exists() {
        let moved = crate::invite::ledger_path_in(dir, to);
        std::fs::rename(&ledger, &moved)
            .with_context(|| format!("moving network {from:?}'s invites to {to:?}"))?;
        sync_dir(moved.parent().context("invite ledger has no directory")?)?;
    }
    if net.name != *to {
        anyhow::ensure!(
            net.name == *from,
            "network config {to:?} contains mismatched name {:?}",
            net.name
        );
        net.name = to.clone();
        save_network_unlocked(dir, &net)?;
    }
    Ok(Some(net))
}

/// Forget a rename once everything that names the network follows it.
pub fn clear_rename_intent() -> Result<()> {
    clear_rename_intent_in(&config_dir()?)
}

fn clear_rename_intent_in(dir: &Path) -> Result<()> {
    ensure_not_in_network_update()?;
    let _guard = NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = dir.join(RENAME_INTENT_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => sync_dir(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Add or update a network in the config. If a network with the same name
/// already exists, it is replaced.
pub fn upsert_network(config: &mut AppConfig, network: NetworkConfig) {
    if let Some(existing) = config.networks.iter_mut().find(|n| n.name == network.name) {
        *existing = network;
    } else {
        config.networks.push(network);
    }
}

/// Remove a network by name. Returns true if it was found and removed.
pub fn remove_network(config: &mut AppConfig, name: &str) -> bool {
    let before = config.networks.len();
    config.networks.retain(|n| n.name != name);
    config.networks.len() < before
}

/// Process-wide lock serializing tests that mutate `RAYFISH_CONFIG_DIR` (or any
/// other env var read by [`config_dir`]), since lib tests share one process and
/// run on parallel threads. Shared across test modules (`identity`, `daemon`)
/// so none of them observe a `RAYFISH_CONFIG_DIR` value set by a concurrent test.
#[cfg(test)]
pub(crate) static CONFIG_ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests;
