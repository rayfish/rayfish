use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::Permissions;
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
#[cfg(not(windows))]
use std::sync::atomic::{AtomicU64, Ordering};
// Only the test-only `CONFIG_ENV_LOCK` holds one.
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

use crate::membership::GroupMode;

/// Per-network transport preference. Defined in `ray-proto` (shared with GUI
/// frontends); re-exported here so existing `crate::config::TransportMode` paths work.
pub use ray_proto::TransportMode;

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
/// captured ones. Unset returns the captured set unchanged.
///
/// IPv4 only, and deliberately so: the captured set this merges with comes from
/// the OS DNS backends, every one of which reads an IPv4 nameserver. A configured
/// IPv6 entry is not dropped so much as handled elsewhere, by
/// [`crate::exit_node::tunnel_upstreams`], which is the one caller that has a
/// path to reach it (an IPv6-only full tunnel, where the IPv4 ones are the
/// unreachable half).
pub fn resolve_upstreams(o: &ServerOverride, captured: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    if o.servers.is_empty() {
        return captured;
    }
    let custom: Vec<Ipv4Addr> = o.servers.iter().filter_map(|s| s.parse().ok()).collect();
    if o.replace {
        // `dns_upstreams` takes any `IpAddr` since IPv6-only tunnels needed it, so
        // an all-IPv6 `--replace` narrows to nothing here. Returning that empty
        // list would leave both consumers with no server at all: the forwarder
        // SERVFAILs every non-`.ray` name, and `control_plane_nameservers` falls
        // back to iroh's own resolv.conf reader, which is the #111 circle. Keep
        // the captured ones instead: the IPv6 entries are still honoured, by
        // `exit_node::tunnel_upstreams`, which is the caller that can reach them.
        if custom.is_empty() {
            return captured;
        }
        custom
    } else {
        custom.into_iter().chain(captured).collect()
    }
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
    o.servers.iter().any(|s| s.parse::<Ipv4Addr>().is_ok())
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
        last_group_hash: None,
        last_group_hash_published: true,
        transport: None,
        auto_accept_firewall: false,
        auto_accept_files: true,
        admins: vec![],
        direct: false,
        direct_peer: None,
        ssh_allow: vec![],
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
    /// Per-user "contact key" used by `ray connect`: a standing, rotatable
    /// identity (distinct from the transport key and per-network keys) published
    /// to pkarr so others can request a direct connection without a room id or
    /// invite code. Lazily generated on first use via [`contact_secret`].
    #[serde(default, with = "option_secret_key_hex")]
    pub contact_secret_key: Option<SecretKey>,
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
    /// Recently successful peer transport paths.  These are only connection
    /// hints: iroh still authenticates the endpoint identity in TLS and falls
    /// back to its normal discovery services when a hint is stale.  Keeping
    /// them lets a restart try a known LAN/direct path or relay immediately,
    /// before a pkarr lookup completes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_hints: Vec<iroh::EndpointAddr>,
    /// Global toggle for the embedded mesh SSH server (`ray firewall ssh on`).
    /// When on, the daemon listens on each mesh IP's port 22 and admits peers
    /// authorized in a network's [`NetworkConfig::ssh_allow`] list. Off by default.
    #[serde(default)]
    pub ssh_enabled: bool,
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
    /// Absolute directory where auto-accepted (own-device) files are written.
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
    /// Legacy device-cert generation counter (pre-nullifier revocation). No longer
    /// used for revocation decisions; kept only so old `settings.toml` files parse.
    #[serde(default)]
    pub cert_generation: u64,
    /// Device keys this user has nullified via `ray unpair` (hex `EndpointId`). The
    /// coordinator's durable nullifier seed: it survives a restart and is unioned
    /// into every coordinated network's signed blob (`GroupBlob.nullifiers`) at seal
    /// time, so a listed device's cert is rejected mesh-wide. A device is removed
    /// here when it re-pairs (re-auth). See `Daemon::unpair`/`reauth_device`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_devices: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mdns_enabled: true,
            operator_uid: None,
            default_hostname: None,
            contact_secret_key: None,
            relay: ServerOverride::default(),
            discovery_dns: ServerOverride::default(),
            dns_upstreams: ServerOverride::default(),
            endpoint_hints: Vec::new(),
            ssh_enabled: false,
            v4_bridge: true,
            pf_passthrough: true,
            on_demand: true,
            idle_timeout_secs: None,
            auto_update: false,
            auto_update_last_target: None,
            auto_update_last_attempt: None,
            download_dir: None,
            download_user: None,
            networks: Vec::new(),
            pending_joins: Vec::new(),
            cert_generation: 0,
            revoked_devices: Vec::new(),
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

/// Return this node's contact key, generating and persisting it on first use.
/// The caller is responsible for `save`-ing the config afterwards (the returned
/// secret is also written into `config.contact_secret_key`).
pub fn contact_secret(config: &mut AppConfig) -> SecretKey {
    if let Some(k) = &config.contact_secret_key {
        return k.clone();
    }
    let secret = SecretKey::generate();
    config.contact_secret_key = Some(secret.clone());
    secret
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

/// Rotate this node's contact key, replacing it with a fresh one. The old
/// contact id stops resolving once its pkarr record TTLs out. The caller must
/// `save` the config afterwards.
pub fn rotate_contact_secret(config: &mut AppConfig) -> SecretKey {
    let secret = SecretKey::generate();
    config.contact_secret_key = Some(secret.clone());
    secret
}

// ---- Storage layout -------------------------------------------------------
//
// Config is sharded so a write to one network can never clobber another:
//
//   <config_dir>/settings.toml          globals (mdns, operator, default
//                                        hostname, contact key), secret-bearing
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
        IN_NETWORK_CONFIG_UPDATE.with(|active| {
            anyhow::ensure!(
                !active.get(),
                "network config update callbacks must not call network config APIs"
            );
            active.set(true);
            Ok(Self)
        })
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
/// the fresh-install default that actually ships (`mdns` on) is built at the one
/// `load_in` site with a `mdns_enabled: true` struct-update override.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Settings {
    #[serde(default = "default_true")]
    mdns_enabled: bool,
    #[serde(default)]
    operator_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_hostname: Option<String>,
    #[serde(default, with = "option_secret_key_hex")]
    contact_secret_key: Option<SecretKey>,
    #[serde(default)]
    relay: ServerOverride,
    #[serde(default)]
    discovery_dns: ServerOverride,
    #[serde(default)]
    dns_upstreams: ServerOverride,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoint_hints: Vec<iroh::EndpointAddr>,
    #[serde(default)]
    ssh_enabled: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    download_user: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_joins: Vec<PendingJoinEntry>,
    #[serde(default)]
    cert_generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revoked_devices: Vec<String>,
}

/// Look up the `rayfish` group's gid (Linux), if the group exists.
#[cfg(target_os = "linux")]
fn rayfish_gid() -> Option<u32> {
    use std::ffi::CString;
    let name = CString::new("rayfish").ok()?;
    // SAFETY: getgrnam returns a pointer to a static struct; we copy gr_gid out
    // immediately before any further libc call could overwrite it.
    let grp = unsafe { libc::getgrnam(name.as_ptr()) };
    if grp.is_null() {
        None
    } else {
        Some(unsafe { (*grp).gr_gid })
    }
}

/// Best-effort `chown` to root, with group `rayfish` for non-secret paths (or
/// root for secret ones). No-op off Linux. Silent on failure so the daemon
/// still starts if the group is missing.
#[cfg(target_os = "linux")]
fn set_owner(path: &Path, secret: bool) {
    let gid = if secret {
        Some(0)
    } else {
        rayfish_gid().or(Some(0))
    };
    if let Err(e) = std::os::unix::fs::chown(path, Some(0), gid) {
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

/// The override in effect: the embedder's [`set_config_dir_override`] first,
/// then `RAYFISH_CONFIG_DIR`. `None` means the platform default applies.
fn effective_override() -> Option<PathBuf> {
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

/// Serial number for temp file names, so two writers in this process never
/// share one. See [`write_file`], which uses an unguessable nonce on Windows
/// instead and so needs no counter.
#[cfg(not(windows))]
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Re-establish the durability barrier for a file already in place: fsync the
/// file, then the directory entry naming it. A [`write_file`] that failed
/// ambiguously may have installed the bytes anyway, so a no-op retry still has
/// to prove the result is on disk before anything is allowed to point at it.
fn sync_file_and_parent(path: &Path) -> Result<()> {
    let dir = path.parent().context("config path has no parent")?;
    std::fs::File::open(path)
        .with_context(|| format!("opening {} to sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    sync_dir(dir)
}

/// Atomically and durably write `bytes` to `path`: write a sibling temp file,
/// set its perms/owner, then rename over the target. The rename is atomic on
/// POSIX, so a concurrent reader sees either the old file or the new one, never
/// a torn one. `secret` selects 0600 root:root vs 0640 root:rayfish.
///
/// Returning `Ok` means the bytes are on disk and reachable under `path` after
/// a power loss, not just in the page cache: the contents are fsynced before
/// the rename and the directory entry after it, and a failure of either is an
/// error rather than a shrug. Callers that persist a pointer to something else
/// (the coordinator recovery hash) depend on that barrier being exact.
///
/// Public so every rayfish config writer (identity key, invite ledger, etc.)
/// shares the same atomic + restrictive-perms guarantees under the config tree.
pub fn write_file(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let dir = path.parent().context("config path has no parent")?;
    ensure_dir(dir)?;
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    // The pid keeps two processes apart and the counter keeps two threads of
    // this one apart. A temp path shared by two writers of the same file lets
    // one rename a file the other has only half filled.
    //
    // Windows uses a random nonce instead: the stage file is created with
    // `CREATE_NEW` and an explicit DACL, so an unpredictable name means nothing
    // can be sitting on the path we are about to claim.
    #[cfg(windows)]
    let tmp = windows_config_stage_path(dir, fname);
    #[cfg(not(windows))]
    let tmp = {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        dir.join(format!(".{fname}.tmp.{}.{seq}", std::process::id()))
    };
    let staged = stage_temp(&tmp, bytes, secret).and_then(|()| {
        // Refuse to rename over something that is not a plain file we own: on
        // Windows the target could have been swapped for a reparse point
        // between the last write and this one.
        #[cfg(all(windows, not(test)))]
        validate_existing_windows_config_child(path)?;
        std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))
    });
    if staged.is_err() {
        // Clean up on any failure so we don't litter: the temp path is ours
        // alone, so nothing else can be waiting on it.
        let _ = std::fs::remove_file(&tmp);
        return staged;
    }
    sync_dir(dir)
}

/// Fill `tmp` with `bytes` and give it the target's perms/owner, leaving it
/// ready to rename into place.
fn stage_temp(tmp: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    {
        use std::io::Write;
        #[cfg(windows)]
        let mut f = create_windows_config_stage(tmp)?;
        #[cfg(not(windows))]
        let mut f =
            std::fs::File::create(tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing {}", tmp.display()))?;
        // Discarding this used to report a write as saved while the bytes were
        // still only in the page cache, so a crash could roll the file back to
        // its previous contents with nothing having failed.
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
    }
    // Windows has no mode bits to set here. `create_windows_config_stage` gave
    // the file an explicit SYSTEM + Administrators DACL with inheritance off at
    // creation, which is stricter than either Unix mode, so `secret` has
    // nothing left to select between.
    #[cfg(windows)]
    let _ = secret;
    #[cfg(unix)]
    {
        let mode = if secret { 0o600 } else { 0o640 };
        let _ = std::fs::set_permissions(tmp, Permissions::from_mode(mode));
    }
    #[cfg(target_os = "linux")]
    set_owner(tmp, secret);
    Ok(())
}

/// fsync a directory, so a rename into it survives a power loss. Without this
/// the new file's contents are durable but the name is not, and the target can
/// come back as the old file or as nothing at all.
fn sync_dir(dir: &Path) -> Result<()> {
    // Windows has no equivalent: a directory cannot be opened as a file for the
    // flush, and there is no API that commits a rename the way fsync does. The
    // stage file's own `sync_all` is the whole barrier available there.
    #[cfg(windows)]
    {
        let _ = dir;
        Ok(())
    }
    #[cfg(not(windows))]
    std::fs::File::open(dir)
        .with_context(|| format!("opening {} to sync", dir.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", dir.display()))
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

fn write_atomic(path: &Path, contents: &str, secret: bool) -> Result<()> {
    write_file(path, contents.as_bytes(), secret)
}

/// Apply restrictive perms/owner to an existing file under the config tree.
/// For append-mode files (e.g. the audit log) that aren't rewritten via
/// [`write_file`]. Best-effort.
pub fn restrict_perms(path: &Path, secret: bool) {
    #[cfg(all(windows, test))]
    let _ = (path, secret);
    #[cfg(all(windows, not(test)))]
    if secret && let Err(error) = crate::windows_security::protect_file(path) {
        tracing::error!(path = %path.display(), %error, "failed to protect Windows config file");
    }
    #[cfg(unix)]
    {
        let mode = if secret { 0o600 } else { 0o640 };
        let _ = std::fs::set_permissions(path, Permissions::from_mode(mode));
    }
    #[cfg(target_os = "linux")]
    set_owner(path, secret);
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
        // Fresh install: mDNS discovery is on by default, everything else is the
        // type-default.
        Settings {
            mdns_enabled: true,
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
        contact_secret_key: settings.contact_secret_key,
        relay: settings.relay,
        discovery_dns: settings.discovery_dns,
        dns_upstreams: settings.dns_upstreams,
        endpoint_hints: settings.endpoint_hints,
        ssh_enabled: settings.ssh_enabled,
        v4_bridge: settings.v4_bridge,
        pf_passthrough: settings.pf_passthrough,
        on_demand: settings.on_demand,
        idle_timeout_secs: settings.idle_timeout_secs,
        auto_update: settings.auto_update,
        auto_update_last_target: settings.auto_update_last_target,
        auto_update_last_attempt: settings.auto_update_last_attempt,
        download_dir: settings.download_dir,
        download_user: settings.download_user,
        networks,
        pending_joins: settings.pending_joins,
        cert_generation: settings.cert_generation,
        revoked_devices: settings.revoked_devices,
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
    // Secret-bearing: holds the contact key.
    write_atomic(&path, &contents, true)
}

/// The `settings.toml` projection of `config`, serialized. Also the change
/// detector for [`update_settings`]: identical text means nothing to write.
fn settings_toml(config: &AppConfig) -> Result<String> {
    let settings = Settings {
        mdns_enabled: config.mdns_enabled,
        operator_uid: config.operator_uid,
        default_hostname: config.default_hostname.clone(),
        contact_secret_key: config.contact_secret_key.clone(),
        relay: config.relay.clone(),
        discovery_dns: config.discovery_dns.clone(),
        dns_upstreams: config.dns_upstreams.clone(),
        endpoint_hints: config.endpoint_hints.clone(),
        ssh_enabled: config.ssh_enabled,
        v4_bridge: config.v4_bridge,
        pf_passthrough: config.pf_passthrough,
        on_demand: config.on_demand,
        idle_timeout_secs: config.idle_timeout_secs,
        auto_update: config.auto_update,
        auto_update_last_target: config.auto_update_last_target.clone(),
        auto_update_last_attempt: config.auto_update_last_attempt,
        download_dir: config.download_dir.clone(),
        download_user: config.download_user,
        pending_joins: config.pending_joins.clone(),
        cert_generation: config.cert_generation,
        revoked_devices: config.revoked_devices.clone(),
    };
    toml::to_string_pretty(&settings).context("serializing settings")
}

/// Record a queued join so its background retry survives a daemon restart.
/// Idempotent: a second call with the same key updates the stored name but
/// does not duplicate the entry.
pub fn add_pending_join(entry: PendingJoinEntry) -> Result<()> {
    add_pending_join_in(&config_dir()?, entry)
}

fn add_pending_join_in(dir: &Path, entry: PendingJoinEntry) -> Result<()> {
    let mut cfg = load_in(dir)?;
    if let Some(existing) = cfg
        .pending_joins
        .iter_mut()
        .find(|e| e.network_key == entry.network_key)
    {
        existing.name = entry.name;
    } else {
        cfg.pending_joins.push(entry);
    }
    save_settings_in(dir, &cfg)
}

/// Drop a pending-join marker once the network is admitted (or abandoned).
pub fn remove_pending_join(network_key: &str) -> Result<()> {
    remove_pending_join_in(&config_dir()?, network_key)
}

fn remove_pending_join_in(dir: &Path, network_key: &str) -> Result<()> {
    let mut cfg = load_in(dir)?;
    let before = cfg.pending_joins.len();
    cfg.pending_joins.retain(|e| e.network_key != network_key);
    if cfg.pending_joins.len() != before {
        save_settings_in(dir, &cfg)?;
    }
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
    anyhow::ensure!(
        net.name == name,
        "network config {name:?} contains mismatched name {:?}",
        net.name
    );
    let before = toml::to_string(&net).context("serializing network config")?;
    let update_scope = NetworkUpdateScope::enter()?;
    update(&mut net)?;
    drop(update_scope);
    anyhow::ensure!(
        net.name == name,
        "network update cannot rename {name:?} to {:?}",
        net.name
    );
    let after = toml::to_string(&net).context("serializing network config")?;
    if after != before {
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
    anyhow::ensure!(
        net.name == name,
        "network config {name:?} contains mismatched name {:?}",
        net.name
    );
    let before = toml::to_string(&net).context("serializing network config")?;
    let update_scope = NetworkUpdateScope::enter()?;
    update(&mut net)?;
    drop(update_scope);
    anyhow::ensure!(
        net.name == name,
        "network update cannot rename {name:?} to {:?}",
        net.name
    );
    let after = toml::to_string(&net).context("serializing network config")?;
    if inserting || after != before {
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
mod tests {

    use super::*;
    use iroh::EndpointId;

    /// `ray-mobile` used to publish its config directory by writing
    /// `RAYFISH_CONFIG_DIR`, which mutates the process environment and so is
    /// undefined behaviour once other threads run. The embedder override
    /// replaces that write, so it has to win over the variable the way the
    /// overwrite did. `ray-mobile`'s own tests cover the wiring end to end;
    /// this is the precedence on its own, with nothing global touched.
    #[test]
    fn the_embedder_override_beats_the_env_var() {
        let from_env = OsString::from("/srv/rayfish-from-env");
        let from_code = PathBuf::from("/srv/rayfish-from-code");

        assert_eq!(
            resolve_override(None, Some(from_env.clone())),
            Some(PathBuf::from("/srv/rayfish-from-env"))
        );
        assert_eq!(
            resolve_override(Some(from_code.clone()), Some(from_env)),
            Some(from_code.clone())
        );
        // Still in effect with no variable at all: the platform default is what
        // the override exists to displace on Android.
        assert_eq!(
            resolve_override(Some(from_code.clone()), None),
            Some(from_code)
        );
        assert_eq!(resolve_override(None, None), None);
    }

    /// An embedder handing over an empty path is the same accident the env var
    /// already guards against, and must not resolve config to the process's
    /// current directory. It falls through to the variable, then the default.
    #[test]
    fn an_empty_embedder_override_is_no_override() {
        assert_eq!(resolve_override(Some(PathBuf::new()), None), None);
        assert_eq!(
            resolve_override(Some(PathBuf::new()), Some(OsString::from("/srv/rayfish"))),
            Some(PathBuf::from("/srv/rayfish"))
        );
    }

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        SecretKey::from(key_bytes).public()
    }

    /// A bare `ray config get` used to print a hand-kept list of five keys, so a
    /// new setting was reachable but invisible. It now lists the whole enum.
    #[test]
    fn the_bare_listing_covers_every_global_key() {
        let rows = config_get(&AppConfig::default(), None);
        let names: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
        for k in settings::GlobalKey::ALL {
            assert!(names.contains(&k.name()), "{} not listed", k.name());
        }
        assert_eq!(rows.len(), settings::GlobalKey::ALL.len());
    }

    #[test]
    fn config_dir_override_ignores_unset_and_empty() {
        assert_eq!(config_dir_override(None), None);
        // An exported-but-empty var must not resolve the tree to `""` (which
        // `create_dir_all` would reject) or to the process's cwd.
        assert_eq!(config_dir_override(Some(OsString::new())), None);
        assert_eq!(
            config_dir_override(Some(OsString::from("/srv/rayfish"))),
            Some(PathBuf::from("/srv/rayfish"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_stage_names_are_random_and_create_new() {
        let dir = tempfile::tempdir().unwrap();
        let first = windows_config_stage_path(dir.path(), "settings.toml");
        let second = windows_config_stage_path(dir.path(), "settings.toml");
        assert_ne!(first, second);
        let name = first.file_name().unwrap().to_string_lossy();
        let nonce = name.strip_prefix(".settings.toml.tmp.").unwrap();
        assert_eq!(nonce.len(), 64);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));

        drop(create_windows_config_stage(&first).unwrap());
        assert!(create_windows_config_stage(&first).is_err());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let config = AppConfig {
            networks: vec![
                NetworkConfig {
                    name: "gaming".to_string(),
                    group_mode: GroupMode::Open,
                    members: vec![
                        MemberEntry {
                            identity: test_id(2),
                            is_coordinator: true,
                            hostname: None,
                        },
                        MemberEntry {
                            identity: test_id(3),
                            is_coordinator: false,
                            hostname: None,
                        },
                    ],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    last_group_hash: None,
                    last_group_hash_published: true,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    direct_peer: None,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
                    ephemeral_ttl_secs: None,
                    exit_allow: vec![],
                    exit_node_use: None,
                },
                NetworkConfig {
                    name: "work".to_string(),
                    group_mode: GroupMode::Restricted,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    last_group_hash: None,
                    last_group_hash_published: true,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    direct_peer: None,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
                    ephemeral_ttl_secs: None,
                    exit_allow: vec![],
                    exit_node_use: None,
                },
            ],
            ..Default::default()
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.networks.len(), 2);
        assert_eq!(parsed.networks[0].name, "gaming");
        assert_eq!(parsed.networks[0].members.len(), 2);
        assert_eq!(parsed.networks[1].name, "work");
    }

    #[test]
    fn test_deserialize_empty() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(config.networks.is_empty());
    }

    #[test]
    fn test_upsert_new() {
        let mut config = AppConfig::default();
        let net = NetworkConfig {
            name: "test".to_string(),
            group_mode: GroupMode::Open,
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
            last_group_hash: None,
            last_group_hash_published: true,
            my_hostname: None,
            pending_hostname: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            direct_peer: None,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        };
        upsert_network(&mut config, net);
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].name, "test");
        assert_eq!(config.networks[0].group_mode, GroupMode::Open);
    }

    #[test]
    fn test_upsert_replaces_existing() {
        let mut config = AppConfig {
            networks: vec![NetworkConfig {
                name: "test".to_string(),
                group_mode: GroupMode::Restricted,
                members: vec![],
                approved: vec![],
                network_secret_key: None,
                network_public_key: None,
                last_group_hash: None,
                last_group_hash_published: true,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                direct_peer: None,
                ssh_allow: vec![],
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                exit_allow: vec![],
                exit_node_use: None,
            }],
            ..Default::default()
        };
        let updated = NetworkConfig {
            name: "test".to_string(),
            group_mode: GroupMode::Open,
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
            last_group_hash: None,
            last_group_hash_published: true,
            my_hostname: None,
            pending_hostname: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            direct_peer: None,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        };
        upsert_network(&mut config, updated.clone());
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].group_mode, GroupMode::Open);
    }

    #[test]
    fn test_remove_network() {
        let mut config = AppConfig {
            networks: vec![
                NetworkConfig {
                    name: "keep".to_string(),
                    group_mode: GroupMode::Restricted,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    last_group_hash: None,
                    last_group_hash_published: true,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    direct_peer: None,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
                    ephemeral_ttl_secs: None,
                    exit_allow: vec![],
                    exit_node_use: None,
                },
                NetworkConfig {
                    name: "remove-me".to_string(),
                    group_mode: GroupMode::Restricted,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    last_group_hash: None,
                    last_group_hash_published: true,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    direct_peer: None,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
                    ephemeral_ttl_secs: None,
                    exit_allow: vec![],
                    exit_node_use: None,
                },
            ],
            ..Default::default()
        };
        assert!(remove_network(&mut config, "remove-me"));
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].name, "keep");
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut config = AppConfig::default();
        assert!(!remove_network(&mut config, "nope"));
    }

    #[test]
    fn test_serialize_with_approved() {
        let id1 = test_id(1);
        let id2 = test_id(2);
        let config = AppConfig {
            networks: vec![NetworkConfig {
                name: "gaming".to_string(),
                group_mode: GroupMode::Restricted,
                members: vec![MemberEntry {
                    identity: id1,
                    is_coordinator: true,
                    hostname: None,
                }],
                approved: vec![ApprovedConfigEntry {
                    identity: id2,
                    hostname: None,
                }],
                network_secret_key: None,
                network_public_key: None,
                last_group_hash: None,
                last_group_hash_published: true,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                direct_peer: None,
                ssh_allow: vec![],
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                exit_allow: vec![],
                exit_node_use: None,
            }],
            ..Default::default()
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.networks[0].approved.len(), 1);
        assert_eq!(parsed.networks[0].approved[0].identity, id2);
    }

    #[test]
    fn test_serialize_with_network_key() {
        let secret = SecretKey::generate();
        let public = secret.public();
        let config = AppConfig {
            networks: vec![NetworkConfig {
                name: "gaming".to_string(),
                group_mode: GroupMode::Restricted,
                members: vec![],
                approved: vec![],
                network_secret_key: Some(secret.clone()),
                network_public_key: Some(public),
                last_group_hash: None,
                last_group_hash_published: true,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                direct_peer: None,
                ssh_allow: vec![],
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                exit_allow: vec![],
                exit_node_use: None,
            }],
            ..Default::default()
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.networks[0].network_public_key, Some(public));
        assert!(parsed.networks[0].network_secret_key.is_some());
    }

    #[test]
    fn test_contact_secret_generate_and_persist() {
        let mut config = AppConfig::default();
        assert!(config.contact_secret_key.is_none());
        let first = contact_secret(&mut config);
        // Stable across calls once generated.
        let second = contact_secret(&mut config);
        assert_eq!(first.public(), second.public());
        // Survives a serialize roundtrip.
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            parsed.contact_secret_key.map(|k| k.public()),
            Some(first.public())
        );
        // Rotation yields a different key.
        let rotated = rotate_contact_secret(&mut config);
        assert_ne!(rotated.public(), first.public());
    }

    #[test]
    fn test_direct_flag_default_false() {
        let toml_str = r#"
[[networks]]
name = "team-alice"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.networks[0].direct);
    }

    #[test]
    fn test_deserialize_minimal() {
        let toml_str = r#"
[[networks]]
name = "test"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].name, "test");
        assert_eq!(config.networks[0].group_mode, GroupMode::Restricted);
        assert!(config.networks[0].members.is_empty());
        assert!(config.networks[0].approved.is_empty());
        assert!(config.networks[0].network_secret_key.is_none());
        assert!(config.networks[0].network_public_key.is_none());
    }

    #[test]
    fn ephemeral_ttl_roundtrips_and_defaults_none() {
        let mut n = net("eph");
        n.ephemeral_ttl_secs = Some(3600);
        let text = toml::to_string(&n).unwrap();
        let back: NetworkConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.ephemeral_ttl_secs, Some(3600));
        // A config written before the field existed omits the key -> None.
        let minimal: NetworkConfig = toml::from_str("name = \"x\"").unwrap();
        assert_eq!(minimal.ephemeral_ttl_secs, None);
    }

    #[test]
    fn last_group_hash_roundtrips_and_defaults_none() {
        let hash = blake3::hash(b"complete signed roster");
        let mut n = net("cached");
        n.last_group_hash = Some(hash);
        n.last_group_hash_published = false;
        let text = toml::to_string(&n).unwrap();
        let back: NetworkConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.last_group_hash, Some(hash));
        assert!(!back.last_group_hash_published);

        let minimal: NetworkConfig = toml::from_str("name = \"x\"").unwrap();
        assert_eq!(minimal.last_group_hash, None);
        assert!(minimal.last_group_hash_published);
    }

    fn net(name: &str) -> NetworkConfig {
        NetworkConfig {
            name: name.to_string(),
            group_mode: GroupMode::Restricted,
            my_hostname: None,
            pending_hostname: None,
            members: vec![],
            approved: vec![],
            network_secret_key: Some(SecretKey::generate()),
            network_public_key: None,
            last_group_hash: None,
            last_group_hash_published: true,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            direct_peer: None,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        }
    }

    #[test]
    fn per_network_roundtrip_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        save_network_unlocked(dir, &net("homelab")).unwrap();
        save_network_unlocked(dir, &net("genesis")).unwrap();
        save_settings_in(
            dir,
            &AppConfig {
                default_hostname: Some("laptop".into()),
                ..Default::default()
            },
        )
        .unwrap();

        let loaded = load_in(dir).unwrap();
        assert_eq!(loaded.networks.len(), 2);
        assert_eq!(loaded.default_hostname.as_deref(), Some("laptop"));

        // Single-network load.
        assert!(load_network_unlocked(dir, "homelab").unwrap().is_some());
        assert!(load_network_unlocked(dir, "absent").unwrap().is_none());

        // Deleting one leaves the other untouched.
        assert!(delete_network_unlocked(dir, "homelab").unwrap());
        assert!(!delete_network_unlocked(dir, "homelab").unwrap());
        let after = load_in(dir).unwrap();
        assert_eq!(after.networks.len(), 1);
        assert_eq!(after.networks[0].name, "genesis");
    }

    #[test]
    fn settings_download_fields_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let cfg = AppConfig {
            download_dir: Some("/srv/incoming".to_string()),
            download_user: Some(1000),
            ..Default::default()
        };
        save_settings_in(dir, &cfg).unwrap();

        let loaded = load_in(dir).unwrap();
        assert_eq!(loaded.download_dir.as_deref(), Some("/srv/incoming"));
        assert_eq!(loaded.download_user, Some(1000));
    }

    #[test]
    fn settings_endpoint_hints_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let hint =
            iroh::EndpointAddr::new(test_id(7)).with_ip_addr("203.0.113.7:41383".parse().unwrap());
        let cfg = AppConfig {
            endpoint_hints: vec![hint.clone()],
            ..Default::default()
        };
        save_settings_in(dir, &cfg).unwrap();

        let loaded = load_in(dir).unwrap();
        assert_eq!(loaded.endpoint_hints, vec![hint]);
    }

    /// The IPv6-only cutover deleted the `ipv6-only` setting, and the release
    /// notes promise a `settings.toml` still carrying it upgrades rather than
    /// failing to parse. Nothing in `Settings` names the key any more, so what
    /// keeps that promise is the absence of `deny_unknown_fields`, which is
    /// exactly the kind of thing a later tidy-up adds without noticing.
    #[test]
    fn a_stale_ipv6_only_key_still_loads() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(SETTINGS_FILE),
            "mdns_enabled = false\nipv6_only = true\n",
        )
        .unwrap();
        let loaded = load_in(tmp.path()).expect("a settings.toml from an older build still loads");
        assert!(!loaded.mdns_enabled, "the keys we do know are still read");
    }

    #[test]
    fn settings_download_fields_default_none() {
        let tmp = tempfile::tempdir().unwrap();
        // No settings.toml written: fields default to None.
        let loaded = load_in(tmp.path()).unwrap();
        assert_eq!(loaded.download_dir, None);
        assert_eq!(loaded.download_user, None);
    }

    #[test]
    fn network_aliases_roundtrip_and_default_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // A network with aliases persists them across a save/load cycle.
        let mut n = net("homelab");
        n.aliases.insert("alice".into(), "id-alice".into());
        n.aliases.insert("bob".into(), "id-bob".into());
        save_network_unlocked(dir, &n).unwrap();
        let loaded = load_network_unlocked(dir, "homelab").unwrap().unwrap();
        assert_eq!(
            loaded.aliases.get("alice").map(String::as_str),
            Some("id-alice")
        );
        assert_eq!(
            loaded.aliases.get("bob").map(String::as_str),
            Some("id-bob")
        );

        // A network with no aliases omits the key; loading a toml without it
        // defaults to an empty map (backward compatible with pre-alias configs).
        let plain = net("genesis");
        assert!(plain.aliases.is_empty());
        let toml = ::toml::to_string(&plain).unwrap();
        assert!(
            !toml.contains("aliases"),
            "empty aliases must not be serialized"
        );
        let back: NetworkConfig = ::toml::from_str(&toml).unwrap();
        assert!(back.aliases.is_empty());
    }

    #[test]
    fn settings_roundtrip_server_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // A fresh dir (no settings.toml) loads all three overrides as unset.
        let fresh = load_in(dir).unwrap();
        assert!(fresh.relay.is_unset());
        assert!(fresh.discovery_dns.is_unset());
        assert!(fresh.dns_upstreams.is_unset());

        let cfg = AppConfig {
            relay: ServerOverride {
                servers: vec!["http://r:1".into()],
                replace: true,
            },
            dns_upstreams: ServerOverride {
                servers: vec!["1.1.1.1".into()],
                replace: false,
            },
            ..Default::default()
        };
        save_settings_in(dir, &cfg).unwrap();

        let loaded = load_in(dir).unwrap();
        assert_eq!(loaded.relay, cfg.relay);
        assert_eq!(loaded.dns_upstreams, cfg.dns_upstreams);
        assert!(loaded.discovery_dns.is_unset());
    }

    #[test]
    fn relay_urls_expands_rayfish_preset() {
        let o = ServerOverride {
            servers: vec!["rayfish".into()],
            replace: false,
        };
        assert_eq!(
            relay_urls(&o).unwrap(),
            vec![RELAY_PRESET_RAYFISH.to_string()]
        );
        let d = ServerOverride {
            servers: vec!["rayfish".into()],
            replace: false,
        };
        assert_eq!(
            discovery_urls(&d).unwrap(),
            vec![DISCOVERY_PRESET_RAYFISH.to_string()]
        );
    }

    #[test]
    fn url_entry_rejects_bad() {
        assert!(
            relay_urls(&ServerOverride {
                servers: vec!["ftp://x".into()],
                replace: false
            })
            .is_err()
        );
        assert!(
            relay_urls(&ServerOverride {
                servers: vec!["not a url".into()],
                replace: false
            })
            .is_err()
        );
        // A real http URL passes through unchanged.
        let ok = ServerOverride {
            servers: vec!["http://r:1".into()],
            replace: false,
        };
        assert_eq!(relay_urls(&ok).unwrap(), vec!["http://r:1".to_string()]);
    }

    #[test]
    fn resolve_upstreams_augment_and_replace() {
        let captured = vec![Ipv4Addr::new(192, 168, 1, 1)];
        let one = Ipv4Addr::new(1, 1, 1, 1);

        // Unset: captured unchanged.
        assert_eq!(
            resolve_upstreams(&ServerOverride::default(), captured.clone()),
            captured
        );

        // Augment: custom first, then captured.
        let aug = ServerOverride {
            servers: vec!["1.1.1.1".into()],
            replace: false,
        };
        assert_eq!(
            resolve_upstreams(&aug, captured.clone()),
            vec![one, captured[0]]
        );

        // Replace: custom only.
        let rep = ServerOverride {
            servers: vec!["1.1.1.1".into()],
            replace: true,
        };
        assert_eq!(resolve_upstreams(&rep, captured.clone()), vec![one]);
    }

    /// `dns-upstreams` takes IPv6 since the IPv6-only tunnel needed it, so an
    /// all-IPv6 `--replace` narrows to nothing here. Returning that empty list
    /// would leave the forwarder with no server and hand `control_plane_nameservers`
    /// an empty set, putting the endpoint back on iroh's resolv.conf reader (#111).
    #[test]
    fn replace_with_only_ipv6_keeps_the_captured_upstreams() {
        let captured = vec![Ipv4Addr::new(192, 168, 1, 1)];
        let v6_only = ServerOverride {
            servers: vec!["2606:4700:4700::1111".into()],
            replace: true,
        };
        assert_eq!(resolve_upstreams(&v6_only, captured.clone()), captured);

        // One usable IPv4 entry and `replace` still means replace: the guard is
        // for "nothing survived the narrowing", not "some entries were dropped".
        let mixed = ServerOverride {
            servers: vec!["2606:4700:4700::1111".into(), "1.1.1.1".into()],
            replace: true,
        };
        assert_eq!(
            resolve_upstreams(&mixed, captured),
            vec![Ipv4Addr::new(1, 1, 1, 1)]
        );
    }

    /// `has_usable_upstream` has to agree with what `resolve_upstreams` keeps.
    ///
    /// It waives the refusal to take over `/etc/resolv.conf` with no verified
    /// upstream of our own. Answering yes on a setting that then narrows to
    /// nothing would take the file, install the re-assert watcher, and leave the
    /// forwarder with an empty list: the host loses every name outside `.ray`,
    /// and repairing the file by hand is undone by the watcher. That is worse
    /// than the refusal it bypassed, so the two must not disagree.
    #[test]
    fn only_a_usable_upstream_waives_the_takeover_guard() {
        let captured: Vec<Ipv4Addr> = Vec::new();
        for (servers, usable) in [
            (vec!["2606:4700:4700::1111"], false),
            (vec!["2606:4700:4700::1111", "2001:4860:4860::8888"], false),
            (vec!["1.1.1.1"], true),
            (vec!["2606:4700:4700::1111", "1.1.1.1"], true),
            (vec!["not-an-address"], false),
            (vec![], false),
        ] {
            for replace in [false, true] {
                let o = ServerOverride {
                    servers: servers.iter().map(|s| s.to_string()).collect(),
                    replace,
                };
                assert_eq!(has_usable_upstream(&o), usable, "{servers:?}");
                // The claim this guard makes, stated the other way round: saying
                // yes must mean the forwarder actually gets a server.
                assert_eq!(
                    !resolve_upstreams(&o, captured.clone()).is_empty(),
                    usable,
                    "{servers:?} replace={replace}"
                );
            }
        }
    }

    #[test]
    fn config_set_n0_resets() {
        let mut cfg = AppConfig::default();
        config_set(&mut cfg, settings::GlobalKey::Relay, "rayfish", true).unwrap();
        assert!(!cfg.relay.is_unset());
        config_set(&mut cfg, settings::GlobalKey::Relay, "n0", false).unwrap();
        assert!(cfg.relay.is_unset());
    }

    #[test]
    fn config_set_dns_upstreams_rejects_non_ip() {
        let mut cfg = AppConfig::default();
        assert!(
            config_set(
                &mut cfg,
                settings::GlobalKey::DnsUpstreams,
                "1.1.1.1",
                false
            )
            .is_ok()
        );
        assert!(
            config_set(
                &mut cfg,
                settings::GlobalKey::DnsUpstreams,
                "not-an-ip",
                false
            )
            .is_err()
        );
        // rayfish is not a valid upstream keyword.
        assert!(
            config_set(
                &mut cfg,
                settings::GlobalKey::DnsUpstreams,
                "rayfish",
                false
            )
            .is_err()
        );
    }

    // Regression for the bug that prompted this change: concurrent saves of
    // distinct networks used to clobber one another through a single
    // non-atomic `networks.toml`. With one file per network they cannot.
    #[test]
    fn concurrent_saves_do_not_clobber() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        const N: usize = 24;

        std::thread::scope(|s| {
            for i in 0..N {
                let dir = dir.clone();
                s.spawn(move || {
                    save_network_unlocked(&dir, &net(&format!("net-{i}"))).unwrap();
                });
            }
        });

        let loaded = load_in(&dir).unwrap();
        assert_eq!(
            loaded.networks.len(),
            N,
            "all concurrent saves must survive"
        );
    }

    /// The network shards got a transaction boundary but `settings.toml` did
    /// not, so the ten `load()` -> mutate one global -> `save_settings()` sites
    /// still raced: each wrote back the whole file, reverting whatever another
    /// task had changed in between.
    #[test]
    fn concurrent_settings_updates_preserve_unrelated_globals() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let barrier = std::sync::Barrier::new(3);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                update_settings_in(&dir, |cfg| {
                    cfg.operator_uid = Some(1234);
                    Ok(())
                })
                .unwrap();
            });
            scope.spawn(|| {
                barrier.wait();
                update_settings_in(&dir, |cfg| {
                    cfg.default_hostname = Some("umbrel".into());
                    Ok(())
                })
                .unwrap();
            });
            barrier.wait();
        });

        let loaded = load_in(&dir).unwrap();
        assert_eq!(loaded.operator_uid, Some(1234));
        assert_eq!(loaded.default_hostname.as_deref(), Some("umbrel"));
    }

    /// A failing callback must leave the file as it was, not write a
    /// half-applied config.
    #[test]
    fn a_failed_settings_update_saves_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        update_settings_in(&dir, |cfg| {
            cfg.operator_uid = Some(7);
            Ok(())
        })
        .unwrap();

        let err = update_settings_in(&dir, |cfg| {
            cfg.operator_uid = Some(9);
            anyhow::bail!("callback failed")
        });

        assert!(err.is_err());
        assert_eq!(load_in(&dir).unwrap().operator_uid, Some(7));
    }

    #[test]
    fn concurrent_same_network_updates_preserve_unrelated_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        save_network_unlocked(&dir, &net("homelab")).unwrap();
        let barrier = std::sync::Barrier::new(3);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                update_network_in(&dir, "homelab", |net| {
                    net.aliases.insert("alice".into(), "id-alice".into());
                    Ok(())
                })
                .unwrap();
            });
            scope.spawn(|| {
                barrier.wait();
                update_network_in(&dir, "homelab", |net| {
                    net.last_group_hash = Some(blake3::hash(b"latest group"));
                    net.auto_accept_files = false;
                    Ok(())
                })
                .unwrap();
            });
            barrier.wait();
        });

        let loaded = load_network_unlocked(&dir, "homelab").unwrap().unwrap();
        assert_eq!(
            loaded.aliases.get("alice").map(String::as_str),
            Some("id-alice")
        );
        assert_eq!(loaded.last_group_hash, Some(blake3::hash(b"latest group")));
        assert!(!loaded.auto_accept_files);
    }

    #[test]
    fn update_or_insert_uses_initial_only_when_network_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let mut initial = net("homelab");
        initial.aliases.insert("local".into(), "first".into());

        update_network_or_insert_in(dir, "homelab", initial, |net| {
            net.last_group_hash = Some(blake3::hash(b"first group"));
            net.auto_accept_firewall = true;
            Ok(())
        })
        .unwrap();

        let mut stale_initial = net("homelab");
        stale_initial.aliases.insert("local".into(), "stale".into());
        update_network_or_insert_in(dir, "homelab", stale_initial, |net| {
            net.my_hostname = Some("latest".into());
            Ok(())
        })
        .unwrap();

        let loaded = load_network_unlocked(dir, "homelab").unwrap().unwrap();
        assert_eq!(
            loaded.aliases.get("local").map(String::as_str),
            Some("first")
        );
        assert_eq!(loaded.last_group_hash, Some(blake3::hash(b"first group")));
        assert!(loaded.auto_accept_firewall);
        assert_eq!(loaded.my_hostname.as_deref(), Some("latest"));
    }

    #[test]
    fn network_update_reentry_is_rejected_before_locking() {
        let _scope = NetworkUpdateScope::enter().unwrap();
        let error = ensure_not_in_network_update().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("network config update callbacks must not call network config APIs")
        );
    }

    #[test]
    fn failed_network_update_does_not_persist_partial_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        save_network_unlocked(dir, &net("homelab")).unwrap();

        let result = update_network_in(dir, "homelab", |net| {
            net.aliases.insert("alice".into(), "id-alice".into());
            anyhow::bail!("reject update")
        });

        assert!(result.is_err());
        assert!(
            load_network_unlocked(dir, "homelab")
                .unwrap()
                .unwrap()
                .aliases
                .is_empty()
        );
    }

    #[test]
    fn migrate_legacy_splits_and_backs_up() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Write a legacy single-file config (the pre-shard format).
        let legacy = AppConfig {
            default_hostname: Some("laptop".into()),
            networks: vec![net("homelab"), net("genesis")],
            ..Default::default()
        };
        std::fs::write(
            dir.join(LEGACY_FILE),
            toml::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        migrate_legacy(dir).unwrap();

        // Legacy file preserved as a backup, original gone.
        assert!(!dir.join(LEGACY_FILE).exists());
        assert!(dir.join("networks.toml.bak").exists());

        // Both networks + globals are now in the sharded layout.
        let loaded = load_in(dir).unwrap();
        assert_eq!(loaded.networks.len(), 2);
        assert_eq!(loaded.default_hostname.as_deref(), Some("laptop"));

        // Idempotent: a second migrate (no legacy file) is a no-op.
        migrate_legacy(dir).unwrap();
        assert_eq!(load_in(dir).unwrap().networks.len(), 2);
    }

    #[test]
    fn rejects_unsafe_network_names() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        assert!(save_network_unlocked(dir, &net("../escape")).is_err());
        assert!(load_network_unlocked(dir, "a/b").is_err());
    }

    #[test]
    fn pending_join_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Start from an empty settings file.
        save_settings_in(dir, &AppConfig::default()).unwrap();

        add_pending_join_in(
            dir,
            PendingJoinEntry {
                network_key: "abc123".to_string(),
                name: Some("homelab".to_string()),
            },
        )
        .unwrap();

        let loaded = load_in(dir).unwrap();
        assert_eq!(loaded.pending_joins.len(), 1);
        assert_eq!(loaded.pending_joins[0].network_key, "abc123");

        // Adding the same key again does not duplicate it.
        add_pending_join_in(
            dir,
            PendingJoinEntry {
                network_key: "abc123".to_string(),
                name: None,
            },
        )
        .unwrap();
        assert_eq!(load_in(dir).unwrap().pending_joins.len(), 1);

        remove_pending_join_in(dir, "abc123").unwrap();
        assert!(load_in(dir).unwrap().pending_joins.is_empty());
    }

    /// The temp file was named `.{fname}.tmp.{pid}`: one path per file per
    /// process, so two threads writing the same config opened the same temp
    /// file and one could rename a file the other was still filling. The
    /// survivor's content was then whatever the two writers had interleaved.
    #[test]
    fn concurrent_writes_to_one_path_never_mix() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.toml");
        let candidates = ["a".repeat(4096), "b".repeat(16384), "c".repeat(65536)];

        for _ in 0..25 {
            std::thread::scope(|s| {
                for c in &candidates {
                    s.spawn(|| write_file(&path, c.as_bytes(), false).unwrap());
                }
            });
            let got = std::fs::read_to_string(&path).unwrap();
            assert!(
                candidates.contains(&got),
                "torn file: {} bytes, starts {:?}",
                got.len(),
                &got[..got.len().min(8)]
            );
        }

        let left: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(left.is_empty(), "temp files left behind: {left:?}");
    }
}
