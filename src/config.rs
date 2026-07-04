use std::collections::BTreeMap;
use std::fs::Permissions;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

use crate::membership::GroupMode;

/// Per-network transport preference. Defined in `ray-proto` (shared with GUI
/// frontends); re-exported here so existing `crate::config::TransportMode` paths work.
pub use ray_proto::TransportMode;

#[allow(dead_code)]
mod secret_key_hex {
    use iroh::SecretKey;
    use serde::de::Error;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes: [u8; 32] = hex::decode(&s)
            .map_err(Error::custom)?
            .try_into()
            .map_err(|_| Error::custom("secret key must be 32 bytes"))?;
        Ok(SecretKey::from(bytes))
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
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub is_coordinator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// A pre-approved peer that hasn't connected yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedConfigEntry {
    pub identity: EndpointId,
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// A single saved network membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Human-friendly network alias (local only, not used for discovery).
    pub name: String,
    /// Membership mode: open or restricted.
    #[serde(default)]
    pub group_mode: GroupMode,
    /// Our assigned IP in this network (None if coordinator, Some if member).
    pub my_ip: Option<Ipv4Addr>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportMode>,
    /// This node auto-installs coordinator-suggested firewall rules without a
    /// manual review queue. Set per-network by `ray join --auto-accept-firewall`
    /// or toggled later with `ray firewall auto-accept <net> on|off`.
    #[serde(default, alias = "allow_trusted")]
    pub auto_accept_firewall: bool,
    /// Auto-accept incoming file offers from our own paired devices on this
    /// network (no manual `ray files accept`). Own-devices-only (the sender's
    /// user identity must match ours); secure default off. Set per-network by
    /// `ray join --auto-accept-files` or toggled with
    /// `ray files auto-accept <net> on|off`.
    #[serde(default)]
    pub auto_accept_files: bool,
    /// Identities this coordinator has granted the per-network secret key to
    /// (`ray admin add`). Local tracking only — the key is shared and not
    /// attributable, so this is the coordinator's record of grants, not a
    /// verifiable roster. Never published in the GroupBlob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<EndpointId>,
    /// This is an auto-minted 2-peer "direct connection" network (`ray connect`),
    /// not a user-created mesh. Tagged so `ray status` can label it `[direct]`
    /// and suppress its (non-shareable) room id.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub direct: bool,
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
/// are targeted (`save_settings` / `save_network` / `delete_network`) so a write
/// to one network can never clobber another. See the storage section below.
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
fn resolve_url_entry(entry: &str, preset: &str) -> Result<String> {
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
pub fn resolve_upstreams(o: &ServerOverride, captured: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    if o.servers.is_empty() {
        return captured;
    }
    let custom: Vec<Ipv4Addr> = o.servers.iter().filter_map(|s| s.parse().ok()).collect();
    if o.replace {
        custom
    } else {
        custom.into_iter().chain(captured).collect()
    }
}

/// Parse a comma list of entries (trimmed, empties dropped).
fn parse_entries(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Apply a `ray config set`/`unset` to the in-memory config. An empty value or
/// the lone keyword `n0` resets the key to its default (iroh n0). Validates
/// every entry, so a bad URL/IP or unknown preset is rejected before persist.
pub fn config_set(cfg: &mut AppConfig, key: &str, value: &str, replace: bool) -> Result<()> {
    let entries = parse_entries(value);
    let reset = entries.is_empty() || entries == ["n0"];
    match key {
        "relay" => {
            if reset {
                cfg.relay = ServerOverride::default();
            } else {
                for e in &entries {
                    resolve_url_entry(e, RELAY_PRESET_RAYFISH)?;
                }
                cfg.relay = ServerOverride {
                    servers: entries,
                    replace,
                };
            }
        }
        "discovery-dns" => {
            if reset {
                cfg.discovery_dns = ServerOverride::default();
            } else {
                for e in &entries {
                    resolve_url_entry(e, DISCOVERY_PRESET_RAYFISH)?;
                }
                cfg.discovery_dns = ServerOverride {
                    servers: entries,
                    replace,
                };
            }
        }
        "dns-upstreams" => {
            if entries.is_empty() {
                cfg.dns_upstreams = ServerOverride::default();
            } else {
                for e in &entries {
                    e.parse::<Ipv4Addr>()
                        .with_context(|| format!("invalid IPv4 address: {e}"))?;
                }
                cfg.dns_upstreams = ServerOverride {
                    servers: entries,
                    replace,
                };
            }
        }
        other => anyhow::bail!(
            "unknown config key: {other} (expected relay, discovery-dns, or dns-upstreams)"
        ),
    }
    Ok(())
}

fn render_override(o: &ServerOverride) -> String {
    if o.is_unset() {
        "<default>".to_string()
    } else {
        let mode = if o.replace { "replace" } else { "augment" };
        format!("{} ({mode})", o.servers.join(","))
    }
}

/// Render config settings as `(key, value)` rows for `ray config get`. With a
/// key, returns just that one (error on unknown key); without, all three.
pub fn config_get(cfg: &AppConfig, key: Option<&str>) -> Result<Vec<(String, String)>> {
    let row = |k: &str| -> Result<(String, String)> {
        let o = match k {
            "relay" => &cfg.relay,
            "discovery-dns" => &cfg.discovery_dns,
            "dns-upstreams" => &cfg.dns_upstreams,
            other => anyhow::bail!(
                "unknown config key: {other} (expected relay, discovery-dns, or dns-upstreams)"
            ),
        };
        Ok((k.to_string(), render_override(o)))
    };
    match key {
        Some(k) => Ok(vec![row(k)?]),
        None => Ok(vec![
            row("relay")?,
            row("discovery-dns")?,
            row("dns-upstreams")?,
        ]),
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
    /// Global toggle for the embedded mesh SSH server (`ray firewall ssh on`).
    /// When on, the daemon listens on each mesh IP's port 22 and admits peers
    /// authorized in a network's [`NetworkConfig::ssh_allow`] list. Off by default.
    #[serde(default)]
    pub ssh_enabled: bool,
    /// Opt-in automatic updates: when on, the daemon periodically checks for a
    /// newer stable release, swaps the binary, and restarts itself onto it. Off
    /// by default; enable via `ray install --auto-update` or `ray auto-update on`.
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
            ssh_enabled: false,
            auto_update: false,
            auto_update_last_target: None,
            auto_update_last_attempt: None,
            download_dir: None,
            download_user: None,
            networks: Vec::new(),
            pending_joins: Vec::new(),
        }
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
//                                        hostname, contact key) — secret-bearing
//   <config_dir>/networks/<name>.toml   one NetworkConfig each — secret-bearing
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

/// Globals persisted to `settings.toml` (everything in [`AppConfig`] except the
/// per-network entries, which live in their own files).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    ssh_enabled: bool,
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

/// Create `dir` (and parents) with restrictive perms: 0750 root:rayfish on
/// Linux. Idempotent.
fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::set_permissions(dir, Permissions::from_mode(0o750));
        set_owner(dir, false);
    }
    Ok(())
}

/// Base directory for all rayfish config + state. Created if missing.
///
/// Linux: `/etc/rayfish` (system service location, root:rayfish). macOS: the
/// daemon's `~/.config/rayfish` (root-only under `/var/root`).
pub fn config_dir() -> Result<PathBuf> {
    // An explicit `RAYFISH_CONFIG_DIR` override is honored only on Android
    // (`ray-mobile`'s `Node::new` points it at the app's `Context.getFilesDir()`)
    // and in `cfg(test)` (headless/test harnesses run against an isolated config
    // tree). Desktop/service production builds never check this var, so their
    // resolved path is byte-for-byte unchanged from before the override existed.
    #[cfg(any(target_os = "android", test))]
    if let Some(dir) = std::env::var_os("RAYFISH_CONFIG_DIR") {
        let dir = PathBuf::from(dir);
        ensure_dir(&dir)?;
        return Ok(dir);
    }
    #[cfg(target_os = "linux")]
    let dir = PathBuf::from("/etc/rayfish");
    // Android without the override falls back to a fixed app-private path so the
    // library still compiles/runs standalone.
    #[cfg(target_os = "android")]
    let dir = PathBuf::from("/data/local/tmp/rayfish");
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("rayfish");
    ensure_dir(&dir)?;
    Ok(dir)
}

/// Reject a network name that can't be a safe single path component (defence in
/// depth — names are already validated as hostnames elsewhere).
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

/// Atomically write `bytes` to `path`: write a sibling temp file, set its
/// perms/owner, then rename over the target. The rename is atomic on POSIX, so
/// a concurrent reader sees either the old file or the new one — never a torn
/// one. `secret` selects 0600 root:root vs 0640 root:rayfish.
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
    let tmp = dir.join(format!(".{fname}.tmp.{}", std::process::id()));
    {
        use std::io::Write;
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all().ok();
    }
    let mode = if secret { 0o600 } else { 0o640 };
    let _ = std::fs::set_permissions(&tmp, Permissions::from_mode(mode));
    #[cfg(target_os = "linux")]
    set_owner(&tmp, secret);
    let renamed = std::fs::rename(&tmp, path);
    if renamed.is_err() {
        // Clean up the temp file on a failed rename so we don't litter.
        let _ = std::fs::remove_file(&tmp);
    }
    renamed.with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

fn write_atomic(path: &Path, contents: &str, secret: bool) -> Result<()> {
    write_file(path, contents.as_bytes(), secret)
}

/// Apply restrictive perms/owner to an existing file under the config tree.
/// For append-mode files (e.g. the audit log) that aren't rewritten via
/// [`write_file`]. Best-effort.
pub fn restrict_perms(path: &Path, secret: bool) {
    let mode = if secret { 0o600 } else { 0o640 };
    let _ = std::fs::set_permissions(path, Permissions::from_mode(mode));
    #[cfg(target_os = "linux")]
    set_owner(path, secret);
}

/// Linux-only: relocate a pre-`/etc` config tree into `/etc/rayfish` on first
/// start after the upgrade that moved the location. Earlier Linux builds stored
/// everything under the daemon's `~/.config/rayfish` (i.e. `/root/.config`); this
/// moves `secret_key`, `networks.toml`, `firewall.toml`, `invites/`, etc. over so
/// the node keeps its identity and networks. No-op on macOS (location unchanged)
/// and once `/etc/rayfish` is populated. Must run before any config/identity read
/// (called at the top of `build_daemon`).
pub fn migrate_location() {
    #[cfg(target_os = "linux")]
    {
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
            // mounts) the entry is left in place and the daemon starts fresh —
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
            // — 0600 everything; later targeted writes relax non-secret files.
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
        save_network_in(dir, net)?;
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
    let dir = config_dir()?;
    migrate_legacy(&dir)?;
    load_in(&dir)
}

fn load_in(dir: &Path) -> Result<AppConfig> {
    let settings_path = dir.join(SETTINGS_FILE);
    let settings: Settings = if settings_path.exists() {
        let s = std::fs::read_to_string(&settings_path).context("reading settings.toml")?;
        toml::from_str(&s).context("parsing settings.toml")?
    } else {
        Settings {
            mdns_enabled: true,
            operator_uid: None,
            default_hostname: None,
            contact_secret_key: None,
            relay: ServerOverride::default(),
            discovery_dns: ServerOverride::default(),
            dns_upstreams: ServerOverride::default(),
            ssh_enabled: false,
            auto_update: false,
            auto_update_last_target: None,
            auto_update_last_attempt: None,
            download_dir: None,
            download_user: None,
            pending_joins: Vec::new(),
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
        ssh_enabled: settings.ssh_enabled,
        auto_update: settings.auto_update,
        auto_update_last_target: settings.auto_update_last_target,
        auto_update_last_attempt: settings.auto_update_last_attempt,
        download_dir: settings.download_dir,
        download_user: settings.download_user,
        networks,
        pending_joins: settings.pending_joins,
    })
}

/// Persist the global settings (`settings.toml`) only. Does not touch networks.
pub fn save_settings(config: &AppConfig) -> Result<()> {
    save_settings_in(&config_dir()?, config)
}

fn save_settings_in(dir: &Path, config: &AppConfig) -> Result<()> {
    let settings = Settings {
        mdns_enabled: config.mdns_enabled,
        operator_uid: config.operator_uid,
        default_hostname: config.default_hostname.clone(),
        contact_secret_key: config.contact_secret_key.clone(),
        relay: config.relay.clone(),
        discovery_dns: config.discovery_dns.clone(),
        dns_upstreams: config.dns_upstreams.clone(),
        ssh_enabled: config.ssh_enabled,
        auto_update: config.auto_update,
        auto_update_last_target: config.auto_update_last_target.clone(),
        auto_update_last_attempt: config.auto_update_last_attempt,
        download_dir: config.download_dir.clone(),
        download_user: config.download_user,
        pending_joins: config.pending_joins.clone(),
    };
    let path = dir.join(SETTINGS_FILE);
    let contents = toml::to_string_pretty(&settings).context("serializing settings")?;
    // Secret-bearing: holds the contact key.
    write_atomic(&path, &contents, true)
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

/// Persist a single network to `networks/<name>.toml`. Touches only that file,
/// so concurrent saves of distinct networks can never clobber one another.
pub fn save_network(net: &NetworkConfig) -> Result<()> {
    save_network_in(&config_dir()?, net)
}

fn save_network_in(dir: &Path, net: &NetworkConfig) -> Result<()> {
    validate_net_name(&net.name)?;
    let ndir = dir.join(NETWORKS_SUBDIR);
    let path = ndir.join(format!("{}.toml", net.name));
    let contents = toml::to_string_pretty(net).context("serializing network config")?;
    // Secret-bearing: holds the per-network coordinator secret key.
    write_atomic(&path, &contents, true)
}

/// Load a single network's config, if present.
pub fn load_network(name: &str) -> Result<Option<NetworkConfig>> {
    load_network_in(&config_dir()?, name)
}

fn load_network_in(dir: &Path, name: &str) -> Result<Option<NetworkConfig>> {
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

/// Delete a single network's config file. Returns true if it existed.
pub fn delete_network(name: &str) -> Result<bool> {
    delete_network_in(&config_dir()?, name)
}

fn delete_network_in(dir: &Path, name: &str) -> Result<bool> {
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
pub(crate) static CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::EndpointId;

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        SecretKey::from(key_bytes).public()
    }

    #[test]
    fn test_serialize_roundtrip() {
        let config = AppConfig {
            networks: vec![
                NetworkConfig {
                    name: "gaming".to_string(),
                    group_mode: GroupMode::Open,
                    my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
                    members: vec![
                        MemberEntry {
                            identity: test_id(2),
                            ip: Ipv4Addr::new(100, 64, 5, 3),
                            is_coordinator: true,
                            hostname: None,
                        },
                        MemberEntry {
                            identity: test_id(3),
                            ip: Ipv4Addr::new(100, 64, 10, 5),
                            is_coordinator: false,
                            hostname: None,
                        },
                    ],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
                },
                NetworkConfig {
                    name: "work".to_string(),
                    group_mode: GroupMode::Restricted,
                    my_ip: None,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
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
            my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
            my_hostname: None,
            pending_hostname: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
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
                my_ip: None,
                members: vec![],
                approved: vec![],
                network_secret_key: None,
                network_public_key: None,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                ssh_allow: vec![],
                aliases: BTreeMap::new(),
            }],
            ..Default::default()
        };
        let updated = NetworkConfig {
            name: "test".to_string(),
            group_mode: GroupMode::Open,
            my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
            my_hostname: None,
            pending_hostname: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
        };
        upsert_network(&mut config, updated.clone());
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].group_mode, GroupMode::Open);
        assert_eq!(
            config.networks[0].my_ip,
            Some(Ipv4Addr::new(100, 64, 10, 5))
        );
    }

    #[test]
    fn test_remove_network() {
        let mut config = AppConfig {
            networks: vec![
                NetworkConfig {
                    name: "keep".to_string(),
                    group_mode: GroupMode::Restricted,
                    my_ip: None,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
                },
                NetworkConfig {
                    name: "remove-me".to_string(),
                    group_mode: GroupMode::Restricted,
                    my_ip: None,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                    my_hostname: None,
                    pending_hostname: None,
                    transport: None,
                    auto_accept_firewall: false,
                    auto_accept_files: false,
                    admins: vec![],
                    direct: false,
                    ssh_allow: vec![],
                    aliases: BTreeMap::new(),
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
                my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
                members: vec![MemberEntry {
                    identity: id1,
                    ip: Ipv4Addr::new(100, 64, 5, 3),
                    is_coordinator: true,
                    hostname: None,
                }],
                approved: vec![ApprovedConfigEntry {
                    identity: id2,
                    ip: Ipv4Addr::new(100, 64, 12, 34),
                    hostname: None,
                }],
                network_secret_key: None,
                network_public_key: None,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                ssh_allow: vec![],
                aliases: BTreeMap::new(),
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
                my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
                members: vec![],
                approved: vec![],
                network_secret_key: Some(secret.clone()),
                network_public_key: Some(public),
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                ssh_allow: vec![],
                aliases: BTreeMap::new(),
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
name = "dario-alice"
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

    fn net(name: &str) -> NetworkConfig {
        NetworkConfig {
            name: name.to_string(),
            group_mode: GroupMode::Restricted,
            my_ip: None,
            my_hostname: None,
            pending_hostname: None,
            members: vec![],
            approved: vec![],
            network_secret_key: Some(SecretKey::generate()),
            network_public_key: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
        }
    }

    #[test]
    fn per_network_roundtrip_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        save_network_in(dir, &net("homelab")).unwrap();
        save_network_in(dir, &net("genesis")).unwrap();
        save_settings_in(
            dir,
            &AppConfig {
                default_hostname: Some("dario".into()),
                ..Default::default()
            },
        )
        .unwrap();

        let loaded = load_in(dir).unwrap();
        assert_eq!(loaded.networks.len(), 2);
        assert_eq!(loaded.default_hostname.as_deref(), Some("dario"));

        // Single-network load.
        assert!(load_network_in(dir, "homelab").unwrap().is_some());
        assert!(load_network_in(dir, "absent").unwrap().is_none());

        // Deleting one leaves the other untouched.
        assert!(delete_network_in(dir, "homelab").unwrap());
        assert!(!delete_network_in(dir, "homelab").unwrap());
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
        save_network_in(dir, &n).unwrap();
        let loaded = load_network_in(dir, "homelab").unwrap().unwrap();
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

    #[test]
    fn config_set_unknown_key_errors() {
        let mut cfg = AppConfig::default();
        assert!(config_set(&mut cfg, "bogus", "rayfish", false).is_err());
        assert!(config_get(&cfg, Some("bogus")).is_err());
    }

    #[test]
    fn config_set_n0_resets() {
        let mut cfg = AppConfig::default();
        config_set(&mut cfg, "relay", "rayfish", true).unwrap();
        assert!(!cfg.relay.is_unset());
        config_set(&mut cfg, "relay", "n0", false).unwrap();
        assert!(cfg.relay.is_unset());
    }

    #[test]
    fn config_set_dns_upstreams_rejects_non_ip() {
        let mut cfg = AppConfig::default();
        assert!(config_set(&mut cfg, "dns-upstreams", "1.1.1.1", false).is_ok());
        assert!(config_set(&mut cfg, "dns-upstreams", "not-an-ip", false).is_err());
        // rayfish is not a valid upstream keyword.
        assert!(config_set(&mut cfg, "dns-upstreams", "rayfish", false).is_err());
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
                    save_network_in(&dir, &net(&format!("net-{i}"))).unwrap();
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

    #[test]
    fn migrate_legacy_splits_and_backs_up() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Write a legacy single-file config (the pre-shard format).
        let legacy = AppConfig {
            default_hostname: Some("dario".into()),
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
        assert_eq!(loaded.default_hostname.as_deref(), Some("dario"));

        // Idempotent: a second migrate (no legacy file) is a no-op.
        migrate_legacy(dir).unwrap();
        assert_eq!(load_in(dir).unwrap().networks.len(), 2);
    }

    #[test]
    fn rejects_unsafe_network_names() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        assert!(save_network_in(dir, &net("../escape")).is_err());
        assert!(load_network_in(dir, "a/b").is_err());
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
}
