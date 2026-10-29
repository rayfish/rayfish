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

pub(crate) mod destruction;
mod write;

pub use write::{restrict_perms, write_file};
use write::{sync_dir, sync_file_and_parent, write_atomic};

pub mod settings;

mod schema;
pub use schema::*;

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

mod paths;
pub use paths::*;

#[cfg(windows)]
mod operator;
#[cfg(windows)]
pub use operator::*;

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
