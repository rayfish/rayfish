//! The settings key registry: one dotted key per user-settable value, mapped to
//! the store that holds it. Every `ray` command that sets a single value routes
//! here instead of carrying its own IPC variant and daemon handler.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::{AppConfig, NetworkConfig, ServerOverride};
use crate::firewall::{Action, FirewallConfig};

/// Which on-disk store backs a key, and therefore which handler serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// `settings.toml` (`AppConfig`).
    Global,
    /// `firewall.toml` (`FirewallConfig`). Node-wide, but a separate file.
    Firewall,
    /// `networks/<name>.toml` (`NetworkConfig`). Needs a network argument.
    Network,
}

/// One registered key. `help` is what `ray config get` prints alongside it.
#[derive(Debug, Clone, Copy)]
pub struct SettingKey {
    pub name: &'static str,
    pub scope: Scope,
    pub help: &'static str,
}

/// Every settable key. Adding a setting means adding a row here and an arm in
/// the matching `apply_*`/`render_*`, and nothing else: no IPC variant, no
/// daemon handler, no new CLI plumbing.
pub static KEYS: &[SettingKey] = &[
    SettingKey {
        name: "mdns",
        scope: Scope::Global,
        help: "LAN peer discovery over mDNS (on|off)",
    },
    SettingKey {
        name: "relay",
        scope: Scope::Global,
        help: "iroh relay servers (preset or URL, comma-separated)",
    },
    SettingKey {
        name: "discovery-dns",
        scope: Scope::Global,
        help: "pkarr discovery server (preset or URL)",
    },
    SettingKey {
        name: "dns-upstreams",
        scope: Scope::Global,
        help: "Magic DNS upstream forwarders (IPv4, comma-separated)",
    },
    SettingKey {
        name: "auto-update",
        scope: Scope::Global,
        help: "install new releases automatically (on|off)",
    },
    SettingKey {
        name: "on-demand",
        scope: Scope::Global,
        help: "dial peers lazily on first packet (on|off)",
    },
    SettingKey {
        name: "ssh",
        scope: Scope::Global,
        help: "embedded mesh SSH server (on|off)",
    },
    SettingKey {
        name: "download-dir",
        scope: Scope::Global,
        help: "directory accepted files land in (absolute path, empty to clear)",
    },
    SettingKey {
        name: "download-user",
        scope: Scope::Global,
        help: "uid that owns accepted files (numeric, empty to clear)",
    },
    SettingKey {
        name: "firewall.enabled",
        scope: Scope::Firewall,
        help: "enforce the firewall at all (on|off)",
    },
    SettingKey {
        name: "firewall.reject",
        scope: Scope::Firewall,
        help: "reply RST/unreachable instead of dropping (on|off)",
    },
    SettingKey {
        name: "firewall.default-in",
        scope: Scope::Firewall,
        help: "default action for inbound traffic (allow|deny)",
    },
    SettingKey {
        name: "net.auto-accept-firewall",
        scope: Scope::Network,
        help: "install coordinator-suggested rules without review (on|off)",
    },
    SettingKey {
        name: "net.auto-accept-files",
        scope: Scope::Network,
        help: "auto-accept file offers from your own devices (on|off)",
    },
    SettingKey {
        name: "net.ephemeral-ttl",
        scope: Scope::Network,
        help: "coordinator: drop members offline longer than N seconds (>=3600, empty to disable)",
    },
];

pub fn lookup(key: &str) -> Option<&'static SettingKey> {
    KEYS.iter().find(|k| k.name == key)
}

pub fn keys_for(scope: Scope) -> impl Iterator<Item = &'static SettingKey> {
    KEYS.iter().filter(move |k| k.scope == scope)
}

/// Parse an on/off value. An empty value (what `ConfigUnset` sends) resets to
/// `default`.
pub fn parse_bool(value: &str, default: bool) -> Result<bool> {
    let v = value.trim();
    if v.is_empty() {
        return Ok(default);
    }
    match v.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        other => bail!("'{other}' is not a valid on/off value (use 'on' or 'off')"),
    }
}

pub fn apply_global(cfg: &mut AppConfig, key: &str, value: &str, replace: bool) -> Result<()> {
    let entries = super::parse_entries(value);
    let reset = entries.is_empty() || entries == ["n0"];
    match key {
        "mdns" => cfg.mdns_enabled = parse_bool(value, true)?,
        "auto-update" => cfg.auto_update = parse_bool(value, false)?,
        "on-demand" => cfg.on_demand = parse_bool(value, true)?,

        // Writing `ssh_enabled` is only half of `ray firewall ssh on|off`: the
        // caller must also seed/remove the `allow in tcp:22` passthrough and
        // start/stop the live listener (see `Daemon::ssh_config_set`).
        "ssh" => cfg.ssh_enabled = parse_bool(value, false)?,
        // Validated here, not in the CLI arm, so every caller is bound by it: a
        // relative download dir would resolve against the daemon's cwd, not the
        // user's.
        "download-dir" => {
            let v = value.trim();
            cfg.download_dir = if v.is_empty() {
                None
            } else {
                if !Path::new(v).is_absolute() {
                    bail!("download-dir must be an absolute path: {v}");
                }
                Some(v.to_string())
            };
        }
        // A numeric uid only: the CLI resolves a username before sending, so the
        // daemon never has to consult the local passwd database.
        "download-user" => {
            let v = value.trim();
            cfg.download_user = if v.is_empty() {
                None
            } else {
                Some(
                    v.parse::<u32>()
                        .with_context(|| format!("invalid uid: {v} (expected a numeric uid)"))?,
                )
            };
        }

        "relay" => {
            cfg.relay = server_override(entries, reset, replace, super::RELAY_PRESET_RAYFISH)?
        }
        "discovery-dns" => {
            cfg.discovery_dns =
                server_override(entries, reset, replace, super::DISCOVERY_PRESET_RAYFISH)?
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

        other => bail!("unknown config key: {other} ({})", key_list()),
    }
    Ok(())
}

/// Build a `ServerOverride`, validating each entry against `preset`.
fn server_override(
    entries: Vec<String>,
    reset: bool,
    replace: bool,
    preset: &str,
) -> Result<ServerOverride> {
    if reset {
        return Ok(ServerOverride::default());
    }
    for e in &entries {
        super::resolve_url_entry(e, preset)?;
    }
    Ok(ServerOverride {
        servers: entries,
        replace,
    })
}

/// Comma-joined key names, for the "unknown key" error.
pub fn key_list() -> String {
    KEYS.iter().map(|k| k.name).collect::<Vec<_>>().join(", ")
}

pub fn render_global(cfg: &AppConfig, key: &str) -> Result<String> {
    let out = match key {
        "mdns" => on_off(cfg.mdns_enabled),
        "auto-update" => on_off(cfg.auto_update),
        "on-demand" => on_off(cfg.on_demand),
        "ssh" => on_off(cfg.ssh_enabled),
        // Empty renders as unset, matching the `net.ephemeral-ttl` convention.
        "download-dir" => cfg.download_dir.clone().unwrap_or_default(),
        "download-user" => cfg.download_user.map(|u| u.to_string()).unwrap_or_default(),
        "relay" => super::render_override(&cfg.relay),
        "discovery-dns" => super::render_override(&cfg.discovery_dns),
        "dns-upstreams" => super::render_override(&cfg.dns_upstreams),
        other => bail!("unknown config key: {other} ({})", key_list()),
    };
    Ok(out)
}

fn on_off(v: bool) -> String {
    if v {
        "on".to_string()
    } else {
        "off".to_string()
    }
}

/// `firewall.toml` (`FirewallConfig`) is a separate store from `settings.toml`,
/// so it gets its own accessor pair rather than being folded into
/// `apply_global`/`render_global`. Pure functions over an owned `&mut
/// FirewallConfig`: the caller is responsible for hot-swapping the live
/// `ArcSwap` the data path reads from and persisting to disk (see
/// `Daemon::edit_firewall`), neither of which happens here.
///
/// `firewall.default-out` (`default_outbound`) is deliberately not registered:
/// there is no existing setter for it anywhere (`ray firewall default` only
/// ever touches the inbound default), so adding it here would be new
/// user-facing surface rather than a migration of an existing one.
pub fn apply_firewall(cfg: &mut FirewallConfig, key: &str, value: &str) -> Result<()> {
    match key {
        // The field is stored inverted: `disabled: true` means the firewall is
        // off. `on` (the enabled default) maps to `disabled = false`.
        "firewall.enabled" => cfg.disabled = !parse_bool(value, true)?,
        "firewall.reject" => cfg.reject = parse_bool(value, false)?,
        "firewall.default-in" => cfg.default_inbound = parse_action(value, Action::Deny)?,
        other => bail!("unknown config key: {other} ({})", key_list()),
    }
    Ok(())
}

pub fn render_firewall(cfg: &FirewallConfig, key: &str) -> Result<String> {
    let out = match key {
        "firewall.enabled" => on_off(!cfg.disabled),
        "firewall.reject" => on_off(cfg.reject),
        "firewall.default-in" => cfg.default_inbound.to_string(),
        other => bail!("unknown config key: {other} ({})", key_list()),
    };
    Ok(out)
}

/// Minimum `net.ephemeral-ttl`. Below an hour, a laptop that closes its lid
/// over lunch gets evicted from the roster.
pub const EPHEMERAL_TTL_FLOOR_SECS: u64 = 3600;

/// `networks/<name>.toml` (`NetworkConfig`) is a third store, distinct from
/// `settings.toml` and `firewall.toml`. Pure over an owned `&mut
/// NetworkConfig`: the caller persists (`config::save_network`) and applies
/// any live re-materialization (e.g. re-installing suggested firewall rules,
/// draining queued file offers), neither of which happens here.
pub fn apply_network(cfg: &mut NetworkConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "net.auto-accept-firewall" => cfg.auto_accept_firewall = parse_bool(value, false)?,
        "net.auto-accept-files" => cfg.auto_accept_files = parse_bool(value, true)?,
        "net.ephemeral-ttl" => {
            let v = value.trim();
            cfg.ephemeral_ttl_secs = if v.is_empty() {
                None
            } else {
                let secs: u64 = v
                    .parse()
                    .with_context(|| format!("invalid ttl: {v} (expected seconds)"))?;
                if secs < EPHEMERAL_TTL_FLOOR_SECS {
                    bail!("ttl must be at least {EPHEMERAL_TTL_FLOOR_SECS} seconds (1 hour)");
                }
                Some(secs)
            };
        }
        other => bail!("unknown config key: {other} ({})", key_list()),
    }
    Ok(())
}

pub fn render_network(cfg: &NetworkConfig, key: &str) -> Result<String> {
    let out = match key {
        "net.auto-accept-firewall" => on_off(cfg.auto_accept_firewall),
        "net.auto-accept-files" => on_off(cfg.auto_accept_files),
        "net.ephemeral-ttl" => match cfg.ephemeral_ttl_secs {
            Some(s) => s.to_string(),
            None => String::new(),
        },
        other => bail!("unknown config key: {other} ({})", key_list()),
    };
    Ok(out)
}

/// Parse an allow/deny value; empty resets to `default`.
fn parse_action(value: &str, default: Action) -> Result<Action> {
    let v = value.trim();
    if v.is_empty() {
        return Ok(default);
    }
    v.to_ascii_lowercase()
        .parse::<Action>()
        .map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::GroupMode;
    use super::*;

    fn empty_network(name: &str) -> super::super::NetworkConfig {
        super::super::NetworkConfig {
            name: name.to_string(),
            group_mode: GroupMode::Open,
            my_ip: None,
            my_hostname: None,
            pending_hostname: None,
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: true,
            admins: vec![],
            direct: false,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        }
    }

    #[test]
    fn network_auto_accept_toggles_round_trip() {
        let mut net = empty_network("gaming");
        apply_network(&mut net, "net.auto-accept-firewall", "on").unwrap();
        assert!(net.auto_accept_firewall);
        apply_network(&mut net, "net.auto-accept-files", "off").unwrap();
        assert!(!net.auto_accept_files);
        // Unset returns to each key's own default, which differ.
        apply_network(&mut net, "net.auto-accept-firewall", "").unwrap();
        apply_network(&mut net, "net.auto-accept-files", "").unwrap();
        assert!(!net.auto_accept_firewall);
        assert!(net.auto_accept_files);
    }

    #[test]
    fn ephemeral_ttl_enforces_the_one_hour_floor() {
        let mut net = empty_network("gaming");
        let err = apply_network(&mut net, "net.ephemeral-ttl", "600").unwrap_err();
        assert!(
            err.to_string().contains("3600"),
            "error should name the floor: {err}"
        );
        assert_eq!(net.ephemeral_ttl_secs, None);

        apply_network(&mut net, "net.ephemeral-ttl", "7200").unwrap();
        assert_eq!(net.ephemeral_ttl_secs, Some(7200));
        assert_eq!(render_network(&net, "net.ephemeral-ttl").unwrap(), "7200");

        apply_network(&mut net, "net.ephemeral-ttl", "").unwrap();
        assert_eq!(net.ephemeral_ttl_secs, None, "unset turns the policy off");
    }

    #[test]
    fn every_registered_network_key_renders() {
        let net = empty_network("gaming");
        for k in keys_for(Scope::Network) {
            render_network(&net, k.name)
                .unwrap_or_else(|e| panic!("key {} has no render arm: {e}", k.name));
        }
    }

    #[test]
    fn lookup_finds_a_known_key_and_rejects_an_unknown_one() {
        let k = lookup("mdns").expect("mdns is a registered key");
        assert_eq!(k.scope, Scope::Global);
        assert!(lookup("not-a-key").is_none());
    }

    #[test]
    fn apply_global_sets_and_resets_mdns() {
        let mut cfg = AppConfig::default();
        apply_global(&mut cfg, "mdns", "off", false).unwrap();
        assert!(!cfg.mdns_enabled);
        apply_global(&mut cfg, "mdns", "on", false).unwrap();
        assert!(cfg.mdns_enabled);
        // An empty value is what `ConfigUnset` sends: back to the default (on).
        apply_global(&mut cfg, "mdns", "", false).unwrap();
        assert!(cfg.mdns_enabled);
    }

    #[test]
    fn apply_global_rejects_a_bad_bool_without_mutating() {
        let mut cfg = AppConfig::default();
        let err = apply_global(&mut cfg, "mdns", "maybe", false).unwrap_err();
        assert!(
            err.to_string().contains("on"),
            "error should name the valid values: {err}"
        );
        assert!(
            cfg.mdns_enabled,
            "a rejected value must leave config untouched"
        );
    }

    #[test]
    fn toggles_round_trip_and_unset_returns_each_key_to_its_own_default() {
        let mut cfg = AppConfig::default();
        apply_global(&mut cfg, "auto-update", "on", false).unwrap();
        assert!(cfg.auto_update);
        apply_global(&mut cfg, "on-demand", "off", false).unwrap();
        assert!(!cfg.on_demand);

        // The two defaults differ, so a shared "reset to false" would pass one and
        // fail the other.
        apply_global(&mut cfg, "auto-update", "", false).unwrap();
        apply_global(&mut cfg, "on-demand", "", false).unwrap();
        assert!(!cfg.auto_update);
        assert!(cfg.on_demand);
    }

    #[test]
    fn hostname_default_is_deliberately_not_registered() {
        // `default_hostname` is written internally (by the join/rename flow), and
        // no command sets it. A key for it would be new user-facing surface.
        let mut cfg = AppConfig::default();
        assert!(apply_global(&mut cfg, "hostname-default", "box", false).is_err());
        assert!(render_global(&cfg, "hostname-default").is_err());
        assert!(lookup("hostname-default").is_none());
    }

    #[test]
    fn ssh_toggles_but_the_side_effects_are_the_callers_job() {
        let mut cfg = AppConfig::default();
        apply_global(&mut cfg, "ssh", "on", false).unwrap();
        assert!(cfg.ssh_enabled);
        assert_eq!(render_global(&cfg, "ssh").unwrap(), "on");
        // Unset goes back to off, the secure default.
        apply_global(&mut cfg, "ssh", "", false).unwrap();
        assert!(!cfg.ssh_enabled);
    }

    #[test]
    fn download_dir_must_be_absolute() {
        let mut cfg = AppConfig::default();
        let err = apply_global(&mut cfg, "download-dir", "relative/path", false).unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "error should say why: {err}"
        );
        assert_eq!(
            cfg.download_dir, None,
            "a rejected value must not be stored"
        );

        apply_global(&mut cfg, "download-dir", "/srv/inbox", false).unwrap();
        assert_eq!(cfg.download_dir.as_deref(), Some("/srv/inbox"));
        assert_eq!(render_global(&cfg, "download-dir").unwrap(), "/srv/inbox");

        // Empty clears it (what `ray files download-dir --clear` sends).
        apply_global(&mut cfg, "download-dir", "", false).unwrap();
        assert_eq!(cfg.download_dir, None);
        assert_eq!(render_global(&cfg, "download-dir").unwrap(), "");
    }

    #[test]
    fn download_user_takes_a_numeric_uid_only() {
        let mut cfg = AppConfig::default();
        // The CLI resolves a username to a uid before sending; the registry does not.
        assert!(apply_global(&mut cfg, "download-user", "alice", false).is_err());
        assert_eq!(cfg.download_user, None);

        apply_global(&mut cfg, "download-user", "501", false).unwrap();
        assert_eq!(cfg.download_user, Some(501));
        assert_eq!(render_global(&cfg, "download-user").unwrap(), "501");

        apply_global(&mut cfg, "download-user", "", false).unwrap();
        assert_eq!(cfg.download_user, None);
        assert_eq!(render_global(&cfg, "download-user").unwrap(), "");
    }

    #[test]
    fn relay_override_still_validates_and_honours_replace() {
        let mut cfg = AppConfig::default();
        apply_global(&mut cfg, "relay", "rayfish", true).unwrap();
        assert_eq!(cfg.relay.servers, vec!["rayfish".to_string()]);
        assert!(cfg.relay.replace);
        assert!(apply_global(&mut cfg, "relay", "not a url", false).is_err());
    }

    #[test]
    fn every_registered_global_key_renders() {
        let cfg = AppConfig::default();
        for k in keys_for(Scope::Global) {
            render_global(&cfg, k.name)
                .unwrap_or_else(|e| panic!("key {} has no render arm: {e}", k.name));
        }
    }

    #[test]
    fn firewall_toggles_round_trip() {
        let mut fw = FirewallConfig::default();
        apply_firewall(&mut fw, "firewall.reject", "on").unwrap();
        assert!(fw.reject);
        assert_eq!(render_firewall(&fw, "firewall.reject").unwrap(), "on");

        apply_firewall(&mut fw, "firewall.enabled", "off").unwrap();
        assert!(fw.disabled, "enabled=off stores as disabled=true");
        assert_eq!(render_firewall(&fw, "firewall.enabled").unwrap(), "off");
    }

    #[test]
    fn firewall_default_in_parses_allow_and_deny_only() {
        let mut fw = FirewallConfig::default();
        apply_firewall(&mut fw, "firewall.default-in", "allow").unwrap();
        assert_eq!(
            render_firewall(&fw, "firewall.default-in").unwrap(),
            "allow"
        );
        assert!(apply_firewall(&mut fw, "firewall.default-in", "maybe").is_err());
    }

    #[test]
    fn every_registered_firewall_key_renders() {
        let fw = FirewallConfig::default();
        for k in keys_for(Scope::Firewall) {
            render_firewall(&fw, k.name)
                .unwrap_or_else(|e| panic!("key {} has no render arm: {e}", k.name));
        }
    }

    #[test]
    fn firewall_default_out_is_deliberately_not_registered() {
        // No existing setter touches the outbound default; registering it would
        // be new user-facing surface, not a migration of an existing one (see
        // `hostname-default` in the global registry for the same rule).
        let mut fw = FirewallConfig::default();
        assert!(apply_firewall(&mut fw, "firewall.default-out", "allow").is_err());
        assert!(render_firewall(&fw, "firewall.default-out").is_err());
        assert!(lookup("firewall.default-out").is_none());
    }
}
