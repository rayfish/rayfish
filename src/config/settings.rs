//! The settings key registry: one dotted key per user-settable value, mapped to
//! the store that holds it. Every `ray` command that sets a single value routes
//! here instead of carrying its own IPC variant and daemon handler.

use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};

use super::{AppConfig, ServerOverride};

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
    SettingKey { name: "mdns", scope: Scope::Global, help: "LAN peer discovery over mDNS (on|off)" },
    SettingKey { name: "relay", scope: Scope::Global, help: "iroh relay servers (preset or URL, comma-separated)" },
    SettingKey { name: "discovery-dns", scope: Scope::Global, help: "pkarr discovery server (preset or URL)" },
    SettingKey { name: "dns-upstreams", scope: Scope::Global, help: "Magic DNS upstream forwarders (IPv4, comma-separated)" },
    SettingKey { name: "auto-update", scope: Scope::Global, help: "install new releases automatically (on|off)" },
    SettingKey { name: "on-demand", scope: Scope::Global, help: "dial peers lazily on first packet (on|off)" },
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

        "relay" => cfg.relay = server_override(entries, reset, replace, super::RELAY_PRESET_RAYFISH)?,
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
                cfg.dns_upstreams = ServerOverride { servers: entries, replace };
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
    Ok(ServerOverride { servers: entries, replace })
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
        "relay" => super::render_override(&cfg.relay),
        "discovery-dns" => super::render_override(&cfg.discovery_dns),
        "dns-upstreams" => super::render_override(&cfg.dns_upstreams),
        other => bail!("unknown config key: {other} ({})", key_list()),
    };
    Ok(out)
}

fn on_off(v: bool) -> String {
    if v { "on".to_string() } else { "off".to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(err.to_string().contains("on"), "error should name the valid values: {err}");
        assert!(cfg.mdns_enabled, "a rejected value must leave config untouched");
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
    fn a_key_that_is_not_registered_here_is_rejected() {
        // `ssh` / `download-dir` / `download-user` are registered in Task 6, in the
        // same commit that migrates their side-effecting handlers. Until then they
        // must not be reachable through the generic `ray config set`.
        let mut cfg = AppConfig::default();
        assert!(apply_global(&mut cfg, "ssh", "on", false).is_err());
        assert!(apply_global(&mut cfg, "download-dir", "/srv/x", false).is_err());
        assert!(apply_global(&mut cfg, "hostname-default", "box", false).is_err());
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
}
