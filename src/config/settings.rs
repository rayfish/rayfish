//! The settings key registry: one dotted key per user-settable value, mapped to
//! the store that holds it. Every `ray` command that sets a single value routes
//! here instead of carrying its own IPC variant and daemon handler.

use anyhow::{bail, Result};

use super::AppConfig;

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
pub static KEYS: &[SettingKey] = &[SettingKey {
    name: "mdns",
    scope: Scope::Global,
    help: "LAN peer discovery over mDNS (on|off)",
}];

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

pub fn apply_global(cfg: &mut AppConfig, key: &str, value: &str, _replace: bool) -> Result<()> {
    match key {
        "mdns" => cfg.mdns_enabled = parse_bool(value, true)?,
        other => bail!("unknown config key: {other}"),
    }
    Ok(())
}

pub fn render_global(cfg: &AppConfig, key: &str) -> Result<String> {
    let out = match key {
        "mdns" => on_off(cfg.mdns_enabled),
        other => bail!("unknown config key: {other}"),
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
}
