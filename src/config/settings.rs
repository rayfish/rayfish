//! What each settings key means: the parse, the field it writes, and how it
//! renders back. The key *names* live in `ray-proto` ([`GlobalKey`],
//! [`FirewallKey`], [`NetworkKey`]) because they travel on the wire; this
//! module is where they meet the config types they write into.
//!
//! Every `ray` command that sets a single value routes here instead of
//! carrying its own IPC variant and daemon handler. Each `apply_*`/`render_*`
//! pair matches its scope's key enum exhaustively, so a new key cannot be
//! added without teaching every handler that serves it.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};

pub use ray_proto::settings::{FirewallKey, GlobalKey, NetworkKey, NodeKey};

use super::{AppConfig, NetworkConfig, ServerOverride};
use crate::firewall::{Action, FirewallConfig};

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

pub fn apply_global(cfg: &mut AppConfig, key: GlobalKey, value: &str, replace: bool) -> Result<()> {
    let entries = super::parse_entries(value);
    let reset = entries.is_empty() || entries == ["n0"];
    match key {
        GlobalKey::Mdns => cfg.mdns_enabled = parse_bool(value, true)?,
        GlobalKey::AutoUpdate => cfg.auto_update = parse_bool(value, false)?,
        GlobalKey::OnDemand => cfg.on_demand = parse_bool(value, true)?,
        // The one tri-state: `auto` (and `unset`, which sends an empty value)
        // both parse to `Auto`, which is not written to the file at all, so the
        // decision stays with the startup scan.
        GlobalKey::Ipv6Only => {
            cfg.ipv6_only = value
                .parse()
                .map_err(|e| anyhow::anyhow!("'{value}' is not a valid ipv6-only value: {e}"))?
        }

        // Writing `ssh_enabled` is only half of `ray firewall ssh on|off`: the
        // caller must also seed/remove the `allow in tcp:22` passthrough and
        // start/stop the live listener (see `Daemon::ssh_config_set`).
        GlobalKey::Ssh => cfg.ssh_enabled = parse_bool(value, false)?,
        // Validated here, not in the CLI arm, so every caller is bound by it: a
        // relative download dir would resolve against the daemon's cwd, not the
        // user's.
        GlobalKey::DownloadDir => {
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
        GlobalKey::DownloadUser => {
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

        GlobalKey::Relay => {
            cfg.relay = server_override(entries, reset, replace, super::RELAY_PRESET_RAYFISH)?
        }
        GlobalKey::DiscoveryDns => {
            cfg.discovery_dns =
                server_override(entries, reset, replace, super::DISCOVERY_PRESET_RAYFISH)?
        }
        GlobalKey::DnsUpstreams => {
            if entries.is_empty() {
                cfg.dns_upstreams = ServerOverride::default();
            } else {
                // Either family. IPv4 entries are merged with the system-captured
                // upstreams (`config::resolve_upstreams`); IPv6 ones are what an
                // exit-node full tunnel in IPv6-only mode forwards to, since that
                // tunnel carries no IPv4 for a v4 resolver to be reached over
                // (`exit_node::tunnel_upstreams`).
                for e in &entries {
                    e.parse::<IpAddr>()
                        .with_context(|| format!("invalid IP address: {e}"))?;
                }
                cfg.dns_upstreams = ServerOverride {
                    servers: entries,
                    replace,
                };
            }
        }
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

/// Render one global key. Infallible: an unknown key is not representable, and
/// the compiler rejects a `GlobalKey` variant with no arm here.
pub fn render_global(cfg: &AppConfig, key: GlobalKey) -> String {
    match key {
        GlobalKey::Mdns => on_off(cfg.mdns_enabled),
        GlobalKey::AutoUpdate => on_off(cfg.auto_update),
        GlobalKey::OnDemand => on_off(cfg.on_demand),
        GlobalKey::Ipv6Only => cfg.ipv6_only.to_string(),
        GlobalKey::Ssh => on_off(cfg.ssh_enabled),
        // Empty renders as unset, matching the `net.ephemeral-ttl` convention.
        GlobalKey::DownloadDir => cfg.download_dir.clone().unwrap_or_default(),
        GlobalKey::DownloadUser => cfg.download_user.map(|u| u.to_string()).unwrap_or_default(),
        GlobalKey::Relay => super::render_override(&cfg.relay),
        GlobalKey::DiscoveryDns => super::render_override(&cfg.discovery_dns),
        GlobalKey::DnsUpstreams => super::render_override(&cfg.dns_upstreams),
    }
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
/// `firewall.default-out` (`default_outbound`) is deliberately not a key: there
/// is no existing setter for it anywhere (`ray firewall default` only ever
/// touches the inbound default), so adding one would be new user-facing surface
/// rather than a migration of an existing one.
pub fn apply_firewall(cfg: &mut FirewallConfig, key: FirewallKey, value: &str) -> Result<()> {
    match key {
        // The field is stored inverted: `disabled: true` means the firewall is
        // off. `on` (the enabled default) maps to `disabled = false`.
        FirewallKey::Enabled => cfg.disabled = !parse_bool(value, true)?,
        FirewallKey::Reject => cfg.reject = parse_bool(value, false)?,
        FirewallKey::DefaultIn => cfg.default_inbound = parse_action(value, Action::Deny)?,
    }
    Ok(())
}

pub fn render_firewall(cfg: &FirewallConfig, key: FirewallKey) -> String {
    match key {
        FirewallKey::Enabled => on_off(!cfg.disabled),
        FirewallKey::Reject => on_off(cfg.reject),
        FirewallKey::DefaultIn => cfg.default_inbound.to_string(),
    }
}

/// Minimum `net.ephemeral-ttl`. Below an hour, a laptop that closes its lid
/// over lunch gets evicted from the roster.
pub const EPHEMERAL_TTL_FLOOR_SECS: u64 = 3600;

/// `networks/<name>.toml` (`NetworkConfig`) is a third store, distinct from
/// `settings.toml` and `firewall.toml`. Pure over an owned `&mut
/// NetworkConfig`: the caller persists (`config::save_network`) and applies
/// any live re-materialization (e.g. re-installing suggested firewall rules,
/// draining queued file offers), neither of which happens here.
pub fn apply_network(cfg: &mut NetworkConfig, key: NetworkKey, value: &str) -> Result<()> {
    match key {
        NetworkKey::AutoAcceptFirewall => cfg.auto_accept_firewall = parse_bool(value, false)?,
        NetworkKey::AutoAcceptFiles => cfg.auto_accept_files = parse_bool(value, true)?,
        NetworkKey::EphemeralTtl => {
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
    }
    Ok(())
}

pub fn render_network(cfg: &NetworkConfig, key: NetworkKey) -> String {
    match key {
        NetworkKey::AutoAcceptFirewall => on_off(cfg.auto_accept_firewall),
        NetworkKey::AutoAcceptFiles => on_off(cfg.auto_accept_files),
        NetworkKey::EphemeralTtl => match cfg.ephemeral_ttl_secs {
            Some(s) => s.to_string(),
            None => String::new(),
        },
    }
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
    use super::super::empty_network_config as empty_network;
    use super::*;
    use crate::config::Ipv6Only;

    /// The one tri-state key: `on`/`off` are stored choices, `auto` (and
    /// `unset`, which sends an empty value) stores nothing, so the daemon
    /// decides at startup from what else is on the host.
    #[test]
    fn ipv6_only_is_on_off_or_auto() {
        let mut cfg = AppConfig::default();
        assert_eq!(cfg.ipv6_only, Ipv6Only::Auto, "auto is the default");
        assert_eq!(render_global(&cfg, GlobalKey::Ipv6Only), "auto");

        for (input, want, rendered) in [
            ("on", Ipv6Only::On, "on"),
            ("off", Ipv6Only::Off, "off"),
            ("auto", Ipv6Only::Auto, "auto"),
            ("on", Ipv6Only::On, "on"),
            ("", Ipv6Only::Auto, "auto"),
        ] {
            apply_global(&mut cfg, GlobalKey::Ipv6Only, input, false).unwrap();
            assert_eq!(cfg.ipv6_only, want, "set ipv6-only {input:?}");
            assert_eq!(render_global(&cfg, GlobalKey::Ipv6Only), rendered);
        }

        assert!(apply_global(&mut cfg, GlobalKey::Ipv6Only, "maybe", false).is_err());
    }

    #[test]
    fn network_auto_accept_toggles_round_trip() {
        let mut net = empty_network("gaming");
        apply_network(&mut net, NetworkKey::AutoAcceptFirewall, "on").unwrap();
        assert!(net.auto_accept_firewall);
        apply_network(&mut net, NetworkKey::AutoAcceptFiles, "off").unwrap();
        assert!(!net.auto_accept_files);
        // Unset returns to each key's own default, which differ.
        apply_network(&mut net, NetworkKey::AutoAcceptFirewall, "").unwrap();
        apply_network(&mut net, NetworkKey::AutoAcceptFiles, "").unwrap();
        assert!(!net.auto_accept_firewall);
        assert!(net.auto_accept_files);
    }

    #[test]
    fn ephemeral_ttl_enforces_the_one_hour_floor() {
        let mut net = empty_network("gaming");
        let err = apply_network(&mut net, NetworkKey::EphemeralTtl, "600").unwrap_err();
        assert!(
            err.to_string().contains("3600"),
            "error should name the floor: {err}"
        );
        assert_eq!(net.ephemeral_ttl_secs, None);

        apply_network(&mut net, NetworkKey::EphemeralTtl, "7200").unwrap();
        assert_eq!(net.ephemeral_ttl_secs, Some(7200));
        assert_eq!(render_network(&net, NetworkKey::EphemeralTtl), "7200");

        apply_network(&mut net, NetworkKey::EphemeralTtl, "").unwrap();
        assert_eq!(net.ephemeral_ttl_secs, None, "unset turns the policy off");
    }

    #[test]
    fn apply_global_sets_and_resets_mdns() {
        let mut cfg = AppConfig::default();
        apply_global(&mut cfg, GlobalKey::Mdns, "off", false).unwrap();
        assert!(!cfg.mdns_enabled);
        apply_global(&mut cfg, GlobalKey::Mdns, "on", false).unwrap();
        assert!(cfg.mdns_enabled);
        // An empty value is what `ConfigUnset` sends: back to the default (on).
        apply_global(&mut cfg, GlobalKey::Mdns, "", false).unwrap();
        assert!(cfg.mdns_enabled);
    }

    #[test]
    fn apply_global_rejects_a_bad_bool_without_mutating() {
        let mut cfg = AppConfig::default();
        let err = apply_global(&mut cfg, GlobalKey::Mdns, "maybe", false).unwrap_err();
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
        apply_global(&mut cfg, GlobalKey::AutoUpdate, "on", false).unwrap();
        assert!(cfg.auto_update);
        apply_global(&mut cfg, GlobalKey::OnDemand, "off", false).unwrap();
        assert!(!cfg.on_demand);

        // The two defaults differ, so a shared "reset to false" would pass one and
        // fail the other.
        apply_global(&mut cfg, GlobalKey::AutoUpdate, "", false).unwrap();
        apply_global(&mut cfg, GlobalKey::OnDemand, "", false).unwrap();
        assert!(!cfg.auto_update);
        assert!(cfg.on_demand);
    }

    /// `default_hostname` is written internally (by the join/rename flow), and no
    /// command sets it. A key for it would be new user-facing surface, so there
    /// is no variant for it and the name does not parse.
    #[test]
    fn hostname_default_is_deliberately_not_a_key() {
        assert!("hostname-default".parse::<NodeKey>().is_err());
    }

    /// No existing setter touches the outbound default; a key for it would be
    /// new user-facing surface, not a migration of an existing one (same rule as
    /// `hostname-default`).
    #[test]
    fn firewall_default_out_is_deliberately_not_a_key() {
        assert!("firewall.default-out".parse::<NodeKey>().is_err());
    }

    #[test]
    fn ssh_toggles_but_the_side_effects_are_the_callers_job() {
        let mut cfg = AppConfig::default();
        apply_global(&mut cfg, GlobalKey::Ssh, "on", false).unwrap();
        assert!(cfg.ssh_enabled);
        assert_eq!(render_global(&cfg, GlobalKey::Ssh), "on");
        // Unset goes back to off, the secure default.
        apply_global(&mut cfg, GlobalKey::Ssh, "", false).unwrap();
        assert!(!cfg.ssh_enabled);
    }

    #[test]
    fn download_dir_must_be_absolute() {
        let mut cfg = AppConfig::default();
        let err =
            apply_global(&mut cfg, GlobalKey::DownloadDir, "relative/path", false).unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "error should say why: {err}"
        );
        assert_eq!(
            cfg.download_dir, None,
            "a rejected value must not be stored"
        );

        apply_global(&mut cfg, GlobalKey::DownloadDir, "/srv/inbox", false).unwrap();
        assert_eq!(cfg.download_dir.as_deref(), Some("/srv/inbox"));
        assert_eq!(render_global(&cfg, GlobalKey::DownloadDir), "/srv/inbox");

        // Empty clears it (what `ray files download-dir --clear` sends).
        apply_global(&mut cfg, GlobalKey::DownloadDir, "", false).unwrap();
        assert_eq!(cfg.download_dir, None);
        assert_eq!(render_global(&cfg, GlobalKey::DownloadDir), "");
    }

    #[test]
    fn download_user_takes_a_numeric_uid_only() {
        let mut cfg = AppConfig::default();
        // The CLI resolves a username to a uid before sending; the registry does not.
        assert!(apply_global(&mut cfg, GlobalKey::DownloadUser, "alice", false).is_err());
        assert_eq!(cfg.download_user, None);

        apply_global(&mut cfg, GlobalKey::DownloadUser, "501", false).unwrap();
        assert_eq!(cfg.download_user, Some(501));
        assert_eq!(render_global(&cfg, GlobalKey::DownloadUser), "501");

        apply_global(&mut cfg, GlobalKey::DownloadUser, "", false).unwrap();
        assert_eq!(cfg.download_user, None);
        assert_eq!(render_global(&cfg, GlobalKey::DownloadUser), "");
    }

    #[test]
    fn relay_override_still_validates_and_honours_replace() {
        let mut cfg = AppConfig::default();
        apply_global(&mut cfg, GlobalKey::Relay, "rayfish", true).unwrap();
        assert_eq!(cfg.relay.servers, vec!["rayfish".to_string()]);
        assert!(cfg.relay.replace);
        assert!(apply_global(&mut cfg, GlobalKey::Relay, "not a url", false).is_err());
    }

    #[test]
    fn firewall_toggles_round_trip() {
        let mut fw = FirewallConfig::default();
        apply_firewall(&mut fw, FirewallKey::Reject, "on").unwrap();
        assert!(fw.reject);
        assert_eq!(render_firewall(&fw, FirewallKey::Reject), "on");

        apply_firewall(&mut fw, FirewallKey::Enabled, "off").unwrap();
        assert!(fw.disabled, "enabled=off stores as disabled=true");
        assert_eq!(render_firewall(&fw, FirewallKey::Enabled), "off");
    }

    #[test]
    fn firewall_default_in_parses_allow_and_deny_only() {
        let mut fw = FirewallConfig::default();
        apply_firewall(&mut fw, FirewallKey::DefaultIn, "allow").unwrap();
        assert_eq!(render_firewall(&fw, FirewallKey::DefaultIn), "allow");
        assert!(apply_firewall(&mut fw, FirewallKey::DefaultIn, "maybe").is_err());
    }
}
