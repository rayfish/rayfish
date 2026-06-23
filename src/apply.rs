//! Declarative deployment spec for `ray apply` (Phase B of the trusted-networks plan).
//!
//! The spec is a read-only description of the *intended* trusted-network state:
//! which networks should exist (and be trusted), and the suggested firewall
//! rules for each. `ray apply` reconciles the live state against it — creating
//! missing networks and publishing suggestions — but never joins or mutates
//! membership directly (B3 only reports the membership gap and offers to mint
//! hostname-bound invites).
//!
//! The spec reuses [`ray_proto::policy::SuggestedFirewall`] verbatim, so the
//! wire/blob shape and the authoring shape are identical: an admin authors the
//! exact rules a node will materialize, keyed by hostname, before any host has
//! joined. TOML is the on-disk format (matching `networks.toml`); the top level
//! is a `networks` table whose keys are network names.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use ray_proto::policy::SuggestedFirewall;
use serde::{Deserialize, Serialize};

/// One network's intended state in a deploy spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    /// Trusted network (coordinator may suggest firewall rules). Currently
    /// always `true` in practice — untrusted networks have nothing to apply —
    /// but kept explicit so the spec is self-describing and a future
    /// trustless field can be added without a format change.
    #[serde(default)]
    pub trusted: bool,
    /// Subject hostname → its suggested rules. Empty means "no suggestions"
    /// (useful with `--prune` to clear an existing set).
    #[serde(default, skip_serializing_if = "SuggestedFirewall::is_empty")]
    pub firewall: SuggestedFirewall,
}

/// The full deploy spec: network name → intended state. A [`BTreeMap`] gives a
/// canonical (sorted) serialization, so two admins authoring the same intent
/// produce byte-identical files.
pub type DeploySpec = BTreeMap<String, NetworkSpec>;

/// Load a deploy spec from a TOML file.
pub fn load(path: &Path) -> Result<DeploySpec> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading spec {}", path.display()))?;
    parse(&contents).with_context(|| format!("parsing spec {}", path.display()))
}

/// Parse a spec from TOML text. The top level is a `[networks]` table; a flat
/// map (no `networks` wrapper) is also accepted for ergonomic single-file use.
/// Unknown fields are rejected so a typo'd key (e.g. `trusted = "yes"` or a
/// misspelled network field) surfaces as an error instead of being silently
/// dropped with defaults.
pub fn parse(toml: &str) -> Result<DeploySpec> {
    // Canonical `[networks]` form (with a wrapper). `deny_unknown_fields` means
    // a flat-shaped input errors here instead of silently yielding an empty map.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wrapper {
        #[serde(default)]
        networks: DeploySpec,
    }
    if let Ok(w) = toml::from_str::<Wrapper>(toml) {
        return Ok(w.networks);
    }
    // Ergonomic flat form: top-level keys are network names.
    toml::from_str::<DeploySpec>(toml).context("expected a [networks] table or a flat map")
}

/// Serialize a spec to TOML (sorted, stable, canonical `[networks.*]` form).
/// Used by `ray apply --dry-run` to echo the normalized intent.
pub fn to_toml(spec: &DeploySpec) -> Result<String> {
    #[derive(Serialize)]
    struct Wrapper<'a> {
        networks: &'a DeploySpec,
    }
    toml::to_string_pretty(&Wrapper { networks: spec }).context("serializing spec")
}

/// The example spec printed by `ray apply --example`.
pub const EXAMPLE_SPEC: &str = r#"# Rayfish deploy spec. See `ray apply --help`.
# Top level is a [networks] table; keys are network names.

[networks.gaming]
trusted = true

# Subject hostname "alice" accepts inbound :22 from "bob" and denies :443
# from "eve", with a catch-all deny on everything else from this network.
[networks.gaming.firewall.alice]
default = "deny"
[networks.gaming.firewall.alice.allows]
bob = "22"
[networks.gaming.firewall.alice.denies]
eve = "443"

[networks.gaming.firewall.bob]
[networks.gaming.firewall.bob.allows]
alice = "9000,8123"
"#;

/// Union of every hostname mentioned in the spec's `firewall:` blocks — both
/// subjects (`self`) and peer hostnames in `allows`/`denies`. This is the set
/// of hosts the spec expects to exist; B3 diffs it against the joined hosts.
pub fn expected_hosts(spec: &DeploySpec) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for net in spec.values() {
        for (subject, rules) in &net.firewall {
            set.insert(subject.clone());
            for peer in rules.allows.keys() {
                set.insert(peer.clone());
            }
            for peer in rules.denies.keys() {
                set.insert(peer.clone());
            }
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ray_proto::policy::HostSuggestions;

    #[test]
    fn parse_networks_wrapper() {
        let toml = r#"
[networks.gaming]
trusted = true

[networks.gaming.firewall.alice]
default = "deny"
allows = { bob = "22" }
"#;
        let spec = parse(toml).unwrap();
        assert_eq!(spec.len(), 1);
        let g = spec.get("gaming").unwrap();
        assert!(g.trusted);
        let alice = g.firewall.get("alice").unwrap();
        assert_eq!(alice.default.as_deref(), Some("deny"));
        assert_eq!(alice.allows.get("bob").map(|s| s.as_str()), Some("22"));
    }

    #[test]
    fn parse_flat_form() {
        let toml = r#"
["gaming"]
trusted = true
"#;
        let spec = parse(toml).unwrap();
        assert!(spec["gaming"].trusted);
        assert!(spec["gaming"].firewall.is_empty());
    }

    #[test]
    fn roundtrip_is_stable_and_sorted() {
        let mut spec = DeploySpec::new();
        let mut fw = SuggestedFirewall::new();
        fw.insert(
            "alice".to_string(),
            HostSuggestions {
                default: Some("deny".to_string()),
                allows: [("bob".to_string(), "22".to_string())].into(),
                denies: [].into(),
            },
        );
        spec.insert(
            "gaming".to_string(),
            NetworkSpec {
                trusted: true,
                firewall: fw,
            },
        );
        spec.insert(
            "admin".to_string(),
            NetworkSpec {
                trusted: true,
                firewall: SuggestedFirewall::new(),
            },
        );
        let s1 = to_toml(&spec).unwrap();
        let s2 = to_toml(&parse(&s1).unwrap()).unwrap();
        assert_eq!(
            s1, s2,
            "roundtrip must be byte-identical (sorted canonical)"
        );
        // Canonical wrapper form.
        assert!(s1.contains("[networks.admin]"));
        assert!(s1.contains("[networks.gaming]"));
        // admin (empty firewall, omitted) sorts before gaming; both present.
        let admin_idx = s1.find("[networks.admin]").unwrap();
        let gaming_idx = s1.find("[networks.gaming]").unwrap();
        assert!(admin_idx < gaming_idx);
    }

    #[test]
    fn empty_firewall_omits_field() {
        let toml = r#"
[networks.gaming]
trusted = true
"#;
        let spec = parse(toml).unwrap();
        // Round-trips without emitting `firewall = {}`.
        let out = to_toml(&spec).unwrap();
        assert!(!out.contains("firewall"));
    }

    #[test]
    fn expected_hosts_collects_subjects_and_peers() {
        let mut spec = DeploySpec::new();
        let mut fw = SuggestedFirewall::new();
        fw.insert(
            "alice".to_string(),
            HostSuggestions {
                default: None,
                allows: [("bob".to_string(), "22".to_string())].into(),
                denies: [("carol".to_string(), "443".to_string())].into(),
            },
        );
        spec.insert(
            "gaming".to_string(),
            NetworkSpec {
                trusted: true,
                firewall: fw,
            },
        );
        let hosts = expected_hosts(&spec);
        assert_eq!(
            hosts,
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        );
    }

    #[test]
    fn invalid_spec_errors() {
        assert!(parse("not = valid = toml").is_err());
        // missing required shape: a value that isn't a NetworkSpec
        assert!(parse("[networks.gaming]\ntrusted = \"yes\"").is_err());
    }

    #[test]
    fn example_spec_parses() {
        // The constant printed by `ray apply --example` must round-trip.
        let spec = parse(EXAMPLE_SPEC).expect("EXAMPLE_SPEC must parse");
        let g = spec.get("gaming").unwrap();
        assert!(g.trusted);
        assert_eq!(g.firewall.len(), 2);
        let alice = g.firewall.get("alice").unwrap();
        assert_eq!(alice.default.as_deref(), Some("deny"));
        assert_eq!(alice.allows.get("bob").map(|s| s.as_str()), Some("22"));
    }
}
