//! Declarative deployment spec for `ray apply`.
//!
//! The spec is a read-only description of the *intended* network state: which
//! networks should exist and the suggested firewall rules for each. `ray apply`
//! reconciles the live state against it — creating missing (closed) networks and
//! publishing suggestions — but never joins or mutates membership directly (it
//! only reports the membership gap and offers to mint hostname-bound invites).
//!
//! The spec reuses [`ray_proto::policy::SuggestedFirewall`] verbatim, so the
//! wire/blob shape and the authoring shape are identical: an admin authors the
//! exact rules a node will materialize, keyed by hostname, before any host has
//! joined. A `*` subject targets every node, and a `*` peer in `allows`/`denies`
//! means any peer — so "everyone opens 6969 to anyone" is one line. Specs are
//! **YAML only** (most readable); output (`--dry-run`, `--example`) is YAML too.
//!
//! Firewall model: if a subject has an `allows` list, only those peers pass
//! (a network-scoped catch-all deny is appended); a subject with only `denies`
//! is a blacklist (rest allowed); an empty subject is fully open. There is no
//! `default` field — the mode is inferred from which list is non-empty.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use ray_proto::policy::SuggestedFirewall;
use serde::{Deserialize, Serialize};

/// The full deploy spec: a `networks:` map of network name → its suggested
/// firewall (subject hostname → rules), with no `firewall:` indirection.
/// Suggestions are advisory on every network; each node queues or auto-accepts
/// them per its own `--auto-accept-firewall` choice. The [`BTreeMap`] gives a
/// canonical (sorted) serialization, so two admins authoring the same intent
/// produce byte-identical files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploySpec {
    /// Network name → its suggested firewall (subject hostname → rules). A bare
    /// [`SuggestedFirewall`], reused verbatim from `ray_proto::policy`.
    #[serde(default)]
    pub networks: BTreeMap<String, SuggestedFirewall>,
}

/// Load a deploy spec from a YAML file (`.yaml`/`.yml` only). The top level is a
/// `networks:` map. Unknown fields error.
pub fn load(path: &Path) -> Result<DeploySpec> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    anyhow::ensure!(
        matches!(ext.as_str(), "yaml" | "yml"),
        "ray apply specs must be YAML (.yaml/.yml): {}",
        path.display()
    );
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading spec {}", path.display()))?;
    let cfg = config::Config::builder()
        .add_source(config::File::from_str(&text, config::FileFormat::Yaml))
        .build()
        .with_context(|| format!("parsing spec {}", path.display()))?;
    deserialize_spec(cfg)
}

/// Deserialize the top-level `{ networks }` table.
fn deserialize_spec(cfg: config::Config) -> Result<DeploySpec> {
    // The `config` crate represents YAML `null` (e.g. an empty `beta:` subject) as
    // `ValueKind::Nil`. serde can't turn a present-but-Nil value into a struct
    // — field-level `#[serde(default)]` only fires for *absent* keys — so an
    // empty subject would error ("invalid type: null, expected struct").
    // Normalize Nil → empty Table first: in this spec a null always means
    // "default/empty" (an open subject).
    let mut value: config::Value = cfg.try_deserialize().context("reading config tree")?;
    normalize_nil(&mut value);
    value
        .try_deserialize::<DeploySpec>()
        .context("expected a top-level `networks:` map")
}

/// Recursively replace `ValueKind::Nil` with an empty `Table` so a null
/// (YAML `key:` with no value) deserializes as a default struct.
fn normalize_nil(v: &mut config::Value) {
    use config::ValueKind;
    match &mut v.kind {
        ValueKind::Nil => {
            v.kind = ValueKind::Table(config::Map::new());
        }
        ValueKind::Table(t) => {
            for (_k, child) in t.iter_mut() {
                normalize_nil(child);
            }
        }
        ValueKind::Array(a) => {
            for child in a.iter_mut() {
                normalize_nil(child);
            }
        }
        _ => {}
    }
}

/// Serialize a spec to YAML (sorted, stable, canonical). Used by `ray apply
/// --dry-run` to echo the normalized intent.
pub fn to_yaml(spec: &DeploySpec) -> Result<String> {
    serde_yml::to_string(spec).context("serializing spec to YAML")
}

/// The example spec printed by `ray apply --example` (YAML).
pub const EXAMPLE_SPEC: &str = r#"# Rayfish deploy spec. See `ray apply --help`.
# Under `networks:`, each network name maps directly to its firewall subjects.
# Save as e.g. deploy.yaml and run: ray apply deploy.yaml  (YAML only).
#
# Subject/peer keys are HOSTNAMES. They are the names `ray apply
# --invite-missing` binds into invites — a node joining with such an invite is
# assigned that exact hostname (it cannot pick another), so the firewall always
# resolves the peer it names. The `*` subject targets every node, and a `*` peer
# means any peer. Suggestions are advisory: each node queues them for
# `ray firewall accept`, or auto-installs them if it joined with
# `--auto-accept-firewall`.

networks:
  gaming:
    # alice has an allow-list ⇒ only listed peers pass, rest denied.
    alice:
      allows:
        bob: "tcp:22"
      denies:
        eve: "icmp"
    # bob's allow-list uses comma-separated proto:ports tokens.
    bob:
      allows:
        alice: "tcp:9000,tcp:8123"
    # An empty subject is fully open (no rules materialized).
    carol: {}
  minecraft:
    # Every node opens 6969 to any peer — one wildcard rule for the whole net.
    "*":
      allows:
        "*": "tcp:6969"
"#;

/// Union of every concrete hostname mentioned in the spec — both subjects and
/// peer hostnames in `allows`/`denies`. This is the set of hosts the spec
/// expects to exist; it is diffed against the joined hosts. The `*` wildcard
/// (subject or peer) is not a real host and is excluded.
pub fn expected_hosts(spec: &DeploySpec) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for firewall in spec.networks.values() {
        for (subject, rules) in firewall {
            if subject != "*" {
                set.insert(subject.clone());
            }
            for peer in rules.allows.keys().chain(rules.denies.keys()) {
                if peer != "*" {
                    set.insert(peer.clone());
                }
            }
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ray_proto::policy::HostSuggestions;

    /// Parse a spec from YAML text. The top level is a `networks:` map. Unknown
    /// fields are rejected so a typo'd key surfaces as an error instead of being
    /// silently dropped with defaults.
    fn parse(text: &str) -> Result<DeploySpec> {
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(text, config::FileFormat::Yaml))
            .build()
            .context("building config")?;
        deserialize_spec(cfg)
    }

    #[test]
    fn parse_yaml() {
        let yaml = r#"
networks:
  gaming:
    alice:
      allows:
        bob: "tcp:22"
"#;
        let spec = parse(yaml).unwrap();
        assert_eq!(spec.networks.len(), 1);
        let g = spec.networks.get("gaming").unwrap();
        let alice = g.get("alice").unwrap();
        assert_eq!(alice.allows.get("bob").map(|s| s.as_str()), Some("tcp:22"));
    }

    #[test]
    fn parse_yaml_empty_networks() {
        // A file may create networks with no firewall blocks.
        // Note: the `config` crate lowercases keys, so spec network/host names should be
        // lowercase (rayfish hostnames are generated lowercase).
        let yaml = r#"
networks:
  neta:
  netb:
"#;
        let spec = parse(yaml).unwrap();
        assert_eq!(spec.networks.len(), 2);
        assert!(spec.networks.get("neta").unwrap().is_empty());
    }

    #[test]
    fn parse_yaml_null_subject_is_open() {
        // A subject written as `beta:` (YAML null) means "empty / fully open".
        // Must deserialize to a default HostSuggestions, not error.
        let yaml = r#"
networks:
  net1:
    beta:
    gamma:
"#;
        let spec = parse(yaml).unwrap();
        let g = spec.networks.get("net1").unwrap();
        assert_eq!(g.len(), 2);
        assert!(g.get("beta").unwrap().allows.is_empty());
        assert!(g.get("gamma").unwrap().allows.is_empty());
    }

    #[test]
    fn parse_yaml_wildcard_subject_and_peer() {
        // The Minecraft case: `*` subject + `*` peer must parse and round-trip.
        let yaml = r#"
networks:
  minecraft:
    "*":
      allows:
        "*": "tcp:6969"
"#;
        let spec = parse(yaml).unwrap();
        let mc = spec.networks.get("minecraft").unwrap();
        let wild = mc.get("*").expect("`*` subject must parse");
        assert_eq!(wild.allows.get("*").map(|s| s.as_str()), Some("tcp:6969"));
        // And it round-trips through YAML byte-for-byte.
        let s1 = to_yaml(&spec).unwrap();
        let s2 = to_yaml(&parse(&s1).unwrap()).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn load_requires_yaml_extension() {
        // `ray apply` is YAML-only: a .toml/.json path is rejected up front.
        let dir = std::env::temp_dir().join(format!("rayfish-apply-ext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join("spec.toml");
        std::fs::write(&toml_path, "networks = {}\n").unwrap();
        let err = load(&toml_path).unwrap_err().to_string();
        assert!(err.contains("YAML"), "{err}");
        // A .yaml file with the same intent loads fine.
        let yaml_path = dir.join("spec.yaml");
        std::fs::write(&yaml_path, "networks:\n  gaming:\n").unwrap();
        let spec = load(&yaml_path).unwrap();
        assert!(spec.networks.contains_key("gaming"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrip_yaml_is_stable_and_sorted() {
        let mut fw = SuggestedFirewall::new();
        fw.insert(
            "alice".to_string(),
            HostSuggestions {
                allows: [("bob".to_string(), "tcp:22".to_string())].into(),
                denies: [].into(),
            },
        );
        let mut spec = DeploySpec {
            networks: BTreeMap::new(),
        };
        spec.networks.insert("gaming".to_string(), fw);
        spec.networks
            .insert("admin".to_string(), SuggestedFirewall::new());
        let s1 = to_yaml(&spec).unwrap();
        let s2 = to_yaml(&parse(&s1).unwrap()).unwrap();
        assert_eq!(
            s1, s2,
            "roundtrip must be byte-identical (sorted canonical)"
        );
        // admin (empty firewall) sorts before gaming; both present.
        let admin_idx = s1.find("admin:").unwrap();
        let gaming_idx = s1.find("gaming:").unwrap();
        assert!(admin_idx < gaming_idx);
    }

    #[test]
    fn expected_hosts_collects_subjects_and_peers_skipping_wildcard() {
        let mut fw = SuggestedFirewall::new();
        fw.insert(
            "alice".to_string(),
            HostSuggestions {
                allows: [("bob".to_string(), "tcp:22".to_string())].into(),
                denies: [("carol".to_string(), "icmp".to_string())].into(),
            },
        );
        // A wildcard subject + wildcard peer must NOT appear as expected hosts.
        fw.insert(
            "*".to_string(),
            HostSuggestions {
                allows: [("*".to_string(), "tcp:6969".to_string())].into(),
                denies: [].into(),
            },
        );
        let mut spec = DeploySpec {
            networks: BTreeMap::new(),
        };
        spec.networks.insert("gaming".to_string(), fw);
        let hosts = expected_hosts(&spec);
        assert_eq!(
            hosts,
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        );
    }

    #[test]
    fn old_file_level_trusted_field_errors() {
        // Hard-cut: the removed file-level `trusted:` flag is now an unknown key.
        let yaml = r#"
trusted: true
networks:
  gaming:
    alice:
      allows:
        bob: "tcp:22"
"#;
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn old_per_network_format_errors() {
        // Hard-cut: the old shape (per-network `trusted` + `firewall:` wrapper)
        // is no longer accepted. `trusted`/`firewall` are unknown network keys.
        let yaml = r#"
networks:
  gaming:
    trusted: true
    firewall:
      alice:
        allows:
          bob: "tcp:22"
"#;
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn unknown_top_level_field_errors() {
        let yaml = r#"
bogus: 1
networks: {}
"#;
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn invalid_yaml_errors() {
        assert!(parse("key: [unclosed").is_err());
    }

    #[test]
    fn example_spec_parses() {
        // The constant printed by `ray apply --example` must round-trip.
        let spec = parse(EXAMPLE_SPEC).expect("EXAMPLE_SPEC must parse");
        let g = spec.networks.get("gaming").unwrap();
        assert_eq!(g.len(), 3);
        let alice = g.get("alice").unwrap();
        assert_eq!(alice.allows.get("bob").map(|s| s.as_str()), Some("tcp:22"));
        // carol is an empty subject → fully open.
        assert!(g.get("carol").unwrap().allows.is_empty());
        // The minecraft network demonstrates the wildcard.
        let mc = spec.networks.get("minecraft").unwrap();
        assert_eq!(mc.get("*").unwrap().allows.get("*").map(|s| s.as_str()), Some("tcp:6969"));
    }
}
