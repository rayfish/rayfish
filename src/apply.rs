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
//! Firewall model: suggestions are additive. An `allows` list opens exactly the
//! listed peers/ports (the node's own inbound default, Deny by default, drops
//! the rest — no catch-all is synthesized); a `denies` list blocks exactly those
//! peers; an empty subject suggests nothing. There is no `default` field.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
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
    /// Optional coordinator-defined name → identity string. An alias names a
    /// *user* (the paired user identity, or a device's transport endpoint id for
    /// an unpaired node), so a firewall rule referencing the alias expands to all
    /// of that user's currently-joined device hostnames. Aliases are spec-only
    /// and expanded client-side at apply time; they never reach the blob. An
    /// alias only resolves for already-joined members (a user has no identity on
    /// the mesh until a device joins/pairs).
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
    /// Optional name → list of members (each an alias name or a literal
    /// hostname). A group is shorthand for a set of hosts that firewall rules can
    /// reference as a subject or peer; it is expanded client-side into concrete
    /// hostnames before publishing. Groups drive firewall rules only, not
    /// membership.
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
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
    let spec = value
        .try_deserialize::<DeploySpec>()
        .context("expected a top-level `networks:` map")?;
    validate_names(&spec)?;
    Ok(spec)
}

/// Structural validation independent of live state: a name may not be defined as
/// both a group and an alias (resolution would be ambiguous).
fn validate_names(spec: &DeploySpec) -> Result<()> {
    for name in spec.groups.keys() {
        anyhow::ensure!(
            !spec.aliases.contains_key(name),
            "`{name}` is defined as both a group and an alias; names must be unique"
        );
    }
    Ok(())
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
#
# Optional `aliases:` and `groups:` are coordinator-side shorthand, expanded
# client-side before publishing (they never reach the network). An alias names a
# user by identity (copy it from `ray identityof <net> <host>`) and expands to
# all of that user's joined device hostnames. A group is a named set of aliases
# and/or literal hostnames. Both can be used as a rule subject or peer. An alias
# only resolves once the user has joined; literal hostnames work pre-join.

aliases:
  # Fill in a real identity, e.g.:
  #   alice: <paste from `ray identityof infra alice-laptop`>
groups:
  admins: [alice, jumpbox]   # `alice` (alias, once defined) + a literal hostname

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
  infra:
    # Every node lets the `admins` group (alice's devices + jumpbox) reach SSH.
    "*":
      allows:
        admins: "tcp:22"
"#;

/// Union of every concrete hostname mentioned in the spec — both subjects and
/// peer hostnames in `allows`/`denies`. This is the set of hosts the spec
/// expects to exist; it is diffed against the joined hosts. The `*` wildcard
/// (subject or peer) is not a real host and is excluded.
pub fn expected_hosts(spec: &DeploySpec) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
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

/// Expand all group/alias references in one network's firewall into a pure,
/// hostname-keyed [`SuggestedFirewall`] ready to publish unchanged.
///
/// `resolve_alias(identity)` returns the hostnames currently joined for that
/// identity *in this network* (the caller builds it from live `Status`). A name
/// used as a subject or peer resolves by precedence: **group → alias → literal
/// hostname** (a name matching no group or alias passes through as itself, so
/// plain-hostname specs behave exactly as before). `*` is never expanded.
///
/// Returns the expanded firewall plus the sorted, unique set of alias names that
/// resolved to zero joined hosts (the caller surfaces these as warnings; their
/// rules simply aren't emitted yet and will materialize on a later apply once the
/// user joins, mirroring how `firewall::materialize_suggestions` skips
/// unresolved peers).
/// Merge a network's stored (node-local `ray alias`) map with a spec's inline
/// `aliases:` map. The spec wins on a name conflict. Both are already canonical
/// (`name -> identity`); the result seeds [`expand_firewall`]. Stored aliases are
/// node-local and never reach the blob, exactly like spec aliases.
pub fn merge_aliases(
    stored: &BTreeMap<String, String>,
    spec: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = stored.clone();
    merged.extend(spec.iter().map(|(k, v)| (k.clone(), v.clone())));
    merged
}

pub fn expand_firewall(
    fw: &SuggestedFirewall,
    aliases: &BTreeMap<String, String>,
    groups: &BTreeMap<String, Vec<String>>,
    resolve_alias: &dyn Fn(&str) -> Vec<String>,
) -> (SuggestedFirewall, Vec<String>) {
    let mut empty_aliases: BTreeSet<String> = BTreeSet::new();

    // Resolve one alias name to its joined hostnames, recording it if empty.
    let mut resolve_one_alias = |name: &str, ident: &str| -> Vec<String> {
        let hosts = resolve_alias(ident);
        if hosts.is_empty() {
            empty_aliases.insert(name.to_string());
        }
        hosts
    };

    // Resolve a subject/peer name to concrete hostnames (or keep `*`).
    let mut resolve_name = |name: &str| -> Vec<String> {
        if name == "*" {
            return vec!["*".to_string()];
        }
        if let Some(members) = groups.get(name) {
            let mut out: Vec<String> = Vec::new();
            for m in members {
                if m == "*" {
                    out.push("*".to_string());
                } else if let Some(ident) = aliases.get(m) {
                    out.extend(resolve_one_alias(m, ident));
                } else {
                    out.push(m.clone()); // literal hostname
                }
            }
            out.sort();
            out.dedup();
            return out;
        }
        if let Some(ident) = aliases.get(name) {
            return resolve_one_alias(name, ident);
        }
        vec![name.to_string()] // literal hostname
    };

    let mut out = SuggestedFirewall::new();
    for (subject, rules) in fw {
        // Expand the peer side once, reused for every concrete subject.
        let mut allows: BTreeMap<String, String> = BTreeMap::new();
        for (peer, spec) in &rules.allows {
            for host in resolve_name(peer) {
                merge_spec(allows.entry(host).or_default(), spec);
            }
        }
        let mut denies: BTreeMap<String, String> = BTreeMap::new();
        for (peer, spec) in &rules.denies {
            for host in resolve_name(peer) {
                merge_spec(denies.entry(host).or_default(), spec);
            }
        }

        for subj in resolve_name(subject) {
            let entry = out.entry(subj).or_default();
            for (peer, spec) in &allows {
                merge_spec(entry.allows.entry(peer.clone()).or_default(), spec);
            }
            for (peer, spec) in &denies {
                merge_spec(entry.denies.entry(peer.clone()).or_default(), spec);
            }
        }
    }

    (out, empty_aliases.into_iter().collect())
}

/// Merge a new comma-separated proto-spec into an existing one, keeping the union
/// of tokens sorted and deduplicated (canonical, so repeated expansions are
/// idempotent). An empty existing value just adopts the new tokens.
fn merge_spec(existing: &mut String, new: &str) {
    let mut tokens: BTreeSet<&str> = existing
        .split(',')
        .chain(new.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();
    *existing = std::mem::take(&mut tokens)
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
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
            ..Default::default()
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
            ..Default::default()
        };
        spec.networks.insert("gaming".to_string(), fw);
        let hosts = expected_hosts(&spec);
        assert_eq!(
            hosts,
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        );
    }

    /// Build a HostSuggestions from (peer, spec) allow pairs.
    fn allows(pairs: &[(&str, &str)]) -> HostSuggestions {
        HostSuggestions {
            allows: pairs
                .iter()
                .map(|(p, s)| (p.to_string(), s.to_string()))
                .collect(),
            denies: BTreeMap::new(),
        }
    }

    #[test]
    fn alias_expands_to_all_user_hostnames() {
        // alias `alice` -> her identity -> all her joined devices.
        let aliases: BTreeMap<String, String> =
            [("alice".to_string(), "id-alice".to_string())].into();
        let groups = BTreeMap::new();
        let resolve = |id: &str| -> Vec<String> {
            if id == "id-alice" {
                vec!["alice-laptop".to_string(), "alice-phone".to_string()]
            } else {
                vec![]
            }
        };
        let mut fw = SuggestedFirewall::new();
        fw.insert("*".to_string(), allows(&[("alice", "tcp:22")]));

        let (out, warnings) = expand_firewall(&fw, &aliases, &groups, &resolve);
        assert!(warnings.is_empty());
        let wild = out.get("*").unwrap();
        assert_eq!(wild.allows.get("alice-laptop").map(String::as_str), Some("tcp:22"));
        assert_eq!(wild.allows.get("alice-phone").map(String::as_str), Some("tcp:22"));
        assert!(!wild.allows.contains_key("alice"), "alias name must not survive");
    }

    #[test]
    fn merge_aliases_spec_overrides_stored() {
        // Stored (node-local `ray alias`) seeds the map; the spec's inline
        // `aliases:` wins on a name conflict and adds new names.
        let stored: BTreeMap<String, String> = [
            ("alice".to_string(), "id-stored-alice".to_string()),
            ("bob".to_string(), "id-bob".to_string()),
        ]
        .into();
        let spec: BTreeMap<String, String> =
            [("alice".to_string(), "id-spec-alice".to_string())].into();
        let merged = merge_aliases(&stored, &spec);
        assert_eq!(merged.get("alice").map(String::as_str), Some("id-spec-alice"));
        assert_eq!(merged.get("bob").map(String::as_str), Some("id-bob"));
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn stored_alias_resolves_when_spec_omits_it() {
        // A spec rule references `alice` but declares no `aliases:`; the stored
        // alias seeds it and the rule expands to alice's joined hosts.
        let merged = merge_aliases(
            &[("alice".to_string(), "id-alice".to_string())].into(),
            &BTreeMap::new(),
        );
        let groups = BTreeMap::new();
        let resolve = |id: &str| -> Vec<String> {
            if id == "id-alice" {
                vec!["alice-laptop".to_string()]
            } else {
                vec![]
            }
        };
        let mut fw = SuggestedFirewall::new();
        fw.insert("*".to_string(), allows(&[("alice", "tcp:22")]));
        let (out, warnings) = expand_firewall(&fw, &merged, &groups, &resolve);
        assert!(warnings.is_empty());
        let wild = out.get("*").unwrap();
        assert_eq!(wild.allows.get("alice-laptop").map(String::as_str), Some("tcp:22"));
        assert!(!wild.allows.contains_key("alice"));
    }

    #[test]
    fn group_as_peer_expands_aliases_and_literals() {
        let aliases: BTreeMap<String, String> =
            [("alice".to_string(), "id-alice".to_string())].into();
        let groups: BTreeMap<String, Vec<String>> = [(
            "admins".to_string(),
            vec!["alice".to_string(), "bob-server".to_string()],
        )]
        .into();
        let resolve = |id: &str| -> Vec<String> {
            if id == "id-alice" {
                vec!["alice-laptop".to_string()]
            } else {
                vec![]
            }
        };
        let mut fw = SuggestedFirewall::new();
        fw.insert("*".to_string(), allows(&[("admins", "tcp:22")]));

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve);
        let wild = out.get("*").unwrap();
        assert_eq!(wild.allows.get("alice-laptop").map(String::as_str), Some("tcp:22"));
        assert_eq!(wild.allows.get("bob-server").map(String::as_str), Some("tcp:22"));
        assert!(!wild.allows.contains_key("admins"));
    }

    #[test]
    fn group_as_subject_expands_to_each_member() {
        let aliases = BTreeMap::new();
        let groups: BTreeMap<String, Vec<String>> = [(
            "webservers".to_string(),
            vec!["web1".to_string(), "web2".to_string()],
        )]
        .into();
        let resolve = |_: &str| -> Vec<String> { vec![] };
        let mut fw = SuggestedFirewall::new();
        fw.insert("webservers".to_string(), allows(&[("*", "tcp:80")]));

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve);
        assert!(!out.contains_key("webservers"));
        assert_eq!(out.get("web1").unwrap().allows.get("*").map(String::as_str), Some("tcp:80"));
        assert_eq!(out.get("web2").unwrap().allows.get("*").map(String::as_str), Some("tcp:80"));
    }

    #[test]
    fn colliding_peer_specs_merge_and_dedup() {
        // `admins` and `alice` both resolve to alice-laptop with different ports;
        // the two allow specs merge into one comma-joined, deduped token list.
        let aliases: BTreeMap<String, String> =
            [("alice".to_string(), "id-alice".to_string())].into();
        let groups: BTreeMap<String, Vec<String>> =
            [("admins".to_string(), vec!["alice".to_string()])].into();
        let resolve = |id: &str| -> Vec<String> {
            if id == "id-alice" {
                vec!["alice-laptop".to_string()]
            } else {
                vec![]
            }
        };
        let mut fw = SuggestedFirewall::new();
        fw.insert(
            "*".to_string(),
            allows(&[("admins", "tcp:22"), ("alice", "tcp:80")]),
        );

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve);
        let merged = out.get("*").unwrap().allows.get("alice-laptop").unwrap();
        assert_eq!(merged, "tcp:22,tcp:80", "specs must merge sorted+deduped");
    }

    #[test]
    fn wildcards_pass_through_untouched() {
        let aliases = BTreeMap::new();
        let groups = BTreeMap::new();
        let resolve = |_: &str| -> Vec<String> { vec![] };
        let mut fw = SuggestedFirewall::new();
        fw.insert("*".to_string(), allows(&[("*", "tcp:6969")]));

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve);
        assert_eq!(out.get("*").unwrap().allows.get("*").map(String::as_str), Some("tcp:6969"));
    }

    #[test]
    fn unknown_name_passes_through_as_literal() {
        let aliases = BTreeMap::new();
        let groups = BTreeMap::new();
        let resolve = |_: &str| -> Vec<String> { vec![] };
        let mut fw = SuggestedFirewall::new();
        fw.insert("jumpbox".to_string(), allows(&[("monitor", "tcp:9100")]));

        let (out, warnings) = expand_firewall(&fw, &aliases, &groups, &resolve);
        assert!(warnings.is_empty());
        assert_eq!(
            out.get("jumpbox").unwrap().allows.get("monitor").map(String::as_str),
            Some("tcp:9100")
        );
    }

    #[test]
    fn alias_resolving_to_zero_hosts_warns_and_emits_nothing() {
        let aliases: BTreeMap<String, String> =
            [("ghost".to_string(), "id-ghost".to_string())].into();
        let groups = BTreeMap::new();
        let resolve = |_: &str| -> Vec<String> { vec![] }; // never joined
        let mut fw = SuggestedFirewall::new();
        fw.insert("*".to_string(), allows(&[("ghost", "tcp:22")]));

        let (out, warnings) = expand_firewall(&fw, &aliases, &groups, &resolve);
        assert_eq!(warnings, vec!["ghost".to_string()]);
        assert!(out.get("*").unwrap().allows.is_empty(), "no rule for an unjoined alias");
    }

    #[test]
    fn group_and_alias_name_collision_errors() {
        let yaml = r#"
aliases:
  admins: someidentitystring
groups:
  admins: [alice]
networks:
  prod: {}
"#;
        let err = parse(yaml).unwrap_err().to_string();
        assert!(err.contains("admins"), "collision must name the offending key: {err}");
    }

    #[test]
    fn aliases_and_groups_parse() {
        let yaml = r#"
aliases:
  alice: someidentitystring
groups:
  admins: [alice, bob-server]
networks:
  prod:
    "*":
      allows:
        admins: "tcp:22"
"#;
        let spec = parse(yaml).unwrap();
        assert_eq!(spec.aliases.get("alice").map(String::as_str), Some("someidentitystring"));
        assert_eq!(spec.groups.get("admins").unwrap().len(), 2);
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
        assert_eq!(
            mc.get("*").unwrap().allows.get("*").map(|s| s.as_str()),
            Some("tcp:6969")
        );
    }
}
