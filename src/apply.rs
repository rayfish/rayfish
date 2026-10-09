//! Declarative deployment spec for `ray apply`.
//!
//! The spec is a read-only description of the *intended* network state: which
//! networks should exist and the suggested firewall rules for each. `ray apply`
//! reconciles the live state against it: creating missing closed networks,
//! publishing suggestions, and asking enrolled machines to join or leave from
//! the per-network hostname diff.
//!
//! Firewall rules are published as suggestions; SSH grants are sent directly
//! to enrolled controlled machines. Both are keyed by hostname. A `*` subject
//! targets every node, and a `*` peer means any peer. A `*-host-a,host-b`
//! subject targets every current or explicitly declared host except those hosts;
//! in `allows`, it means any peer except those hosts. Exclusion groups and
//! aliases expand to joined hostnames when applied. Reapply after new hosts join
//! to update target exclusions. Specs and their output (`--dry-run`, `--example`)
//! use YAML.
//!
//! Firewall model: suggestions are additive. An `allows` list opens exactly the
//! listed peers/ports (the node's own inbound default, Deny by default, drops
//! the rest, no catch-all is synthesized); a `denies` list blocks exactly those
//! peers; an empty subject suggests nothing. There is no `default` field.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::collections::btree_map::Entry;
use std::iter::once;
use std::path::Path;

use anyhow::{Context, Result};
use ray_proto::ipc::MachineHostname;
use ray_proto::policy::{HostSuggestions, SuggestedFirewall};
use serde::{Deserialize, Serialize};

/// The full deploy spec: a `networks:` map of network name to target hostname
/// to rules. Firewall suggestions are advisory; SSH grants require enrollment
/// and are installed directly on controlled targets. The [`BTreeMap`] gives a
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
    /// Network name to target hostname to firewall and SSH rules.
    #[serde(default)]
    pub networks: BTreeMap<String, DeployNetwork>,
}

/// Rules for one target host. SSH grants name connecting peers and the local
/// accounts they may use. An empty account list permits any non-root account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployHost {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allows: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub denies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ssh: BTreeMap<String, Vec<String>>,
}

#[cfg(test)]
impl From<HostSuggestions> for DeployHost {
    fn from(value: HostSuggestions) -> Self {
        Self {
            allows: value.allows,
            denies: value.denies,
            ssh: BTreeMap::new(),
        }
    }
}

impl DeployHost {
    fn firewall(&self) -> HostSuggestions {
        HostSuggestions {
            allows: self.allows.clone(),
            denies: self.denies.clone(),
        }
    }
}

pub type DeployNetwork = BTreeMap<String, DeployHost>;

pub fn suggested_firewall(network: &DeployNetwork) -> SuggestedFirewall {
    network
        .iter()
        .map(|(host, rules)| (host.clone(), rules.firewall()))
        .collect()
}

pub fn ssh_grants_for_host(network: &DeployNetwork, host: &str) -> BTreeMap<String, Vec<String>> {
    let mut grants = network
        .get("*")
        .map(|rules| rules.ssh.clone())
        .unwrap_or_default();
    if let Some(rules) = network.get(host) {
        for (peer, users) in &rules.ssh {
            add_ssh_grant(&mut grants, peer.clone(), users);
        }
    }
    grants
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
    // (field-level `#[serde(default)]` only fires for *absent* keys) so an
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
    for firewall in spec.networks.values() {
        for (subject, rules) in firewall {
            for peer in once(subject).chain(rules.allows.keys()) {
                if let Some(exclusions) = crate::firewall::parse_excluded_peer_terms(peer)? {
                    for name in exclusions {
                        if let Some(members) = spec.groups.get(name) {
                            anyhow::ensure!(
                                !members.is_empty(),
                                "excluded group '{name}' is empty"
                            );
                            for member in members {
                                anyhow::ensure!(
                                    member != "*" && !spec.groups.contains_key(member),
                                    "excluded group '{name}' must contain aliases or hostnames"
                                );
                                if !spec.aliases.contains_key(member) {
                                    member.parse::<MachineHostname>().with_context(|| {
                                        format!(
                                            "invalid hostname '{member}' in excluded group '{name}'"
                                        )
                                    })?;
                                }
                            }
                        } else if !spec.aliases.contains_key(name) {
                            name.parse::<MachineHostname>().with_context(|| {
                                format!("invalid excluded peer '{name}' in '{peer}'")
                            })?;
                        }
                    }
                }
            }
            for peer in rules.denies.keys() {
                anyhow::ensure!(
                    crate::firewall::parse_excluded_peer_terms(peer)?.is_none(),
                    "excluded-peer selector '{peer}' is only valid in allows"
                );
            }
            for (peer, users) in &rules.ssh {
                anyhow::ensure!(
                    crate::firewall::parse_excluded_peer_terms(peer)?.is_none(),
                    "excluded-peer selector '{peer}' is not valid in ssh"
                );
                anyhow::ensure!(
                    users.iter().all(|user| !user.is_empty()),
                    "ssh login users cannot be empty strings"
                );
            }
        }
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
            for child in t.values_mut() {
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
# means any peer. In `allows`, `*-host-a,admins` means any peer except the named
# host and group. An alias in an exclusion needs a joined device at apply time.
# Paired devices share a firewall identity, so excluding one also
# excludes its user's other devices as peers. As a target, `*-admins` selects
# current and explicitly declared hosts except that group's hosts. Reapply after
# new hosts join. Other matching target blocks still add their rules.
# Suggestions are advisory: each node queues
# them for `ray firewall accept`, or auto-installs them if it joined with
# `--auto-accept-firewall`.
#
# Optional `aliases:` and `groups:` are coordinator-side shorthand, expanded
# client-side before publishing (they never reach the network). An alias names a
# user by identity (copy it from `ray identityof <host>`) and expands to
# all of that user's joined device hostnames. A group is a named set of aliases
# and/or literal hostnames. Both can be used as a rule subject or peer. An alias
# only resolves once the user has joined; literal hostnames work pre-join.

aliases:
  # Fill in a real identity, e.g.:
  #   alice: <paste from `ray identityof <host>`>
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
    # On a controlled host, `ssh` enables mesh SSH and grants login to peers.
    # The list names local login accounts; [] means any non-root account.
    jumpbox:
      ssh:
        alice: [deploy]
"#;

/// Union of every concrete hostname mentioned in the spec, both subjects and
/// peer hostnames in `allows`/`denies`. The `*` wildcard (subject or peer) is
/// not a real host and is excluded. Test-only: apply diffs per network through
/// [`expected_hosts_for_network`].
#[cfg(test)]
fn expected_hosts(spec: &DeploySpec) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for firewall in spec.networks.values() {
        set.extend(expected_hosts_for_network(firewall));
    }
    set.into_iter().collect()
}

/// Concrete hostnames expected on one network. Wildcards are excluded; the
/// apply reconciler expands them against the live roster before taking a diff.
pub fn expected_hosts_for_network(firewall: &DeployNetwork) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (subject, rules) in firewall {
        if subject != "*" && !subject.starts_with("*-") {
            set.insert(subject.clone());
        }
        for peer in rules
            .allows
            .keys()
            .chain(rules.denies.keys())
            .chain(rules.ssh.keys())
        {
            if peer != "*" && !peer.starts_with("*-") {
                set.insert(peer.clone());
            }
        }
    }
    set
}

/// Managed-machine joins and leaves needed to reach the desired membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipDiff {
    /// Hostnames absent from the live roster.
    pub joins: Vec<MachineHostname>,
    /// Hostnames present in the live roster but absent from the spec.
    pub leaves: Vec<MachineHostname>,
}

/// Compare one network's live roster with the concrete hostnames named by its
/// new spec. Wildcards are policy selectors, not membership declarations.
pub fn membership_diff(
    firewall: &DeployNetwork,
    current: &HashSet<MachineHostname>,
) -> Result<MembershipDiff> {
    let desired: HashSet<MachineHostname> = expected_hosts_for_network(firewall)
        .into_iter()
        .map(|hostname| {
            hostname
                .parse()
                .with_context(|| format!("invalid hostname '{hostname}' in deploy spec"))
        })
        .collect::<Result<_>>()?;
    let mut joins: Vec<MachineHostname> = desired.difference(current).cloned().collect();
    let mut leaves: Vec<MachineHostname> = current.difference(&desired).cloned().collect();
    joins.sort();
    leaves.sort();
    Ok(MembershipDiff { joins, leaves })
}

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

/// Expand all group/alias references in one network's firewall into a pure,
/// hostname-keyed deploy rules ready to publish or send to controlled hosts.
///
/// `resolve_alias(identity)` returns the hostnames currently joined for that
/// identity *in this network* (the caller builds it from live `Status`). A name
/// used as a subject or peer resolves by precedence: **group, alias, then literal
/// hostname** (a name matching no group or alias passes through as itself, so
/// plain-hostname specs behave exactly as before). `*` is never expanded.
///
/// Returns the expanded firewall plus the sorted, unique set of alias names that
/// resolved to zero joined hosts (the caller surfaces these as warnings; their
/// rules simply aren't emitted yet and will materialize on a later apply once the
/// user joins, mirroring how `firewall::materialize_suggestions` skips
/// unresolved peers).
///
/// Target exclusions expand against `current` and explicit spec hosts. Empty
/// entries preserve membership and clear prior suggestions on excluded targets.
/// Excluded aliases with no joined devices return an error.
pub fn expand_firewall(
    fw: &DeployNetwork,
    aliases: &BTreeMap<String, String>,
    groups: &BTreeMap<String, Vec<String>>,
    resolve_alias: &dyn Fn(&str) -> Vec<String>,
    current: &HashSet<MachineHostname>,
) -> Result<(DeployNetwork, Vec<String>)> {
    let mut empty_aliases: BTreeSet<String> = BTreeSet::new();

    // Resolve one alias name to its joined hostnames, recording it if empty.
    let mut resolve_one_alias = |name: &str, ident: &str| -> Vec<String> {
        let hosts = resolve_alias(ident);
        if hosts.is_empty() {
            empty_aliases.insert(name.to_string());
        }
        hosts
    };

    let expand_exclusion = |selector: &str| -> Result<String> {
        let exclusions = crate::firewall::parse_excluded_peer_terms(selector)?
            .context("expected excluded-peer selector")?;
        let mut hosts = BTreeSet::new();
        // An alias expands to its joined devices; anything else is a literal
        // hostname.
        let mut add = |name: &str| -> Result<()> {
            if let Some(identity) = aliases.get(name) {
                let joined = resolve_alias(identity);
                anyhow::ensure!(
                    !joined.is_empty(),
                    "excluded alias '{name}' has no joined devices"
                );
                hosts.extend(joined);
            } else {
                hosts.insert(name.to_string());
            }
            Ok(())
        };
        for name in exclusions {
            if let Some(members) = groups.get(name) {
                for member in members {
                    add(member)?;
                }
            } else {
                add(name)?;
            }
        }
        anyhow::ensure!(
            !hosts.is_empty(),
            "excluded-peer selector '{selector}' is empty"
        );
        let expanded = format!("*-{}", hosts.into_iter().collect::<Vec<_>>().join(","));
        crate::firewall::parse_excluded_peers(&expanded)?;
        Ok(expanded)
    };

    // Resolve a subject/peer name to concrete hostnames (or keep `*`).
    let mut resolve_name = |name: &str| -> Vec<String> {
        if name == "*" {
            return vec![name.to_string()];
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

    let has_target_exclusions = fw.keys().any(|subject| subject.starts_with("*-"));
    let mut targets = BTreeSet::new();
    let mut out = DeployNetwork::new();
    if has_target_exclusions {
        targets.extend(current.iter().map(ToString::to_string));
        for name in expected_hosts_for_network(fw) {
            targets.extend(resolve_name(&name));
        }
        targets.remove("*");
        // Keep excluded hosts enrolled, and replace their previous suggestions.
        out.insert("*".to_string(), DeployHost::default());
        for host in &targets {
            out.insert(host.clone(), DeployHost::default());
        }
    }
    for (subject, rules) in fw {
        // Expand the peer side once, reused for every concrete subject.
        let mut allows: BTreeMap<String, String> = BTreeMap::new();
        for (peer, spec) in &rules.allows {
            let names = if peer.starts_with("*-") {
                vec![expand_exclusion(peer)?]
            } else {
                resolve_name(peer)
            };
            for host in names {
                merge_spec(allows.entry(host).or_default(), spec);
            }
        }
        let mut denies: BTreeMap<String, String> = BTreeMap::new();
        for (peer, spec) in &rules.denies {
            for host in resolve_name(peer) {
                merge_spec(denies.entry(host).or_default(), spec);
            }
        }
        let mut ssh: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (peer, users) in &rules.ssh {
            for host in resolve_name(peer) {
                add_ssh_grant(&mut ssh, host, users);
            }
        }

        let subjects = if subject.starts_with("*-") {
            let exclusion = expand_exclusion(subject)?;
            let excluded: BTreeSet<_> = exclusion[2..].split(',').collect();
            targets
                .iter()
                .filter(|host| !excluded.contains(host.as_str()))
                .cloned()
                .collect()
        } else {
            resolve_name(subject)
        };
        for subj in subjects {
            let entry = out.entry(subj).or_default();
            for (peer, spec) in &allows {
                merge_spec(entry.allows.entry(peer.clone()).or_default(), spec);
            }
            for (peer, spec) in &denies {
                merge_spec(entry.denies.entry(peer.clone()).or_default(), spec);
            }
            for (peer, users) in &ssh {
                add_ssh_grant(&mut entry.ssh, peer.clone(), users);
            }
        }
    }

    Ok((out, empty_aliases.into_iter().collect()))
}

/// Add one peer's ssh grant to `grants`. A new peer takes `users` as given: an
/// empty list there means any non-root account, so it must not go through
/// [`merge_ssh_users`] against an empty existing list.
fn add_ssh_grant(grants: &mut BTreeMap<String, Vec<String>>, peer: String, users: &[String]) {
    match grants.entry(peer) {
        Entry::Vacant(entry) => {
            entry.insert(users.to_vec());
        }
        Entry::Occupied(mut entry) => merge_ssh_users(entry.get_mut(), users),
    }
}

fn merge_ssh_users(existing: &mut Vec<String>, new: &[String]) {
    if existing.iter().chain(new).any(|user| user == "*") {
        *existing = vec!["*".to_string()];
    } else if existing.is_empty() || new.is_empty() {
        existing.clear();
    } else {
        *existing = existing
            .iter()
            .chain(new)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
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
    fn ssh_grants_expand_and_do_not_enter_firewall_suggestions() {
        let spec = parse(
            "groups:\n  admins: [laptop, phone]\nnetworks:\n  infra:\n    server:\n      ssh:\n        admins: [deploy]\n",
        )
        .unwrap();
        let network = &spec.networks["infra"];
        assert_eq!(
            expected_hosts_for_network(network),
            ["server", "admins"].into_iter().map(String::from).collect()
        );
        let (expanded, warnings) = expand_firewall(
            network,
            &BTreeMap::new(),
            &spec.groups,
            &|_| Vec::new(),
            &HashSet::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(expanded["server"].ssh["laptop"], ["deploy"]);
        assert_eq!(expanded["server"].ssh["phone"], ["deploy"]);
        assert!(suggested_firewall(&expanded)["server"].allows.is_empty());
        assert_eq!(parse(&to_yaml(&spec).unwrap()).unwrap(), spec);
    }

    #[test]
    fn ssh_grants_reject_excluded_peer_selectors() {
        assert!(
            parse("networks:\n  infra:\n    server:\n      ssh:\n        '*-peer': [deploy]\n")
                .is_err()
        );
    }

    #[test]
    fn overlapping_ssh_groups_keep_both_named_accounts() {
        let spec = parse(
            "groups:\n  admins: [laptop]\n  operators: [laptop]\nnetworks:\n  infra:\n    server:\n      ssh:\n        admins: [deploy]\n        operators: [audit]\n",
        )
        .unwrap();
        let (expanded, _) = expand_firewall(
            &spec.networks["infra"],
            &BTreeMap::new(),
            &spec.groups,
            &|_| Vec::new(),
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(expanded["server"].ssh["laptop"], ["audit", "deploy"]);
    }

    #[test]
    fn wildcard_and_host_ssh_grants_combine_accounts() {
        let spec = parse(
            "networks:\n  infra:\n    '*':\n      ssh:\n        laptop: [deploy]\n    server:\n      ssh:\n        laptop: [audit]\n",
        )
        .unwrap();
        assert_eq!(
            ssh_grants_for_host(&spec.networks["infra"], "server")["laptop"],
            ["audit", "deploy"]
        );
    }

    #[test]
    fn excluded_peer_selector_survives_expansion_without_declaring_membership() {
        let spec = parse(
            r#"
networks:
  sample-net:
    target-host:
      allows:
        "*-a,b,c": "tcp:12345,tcp:23456"
"#,
        )
        .unwrap();
        let firewall = &spec.networks["sample-net"];
        assert_eq!(
            expected_hosts_for_network(firewall),
            ["target-host".to_string()].into()
        );
        let current = ["target-host", "a", "new-peer"]
            .into_iter()
            .map(|host| host.parse().unwrap())
            .collect();
        let diff = membership_diff(firewall, &current).unwrap();
        assert!(diff.joins.is_empty());
        assert_eq!(
            diff.leaves,
            ["a", "new-peer"]
                .into_iter()
                .map(|host| host.parse().unwrap())
                .collect::<Vec<_>>()
        );
        let (expanded, warnings) = expand_firewall(
            firewall,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &|_| Vec::new(),
            &HashSet::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(
            expanded["target-host"].allows["*-a,b,c"],
            "tcp:12345,tcp:23456"
        );
    }

    #[test]
    fn malformed_or_denied_excluded_peer_selector_fails_validation() {
        for peer in ["*-", "*-a,", "*-A"] {
            let yaml = format!(
                "networks:\n  sample-net:\n    host:\n      allows:\n        '{peer}': 'tcp:12345'\n"
            );
            assert!(parse(&yaml).is_err(), "selector {peer} should fail");
        }
        assert!(
            parse(
                "networks:\n  sample-net:\n    host:\n      denies:\n        '*-a': 'tcp:12345'\n"
            )
            .is_err()
        );
        assert!(
            parse("groups:\n  admins: []\nnetworks:\n  sample-net:\n    host:\n      allows:\n        '*-admins': 'tcp:12345'\n")
                .is_err()
        );
        assert!(
            parse("groups:\n  admins: ['*']\nnetworks:\n  sample-net:\n    host:\n      allows:\n        '*-admins': 'tcp:12345'\n")
                .is_err()
        );
    }

    #[test]
    fn excluded_group_and_alias_expand_to_joined_hostnames() {
        let spec = parse(
            "aliases:\n  owner: identity-owner\ngroups:\n  admin_team: [owner, build-box]\nnetworks:\n  sample-net:\n    target-host:\n      allows:\n        '*-admin_team,other-host': 'tcp:12345'\n        '*-owner': 'tcp:23456'\n",
        )
        .unwrap();
        let (expanded, warnings) = expand_firewall(
            &spec.networks["sample-net"],
            &spec.aliases,
            &spec.groups,
            &|identity| {
                assert_eq!(identity, "identity-owner");
                vec!["owner-phone".to_string(), "owner-laptop".to_string()]
            },
            &HashSet::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(
            expanded["target-host"].allows["*-build-box,other-host,owner-laptop,owner-phone"],
            "tcp:12345"
        );
        assert_eq!(
            expanded["target-host"].allows["*-owner-laptop,owner-phone"],
            "tcp:23456"
        );
        assert!(
            !expanded["target-host"]
                .allows
                .contains_key("*-admin_team,other-host")
        );
    }

    #[test]
    fn excluded_alias_without_joined_device_rejects_apply() {
        let spec = parse(
            "aliases:\n  owner: identity-owner\nnetworks:\n  sample-net:\n    target-host:\n      allows:\n        '*-owner': 'tcp:12345'\n",
        )
        .unwrap();
        let error = expand_firewall(
            &spec.networks["sample-net"],
            &spec.aliases,
            &spec.groups,
            &|_| Vec::new(),
            &HashSet::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("excluded alias 'owner' has no joined devices"));
    }

    #[test]
    fn excluded_targets_skip_user_devices_but_preserve_ssh_and_membership() {
        let spec = parse(
            r#"
aliases:
  owner: identity-owner
groups:
  users: [owner, guest-laptop]
  servers: [new-server]
networks:
  sample-net:
    "*":
      ssh:
        owner: [deploy]
    "*-users,spare-host":
      allows:
        "*": "tcp:12345"
      denies:
        "*": "udp:12345"
      ssh:
        owner: [audit]
    servers:
      allows:
        "*": "tcp:23456"
"#,
        )
        .unwrap();
        let current: HashSet<MachineHostname> = [
            "owner-laptop",
            "owner-phone",
            "guest-laptop",
            "spare-host",
            "build-box",
        ]
        .into_iter()
        .map(|host| host.parse().unwrap())
        .collect();
        let (expanded, warnings) = expand_firewall(
            &spec.networks["sample-net"],
            &spec.aliases,
            &spec.groups,
            &|_| vec!["owner-laptop".to_string(), "owner-phone".to_string()],
            &current,
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert!(!expanded.keys().any(|host| host.starts_with("*-")));
        let suggestions = suggested_firewall(&expanded);
        for host in ["owner-laptop", "owner-phone", "guest-laptop", "spare-host"] {
            assert_eq!(suggestions[host], HostSuggestions::default());
            assert!(
                crate::firewall::materialize_suggestions("sample-net", host, &suggestions, &|_| {
                    None
                })
                .is_empty()
            );
            assert_eq!(
                ssh_grants_for_host(&expanded, host)["owner-laptop"],
                ["deploy"]
            );
        }
        assert_eq!(expanded["build-box"].allows["*"], "tcp:12345");
        assert_eq!(expanded["build-box"].denies["*"], "udp:12345");
        assert_eq!(expanded["new-server"].allows["*"], "tcp:12345,tcp:23456");
        assert_eq!(
            ssh_grants_for_host(&expanded, "build-box")["owner-laptop"],
            ["audit", "deploy"]
        );
        let diff = membership_diff(&expanded, &current).unwrap();
        assert_eq!(diff.joins, ["new-server".parse().unwrap()]);
        assert!(diff.leaves.is_empty());
    }

    #[test]
    fn excluded_targets_clear_previous_suggestions_without_pruning() {
        let spec = parse(
            "networks:\n  sample-net:\n    '*-laptop':\n      allows:\n        '*': 'tcp:12345'\n",
        )
        .unwrap();
        let current = ["laptop", "build-box"]
            .into_iter()
            .map(|host| host.parse().unwrap())
            .collect();
        let network = &spec.networks["sample-net"];
        assert!(expected_hosts_for_network(network).is_empty());
        let diff = membership_diff(network, &current).unwrap();
        assert!(diff.joins.is_empty());
        assert_eq!(
            diff.leaves,
            ["build-box", "laptop"]
                .into_iter()
                .map(|host| host.parse().unwrap())
                .collect::<Vec<_>>()
        );
        let (expanded, _) = expand_firewall(
            network,
            &spec.aliases,
            &spec.groups,
            &|_| Vec::new(),
            &current,
        )
        .unwrap();
        let mut live: SuggestedFirewall = ["*", "laptop", "build-box"]
            .into_iter()
            .map(|host| (host.to_string(), allows(&[("*", "tcp:23456")]).firewall()))
            .collect();
        live.extend(suggested_firewall(&expanded));
        assert!(
            crate::firewall::materialize_suggestions("sample-net", "laptop", &live, &|_| None)
                .is_empty()
        );
        assert_eq!(live["build-box"].allows["*"], "tcp:12345");
        assert!(
            membership_diff(&expanded, &current)
                .unwrap()
                .leaves
                .is_empty()
        );
    }

    #[test]
    fn target_exclusions_reapply_to_new_members_and_merge_explicit_rules() {
        let spec = parse(
            "networks:\n  sample-net:\n    '*-laptop':\n      allows:\n        '*': 'tcp:12345'\n    laptop:\n      allows:\n        '*': 'tcp:23456'\n",
        )
        .unwrap();
        for hosts in [vec!["laptop"], vec!["laptop", "new-server"]] {
            let current = hosts.iter().map(|host| host.parse().unwrap()).collect();
            let (expanded, _) = expand_firewall(
                &spec.networks["sample-net"],
                &spec.aliases,
                &spec.groups,
                &|_| Vec::new(),
                &current,
            )
            .unwrap();
            assert_eq!(expanded["laptop"].allows["*"], "tcp:23456");
            assert_eq!(expanded.contains_key("new-server"), hosts.len() == 2);
            if let Some(server) = expanded.get("new-server") {
                assert_eq!(server.allows["*"], "tcp:12345");
            }
        }
    }

    #[test]
    fn target_exclusions_reject_malformed_selectors_and_unsafe_groups() {
        for subject in ["*-", "*-host,", "*-INVALID"] {
            let yaml = format!("networks:\n  sample-net:\n    '{subject}': {{}}\n");
            assert!(parse(&yaml).is_err(), "selector {subject} should fail");
        }
        for members in ["[]", "['*']", "[users]"] {
            let yaml = format!(
                "groups:\n  users: {members}\nnetworks:\n  sample-net:\n    '*-users': {{}}\n"
            );
            assert!(
                parse(&yaml).is_err(),
                "excluded group {members} should fail"
            );
        }
    }

    #[test]
    fn excluded_target_alias_without_joined_devices_rejects_apply() {
        let spec = parse(
            "networks:\n  sample-net:\n    '*-owner':\n      allows:\n        '*': 'tcp:12345'\n",
        )
        .unwrap();
        // Stored aliases must have the same exclusion behavior as inline aliases.
        let aliases = [("owner".to_string(), "identity-owner".to_string())].into();
        let error = expand_firewall(
            &spec.networks["sample-net"],
            &aliases,
            &spec.groups,
            &|_| Vec::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("excluded alias 'owner' has no joined devices")
        );
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
        let mut fw = DeployNetwork::new();
        fw.insert(
            "alice".to_string(),
            HostSuggestions {
                allows: [("bob".to_string(), "tcp:22".to_string())].into(),
                denies: [].into(),
            }
            .into(),
        );
        let mut spec = DeploySpec {
            networks: BTreeMap::new(),
            ..Default::default()
        };
        spec.networks.insert("gaming".to_string(), fw);
        spec.networks
            .insert("admin".to_string(), DeployNetwork::new());
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
        let mut fw = DeployNetwork::new();
        fw.insert(
            "alice".to_string(),
            HostSuggestions {
                allows: [("bob".to_string(), "tcp:22".to_string())].into(),
                denies: [("carol".to_string(), "icmp".to_string())].into(),
            }
            .into(),
        );
        // A wildcard subject + wildcard peer must NOT appear as expected hosts.
        fw.insert(
            "*".to_string(),
            HostSuggestions {
                allows: [("*".to_string(), "tcp:6969".to_string())].into(),
                denies: [].into(),
            }
            .into(),
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

    #[test]
    fn membership_diff_is_scoped_to_one_network() {
        let mut firewall = DeployNetwork::new();
        firewall.insert("alice".to_string(), DeployHost::default());
        firewall.insert("bob".to_string(), DeployHost::default());
        let current = ["alice", "carol"]
            .into_iter()
            .map(|hostname| hostname.parse().unwrap())
            .collect();
        assert_eq!(
            membership_diff(&firewall, &current).unwrap(),
            MembershipDiff {
                joins: vec!["bob".parse().unwrap()],
                leaves: vec!["carol".parse().unwrap()],
            }
        );
    }

    #[test]
    fn membership_diff_does_not_treat_wildcards_as_membership() {
        let mut firewall = DeployNetwork::new();
        firewall.insert("*".to_string(), allows(&[("*", "tcp:22")]));
        let current = ["alice", "bob"]
            .into_iter()
            .map(|hostname| hostname.parse().unwrap())
            .collect();
        assert_eq!(
            membership_diff(&firewall, &current).unwrap(),
            MembershipDiff {
                joins: Vec::new(),
                leaves: vec!["alice".parse().unwrap(), "bob".parse().unwrap()],
            }
        );
    }

    /// Build deploy rules from (peer, spec) allow pairs.
    fn allows(pairs: &[(&str, &str)]) -> DeployHost {
        HostSuggestions {
            allows: pairs
                .iter()
                .map(|(p, s)| (p.to_string(), s.to_string()))
                .collect(),
            denies: BTreeMap::new(),
        }
        .into()
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
        let mut fw = DeployNetwork::new();
        fw.insert("*".to_string(), allows(&[("alice", "tcp:22")]));

        let (out, warnings) =
            expand_firewall(&fw, &aliases, &groups, &resolve, &HashSet::new()).unwrap();
        assert!(warnings.is_empty());
        let wild = out.get("*").unwrap();
        assert_eq!(
            wild.allows.get("alice-laptop").map(String::as_str),
            Some("tcp:22")
        );
        assert_eq!(
            wild.allows.get("alice-phone").map(String::as_str),
            Some("tcp:22")
        );
        assert!(
            !wild.allows.contains_key("alice"),
            "alias name must not survive"
        );
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
        assert_eq!(
            merged.get("alice").map(String::as_str),
            Some("id-spec-alice")
        );
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
        let mut fw = DeployNetwork::new();
        fw.insert("*".to_string(), allows(&[("alice", "tcp:22")]));
        let (out, warnings) =
            expand_firewall(&fw, &merged, &groups, &resolve, &HashSet::new()).unwrap();
        assert!(warnings.is_empty());
        let wild = out.get("*").unwrap();
        assert_eq!(
            wild.allows.get("alice-laptop").map(String::as_str),
            Some("tcp:22")
        );
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
        let mut fw = DeployNetwork::new();
        fw.insert("*".to_string(), allows(&[("admins", "tcp:22")]));

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve, &HashSet::new()).unwrap();
        let wild = out.get("*").unwrap();
        assert_eq!(
            wild.allows.get("alice-laptop").map(String::as_str),
            Some("tcp:22")
        );
        assert_eq!(
            wild.allows.get("bob-server").map(String::as_str),
            Some("tcp:22")
        );
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
        let mut fw = DeployNetwork::new();
        fw.insert("webservers".to_string(), allows(&[("*", "tcp:80")]));

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve, &HashSet::new()).unwrap();
        assert!(!out.contains_key("webservers"));
        assert_eq!(
            out.get("web1").unwrap().allows.get("*").map(String::as_str),
            Some("tcp:80")
        );
        assert_eq!(
            out.get("web2").unwrap().allows.get("*").map(String::as_str),
            Some("tcp:80")
        );
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
        let mut fw = DeployNetwork::new();
        fw.insert(
            "*".to_string(),
            allows(&[("admins", "tcp:22"), ("alice", "tcp:80")]),
        );

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve, &HashSet::new()).unwrap();
        let merged = out.get("*").unwrap().allows.get("alice-laptop").unwrap();
        assert_eq!(merged, "tcp:22,tcp:80", "specs must merge sorted+deduped");
    }

    #[test]
    fn wildcards_pass_through_untouched() {
        let aliases = BTreeMap::new();
        let groups = BTreeMap::new();
        let resolve = |_: &str| -> Vec<String> { vec![] };
        let mut fw = DeployNetwork::new();
        fw.insert("*".to_string(), allows(&[("*", "tcp:6969")]));

        let (out, _) = expand_firewall(&fw, &aliases, &groups, &resolve, &HashSet::new()).unwrap();
        assert_eq!(
            out.get("*").unwrap().allows.get("*").map(String::as_str),
            Some("tcp:6969")
        );
    }

    #[test]
    fn unknown_name_passes_through_as_literal() {
        let aliases = BTreeMap::new();
        let groups = BTreeMap::new();
        let resolve = |_: &str| -> Vec<String> { vec![] };
        let mut fw = DeployNetwork::new();
        fw.insert("jumpbox".to_string(), allows(&[("monitor", "tcp:9100")]));

        let (out, warnings) =
            expand_firewall(&fw, &aliases, &groups, &resolve, &HashSet::new()).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(
            out.get("jumpbox")
                .unwrap()
                .allows
                .get("monitor")
                .map(String::as_str),
            Some("tcp:9100")
        );
    }

    #[test]
    fn alias_resolving_to_zero_hosts_warns_and_emits_nothing() {
        let aliases: BTreeMap<String, String> =
            [("ghost".to_string(), "id-ghost".to_string())].into();
        let groups = BTreeMap::new();
        let resolve = |_: &str| -> Vec<String> { vec![] }; // never joined
        let mut fw = DeployNetwork::new();
        fw.insert("*".to_string(), allows(&[("ghost", "tcp:22")]));

        let (out, warnings) =
            expand_firewall(&fw, &aliases, &groups, &resolve, &HashSet::new()).unwrap();
        assert_eq!(warnings, vec!["ghost".to_string()]);
        assert!(
            out.get("*").unwrap().allows.is_empty(),
            "no rule for an unjoined alias"
        );
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
        assert!(
            err.contains("admins"),
            "collision must name the offending key: {err}"
        );
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
        assert_eq!(
            spec.aliases.get("alice").map(String::as_str),
            Some("someidentitystring")
        );
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
