//! Host-firewall exceptions for the exit-node gateway's forwarded traffic.
//!
//! A host firewall that drops forwarding swallows every exit-node packet: Docker
//! 27+ sets the ip6tables `FORWARD` policy to `DROP`, ufw does the same with
//! `DEFAULT_FORWARD_POLICY="DROP"`, and firewalld's nft forward chain ends in a
//! reject. Our own nft table cannot override any of them (an `accept` ends only the
//! chain it is in), so, as Tailscale does, we put two accepts at the top of the
//! chain that drops: everything arriving from the TUN, and replies going back into
//! it. Nothing is added to a firewall that would forward anyway.
//!
//! Every rule carries a `rayfish-exit-*` comment, which is how teardown finds them.
//! That keeps removal stateless, so the panic hook and a restart after a crash can
//! clean up without knowing the TUN name or what was added.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;

use crate::hostfw::{self, Manager};

const COMMENT_IN: &str = "rayfish-exit-in";
const COMMENT_OUT: &str = "rayfish-exit-out";
const COMMENT_PREFIX: &str = "rayfish-exit-";

const IP6TABLES_DUMP: [&str; 5] = ["ip6tables", "-w", "5", "-S", "FORWARD"];
pub(super) const NFT_RULESET: [&str; 4] = ["nft", "-j", "list", "ruleset"];

/// The key of the dumps a periodic re-add last failed on (0 for none), so the
/// check does not retry the same failing inserts every pass. Any change to
/// either dump retries.
static FAILED_ON: AtomicU64 = AtomicU64::new(0);

/// What [`allow`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ForwardReport {
    /// Rules inserted by this call (0 when they were already there or not needed).
    pub(super) added: usize,
    /// The command the operator has to run, when a rule was needed and could not
    /// be inserted.
    pub(super) manual_fix: Option<String>,
}

/// Insert the forwarding accepts for `tun` wherever the host firewall would drop
/// them, skipping any already present. Idempotent. Rules of ours left for
/// another TUN name (a rename, or a crash before teardown) are removed.
pub(super) fn allow(tun: &str) -> ForwardReport {
    allow_with(tun, &mut hostfw::run)
}

/// The two dumps the exceptions are decided from.
pub(super) struct ForwardDumps {
    ip6tables: Option<String>,
    nft: Option<String>,
}

impl ForwardDumps {
    /// Reads the ip6tables dump; `nft` is the ruleset the caller already holds.
    pub(super) fn read(nft: Option<String>) -> Self {
        Self {
            ip6tables: hostfw::run(&IP6TABLES_DUMP),
            nft,
        }
    }

    /// What decides the exceptions for `tun`, hashed: the TUN name, the
    /// ip6tables dump, and the dropping nft chains with our rules in them. Not
    /// the raw nft dump, whose counters change on every read.
    fn key(&self, tun: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        tun.hash(&mut hasher);
        self.ip6tables.hash(&mut hasher);
        self.nft
            .as_deref()
            .map(nft_dropping_forward_chains)
            .hash(&mut hasher);
        hasher.finish()
    }
}

/// Whether [`reassert`] has anything to do: a dropping chain lacks one of our
/// accepts for `tun`, or holds one for another TUN, and the last attempt did
/// not already fail on these same dumps. Reads only.
pub(super) fn needs_reassert(tun: &str, dumps: &ForwardDumps) -> bool {
    needs_allow(tun, dumps) && FAILED_ON.load(Ordering::Relaxed) != dumps.key(tun)
}

/// [`allow`] for the periodic check, from fresh dumps. Remembers a failure so
/// [`needs_reassert`] stays quiet until something changes.
pub(super) fn reassert(tun: &str, dumps: &ForwardDumps) -> Option<String> {
    let report = allow_from(tun, dumps, &mut hostfw::run);
    let failed = report.manual_fix.is_some().then(|| dumps.key(tun));
    FAILED_ON.store(failed.unwrap_or(0), Ordering::Relaxed);
    report.manual_fix
}

fn needs_allow(tun: &str, dumps: &ForwardDumps) -> bool {
    let ip6tables = dumps
        .ip6tables
        .as_deref()
        .filter(|dump| ip6tables_forward_drops(dump))
        .is_some_and(|dump| {
            let ours: Vec<&str> = dump
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("-A FORWARD ") && line.contains(COMMENT_PREFIX))
                .collect();
            let names = |line: &str, flag: &str| {
                line.split_whitespace()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|w| w[0] == flag && w[1] == tun)
            };
            let has = |comment: &str, flag: &str| {
                ours.iter()
                    .any(|line| line.contains(comment) && names(line, flag))
            };
            ours.iter()
                .any(|line| !names(line, "-i") && !names(line, "-o"))
                || !has(COMMENT_IN, "-i")
                || !has(COMMENT_OUT, "-o")
        });
    let nft = dumps.nft.as_deref().is_some_and(|json| {
        nft_dropping_forward_chains(json).iter().any(|chain| {
            chain.ours.iter().any(|r| r.iface != tun)
                || [COMMENT_IN, COMMENT_OUT]
                    .iter()
                    .any(|c| !chain.ours.iter().any(|r| r.comment == *c))
        })
    });
    ip6tables || nft
}

/// Remove every rule [`allow`] ever inserted, by comment. Best-effort.
pub fn remove() {
    remove_with(&mut hostfw::run)
}

/// The two ip6tables rule specs, after the chain name.
fn ip6tables_specs(tun: &str) -> [Vec<&str>; 2] {
    [
        vec![
            "-i",
            tun,
            "-m",
            "comment",
            "--comment",
            COMMENT_IN,
            "-j",
            "ACCEPT",
        ],
        vec![
            "-o",
            tun,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-m",
            "comment",
            "--comment",
            COMMENT_OUT,
            "-j",
            "ACCEPT",
        ],
    ]
}

/// The two nft rules, as `(comment, rule text)`.
fn nft_rules(tun: &str) -> [(&'static str, String); 2] {
    [
        (
            COMMENT_IN,
            format!("iifname \"{tun}\" accept comment \"{COMMENT_IN}\""),
        ),
        (
            COMMENT_OUT,
            format!(
                "oifname \"{tun}\" ct state established,related accept comment \"{COMMENT_OUT}\""
            ),
        ),
    ]
}

fn allow_with(tun: &str, run: &mut impl FnMut(&[&str]) -> Option<String>) -> ForwardReport {
    let dumps = ForwardDumps {
        ip6tables: run(&IP6TABLES_DUMP),
        nft: run(&NFT_RULESET),
    };
    allow_from(tun, &dumps, run)
}

fn allow_from(
    tun: &str,
    dumps: &ForwardDumps,
    run: &mut impl FnMut(&[&str]) -> Option<String>,
) -> ForwardReport {
    let mut report = ForwardReport::default();
    let mut failed: Vec<String> = Vec::new();

    if let Some(dump) = dumps.ip6tables.as_deref()
        && ip6tables_forward_drops(dump)
    {
        for del in ip6tables_deletions(dump) {
            if !del
                .windows(2)
                .any(|w| matches!(w[0].as_str(), "-i" | "-o") && w[1] == tun)
            {
                ip6tables_delete(run, &del);
            }
        }
        for spec in ip6tables_specs(tun) {
            let mut check = vec!["ip6tables", "-w", "5", "-C", "FORWARD"];
            check.extend(&spec);
            if run(&check).is_some() {
                continue;
            }
            let mut insert = vec!["ip6tables", "-w", "5", "-I", "FORWARD", "1"];
            insert.extend(&spec);
            if run(&insert).is_some() {
                report.added += 1;
            } else {
                failed.push(format!("ip6tables -I FORWARD 1 {}", spec.join(" ")));
            }
        }
    }

    if let Some(json) = dumps.nft.as_deref() {
        for chain in nft_dropping_forward_chains(json) {
            for stale in chain.ours.iter().filter(|r| r.iface != tun) {
                nft_delete(run, stale);
            }
            for (comment, rule) in nft_rules(tun) {
                if chain
                    .ours
                    .iter()
                    .any(|r| r.comment == comment && r.iface == tun)
                {
                    continue;
                }
                // nft joins its arguments with spaces and parses the result, so
                // the rule can travel as one argument with its quotes intact.
                let args = [
                    "nft",
                    "insert",
                    "rule",
                    &chain.family,
                    &chain.table,
                    &chain.name,
                    &rule,
                ];
                if run(&args).is_some() {
                    report.added += 1;
                } else {
                    failed.push(format!(
                        "nft insert rule {} {} {} '{rule}'",
                        chain.family, chain.table, chain.name
                    ));
                }
            }
        }
    }

    if report.added > 0 {
        tracing::info!(
            tun,
            added = report.added,
            "allowed exit-node forwarding through the host firewall"
        );
    }
    if !failed.is_empty() {
        report.manual_fix = Some(match hostfw::detect_manager(run) {
            Some(manager) => manager_fix(manager, tun),
            None => failed.join(" && "),
        });
    }
    report
}

/// The fix to print for a firewall front-end we recognise, in its own terms, so
/// the operator's next reload does not discard it.
fn manager_fix(manager: Manager, tun: &str) -> String {
    match manager {
        Manager::Ufw => format!("ufw route allow in on {tun} && ufw route allow out on {tun}"),
        Manager::Firewalld => format!(
            "firewall-cmd --permanent --zone=trusted --add-interface={tun} && \
             firewall-cmd --permanent --new-policy rayfish-exit && \
             firewall-cmd --permanent --policy rayfish-exit --add-ingress-zone=trusted \
             --add-egress-zone=ANY --set-target=ACCEPT && firewall-cmd --reload"
        ),
        Manager::Iptables | Manager::Nftables => {
            let [inbound, outbound] = ip6tables_specs(tun);
            format!(
                "ip6tables -I FORWARD 1 {} && ip6tables -I FORWARD 1 {}",
                inbound.join(" "),
                outbound.join(" ")
            )
        }
    }
}

fn remove_with(run: &mut impl FnMut(&[&str]) -> Option<String>) {
    if let Some(dump) = run(&IP6TABLES_DUMP) {
        for del in ip6tables_deletions(&dump) {
            ip6tables_delete(run, &del);
        }
    }
    if let Some(json) = run(&NFT_RULESET) {
        for rule in nft_our_rules(&json) {
            nft_delete(run, &rule);
        }
    }
}

/// Run one `-D` argv from [`ip6tables_deletions`]. Best-effort.
fn ip6tables_delete(run: &mut impl FnMut(&[&str]) -> Option<String>, del: &[String]) {
    let mut args = vec!["ip6tables", "-w", "5"];
    args.extend(del.iter().map(String::as_str));
    let _ = run(&args);
}

/// Delete one rule of ours by its handle. Best-effort.
fn nft_delete(run: &mut impl FnMut(&[&str]) -> Option<String>, rule: &NftRule) {
    let handle = rule.handle.to_string();
    let _ = run(&[
        "nft",
        "delete",
        "rule",
        &rule.family,
        &rule.table,
        &rule.chain,
        "handle",
        &handle,
    ]);
}

/// Whether an `ip6tables -S FORWARD` dump drops what it does not accept: a `DROP`
/// policy, or an unconditional `DROP`/`REJECT` rule.
pub(super) fn ip6tables_forward_drops(dump: &str) -> bool {
    dump.lines().map(str::trim).any(|line| {
        line == "-P FORWARD DROP"
            || line == "-A FORWARD -j DROP"
            || line.starts_with("-A FORWARD -j REJECT")
    })
}

/// The `-D` argv (after `ip6tables -w 5`) for every rule of ours in an
/// `ip6tables -S FORWARD` dump.
pub(super) fn ip6tables_deletions(dump: &str) -> Vec<Vec<String>> {
    dump.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("-A FORWARD ") && line.contains(COMMENT_PREFIX))
        .map(|line| {
            let mut args: Vec<String> = line
                .split_whitespace()
                .map(|f| f.trim_matches('"').to_string())
                .collect();
            args[0] = "-D".to_string();
            args
        })
        .collect()
}

/// An nft forward base chain that drops what it does not accept.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct NftChain {
    pub(super) family: String,
    pub(super) table: String,
    pub(super) name: String,
    /// The chain's rules that carry one of our comments, to tell whether ours
    /// are already there and for which TUN.
    pub(super) ours: Vec<NftRule>,
}

/// One rule of ours, found by its comment.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct NftRule {
    pub(super) family: String,
    pub(super) table: String,
    pub(super) chain: String,
    pub(super) comment: String,
    /// The `iifname`/`oifname` it matches, empty when it names none.
    pub(super) iface: String,
    pub(super) handle: u64,
}

/// The rule of ours `rule` is, if it carries one of our comments.
fn our_rule(rule: &serde_json::Value) -> Option<NftRule> {
    let comment = rule.get("comment")?.as_str()?;
    if !comment.starts_with(COMMENT_PREFIX) {
        return None;
    }
    Some(NftRule {
        family: str_field(rule, "family").to_string(),
        table: str_field(rule, "table").to_string(),
        chain: str_field(rule, "chain").to_string(),
        comment: comment.to_string(),
        iface: rule_iface(rule).to_string(),
        handle: rule.get("handle")?.as_u64()?,
    })
}

#[derive(Deserialize)]
struct Ruleset {
    nftables: Vec<serde_json::Value>,
}

fn nft_items(json: &str) -> Vec<serde_json::Value> {
    serde_json::from_str::<Ruleset>(json)
        .map(|r| r.nftables)
        .unwrap_or_default()
}

/// Whether this is a JSON ruleset at all. An `nft` built without JSON support
/// (OpenWrt's) prints nothing useful for `-j`, which says nothing about which
/// tables exist.
pub(super) fn nft_json_readable(json: &str) -> bool {
    serde_json::from_str::<Ruleset>(json).is_ok()
}

/// Whether `nft -j list ruleset` output has the table `family` `name`.
pub(super) fn nft_has_table(json: &str, family: &str, name: &str) -> bool {
    nft_items(json).iter().any(|item| {
        item.get("table")
            .is_some_and(|t| str_field(t, "family") == family && str_field(t, "name") == name)
    })
}

fn str_field<'a>(obj: &'a serde_json::Value, key: &str) -> &'a str {
    obj.get(key).and_then(|v| v.as_str()).unwrap_or_default()
}

/// The IPv6-reaching forward base chains in `nft -j list ruleset` output that
/// drop by default: `policy drop`, or a last rule that drops or rejects
/// unconditionally (firewalld's shape).
///
/// iptables-nft's own `ip6 filter` `FORWARD` chain is skipped: the ip6tables
/// pass already handles it, through the tool that owns it. So are `ip` tables,
/// which never see the IPv6 the exit node carries, and our own table, which does
/// not drop.
pub(super) fn nft_dropping_forward_chains(json: &str) -> Vec<NftChain> {
    struct Seen {
        chain: NftChain,
        policy_drop: bool,
        last_rule_drops: bool,
    }
    let mut chains: Vec<Seen> = Vec::new();
    for item in nft_items(json) {
        if let Some(chain) = item.get("chain") {
            let family = str_field(chain, "family");
            let table = str_field(chain, "table");
            let name = str_field(chain, "name");
            if str_field(chain, "hook") != "forward"
                || str_field(chain, "type") != "filter"
                || !matches!(family, "inet" | "ip6")
                || (family == "ip6" && name == "FORWARD")
                || table == super::SERVER_TABLE
            {
                continue;
            }
            chains.push(Seen {
                chain: NftChain {
                    family: family.to_string(),
                    table: table.to_string(),
                    name: name.to_string(),
                    ours: Vec::new(),
                },
                policy_drop: str_field(chain, "policy") == "drop",
                last_rule_drops: false,
            });
        } else if let Some(rule) = item.get("rule")
            && let Some(seen) = chains.iter_mut().find(|s| {
                s.chain.family == str_field(rule, "family")
                    && s.chain.table == str_field(rule, "table")
                    && s.chain.name == str_field(rule, "chain")
            })
        {
            if let Some(ours) = our_rule(rule) {
                seen.chain.ours.push(ours);
            }
            seen.last_rule_drops = rule_drops_unconditionally(rule);
        }
    }
    chains
        .into_iter()
        .filter(|s| s.policy_drop || s.last_rule_drops)
        .map(|s| s.chain)
        .collect()
}

/// The interface name a rule matches with `iifname` or `oifname`, if any.
fn rule_iface(rule: &serde_json::Value) -> &str {
    rule.get("expr")
        .and_then(|e| e.as_array())
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("match"))
        .find(|m| {
            matches!(
                m.get("left")
                    .and_then(|l| l.get("meta"))
                    .map(|meta| str_field(meta, "key")),
                Some("iifname" | "oifname")
            )
        })
        .map(|m| str_field(m, "right"))
        .unwrap_or_default()
}

/// Whether a rule is nothing but a drop or reject (plus counters or logging).
fn rule_drops_unconditionally(rule: &serde_json::Value) -> bool {
    let Some(exprs) = rule.get("expr").and_then(|e| e.as_array()) else {
        return false;
    };
    let key = |e: &serde_json::Value| -> Option<String> { e.as_object()?.keys().next().cloned() };
    let keys: Vec<String> = exprs.iter().filter_map(key).collect();
    keys.len() == exprs.len()
        && keys
            .iter()
            .all(|k| matches!(k.as_str(), "counter" | "log" | "drop" | "reject"))
        && keys.iter().any(|k| matches!(k.as_str(), "drop" | "reject"))
}

/// Every rule in `nft -j list ruleset` output that carries one of our comments.
pub(super) fn nft_our_rules(json: &str) -> Vec<NftRule> {
    nft_items(json)
        .iter()
        .filter_map(|item| our_rule(item.get("rule")?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ip6tables with Docker's `DROP` policy and its jump chains.
    const DOCKER_FORWARD: &str = "\
-P FORWARD DROP
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
";

    /// firewalld's nft forward chain: `policy accept`, ending in a reject.
    const FIREWALLD_JSON: &str = r#"{"nftables": [
{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
{"table": {"family": "inet", "name": "firewalld", "handle": 1}},
{"chain": {"family": "inet", "table": "firewalld", "name": "filter_FORWARD", "handle": 20,
  "type": "filter", "hook": "forward", "prio": 10, "policy": "accept"}},
{"rule": {"family": "inet", "table": "firewalld", "chain": "filter_FORWARD", "handle": 21,
  "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "firewalld", "chain": "filter_FORWARD", "handle": 22,
  "expr": [{"jump": {"target": "filter_FORWARD_ZONES"}}]}},
{"rule": {"family": "inet", "table": "firewalld", "chain": "filter_FORWARD", "handle": 23,
  "expr": [{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}]}},
{"chain": {"family": "ip6", "table": "filter", "name": "FORWARD", "handle": 2,
  "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
{"chain": {"family": "inet", "table": "rayfish_exit", "name": "forward", "handle": 3,
  "type": "filter", "hook": "forward", "prio": -150, "policy": "accept"}},
{"chain": {"family": "inet", "table": "plain", "name": "forward", "handle": 4,
  "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
{"rule": {"family": "inet", "table": "plain", "chain": "forward", "handle": 5,
  "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}, {"drop": null}]}}
]}"#;

    struct Fake {
        forward: Option<String>,
        nft: Option<String>,
        existing: Vec<String>,
        fail_inserts: bool,
        calls: Vec<String>,
    }

    impl Fake {
        fn new(forward: Option<&str>, nft: Option<&str>) -> Self {
            Self {
                forward: forward.map(str::to_owned),
                nft: nft.map(str::to_owned),
                existing: Vec::new(),
                fail_inserts: false,
                calls: Vec::new(),
            }
        }

        fn run(&mut self, args: &[&str]) -> Option<String> {
            let line = args.join(" ");
            self.calls.push(line.clone());
            match args {
                ["ip6tables", "-w", "5", "-S", "FORWARD"] => self.forward.clone(),
                ["nft", "-j", "list", "ruleset"] => self.nft.clone(),
                ["ip6tables", "-w", "5", "-C", rest @ ..] => {
                    let spec = rest.join(" ");
                    self.existing.contains(&spec).then(String::new)
                }
                ["ip6tables", "-w", "5", "-I", "FORWARD", "1", rest @ ..] => {
                    if self.fail_inserts {
                        return None;
                    }
                    self.existing.push(format!("FORWARD {}", rest.join(" ")));
                    Some(String::new())
                }
                ["nft", "insert", ..] => (!self.fail_inserts).then(String::new),
                _ => None,
            }
        }
    }

    #[test]
    fn a_dropping_ip6tables_forward_gets_both_accepts_once() {
        let mut fake = Fake::new(Some(DOCKER_FORWARD), None);
        let report = allow_with("tun0", &mut |a| fake.run(a));
        assert_eq!(report.added, 2);
        assert_eq!(report.manual_fix, None);
        assert!(fake.calls.iter().any(|c| c
            == "ip6tables -w 5 -I FORWARD 1 -i tun0 -m comment --comment rayfish-exit-in -j ACCEPT"));
        assert!(fake.calls.iter().any(|c| c
            == "ip6tables -w 5 -I FORWARD 1 -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED \
                -m comment --comment rayfish-exit-out -j ACCEPT"));
        // A second pass finds them with `-C` and inserts nothing.
        let again = allow_with("tun0", &mut |a| fake.run(a));
        assert_eq!(again.added, 0);
    }

    #[test]
    fn ip6tables_rules_for_another_tun_are_removed() {
        let dump = format!(
            "{DOCKER_FORWARD}-A FORWARD -i old0 -m comment --comment rayfish-exit-in -j ACCEPT\n\
             -A FORWARD -i tun0 -m comment --comment rayfish-exit-in -j ACCEPT\n"
        );
        let mut fake = Fake::new(Some(&dump), None);
        allow_with("tun0", &mut |a| fake.run(a));
        let deletes: Vec<&String> = fake.calls.iter().filter(|c| c.contains(" -D ")).collect();
        assert_eq!(
            deletes,
            ["ip6tables -w 5 -D FORWARD -i old0 -m comment --comment rayfish-exit-in -j ACCEPT"]
        );
    }

    #[test]
    fn an_accepting_firewall_is_left_alone() {
        let mut fake = Fake::new(Some("-P FORWARD ACCEPT\n-A FORWARD -j DOCKER-USER\n"), None);
        assert_eq!(
            allow_with("tun0", &mut |a| fake.run(a)),
            ForwardReport::default()
        );
        assert!(
            !fake
                .calls
                .iter()
                .any(|c| c.contains("-I") || c.contains("-C"))
        );
    }

    #[test]
    fn a_failed_insert_names_the_fix() {
        let mut fake = Fake::new(Some(DOCKER_FORWARD), None);
        fake.fail_inserts = true;
        let report = allow_with("tun0", &mut |a| fake.run(a));
        assert_eq!(report.added, 0);
        let fix = report
            .manual_fix
            .expect("a needed rule that failed is reported");
        assert!(fix.contains("-I FORWARD 1 -i tun0"), "{fix}");
    }

    #[test]
    fn only_native_forward_chains_that_drop_are_patched() {
        let chains = nft_dropping_forward_chains(FIREWALLD_JSON);
        // firewalld's trailing reject counts; iptables-nft's `FORWARD`, our own
        // table and a chain whose only drop is conditional do not.
        assert_eq!(
            chains,
            [NftChain {
                family: "inet".into(),
                table: "firewalld".into(),
                name: "filter_FORWARD".into(),
                ours: Vec::new(),
            }]
        );
        let mut fake = Fake::new(None, Some(FIREWALLD_JSON));
        let report = allow_with("tun0", &mut |a| fake.run(a));
        assert_eq!(report.added, 2);
        assert!(fake.calls.iter().any(|c| c
            == "nft insert rule inet firewalld filter_FORWARD iifname \"tun0\" accept comment \"rayfish-exit-in\""));
    }

    #[test]
    fn a_policy_drop_chain_with_our_rules_needs_nothing() {
        let json = r#"{"nftables": [
{"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 1,
  "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
{"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 7,
  "comment": "rayfish-exit-in", "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "tun0"}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 8,
  "comment": "rayfish-exit-out", "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "tun0"}}, {"accept": null}]}}
]}"#;
        let mut fake = Fake::new(None, Some(json));
        assert_eq!(allow_with("tun0", &mut |a| fake.run(a)).added, 0);
        assert!(!fake.calls.iter().any(|c| c.starts_with("nft delete")));

        // The same rules for another TUN are stale: deleted, and ours inserted.
        let mut fake = Fake::new(None, Some(json));
        assert_eq!(allow_with("tun1", &mut |a| fake.run(a)).added, 2);
        assert!(
            fake.calls
                .iter()
                .any(|c| c == "nft delete rule inet filter forward handle 7")
        );
        assert!(
            fake.calls
                .iter()
                .any(|c| c == "nft delete rule inet filter forward handle 8")
        );
        assert_eq!(
            nft_our_rules(json)
                .into_iter()
                .map(|r| r.handle)
                .collect::<Vec<_>>(),
            [7, 8]
        );
    }

    #[test]
    fn teardown_deletes_only_commented_rules() {
        let dump = "\
-P FORWARD DROP
-A FORWARD -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment \"rayfish-exit-out\" -j ACCEPT
-A FORWARD -i tun0 -m comment --comment rayfish-exit-in -j ACCEPT
-A FORWARD -i tun0 -j ACCEPT
-A FORWARD -j DOCKER-USER
";
        let dels: Vec<String> = ip6tables_deletions(dump)
            .into_iter()
            .map(|d| d.join(" "))
            .collect();
        assert_eq!(
            dels,
            [
                "-D FORWARD -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment rayfish-exit-out -j ACCEPT",
                "-D FORWARD -i tun0 -m comment --comment rayfish-exit-in -j ACCEPT",
            ]
        );
    }

    #[test]
    fn forward_drop_is_read_from_policy_or_a_catch_all() {
        assert!(ip6tables_forward_drops(DOCKER_FORWARD));
        assert!(ip6tables_forward_drops(
            "-P FORWARD ACCEPT\n-A FORWARD -j REJECT --reject-with icmp6-adm-prohibited\n"
        ));
        assert!(!ip6tables_forward_drops(
            "-P FORWARD ACCEPT\n-A FORWARD -i eth0 -j DROP\n"
        ));
    }

    fn dumps(ip6tables: Option<&str>, nft: Option<&str>) -> ForwardDumps {
        ForwardDumps {
            ip6tables: ip6tables.map(str::to_owned),
            nft: nft.map(str::to_owned),
        }
    }

    #[test]
    fn the_periodic_check_reads_whether_anything_needs_adding() {
        assert!(needs_allow("tun0", &dumps(Some(DOCKER_FORWARD), None)));
        let done = format!(
            "{DOCKER_FORWARD}-A FORWARD -i tun0 -m comment --comment rayfish-exit-in -j ACCEPT\n\
             -A FORWARD -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment rayfish-exit-out -j ACCEPT\n"
        );
        assert!(!needs_allow("tun0", &dumps(Some(&done), None)));
        // Ours for another TUN is stale and has to go.
        let stale =
            format!("{done}-A FORWARD -i old0 -m comment --comment rayfish-exit-in -j ACCEPT\n");
        assert!(needs_allow("tun0", &dumps(Some(&stale), None)));
        // A firewall that forwards anyway needs nothing.
        assert!(!needs_allow(
            "tun0",
            &dumps(Some("-P FORWARD ACCEPT\n"), Some(r#"{"nftables": []}"#))
        ));
        assert!(needs_allow("tun0", &dumps(None, Some(FIREWALLD_JSON))));
    }

    #[test]
    fn the_failure_key_ignores_nft_counters_but_not_the_tun() {
        let a = r#"{"nftables": [
{"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 1,
  "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
{"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 2,
  "expr": [{"counter": {"packets": 1, "bytes": 80}}, {"accept": null}]}}
]}"#;
        let b = a.replace(
            "\"packets\": 1, \"bytes\": 80",
            "\"packets\": 9, \"bytes\": 720",
        );
        let one = dumps(Some(DOCKER_FORWARD), Some(a));
        let two = dumps(Some(DOCKER_FORWARD), Some(&b));
        assert_eq!(one.key("tun0"), two.key("tun0"));
        assert_ne!(one.key("tun0"), one.key("tun1"));
    }

    #[test]
    fn tables_are_found_in_the_ruleset() {
        assert!(nft_has_table(FIREWALLD_JSON, "inet", "firewalld"));
        assert!(!nft_has_table(FIREWALLD_JSON, "ip6", "firewalld"));
        assert!(!nft_has_table("not json", "inet", "firewalld"));
    }
}
