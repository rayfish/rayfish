//! Local device firewall for VPN traffic flowing through the TUN device.
//!
//! ## Scope: what is and isn't filtered
//!
//! This firewall only inspects **IP packets carried inside the VPN** (datagrams
//! read from the TUN device on the outbound side, and QUIC datagrams from peers
//! on the inbound side, see `forward::run_mesh` / `forward::evaluate_inbound`).
//!
//! The rayfish/iroh **control plane** (`Welcome`, `MemberSync`, `BlobUpdated`,
//! `MeshHello`, …) travels over QUIC *bidirectional streams*,
//! not datagrams, and the iroh transport itself runs on the host's real network
//! interfaces, neither ever enters the TUN device. **The firewall therefore
//! cannot block rayfish/iroh connections**, regardless of rules. Blocking the VPN
//! transport itself is deliberately impossible from the firewall policy.
//!
//! ## Default posture (no user rules)
//!
//! Out of the box, with an empty `firewall.toml`, the defaults are **direction-
//! aware and secure-by-default for inbound**:
//!
//! | Traffic              | Default |
//! |----------------------|---------|
//! | Inbound ICMP (v4+v6) | allow (so `ping`/reachability works) |
//! | Inbound TCP          | deny  (no listening port is exposed) |
//! | Inbound UDP          | deny  |
//! | Outbound (any proto) | allow (you initiate freely) |
//! | Return traffic       | allow (conntrack, see below) |
//!
//! So joining a public/open network never exposes a local service port to peers.
//! `ray firewall default allow` flips inbound TCP/UDP back to permissive (the old
//! behaviour); `ray firewall default deny` restores the secure inbound default.
//! The outbound default starts at `allow` and is not affected by
//! `ray firewall default`. Change it with `ray config set firewall.default-out`.
//!
//! Inbound ICMP-allow is **not** a hard-coded special case: a fresh config ships
//! a seeded, ordinary `allow in icmp` rule (`default_icmp_rule`) that the rule
//! scan matches first. It shows up in `ray firewall show` like any other rule, so
//! a user who wants to deny ICMP simply removes it (`ray firewall remove <i>`),
//! after which inbound ICMP falls through to the deny default. (An explicit
//! `deny in icmp` rule ordered before it also blocks it: explicit rules always
//! win, first-match.)
//!
//! ## Stateful behaviour
//!
//! The firewall is **stateful for TCP and UDP**: when this device initiates an
//! outbound connection, the flow is tracked, and return traffic for that flow is
//! allowed in even under a `deny` default policy or a targeted inbound deny. This
//! means:
//!
//! - `default allow` + `deny in tcp port 22` → blocks unsolicited inbound to SSH
//!   while leaving all your own outbound connections (and their return traffic)
//!   working. This is the recommended pattern for "allow basic traffic, block
//!   specific ports".
//! - `default deny` + `allow out ...` rules → lets you initiate exactly the
//!   outbound connections you permit; their return traffic is auto-allowed, and
//!   all unsolicited inbound is denied.
//!
//! Explicit rules always win (first-match). Established return traffic only
//! bypasses the *default* action, never an explicit rule.
//!
//! A TCP write-half-close keeps return traffic allowed. After both FINs, a fixed
//! closing window admits final acknowledgments and retransmissions; RST removes
//! tracking immediately. This is a flow tracker, not TCP sequence validation:
//! after eviction, permitted outbound traffic can create a fresh entry.

use std::convert::Infallible;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::peers::FastDashMap;
use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use dashmap::mapref::entry::Entry;
use iroh::EndpointId;
use ray_proto::SuggestedFirewall;
use ray_proto::ipc::{FirewallRuleView, MachineHostname};
use serde::{Deserialize, Serialize};
use tokio::runtime::RuntimeFlavor;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

mod packet;

pub use packet::{
    FragmentKey, IPV6_EXTENSION_HEADERS, Ipv6Fragment, PacketInfo, is_link_scoped_v6,
    parse_ipv6_fragment, parse_packet_info,
};
#[cfg(test)]
pub(crate) use packet::{IPV6_AH, IPV6_FRAGMENT};

// Direction / Protocol / Action live in `ray-proto` so the IPC layer carries them
// typed (not stringified); re-exported here so the daemon keeps its original
// `firewall::Action` paths.
pub use ray_proto::{Action, Direction, Protocol};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerFilter {
    Any,
    Identity(EndpointId),
    Except {
        hostnames: Vec<MachineHostname>,
        identities: Vec<EndpointId>,
    },
}

/// Parse the terms of a wildcard exclusion. `ray apply` expands group and alias
/// names before validating the resulting hostnames.
pub fn parse_excluded_peer_terms(selector: &str) -> Result<Option<Vec<&str>>> {
    let Some(terms) = selector.strip_prefix("*-") else {
        return Ok(None);
    };
    let exclusions: Vec<&str> = terms.split(',').collect();
    anyhow::ensure!(
        exclusions.iter().all(|term| !term.is_empty()),
        "invalid excluded-peer selector '{selector}'"
    );
    Ok(Some(exclusions))
}

/// Parse `*-host-a,host-b` as a wildcard with excluded peer hostnames.
/// Ordinary peer selectors return `None`.
pub fn parse_excluded_peers(selector: &str) -> Result<Option<Vec<MachineHostname>>> {
    let Some(terms) = parse_excluded_peer_terms(selector)? else {
        return Ok(None);
    };
    let mut hosts = terms
        .into_iter()
        .map(|host| {
            host.parse::<MachineHostname>()
                .with_context(|| format!("invalid excluded peer '{host}' in '{selector}'"))
        })
        .collect::<Result<Vec<_>>>()?;
    hosts.sort();
    hosts.dedup();
    Ok(Some(hosts))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// Where a [`FirewallRule`] came from. `Local` rules are hand-added by this
/// device (`ray firewall add`) and are never touched by trusted-network
/// reconvergence. `Network(net)` rules were materialized from a coordinator's
/// suggestions for that network; the node replaces the whole `Network(net)` set
/// on each blob update, so the blob stays authoritative for what it manages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleOrigin {
    #[default]
    Local,
    Network(String),
    /// Auto-seeded passthrough rule for the embedded mesh SSH server: when
    /// `ray firewall ssh on` is set, the daemon installs an allow rule on the
    /// configured port with this origin so SSH packets reach the listener under
    /// the deny-inbound default. `ssh off` removes exactly this rule, and
    /// reconvergence never touches it. The SSH allow-list (per-network) is the
    /// real authorization gate; this only opens the port at the packet layer.
    Ssh,
}

impl RuleOrigin {
    pub fn is_local(&self) -> bool {
        matches!(self, RuleOrigin::Local)
    }
}

/// The auto-seeded passthrough rule installed while mesh SSH
/// is enabled (see [`RuleOrigin::Ssh`]). Opens the configured port at the packet layer so
/// the embedded SSH listener can receive connections; per-network `ssh_allow`
/// is what actually authorizes a session.
pub fn ssh_passthrough_rule(port: u16) -> FirewallRule {
    FirewallRule {
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        port: Some(PortRange {
            start: port,
            end: port,
        }),
        peer: PeerFilter::Any,
        network: None,
        origin: RuleOrigin::Ssh,
    }
}

/// Two rules have the same *selector* if they match the same traffic:
/// direction, protocol, port, peer, and network, regardless of `action` or
/// `origin`. Used by `ray firewall add` to merge a contradicting/duplicate rule
/// (drop the old same-selector entry, keep only the new one) so the rule list
/// stays bounded instead of accumulating shadowed rules on every toggle.
pub fn same_selector(a: &FirewallRule, b: &FirewallRule) -> bool {
    a.direction == b.direction
        && a.protocol == b.protocol
        && a.port == b.port
        && a.peer == b.peer
        && a.network == b.network
}

/// Collapse rules that share a selector, keeping the *last* occurrence of each
/// (newest wins) while preserving relative order. Used when merging freshly
/// accepted suggestions into a network's installed set so re-accepting an
/// already-installed selector replaces it rather than stacking a duplicate.
pub fn dedup_by_selector(rules: Vec<FirewallRule>) -> Vec<FirewallRule> {
    let mut deduped: Vec<FirewallRule> = Vec::with_capacity(rules.len());
    for rule in rules.into_iter().rev() {
        if !deduped.iter().any(|r| same_selector(r, &rule)) {
            deduped.push(rule);
        }
    }
    deduped.reverse();
    deduped
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub direction: Direction,
    pub action: Action,
    pub protocol: Protocol,
    pub port: Option<PortRange>,
    pub peer: PeerFilter,
    /// Restrict the rule to peers sharing this network, regardless of the
    /// packet's transport handle. `None` matches any reachable peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Provenance: hand-added (`Local`) vs. materialized from a network's
    /// coordinator suggestions (`Network(net)`). Defaults to `Local` so older
    /// `firewall.toml` files keep working.
    #[serde(default, skip_serializing_if = "RuleOrigin::is_local")]
    pub origin: RuleOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Catch-all action for *inbound* traffic that matches no explicit rule.
    /// Defaults to `Deny` (secure posture: no listening port is exposed to peers
    /// out of the box). Inbound ICMP is allowed-by-default *before* this falls
    /// through (so `ping`/reachability works), unless an explicit `deny in icmp`
    /// rule overrides it. Older `firewall.toml` files that predate the split (and
    /// carried a single `default_action`) deserialize with this serde default,
    /// i.e. they too become deny-inbound on upgrade.
    #[serde(default = "default_inbound_action")]
    pub default_inbound: Action,
    /// Catch-all action for *outbound* traffic that matches no explicit rule.
    /// Defaults to `Allow` (you initiate connections freely; conntrack then lets
    /// their return traffic back in).
    #[serde(default = "default_outbound_action")]
    pub default_outbound: Action,
    /// "Fail fast" REJECT mode. When `true`, a denied packet gets a synthetic
    /// reply (TCP RST or ICMP unreachable, see [`crate::reject`]) so the initiator
    /// fails immediately instead of hanging; when `false` (the default), denied
    /// packets other than SSH are silently dropped. Denied TCP connections to
    /// port 22 or the configured mesh SSH port always receive a reset. Opt-in via
    /// `ray firewall reject on`; `#[serde(default)]` keeps existing
    /// `firewall.toml` files on the silent-drop posture for other traffic.
    #[serde(default)]
    pub reject: bool,
    /// Global kill switch. When `true`, the firewall stops enforcing: every packet
    /// is allowed regardless of rules or defaults (the ingress anti-spoof check in
    /// [`crate::forward::evaluate_inbound`] still runs, it is upstream of this).
    /// Set via `ray firewall off`; `#[serde(default)]` keeps existing
    /// `firewall.toml` files enforcing on upgrade.
    #[serde(default)]
    pub disabled: bool,
    pub rules: Vec<FirewallRule>,
}

fn default_inbound_action() -> Action {
    Action::Deny
}

fn default_outbound_action() -> Action {
    Action::Allow
}

/// The seeded "allow inbound ICMP from any peer" rule that ships in a fresh
/// firewall config. It is an ordinary `Local`, first-match rule (not a magic
/// default), so `ray firewall show` lists it and `ray firewall remove <i>`
/// deletes it: removing it makes the inbound default deny ICMP too.
pub fn default_icmp_rule() -> FirewallRule {
    FirewallRule {
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Icmp,
        port: None,
        peer: PeerFilter::Any,
        network: None,
        origin: RuleOrigin::Local,
    }
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            default_inbound: default_inbound_action(),
            default_outbound: default_outbound_action(),
            reject: false,
            disabled: false,
            // Ship inbound TCP/UDP denied but inbound ICMP allowed, as a visible,
            // removable rule rather than a hard-coded special case.
            rules: vec![default_icmp_rule()],
        }
    }
}

impl FirewallConfig {
    fn rejects_denied(&self, info: &PacketInfo) -> bool {
        self.reject
            || (info.protocol == 6
                && (info.dst_port == crate::forward::SSH_PORT
                    || info.dst_port == crate::forward::ssh_port()))
    }

    /// Replace the rules installed from network `net`'s suggestions with
    /// `new_rules`, leaving `Local` rules and other networks' rules untouched.
    pub fn replace_network_rules(&mut self, net: &str, new_rules: Vec<FirewallRule>) {
        self.rules
            .retain(|r| !matches!(&r.origin, RuleOrigin::Network(n) if n == net));
        self.rules.extend(new_rules);
    }

    /// Follow a network renamed on this node from `from` to `to`: rules scoped
    /// to it and rules installed from its suggestions name it by its local name,
    /// and without this a scoped rule would stop matching while the suggested
    /// ones were never replaced again. Returns whether any rule named it.
    pub fn rename_network(&mut self, from: &str, to: &str) -> bool {
        let mut renamed = false;
        for rule in &mut self.rules {
            if rule.network.as_deref() == Some(from) {
                rule.network = Some(to.to_string());
                renamed = true;
            }
            if matches!(&rule.origin, RuleOrigin::Network(n) if n == from) {
                rule.origin = RuleOrigin::Network(to.to_string());
                renamed = true;
            }
        }
        renamed
    }
}

/// How long an idle TCP flow stays "established" (return traffic still allowed).
const TCP_FLOW_TIMEOUT: Duration = Duration::from_secs(300);
/// Keep final ACKs and retransmitted FINs admissible for a fixed closing window.
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(30);
/// UDP is connectionless: use a short window so return traffic for a recent
/// outbound query/datagram is allowed, but stale entries expire quickly.
const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(30);

/// A normalized connection flow, keyed by protocol + the local and peer
/// (ip, port) endpoints. Direction-agnostic: both directions of one connection
/// map to the same `Flow`, so return traffic matches the outbound entry.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Flow {
    proto: u8,
    local_ip: IpAddr,
    local_port: u16,
    peer_ip: IpAddr,
    peer_port: u16,
    /// ICMP echo identifier (0 for TCP/UDP and non-echo ICMP). ICMP has no
    /// ports, so this is what distinguishes one ping session's flow from
    /// another's; an echo-request and its reply share it, so the reply matches.
    icmp_id: u16,
}

impl Flow {
    /// The flow `info` belongs to, seen from this host in `direction`.
    fn of(direction: Direction, info: &PacketInfo) -> Self {
        let (local_ip, local_port, peer_ip, peer_port) = match direction {
            Direction::Out => (info.src_ip, info.src_port, info.dst_ip, info.dst_port),
            Direction::In => (info.dst_ip, info.dst_port, info.src_ip, info.src_port),
        };
        Self {
            proto: info.protocol,
            local_ip,
            local_port,
            peer_ip,
            peer_port,
            icmp_id: info.icmp_id,
        }
    }
}

/// One-sided TCP close still permits data from the other side. Once both FINs
/// arrive, a fixed grace period admits the final ACK and retransmissions.
#[derive(Clone, Copy)]
enum FlowState {
    Active { last_seen: Instant },
    HalfClosed { last_seen: Instant, fin: Direction },
    Closing { since: Instant },
}

impl FlowState {
    fn active(&self, protocol: u8, now: Instant) -> bool {
        let (seen, timeout) = match self {
            Self::Active { last_seen } | Self::HalfClosed { last_seen, .. } => (
                *last_seen,
                if protocol == 6 {
                    TCP_FLOW_TIMEOUT
                } else {
                    UDP_FLOW_TIMEOUT
                },
            ),
            Self::Closing { since } => (*since, TCP_CLOSING_TIMEOUT),
        };
        now.saturating_duration_since(seen) < timeout
    }

    fn record(&mut self, direction: Direction, info: &PacketInfo, now: Instant) {
        if info.protocol == 6 && direction == Direction::Out && info.tcp_flags & 0x02 != 0 {
            // A new handshake can reuse the tuple of a previously closed connection.
            *self = Self::Active { last_seen: now };
            return;
        }
        let fin = info.protocol == 6 && info.tcp_flags & 0x01 != 0;
        match self {
            Self::Active { last_seen } if !fin => *last_seen = now,
            Self::Active { .. } => {
                *self = Self::HalfClosed {
                    last_seen: now,
                    fin: direction,
                }
            }
            Self::HalfClosed { fin: first, .. } if fin && *first != direction => {
                *self = Self::Closing { since: now };
            }
            Self::HalfClosed { last_seen, .. } => *last_seen = now,
            // Closing traffic must not keep an otherwise closed connection alive.
            Self::Closing { .. } => {}
        }
    }
}

/// What decided a [`Verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedBy {
    /// The firewall is off (`ray firewall off`), so nothing was checked.
    Disabled,
    /// The first matching rule, at `index` in [`FirewallConfig::rules`], which
    /// is also its number in `ray firewall show`.
    Rule { index: usize, rule: FirewallRule },
    /// No rule matched, so the direction's default applied.
    Default,
}

/// [`SharedFirewall::explain`]'s answer: how a packet would be treated, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    pub decided_by: DecidedBy,
    /// Denied with REJECT mode on, so the sender gets a TCP RST or ICMP
    /// unreachable instead of a silent drop.
    pub reject: bool,
    /// Denied by the inbound default, which conntrack lifts for return traffic
    /// of a flow this device opened. Never set when a rule decided: return
    /// traffic bypasses only the default.
    pub return_traffic: bool,
}

#[derive(Clone)]
pub struct SharedFirewall {
    inner: Arc<ArcSwap<FirewallConfig>>,
    /// Stateful connection tracker: outbound-initiated flows whose return
    /// traffic is allowed in even under a deny default.
    conntrack: Arc<FastDashMap<Flow, FlowState>>,
    /// Serializes read-modify-write edits (see [`Self::try_edit`]). The data
    /// path never takes it: packets read `inner` lock-free.
    edits: Arc<Mutex<()>>,
}

impl SharedFirewall {
    pub fn new(config: FirewallConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
            conntrack: Arc::new(FastDashMap::default()),
            edits: Arc::new(Mutex::new(())),
        }
    }

    /// Apply `edit` to the live config and `persist` the result, as one step.
    /// Edits are serialized: two that ran concurrently used to start from the
    /// same snapshot, and whichever stored last dropped the other's change.
    /// `persist` runs before the next edit starts, so the saved file ends in
    /// the same state as the live config. An `Err` from `edit` leaves both
    /// untouched.
    ///
    /// Waiting for the lock and the save are blocking work, and the callers are
    /// async IPC and reconverge handlers. On a multi-thread runtime the worker
    /// is handed off for the duration, so other tasks keep running.
    pub fn try_edit<T, E>(
        &self,
        edit: impl FnOnce(&mut FirewallConfig) -> std::result::Result<T, E>,
        persist: impl FnOnce(&FirewallConfig),
    ) -> std::result::Result<T, E> {
        let run = || {
            let _serialized = self.edits.lock().unwrap_or_else(PoisonError::into_inner);
            let mut config = (*self.inner.load_full()).clone();
            let out = edit(&mut config)?;
            let config = Arc::new(config);
            self.inner.store(Arc::clone(&config));
            persist(&config);
            Ok(out)
        };
        // `block_in_place` panics on a current-thread runtime; there, and
        // outside any runtime, there is no other worker to hand off to.
        let multi_thread = tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == RuntimeFlavor::MultiThread);
        if multi_thread {
            tokio::task::block_in_place(run)
        } else {
            run()
        }
    }

    /// [`Self::try_edit`] for an edit that cannot fail.
    pub fn edit<T>(
        &self,
        edit: impl FnOnce(&mut FirewallConfig) -> T,
        persist: impl FnOnce(&FirewallConfig),
    ) -> T {
        let result: std::result::Result<T, Infallible> =
            self.try_edit(|config| Ok(edit(config)), persist);
        match result {
            Ok(out) => out,
            Err(never) => match never {},
        }
    }

    /// First matching explicit rule and its index in `config.rules`, or `None`
    /// if no rule matches.
    fn match_rule<'c>(
        config: &'c FirewallConfig,
        direction: Direction,
        protocol: u8,
        dst_port: u16,
        peer: &EndpointId,
        shares_network: impl Fn(&str) -> bool,
    ) -> Option<(usize, &'c FirewallRule)> {
        for (index, rule) in config.rules.iter().enumerate() {
            if rule.direction != direction {
                continue;
            }
            if !protocol_matches(rule.protocol, protocol) {
                continue;
            }
            if let Some(ref range) = rule.port
                && !range.contains(dst_port)
            {
                continue;
            }
            match &rule.peer {
                PeerFilter::Any => {}
                PeerFilter::Identity(id) => {
                    if id != peer {
                        continue;
                    }
                }
                PeerFilter::Except { identities, .. } => {
                    if identities.contains(peer) {
                        continue;
                    }
                }
            }
            // Last, since it is the only check that consults the peer table.
            if let Some(ref rule_net) = rule.network
                && !shares_network(rule_net)
            {
                continue;
            }
            return Some((index, rule));
        }
        None
    }

    /// The default action for a packet that matched no explicit rule, by
    /// direction. Inbound ICMP is *not* special-cased here: it is allowed by a
    /// seeded, removable `allow in icmp` rule (see [`default_icmp_rule`]) that the
    /// rule scan matches first, so the user can delete it to deny ICMP.
    fn default_for(config: &FirewallConfig, direction: Direction) -> Action {
        match direction {
            Direction::Out => config.default_outbound,
            Direction::In => config.default_inbound,
        }
    }

    /// Stateless rule + default evaluation (no connection tracking), for direct
    /// rule tests. The data plane uses [`Self::evaluate_packet`], which is stateful.
    #[cfg(test)]
    pub fn evaluate(
        &self,
        direction: Direction,
        protocol: u8,
        dst_port: u16,
        peer: &EndpointId,
    ) -> Action {
        let config = self.inner.load();
        Self::match_rule(&config, direction, protocol, dst_port, peer, |_| false)
            .map(|(_, rule)| rule.action)
            .unwrap_or_else(|| Self::default_for(&config, direction))
    }

    /// Whether "fail fast" REJECT mode is enabled (opt-in, default off). When on,
    /// the data path answers a denied packet with a synthetic reply instead of
    /// dropping it silently.
    pub fn reject_enabled(&self) -> bool {
        self.inner.load().reject
    }

    /// Denied SSH always fails fast, including when general REJECT mode is off.
    pub(crate) fn rejects_denied(&self, info: &PacketInfo) -> bool {
        self.inner.load().rejects_denied(info)
    }

    /// Stateful evaluation of a fully-parsed packet against the peer's shared
    /// networks. Rules keep their configured order across networks, so an
    /// explicit deny cannot be bypassed by choosing another transport handle.
    pub fn evaluate_packet(
        &self,
        direction: Direction,
        info: &PacketInfo,
        peer: &EndpointId,
        shares_network: impl Fn(&str) -> bool,
    ) -> Action {
        // Hold one immutable firewall generation for this packet. A concurrent
        // configuration update is allowed to affect the next packet, but never
        // makes one packet evaluate its rules and default against different
        // generations. This also keeps the forwarding hot path to one ArcSwap
        // load instead of up to three.
        let config = self.inner.load();
        // Global kill switch (`ray firewall off`): allow everything, skip rules,
        // defaults, and conntrack. The ingress anti-spoof check runs upstream in
        // `forward::evaluate_inbound`, so spoofed sources are still dropped.
        if config.disabled {
            return Action::Allow;
        }
        let proto = info.protocol;
        let flow = Flow::of(direction, info);

        // 1. Explicit rules always win.
        if let Some((_, rule)) = Self::match_rule(
            &config,
            direction,
            proto,
            info.dst_port,
            peer,
            shares_network,
        ) {
            let action = rule.action;
            if action.is_allow() {
                self.track_packet(direction, &flow, info);
            }
            return action;
        }

        match direction {
            Direction::Out => {
                let default = Self::default_for(&config, Direction::Out);
                if default.is_allow() {
                    self.track_packet(Direction::Out, &flow, info);
                }
                default
            }
            Direction::In => {
                // No explicit inbound rule. Allow established return traffic so
                // the inbound default deny (or targeted inbound denies) don't
                // sever this device's own outbound connections.
                //
                // ICMP is the exception: an echo-*request* is always new inbound
                // (someone pinging us), never return traffic: only an
                // echo-*reply* answers a ping we sent. So conntrack may rescue an
                // inbound ICMP packet only when it's a reply; a request must face
                // the rules/default. Without this, a request and reply share a
                // flow (ICMP has no ports) and a recent outbound ping would
                // wrongly whitelist the peer's inbound pings.
                if conntrack_eligible(info) && self.track_packet(Direction::In, &flow, info) {
                    Action::Allow
                } else {
                    Self::default_for(&config, Direction::In)
                }
            }
        }
    }

    /// Whether an inbound packet answers a flow this host opened. Exit-node
    /// replies come from internet hosts no rule names, so they are admitted on
    /// conntrack alone: an allow rule for the gateway peer must not let a flow
    /// started on the gateway's side reach a local port.
    pub fn admits_reply(&self, info: &PacketInfo) -> bool {
        self.inner.load().disabled
            || self.track_packet(Direction::In, &Flow::of(Direction::In, info), info)
    }

    /// How [`Self::evaluate_packet`] would decide `info` as a new packet, and
    /// what decided it, without recording anything: an allowed outbound packet
    /// opens no conntrack flow here. `ray firewall test` asks this, so its answer
    /// comes from the matcher and defaults the data path enforces, not a copy of
    /// them. Conntrack is not consulted, since a new packet has no flow;
    /// [`Verdict::return_traffic`] says whether it would rescue a reply.
    pub fn explain(
        &self,
        direction: Direction,
        info: &PacketInfo,
        peer: &EndpointId,
        shares_network: impl Fn(&str) -> bool,
    ) -> Verdict {
        // One generation for the whole answer, as in `evaluate_packet`: the rule
        // index and the rule it names must come from the same config.
        let config = self.inner.load();
        if config.disabled {
            return Verdict {
                action: Action::Allow,
                decided_by: DecidedBy::Disabled,
                reject: false,
                return_traffic: false,
            };
        }
        if let Some((index, rule)) = Self::match_rule(
            &config,
            direction,
            info.protocol,
            info.dst_port,
            peer,
            shares_network,
        ) {
            return Verdict {
                action: rule.action,
                decided_by: DecidedBy::Rule {
                    index,
                    rule: rule.clone(),
                },
                reject: config.rejects_denied(info) && rule.action.is_deny(),
                return_traffic: false,
            };
        }
        let action = Self::default_for(&config, direction);
        Verdict {
            action,
            decided_by: DecidedBy::Default,
            reject: config.rejects_denied(info) && action.is_deny(),
            return_traffic: direction == Direction::In
                && action.is_deny()
                && conntrack_eligible(info),
        }
    }

    /// Only outbound traffic opens a flow. Admission and updates share one entry
    /// guard, so a packet cannot recreate state concurrently removed by a reset.
    fn track_packet(&self, direction: Direction, flow: &Flow, info: &PacketInfo) -> bool {
        if (direction == Direction::In && !conntrack_eligible(info))
            || (direction == Direction::Out
                && is_icmp(flow.proto)
                && !is_icmp_echo_request(flow.proto, info.icmp_type))
        {
            return false;
        }
        match self.conntrack.entry(*flow) {
            Entry::Occupied(mut entry) => {
                let now = Instant::now();
                let active = entry.get().active(flow.proto, now);
                if flow.proto == 6 && info.tcp_flags & 0x04 != 0 {
                    entry.remove();
                    return direction == Direction::Out || active;
                }
                if direction == Direction::In
                    && (!active
                        || (matches!(entry.get(), FlowState::Closing { .. })
                            && info.tcp_flags & 0x02 != 0))
                {
                    return false;
                }
                if !active && flow.proto == 6 && info.tcp_flags & 0x01 != 0 {
                    return false;
                }
                entry.get_mut().record(direction, info, now);
                true
            }
            Entry::Vacant(entry) => {
                if direction == Direction::In || (flow.proto == 6 && info.tcp_flags & 0x05 != 0) {
                    return false;
                }
                entry.insert(FlowState::Active {
                    last_seen: Instant::now(),
                });
                true
            }
        }
    }

    /// Periodically evicts idle flows so the tracker doesn't grow unbounded.
    /// Call once from the daemon with the daemon's cancellation token.
    pub fn spawn_evictor(self, token: CancellationToken) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        let now = Instant::now();
                        self.conntrack.retain(|flow, state| state.active(flow.proto, now));
                    }
                }
            }
        });
    }

    pub fn update(&self, config: FirewallConfig) {
        let _serialized = self.edits.lock().unwrap_or_else(PoisonError::into_inner);
        self.inner.store(Arc::new(config));
    }

    pub fn get_config(&self) -> Arc<FirewallConfig> {
        self.inner.load_full()
    }

    /// Replace the set of rules suggested by trusted network `net` with
    /// `new_rules`, leaving `Local` rules and other networks' rules untouched.
    /// The blob is authoritative for what it manages, so each reconverge swaps
    /// the whole `Network(net)` set. `persist` saves it (see [`Self::try_edit`]).
    pub fn replace_network_rules(
        &self,
        net: &str,
        new_rules: Vec<FirewallRule>,
        persist: impl FnOnce(&FirewallConfig),
    ) -> FirewallConfig {
        self.edit(
            |config| {
                config.replace_network_rules(net, new_rules);
                config.clone()
            },
            persist,
        )
    }

    /// [`FirewallConfig::rename_network`] on the live rules, saved by `persist`.
    /// Returns the updated config, or `None` (and persists nothing) when no rule
    /// names the network.
    pub fn rename_network(
        &self,
        from: &str,
        to: &str,
        persist: impl FnOnce(&FirewallConfig),
    ) -> Option<FirewallConfig> {
        self.try_edit(
            |config| {
                if config.rename_network(from, to) {
                    Ok(config.clone())
                } else {
                    Err(())
                }
            },
            persist,
        )
        .ok()
    }

    /// Install or remove the auto-seeded SSH passthrough rule
    /// ([`RuleOrigin::Ssh`]) so the embedded mesh SSH listener can receive
    /// connections under the deny-inbound default. Idempotent: enabling twice
    /// keeps a single rule, disabling removes exactly the seeded rule and leaves
    /// any hand-added rules alone. `persist` saves it (see [`Self::try_edit`]).
    pub fn set_ssh_passthrough(
        &self,
        enabled: bool,
        port: u16,
        persist: impl FnOnce(&FirewallConfig),
    ) -> FirewallConfig {
        self.edit(
            |config| {
                config
                    .rules
                    .retain(|r| !matches!(&r.origin, RuleOrigin::Ssh));
                if enabled {
                    // Front-insert so it wins over a stale deny, matching `firewall add`.
                    config.rules.insert(0, ssh_passthrough_rule(port));
                }
                config.clone()
            },
            persist,
        )
    }
}

fn protocol_matches(filter: Protocol, ip_proto: u8) -> bool {
    match filter {
        Protocol::Any => true,
        Protocol::Tcp => ip_proto == 6,
        Protocol::Udp => ip_proto == 17,
        Protocol::Icmp => ip_proto == 1 || ip_proto == 58, // ICMPv4 + ICMPv6
    }
}

/// ICMP (v4) and ICMPv6 protocol numbers.
fn is_icmp(proto: u8) -> bool {
    proto == 1 || proto == 58
}

/// True when an ICMP echo request starts a flow we expect a reply for.
fn is_icmp_echo_request(proto: u8, icmp_type: u8) -> bool {
    (proto == 1 && icmp_type == 8) || (proto == 58 && icmp_type == 128)
}

/// True when an ICMP echo reply can be treated as return traffic. Also tells
/// the Android forwarder that a kernel reply to a remote ping is not local demand.
pub(crate) fn is_icmp_echo_reply(proto: u8, icmp_type: u8) -> bool {
    (proto == 1 && icmp_type == 0) || (proto == 58 && icmp_type == 129)
}

/// Whether conntrack may admit `info` inbound as return traffic: any TCP or UDP
/// packet, but of ICMP only an echo reply (see `evaluate_packet`).
fn conntrack_eligible(info: &PacketInfo) -> bool {
    !is_icmp(info.protocol) || is_icmp_echo_reply(info.protocol, info.icmp_type)
}

pub fn firewall_path() -> Result<PathBuf> {
    Ok(crate::config::config_dir()?.join("firewall.toml"))
}

pub fn load_firewall() -> Result<FirewallConfig> {
    let path = firewall_path()?;
    if !path.exists() {
        return Ok(FirewallConfig::default());
    }
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("parse {}", path.display()))
}

pub fn save_firewall(config: &FirewallConfig) -> Result<()> {
    let path = firewall_path()?;
    let content = toml::to_string_pretty(config).context("serialize firewall config")?;
    // Not secret-bearing → 0640 root:rayfish, written atomically.
    crate::config::write_file(&path, content.as_bytes(), false)
}

pub fn parse_port_range(s: &str) -> Result<PortRange> {
    // `*` = wildcard = all ports. Accepted anywhere a port spec is expected
    // (local `ray firewall add --port '*'` and suggested-firewall tokens).
    if s.trim() == "*" {
        return Ok(PortRange {
            start: 0,
            end: u16::MAX,
        });
    }
    if let Some((start, end)) = s.split_once('-') {
        let start: u16 = start.parse().context("invalid start port")?;
        let end: u16 = end.parse().context("invalid end port")?;
        if start > end {
            bail!("start port ({start}) must be <= end port ({end})");
        }
        Ok(PortRange { start, end })
    } else {
        let port: u16 = s.parse().context("invalid port number")?;
        Ok(PortRange {
            start: port,
            end: port,
        })
    }
}

/// Parse a comma-separated port list into one `PortRange` per item.
///
/// Each item is a single port, a `start-end` range, or `*` (see
/// `parse_port_range`); empty items (e.g. a trailing comma) are skipped. Used by
/// `ray firewall add --port 80,443`, which turns each range into its own rule.
/// Errors if no usable item remains.
pub fn parse_port_list(s: &str) -> Result<Vec<PortRange>> {
    let ranges = s
        .split(',')
        .map(str::trim)
        .filter(|i| !i.is_empty())
        .map(parse_port_range)
        .collect::<Result<Vec<_>>>()?;
    if ranges.is_empty() {
        bail!("no valid port given");
    }
    Ok(ranges)
}

/// Parse a single suggested-firewall spec token into (protocol, optional port).
///
/// Grammar (protocol is always explicit, no bare-number back-compat):
/// - `tcp:22`, `tcp:80-443`, `tcp:*` → TCP with a port / range / wildcard
/// - `udp:53`, `udp:*`              → UDP
/// - `icmp`                         → ICMP (port-less; `:*` ignored)
/// - `any` / `any:*`                → every protocol, every port
/// - bare `tcp` / `udp`             → all ports of that protocol
///
/// A bare number (`"22"`) is rejected: use `tcp:22`. Comma-separated tokens
/// (`tcp:22,icmp`) are split by the caller, which produces one rule each.
pub fn parse_spec_token(tok: &str) -> Result<(Protocol, Option<PortRange>)> {
    let tok = tok.trim();
    match tok.split_once(':') {
        Some((proto_str, port_str)) => {
            let proto = proto_str.parse::<Protocol>().map_err(anyhow::Error::msg)?;
            match proto {
                // Port-less protocols: a port spec is meaningless, ignore it
                // so `icmp:*` reads the same as `icmp`.
                Protocol::Icmp | Protocol::Any => Ok((proto, None)),
                Protocol::Tcp | Protocol::Udp => {
                    let range = parse_port_range(port_str)?;
                    Ok((proto, Some(range)))
                }
            }
        }
        None => {
            // Bare token: must be a protocol keyword. A bare number is a
            // missing-protocol error, not an implicit TCP default.
            if tok.parse::<u16>().is_ok() {
                bail!("missing protocol prefix for '{tok}'; use e.g. 'tcp:{tok}' or 'icmp'");
            }
            let proto = tok.parse::<Protocol>().map_err(anyhow::Error::msg)?;
            match proto {
                Protocol::Icmp | Protocol::Any => Ok((proto, None)),
                // Bare `tcp`/`udp` = all ports of that protocol.
                Protocol::Tcp | Protocol::Udp => Ok((
                    proto,
                    Some(PortRange {
                        start: 0,
                        end: u16::MAX,
                    }),
                )),
            }
        }
    }
}

/// Parse the packet `ray firewall test` asks about: `tcp:<port>`, `udp:<port>`,
/// or `icmp`, in the [`parse_spec_token`] grammar. A spec there can cover many
/// packets; this one names a single packet, so TCP and UDP need exactly one port
/// and `any` is refused.
pub fn parse_probe(spec: &str) -> Result<(Protocol, Option<u16>)> {
    match parse_spec_token(spec)? {
        (Protocol::Any, _) => {
            bail!("'{spec}' names no single protocol; use tcp:<port>, udp:<port>, or icmp")
        }
        (Protocol::Icmp, _) => Ok((Protocol::Icmp, None)),
        (protocol, Some(range)) if range.start == range.end => Ok((protocol, Some(range.start))),
        (protocol, _) => bail!("'{spec}' is not a single port; use e.g. {protocol}:22"),
    }
}

/// The opening packet of a new exchange with a peer, as the data path would see
/// it: a TCP SYN, a UDP datagram, or an ICMPv6 echo request (the overlay is
/// IPv6-only), to `port` on the receiving end. Inbound runs from `peer` to
/// `local`, outbound the other way. Only what the rules and conntrack read is
/// filled in.
pub fn probe_packet(
    direction: Direction,
    protocol: Protocol,
    port: Option<u16>,
    local: Ipv6Addr,
    peer: Ipv6Addr,
) -> Result<PacketInfo> {
    const TCP_SYN: u8 = 0x02;
    const ICMPV6: u8 = 58;
    const ICMPV6_ECHO_REQUEST: u8 = 128;
    let (proto, dst_port, tcp_flags, icmp_type) = match (protocol, port) {
        (Protocol::Tcp, Some(port)) => (6, port, TCP_SYN, 0),
        (Protocol::Udp, Some(port)) => (17, port, 0, 0),
        (Protocol::Icmp, None) => (ICMPV6, 0, 0, ICMPV6_ECHO_REQUEST),
        (Protocol::Tcp | Protocol::Udp, None) => bail!("{protocol} needs a port"),
        (Protocol::Icmp, Some(_)) => bail!("icmp has no port"),
        (Protocol::Any, _) => bail!("name one protocol: tcp, udp, or icmp"),
    };
    let (src, dst) = match direction {
        Direction::In => (peer, local),
        Direction::Out => (local, peer),
    };
    Ok(PacketInfo {
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
        protocol: proto,
        src_port: 0,
        dst_port,
        tcp_flags,
        icmp_type,
        icmp_id: 0,
        // A bare IPv6 header: no extension headers precede the transport header.
        transport_offset: 40,
    })
}

/// Build the concrete local firewall rules a node enforces for network `net`,
/// from `suggestions` targeting `my_hostname`. Two subjects apply to a node: its
/// own hostname and the wildcard `*` subject (which targets every node, e.g.
/// "everyone opens 6969"). Peer hostnames are resolved to identities via
/// `resolve` (the blob's member list); unresolved peers are skipped, their rules
/// materialize once they join. The `*` peer key means any peer, and
/// `*-host-a,host-b` means any peer except those hostnames. Every rule is inbound,
/// network-scoped to `net`, and tagged
/// `origin: Network(net)`. Suggestions are purely additive: each token yields
/// exactly one rule (allow or deny) and nothing is synthesized: the node's own
/// `default_inbound` (Deny by default) already covers anything an allow-list
/// leaves out, so no catch-all deny is appended. Each port spec token is
/// `proto:ports` or a bare proto keyword (`icmp`, `any`, `tcp`); a comma-separated
/// value yields one rule per token.
pub fn materialize_suggestions(
    net: &str,
    my_hostname: &str,
    suggestions: &SuggestedFirewall,
    resolve: &dyn Fn(&str) -> Option<EndpointId>,
) -> Vec<FirewallRule> {
    materialize_suggestions_with_exclusion_resolver(net, my_hostname, suggestions, resolve, resolve)
}

/// Exclusions use the identity seen by the packet filter, which may be a paired
/// device's user identity instead of its transport identity.
pub(crate) fn materialize_suggestions_with_exclusion_resolver(
    net: &str,
    my_hostname: &str,
    suggestions: &SuggestedFirewall,
    resolve: &dyn Fn(&str) -> Option<EndpointId>,
    resolve_excluded: &dyn Fn(&str) -> Option<EndpointId>,
) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    // The wildcard `*` subject applies to every node, alongside its own subject
    // (deduped so a node literally named "*" isn't counted twice).
    let mut keys = vec!["*"];
    if my_hostname != "*" {
        keys.push(my_hostname);
    }
    let applicable: Vec<_> = keys.iter().filter_map(|k| suggestions.get(*k)).collect();
    if applicable.is_empty() {
        return rules;
    }
    for host in &applicable {
        for (action, list) in [(Action::Allow, &host.allows), (Action::Deny, &host.denies)] {
            for (peer, ports) in list {
                let filter = match parse_excluded_peers(peer) {
                    Ok(Some(hostnames)) if action == Action::Allow => PeerFilter::Except {
                        identities: hostnames
                            .iter()
                            .filter_map(|hostname| resolve_excluded(hostname.as_ref()))
                            .collect(),
                        hostnames,
                    },
                    Ok(Some(_)) => {
                        tracing::warn!(selector = %peer, "excluded-peer selector is only valid in allows");
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(selector = %peer, %error, "skipping invalid peer selector");
                        continue;
                    }
                    Ok(None) if peer == "*" => PeerFilter::Any,
                    Ok(None) => match resolve(peer) {
                        Some(id) => PeerFilter::Identity(id),
                        None => continue,
                    },
                };
                for tok in ports.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    match parse_spec_token(tok) {
                        Ok((proto, port)) => rules.push(FirewallRule {
                            direction: Direction::In,
                            action,
                            protocol: proto,
                            port,
                            peer: filter.clone(),
                            network: Some(net.to_string()),
                            origin: RuleOrigin::Network(net.to_string()),
                        }),
                        Err(e) => tracing::warn!(
                            token = %tok, network = %net, error = %e,
                            "skipping invalid firewall spec token"
                        ),
                    }
                }
            }
        }
    }
    // Suggestions are purely additive: each token becomes one rule, allow or
    // deny, and nothing else is synthesized. A node's own `default_inbound`
    // (Deny by default) already drops everything an allow-list doesn't cover,
    // so we don't append a network-scoped catch-all deny, it would only be
    // redundant under the deny default and would surprise operators reviewing
    // `ray firewall pending` with a rule they never suggested.
    rules
}

/// Build a display-oriented [`FirewallRuleView`] for one rule, resolving the
/// peer identity to a short id via `short_id`. Used for IPC (the CLI renders /
/// serializes the view) and for value-matching queued suggestions.
pub fn rule_view(
    rule: &FirewallRule,
    short_id: &dyn Fn(&EndpointId) -> String,
) -> FirewallRuleView {
    let peer = match &rule.peer {
        PeerFilter::Any => "any".to_string(),
        PeerFilter::Identity(id) => short_id(id),
        PeerFilter::Except { hostnames, .. } => format!(
            "any except {}",
            hostnames
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    };
    let port = match &rule.port {
        None => "*".to_string(),
        Some(r) if r.start == r.end => r.start.to_string(),
        Some(r) => format!("{}-{}", r.start, r.end),
    };
    let network = rule.network.clone().unwrap_or_else(|| "any".to_string());
    let suggested_by = match &rule.origin {
        RuleOrigin::Local => None,
        RuleOrigin::Network(n) => Some(n.clone()),
        RuleOrigin::Ssh => Some("ssh".to_string()),
    };
    FirewallRuleView {
        direction: rule.direction,
        action: rule.action,
        protocol: rule.protocol,
        port,
        peer,
        network,
        suggested_by,
    }
}

/// Build the views for every rule in `config`, in order.
pub fn rule_views(
    rules: &[FirewallRule],
    short_id: &dyn Fn(&EndpointId) -> String,
) -> Vec<FirewallRuleView> {
    rules.iter().map(|r| rule_view(r, short_id)).collect()
}

#[cfg(test)]
mod tests;
