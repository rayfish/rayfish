//! Local device firewall for VPN traffic flowing through the TUN device.
//!
//! ## Scope — what is and isn't filtered
//!
//! This firewall only inspects **IP packets carried inside the VPN** (datagrams
//! read from the TUN device on the outbound side, and QUIC datagrams from peers
//! on the inbound side — see `forward::run_mesh` / `forward::evaluate_inbound`).
//!
//! The rayfish/iroh **control plane** (`Welcome`, `MemberSync`, `BlobUpdated`,
//! `MeshHello`, …) travels over QUIC *bidirectional streams*,
//! not datagrams, and the iroh transport itself runs on the host's real network
//! interfaces — neither ever enters the TUN device. **The firewall therefore
//! cannot block rayfish/iroh connections**, regardless of rules. Blocking the VPN
//! transport itself is deliberately impossible from the firewall policy.
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use iroh::EndpointId;
use ray_proto::SuggestedFirewall;
use ray_proto::ipc::FirewallRuleView;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, derive_more::Display)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[display("in")]
    In,
    #[display("out")]
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, derive_more::Display)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[display("tcp")]
    Tcp,
    #[display("udp")]
    Udp,
    #[display("icmp")]
    Icmp,
    #[display("any")]
    Any,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, derive_more::IsVariant, derive_more::Display,
)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[display("allow")]
    Allow,
    #[display("deny")]
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerFilter {
    Any,
    Identity(EndpointId),
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
}

impl RuleOrigin {
    pub fn is_local(&self) -> bool {
        matches!(self, RuleOrigin::Local)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub direction: Direction,
    pub action: Action,
    pub protocol: Protocol,
    pub port: Option<PortRange>,
    pub peer: PeerFilter,
    /// Restrict the rule to traffic on a specific network. `None` (the default,
    /// so older `firewall.toml` files keep working) matches any network. Lets a
    /// multi-homed host scope a rule to the network a packet arrived on — e.g.
    /// "allow :8080 only from peers reached via `db`".
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
    pub default_action: Action,
    pub rules: Vec<FirewallRule>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            default_action: Action::Allow,
            rules: vec![],
        }
    }
}

/// How long an idle TCP flow stays "established" (return traffic still allowed).
const TCP_FLOW_TIMEOUT: Duration = Duration::from_secs(300);
/// UDP is connectionless: use a short window so return traffic for a recent
/// outbound query/datagram is allowed, but stale entries expire quickly.
const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(30);

/// A normalized connection flow, keyed by protocol + the local and peer
/// (ip, port) endpoints. Direction-agnostic: both directions of one connection
/// map to the same `Flow`, so return traffic matches the outbound entry.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Flow {
    proto: u8,
    local_ip: IpAddr,
    local_port: u16,
    peer_ip: IpAddr,
    peer_port: u16,
}

#[derive(Clone)]
pub struct SharedFirewall {
    inner: Arc<ArcSwap<FirewallConfig>>,
    /// Stateful connection tracker: outbound-initiated flows whose return
    /// traffic is allowed in even under a deny default.
    conntrack: Arc<DashMap<Flow, Instant>>,
}

impl SharedFirewall {
    pub fn new(config: FirewallConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
            conntrack: Arc::new(DashMap::new()),
        }
    }

    /// First matching explicit rule's action, or `None` if no rule matches.
    fn match_rule(
        &self,
        direction: Direction,
        protocol: u8,
        dst_port: u16,
        peer: &EndpointId,
        network: Option<&str>,
    ) -> Option<Action> {
        let config = self.inner.load();
        for rule in &config.rules {
            if rule.direction != direction {
                continue;
            }
            if let Some(ref rule_net) = rule.network
                && Some(rule_net.as_str()) != network
            {
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
            }
            return Some(rule.action);
        }
        None
    }

    fn default_action(&self) -> Action {
        self.inner.load().default_action
    }

    /// Stateless rule + default evaluation (no connection tracking).
    /// Retained for compatibility and direct rule testing; the data plane uses
    /// [`Self::evaluate_packet`] which is stateful.
    #[allow(dead_code)]
    pub fn evaluate(
        &self,
        direction: Direction,
        protocol: u8,
        dst_port: u16,
        peer: &EndpointId,
    ) -> Action {
        self.match_rule(direction, protocol, dst_port, peer, None)
            .unwrap_or_else(|| self.default_action())
    }

    /// Stateful evaluation of a fully-parsed packet. This is what the data plane
    /// (`forward.rs`) calls. See the module docs for the full semantics.
    ///
    /// Order:
    /// 1. Explicit rules (first-match wins) — for both directions.
    /// 2. If outbound and permitted: record/refresh the flow so the peer's return
    ///    traffic is recognized. Denied outbound is never tracked (otherwise a
    ///    denied connection could whitelist its own return traffic).
    /// 3. If inbound and no explicit rule matched: allow established return
    ///    traffic; otherwise fall back to the default action.
    pub fn evaluate_packet(
        &self,
        direction: Direction,
        info: &PacketInfo,
        peer: &EndpointId,
        network: Option<&str>,
    ) -> Action {
        let proto = info.protocol;
        let (local_ip, local_port, peer_ip, peer_port) = match direction {
            Direction::Out => (info.src_ip, info.src_port, info.dst_ip, info.dst_port),
            Direction::In => (info.dst_ip, info.dst_port, info.src_ip, info.src_port),
        };
        let flow = Flow {
            proto,
            local_ip,
            local_port,
            peer_ip,
            peer_port,
        };

        // 1. Explicit rules always win.
        if let Some(action) = self.match_rule(direction, proto, info.dst_port, peer, network) {
            if direction == Direction::Out && action.is_allow() {
                self.track_outbound(&flow, info);
            }
            return action;
        }

        match direction {
            Direction::Out => {
                let default = self.default_action();
                if default.is_allow() {
                    self.track_outbound(&flow, info);
                }
                default
            }
            Direction::In => {
                // No explicit inbound rule. Allow established return traffic so
                // `default deny` (or targeted inbound denies) don't sever this
                // device's own outbound connections.
                if self.flow_active(&flow) {
                    self.conntrack.insert(flow, Instant::now());
                    Action::Allow
                } else {
                    self.default_action()
                }
            }
        }
    }

    /// Records or refreshes an outbound flow. TCP FIN/RST evict the flow
    /// immediately so a closed connection stops whitelisting return traffic.
    fn track_outbound(&self, flow: &Flow, info: &PacketInfo) {
        if flow.proto == 6 {
            let fin = info.tcp_flags & 0x01 != 0;
            let rst = info.tcp_flags & 0x04 != 0;
            if fin || rst {
                self.conntrack.remove(flow);
                return;
            }
        }
        self.conntrack.insert(flow.clone(), Instant::now());
    }

    /// True if `flow` is a tracked, non-expired outbound-initiated connection.
    fn flow_active(&self, flow: &Flow) -> bool {
        let timeout = if flow.proto == 6 {
            TCP_FLOW_TIMEOUT
        } else {
            UDP_FLOW_TIMEOUT
        };
        if let Some(ts) = self.conntrack.get(flow)
            && ts.elapsed() < timeout
        {
            return true;
        }
        false
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
                        self.conntrack.retain(|flow, ts| {
                            let timeout = if flow.proto == 6 { TCP_FLOW_TIMEOUT } else { UDP_FLOW_TIMEOUT };
                            now.duration_since(*ts) < timeout
                        });
                    }
                }
            }
        });
    }

    pub fn update(&self, config: FirewallConfig) {
        self.inner.store(Arc::new(config));
    }

    pub fn get_config(&self) -> Arc<FirewallConfig> {
        self.inner.load_full()
    }

    /// Replace the set of rules suggested by trusted network `net` with
    /// `new_rules`, leaving `Local` rules and other networks' rules untouched.
    /// The blob is authoritative for what it manages, so each reconverge swaps
    /// the whole `Network(net)` set. Returns the updated config for persistence.
    pub fn replace_network_rules(&self, net: &str, new_rules: Vec<FirewallRule>) -> FirewallConfig {
        let mut config = (*self.get_config()).clone();
        config
            .rules
            .retain(|r| !matches!(&r.origin, RuleOrigin::Network(n) if n == net));
        config.rules.extend(new_rules);
        self.update(config.clone());
        config
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

pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP flags byte (offset 13 of the TCP header). 0 for non-TCP. Used by the
    /// stateful tracker to detect SYN/FIN/RST. Bits: FIN 0x01, SYN 0x02,
    /// RST 0x04, ACK 0x10.
    pub tcp_flags: u8,
}

pub fn parse_packet_info(packet: &[u8]) -> Option<PacketInfo> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    if packet.len() < header_len {
        return None;
    }

    let protocol = packet[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));

    let (src_port, dst_port) = extract_ports(protocol, packet, header_len);
    let tcp_flags = extract_tcp_flags(protocol, packet, header_len);

    Some(PacketInfo {
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
    })
}

fn parse_ipv6(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 40 {
        return None;
    }
    let protocol = packet[6]; // Next Header
    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    dst_octets.copy_from_slice(&packet[24..40]);
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets));

    let header_len = 40; // fixed IPv6 header (extension headers not yet supported)
    let (src_port, dst_port) = extract_ports(protocol, packet, header_len);
    let tcp_flags = extract_tcp_flags(protocol, packet, header_len);

    Some(PacketInfo {
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
    })
}

fn extract_ports(protocol: u8, packet: &[u8], header_len: usize) -> (u16, u16) {
    if (protocol == 6 || protocol == 17) && packet.len() >= header_len + 4 {
        (
            u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
            u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
        )
    } else {
        (0, 0)
    }
}

fn extract_tcp_flags(protocol: u8, packet: &[u8], header_len: usize) -> u8 {
    if protocol == 6 && packet.len() >= header_len + 14 {
        packet[header_len + 13]
    } else {
        0
    }
}

pub fn firewall_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("rayfish");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("firewall.toml"))
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
    std::fs::write(&path, content).with_context(|| format!("write {}", path.display()))
}

pub fn parse_direction(s: &str) -> Result<Direction> {
    match s {
        "in" => Ok(Direction::In),
        "out" => Ok(Direction::Out),
        _ => bail!("invalid direction '{}' (expected 'in' or 'out')", s),
    }
}

pub fn parse_action(s: &str) -> Result<Action> {
    match s {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        _ => bail!("invalid action '{}' (expected 'allow' or 'deny')", s),
    }
}

pub fn parse_protocol(s: &str) -> Result<Protocol> {
    match s {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "any" => Ok(Protocol::Any),
        _ => bail!(
            "invalid protocol '{}' (expected 'tcp', 'udp', 'icmp', or 'any')",
            s
        ),
    }
}

pub fn parse_port_range(s: &str) -> Result<PortRange> {
    // `*` = wildcard = all ports. Accepted anywhere a port spec is expected
    // (local `ray firewall add --port '*'` and suggested-firewall tokens).
    if s.trim() == "*" {
        return Ok(PortRange { start: 0, end: u16::MAX });
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

/// Parse a single suggested-firewall spec token into (protocol, optional port).
///
/// Grammar (protocol is always explicit — no bare-number back-compat):
/// - `tcp:22`, `tcp:80-443`, `tcp:*` → TCP with a port / range / wildcard
/// - `udp:53`, `udp:*`              → UDP
/// - `icmp`                         → ICMP (port-less; `:*` ignored)
/// - `any` / `any:*`                → every protocol, every port
/// - bare `tcp` / `udp`             → all ports of that protocol
///
/// A bare number (`"22"`) is rejected — use `tcp:22`. Comma-separated tokens
/// (`tcp:22,icmp`) are split by the caller, which produces one rule each.
pub fn parse_spec_token(tok: &str) -> Result<(Protocol, Option<PortRange>)> {
    let tok = tok.trim();
    match tok.split_once(':') {
        Some((proto_str, port_str)) => {
            let proto = parse_protocol(proto_str)?;
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
                bail!(
                    "missing protocol prefix for '{tok}'; use e.g. 'tcp:{tok}' or 'icmp'"
                );
            }
            let proto = parse_protocol(tok)?;
            match proto {
                Protocol::Icmp | Protocol::Any => Ok((proto, None)),
                // Bare `tcp`/`udp` = all ports of that protocol.
                Protocol::Tcp | Protocol::Udp => {
                    Ok((proto, Some(PortRange { start: 0, end: u16::MAX })))
                }
            }
        }
    }
}

/// Build the concrete local firewall rules a node enforces for network `net`,
/// from `suggestions` targeting `my_hostname`. Two subjects apply to a node: its
/// own hostname and the wildcard `*` subject (which targets every node, e.g.
/// "everyone opens 6969"). Peer hostnames are resolved to identities via
/// `resolve` (the blob's member list); unresolved peers are skipped — their rules
/// materialize once they join. The `*` peer key means *any peer* and bypasses
/// resolution. Every rule is inbound, network-scoped to `net`, and tagged
/// `origin: Network(net)`. When any applicable subject has an allow-list, a
/// trailing network-scoped catch-all deny is appended so only the listed peers
/// pass, without touching the global default action. Each port spec token is
/// `proto:ports` or a bare proto keyword (`icmp`, `any`, `tcp`); a comma-separated
/// value yields one rule per token.
pub fn materialize_suggestions(
    net: &str,
    my_hostname: &str,
    suggestions: &SuggestedFirewall,
    resolve: &dyn Fn(&str) -> Option<EndpointId>,
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
                // `*` ⇒ any peer (no resolution); otherwise resolve the hostname.
                let filter = if peer == "*" {
                    PeerFilter::Any
                } else {
                    match resolve(peer) {
                        Some(id) => PeerFilter::Identity(id),
                        None => continue,
                    }
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
    // Whitelist mode: an allow-list is present on any applicable subject ⇒ only
    // listed peers pass, append a network-scoped catch-all deny. A subject with
    // only `denies` (blacklist) or neither list stays open (global default).
    let want_default_deny = applicable.iter().any(|h| !h.allows.is_empty());
    if want_default_deny {
        rules.push(FirewallRule {
            direction: Direction::In,
            action: Action::Deny,
            protocol: Protocol::Any,
            port: None,
            peer: PeerFilter::Any,
            network: Some(net.to_string()),
            origin: RuleOrigin::Network(net.to_string()),
        });
    }
    rules
}

/// Build a display-oriented [`FirewallRuleView`] for one rule, resolving the
/// peer identity to a short id via `short_id`. Used for IPC (the CLI renders /
/// serializes the view) and for value-matching queued suggestions.
pub fn rule_view(rule: &FirewallRule, short_id: &dyn Fn(&EndpointId) -> String) -> FirewallRuleView {
    let peer = match &rule.peer {
        PeerFilter::Any => "any".to_string(),
        PeerFilter::Identity(id) => short_id(id),
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
    };
    FirewallRuleView {
        direction: rule.direction.to_string(),
        action: rule.action.to_string(),
        protocol: rule.protocol.to_string(),
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
mod tests {
    use super::*;

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        iroh::SecretKey::from(key_bytes).public()
    }

    #[test]
    fn parse_valid_ipv4_tcp() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20] = 0x1F; // src port 8080
        pkt[21] = 0x90;
        pkt[22] = 0x01; // dst port 443
        pkt[23] = 0xBB;

        let info = parse_packet_info(&pkt).unwrap();
        assert_eq!(info.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(info.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(info.protocol, 6);
        assert_eq!(info.src_port, 8080);
        assert_eq!(info.dst_port, 443);
    }

    #[test]
    fn parse_udp_packet() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[20] = 0x00;
        pkt[21] = 53; // src port 53
        pkt[22] = 0x04;
        pkt[23] = 0xD2; // dst port 1234

        let info = parse_packet_info(&pkt).unwrap();
        assert_eq!(info.protocol, 17);
        assert_eq!(info.src_port, 53);
        assert_eq!(info.dst_port, 1234);
    }

    #[test]
    fn parse_icmp_no_ports() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 1; // ICMP

        let info = parse_packet_info(&pkt).unwrap();
        assert_eq!(info.protocol, 1);
        assert_eq!(info.src_port, 0);
        assert_eq!(info.dst_port, 0);
    }

    #[test]
    fn parse_too_short() {
        assert!(parse_packet_info(&[0x45; 10]).is_none());
    }

    #[test]
    fn parse_ipv6_basic() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // IPv6
        pkt[6] = 17; // UDP next header
        pkt[24] = 0x02; // dst starts with 0x02 (200::/7)
        let info = parse_packet_info(&pkt).unwrap();
        assert!(info.dst_ip.is_ipv6());
        assert_eq!(info.protocol, 17);
    }

    #[test]
    fn parse_not_ip() {
        let pkt = vec![0x30; 40]; // version nibble 3
        assert!(parse_packet_info(&pkt).is_none());
    }

    #[test]
    fn evaluate_default_allow() {
        let fw = SharedFirewall::new(FirewallConfig::default());
        assert_eq!(
            fw.evaluate(Direction::In, 6, 22, &test_id(1)),
            Action::Allow
        );
    }

    #[test]
    fn evaluate_default_deny() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![],
        });
        assert_eq!(fw.evaluate(Direction::In, 6, 22, &test_id(1)), Action::Deny);
    }

    #[test]
    fn evaluate_deny_specific_port() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Allow,
            rules: vec![FirewallRule {
                direction: Direction::In,
                action: Action::Deny,
                protocol: Protocol::Tcp,
                port: Some(PortRange { start: 22, end: 22 }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        assert_eq!(fw.evaluate(Direction::In, 6, 22, &test_id(1)), Action::Deny);
        assert_eq!(
            fw.evaluate(Direction::In, 6, 80, &test_id(1)),
            Action::Allow
        );
        assert_eq!(
            fw.evaluate(Direction::Out, 6, 22, &test_id(1)),
            Action::Allow
        );
    }

    #[test]
    fn rule_scoped_to_arrival_network() {
        // A deny rule scoped to network "db" must only bite traffic arriving via
        // "db" — letting a multi-homed host (in `db` and `dev`) restrict a peer
        // on one network while leaving the other untouched.
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Allow,
            rules: vec![FirewallRule {
                direction: Direction::In,
                action: Action::Deny,
                protocol: Protocol::Tcp,
                port: Some(PortRange { start: 22, end: 22 }),
                peer: PeerFilter::Any,
                network: Some("db".to_string()),
                origin: RuleOrigin::Local,
            }],
        });
        let info = PacketInfo {
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            protocol: 6,
            src_port: 40000,
            dst_port: 22,
            tcp_flags: 0,
        };
        let peer = test_id(1);
        // Arrives via db -> rule matches -> denied.
        assert_eq!(
            fw.evaluate_packet(Direction::In, &info, &peer, Some("db")),
            Action::Deny
        );
        // Arrives via another network -> rule skipped -> default allow.
        assert_eq!(
            fw.evaluate_packet(Direction::In, &info, &peer, Some("dev")),
            Action::Allow
        );
        // No network context -> network-scoped rule can't match -> default allow.
        assert_eq!(
            fw.evaluate_packet(Direction::In, &info, &peer, None),
            Action::Allow
        );
    }

    #[test]
    fn evaluate_port_range() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![FirewallRule {
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Any,
                port: Some(PortRange {
                    start: 80,
                    end: 443,
                }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        assert_eq!(
            fw.evaluate(Direction::In, 6, 80, &test_id(1)),
            Action::Allow
        );
        assert_eq!(
            fw.evaluate(Direction::In, 17, 443, &test_id(1)),
            Action::Allow
        );
        assert_eq!(fw.evaluate(Direction::In, 6, 22, &test_id(1)), Action::Deny);
    }

    #[test]
    fn evaluate_peer_filter() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![FirewallRule {
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Any,
                port: None,
                peer: PeerFilter::Identity(test_id(1)),
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        assert_eq!(
            fw.evaluate(Direction::In, 6, 22, &test_id(1)),
            Action::Allow
        );
        assert_eq!(fw.evaluate(Direction::In, 6, 22, &test_id(2)), Action::Deny);
    }

    #[test]
    fn evaluate_first_match_wins() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![
                FirewallRule {
                    direction: Direction::In,
                    action: Action::Deny,
                    protocol: Protocol::Tcp,
                    port: Some(PortRange { start: 22, end: 22 }),
                    peer: PeerFilter::Any,
                    network: None,
                    origin: RuleOrigin::Local,
                },
                FirewallRule {
                    direction: Direction::In,
                    action: Action::Allow,
                    protocol: Protocol::Any,
                    port: None,
                    peer: PeerFilter::Any,
                    network: None,
                    origin: RuleOrigin::Local,
                },
            ],
        });
        // SSH denied by first rule even though second allows all
        assert_eq!(fw.evaluate(Direction::In, 6, 22, &test_id(1)), Action::Deny);
        // Other ports allowed by second rule
        assert_eq!(
            fw.evaluate(Direction::In, 6, 80, &test_id(1)),
            Action::Allow
        );
    }

    #[test]
    fn port_range_parsing() {
        let r = parse_port_range("80").unwrap();
        assert_eq!(r, PortRange { start: 80, end: 80 });

        let r = parse_port_range("80-443").unwrap();
        assert_eq!(
            r,
            PortRange {
                start: 80,
                end: 443
            }
        );

        assert!(parse_port_range("443-80").is_err());
        assert!(parse_port_range("abc").is_err());
        // wildcard = all ports
        assert_eq!(parse_port_range("*").unwrap(), PortRange { start: 0, end: u16::MAX });
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = FirewallConfig {
            default_action: Action::Deny,
            rules: vec![FirewallRule {
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let decoded: FirewallConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(decoded.default_action, Action::Deny);
        assert_eq!(decoded.rules.len(), 1);
        assert_eq!(decoded.rules[0].port.as_ref().unwrap().start, 443);
    }

    // -- Stateful connection tracking -----------------------------------------

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const FIN: u8 = 0x01;
    const RST: u8 = 0x04;

    /// Builds a 40-byte IPv4/TCP packet with the given 5-tuple and flags.
    fn tcp_pkt(
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        flags: u8,
    ) -> PacketInfo {
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // IPv4, IHL=5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20] = (src_port >> 8) as u8;
        p[21] = src_port as u8;
        p[22] = (dst_port >> 8) as u8;
        p[23] = dst_port as u8;
        p[32] = 0x50; // data offset 5
        p[33] = flags;
        parse_packet_info(&p).unwrap()
    }

    fn udp_pkt(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16) -> PacketInfo {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20] = (src_port >> 8) as u8;
        p[21] = src_port as u8;
        p[22] = (dst_port >> 8) as u8;
        p[23] = dst_port as u8;
        parse_packet_info(&p).unwrap()
    }

    #[test]
    fn default_allow_plus_deny_in_22_blocks_ssh_but_allows_return() {
        // Recommended pattern: allow basic traffic, block specific ports.
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Allow,
            rules: vec![FirewallRule {
                direction: Direction::In,
                action: Action::Deny,
                protocol: Protocol::Tcp,
                port: Some(PortRange { start: 22, end: 22 }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let peer = Ipv4Addr::new(100, 64, 0, 3);
        let peer_id = test_id(1);

        // Unsolicited inbound to port 22 -> blocked.
        let inbound_ssh = tcp_pkt(peer, 51000, me, 22, SYN);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &inbound_ssh, &peer_id, None),
            Action::Deny
        );

        // Outbound SSH to a peer's port 22 -> allowed (default allow).
        let outbound_ssh = tcp_pkt(me, 54321, peer, 22, SYN);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &outbound_ssh, &peer_id, None),
            Action::Allow
        );

        // Return traffic peer:22 -> me:54321 -> allowed (not matched by deny-in-22,
        // and would be allowed by default anyway).
        let ret = tcp_pkt(peer, 22, me, 54321, ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &ret, &peer_id, None),
            Action::Allow
        );
    }

    #[test]
    fn default_deny_allows_return_traffic_for_initiated_connections() {
        // Strict policy: default deny everywhere, allow outbound HTTPS only.
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![FirewallRule {
                direction: Direction::Out,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let peer = Ipv4Addr::new(100, 64, 0, 3);
        let peer_id = test_id(1);

        // We initiate HTTPS: outbound SYN me:50000 -> peer:443, allowed by rule.
        let syn = tcp_pkt(me, 50000, peer, 443, SYN);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &syn, &peer_id, None),
            Action::Allow
        );

        // Return traffic peer:443 -> me:50000: no explicit rule matches, but the
        // flow is established from our outbound SYN -> allowed.
        let ret = tcp_pkt(peer, 443, me, 50000, SYN | ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &ret, &peer_id, None),
            Action::Allow
        );

        // Unsolicited inbound to some other port -> denied by default.
        let unsolicited = tcp_pkt(peer, 1234, me, 8080, SYN);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &unsolicited, &peer_id, None),
            Action::Deny
        );

        // Outbound to a non-allowed port -> denied by default, and NOT tracked
        // (so its would-be return traffic is also denied).
        let blocked_out = tcp_pkt(me, 40000, peer, 6667, SYN);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &blocked_out, &peer_id, None),
            Action::Deny
        );
        let blocked_ret = tcp_pkt(peer, 6667, me, 40000, ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &blocked_ret, &peer_id, None),
            Action::Deny
        );
    }

    #[test]
    fn tcp_fin_evicts_flow_so_return_traffic_stops() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![FirewallRule {
                direction: Direction::Out,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let peer = Ipv4Addr::new(100, 64, 0, 3);
        let peer_id = test_id(2);

        // Establish the flow.
        let syn = tcp_pkt(me, 50000, peer, 443, SYN);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &syn, &peer_id, None),
            Action::Allow
        );
        let ret = tcp_pkt(peer, 443, me, 50000, ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &ret, &peer_id, None),
            Action::Allow
        );

        // We close with FIN. Flow should be evicted.
        let fin = tcp_pkt(me, 50000, peer, 443, FIN | ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &fin, &peer_id, None),
            Action::Allow
        );

        // Now return traffic from the closed flow is denied again.
        let after = tcp_pkt(peer, 443, me, 50000, ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &after, &peer_id, None),
            Action::Deny
        );
    }

    #[test]
    fn udp_return_traffic_tracked_within_flow() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![FirewallRule {
                direction: Direction::Out,
                action: Action::Allow,
                protocol: Protocol::Udp,
                port: Some(PortRange { start: 53, end: 53 }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let peer = Ipv4Addr::new(100, 64, 0, 3);
        let peer_id = test_id(3);

        // Outbound DNS query me:53000 -> peer:53.
        let q = udp_pkt(me, 53000, peer, 53);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &q, &peer_id, None),
            Action::Allow
        );

        // Return response peer:53 -> me:53000 allowed via established flow.
        let resp = udp_pkt(peer, 53, me, 53000);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &resp, &peer_id, None),
            Action::Allow
        );

        // Unsolicited inbound UDP -> denied.
        let unsolicited = udp_pkt(peer, 9999, me, 53);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &unsolicited, &peer_id, None),
            Action::Deny
        );
    }

    #[test]
    fn explicit_inbound_rule_still_wins_over_established() {
        // If a peer is explicitly denied inbound, established-bypass must NOT
        // override it (explicit rules always win).
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Allow,
            rules: vec![FirewallRule {
                direction: Direction::In,
                action: Action::Deny,
                protocol: Protocol::Tcp,
                port: None,
                peer: PeerFilter::Identity(test_id(9)),
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let peer = Ipv4Addr::new(100, 64, 0, 3);
        let bad_peer = test_id(9);

        // Even if we (somehow) had an outbound flow to bad_peer, inbound from
        // them hits the explicit deny first.
        let syn = tcp_pkt(me, 50000, peer, 443, SYN);
        fw.evaluate_packet(Direction::Out, &syn, &bad_peer, None); // track
        let ret = tcp_pkt(peer, 443, me, 50000, ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &ret, &bad_peer, None),
            Action::Deny
        );
    }

    #[test]
    fn parse_packet_extracts_tcp_flags() {
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let peer = Ipv4Addr::new(100, 64, 0, 3);
        let syn = tcp_pkt(me, 1000, peer, 443, SYN);
        assert_eq!(syn.tcp_flags & SYN, SYN);
        assert_eq!(syn.tcp_flags & ACK, 0);
        let synack = tcp_pkt(peer, 443, me, 1000, SYN | ACK);
        assert_eq!(synack.tcp_flags & (SYN | ACK), SYN | ACK);
    }

    #[test]
    fn tcp_rst_evicts_flow() {
        let fw = SharedFirewall::new(FirewallConfig {
            default_action: Action::Deny,
            rules: vec![FirewallRule {
                direction: Direction::Out,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
                peer: PeerFilter::Any,
                network: None,
                origin: RuleOrigin::Local,
            }],
        });
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let peer = Ipv4Addr::new(100, 64, 0, 3);
        let peer_id = test_id(4);

        let syn = tcp_pkt(me, 50000, peer, 443, SYN);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &syn, &peer_id, None),
            Action::Allow
        );
        let ret = tcp_pkt(peer, 443, me, 50000, ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &ret, &peer_id, None),
            Action::Allow
        );

        // Peer sends RST (inbound). We don't track inbound-eviction, but our own
        // outbound RST should evict. Send an outbound RST.
        let rst = tcp_pkt(me, 50000, peer, 443, RST | ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::Out, &rst, &peer_id, None),
            Action::Allow
        );

        let after = tcp_pkt(peer, 443, me, 50000, ACK);
        assert_eq!(
            fw.evaluate_packet(Direction::In, &after, &peer_id, None),
            Action::Deny
        );
    }

    // -- Suggested firewall materialization -----------------------------------

    use ray_proto::{HostSuggestions, SuggestedFirewall};

    /// Build a one-entry suggestion map for `subject` with the given allows.
    fn suggest(subject: &str, allows: &[(&str, &str)]) -> SuggestedFirewall {
        let mut entry = HostSuggestions::default();
        for (peer, ports) in allows {
            entry.allows.insert((*peer).to_string(), (*ports).to_string());
        }
        let mut map = SuggestedFirewall::new();
        map.insert(subject.to_string(), entry);
        map
    }

    #[test]
    fn materialize_resolves_peer_hostnames_and_expands_comma_ports() {
        let me = test_id(1);
        let peer = test_id(2);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            "peer" => Some(peer),
            _ => None,
        };
        let suggestions = suggest("me", &[("peer", "tcp:9000,tcp:8123")]);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        // Two allow rules (one per port), all inbound, network-scoped, origin prod.
        let allows: Vec<_> = rules
            .iter()
            .filter(|r| r.action == Action::Allow)
            .collect();
        assert_eq!(allows.len(), 2);
        for r in &allows {
            assert_eq!(r.direction, Direction::In);
            assert_eq!(r.network.as_deref(), Some("prod"));
            assert_eq!(r.origin, RuleOrigin::Network("prod".to_string()));
            assert_eq!(r.peer, PeerFilter::Identity(peer));
            assert_eq!(r.protocol, Protocol::Tcp);
        }
        let ports: Vec<u16> = allows
            .iter()
            .map(|r| r.port.as_ref().unwrap().start)
            .collect();
        assert!(ports.contains(&9000));
        assert!(ports.contains(&8123));
    }

    #[test]
    fn materialize_appends_catch_all_deny_with_allow_list() {
        let me = test_id(1);
        let peer = test_id(2);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            "peer" => Some(peer),
            _ => None,
        };
        // An allow-list with no explicit default ⇒ default-deny within network.
        let suggestions = suggest("me", &[("peer", "tcp:9000")]);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        let deny_any = rules.iter().find(|r| {
            r.action == Action::Deny
                && r.peer == PeerFilter::Any
                && r.port.is_none()
                && r.network.as_deref() == Some("prod")
        });
        assert!(deny_any.is_some(), "expected a network-scoped catch-all deny");
    }

    #[test]
    fn materialize_deny_only_blacklist_no_catch_all() {
        // A subject with only `denies` (blacklist mode) does NOT get a
        // catch-all deny — the listed peer is blocked, the rest stays open.
        let me = test_id(1);
        let eve = test_id(3);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            "eve" => Some(eve),
            _ => None,
        };
        let entry = HostSuggestions {
            denies: [("eve".to_string(), "any".to_string())].into(),
            ..Default::default()
        };
        let mut suggestions = SuggestedFirewall::new();
        suggestions.insert("me".to_string(), entry);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        // One deny rule for eve, no catch-all deny.
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, Action::Deny);
        assert_eq!(rules[0].peer, PeerFilter::Identity(eve));
        assert!(rules.iter().all(|r| r.peer != PeerFilter::Any));
    }

    #[test]
    fn materialize_no_allow_list_no_default_keeps_open() {
        let me = test_id(1);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            _ => None,
        };
        // Subject present but no allows and no default ⇒ no catch-all deny.
        let mut suggestions = SuggestedFirewall::new();
        suggestions.insert("me".to_string(), HostSuggestions::default());
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        assert!(rules.is_empty(), "expected no rules for an open subject");
    }

    #[test]
    fn materialize_skips_unresolved_peers() {
        // No resolver ever returns an identity for "ghost".
        let resolve = |_: &str| None;
        let suggestions = suggest("me", &[("ghost", "tcp:9000")]);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        // The allow rule is dropped (peer not joined), but an allow-list is still
        // present, so the catch-all deny remains.
        assert!(rules.iter().all(|r| r.action == Action::Deny));
        assert!(rules.iter().all(|r| r.peer == PeerFilter::Any));
    }

    #[test]
    fn materialize_no_rules_for_unknown_subject() {
        let me = test_id(1);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            _ => None,
        };
        // Suggestions target a different subject.
        let suggestions = suggest("other", &[("me", "tcp:9000")]);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        assert!(rules.is_empty());
    }

    #[test]
    fn materialize_icmp_udp_and_wildcard_tokens() {
        let me = test_id(1);
        let peer = test_id(2);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            "peer" => Some(peer),
            _ => None,
        };
        // One peer, mixed protocols in a single comma-list.
        let suggestions = suggest("me", &[("peer", "icmp,tcp:*,udp:53,any")]);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        let allows: Vec<_> = rules.iter().filter(|r| r.action == Action::Allow).collect();
        // icmp + tcp:* + udp:53 + any = 4 rules.
        assert_eq!(allows.len(), 4);
        let icmp = allows.iter().find(|r| r.protocol == Protocol::Icmp).unwrap();
        assert!(icmp.port.is_none(), "icmp rule must be port-less");
        let tcp_any = allows.iter().find(|r| r.protocol == Protocol::Tcp).unwrap();
        assert_eq!(tcp_any.port.as_ref().unwrap().end, u16::MAX);
        let udp = allows.iter().find(|r| r.protocol == Protocol::Udp).unwrap();
        assert_eq!(udp.port.as_ref().unwrap().start, 53);
        let any = allows.iter().find(|r| r.protocol == Protocol::Any).unwrap();
        assert!(any.port.is_none());
    }

    #[test]
    fn materialize_wildcard_subject_applies_to_any_host() {
        // A `*` subject targets every node, even one whose own hostname has no
        // dedicated entry. The Minecraft case: "everyone opens 6969 to anyone".
        let me = test_id(1);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            _ => None,
        };
        let mut suggestions = SuggestedFirewall::new();
        let mut entry = HostSuggestions::default();
        entry.allows.insert("*".to_string(), "tcp:6969".to_string());
        suggestions.insert("*".to_string(), entry);
        // "me" has no own subject, only the wildcard.
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        let allow = rules
            .iter()
            .find(|r| r.action == Action::Allow)
            .expect("wildcard subject should materialize for any host");
        assert_eq!(allow.peer, PeerFilter::Any, "`*` peer ⇒ any peer");
        assert_eq!(allow.protocol, Protocol::Tcp);
        assert_eq!(allow.port.as_ref().unwrap().start, 6969);
        assert_eq!(allow.network.as_deref(), Some("prod"));
        // Allow-list present ⇒ a catch-all deny is appended.
        assert!(rules.iter().any(|r| r.action == Action::Deny && r.peer == PeerFilter::Any));
    }

    #[test]
    fn materialize_any_peer_star_bypasses_resolution() {
        // A `*` peer key opens the port to anyone, without resolving a hostname.
        let resolve = |_: &str| None; // resolves nothing
        let suggestions = suggest("me", &[("*", "udp:53")]);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        let allow = rules
            .iter()
            .find(|r| r.action == Action::Allow)
            .expect("`*` peer must not be dropped by the resolver");
        assert_eq!(allow.peer, PeerFilter::Any);
        assert_eq!(allow.protocol, Protocol::Udp);
        assert_eq!(allow.port.as_ref().unwrap().start, 53);
    }

    #[test]
    fn materialize_merges_own_subject_and_wildcard() {
        // A node with its own subject AND a wildcard subject gets both rule sets.
        let me = test_id(1);
        let peer = test_id(2);
        let resolve = |h: &str| match h {
            "me" => Some(me),
            "peer" => Some(peer),
            _ => None,
        };
        let mut suggestions = suggest("me", &[("peer", "tcp:22")]);
        let mut wild = HostSuggestions::default();
        wild.allows.insert("*".to_string(), "tcp:6969".to_string());
        suggestions.insert("*".to_string(), wild);
        let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
        let allows: Vec<_> = rules.iter().filter(|r| r.action == Action::Allow).collect();
        assert_eq!(allows.len(), 2, "own subject + wildcard subject");
        assert!(allows.iter().any(|r| r.peer == PeerFilter::Identity(peer)
            && r.port.as_ref().unwrap().start == 22));
        assert!(allows.iter().any(|r| r.peer == PeerFilter::Any
            && r.port.as_ref().unwrap().start == 6969));
    }

    #[test]
    fn parse_spec_token_grammar() {
        // proto:port
        let (p, r) = parse_spec_token("tcp:22").unwrap();
        assert_eq!(p, Protocol::Tcp);
        assert_eq!(r.unwrap().start, 22);
        // proto:range
        let (p, r) = parse_spec_token("tcp:80-443").unwrap();
        assert_eq!(p, Protocol::Tcp);
        assert_eq!(r.unwrap().end, 443);
        // proto:wildcard
        let (p, r) = parse_spec_token("udp:*").unwrap();
        assert_eq!(p, Protocol::Udp);
        assert_eq!(r.unwrap().end, u16::MAX);
        // bare icmp → port-less
        let (p, r) = parse_spec_token("icmp").unwrap();
        assert_eq!(p, Protocol::Icmp);
        assert!(r.is_none());
        // icmp:* == icmp (port ignored)
        let (p, r) = parse_spec_token("icmp:*").unwrap();
        assert_eq!(p, Protocol::Icmp);
        assert!(r.is_none());
        // bare any → port-less
        let (p, r) = parse_spec_token("any").unwrap();
        assert_eq!(p, Protocol::Any);
        assert!(r.is_none());
        // bare tcp → all ports
        let (p, r) = parse_spec_token("tcp").unwrap();
        assert_eq!(p, Protocol::Tcp);
        assert_eq!(r.unwrap().end, u16::MAX);
        // bare number → error (no implicit tcp)
        assert!(parse_spec_token("22").is_err());
        // unknown proto → error
        assert!(parse_spec_token("foo:22").is_err());
        // empty port after colon → error
        assert!(parse_spec_token("tcp:").is_err());
    }

    #[test]
    fn replace_network_rules_swaps_network_set_keeps_local() {
        let local_rule = FirewallRule {
            direction: Direction::In,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            port: Some(PortRange { start: 22, end: 22 }),
            peer: PeerFilter::Any,
            network: None,
            origin: RuleOrigin::Local,
        };
        let stale_net = FirewallRule {
            direction: Direction::In,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            port: Some(PortRange { start: 9000, end: 9000 }),
            peer: PeerFilter::Identity(test_id(9)),
            network: Some("prod".to_string()),
            origin: RuleOrigin::Network("prod".to_string()),
        };
        // A rule from a *different* network must survive a prod replace.
        let other_net = FirewallRule {
            direction: Direction::In,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            port: Some(PortRange { start: 8080, end: 8080 }),
            peer: PeerFilter::Any,
            network: Some("dev".to_string()),
            origin: RuleOrigin::Network("dev".to_string()),
        };
        let config = FirewallConfig {
            default_action: Action::Allow,
            rules: vec![local_rule.clone(), stale_net, other_net.clone()],
        };
        let fw = SharedFirewall::new(config);

        let fresh = FirewallRule {
            direction: Direction::In,
            action: Action::Deny,
            protocol: Protocol::Any,
            port: None,
            peer: PeerFilter::Any,
            network: Some("prod".to_string()),
            origin: RuleOrigin::Network("prod".to_string()),
        };
        let updated = fw.replace_network_rules("prod", vec![fresh.clone()]);

        // Local + other-network rules preserved; prod set fully replaced.
        assert!(updated.rules.iter().any(|r| r.origin == RuleOrigin::Local));
        assert!(updated
            .rules
            .iter()
            .any(|r| matches!(&r.origin, RuleOrigin::Network(n) if n == "dev")));
        let prod: Vec<_> = updated
            .rules
            .iter()
            .filter(|r| matches!(&r.origin, RuleOrigin::Network(n) if n == "prod"))
            .collect();
        assert_eq!(prod.len(), 1);
        assert_eq!(prod[0].action, Action::Deny);
        assert_eq!(prod[0].peer, PeerFilter::Any);
    }
}
