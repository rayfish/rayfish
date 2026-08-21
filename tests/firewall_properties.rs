//! Property tests for the per-packet data path: the IP parser
//! (`firewall::parse_packet_info`) and stateful rule evaluation
//! (`SharedFirewall::evaluate_packet`).
//!
//! These are the only functions in the crate that run on bytes chosen by a
//! remote peer, so the properties here are about what must hold for *every*
//! input, not for a handful of hand-written packets. The unit tests in
//! `src/firewall.rs` cover the concrete cases; this file covers the space
//! around them.
//!
//! Kept out of `src/` so the proptest dependency and the slower runtime stay
//! isolated from `cargo test --lib`.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::{assert_info_eq, packet_spec};
use proptest::prelude::*;
use rayfish::firewall::{
    Action, Direction, FirewallConfig, FirewallRule, PacketInfo, PeerFilter, PortRange, Protocol,
    RuleOrigin, SharedFirewall, parse_packet_info,
};

use iroh::EndpointId;

fn test_id(seed: u8) -> EndpointId {
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = seed;
    iroh::SecretKey::from(key_bytes).public()
}

// ---------------------------------------------------------------------------
// Parser properties
// ---------------------------------------------------------------------------

proptest! {
    /// The parser runs on remote bytes before anything has validated them. It
    /// must return `None` rather than panic, whatever it is handed.
    #[test]
    fn parser_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_packet_info(&bytes);
    }

    /// Every field the parser reports for a well-formed packet is the field
    /// that was encoded into it.
    #[test]
    fn parse_recovers_encoded_fields(spec in packet_spec()) {
        let pkt = spec.encode();
        let info = parse_packet_info(&pkt).expect("well-formed packet must parse");
        assert_info_eq(&info, &spec.expected())?;
    }

    /// The refusal the round-trip property above is filtered around. An IPv6
    /// next header naming an extension header means byte 6 is not the
    /// upper-layer protocol and offset 40 is not the ports, so the parser cannot
    /// answer and must say so rather than report a protocol of 44 with no ports:
    /// the conntrack key is built from exactly those fields.
    #[test]
    fn ipv6_extension_headers_are_refused(
        nh in prop::sample::select(&rayfish::firewall::IPV6_EXTENSION_HEADERS[..]),
        spec in packet_spec(),
    ) {
        let mut pkt = spec.encode();
        // Force the packet to v6 with an extension header in the next-header slot.
        let mut v6 = vec![0u8; 60];
        v6[0] = 0x60;
        v6[4..6].copy_from_slice(&20u16.to_be_bytes());
        v6[6] = nh;
        v6[7] = 64;
        v6[24] = 0x02;
        prop_assert!(parse_packet_info(&v6).is_none(), "next header {} must not parse", nh);
        // And the IPv4 packet with the same protocol number is unaffected: these
        // values are only extension headers in IPv6.
        if !spec.v6 {
            pkt[9] = nh;
            prop_assert!(parse_packet_info(&pkt).is_some());
        }
    }

    /// The version nibble is the parser's dispatch key: anything other than 4
    /// or 6 has no defined layout and must be rejected outright.
    #[test]
    fn unknown_version_rejected(
        version in 0u8..16,
        rest in prop::collection::vec(any::<u8>(), 60..80),
    ) {
        prop_assume!(version != 4 && version != 6);
        let mut pkt = rest;
        pkt[0] = (version << 4) | (pkt[0] & 0x0F);
        prop_assert!(parse_packet_info(&pkt).is_none());
    }

    /// A truncated packet must never yield a field read from bytes that
    /// aren't there. Fields whose bytes survive the truncation keep their
    /// value; fields that don't read back as zero.
    #[test]
    fn truncation_never_invents_fields(spec in packet_spec(), cut in 0usize..80) {
        let pkt = spec.encode();
        let cut = cut.min(pkt.len());
        let Some(info) = parse_packet_info(&pkt[..cut]) else {
            return Ok(());
        };
        let want = spec.expected();
        let l4 = spec.header_len();

        prop_assert_eq!(info.src_ip, want.src_ip);
        prop_assert_eq!(info.dst_ip, want.dst_ip);
        prop_assert_eq!(info.protocol, want.protocol);

        let ports_present = cut >= l4 + 4;
        prop_assert_eq!(info.src_port, if ports_present { want.src_port } else { 0 });
        prop_assert_eq!(info.dst_port, if ports_present { want.dst_port } else { 0 });

        let flags_present = cut >= l4 + 14;
        prop_assert_eq!(info.tcp_flags, if flags_present { want.tcp_flags } else { 0 });

        // i.e. `cut >= l4 + 1`, spelled to match the other bounds; clippy
        // prefers the subtraction-free form.
        let icmp_type_present = cut > l4;
        prop_assert_eq!(info.icmp_type, if icmp_type_present { want.icmp_type } else { 0 });

        let icmp_id_present = cut >= l4 + 6;
        prop_assert_eq!(info.icmp_id, if icmp_id_present { want.icmp_id } else { 0 });
    }

    /// An IPv4 header claiming fewer than 5 words (20 bytes) is malformed: the
    /// header cannot fit the addresses the parser then reads. Such a packet
    /// must be rejected, not parsed with a header length that overlaps the
    /// header's own bytes.
    #[test]
    fn short_ihl_rejected(spec in packet_spec(), ihl in 0u8..5) {
        let mut spec = spec;
        spec.v6 = false;
        spec.src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        spec.dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        spec.ihl = 5;
        let mut pkt = spec.encode();
        pkt[0] = 0x40 | ihl;
        prop_assert!(
            parse_packet_info(&pkt).is_none(),
            "IPv4 packet with ihl={} must be rejected",
            ihl,
        );
    }
}

// ---------------------------------------------------------------------------
// Rule and config generation
// ---------------------------------------------------------------------------

fn port_range() -> impl Strategy<Value = PortRange> {
    (any::<u16>(), any::<u16>()).prop_map(|(a, b)| PortRange {
        start: a.min(b),
        end: a.max(b),
    })
}

fn rule_strategy() -> impl Strategy<Value = FirewallRule> {
    (
        prop_oneof![Just(Direction::In), Just(Direction::Out)],
        prop_oneof![Just(Action::Allow), Just(Action::Deny)],
        prop_oneof![
            Just(Protocol::Any),
            Just(Protocol::Tcp),
            Just(Protocol::Udp),
            Just(Protocol::Icmp)
        ],
        prop::option::of(port_range()),
        prop_oneof![
            2 => Just(PeerFilter::Any),
            1 => (0u8..4).prop_map(|s| PeerFilter::Identity(test_id(s))),
        ],
        prop_oneof![
            2 => Just(None),
            1 => (0usize..3).prop_map(|i| Some(format!("net{i}"))),
        ],
    )
        .prop_map(
            |(direction, action, protocol, port, peer, network)| FirewallRule {
                direction,
                action,
                protocol,
                port,
                peer,
                network,
                origin: RuleOrigin::Local,
            },
        )
}

fn config_strategy() -> impl Strategy<Value = FirewallConfig> {
    (
        prop::collection::vec(rule_strategy(), 0..8),
        prop_oneof![Just(Action::Allow), Just(Action::Deny)],
        prop_oneof![Just(Action::Allow), Just(Action::Deny)],
    )
        .prop_map(
            |(rules, default_inbound, default_outbound)| FirewallConfig {
                default_inbound,
                default_outbound,
                reject: false,
                disabled: false,
                rules,
            },
        )
}

/// Evaluation records conntrack state, so every property that cares only
/// about the rule decision evaluates on a fresh instance.
fn verdict(
    config: FirewallConfig,
    direction: Direction,
    info: &PacketInfo,
    peer: &EndpointId,
    network: Option<&str>,
) -> Action {
    SharedFirewall::new(config).evaluate_packet(direction, info, peer, network)
}

/// Whether `rule` selects this packet, determined by observation rather than
/// by reimplementing the matcher: evaluate a config holding only `rule`, with
/// both defaults set to the opposite action. The rule's action can then only
/// come out if the rule actually matched.
fn rule_matches(
    rule: &FirewallRule,
    direction: Direction,
    info: &PacketInfo,
    peer: &EndpointId,
    network: Option<&str>,
) -> bool {
    let opposite = match rule.action {
        Action::Allow => Action::Deny,
        Action::Deny => Action::Allow,
    };
    let probe = FirewallConfig {
        default_inbound: opposite,
        default_outbound: opposite,
        reject: false,
        disabled: false,
        rules: vec![rule.clone()],
    };
    verdict(probe, direction, info, peer, network) == rule.action
}

fn direction_strategy() -> impl Strategy<Value = Direction> {
    prop_oneof![Just(Direction::In), Just(Direction::Out)]
}

fn network_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        1 => Just(None),
        2 => (0usize..3).prop_map(|i| Some(format!("net{i}"))),
    ]
}

// ---------------------------------------------------------------------------
// Evaluation properties
// ---------------------------------------------------------------------------

proptest! {
    /// Secure-by-default: on a fresh config, no inbound TCP or UDP packet is
    /// ever allowed, and no outbound packet is ever denied. Only ICMP has an
    /// inbound exception, via the seeded rule.
    #[test]
    fn default_config_denies_inbound_tcp_udp(
        spec in packet_spec(),
        seed in 0u8..4,
        network in network_strategy(),
    ) {
        prop_assume!(spec.protocol == 6 || spec.protocol == 17);
        let info = spec.expected();
        let peer = test_id(seed);

        prop_assert_eq!(
            verdict(FirewallConfig::default(), Direction::In, &info, &peer, network.as_deref()),
            Action::Deny,
        );
        prop_assert_eq!(
            verdict(FirewallConfig::default(), Direction::Out, &info, &peer, network.as_deref()),
            Action::Allow,
        );
    }

    /// `ray firewall off` is unconditional: no rule set, default, or direction
    /// can produce a deny while it is set.
    #[test]
    fn disabled_allows_everything(
        config in config_strategy(),
        spec in packet_spec(),
        direction in direction_strategy(),
        seed in 0u8..4,
        network in network_strategy(),
    ) {
        let config = FirewallConfig { disabled: true, ..config };
        let info = spec.expected();
        prop_assert_eq!(
            verdict(config, direction, &info, &test_id(seed), network.as_deref()),
            Action::Allow,
        );
    }

    /// A config that can only say "deny" cannot be talked into an allow: with
    /// every inbound rule denying and the inbound default denying, no inbound
    /// packet is allowed. Conntrack is included in the claim, since return
    /// traffic is checked only after the rules fail to match.
    #[test]
    fn all_deny_config_never_allows_inbound(
        config in config_strategy(),
        spec in packet_spec(),
        seed in 0u8..4,
        network in network_strategy(),
    ) {
        let rules = config.rules.into_iter()
            .map(|r| FirewallRule { action: Action::Deny, ..r })
            .collect();
        let config = FirewallConfig {
            default_inbound: Action::Deny,
            rules,
            ..config
        };
        let info = spec.expected();
        prop_assert_eq!(
            verdict(config, Direction::In, &info, &test_id(seed), network.as_deref()),
            Action::Deny,
        );
    }

    /// First-match-wins, stated as a property: prepending a rule changes the
    /// verdict to that rule's action when it matches the packet, and changes
    /// nothing when it doesn't.
    #[test]
    fn prepended_rule_wins_iff_it_matches(
        config in config_strategy(),
        rule in rule_strategy(),
        spec in packet_spec(),
        direction in direction_strategy(),
        seed in 0u8..4,
        network in network_strategy(),
    ) {
        let info = spec.expected();
        let peer = test_id(seed);
        let net = network.as_deref();

        let before = verdict(config.clone(), direction, &info, &peer, net);

        let mut rules = vec![rule.clone()];
        rules.extend(config.rules.iter().cloned());
        let extended = FirewallConfig { rules, ..config };
        let after = verdict(extended, direction, &info, &peer, net);

        if rule.direction == direction && rule_matches(&rule, direction, &info, &peer, net) {
            prop_assert_eq!(after, rule.action);
        } else {
            prop_assert_eq!(after, before);
        }
    }

    /// Conntrack admits the return packet of a flow this device opened, even
    /// under the default inbound deny: the reply's source is the destination
    /// we sent to, and vice versa.
    #[test]
    fn conntrack_admits_return_traffic(spec in packet_spec(), seed in 0u8..4) {
        prop_assume!(spec.protocol == 6 || spec.protocol == 17);
        // A FIN or RST closes the flow on the way out by design.
        prop_assume!(spec.protocol != 6 || spec.tcp_flags & 0x05 == 0);
        let out = spec.expected();
        prop_assume!(out.src_port != out.dst_port || out.src_ip != out.dst_ip);

        let fw = SharedFirewall::new(FirewallConfig::default());
        let peer = test_id(seed);

        prop_assert_eq!(fw.evaluate_packet(Direction::Out, &out, &peer, None), Action::Allow);

        let reply = PacketInfo {
            src_ip: out.dst_ip,
            dst_ip: out.src_ip,
            src_port: out.dst_port,
            dst_port: out.src_port,
            ..out
        };
        prop_assert_eq!(fw.evaluate_packet(Direction::In, &reply, &peer, None), Action::Allow);
    }

    /// Conntrack admits *only* that flow. An inbound packet that differs in
    /// any endpoint field is not return traffic and stays denied.
    #[test]
    fn conntrack_does_not_admit_other_flows(
        spec in packet_spec(),
        seed in 0u8..4,
        other_port in any::<u16>(),
    ) {
        prop_assume!(spec.protocol == 6 || spec.protocol == 17);
        prop_assume!(spec.protocol != 6 || spec.tcp_flags & 0x05 == 0);
        let out = spec.expected();
        prop_assume!(other_port != out.dst_port);

        let fw = SharedFirewall::new(FirewallConfig::default());
        let peer = test_id(seed);
        prop_assert_eq!(fw.evaluate_packet(Direction::Out, &out, &peer, None), Action::Allow);

        // Same flow except for the peer's port: a different connection.
        let unrelated = PacketInfo {
            src_ip: out.dst_ip,
            dst_ip: out.src_ip,
            src_port: other_port,
            dst_port: out.src_port,
            ..out
        };
        prop_assert_eq!(
            fw.evaluate_packet(Direction::In, &unrelated, &peer, None),
            Action::Deny,
        );
    }

    /// An inbound ICMP echo *request* is someone pinging us, never return
    /// traffic. Having sent a ping must not open the door to receiving them,
    /// so with the seeded ICMP rule removed a request stays denied.
    #[test]
    fn outbound_ping_does_not_admit_inbound_pings(spec in packet_spec(), seed in 0u8..4) {
        prop_assume!(spec.protocol == 1 || spec.protocol == 58);
        let echo_request = if spec.protocol == 1 { 8 } else { 128 };
        let mut spec = spec;
        spec.icmp_type = echo_request;
        let out = spec.expected();

        // Deny-inbound with no ICMP allowance: conntrack is the only thing
        // that could let the request through, and it must not.
        let config = FirewallConfig {
            default_inbound: Action::Deny,
            default_outbound: Action::Allow,
            reject: false,
            disabled: false,
            rules: vec![],
        };
        let fw = SharedFirewall::new(config);
        let peer = test_id(seed);

        prop_assert_eq!(fw.evaluate_packet(Direction::Out, &out, &peer, None), Action::Allow);

        let inbound_request = PacketInfo {
            src_ip: out.dst_ip,
            dst_ip: out.src_ip,
            ..out
        };
        prop_assert_eq!(
            fw.evaluate_packet(Direction::In, &inbound_request, &peer, None),
            Action::Deny,
        );
    }
}
