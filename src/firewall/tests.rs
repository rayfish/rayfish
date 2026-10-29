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
    // 48 bytes, not 40: a UDP packet carries a UDP header, and one that does
    // not has no ports to key a conntrack entry on. See `parse_ipv6`.
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x60; // IPv6
    pkt[6] = 17; // UDP next header
    pkt[24] = 0x02; // dst starts with 0x02 (200::/7)
    let info = parse_packet_info(&pkt).unwrap();
    assert!(info.dst_ip.is_ipv6());
    assert_eq!(info.protocol, 17);

    // The header alone is refused rather than reported with ports of zero.
    assert!(parse_packet_info(&pkt[..40]).is_none());
}

#[test]
fn parse_not_ip() {
    let pkt = vec![0x30; 40]; // version nibble 3
    assert!(parse_packet_info(&pkt).is_none());
}

/// An extension header is walked past rather than read as the upper-layer
/// protocol, and the transport offset records where the walk ended. See
/// [`IPV6_EXTENSION_HEADERS`].
#[test]
fn an_ipv6_extension_header_is_walked_past_to_the_real_protocol() {
    // Hop-by-hop, then TCP. The `hdr_ext_len` of 0 means 8 octets, so the
    // TCP header starts at 48 and its ports are there, not at 40.
    let mut pkt = ipv6_tcp(&[(0u8, 0u8)], 48);
    assert_eq!(
        parse_packet_info(&pkt).map(|i| (i.protocol, i.src_port, i.dst_port)),
        Some((6, 4444, 443)),
        "byte 6 is the chain's first link, not the protocol"
    );
    assert_eq!(
        parse_packet_info(&pkt).map(|i| i.transport_offset),
        Some(48)
    );

    // Two links deep: hop-by-hop, destination options, then TCP at 56.
    pkt = ipv6_tcp(&[(0u8, 0u8), (60u8, 0u8)], 56);
    assert_eq!(
        parse_packet_info(&pkt).map(|i| (i.protocol, i.dst_port)),
        Some((6, 443))
    );

    // The upper-layer protocols with no chain at all still parse.
    for nh in [6u8, 17, 58] {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60;
        pkt[6] = nh;
        pkt[24] = 0x02;
        assert_eq!(parse_packet_info(&pkt).map(|i| i.protocol), Some(nh));
    }
}

/// The Authentication Header is the one link measured in 4-octet units, and
/// minus 2 rather than plus 1 (RFC 4302 §2.2). Applying the ordinary formula
/// walks into the middle of the payload and reads two arbitrary bytes as the
/// ports, so the arithmetic is pinned rather than left to review.
#[test]
fn the_authentication_headers_length_is_in_its_own_units() {
    // `hdr_ext_len` 4 means (4 + 2) * 4 = 24 octets, so TCP starts at 64.
    // The TLV formula would say (4 + 1) * 8 = 40 and look at 80.
    let pkt = ipv6_tcp(&[(IPV6_AH, 4u8)], 64);
    assert_eq!(
        parse_packet_info(&pkt).map(|i| (i.protocol, i.dst_port)),
        Some((6, 443))
    );
}

/// A TLV link is not always 8 octets, and every other test here happens to
/// use one that is.
///
/// `hdr_ext_len` counts 8-octet units *after* the first 8, so it is zero on
/// the minimum-size header a fixture reaches for by default. Treating the
/// length as the constant 8 therefore passes every one of those and still
/// reads the ports out of the middle of a hop-by-hop header carrying a single
/// option, which is ordinary traffic (a jumbogram, an MLD router alert).
#[test]
fn a_tlv_links_length_is_read_and_not_assumed() {
    // Hop-by-hop with `hdr_ext_len` 2, so (2 + 1) * 8 = 24 octets and TCP
    // starts at 64. Assuming 8 would look at 48, inside the option data.
    let pkt = ipv6_tcp(&[(0u8, 2u8)], 64);
    assert_eq!(
        parse_packet_info(&pkt).map(|i| (i.protocol, i.dst_port)),
        Some((6, 443))
    );

    // The same, one link further in: a destination-options header behind it,
    // so a chain of two differently-sized TLVs has to be walked, not counted.
    let pkt = ipv6_tcp(&[(0u8, 2u8), (60u8, 1u8)], 80);
    assert_eq!(
        parse_packet_info(&pkt).map(|i| (i.protocol, i.dst_port)),
        Some((6, 443))
    );
}

/// Every fragment is refused as a whole packet, whichever end of the
/// datagram it is.
///
/// The later ones have to be: they carry no L4 header, so keying them meant
/// inventing `(44, 0, 0)`, which is the wildcard this whole walk exists to
/// stop. The first one could be classified, but on its own it only buys
/// permission to forward one fragment of a datagram whose siblings are
/// dropped. Fragments take their own path instead (`parse_ipv6_fragment`,
/// then `forward::frag_verdicts`), where the first decides for the rest.
#[test]
fn every_fragment_of_a_datagram_is_refused() {
    // Fragment header (8 octets), then TCP at 48. Offset 0, more-fragments
    // set: the first fragment of a large datagram.
    let mut first = ipv6_tcp(&[(IPV6_FRAGMENT, 0u8)], 48);
    first[42..44].copy_from_slice(&1u16.to_be_bytes()); // offset 0, M = 1
    assert!(
        parse_packet_info(&first).is_none(),
        "a first fragment is deliverable only if its siblings are, and they are not"
    );

    // The same datagram's second fragment: offset 185 (1480 octets in).
    let mut later = first.clone();
    later[42..44].copy_from_slice(&(185u16 << 3).to_be_bytes());
    assert!(
        parse_packet_info(&later).is_none(),
        "a non-first fragment has no ports to read, so it cannot be classified"
    );

    // The same packet without the fragment header still parses: it is the
    // fragmentation that is refused, not the traffic.
    let whole = ipv6_tcp(&[], 40);
    assert_eq!(
        parse_packet_info(&whole).map(|i| (i.protocol, i.dst_port)),
        Some((6, 443))
    );
}

/// The bypass itself, end to end: one outbound fragment must not open a hole
/// that inbound traffic can walk through. Before the chain walk both packets
/// parsed as `(proto 44, ports 0/0)`, which is the same `Flow`, so
/// `track_outbound` whitelisted every fragment the peer cared to send.
#[test]
fn an_outbound_fragment_does_not_whitelist_inbound_traffic() {
    let fw = SharedFirewall::new(FirewallConfig::default());
    let peer = test_id(1);
    let mut us = [0u8; 16];
    us[0] = 0x02;
    us[15] = 1;
    let mut them = [0u8; 16];
    them[0] = 0x02;
    them[15] = 2;
    // A later fragment of a large UDP send, in each direction.
    let frag = |src: [u8; 16], dst: [u8; 16]| {
        let mut pkt = ipv6_tcp(&[(IPV6_FRAGMENT, 0u8)], 48);
        pkt[42..44].copy_from_slice(&(185u16 << 3).to_be_bytes());
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt
    };

    let out = parse_packet_info(&frag(us, them));
    assert!(out.is_none(), "an unclassifiable packet opens no flow");

    // Inbound from the same peer: must not be rescued by conntrack.
    let inbound = parse_packet_info(&frag(them, us));
    assert!(inbound.is_none(), "and none is waiting to rescue this one");

    // The default inbound policy is what such a packet now meets instead.
    assert_eq!(fw.evaluate(Direction::In, 6, 22, &peer), Action::Deny);

    // Nor does the first fragment open one. It could be classified, but the
    // datagram behind it cannot be delivered, so forwarding it would open a
    // conntrack entry on the strength of a send that never completes.
    let mut first = ipv6_tcp(&[(IPV6_FRAGMENT, 0u8)], 48);
    first[42..44].copy_from_slice(&1u16.to_be_bytes());
    first[8..24].copy_from_slice(&us);
    first[24..40].copy_from_slice(&them);
    assert!(
        parse_packet_info(&first).is_none(),
        "a first fragment opens no flow either"
    );

    // The same send under the MTU is unaffected: it is fragmentation that is
    // refused, and it keys on its own port, so a flow to :443 never admits :22.
    let mut whole = ipv6_tcp(&[], 40);
    whole[8..24].copy_from_slice(&us);
    whole[24..40].copy_from_slice(&them);
    let info = parse_packet_info(&whole).expect("an unfragmented send is classifiable");
    assert_eq!((info.protocol, info.dst_port), (6, 443));
}

/// A chain that never reaches a protocol must not be walked forever, and a
/// chain that runs off the end of the packet must not be read past it.
#[test]
fn a_chain_that_goes_nowhere_is_refused_rather_than_followed() {
    // Every link says "hop-by-hop next", so the walk never terminates.
    let mut pkt = vec![0u8; 200];
    pkt[0] = 0x60;
    pkt[6] = 0;
    pkt[24] = 0x02;
    assert!(parse_packet_info(&pkt).is_none(), "the depth cap must hold");

    // A length that points past the last byte.
    let mut pkt = vec![0u8; 60];
    pkt[0] = 0x60;
    pkt[6] = 0;
    pkt[24] = 0x02;
    pkt[40] = 6; // next = TCP
    pkt[41] = 200; // ... 1608 octets away, which is not in this packet
    assert!(parse_packet_info(&pkt).is_none());

    // `No Next Header` (59) ends the chain, but it is a protocol number
    // rather than a link: it keys as `(59, 0, 0)`, which is per-protocol and
    // not the cross-protocol wildcard the walk exists to stop.
    let mut pkt = ipv6_tcp(&[(0u8, 0u8)], 48);
    pkt[40] = 59;
    assert_eq!(
        parse_packet_info(&pkt).map(|i| (i.protocol, i.src_port, i.dst_port)),
        Some((59, 0, 0))
    );
}

/// A non-first IPv4 fragment has the same missing L4 header as its IPv6 twin.
/// Nothing on the mesh produces IPv4 any more, so this guards the path rather
/// than fixing a live bug, and it costs one comparison to keep it guarded.
#[test]
fn a_non_first_ipv4_fragment_is_refused() {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[100, 64, 0, 5]);
    pkt[16..20].copy_from_slice(&[100, 64, 0, 9]);
    pkt[22] = 1;
    pkt[23] = 0xbb; // "dst port" 443, which is payload on a later fragment
    assert!(parse_packet_info(&pkt).is_some(), "offset 0 parses");

    // Fragment offset 185, i.e. 1480 octets into the datagram.
    pkt[6..8].copy_from_slice(&185u16.to_be_bytes());
    assert!(parse_packet_info(&pkt).is_none());
}

/// An IPv6 packet whose extension chain is `links` in wire order, each
/// `(kind, hdr_ext_len)`, followed by a TCP header at `tcp_off`. Ports are
/// 4444 and 443, so a walk that lands anywhere else reads zeros and the
/// caller's assertion fails rather than passing on a coincidence.
///
/// `tcp_off` is passed rather than returned so the fixture and the test agree
/// on where the header should be; a mismatch is the fixture's own bug and is
/// asserted here.
fn ipv6_tcp(links: &[(u8, u8)], tcp_off: usize) -> Vec<u8> {
    let mut pkt = vec![0u8; tcp_off + 20];
    pkt[0] = 0x60;
    pkt[24] = 0x02; // an overlay destination, so callers take the firewall path
    pkt[6] = links.first().map(|(kind, _)| *kind).unwrap_or(6);
    let mut off = 40;
    for (i, (kind, len)) in links.iter().enumerate() {
        // The next link, or the upper-layer protocol once the chain runs out.
        pkt[off] = links.get(i + 1).map(|(k, _)| *k).unwrap_or(6);
        // Reserved on a Fragment header, a length everywhere else.
        pkt[off + 1] = *len;
        off += match *kind {
            IPV6_FRAGMENT => 8,
            IPV6_AH => (usize::from(*len) + 2) * 4,
            _ => (usize::from(*len) + 1) * 8,
        };
    }
    assert_eq!(off, tcp_off, "the fixture disagrees with its own tcp_off");
    pkt[tcp_off..tcp_off + 2].copy_from_slice(&4444u16.to_be_bytes());
    pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&443u16.to_be_bytes());
    pkt
}

#[test]
fn default_config_is_secure_inbound() {
    // The built-in default: inbound TCP/UDP denied, inbound ICMP allowed,
    // outbound (any proto) allowed.
    let fw = SharedFirewall::new(FirewallConfig::default());
    // Inbound TCP and UDP to a service port -> denied.
    assert_eq!(fw.evaluate(Direction::In, 6, 22, &test_id(1)), Action::Deny);
    assert_eq!(
        fw.evaluate(Direction::In, 17, 53, &test_id(1)),
        Action::Deny
    );
    // Inbound ICMPv4 and ICMPv6 -> allowed (reachability out of the box).
    assert_eq!(fw.evaluate(Direction::In, 1, 0, &test_id(1)), Action::Allow);
    assert_eq!(
        fw.evaluate(Direction::In, 58, 0, &test_id(1)),
        Action::Allow
    );
    // Outbound any proto -> allowed.
    assert_eq!(
        fw.evaluate(Direction::Out, 6, 443, &test_id(1)),
        Action::Allow
    );
    assert_eq!(
        fw.evaluate(Direction::Out, 17, 53, &test_id(1)),
        Action::Allow
    );
}

#[test]
fn default_config_seeds_one_removable_icmp_rule() {
    // The ICMP-allow is an ordinary visible rule, not a hidden default.
    let config = FirewallConfig::default();
    assert_eq!(config.rules.len(), 1);
    let r = &config.rules[0];
    assert_eq!(r.direction, Direction::In);
    assert_eq!(r.action, Action::Allow);
    assert_eq!(r.protocol, Protocol::Icmp);
    assert_eq!(r.peer, PeerFilter::Any);
    assert_eq!(r.origin, RuleOrigin::Local); // hand-removable, survives reconverge
}

#[test]
fn removing_seeded_icmp_rule_denies_icmp() {
    // The whole point of seeding it as a rule: delete it and ICMP falls
    // through to the deny-inbound default.
    let mut config = FirewallConfig::default();
    config.rules.clear();
    let fw = SharedFirewall::new(config);
    assert_eq!(fw.evaluate(Direction::In, 1, 0, &test_id(1)), Action::Deny);
    assert_eq!(fw.evaluate(Direction::In, 58, 0, &test_id(1)), Action::Deny);
}

#[test]
fn same_selector_ignores_action_and_origin_but_not_match_fields() {
    let allow_icmp = default_icmp_rule();
    let deny_icmp = FirewallRule {
        action: Action::Deny,
        ..default_icmp_rule()
    };
    // Same direction/proto/port/peer/network, opposite action -> same selector.
    assert!(same_selector(&allow_icmp, &deny_icmp));
    // A peer-scoped variant is a *different* selector (narrower), so it layers
    // rather than replacing the broad rule.
    let deny_icmp_peer = FirewallRule {
        action: Action::Deny,
        peer: PeerFilter::Identity(test_id(7)),
        ..default_icmp_rule()
    };
    assert!(!same_selector(&allow_icmp, &deny_icmp_peer));
}

#[test]
fn merge_same_selector_then_prepend_makes_latest_win() {
    // Mirrors what the `firewall add` IPC handler does: drop the old
    // same-selector rule and prepend the new one. Adding `deny in icmp` over
    // the seeded `allow in icmp` must (a) leave exactly one ICMP rule and
    // (b) make deny prevail.
    let mut rules = vec![default_icmp_rule()];
    let deny_icmp = FirewallRule {
        action: Action::Deny,
        ..default_icmp_rule()
    };
    rules.retain(|r| !same_selector(r, &deny_icmp));
    rules.insert(0, deny_icmp);
    assert_eq!(rules.len(), 1, "merged, not accumulated");
    let fw = SharedFirewall::new(FirewallConfig {
        rules,
        ..FirewallConfig::default()
    });
    assert_eq!(fw.evaluate(Direction::In, 1, 0, &test_id(1)), Action::Deny);
}

#[test]
fn dedup_by_selector_keeps_newest_and_collapses_duplicates() {
    // Reproduces the duplicate-suggestion bug: an already-installed
    // `allow tcp:22` plus a re-accepted copy (and a re-accepted action flip)
    // must collapse to one rule per selector, the newest winning.
    let installed_22 = FirewallRule {
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        port: Some(PortRange { start: 22, end: 22 }),
        peer: PeerFilter::Any,
        network: Some("homelab".into()),
        origin: RuleOrigin::Network("homelab".into()),
    };
    let installed_80 = FirewallRule {
        port: Some(PortRange {
            start: 80,
            end: 443,
        }),
        ..installed_22.clone()
    };
    // Same selector as installed_22 but flipped to deny (a re-suggested change).
    let reaccepted_22 = FirewallRule {
        action: Action::Deny,
        ..installed_22.clone()
    };
    let out = dedup_by_selector(vec![
        installed_80.clone(),
        installed_22.clone(),
        reaccepted_22.clone(),
    ]);
    assert_eq!(out.len(), 2, "one rule per selector");
    // tcp:80-443 retained, tcp:22 collapsed to the newest (deny).
    assert!(out.iter().any(|r| r == &installed_80));
    assert!(out.iter().any(|r| r == &reaccepted_22));
    assert!(!out.iter().any(|r| r == &installed_22));
}

#[test]
fn default_allow_override_permits_inbound_tcp() {
    // `ray firewall default allow` flips the inbound default back to
    // permissive.
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Allow,
        ..FirewallConfig::default()
    });
    assert_eq!(
        fw.evaluate(Direction::In, 6, 22, &test_id(1)),
        Action::Allow
    );
}

#[test]
fn explicit_deny_in_icmp_ordered_before_seed_wins() {
    // A user-added `deny in icmp` placed ahead of the seeded allow rule blocks
    // ICMP: first-match wins. (Equivalently, removing the seed rule denies it
    // too; see `removing_seeded_icmp_rule_denies_icmp`.)
    let deny_icmp = FirewallRule {
        direction: Direction::In,
        action: Action::Deny,
        protocol: Protocol::Icmp,
        port: None,
        peer: PeerFilter::Any,
        network: None,
        origin: RuleOrigin::Local,
    };
    let fw = SharedFirewall::new(FirewallConfig {
        // deny first, then the seeded allow: the deny must win.
        rules: vec![deny_icmp, default_icmp_rule()],
        ..FirewallConfig::default()
    });
    assert_eq!(fw.evaluate(Direction::In, 1, 0, &test_id(1)), Action::Deny);
    assert_eq!(fw.evaluate(Direction::In, 58, 0, &test_id(1)), Action::Deny);
}

#[test]
fn default_config_denies_unsolicited_inbound_but_allows_return() {
    // End-to-end of the secure default through the stateful path: an
    // unsolicited inbound TCP SYN is denied, but return traffic for an
    // outbound flow we initiated is allowed.
    let fw = SharedFirewall::new(FirewallConfig::default());
    let me = Ipv4Addr::new(100, 64, 0, 2);
    let peer = Ipv4Addr::new(100, 64, 0, 3);
    let peer_id = test_id(1);

    // Unsolicited inbound -> denied.
    let unsolicited = tcp_pkt(peer, 51000, me, 8080, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &unsolicited, &peer_id, |_| false),
        Action::Deny
    );

    // We initiate outbound -> allowed (default_outbound), and tracked.
    let out = tcp_pkt(me, 50000, peer, 443, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &out, &peer_id, |_| false),
        Action::Allow
    );
    // Its return traffic -> allowed via conntrack despite deny-inbound.
    let ret = tcp_pkt(peer, 443, me, 50000, SYN | ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &ret, &peer_id, |_| false),
        Action::Allow
    );

    // Inbound ICMP under the default config -> allowed.
    let mut icmp = vec![0u8; 28];
    icmp[0] = 0x45;
    icmp[9] = 1; // ICMP
    icmp[12..16].copy_from_slice(&peer.octets());
    icmp[16..20].copy_from_slice(&me.octets());
    let icmp = parse_packet_info(&icmp).unwrap();
    assert_eq!(
        fw.evaluate_packet(Direction::In, &icmp, &peer_id, |_| false),
        Action::Allow
    );
}

#[test]
fn disabled_allows_everything_both_directions() {
    // `ray firewall off`: the kill switch allows every packet regardless of
    // the deny-inbound default, bypassing rules entirely.
    let fw = SharedFirewall::new(FirewallConfig {
        disabled: true,
        ..FirewallConfig::default()
    });
    let me = Ipv4Addr::new(100, 64, 0, 2);
    let peer = Ipv4Addr::new(100, 64, 0, 3);
    let peer_id = test_id(1);
    // Unsolicited inbound TCP would be denied when enforcing; here it passes.
    let unsolicited = tcp_pkt(peer, 51000, me, 8080, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &unsolicited, &peer_id, |_| false),
        Action::Allow
    );
    // Outbound also allowed (trivially, but confirms the short-circuit path).
    let out = tcp_pkt(me, 50000, peer, 443, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &out, &peer_id, |_| false),
        Action::Allow
    );
}

#[test]
fn disabled_ignores_explicit_deny_rule() {
    // An explicit deny is bypassed while disabled.
    let fw = SharedFirewall::new(FirewallConfig {
        disabled: true,
        rules: vec![FirewallRule {
            direction: Direction::In,
            action: Action::Deny,
            protocol: Protocol::Tcp,
            port: Some(PortRange { start: 22, end: 22 }),
            peer: PeerFilter::Any,
            network: None,
            origin: RuleOrigin::Local,
        }],
        ..FirewallConfig::default()
    });
    let me = Ipv4Addr::new(100, 64, 0, 2);
    let peer = Ipv4Addr::new(100, 64, 0, 3);
    let ssh = tcp_pkt(peer, 51000, me, 22, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &ssh, &test_id(1), |_| false),
        Action::Allow
    );
}

#[test]
fn evaluate_default_deny() {
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
        rules: vec![],
    });
    assert_eq!(fw.evaluate(Direction::In, 6, 22, &test_id(1)), Action::Deny);
}

#[test]
fn evaluate_deny_specific_port() {
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Allow,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
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
fn rule_scoped_to_shared_network() {
    // A scoped rule applies to every packet from a peer sharing its network.
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Allow,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
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
        icmp_type: 0,
        icmp_id: 0,
        transport_offset: 20,
    };
    let peer = test_id(1);
    // The peer shares both networks, so the scoped deny applies.
    assert_eq!(
        fw.evaluate_packet(Direction::In, &info, &peer, |name| {
            ["db", "dev"].contains(&name)
        }),
        Action::Deny
    );
    // A peer sharing only another network does not match.
    assert_eq!(
        fw.evaluate_packet(Direction::In, &info, &peer, |name| name == "dev"),
        Action::Allow
    );
    // No shared network means the scoped rule cannot match.
    assert_eq!(
        fw.evaluate_packet(Direction::In, &info, &peer, |_| false),
        Action::Allow
    );
}

#[test]
fn shared_network_rules_keep_order_and_peer_filters() {
    let peer = test_id(1);
    let other = test_id(2);
    let packet = tcp_pkt(
        Ipv4Addr::new(100, 64, 0, 1),
        40000,
        Ipv4Addr::new(100, 64, 0, 2),
        8080,
        SYN,
    );
    let allow = FirewallRule {
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Any,
        port: None,
        peer: PeerFilter::Identity(peer),
        network: Some("allowed".to_string()),
        origin: RuleOrigin::Local,
    };
    let deny = FirewallRule {
        action: Action::Deny,
        network: Some("restricted".to_string()),
        ..allow.clone()
    };
    let fw = SharedFirewall::new(FirewallConfig {
        rules: vec![deny.clone(), allow.clone()],
        ..Default::default()
    });
    let evaluate = |peer, networks: &[&str]| {
        fw.evaluate_packet(Direction::In, &packet, peer, |name| {
            networks.contains(&name)
        })
    };
    assert_eq!(evaluate(&peer, &["allowed"]), Action::Allow);
    assert_eq!(evaluate(&other, &["allowed"]), Action::Deny);
    assert_eq!(evaluate(&peer, &["unrelated"]), Action::Deny);
    assert_eq!(evaluate(&peer, &["allowed", "restricted"]), Action::Deny);
    fw.update(FirewallConfig {
        rules: vec![allow, deny],
        ..Default::default()
    });
    assert_eq!(evaluate(&peer, &["allowed", "restricted"]), Action::Allow);
}

#[test]
fn evaluate_port_range() {
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
    assert_eq!(
        parse_port_range("*").unwrap(),
        PortRange {
            start: 0,
            end: u16::MAX
        }
    );
}

#[test]
fn port_list_parsing() {
    // Single item behaves like parse_port_range.
    assert_eq!(
        parse_port_list("80").unwrap(),
        vec![PortRange { start: 80, end: 80 }]
    );
    // Comma list of discrete ports and a range, mixed.
    assert_eq!(
        parse_port_list("80,443,8000-9000").unwrap(),
        vec![
            PortRange { start: 80, end: 80 },
            PortRange {
                start: 443,
                end: 443
            },
            PortRange {
                start: 8000,
                end: 9000
            },
        ]
    );
    // Whitespace and a trailing comma are tolerated.
    assert_eq!(
        parse_port_list(" 22 , 80 ,").unwrap(),
        vec![
            PortRange { start: 22, end: 22 },
            PortRange { start: 80, end: 80 },
        ]
    );
    // One bad item fails the whole list.
    assert!(parse_port_list("80,abc").is_err());
    // Nothing usable.
    assert!(parse_port_list(",").is_err());
}

#[test]
fn config_serialization_roundtrip() {
    let config = FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
    assert_eq!(decoded.default_inbound, Action::Deny);
    assert_eq!(decoded.default_outbound, Action::Deny);
    assert_eq!(decoded.rules.len(), 1);
    assert_eq!(decoded.rules[0].port.as_ref().unwrap().start, 443);
}

// -- Stateful connection tracking -----------------------------------------

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;

/// Builds a 40-byte IPv4/TCP packet with the given 5-tuple and flags.
fn tcp_pkt(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16, flags: u8) -> PacketInfo {
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
        default_inbound: Action::Allow,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
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
        fw.evaluate_packet(Direction::In, &inbound_ssh, &peer_id, |_| false),
        Action::Deny
    );

    // Outbound SSH to a peer's port 22 -> allowed (default allow).
    let outbound_ssh = tcp_pkt(me, 54321, peer, 22, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &outbound_ssh, &peer_id, |_| false),
        Action::Allow
    );

    // Return traffic peer:22 -> me:54321 -> allowed (not matched by deny-in-22,
    // and would be allowed by default anyway).
    let ret = tcp_pkt(peer, 22, me, 54321, ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &ret, &peer_id, |_| false),
        Action::Allow
    );
}

#[test]
fn default_deny_allows_return_traffic_for_initiated_connections() {
    // Strict policy: default deny everywhere, allow outbound HTTPS only.
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
        fw.evaluate_packet(Direction::Out, &syn, &peer_id, |_| false),
        Action::Allow
    );

    // Return traffic peer:443 -> me:50000: no explicit rule matches, but the
    // flow is established from our outbound SYN -> allowed.
    let ret = tcp_pkt(peer, 443, me, 50000, SYN | ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &ret, &peer_id, |_| false),
        Action::Allow
    );

    // Unsolicited inbound to some other port -> denied by default.
    let unsolicited = tcp_pkt(peer, 1234, me, 8080, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &unsolicited, &peer_id, |_| false),
        Action::Deny
    );

    // Outbound to a non-allowed port -> denied by default, and NOT tracked
    // (so its would-be return traffic is also denied).
    let blocked_out = tcp_pkt(me, 40000, peer, 6667, SYN);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &blocked_out, &peer_id, |_| false),
        Action::Deny
    );
    let blocked_ret = tcp_pkt(peer, 6667, me, 40000, ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &blocked_ret, &peer_id, |_| false),
        Action::Deny
    );
}

#[test]
fn tcp_half_close_keeps_return_traffic_allowed() {
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
        fw.evaluate_packet(Direction::Out, &syn, &peer_id, |_| false),
        Action::Allow
    );
    let ret = tcp_pkt(peer, 443, me, 50000, ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &ret, &peer_id, |_| false),
        Action::Allow
    );

    // Closing our write half must still allow the peer to send its reply.
    let fin = tcp_pkt(me, 50000, peer, 443, FIN | ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &fin, &peer_id, |_| false),
        Action::Allow
    );

    let after = tcp_pkt(peer, 443, me, 50000, ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &after, &peer_id, |_| false),
        Action::Allow
    );
}

#[test]
fn udp_return_traffic_tracked_within_flow() {
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
        fw.evaluate_packet(Direction::Out, &q, &peer_id, |_| false),
        Action::Allow
    );

    // Return response peer:53 -> me:53000 allowed via established flow.
    let resp = udp_pkt(peer, 53, me, 53000);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &resp, &peer_id, |_| false),
        Action::Allow
    );

    // Unsolicited inbound UDP -> denied.
    let unsolicited = udp_pkt(peer, 9999, me, 53);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &unsolicited, &peer_id, |_| false),
        Action::Deny
    );
}

#[test]
fn explicit_inbound_rule_still_wins_over_established() {
    // If a peer is explicitly denied inbound, established-bypass must NOT
    // override it (explicit rules always win).
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Allow,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
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
    fw.evaluate_packet(Direction::Out, &syn, &bad_peer, |_| false); // track
    let ret = tcp_pkt(peer, 443, me, 50000, ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &ret, &bad_peer, |_| false),
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
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        reject: false,
        disabled: false,
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
        fw.evaluate_packet(Direction::Out, &syn, &peer_id, |_| false),
        Action::Allow
    );
    let ret = tcp_pkt(peer, 443, me, 50000, ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &ret, &peer_id, |_| false),
        Action::Allow
    );

    // Peer sends RST (inbound). We don't track inbound-eviction, but our own
    // outbound RST should evict. Send an outbound RST.
    let rst = tcp_pkt(me, 50000, peer, 443, RST | ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &rst, &peer_id, |_| false),
        Action::Allow
    );

    let after = tcp_pkt(peer, 443, me, 50000, ACK);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &after, &peer_id, |_| false),
        Action::Deny
    );
}

// -- ICMP connection tracking ---------------------------------------------

const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REPLY_V4: u8 = 0;
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY_V6: u8 = 129;

/// Builds a 28-byte IPv4/ICMP packet with the given type + echo identifier.
fn icmp_pkt(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: u8, id: u16) -> PacketInfo {
    let mut p = vec![0u8; 28];
    p[0] = 0x45; // IPv4, IHL=5
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20] = icmp_type; // ICMP type (offset 0 of the ICMP header)
    p[24] = (id >> 8) as u8; // identifier (offset 4..6)
    p[25] = id as u8;
    parse_packet_info(&p).unwrap()
}

/// Builds a 48-byte IPv6/ICMPv6 packet with the given type + echo identifier.
fn icmp6_pkt(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: u8, id: u16) -> PacketInfo {
    let mut p = vec![0u8; 48];
    p[0] = 0x60; // IPv6
    p[6] = 58; // ICMPv6 next header
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40] = icmp_type; // ICMPv6 type (offset 0 of the ICMPv6 header)
    p[44] = (id >> 8) as u8; // identifier
    p[45] = id as u8;
    parse_packet_info(&p).unwrap()
}

#[test]
fn inbound_echo_request_not_masked_by_prior_outbound_ping() {
    // The conntrack ICMP leak: with the allow-icmp rule removed and a
    // deny-inbound default, a recent *outbound* ping to a peer must NOT let
    // that peer ping us back in. An inbound echo-request is always new
    // inbound traffic, never "return traffic", even with the same echo id.
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
        rules: vec![], // seeded allow-icmp removed
    });
    let me = Ipv4Addr::new(100, 64, 0, 2);
    let peer = Ipv4Addr::new(100, 64, 0, 3);
    let peer_id = test_id(1);

    // We ping the peer: outbound echo-request, allowed (default) + tracked.
    let out_req = icmp_pkt(me, peer, ECHO_REQUEST_V4, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &out_req, &peer_id, |_| false),
        Action::Allow
    );

    // Peer pings us: inbound echo-request (same echo id). Must be denied by
    // the default, not masked by the tracked outbound flow.
    let in_req = icmp_pkt(peer, me, ECHO_REQUEST_V4, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &in_req, &peer_id, |_| false),
        Action::Deny
    );
}

#[test]
fn inbound_echo_reply_allowed_for_our_outbound_ping() {
    // The legitimate case the tracking exists for: under deny-inbound, the
    // reply to a ping *we* sent must come back in. Matched by echo id.
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
        rules: vec![],
    });
    let me = Ipv4Addr::new(100, 64, 0, 2);
    let peer = Ipv4Addr::new(100, 64, 0, 3);
    let peer_id = test_id(1);

    let out_req = icmp_pkt(me, peer, ECHO_REQUEST_V4, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &out_req, &peer_id, |_| false),
        Action::Allow
    );
    // Inbound echo-reply with the matching id -> allowed return traffic.
    let in_reply = icmp_pkt(peer, me, ECHO_REPLY_V4, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &in_reply, &peer_id, |_| false),
        Action::Allow
    );
}

#[test]
fn inbound_echo_reply_for_unrelated_id_is_not_return_traffic() {
    // A reply whose echo id we never sent isn't return traffic for any flow
    // we initiated -> denied under deny-inbound (spoofed-reply hardening).
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
        rules: vec![],
    });
    let me = Ipv4Addr::new(100, 64, 0, 2);
    let peer = Ipv4Addr::new(100, 64, 0, 3);
    let peer_id = test_id(1);

    let out_req = icmp_pkt(me, peer, ECHO_REQUEST_V4, 0x1111);
    fw.evaluate_packet(Direction::Out, &out_req, &peer_id, |_| false);
    let in_reply = icmp_pkt(peer, me, ECHO_REPLY_V4, 0x2222);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &in_reply, &peer_id, |_| false),
        Action::Deny
    );
}

#[test]
fn replying_to_a_ping_does_not_whitelist_the_pinger() {
    // Sending an outbound echo-*reply* (because someone pinged us) must NOT
    // create a flow that lets that peer's next echo-request in. Only
    // echo-requests we initiate are trackable.
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
        rules: vec![],
    });
    let me = Ipv4Addr::new(100, 64, 0, 2);
    let peer = Ipv4Addr::new(100, 64, 0, 3);
    let peer_id = test_id(1);

    // We emit an outbound echo-reply (id chosen by the original requester).
    let out_reply = icmp_pkt(me, peer, ECHO_REPLY_V4, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &out_reply, &peer_id, |_| false),
        Action::Allow
    );
    // The peer's subsequent unsolicited echo-request stays denied.
    let in_req = icmp_pkt(peer, me, ECHO_REQUEST_V4, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &in_req, &peer_id, |_| false),
        Action::Deny
    );
}

#[test]
fn icmpv6_echo_request_not_masked_by_prior_outbound_ping() {
    // Same leak, ICMPv6 (types 128/129).
    let fw = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
        rules: vec![],
    });
    let me = Ipv6Addr::new(0x2, 0, 0, 0, 0, 0, 0, 2);
    let peer = Ipv6Addr::new(0x2, 0, 0, 0, 0, 0, 0, 3);
    let peer_id = test_id(1);

    let out_req = icmp6_pkt(me, peer, ECHO_REQUEST_V6, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::Out, &out_req, &peer_id, |_| false),
        Action::Allow
    );
    let in_req = icmp6_pkt(peer, me, ECHO_REQUEST_V6, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &in_req, &peer_id, |_| false),
        Action::Deny
    );
    // The matching reply still gets in.
    let in_reply = icmp6_pkt(peer, me, ECHO_REPLY_V6, 0x1234);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &in_reply, &peer_id, |_| false),
        Action::Allow
    );
}

// -- Suggested firewall materialization -----------------------------------

use ray_proto::{HostSuggestions, SuggestedFirewall};

/// Build a one-entry suggestion map for `subject` with the given allows.
fn suggest(subject: &str, allows: &[(&str, &str)]) -> SuggestedFirewall {
    let mut entry = HostSuggestions::default();
    for (peer, ports) in allows {
        entry
            .allows
            .insert((*peer).to_string(), (*ports).to_string());
    }
    let mut map = SuggestedFirewall::new();
    map.insert(subject.to_string(), entry);
    map
}

#[test]
fn excluded_peers_allow_other_members_and_follow_roster_changes() {
    let excluded = test_id(2);
    let other = test_id(3);
    let suggestions = suggest("sample-net", &[("*-a,b", "tcp:12345,tcp:23456")]);
    let resolve = |host: &str| match host {
        "a" => Some(excluded),
        "b" => None,
        _ => None,
    };
    let rules = materialize_suggestions("prod", "sample-net", &suggestions, &resolve);
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rule_view(&rules[0], &|id| id.fmt_short().to_string()).peer,
        "any except a,b"
    );
    let config = FirewallConfig {
        rules,
        ..FirewallConfig::default()
    };
    assert_eq!(
        SharedFirewall::match_rule(&config, Direction::In, 6, 12345, &excluded, |name| name
            == "prod"),
        None
    );
    assert_eq!(
        SharedFirewall::match_rule(&config, Direction::In, 6, 12345, &other, |name| name
            == "prod")
        .map(|(_, rule)| rule.action),
        Some(Action::Allow)
    );

    let resolve_after_join = |host: &str| match host {
        "a" => Some(excluded),
        "b" => Some(other),
        _ => None,
    };
    let updated = materialize_suggestions("prod", "sample-net", &suggestions, &resolve_after_join);
    let config = FirewallConfig {
        rules: updated,
        ..FirewallConfig::default()
    };
    assert_eq!(
        SharedFirewall::match_rule(&config, Direction::In, 6, 12345, &other, |name| name
            == "prod"),
        None
    );
}

#[test]
fn malformed_excluded_peer_selector_is_rejected() {
    assert!(parse_excluded_peers("*-").is_err());
    assert!(parse_excluded_peers("*-a,").is_err());
    assert!(parse_excluded_peers("*-A").is_err());
}

#[test]
fn excluded_paired_device_matches_its_packet_identity() {
    let device = test_id(2);
    let user = test_id(3);
    let other = test_id(4);
    let suggestions = suggest("sample-net", &[("*-phone", "tcp:12345")]);
    let rules = materialize_suggestions_with_exclusion_resolver(
        "prod",
        "sample-net",
        &suggestions,
        &|hostname| (hostname == "phone").then_some(device),
        &|hostname| (hostname == "phone").then_some(user),
    );
    let config = FirewallConfig {
        rules,
        ..FirewallConfig::default()
    };
    assert_eq!(
        SharedFirewall::match_rule(&config, Direction::In, 6, 12345, &user, |name| name
            == "prod"),
        None
    );
    assert_eq!(
        SharedFirewall::match_rule(&config, Direction::In, 6, 12345, &other, |name| name
            == "prod")
        .map(|(_, rule)| rule.action),
        Some(Action::Allow)
    );
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
    let allows: Vec<_> = rules.iter().filter(|r| r.action == Action::Allow).collect();
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
fn materialize_allow_list_is_additive_no_catch_all() {
    let me = test_id(1);
    let peer = test_id(2);
    let resolve = |h: &str| match h {
        "me" => Some(me),
        "peer" => Some(peer),
        _ => None,
    };
    // An allow-list yields exactly its allow rules, no synthesized catch-all
    // deny. The node's own `default_inbound` already drops the rest.
    let suggestions = suggest("me", &[("peer", "tcp:9000")]);
    let rules = materialize_suggestions("prod", "me", &suggestions, &resolve);
    assert_eq!(rules.len(), 1, "only the suggested allow rule");
    assert_eq!(rules[0].action, Action::Allow);
    assert_eq!(rules[0].peer, PeerFilter::Identity(peer));
    assert!(
        rules.iter().all(|r| r.action != Action::Deny),
        "no catch-all deny should be appended"
    );
}

#[test]
fn materialize_deny_only_blacklist_no_catch_all() {
    // A subject with only `denies` (blacklist mode) does NOT get a
    // catch-all deny: the listed peer is blocked, the rest stays open.
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
    // The allow rule is dropped (peer not joined) and nothing is synthesized,
    // so no rules materialize at all.
    assert!(rules.is_empty());
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
    let icmp = allows
        .iter()
        .find(|r| r.protocol == Protocol::Icmp)
        .unwrap();
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
    // Additive: only the suggested allow, no synthesized catch-all deny.
    assert!(rules.iter().all(|r| r.action != Action::Deny));
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
    assert!(
        allows
            .iter()
            .any(|r| r.peer == PeerFilter::Identity(peer) && r.port.as_ref().unwrap().start == 22)
    );
    assert!(
        allows
            .iter()
            .any(|r| r.peer == PeerFilter::Any && r.port.as_ref().unwrap().start == 6969)
    );
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
        port: Some(PortRange {
            start: 9000,
            end: 9000,
        }),
        peer: PeerFilter::Identity(test_id(9)),
        network: Some("prod".to_string()),
        origin: RuleOrigin::Network("prod".to_string()),
    };
    // A rule from a *different* network must survive a prod replace.
    let other_net = FirewallRule {
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        port: Some(PortRange {
            start: 8080,
            end: 8080,
        }),
        peer: PeerFilter::Any,
        network: Some("dev".to_string()),
        origin: RuleOrigin::Network("dev".to_string()),
    };
    let config = FirewallConfig {
        default_inbound: Action::Allow,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
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
    let updated = fw.replace_network_rules("prod", vec![fresh.clone()], |_| {});

    // Local + other-network rules preserved; prod set fully replaced.
    assert!(updated.rules.iter().any(|r| r.origin == RuleOrigin::Local));
    assert!(
        updated
            .rules
            .iter()
            .any(|r| matches!(&r.origin, RuleOrigin::Network(n) if n == "dev"))
    );
    let prod: Vec<_> = updated
        .rules
        .iter()
        .filter(|r| matches!(&r.origin, RuleOrigin::Network(n) if n == "prod"))
        .collect();
    assert_eq!(prod.len(), 1);
    assert_eq!(prod[0].action, Action::Deny);
    assert_eq!(prod[0].peer, PeerFilter::Any);
}

/// A network renamed on this node keeps its rules: the ones scoped to it
/// and the ones installed from its suggestions follow the new name, while
/// local rules and other networks' rules stay as they were.
#[test]
fn renaming_a_network_moves_its_rules_to_the_new_name() {
    let rule = |network: Option<&str>, origin: RuleOrigin| FirewallRule {
        direction: Direction::In,
        action: Action::Deny,
        protocol: Protocol::Tcp,
        port: Some(PortRange { start: 22, end: 22 }),
        peer: PeerFilter::Any,
        network: network.map(str::to_string),
        origin,
    };
    let suggested = |net: &str| RuleOrigin::Network(net.to_string());
    let fw = SharedFirewall::new(FirewallConfig {
        rules: vec![
            rule(Some("home"), RuleOrigin::Local),
            rule(Some("home"), suggested("home")),
            rule(None, suggested("home")),
            rule(Some("work"), suggested("work")),
            rule(None, RuleOrigin::Local),
        ],
        ..FirewallConfig::default()
    });

    let renamed = fw.rename_network("home", "lab", |_| {}).unwrap();
    let expected = vec![
        rule(Some("lab"), RuleOrigin::Local),
        rule(Some("lab"), suggested("lab")),
        rule(None, suggested("lab")),
        rule(Some("work"), suggested("work")),
        rule(None, RuleOrigin::Local),
    ];
    assert_eq!(renamed.rules, expected);
    assert_eq!(fw.get_config().rules, expected);
    assert!(fw.rename_network("home", "office", |_| {}).is_none());
}

/// Concurrent edits each keep their change. They used to clone the same
/// snapshot, and the last store dropped the rules the others added.
#[test]
fn concurrent_edits_are_not_lost() {
    const THREADS: u16 = 8;
    const EDITS: u16 = 50;
    let fw = SharedFirewall::new(FirewallConfig {
        rules: Vec::new(),
        ..FirewallConfig::default()
    });
    let start = std::sync::Barrier::new(usize::from(THREADS));
    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let (fw, start) = (&fw, &start);
            scope.spawn(move || {
                start.wait();
                for edit in 0..EDITS {
                    let port = thread * EDITS + edit + 1;
                    fw.edit(
                        |c| {
                            c.rules.push(FirewallRule {
                                direction: Direction::In,
                                action: Action::Allow,
                                protocol: Protocol::Tcp,
                                port: Some(PortRange {
                                    start: port,
                                    end: port,
                                }),
                                peer: PeerFilter::Any,
                                network: None,
                                origin: RuleOrigin::Local,
                            })
                        },
                        |_| {},
                    );
                }
            });
        }
    });
    assert_eq!(fw.get_config().rules.len(), usize::from(THREADS * EDITS));
}

#[test]
fn ssh_passthrough_toggles_a_single_managed_rule() {
    let fw = SharedFirewall::new(FirewallConfig::default());
    // A hand-added tcp:22 deny that ssh on/off must never touch.
    let local_22 = FirewallRule {
        direction: Direction::In,
        action: Action::Deny,
        protocol: Protocol::Tcp,
        port: Some(PortRange { start: 22, end: 22 }),
        peer: PeerFilter::Any,
        network: None,
        origin: RuleOrigin::Local,
    };
    let mut cfg = (*fw.get_config()).clone();
    cfg.rules.push(local_22.clone());
    fw.update(cfg);

    // Changing ports replaces the old managed rule without touching local rules.
    fw.set_ssh_passthrough(true, 22, |_| {});
    let cfg = fw.set_ssh_passthrough(true, 2222, |_| {});
    let ssh_rules: Vec<_> = cfg
        .rules
        .iter()
        .filter(|r| r.origin == RuleOrigin::Ssh)
        .collect();
    assert_eq!(ssh_rules.len(), 1);
    assert_eq!(ssh_rules[0].action, Action::Allow);
    assert_eq!(
        ssh_rules[0].port,
        Some(PortRange {
            start: 2222,
            end: 2222
        })
    );
    // The managed rule wins (front-inserted) and the Local rule survives.
    assert_eq!(cfg.rules[0].origin, RuleOrigin::Ssh);
    assert!(cfg.rules.contains(&local_22));

    // Disabling removes the managed rule but keeps the Local one.
    let cfg = fw.set_ssh_passthrough(false, 2222, |_| {});
    assert!(!cfg.rules.iter().any(|r| r.origin == RuleOrigin::Ssh));
    assert!(cfg.rules.contains(&local_22));
}

// -- `ray firewall test` -------------------------------------------------

const LOCAL_V6: Ipv6Addr = Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 1);
const PEER_V6: Ipv6Addr = Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 2);

fn probe(direction: Direction, protocol: Protocol, port: Option<u16>) -> PacketInfo {
    probe_packet(direction, protocol, port, LOCAL_V6, PEER_V6).unwrap()
}

fn tcp_rule(action: Action, port: u16, peer: PeerFilter) -> FirewallRule {
    FirewallRule {
        direction: Direction::In,
        action,
        protocol: Protocol::Tcp,
        port: Some(PortRange {
            start: port,
            end: port,
        }),
        peer,
        network: None,
        origin: RuleOrigin::Local,
    }
}

#[test]
fn explain_names_the_rule_or_default_that_decides() {
    let fw = SharedFirewall::new(FirewallConfig::default());
    let peer = test_id(1);

    // The seeded rule, #0 in `ray firewall show`, admits pings.
    let ping = probe(Direction::In, Protocol::Icmp, None);
    let verdict = fw.explain(Direction::In, &ping, &peer, |_| false);
    assert_eq!(verdict.action, Action::Allow);
    assert_eq!(
        verdict.decided_by,
        DecidedBy::Rule {
            index: 0,
            rule: default_icmp_rule()
        }
    );

    // Inbound TCP falls to the deny default, which still lets replies to
    // this device's own connections in.
    let ssh = probe(Direction::In, Protocol::Tcp, Some(22));
    let verdict = fw.explain(Direction::In, &ssh, &peer, |_| false);
    assert_eq!(verdict.action, Action::Deny);
    assert_eq!(verdict.decided_by, DecidedBy::Default);
    assert!(verdict.return_traffic);
    assert!(verdict.reject);

    let web = probe(Direction::Out, Protocol::Tcp, Some(443));
    let verdict = fw.explain(Direction::Out, &web, &peer, |_| false);
    assert_eq!(verdict.action, Action::Allow);
    assert_eq!(verdict.decided_by, DecidedBy::Default);
    assert!(!verdict.return_traffic);
}

#[test]
fn explain_reports_the_first_match_by_its_show_index() {
    let peer = test_id(1);
    let deny_peer = tcp_rule(Action::Deny, 22, PeerFilter::Identity(peer));
    let allow_all = tcp_rule(Action::Allow, 22, PeerFilter::Any);
    let fw = SharedFirewall::new(FirewallConfig {
        rules: vec![default_icmp_rule(), deny_peer.clone(), allow_all.clone()],
        ..FirewallConfig::default()
    });
    let ssh = probe(Direction::In, Protocol::Tcp, Some(22));

    // The peer meets its own deny first; anyone else falls through to #2.
    assert_eq!(
        fw.explain(Direction::In, &ssh, &peer, |_| false).decided_by,
        DecidedBy::Rule {
            index: 1,
            rule: deny_peer
        }
    );
    assert_eq!(
        fw.explain(Direction::In, &ssh, &test_id(2), |_| false)
            .decided_by,
        DecidedBy::Rule {
            index: 2,
            rule: allow_all
        }
    );
}

#[test]
fn explain_matches_a_network_scoped_rule_only_on_a_shared_network() {
    let rule = FirewallRule {
        network: Some("home".into()),
        origin: RuleOrigin::Network("home".into()),
        ..tcp_rule(Action::Allow, 8080, PeerFilter::Any)
    };
    let fw = SharedFirewall::new(FirewallConfig {
        rules: vec![rule.clone()],
        ..FirewallConfig::default()
    });
    let info = probe(Direction::In, Protocol::Tcp, Some(8080));
    let peer = test_id(1);

    let shared = fw.explain(Direction::In, &info, &peer, |net| net == "home");
    assert_eq!(shared.decided_by, DecidedBy::Rule { index: 0, rule });
    let elsewhere = fw.explain(Direction::In, &info, &peer, |net| net == "work");
    assert_eq!(elsewhere.decided_by, DecidedBy::Default);
    assert_eq!(elsewhere.action, Action::Deny);
}

#[test]
fn explain_reports_ssh_reject_without_general_reject() {
    let peer = test_id(1);
    let fw = SharedFirewall::new(FirewallConfig::default());
    let ssh = probe(Direction::In, Protocol::Tcp, Some(22));
    assert!(fw.explain(Direction::In, &ssh, &peer, |_| false).reject);
    let https = probe(Direction::In, Protocol::Tcp, Some(443));
    assert!(!fw.explain(Direction::In, &https, &peer, |_| false).reject);
    let udp = probe(Direction::In, Protocol::Udp, Some(22));
    assert!(!fw.explain(Direction::In, &udp, &peer, |_| false).reject);
}

#[test]
fn explain_reports_reject_for_denials_only_and_nothing_when_off() {
    let peer = test_id(1);
    let ssh = probe(Direction::In, Protocol::Tcp, Some(22));
    let fw = SharedFirewall::new(FirewallConfig {
        reject: true,
        ..FirewallConfig::default()
    });
    assert!(fw.explain(Direction::In, &ssh, &peer, |_| false).reject);
    let ping = probe(Direction::In, Protocol::Icmp, None);
    assert!(!fw.explain(Direction::In, &ping, &peer, |_| false).reject);

    let fw = SharedFirewall::new(FirewallConfig {
        reject: true,
        disabled: true,
        ..FirewallConfig::default()
    });
    let off = fw.explain(Direction::In, &ssh, &peer, |_| false);
    assert_eq!(off.action, Action::Allow);
    assert_eq!(off.decided_by, DecidedBy::Disabled);
    assert!(!off.reject && !off.return_traffic);
}

#[test]
fn explain_records_no_conntrack_flow() {
    let fw = SharedFirewall::new(FirewallConfig::default());
    let peer = test_id(1);
    let syn = probe(Direction::Out, Protocol::Tcp, Some(22));
    let reply = PacketInfo {
        src_ip: syn.dst_ip,
        dst_ip: syn.src_ip,
        src_port: syn.dst_port,
        dst_port: syn.src_port,
        tcp_flags: SYN | ACK,
        ..syn
    };

    // Asking about the SYN does not open its flow, so the reply stays out...
    assert_eq!(
        fw.explain(Direction::Out, &syn, &peer, |_| false).action,
        Action::Allow
    );
    assert_eq!(
        fw.evaluate_packet(Direction::In, &reply, &peer, |_| false),
        Action::Deny
    );
    // ...where sending it would have let the reply in.
    fw.evaluate_packet(Direction::Out, &syn, &peer, |_| false);
    assert_eq!(
        fw.evaluate_packet(Direction::In, &reply, &peer, |_| false),
        Action::Allow
    );
}

#[test]
fn an_inbound_ping_is_never_return_traffic() {
    let mut config = FirewallConfig::default();
    config.rules.clear();
    let fw = SharedFirewall::new(config);
    let ping = probe(Direction::In, Protocol::Icmp, None);
    let verdict = fw.explain(Direction::In, &ping, &test_id(1), |_| false);
    assert_eq!(verdict.action, Action::Deny);
    assert!(!verdict.return_traffic);
}

#[test]
fn a_probe_spec_names_one_packet() {
    assert_eq!(parse_probe("tcp:22").unwrap(), (Protocol::Tcp, Some(22)));
    assert_eq!(parse_probe("udp:53").unwrap(), (Protocol::Udp, Some(53)));
    assert_eq!(parse_probe("icmp").unwrap(), (Protocol::Icmp, None));
    for spec in ["any", "any:*", "tcp", "tcp:*", "udp:80-443", "22", "ftp:21"] {
        assert!(parse_probe(spec).is_err(), "{spec} is not one packet");
    }
}

#[test]
fn a_probe_packet_opens_an_exchange_in_the_asked_direction() {
    let syn = probe(Direction::In, Protocol::Tcp, Some(22));
    assert_eq!(syn.src_ip, IpAddr::V6(PEER_V6));
    assert_eq!(syn.dst_ip, IpAddr::V6(LOCAL_V6));
    assert_eq!((syn.protocol, syn.dst_port, syn.tcp_flags), (6, 22, SYN));
    assert_eq!(syn.transport_offset, 40);

    let ping = probe(Direction::Out, Protocol::Icmp, None);
    assert_eq!(ping.src_ip, IpAddr::V6(LOCAL_V6));
    assert_eq!(ping.dst_ip, IpAddr::V6(PEER_V6));
    assert!(is_icmp_echo_request(ping.protocol, ping.icmp_type));

    for (protocol, port) in [
        (Protocol::Tcp, None),
        (Protocol::Icmp, Some(1)),
        (Protocol::Any, None),
    ] {
        assert!(probe_packet(Direction::In, protocol, port, LOCAL_V6, PEER_V6).is_err());
    }
}

mod conntrack;
