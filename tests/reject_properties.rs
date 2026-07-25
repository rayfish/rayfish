//! Property tests for REJECT reply synthesis (`src/reject.rs`).
//!
//! These functions hand-build IP, TCP, and ICMP headers, checksums included,
//! and inject the result into the local TUN. A malformed reply is worse than
//! no reply: the kernel drops it and the connection hangs exactly as it would
//! have without reject mode, which is the failure mode reject mode exists to
//! prevent. Checksum folding in particular has edge cases (odd-length
//! payloads, the 0xFFFF carry wrap) that example tests reach only by accident.
//!
//! Every property here builds the reply from a packet the crate's own parser
//! accepts, then checks the reply back through that same parser: whatever the
//! data path would do with it, these tests do too.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::{
    PROTO_ICMPV4, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, PacketSpec, checksum_valid, packet_spec,
    pseudo_checksum_valid,
};
use proptest::prelude::*;
use rayfish::firewall::{PacketInfo, parse_packet_info};
use rayfish::reject::{build_packet_too_big, build_reject};

/// TUN MTU. Every synthesized reply has to fit one datagram.
const MTU: usize = 1280;

const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

fn has_unicast_source(spec: &PacketSpec) -> bool {
    match spec.src {
        IpAddr::V4(v4) => !(v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified()),
        IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified()),
    }
}

fn is_icmp_error(spec: &PacketSpec) -> bool {
    match spec.protocol {
        PROTO_ICMPV4 => matches!(spec.icmp_type, 3 | 4 | 5 | 11 | 12),
        PROTO_ICMPV6 => spec.icmp_type < 128,
        _ => false,
    }
}

/// The three suppression rules, as one predicate: a packet drawing a reply
/// must have a unicast source, not be an ICMP error, and not be an RST.
fn is_rejectable(spec: &PacketSpec) -> bool {
    let bare_rst = spec.protocol == PROTO_TCP && spec.tcp_flags & TCP_RST != 0;
    has_unicast_source(spec) && !is_icmp_error(spec) && !bare_rst
}

/// Packets that are legitimate reject targets. The suppression rules get
/// their own properties; this filter keeps the "a reply was built and it is
/// well-formed" properties from spending their budget on inputs that
/// correctly produce `None`.
fn rejectable_spec() -> impl Strategy<Value = PacketSpec> {
    packet_spec().prop_filter("must be a legitimate reject target", is_rejectable)
}

/// Rejectable packets narrowed to one protocol. Filtering `packet_spec()`
/// down to a single protocol would throw away most of what it generates, so
/// the protocol is forced first and the suppression filter applied after: the
/// order matters, since forcing TCP onto a spec whose flags happen to carry
/// RST would otherwise smuggle an unrejectable packet past the filter.
fn rejectable_proto(protocol: u8) -> impl Strategy<Value = PacketSpec> {
    packet_spec()
        .prop_map(move |mut spec| {
            spec.protocol = protocol;
            if protocol == PROTO_TCP {
                spec.tcp_flags &= !TCP_RST;
            }
            spec
        })
        .prop_filter("must be a legitimate reject target", is_rejectable)
}

/// A packet whose source address is one no reply may be sent to.
fn non_unicast_spec() -> impl Strategy<Value = PacketSpec> {
    (packet_spec(), 0usize..3).prop_map(|(mut spec, which)| {
        spec.src = match (spec.v6, which) {
            (false, 0) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            (false, 1) => IpAddr::V4(Ipv4Addr::BROADCAST),
            (false, _) => IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            (true, 0) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            (true, _) => IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
        };
        spec
    })
}

/// An ICMP or ICMPv6 *error* message, which must never draw a reply.
fn icmp_error_spec() -> impl Strategy<Value = PacketSpec> {
    (
        packet_spec(),
        prop_oneof![Just(3u8), Just(4), Just(5), Just(11), Just(12)],
        0u8..128,
    )
        .prop_map(|(mut spec, v4_type, v6_type)| {
            if spec.v6 {
                spec.protocol = PROTO_ICMPV6;
                spec.icmp_type = v6_type;
            } else {
                spec.protocol = PROTO_ICMPV4;
                spec.icmp_type = v4_type;
            }
            spec
        })
}

/// A TCP segment carrying RST, which must never draw an RST back.
fn tcp_rst_spec() -> impl Strategy<Value = PacketSpec> {
    packet_spec().prop_map(|mut spec| {
        spec.protocol = PROTO_TCP;
        spec.tcp_flags |= TCP_RST;
        spec
    })
}

/// The reply's own IP header must verify, and its length fields must describe
/// the bytes actually present.
fn assert_ip_header_sound(reply: &[u8]) -> Result<(), TestCaseError> {
    prop_assert!(
        reply.len() <= MTU,
        "reply of {} bytes exceeds MTU",
        reply.len()
    );
    match reply[0] >> 4 {
        4 => {
            prop_assert!(reply.len() >= 20);
            let total = u16::from_be_bytes([reply[2], reply[3]]) as usize;
            prop_assert_eq!(
                total,
                reply.len(),
                "IPv4 total-length field disagrees with the reply"
            );
            prop_assert!(checksum_valid(&reply[..20]), "IPv4 header checksum invalid");
        }
        6 => {
            prop_assert!(reply.len() >= 40);
            let payload = u16::from_be_bytes([reply[4], reply[5]]) as usize;
            prop_assert_eq!(
                payload + 40,
                reply.len(),
                "IPv6 payload-length field disagrees"
            );
        }
        v => prop_assert!(false, "reply has version nibble {}", v),
    }
    Ok(())
}

/// The reply's L4 checksum, over the right pseudo-header for its family.
/// ICMPv4 has no pseudo-header; ICMPv6 and TCP do.
fn assert_l4_checksum(reply: &[u8], info: &PacketInfo) -> Result<(), TestCaseError> {
    match (info.src_ip, info.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let l4 = &reply[20..];
            match info.protocol {
                PROTO_TCP => prop_assert!(
                    pseudo_checksum_valid(&src.octets(), &dst.octets(), PROTO_TCP, l4),
                    "TCP checksum invalid",
                ),
                PROTO_ICMPV4 => {
                    prop_assert!(checksum_valid(l4), "ICMPv4 checksum invalid")
                }
                p => prop_assert!(false, "unexpected reply protocol {}", p),
            }
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let l4 = &reply[40..];
            let proto = info.protocol;
            prop_assert!(
                proto == PROTO_TCP || proto == PROTO_ICMPV6,
                "unexpected reply protocol {}",
                proto,
            );
            prop_assert!(
                pseudo_checksum_valid(&src.octets(), &dst.octets(), proto, l4),
                "IPv6 pseudo-header checksum invalid for protocol {}",
                proto,
            );
        }
        _ => prop_assert!(false, "reply mixes address families"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reject replies
// ---------------------------------------------------------------------------

proptest! {
    /// The reply is a packet the data path can parse. Everything downstream
    /// (the TUN write, the peer's stack) assumes this.
    #[test]
    fn reject_reply_is_well_formed(spec in rejectable_spec()) {
        let packet = spec.encode();
        let info = spec.expected();
        let Some(reply) = build_reject(&packet, &info) else {
            return Ok(());
        };

        assert_ip_header_sound(&reply)?;
        let reply_info = parse_packet_info(&reply).expect("a synthesized reply must parse");
        assert_l4_checksum(&reply, &reply_info)?;
    }

    /// The reply must look like it came back from the destination, or the
    /// initiator's socket ignores it and hangs anyway.
    #[test]
    fn reject_reply_comes_from_the_destination(spec in rejectable_spec()) {
        let packet = spec.encode();
        let info = spec.expected();
        let Some(reply) = build_reject(&packet, &info) else {
            return Ok(());
        };
        let reply_info = parse_packet_info(&reply).expect("a synthesized reply must parse");

        prop_assert_eq!(reply_info.src_ip, info.dst_ip);
        prop_assert_eq!(reply_info.dst_ip, info.src_ip);
    }

    /// A denied TCP segment gets an RST with the ports swapped. Without the
    /// swap the peer's stack drops it as belonging to no connection.
    #[test]
    fn tcp_reject_is_an_rst_with_swapped_ports(spec in rejectable_proto(PROTO_TCP)) {
        let packet = spec.encode();
        let info = spec.expected();
        let reply = build_reject(&packet, &info).expect("TCP must get an RST");
        let reply_info = parse_packet_info(&reply).expect("a synthesized reply must parse");

        prop_assert_eq!(reply_info.protocol, PROTO_TCP);
        prop_assert!(reply_info.tcp_flags & TCP_RST != 0, "reply is not an RST");
        prop_assert_eq!(reply_info.src_port, info.dst_port);
        prop_assert_eq!(reply_info.dst_port, info.src_port);
    }

    /// RFC 793's reset rules. A segment carrying an ACK gets an RST seated at
    /// that ack with no ACK of its own; one without gets RST+ACK acknowledging
    /// the sequence space the segment consumed. Get this wrong and the peer
    /// discards the RST as out of window, so the connection still hangs.
    #[test]
    fn tcp_rst_follows_rfc793_sequencing(spec in rejectable_proto(PROTO_TCP)) {
        let packet = spec.encode();
        let info = spec.expected();
        let reply = build_reject(&packet, &info).expect("TCP must get an RST");

        let l4 = if spec.v6 { 40 } else { 20 };
        let seq = u32::from_be_bytes(reply[l4 + 4..l4 + 8].try_into().unwrap());
        let ack = u32::from_be_bytes(reply[l4 + 8..l4 + 12].try_into().unwrap());
        let flags = reply[l4 + 13];

        if spec.tcp_flags & TCP_ACK != 0 {
            prop_assert_eq!(seq, spec.tcp_ack);
            prop_assert_eq!(flags & TCP_ACK, 0, "an RST answering an ACK must not carry one");
        } else {
            prop_assert_eq!(seq, 0);
            prop_assert!(flags & TCP_ACK != 0, "an RST answering a non-ACK must carry one");
            // The generated segment has no payload, so the only sequence
            // space consumed is one each for SYN and FIN.
            let syn = u32::from(spec.tcp_flags & 0x02 != 0);
            let fin = u32::from(spec.tcp_flags & 0x01 != 0);
            prop_assert_eq!(ack, spec.tcp_seq.wrapping_add(syn + fin));
        }
    }

    /// Non-TCP gets an ICMP unreachable. UDP specifically gets the code that
    /// maps to `ECONNREFUSED`, which is what makes a client fail fast.
    #[test]
    fn non_tcp_reject_is_an_icmp_unreachable(
        spec in prop_oneof![
            rejectable_proto(PROTO_UDP),
            // An arbitrary protocol with no L4 handling of its own.
            rejectable_proto(0),
            // Informational ICMP: an echo request is rejectable, an ICMP
            // error is not (that has its own property).
            rejectable_spec().prop_filter("ICMP only", |s| s.is_icmp()),
        ],
    ) {
        let packet = spec.encode();
        let info = spec.expected();
        let reply = build_reject(&packet, &info).expect("non-TCP must get an ICMP error");
        let reply_info = parse_packet_info(&reply).expect("a synthesized reply must parse");

        let l4 = if spec.v6 { 40 } else { 20 };
        let (icmp_type, code) = (reply[l4], reply[l4 + 1]);
        if spec.v6 {
            prop_assert_eq!(reply_info.protocol, PROTO_ICMPV6);
            prop_assert_eq!(icmp_type, 1, "ICMPv6 destination unreachable");
            prop_assert_eq!(code, if spec.protocol == PROTO_UDP { 4 } else { 1 });
        } else {
            prop_assert_eq!(reply_info.protocol, PROTO_ICMPV4);
            prop_assert_eq!(icmp_type, 3, "ICMPv4 destination unreachable");
            prop_assert_eq!(code, if spec.protocol == PROTO_UDP { 3 } else { 13 });
        }
    }

    /// The loop guard, stated end to end: a reply must never itself be
    /// rejectable. If it were, two peers in reject mode could answer each
    /// other's replies forever.
    #[test]
    fn replies_never_trigger_another_reply(spec in rejectable_spec()) {
        let packet = spec.encode();
        let info = spec.expected();
        let Some(reply) = build_reject(&packet, &info) else {
            return Ok(());
        };
        let reply_info = parse_packet_info(&reply).expect("a synthesized reply must parse");
        prop_assert!(
            build_reject(&reply, &reply_info).is_none(),
            "a reject reply provoked another reject",
        );
    }
}

// ---------------------------------------------------------------------------
// Suppression rules
// ---------------------------------------------------------------------------

proptest! {
    /// Never answer a packet whose source isn't a unicast host: the reply goes
    /// nowhere useful and turns the node into an amplifier.
    #[test]
    fn no_reply_to_non_unicast_sources(spec in non_unicast_spec()) {
        let packet = spec.encode();
        let info = spec.expected();
        prop_assert!(build_reject(&packet, &info).is_none());
        prop_assert!(build_packet_too_big(&packet, &info, 1280).is_none());
    }

    /// Never answer an ICMP error with another ICMP error.
    #[test]
    fn no_reply_to_icmp_errors(spec in icmp_error_spec()) {
        let packet = spec.encode();
        let info = spec.expected();
        prop_assert!(build_reject(&packet, &info).is_none());
        prop_assert!(build_packet_too_big(&packet, &info, 1280).is_none());
    }

    /// Never answer an RST with an RST.
    #[test]
    fn no_reply_to_tcp_rst(spec in tcp_rst_spec()) {
        let packet = spec.encode();
        let info = spec.expected();
        prop_assert!(build_reject(&packet, &info).is_none());
    }
}

// ---------------------------------------------------------------------------
// Packet-too-big (PMTUD feedback)
// ---------------------------------------------------------------------------

proptest! {
    /// The PMTUD reply is well-formed and appears to come from the
    /// destination, same as a reject.
    #[test]
    fn packet_too_big_is_well_formed(spec in rejectable_spec(), mtu in 1280u16..1500) {
        let packet = spec.encode();
        let info = spec.expected();
        let Some(reply) = build_packet_too_big(&packet, &info, mtu) else {
            return Ok(());
        };

        assert_ip_header_sound(&reply)?;
        let reply_info = parse_packet_info(&reply).expect("a synthesized reply must parse");
        assert_l4_checksum(&reply, &reply_info)?;
        prop_assert_eq!(reply_info.src_ip, info.dst_ip);
        prop_assert_eq!(reply_info.dst_ip, info.src_ip);
    }

    /// The MTU has to land in the field the kernel actually reads, or the
    /// local stack learns nothing and keeps sending packets that don't fit.
    /// IPv4 puts it in the low half of the unused word (RFC 1191); IPv6 has a
    /// dedicated 32-bit field (RFC 4443).
    #[test]
    fn packet_too_big_carries_the_mtu(spec in rejectable_spec(), mtu in 1280u16..1500) {
        let packet = spec.encode();
        let info = spec.expected();
        let reply = build_packet_too_big(&packet, &info, mtu).expect("must build");

        if spec.v6 {
            prop_assert_eq!(reply[40], 2, "ICMPv6 packet too big");
            prop_assert_eq!(reply[41], 0);
            let field = u32::from_be_bytes(reply[44..48].try_into().unwrap());
            prop_assert_eq!(field, u32::from(mtu));
        } else {
            prop_assert_eq!(reply[20], 3, "ICMPv4 destination unreachable");
            prop_assert_eq!(reply[21], 4, "fragmentation needed");
            let field = u16::from_be_bytes(reply[26..28].try_into().unwrap());
            prop_assert_eq!(field, mtu);
        }
    }
}
