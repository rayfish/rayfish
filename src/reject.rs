//! Synthesis of "fail fast" REJECT replies for firewall-denied packets.
//!
//! When the firewall denies a packet and `reject` mode is enabled (opt-in,
//! default off, see [`crate::firewall::FirewallConfig`]), the data path builds a
//! reply here instead of silently dropping: a TCP RST for TCP, or an ICMP
//! destination-unreachable for UDP / everything else. The reply has its src/dst
//! (and ports) swapped so it looks like it came back from the destination, which
//! makes the initiator's socket fail immediately ("connection refused") rather
//! than hang to a timeout.
//!
//! Dual-stack: IPv4 (ICMP) and IPv6 (ICMPv6) are both handled. All headers and
//! checksums are built by hand (no extra deps); the one's-complement folding
//! mirrors [`crate::dns::packet`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::firewall::PacketInfo;

/// TUN MTU (RFC 8200 IPv6 minimum). Replies must fit.
const MTU: usize = 1280;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
/// ICMP / ICMPv6 error header: type, code, checksum, 4 unused bytes.
const ICMP_HEADER_LEN: usize = 8;

const PROTO_ICMPV4: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_ICMPV6: u8 = 58;

// TCP flag bits.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Build a REJECT reply for a denied packet, or `None` when no reply should be
/// sent. `packet` is the full original IP datagram; `info` is the already-parsed
/// [`PacketInfo`] for it.
///
/// Returns `None` (silently drop, as before) for packets that must not trigger a
/// reply: an incoming TCP RST, an incoming ICMP/ICMPv6 *error* message (both
/// would risk a reject storm), a multicast/broadcast source, or a packet too
/// short to parse the fields we need.
pub fn build_reject(packet: &[u8], info: &PacketInfo) -> Option<Bytes> {
    // Never answer a packet whose source isn't a normal unicast host: a reply
    // would go nowhere useful and could amplify.
    if is_multicast_or_unspecified(info.src_ip) {
        return None;
    }
    // Don't reply to an ICMP error with another ICMP error (loop guard).
    if is_icmp_error(info) {
        return None;
    }
    if info.protocol == PROTO_TCP {
        // A RST needs no RST in return; that would ping-pong forever.
        if info.tcp_flags & TCP_RST != 0 {
            return None;
        }
        build_tcp_rst(packet, info)
    } else {
        build_icmp_unreachable(packet, info)
    }
}

/// Build an ICMP "packet too big" reply telling the source to lower its path MTU
/// to `mtu` for this destination, or `None` when no reply should be sent. This is
/// the PMTUD feedback the forwarder emits when a packet won't fit a single QUIC
/// datagram on a peer's path (common under an exit-node full tunnel over a
/// relayed peer): injected back into our own TUN, it makes the local kernel lower
/// the flow's path MTU and resend a packet that fits, instead of a silent
/// blackhole. Addressing mirrors [`build_reject`]: the reply appears to come back
/// from the destination.
///
/// IPv4: ICMP Destination Unreachable, code 4 (fragmentation needed, DF set),
/// with `mtu` in the next-hop-MTU field (RFC 1191). IPv6: ICMPv6 Packet Too Big
/// (RFC 4443) with `mtu` in its 32-bit MTU field.
pub fn build_packet_too_big(packet: &[u8], info: &PacketInfo, mtu: u16) -> Option<Bytes> {
    if is_multicast_or_unspecified(info.src_ip) || is_icmp_error(info) {
        return None;
    }
    match (info.dst_ip, info.src_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let quote_len = (ip_header_len(packet, info) + 8).min(packet.len());
            let mut msg = build_icmp_message(3, 4, &packet[..quote_len]);
            // RFC 1191: the low 16 bits of the "unused" word carry the next-hop MTU.
            msg[6..8].copy_from_slice(&mtu.to_be_bytes());
            let csum = icmpv4_checksum(&msg);
            msg[2..4].copy_from_slice(&csum.to_be_bytes());
            Some(wrap_ipv4(src, dst, PROTO_ICMPV4, &msg))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let budget = MTU - IPV6_HEADER_LEN - ICMP_HEADER_LEN;
            let quote_len = packet.len().min(budget);
            let mut msg = build_icmp_message(2, 0, &packet[..quote_len]);
            // RFC 4443: the 32-bit field after the checksum carries the MTU.
            msg[4..8].copy_from_slice(&(mtu as u32).to_be_bytes());
            let csum = icmpv6_checksum(&src, &dst, &msg);
            msg[2..4].copy_from_slice(&csum.to_be_bytes());
            Some(wrap_ipv6(src, dst, PROTO_ICMPV6, &msg))
        }
        _ => None,
    }
}

/// IPv4 link-local broadcast, any multicast, or the unspecified address: never a
/// legitimate REJECT target.
fn is_multicast_or_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
    }
}

/// True for an ICMP/ICMPv6 *error* message (as opposed to an informational one
/// like echo). ICMPv4 error types: 3 (unreachable), 4, 5, 11, 12. ICMPv6 error
/// messages occupy the low type range 0..=127.
fn is_icmp_error(info: &PacketInfo) -> bool {
    match info.protocol {
        PROTO_ICMPV4 => matches!(info.icmp_type, 3 | 4 | 5 | 11 | 12),
        PROTO_ICMPV6 => info.icmp_type < 128,
        _ => false,
    }
}

/// Length of the original IP header (so we can find the TCP header / how much to
/// quote in an ICMP error).
fn ip_header_len(packet: &[u8], info: &PacketInfo) -> usize {
    match info.src_ip {
        IpAddr::V4(_) => ((packet[0] & 0x0F) as usize) * 4,
        IpAddr::V6(_) => IPV6_HEADER_LEN,
    }
}

// ---------------------------------------------------------------------------
// TCP RST
// ---------------------------------------------------------------------------

/// Build an IP + TCP RST segment per RFC 793's reset generation rules. The reply
/// addresses/ports are the original's, swapped.
fn build_tcp_rst(packet: &[u8], info: &PacketInfo) -> Option<Bytes> {
    let ihl = ip_header_len(packet, info);
    let tcp = packet.get(ihl..)?;
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    let seg_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let seg_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];

    // Payload length consumed by the incoming segment, counting SYN and FIN as
    // one sequence number each (they advance the peer's seq space).
    let ip_total = match info.src_ip {
        IpAddr::V4(_) => u16::from_be_bytes([packet[2], packet[3]]) as usize,
        IpAddr::V6(_) => IPV6_HEADER_LEN + u16::from_be_bytes([packet[4], packet[5]]) as usize,
    };
    let payload = ip_total.saturating_sub(ihl + data_off);
    let mut seg_len = payload as u32;
    if flags & TCP_SYN != 0 {
        seg_len += 1;
    }
    if flags & TCP_FIN != 0 {
        seg_len += 1;
    }

    // RFC 793: if the incoming segment carries an ACK, the RST takes its seq from
    // that ack and bears no ACK of its own; otherwise the RST acknowledges the
    // incoming data (seq 0, RST+ACK).
    let (rst_seq, rst_ack, rst_flags) = if flags & TCP_ACK != 0 {
        (seg_ack, 0, TCP_RST)
    } else {
        (0, seg_seq.wrapping_add(seg_len), TCP_RST | TCP_ACK)
    };

    let mut seg = [0u8; TCP_HEADER_LEN];
    seg[0..2].copy_from_slice(&info.dst_port.to_be_bytes()); // src = original dst
    seg[2..4].copy_from_slice(&info.src_port.to_be_bytes()); // dst = original src
    seg[4..8].copy_from_slice(&rst_seq.to_be_bytes());
    seg[8..12].copy_from_slice(&rst_ack.to_be_bytes());
    seg[12] = ((TCP_HEADER_LEN / 4) as u8) << 4; // data offset 5, no options
    seg[13] = rst_flags;
    // window 0, urgent 0; checksum filled in below.

    // Reply src is the original destination, dst the original source.
    match (info.dst_ip, info.src_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let csum = tcp_checksum_v4(&src, &dst, &seg);
            seg[16..18].copy_from_slice(&csum.to_be_bytes());
            Some(wrap_ipv4(src, dst, PROTO_TCP, &seg))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let csum = tcp_checksum_v6(&src, &dst, &seg);
            seg[16..18].copy_from_slice(&csum.to_be_bytes());
            Some(wrap_ipv6(src, dst, PROTO_TCP, &seg))
        }
        _ => None, // mixed v4/v6 is impossible for a single packet
    }
}

// ---------------------------------------------------------------------------
// ICMP / ICMPv6 destination unreachable
// ---------------------------------------------------------------------------

/// Build an ICMP(v6) destination-unreachable quoting the offending packet. UDP
/// gets "port unreachable" (the code apps map to `ECONNREFUSED`); anything else
/// gets "administratively prohibited / filtered".
fn build_icmp_unreachable(packet: &[u8], info: &PacketInfo) -> Option<Bytes> {
    let udp = info.protocol == 17;
    match (info.dst_ip, info.src_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // Quote the original IP header + 8 bytes (RFC 792).
            let quote_len = (ip_header_len(packet, info) + 8).min(packet.len());
            let code = if udp { 3 } else { 13 }; // port-unreach / admin-filtered
            let mut msg = build_icmp_message(3, code, &packet[..quote_len]);
            let csum = icmpv4_checksum(&msg);
            msg[2..4].copy_from_slice(&csum.to_be_bytes());
            Some(wrap_ipv4(src, dst, PROTO_ICMPV4, &msg))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            // RFC 4443: quote as much of the packet as fits the min MTU.
            let budget = MTU - IPV6_HEADER_LEN - ICMP_HEADER_LEN;
            let quote_len = packet.len().min(budget);
            let code = if udp { 4 } else { 1 }; // port-unreach / admin-prohibited
            let mut msg = build_icmp_message(1, code, &packet[..quote_len]);
            let csum = icmpv6_checksum(&src, &dst, &msg);
            msg[2..4].copy_from_slice(&csum.to_be_bytes());
            Some(wrap_ipv6(src, dst, PROTO_ICMPV6, &msg))
        }
        _ => None,
    }
}

/// Assemble an ICMP/ICMPv6 error message: type, code, zero checksum, 4 unused
/// bytes, then the quoted original packet. The checksum is filled in by the
/// caller (it differs between v4 and v6).
fn build_icmp_message(icmp_type: u8, code: u8, quote: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; ICMP_HEADER_LEN + quote.len()];
    msg[0] = icmp_type;
    msg[1] = code;
    // msg[2..4] checksum, msg[4..8] unused, left zero.
    msg[ICMP_HEADER_LEN..].copy_from_slice(quote);
    msg
}

// ---------------------------------------------------------------------------
// IP wrappers
// ---------------------------------------------------------------------------

fn wrap_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Bytes {
    let total = IPV4_HEADER_LEN + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45; // version 4, IHL 5
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64; // TTL
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let csum = fold(checksum_words(&p[..IPV4_HEADER_LEN]));
    p[10..12].copy_from_slice(&csum.to_be_bytes());
    p[IPV4_HEADER_LEN..].copy_from_slice(payload);
    Bytes::from(p)
}

fn wrap_ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Bytes {
    let total = IPV6_HEADER_LEN + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x60; // version 6
    p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    p[6] = next_header;
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[IPV6_HEADER_LEN..].copy_from_slice(payload);
    Bytes::from(p)
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// Sum 16-bit big-endian words (with odd-byte padding) into a 32-bit accumulator.
fn checksum_words(bytes: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    sum
}

/// Fold a checksum accumulator to its one's-complement 16-bit result.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv4_checksum(msg: &[u8]) -> u16 {
    fold(checksum_words(msg))
}

fn tcp_checksum_v4(src: &Ipv4Addr, dst: &Ipv4Addr, seg: &[u8]) -> u16 {
    let mut sum = checksum_words(&src.octets()) + checksum_words(&dst.octets());
    sum += PROTO_TCP as u32;
    sum += seg.len() as u32;
    sum += checksum_words(seg);
    fold(sum)
}

fn tcp_checksum_v6(src: &Ipv6Addr, dst: &Ipv6Addr, seg: &[u8]) -> u16 {
    icmpv6_like_checksum(src, dst, PROTO_TCP, seg)
}

fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, msg: &[u8]) -> u16 {
    icmpv6_like_checksum(src, dst, PROTO_ICMPV6, msg)
}

/// IPv6 pseudo-header checksum (shared by TCP and ICMPv6): src, dst, upper-layer
/// length, next header, then the payload.
fn icmpv6_like_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut sum = checksum_words(&src.octets()) + checksum_words(&dst.octets());
    sum += payload.len() as u32;
    sum += next_header as u32;
    sum += checksum_words(payload);
    fold(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::parse_packet_info;

    /// A full 16-bit ones-complement sum over a header should fold to 0xffff when
    /// the embedded checksum is correct.
    fn checksum_ok(bytes: &[u8]) -> bool {
        let mut sum = checksum_words(bytes);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    fn tcp_v4(flags: u8, seq: u32, ack: u32) -> Vec<u8> {
        let mut p = vec![0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16).to_be_bytes());
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 5).octets()); // src
        p[16..20].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 9).octets()); // dst
        let t = IPV4_HEADER_LEN;
        p[t..t + 2].copy_from_slice(&44321u16.to_be_bytes()); // src port
        p[t + 2..t + 4].copy_from_slice(&8080u16.to_be_bytes()); // dst port
        p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        p[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
        p[t + 12] = ((TCP_HEADER_LEN / 4) << 4) as u8;
        p[t + 13] = flags;
        p
    }

    #[test]
    fn tcp_syn_gets_rst_ack() {
        let pkt = tcp_v4(TCP_SYN, 1000, 0);
        let info = parse_packet_info(&pkt).unwrap();
        let reply = build_reject(&pkt, &info).unwrap();
        let r = parse_packet_info(&reply).unwrap();
        // addresses + ports swapped
        assert_eq!(r.src_ip, info.dst_ip);
        assert_eq!(r.dst_ip, info.src_ip);
        assert_eq!(r.src_port, 8080);
        assert_eq!(r.dst_port, 44321);
        // RST+ACK, ack = seq + 1 (SYN consumes one)
        assert_eq!(r.tcp_flags & TCP_RST, TCP_RST);
        assert_eq!(r.tcp_flags & TCP_ACK, TCP_ACK);
        let t = IPV4_HEADER_LEN;
        let ack = u32::from_be_bytes([reply[t + 8], reply[t + 9], reply[t + 10], reply[t + 11]]);
        assert_eq!(ack, 1001);
        // IPv4 header checksum valid (no pseudo-header).
        assert!(checksum_ok(&reply[..IPV4_HEADER_LEN]));
        // TCP checksum covers the IPv4 pseudo-header, so recompute with it.
        let (IpAddr::V4(s), IpAddr::V4(d)) = (r.src_ip, r.dst_ip) else {
            panic!("v4");
        };
        let seg = &reply[IPV4_HEADER_LEN..];
        let mut sum = checksum_words(&s.octets()) + checksum_words(&d.octets());
        sum += PROTO_TCP as u32 + seg.len() as u32 + checksum_words(seg);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn tcp_with_ack_gets_bare_rst() {
        // A non-SYN segment carrying an ACK: RST seq = incoming ack, no ACK flag.
        let pkt = tcp_v4(TCP_ACK, 5000, 7777);
        let info = parse_packet_info(&pkt).unwrap();
        let reply = build_reject(&pkt, &info).unwrap();
        let r = parse_packet_info(&reply).unwrap();
        assert_eq!(r.tcp_flags & TCP_RST, TCP_RST);
        assert_eq!(r.tcp_flags & TCP_ACK, 0);
        let t = IPV4_HEADER_LEN;
        let seq = u32::from_be_bytes([reply[t + 4], reply[t + 5], reply[t + 6], reply[t + 7]]);
        assert_eq!(seq, 7777);
    }

    #[test]
    fn incoming_rst_is_not_answered() {
        let pkt = tcp_v4(TCP_RST, 1, 1);
        let info = parse_packet_info(&pkt).unwrap();
        assert!(build_reject(&pkt, &info).is_none());
    }

    fn udp_v4() -> Vec<u8> {
        let mut p = vec![0u8; IPV4_HEADER_LEN + 8];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((IPV4_HEADER_LEN + 8) as u16).to_be_bytes());
        p[9] = 17;
        p[12..16].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 5).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 9).octets());
        let u = IPV4_HEADER_LEN;
        p[u..u + 2].copy_from_slice(&33333u16.to_be_bytes());
        p[u + 2..u + 4].copy_from_slice(&53u16.to_be_bytes());
        p[u + 4..u + 6].copy_from_slice(&8u16.to_be_bytes());
        p
    }

    #[test]
    fn udp_gets_icmp_port_unreachable() {
        let pkt = udp_v4();
        let info = parse_packet_info(&pkt).unwrap();
        let reply = build_reject(&pkt, &info).unwrap();
        let r = parse_packet_info(&reply).unwrap();
        assert_eq!(r.protocol, PROTO_ICMPV4);
        assert_eq!(r.src_ip, info.dst_ip); // reply from the original destination
        assert_eq!(r.dst_ip, info.src_ip);
        // ICMP type 3 (unreachable), code 3 (port)
        assert_eq!(reply[IPV4_HEADER_LEN], 3);
        assert_eq!(reply[IPV4_HEADER_LEN + 1], 3);
        assert!(checksum_ok(&reply[..IPV4_HEADER_LEN]));
        assert!(checksum_ok(&reply[IPV4_HEADER_LEN..]));
        // quotes the original IP header + 8 bytes
        assert_eq!(&reply[IPV4_HEADER_LEN + ICMP_HEADER_LEN..], &pkt[..]);
    }

    #[test]
    fn incoming_icmp_error_is_not_answered() {
        // An ICMP time-exceeded (type 11) must not provoke a reject.
        let mut p = vec![0u8; IPV4_HEADER_LEN + 8];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((IPV4_HEADER_LEN + 8) as u16).to_be_bytes());
        p[9] = PROTO_ICMPV4;
        p[12..16].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 5).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 9).octets());
        p[IPV4_HEADER_LEN] = 11; // time exceeded
        let info = parse_packet_info(&p).unwrap();
        assert!(build_reject(&p, &info).is_none());
    }

    fn tcp_v6(flags: u8, seq: u32) -> Vec<u8> {
        let mut p = vec![0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(TCP_HEADER_LEN as u16).to_be_bytes());
        p[6] = PROTO_TCP;
        let src = Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 5);
        let dst = Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 9);
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        let t = IPV6_HEADER_LEN;
        p[t..t + 2].copy_from_slice(&44321u16.to_be_bytes());
        p[t + 2..t + 4].copy_from_slice(&8080u16.to_be_bytes());
        p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        p[t + 12] = ((TCP_HEADER_LEN / 4) << 4) as u8;
        p[t + 13] = flags;
        p
    }

    #[test]
    fn packet_too_big_v4_is_frag_needed_with_mtu() {
        // A full-size TCP/v4 packet that won't fit the tunnel: the PMTUD reply
        // must be ICMP Destination Unreachable / code 4 (fragmentation needed),
        // carry the next-hop MTU in the low half of the unused word (RFC 1191),
        // swap addresses, and checksum cleanly.
        let pkt = tcp_v4(TCP_SYN, 1000, 0);
        let info = parse_packet_info(&pkt).unwrap();
        let reply = build_packet_too_big(&pkt, &info, 1200).unwrap();
        let r = parse_packet_info(&reply).unwrap();
        assert_eq!(r.protocol, PROTO_ICMPV4);
        assert_eq!(r.src_ip, info.dst_ip); // appears to come back from the dst
        assert_eq!(r.dst_ip, info.src_ip);
        assert_eq!(reply[IPV4_HEADER_LEN], 3); // type: dest unreachable
        assert_eq!(reply[IPV4_HEADER_LEN + 1], 4); // code: fragmentation needed
        // next-hop MTU sits in bytes 6..8 of the ICMP header.
        let mtu = u16::from_be_bytes([reply[IPV4_HEADER_LEN + 6], reply[IPV4_HEADER_LEN + 7]]);
        assert_eq!(mtu, 1200);
        assert!(checksum_ok(&reply[..IPV4_HEADER_LEN]));
        assert!(checksum_ok(&reply[IPV4_HEADER_LEN..]));
        // quotes the original IP header + 8 bytes.
        assert_eq!(
            &reply[IPV4_HEADER_LEN + ICMP_HEADER_LEN..],
            &pkt[..IPV4_HEADER_LEN + 8]
        );
    }

    #[test]
    fn packet_too_big_v6_is_ptb_with_mtu() {
        let pkt = tcp_v6(TCP_SYN, 2000);
        let info = parse_packet_info(&pkt).unwrap();
        let reply = build_packet_too_big(&pkt, &info, 1280).unwrap();
        let r = parse_packet_info(&reply).unwrap();
        assert_eq!(r.protocol, PROTO_ICMPV6);
        assert_eq!(r.src_ip, info.dst_ip);
        assert_eq!(r.dst_ip, info.src_ip);
        assert_eq!(reply[IPV6_HEADER_LEN], 2); // type: packet too big
        assert_eq!(reply[IPV6_HEADER_LEN + 1], 0); // code 0
        // RFC 4443: MTU is the 32-bit field right after the checksum.
        let mtu = u32::from_be_bytes([
            reply[IPV6_HEADER_LEN + 4],
            reply[IPV6_HEADER_LEN + 5],
            reply[IPV6_HEADER_LEN + 6],
            reply[IPV6_HEADER_LEN + 7],
        ]);
        assert_eq!(mtu, 1280);
        // ICMPv6 checksum covers the pseudo-header; recompute in place folds to 0.
        let (IpAddr::V6(s), IpAddr::V6(d)) = (r.src_ip, r.dst_ip) else {
            panic!("v6");
        };
        let msg = &reply[IPV6_HEADER_LEN..];
        let mut sum = checksum_words(&s.octets()) + checksum_words(&d.octets());
        sum += msg.len() as u32 + PROTO_ICMPV6 as u32 + checksum_words(msg);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn packet_too_big_does_not_answer_an_icmp_error() {
        // An inbound ICMP error must never provoke a PMTUD reply (loop guard).
        let mut p = vec![0u8; IPV4_HEADER_LEN + 8];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((IPV4_HEADER_LEN + 8) as u16).to_be_bytes());
        p[9] = PROTO_ICMPV4;
        p[12..16].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 5).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(100, 64, 0, 9).octets());
        p[IPV4_HEADER_LEN] = 3; // dest unreachable (an error)
        let info = parse_packet_info(&p).unwrap();
        assert!(build_packet_too_big(&p, &info, 1200).is_none());
    }

    #[test]
    fn tcp_v6_syn_gets_rst_with_valid_checksum() {
        let pkt = tcp_v6(TCP_SYN, 2000);
        let info = parse_packet_info(&pkt).unwrap();
        let reply = build_reject(&pkt, &info).unwrap();
        let r = parse_packet_info(&reply).unwrap();
        assert_eq!(r.src_ip, info.dst_ip);
        assert_eq!(r.dst_ip, info.src_ip);
        assert_eq!(r.tcp_flags & TCP_RST, TCP_RST);
        // verify the TCP checksum folds correctly over pseudo-header + segment
        let (IpAddr::V6(s), IpAddr::V6(d)) = (r.src_ip, r.dst_ip) else {
            panic!("v6");
        };
        let seg = &reply[IPV6_HEADER_LEN..];
        // recomputing with the embedded checksum in place should yield 0
        let mut sum = checksum_words(&s.octets()) + checksum_words(&d.octets());
        sum += PROTO_TCP as u32;
        sum += seg.len() as u32;
        sum += checksum_words(seg);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }
}
