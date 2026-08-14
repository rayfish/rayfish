//! Synthesis of UDP reply packets injected back into the TUN, so the in-daemon
//! Magic DNS resolver can answer queries addressed to the magic IP without a
//! host socket. Both families: IPv4 for [`crate::dns::MAGIC_DNS_V4`], IPv6 for
//! [`crate::dns::MAGIC_DNS_V6`] (the IPv6-only data plane).

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use bytes::Bytes;

use crate::firewall::PacketInfo;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
/// TUN MTU (RFC 8200 IPv6 minimum). Replies must fit.
const MTU: usize = 1280;

/// Builds a complete IP+UDP reply packet for a query, swapping src/dst and
/// computing the checksums. Returns `None` for a mixed-family query (which
/// cannot happen: the query was parsed off the wire) or a payload that would
/// overflow the MTU.
pub fn build_udp_reply(query: &PacketInfo, dns_payload: &[u8]) -> Option<Bytes> {
    match (query.src_ip, query.dst_ip) {
        (IpAddr::V4(app), IpAddr::V4(magic)) => build_v4_reply(query, app, magic, dns_payload),
        (IpAddr::V6(app), IpAddr::V6(magic)) => build_v6_reply(query, app, magic, dns_payload),
        _ => None,
    }
}

fn build_v4_reply(
    query: &PacketInfo,
    app_ip: Ipv4Addr,
    magic_ip: Ipv4Addr,
    dns_payload: &[u8],
) -> Option<Bytes> {
    let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + dns_payload.len();
    if total > MTU {
        return None;
    }
    let mut p = vec![0u8; total];

    // ---- IPv4 header ----
    p[0] = 0x45; // version 4, IHL 5
    p[1] = 0; // DSCP/ECN
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    // id 0, flags 0, frag 0 (already zero)
    p[8] = 64; // TTL
    p[9] = 17; // protocol UDP
    // checksum (10..12) left zero for now
    p[12..16].copy_from_slice(&magic_ip.octets()); // src = magic IP (reply from)
    p[16..20].copy_from_slice(&app_ip.octets()); // dst = the app

    let ip_csum = ones_complement_sum(&p[..IPV4_HEADER_LEN]);
    p[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ---- UDP header ----
    let udp_off = IPV4_HEADER_LEN;
    p[udp_off..udp_off + 2].copy_from_slice(&query.dst_port.to_be_bytes()); // src port = 53
    p[udp_off + 2..udp_off + 4].copy_from_slice(&query.src_port.to_be_bytes()); // dst = app's port
    let udp_len = (UDP_HEADER_LEN + dns_payload.len()) as u16;
    p[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    // checksum (udp_off+6..+8) zero for now
    p[udp_off + UDP_HEADER_LEN..].copy_from_slice(dns_payload);

    let udp_csum = udp_checksum(&IpAddr::V4(magic_ip), &IpAddr::V4(app_ip), &p[udp_off..]);
    // 0 is illegal for IPv4 UDP checksum; use 0xffff per RFC 768.
    let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
    p[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());

    Some(Bytes::from(p))
}

/// The IPv6 twin. No header checksum (IPv6 has none), and the UDP checksum is
/// mandatory rather than optional, so a computed zero must still be sent as
/// `0xffff` (RFC 768 / RFC 8200 §8.1).
fn build_v6_reply(
    query: &PacketInfo,
    app_ip: Ipv6Addr,
    magic_ip: Ipv6Addr,
    dns_payload: &[u8],
) -> Option<Bytes> {
    let total = IPV6_HEADER_LEN + UDP_HEADER_LEN + dns_payload.len();
    if total > MTU {
        return None;
    }
    let mut p = vec![0u8; total];

    // ---- IPv6 header ----
    p[0] = 0x60; // version 6, traffic class 0
    // flow label (1..4) left zero
    let payload_len = (UDP_HEADER_LEN + dns_payload.len()) as u16;
    p[4..6].copy_from_slice(&payload_len.to_be_bytes());
    p[6] = 17; // next header: UDP
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&magic_ip.octets()); // src = magic IP (reply from)
    p[24..40].copy_from_slice(&app_ip.octets()); // dst = the app

    // ---- UDP header ----
    let udp_off = IPV6_HEADER_LEN;
    p[udp_off..udp_off + 2].copy_from_slice(&query.dst_port.to_be_bytes()); // src port = 53
    p[udp_off + 2..udp_off + 4].copy_from_slice(&query.src_port.to_be_bytes()); // dst = app's port
    p[udp_off + 4..udp_off + 6].copy_from_slice(&payload_len.to_be_bytes());
    // checksum (udp_off+6..+8) zero while computing
    p[udp_off + UDP_HEADER_LEN..].copy_from_slice(dns_payload);

    let udp_csum = udp_checksum(&IpAddr::V6(magic_ip), &IpAddr::V6(app_ip), &p[udp_off..]);
    let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
    p[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());

    Some(Bytes::from(p))
}

/// 16-bit one's-complement checksum (used for the IPv4 header).
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum over the pseudo-header + UDP header + payload. The two families'
/// pseudo-headers differ only in the address width: both then carry the
/// upper-layer length and the protocol number, so one routine covers each.
fn udp_checksum(src: &IpAddr, dst: &IpAddr, udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add_addr = |ip: &IpAddr| {
        let octets: Vec<u8> = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        for o in octets.chunks(2) {
            sum += u16::from_be_bytes([o[0], o[1]]) as u32;
        }
    };
    add_addr(src);
    add_addr(dst);
    sum += 17u32; // protocol
    sum += udp_segment.len() as u32; // UDP length
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ipv4_checksum_ok(hdr: &[u8]) -> bool {
        let mut sum: u32 = 0;
        for c in hdr.chunks(2) {
            sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    #[test]
    fn build_udp_reply_swaps_and_checksums() {
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)), // the app
            dst_ip: IpAddr::V4(Ipv4Addr::new(100, 100, 100, 53)), // magic IP
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        let dns = b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00"; // arbitrary DNS body
        let pkt = build_udp_reply(&query, dns).expect("v4 reply");
        let info = crate::firewall::parse_packet_info(&pkt).expect("parses");
        // src/dst swapped:
        assert_eq!(info.src_ip, query.dst_ip);
        assert_eq!(info.dst_ip, query.src_ip);
        assert_eq!(info.src_port, 53);
        assert_eq!(info.dst_port, 51000);
        // IPv4 header checksum valid (first 20 bytes):
        assert!(ipv4_checksum_ok(&pkt[..20]));
        // payload preserved:
        assert_eq!(&pkt[28..], dns);
    }

    /// The IPv6 twin, used by an IPv6-only data plane. Same swap, and a UDP
    /// checksum that actually verifies: IPv6 has no header checksum to fall back
    /// on and makes the UDP one mandatory, so a wrong one is a silent drop by
    /// the receiving stack rather than a visible error.
    #[test]
    fn build_udp_reply_v6_swaps_and_checksums() {
        let app: Ipv6Addr = "200::5".parse().unwrap();
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V6(app),
            dst_ip: IpAddr::V6(crate::dns::MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        let dns = b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
        let pkt = build_udp_reply(&query, dns).expect("v6 reply");
        let info = crate::firewall::parse_packet_info(&pkt).expect("parses");
        assert_eq!(info.src_ip, query.dst_ip);
        assert_eq!(info.dst_ip, query.src_ip);
        assert_eq!(info.src_port, 53);
        assert_eq!(info.dst_port, 51000);

        assert_eq!(pkt[0] >> 4, 6);
        assert_eq!(pkt[6], 17); // next header: UDP
        // Payload length covers the UDP header + the DNS body, and the header is
        // a fixed 40 bytes, so the body starts at 48.
        assert_eq!(
            u16::from_be_bytes([pkt[4], pkt[5]]) as usize,
            UDP_HEADER_LEN + dns.len()
        );
        assert_eq!(&pkt[48..], dns);

        // Recomputing over the received segment must come out zero: the sum of
        // the pseudo-header and a segment carrying a correct checksum folds to
        // 0xffff, which the routine complements to 0.
        assert_eq!(
            udp_checksum(&query.dst_ip, &query.src_ip, &pkt[IPV6_HEADER_LEN..]),
            0
        );
    }

    #[test]
    fn build_udp_reply_rejects_mixed_families() {
        // Cannot arise from a parsed packet; guarded so a future caller that
        // hand-builds a PacketInfo gets nothing rather than a malformed reply.
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)),
            dst_ip: IpAddr::V6(crate::dns::MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        assert!(build_udp_reply(&query, b"\x00\x00").is_none());
    }

    #[test]
    fn build_udp_reply_rejects_oversize() {
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(100, 100, 100, 53)),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        let big = vec![0u8; 1300];
        assert!(build_udp_reply(&query, &big).is_none());
    }
}
