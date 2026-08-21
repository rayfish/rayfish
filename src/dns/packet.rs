//! Synthesis of UDP reply packets injected back into the TUN, so the in-daemon
//! Magic DNS resolver can answer queries addressed to the magic IP without a
//! host socket. IPv6 only: the resolver is reached at [`crate::dns::MAGIC_DNS_V6`]
//! and nowhere else, so there is one family to synthesise for.

use std::net::IpAddr;
use std::net::Ipv6Addr;

use bytes::Bytes;

use crate::firewall::PacketInfo;

const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
/// TUN MTU (RFC 8200 IPv6 minimum). Replies must fit.
const MTU: usize = 1280;

/// Builds a complete IP+UDP reply packet for a query, swapping src/dst and
/// computing the checksums. The resolver answers on [`crate::dns::MAGIC_DNS_V6`]
/// alone, so an IPv4 query never reaches here; it and a payload that would
/// overflow the MTU both return `None`.
pub fn build_udp_reply(query: &PacketInfo, dns_payload: &[u8]) -> Option<Bytes> {
    match (query.src_ip, query.dst_ip) {
        (IpAddr::V6(app), IpAddr::V6(magic)) => build_v6_reply(query, app, magic, dns_payload),
        _ => None,
    }
}

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

    /// The swap, and a UDP checksum that actually verifies: IPv6 has no header
    /// checksum to fall back on and makes the UDP one mandatory, so a wrong one is
    /// a silent drop by the receiving stack rather than a visible error.
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
    fn build_udp_reply_rejects_ipv4() {
        // The resolver answers on the IPv6 magic address alone, so an IPv4 query
        // never reaches here; guarded so a future caller that hand-builds a
        // PacketInfo gets nothing rather than a malformed reply.
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
