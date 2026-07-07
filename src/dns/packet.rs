//! Synthesis of IPv4/UDP reply packets injected back into the TUN, so the
//! in-daemon Magic DNS resolver can answer queries addressed to the magic IP
//! without a host socket. v1 is IPv4/UDP only.

use std::net::IpAddr;
use std::net::Ipv4Addr;

use bytes::Bytes;

use crate::firewall::PacketInfo;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
/// TUN MTU (RFC 8200 IPv6 minimum). Replies must fit.
const MTU: usize = 1280;

/// Builds a complete IPv4+UDP reply packet for a query, swapping src/dst and
/// computing both checksums. Returns `None` for non-IPv4 endpoints or a payload
/// that would overflow the MTU.
pub fn build_udp_reply(query: &PacketInfo, dns_payload: &[u8]) -> Option<Bytes> {
    let (IpAddr::V4(app_ip), IpAddr::V4(magic_ip)) = (query.src_ip, query.dst_ip) else {
        return None;
    };
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

    let udp_csum = udp_checksum(&magic_ip, &app_ip, &p[udp_off..]);
    // 0 is illegal for IPv4 UDP checksum; use 0xffff per RFC 768.
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

/// UDP checksum over the pseudo-header + UDP header + payload.
fn udp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for o in src.octets().chunks(2) {
        sum += u16::from_be_bytes([o[0], o[1]]) as u32;
    }
    for o in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([o[0], o[1]]) as u32;
    }
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
    use std::net::{IpAddr, Ipv4Addr};

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
