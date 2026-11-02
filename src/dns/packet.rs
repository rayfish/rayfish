//! Synthesis of DNS and echo replies injected back into the TUN, so the in-daemon
//! Magic DNS resolver can answer queries addressed to the magic IP without a
//! host socket. IPv6 only: the resolver is reached at [`crate::dns::MAGIC_DNS_V6`]
//! and nowhere else, so there is one family to synthesise for.

use std::net::IpAddr;
use std::net::Ipv6Addr;

use bytes::Bytes;

use crate::firewall::PacketInfo;

const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
/// Keep DNS replies within IPv6's minimum MTU, even when the TUN is larger.
const MTU: usize = 1280;
/// The largest DNS message [`build_udp_reply`] can carry.
pub const MAX_DNS_PAYLOAD: usize = MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN;

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
    if dns_payload.len() > MAX_DNS_PAYLOAD {
        return None;
    }
    let total = IPV6_HEADER_LEN + UDP_HEADER_LEN + dns_payload.len();
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

    let udp_csum = udp_checksum(magic_ip, app_ip, &p[udp_off..]);
    let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
    p[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());

    Some(Bytes::from(p))
}

/// UDP checksum over the IPv6 pseudo-header + UDP header + payload.
fn udp_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp_segment: &[u8]) -> u16 {
    transport_checksum(src, dst, 17, udp_segment)
}

/// Answer reachability probes to the resolver without looking for a mesh peer.
/// Only valid, unicast ICMPv6 echo requests receive a reply.
pub(crate) fn build_echo_reply(packet: &[u8], query: &PacketInfo) -> Option<Bytes> {
    let IpAddr::V6(app) = query.src_ip else {
        return None;
    };
    if query.dst_ip != IpAddr::V6(super::MAGIC_DNS_V6)
        || query.protocol != 58
        || app.is_unspecified()
        || app.is_multicast()
    {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes(packet.get(4..6)?.try_into().ok()?));
    let end = IPV6_HEADER_LEN.checked_add(payload_len)?;
    let echo = packet.get(query.transport_offset..end)?;
    if echo.len() < 8
        || echo[0] != 128
        || echo[1] != 0
        || IPV6_HEADER_LEN.checked_add(echo.len())? > MTU
        || transport_checksum(app, super::MAGIC_DNS_V6, 58, echo) != 0
    {
        return None;
    }
    let mut reply = vec![0; IPV6_HEADER_LEN + echo.len()];
    reply[0] = 0x60;
    reply[4..6].copy_from_slice(&u16::try_from(echo.len()).ok()?.to_be_bytes());
    reply[6] = 58;
    reply[7] = 64;
    reply[8..24].copy_from_slice(&super::MAGIC_DNS_V6.octets());
    reply[24..40].copy_from_slice(&app.octets());
    reply[40..].copy_from_slice(echo);
    reply[40] = 129;
    reply[42..44].fill(0);
    let checksum = transport_checksum(super::MAGIC_DNS_V6, app, 58, &reply[40..]);
    reply[42..44].copy_from_slice(&checksum.to_be_bytes());
    Some(Bytes::from(reply))
}

fn transport_checksum(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for ip in [src, dst] {
        for segment in ip.segments() {
            sum += segment as u32;
        }
    }
    sum += u32::from(protocol);
    sum += payload.len() as u32;
    let mut i = 0;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
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

    use crate::dns::MAGIC_DNS_V6;

    fn echo_request(extension: bool) -> Vec<u8> {
        let source = Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 5);
        let offset = if extension { 48 } else { 40 };
        let mut packet = vec![0; offset + 13];
        packet[0] = 0x60;
        let payload_len = u16::try_from(packet.len() - 40).unwrap();
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = if extension { 60 } else { 58 };
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&MAGIC_DNS_V6.octets());
        if extension {
            packet[40] = 58;
        }
        packet[offset] = 128;
        packet[offset + 4..].copy_from_slice(b"\x12\x34\x00\x01probe");
        let checksum = transport_checksum(source, MAGIC_DNS_V6, 58, &packet[offset..]);
        packet[offset + 2..offset + 4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn resolver_echo_reply_preserves_payload_and_validates_checksum() {
        for extension in [false, true] {
            let request = echo_request(extension);
            let info = crate::firewall::parse_packet_info(&request).unwrap();
            let reply = build_echo_reply(&request, &info).expect("valid resolver echo reply");
            let response = crate::firewall::parse_packet_info(&reply).unwrap();
            assert_eq!(response.src_ip, info.dst_ip);
            assert_eq!(response.dst_ip, info.src_ip);
            assert_eq!(response.icmp_type, 129);
            assert_eq!(reply[41], 0);
            assert_eq!(&reply[44..], &request[info.transport_offset + 4..]);
            let IpAddr::V6(app) = info.src_ip else {
                panic!("IPv6 fixture");
            };
            assert_eq!(transport_checksum(MAGIC_DNS_V6, app, 58, &reply[40..]), 0);
        }
    }

    #[test]
    fn resolver_echo_does_not_answer_corrupt_or_non_request_packets() {
        let request = echo_request(false);
        let info = crate::firewall::parse_packet_info(&request).unwrap();
        for index in [40, 41, 42, 52] {
            let mut corrupt = request.clone();
            corrupt[index] ^= 1;
            assert!(build_echo_reply(&corrupt, &info).is_none());
        }
        let IpAddr::V6(app) = info.src_ip else {
            panic!("IPv6 fixture");
        };
        for (kind, code) in [(129, 0), (1, 0), (128, 1)] {
            let mut other = request.clone();
            other[40] = kind;
            other[41] = code;
            other[42..44].fill(0);
            let checksum = transport_checksum(app, MAGIC_DNS_V6, 58, &other[40..]);
            other[42..44].copy_from_slice(&checksum.to_be_bytes());
            let other_info = crate::firewall::parse_packet_info(&other).unwrap();
            assert!(build_echo_reply(&other, &other_info).is_none());
        }
        assert!(build_echo_reply(&request[..48], &info).is_none());
        for source in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        ] {
            let invalid = PacketInfo {
                src_ip: IpAddr::V6(source),
                ..info
            };
            assert!(build_echo_reply(&request, &invalid).is_none());
        }
        let reply = build_echo_reply(&request, &info).unwrap();
        let reply_info = crate::firewall::parse_packet_info(&reply).unwrap();
        assert!(build_echo_reply(&reply, &reply_info).is_none());
    }

    /// The swap, and a UDP checksum that actually verifies: IPv6 has no header
    /// checksum to fall back on and makes the UDP one mandatory, so a wrong one is
    /// a silent drop by the receiving stack rather than a visible error.
    #[test]
    fn build_udp_reply_v6_swaps_and_checksums() {
        let app: Ipv6Addr = "200::5".parse().unwrap();
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V6(app),
            dst_ip: IpAddr::V6(MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
            transport_offset: 40,
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
        assert_eq!(udp_checksum(MAGIC_DNS_V6, app, &pkt[IPV6_HEADER_LEN..]), 0);
    }

    #[test]
    fn build_udp_reply_rejects_ipv4() {
        // The resolver answers on the IPv6 magic address alone, so an IPv4 query
        // never reaches here; guarded so a future caller that hand-builds a
        // PacketInfo gets nothing rather than a malformed reply.
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)),
            dst_ip: IpAddr::V6(MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
            transport_offset: 20,
        };
        assert!(build_udp_reply(&query, b"\x00\x00").is_none());
    }

    #[test]
    fn build_udp_reply_rejects_oversize() {
        let query = crate::firewall::PacketInfo {
            src_ip: IpAddr::V6("200::5".parse().unwrap()),
            dst_ip: IpAddr::V6(MAGIC_DNS_V6),
            protocol: 17,
            src_port: 51000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
            transport_offset: 40,
        };
        // One byte past what fits: the largest payload that does still builds.
        let fits = MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN;
        assert!(build_udp_reply(&query, &vec![0u8; fits]).is_some());
        assert!(build_udp_reply(&query, &vec![0u8; fits + 1]).is_none());
    }
}
