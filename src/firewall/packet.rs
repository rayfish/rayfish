//! IP packet classification for the firewall hot path.
//!
//! The parser is deliberately conservative. A packet is returned only when its
//! network and transport fields can be read without guessing, because those
//! fields feed rule matching and connection tracking.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{is_icmp, is_icmp_echo_reply, is_icmp_echo_request};

#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP flags byte (0 for non-TCP or truncated TCP header).
    pub tcp_flags: u8,
    /// ICMP/ICMPv6 type (0 for non-ICMP or truncated ICMP header).
    pub icmp_type: u8,
    /// ICMP echo identifier (0 for non-echo ICMP).
    pub icmp_id: u16,
}

pub fn parse_packet_info(packet: &[u8]) -> Option<PacketInfo> {
    match packet.first()? >> 4 {
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
    if ihl < 5 {
        return None;
    }
    let header_len = ihl * 4;
    if packet.len() < header_len {
        return None;
    }
    // Non-first fragments have no transport header. Refusing every fragment
    // avoids creating a flow from payload bytes or forwarding an incomplete
    // datagram when its siblings are refused.
    let frag_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1FFF;
    if frag_offset != 0 {
        return None;
    }

    let protocol = packet[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    packet_info(packet, protocol, header_len, src_ip, dst_ip)
}

/// IPv6 next-header values that are extension headers rather than upper-layer
/// protocols. The parser walks them before reading ports.
pub const IPV6_EXTENSION_HEADERS: [u8; 8] = [0, 43, 44, 51, 60, 135, 139, 140];

const IPV6_TLV_EXT_HEADERS: [u8; 6] = [0, 43, 60, 135, 139, 140];
pub(crate) const IPV6_AH: u8 = 51;
pub(crate) const IPV6_FRAGMENT: u8 = 44;

/// Return the actual upper-layer protocol and offset, refusing fragments,
/// truncated chains, and chains that exceed the RFC-recommended depth.
fn ipv6_upper_layer(packet: &[u8]) -> Option<(u8, usize)> {
    const MAX_HEADERS: usize = 8;
    let mut next = packet[6];
    let mut off = 40;
    for _ in 0..MAX_HEADERS {
        let len = match next {
            IPV6_FRAGMENT => return None,
            IPV6_AH => (usize::from(*packet.get(off + 1)?) + 2) * 4,
            h if IPV6_TLV_EXT_HEADERS.contains(&h) => (usize::from(*packet.get(off + 1)?) + 1) * 8,
            h => return Some((h, off)),
        };
        next = *packet.get(off)?;
        off = off.checked_add(len)?;
        if off >= packet.len() {
            return None;
        }
    }
    None
}

fn parse_ipv6(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 40 {
        return None;
    }
    let (protocol, header_len) = ipv6_upper_layer(packet)?;
    if matches!(protocol, 6 | 17) && packet.len() < header_len + 4 {
        return None;
    }
    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    dst_octets.copy_from_slice(&packet[24..40]);
    packet_info(
        packet,
        protocol,
        header_len,
        IpAddr::V6(Ipv6Addr::from(src_octets)),
        IpAddr::V6(Ipv6Addr::from(dst_octets)),
    )
}

fn packet_info(
    packet: &[u8],
    protocol: u8,
    header_len: usize,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<PacketInfo> {
    Some(PacketInfo {
        src_ip,
        dst_ip,
        protocol,
        src_port: port(packet, protocol, header_len, 0),
        dst_port: port(packet, protocol, header_len, 2),
        tcp_flags: tcp_flags(packet, protocol, header_len),
        icmp_type: icmp_type(packet, protocol, header_len),
        icmp_id: icmp_id(packet, protocol, header_len),
    })
}

fn port(packet: &[u8], protocol: u8, header_len: usize, offset: usize) -> u16 {
    if protocol != 6 && protocol != 17 {
        return 0;
    }
    let Some(bytes) = packet.get(header_len + offset..header_len + offset + 2) else {
        return 0;
    };
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn tcp_flags(packet: &[u8], protocol: u8, header_len: usize) -> u8 {
    if protocol == 6 {
        packet.get(header_len + 13).copied().unwrap_or(0)
    } else {
        0
    }
}

fn icmp_type(packet: &[u8], protocol: u8, header_len: usize) -> u8 {
    if is_icmp(protocol) {
        packet.get(header_len).copied().unwrap_or(0)
    } else {
        0
    }
}

fn icmp_id(packet: &[u8], protocol: u8, header_len: usize) -> u16 {
    let kind = icmp_type(packet, protocol, header_len);
    if !is_icmp_echo_request(protocol, kind) && !is_icmp_echo_reply(protocol, kind) {
        return 0;
    }
    let bytes = match packet.get(header_len + 4..header_len + 6) {
        Some(bytes) => bytes,
        None => return 0,
    };
    u16::from_be_bytes([bytes[0], bytes[1]])
}
