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
    /// Byte offset of the transport header: IHL * 4 for IPv4, 40 plus any
    /// extension headers for IPv6. Anything that edits or reads the transport
    /// header must use this rather than assume a fixed IP header length.
    pub transport_offset: usize,
}

pub fn parse_packet_info(packet: &[u8]) -> Option<PacketInfo> {
    match packet.first()? >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

/// Whether an IPv6 packet is addressed within its own link: a link-local
/// unicast destination (`fe80::/10`) or an interface- or link-scoped multicast
/// group (`ff01::/16`, `ff02::/16`). The kernel sends router solicitations and
/// MLD reports like this into any interface it runs IPv6 on. They have no peer
/// to go to and must not leave the link, so the forwarding loop discards them
/// without counting them as drops.
pub fn is_link_scoped_v6(packet: &[u8]) -> bool {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return false;
    }
    let dst = &packet[24..40];
    let link_local_unicast = dst[0] == 0xfe && dst[1] & 0xc0 == 0x80;
    let link_scoped_multicast = dst[0] == 0xff && matches!(dst[1] & 0x0f, 1 | 2);
    link_local_unicast || link_scoped_multicast
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
    let chain = ipv6_chain(packet)?;
    chain
        .fragment
        .is_none()
        .then_some((chain.protocol, chain.offset))
}

/// Where an IPv6 extension-header walk ended.
struct Ipv6Chain {
    /// The upper-layer protocol, or [`IPV6_FRAGMENT`] for a non-first fragment,
    /// which carries no upper-layer header.
    protocol: u8,
    /// Offset of the upper-layer header, or of the payload on a non-first
    /// fragment.
    offset: usize,
    fragment: Option<FragmentHeader>,
}

#[derive(Clone, Copy)]
struct FragmentHeader {
    /// Fragment offset in 8-octet units; 0 on the first fragment.
    offset: u16,
    id: u32,
}

/// Walk the extension chain. A first fragment is walked through to its
/// upper-layer header, which RFC 7112 requires it to carry; a later fragment
/// stops at its Fragment header. A second Fragment header is refused.
fn ipv6_chain(packet: &[u8]) -> Option<Ipv6Chain> {
    const MAX_HEADERS: usize = 8;
    let mut next = packet[6];
    let mut off = 40;
    let mut fragment = None;
    for _ in 0..MAX_HEADERS {
        let len = match next {
            IPV6_FRAGMENT => {
                if fragment.is_some() {
                    return None;
                }
                let header = packet.get(off..off + 8)?;
                let header = FragmentHeader {
                    offset: u16::from_be_bytes([header[2], header[3]]) >> 3,
                    id: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                };
                fragment = Some(header);
                if header.offset != 0 {
                    return Some(Ipv6Chain {
                        protocol: IPV6_FRAGMENT,
                        offset: off + 8,
                        fragment,
                    });
                }
                8
            }
            IPV6_AH => (usize::from(*packet.get(off + 1)?) + 2) * 4,
            h if IPV6_TLV_EXT_HEADERS.contains(&h) => (usize::from(*packet.get(off + 1)?) + 1) * 8,
            h => {
                return Some(Ipv6Chain {
                    protocol: h,
                    offset: off,
                    fragment,
                });
            }
        };
        next = *packet.get(off)?;
        off = off.checked_add(len)?;
        if off >= packet.len() {
            return None;
        }
    }
    None
}

/// Names the fragments of one original IPv6 packet (RFC 8200 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub id: u32,
}

/// One fragment of an IPv6 packet, classified.
pub struct Ipv6Fragment {
    /// For the first fragment, the upper-layer fields exactly as for a whole
    /// packet. For a later one, only the addresses are real: the protocol is
    /// [`IPV6_FRAGMENT`] and the ports are 0, so it must never be matched
    /// against rules or connection tracking on its own.
    pub info: PacketInfo,
    pub key: FragmentKey,
    /// Offset 0: carries the upper-layer header and decides for the rest.
    pub first: bool,
}

/// Classifies an IPv6 fragment. `None` for anything that is not one, or whose
/// headers cannot be read; [`parse_packet_info`] handles whole packets and
/// still refuses every fragment.
pub fn parse_ipv6_fragment(packet: &[u8]) -> Option<Ipv6Fragment> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let chain = ipv6_chain(packet)?;
    let fragment = chain.fragment?;
    let first = fragment.offset == 0;
    if first && !carries_upper_header(packet, chain.protocol, chain.offset) {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    dst.copy_from_slice(&packet[24..40]);
    let (src, dst) = (Ipv6Addr::from(src), Ipv6Addr::from(dst));
    let info = packet_info(
        packet,
        chain.protocol,
        chain.offset,
        IpAddr::V6(src),
        IpAddr::V6(dst),
    )?;
    Some(Ipv6Fragment {
        info,
        key: FragmentKey {
            src,
            dst,
            id: fragment.id,
        },
        first,
    })
}

/// Whether a first fragment holds its whole upper-layer header, as RFC 7112
/// requires. A tiny first fragment would leave the TCP checksum or flags in a
/// later fragment, out of reach of the firewall and the SSH port rewrite, so it
/// is refused. TCP must also hold any options its data offset declares.
/// Protocols this parser does not read are left to the firewall.
fn carries_upper_header(packet: &[u8], protocol: u8, offset: usize) -> bool {
    const TCP_MIN: usize = 20;
    const UDP_LEN: usize = 8;
    const ICMPV6_LEN: usize = 8;
    let needed = match protocol {
        6 => match packet.get(offset + 12) {
            Some(byte) => usize::from(byte >> 4) * 4,
            None => return false,
        },
        17 => UDP_LEN,
        58 => ICMPV6_LEN,
        _ => 0,
    };
    if protocol == 6 && needed < TCP_MIN {
        return false;
    }
    packet.len() >= offset + needed
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
        transport_offset: header_len,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv6 UDP from `200::1` to `200::2` behind a Fragment header with this
    /// offset (in 8-octet units), M flag set and identification 0xabcd.
    fn udp_fragment(offset: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 64];
        packet[0] = 0x60;
        packet[6] = IPV6_FRAGMENT;
        packet[8] = 0x02;
        packet[23] = 1;
        packet[24] = 0x02;
        packet[39] = 2;
        packet[40] = 17;
        packet[42..44].copy_from_slice(&((offset << 3) | 1).to_be_bytes());
        packet[44..48].copy_from_slice(&0xabcdu32.to_be_bytes());
        packet[48..50].copy_from_slice(&5353u16.to_be_bytes());
        packet[50..52].copy_from_slice(&4500u16.to_be_bytes());
        packet
    }

    #[test]
    fn a_first_fragment_is_classified_by_its_upper_layer() {
        let packet = udp_fragment(0);
        assert!(parse_packet_info(&packet).is_none(), "still refused whole");
        let fragment = parse_ipv6_fragment(&packet).expect("a fragment");
        assert!(fragment.first);
        assert_eq!(
            (
                fragment.info.protocol,
                fragment.info.src_port,
                fragment.info.dst_port
            ),
            (17, 5353, 4500)
        );
        assert_eq!(fragment.info.transport_offset, 48);
        assert_eq!(fragment.key.id, 0xabcd);
        assert_eq!(
            fragment.key.src,
            "200::1".parse::<Ipv6Addr>().expect("addr")
        );
        assert_eq!(
            fragment.key.dst,
            "200::2".parse::<Ipv6Addr>().expect("addr")
        );
    }

    /// A later fragment's first bytes are payload. Reading them as ports would
    /// let a payload pick its own firewall rule.
    #[test]
    fn a_later_fragment_has_no_ports() {
        let fragment = parse_ipv6_fragment(&udp_fragment(185)).expect("a fragment");
        assert!(!fragment.first);
        assert_eq!(
            (
                fragment.info.protocol,
                fragment.info.src_port,
                fragment.info.dst_port
            ),
            (IPV6_FRAGMENT, 0, 0)
        );
        assert_eq!(
            fragment.key,
            parse_ipv6_fragment(&udp_fragment(0)).expect("first").key
        );
    }

    #[test]
    fn only_fragments_are_fragments() {
        let mut whole = udp_fragment(0);
        whole[6] = 17;
        whole.drain(40..48);
        assert!(parse_ipv6_fragment(&whole).is_none());
        assert!(parse_packet_info(&whole).is_some());

        // A fragment header inside a fragment.
        let mut nested = udp_fragment(0);
        nested[40] = IPV6_FRAGMENT;
        assert!(parse_ipv6_fragment(&nested).is_none());

        // Truncated inside the Fragment header.
        assert!(parse_ipv6_fragment(&udp_fragment(185)[..46]).is_none());
    }

    /// A first fragment cut short inside its transport header leaves the rest
    /// of that header, the TCP checksum among it, to a later fragment.
    #[test]
    fn a_tiny_first_fragment_is_refused() {
        // UDP with only its ports.
        assert!(parse_ipv6_fragment(&udp_fragment(0)[..52]).is_none());
        assert!(parse_ipv6_fragment(&udp_fragment(0)[..56]).is_some());

        let mut tcp = udp_fragment(0);
        tcp[40] = 6;
        tcp.resize(48 + 20, 0);
        tcp[48 + 12] = 5 << 4;
        assert!(parse_ipv6_fragment(&tcp).is_some(), "a full TCP header");
        assert!(parse_ipv6_fragment(&tcp[..48 + 18]).is_none(), "18 bytes");
        assert!(parse_ipv6_fragment(&tcp[..48 + 4]).is_none(), "ports only");
        tcp[48 + 12] = 8 << 4;
        assert!(parse_ipv6_fragment(&tcp).is_none(), "options cut off");
        tcp[48 + 12] = 4 << 4;
        assert!(parse_ipv6_fragment(&tcp).is_none(), "data offset below 5");

        let mut icmp = udp_fragment(0);
        icmp[40] = 58;
        assert!(parse_ipv6_fragment(&icmp[..52]).is_none());
        assert!(parse_ipv6_fragment(&icmp[..56]).is_some());
    }

    fn ipv6_to(dst: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[24..40].copy_from_slice(&dst.octets());
        packet
    }

    #[test]
    fn link_scoped_destinations_are_recognised() {
        for dst in ["ff02::2", "ff02::16", "ff01::1", "fe80::1", "febf::1"] {
            let dst: Ipv6Addr = dst.parse().expect("address");
            assert!(is_link_scoped_v6(&ipv6_to(dst)), "{dst}");
        }
    }

    #[test]
    fn routable_destinations_are_not_link_scoped() {
        for dst in ["200::1", "2001:db8::1", "ff05::2", "ff0e::1", "fec0::1"] {
            let dst: Ipv6Addr = dst.parse().expect("address");
            assert!(!is_link_scoped_v6(&ipv6_to(dst)), "{dst}");
        }
        let mut v4 = ipv6_to("ff02::2".parse().expect("address"));
        v4[0] = 0x45;
        assert!(!is_link_scoped_v6(&v4));
        assert!(!is_link_scoped_v6(&[0x60; 39]));
    }
}
