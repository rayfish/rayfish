//! Shared generators for the property tests.
//!
//! The packet strategy lives here because two suites need it: the firewall
//! properties parse these packets, and the reject properties synthesize
//! replies to them. Both need the packets to be structurally honest (correct
//! length fields, a real TCP data offset), which is easy to get subtly wrong
//! twice.
//!
//! Each test binary compiles this module and uses a different subset of it, so
//! "never used" here means "not used by *this* binary" and says nothing about
//! whether the helper is dead. That is what the blanket allow below is for; it
//! is not a stand-in for deleting code no one calls.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rayfish::firewall::PacketInfo;

use iroh::EndpointId;

/// Distinct identities from a seed, derived through a secret key so they are
/// real curve points.
pub fn id_from_seed(seed: u32) -> EndpointId {
    let mut key_bytes = [0u8; 32];
    key_bytes[..4].copy_from_slice(&seed.to_le_bytes());
    iroh::SecretKey::from(key_bytes).public()
}

pub const PROTO_ICMPV4: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// A structurally valid IP packet, described by the values a correct parser
/// must recover from it. `encode` renders it to wire bytes; `expected` gives
/// the `PacketInfo` the parser must produce for those bytes.
#[derive(Debug, Clone)]
pub struct PacketSpec {
    pub v6: bool,
    /// IPv4 header length in 32-bit words. Always >= 5 for a valid packet;
    /// the malformed-header property drives this below 5 deliberately.
    pub ihl: u8,
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub icmp_type: u8,
    pub icmp_id: u16,
}

/// Bytes of L4 header the encoder reserves. Covers a 20-byte TCP header, the
/// largest of the three.
const L4_LEN: usize = 20;

impl PacketSpec {
    pub fn header_len(&self) -> usize {
        if self.v6 { 40 } else { self.ihl as usize * 4 }
    }

    pub fn is_icmp(&self) -> bool {
        self.protocol == PROTO_ICMPV4 || self.protocol == PROTO_ICMPV6
    }

    /// Whether this is an ICMP echo request or reply, the only ICMP types
    /// carrying an identifier.
    pub fn is_icmp_echo(&self) -> bool {
        (self.protocol == PROTO_ICMPV4 && (self.icmp_type == 8 || self.icmp_type == 0))
            || (self.protocol == PROTO_ICMPV6 && (self.icmp_type == 128 || self.icmp_type == 129))
    }

    pub fn encode(&self) -> Vec<u8> {
        let header_len = self.header_len();
        let total = header_len + L4_LEN;
        let mut pkt = vec![0u8; total];

        if self.v6 {
            pkt[0] = 0x60;
            // Payload length: everything after the fixed 40-byte header.
            pkt[4..6].copy_from_slice(&(L4_LEN as u16).to_be_bytes());
            pkt[6] = self.protocol;
            pkt[7] = 64; // hop limit
            let IpAddr::V6(src) = self.src else {
                unreachable!("v6 spec carries v6 addresses")
            };
            let IpAddr::V6(dst) = self.dst else {
                unreachable!("v6 spec carries v6 addresses")
            };
            pkt[8..24].copy_from_slice(&src.octets());
            pkt[24..40].copy_from_slice(&dst.octets());
        } else {
            pkt[0] = 0x40 | (self.ihl & 0x0F);
            // Total length: the whole datagram, header included.
            pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            pkt[8] = 64; // TTL
            pkt[9] = self.protocol;
            let IpAddr::V4(src) = self.src else {
                unreachable!("v4 spec carries v4 addresses")
            };
            let IpAddr::V4(dst) = self.dst else {
                unreachable!("v4 spec carries v4 addresses")
            };
            pkt[12..16].copy_from_slice(&src.octets());
            pkt[16..20].copy_from_slice(&dst.octets());
        }

        let l4 = header_len;
        match self.protocol {
            PROTO_TCP => {
                pkt[l4..l4 + 2].copy_from_slice(&self.src_port.to_be_bytes());
                pkt[l4 + 2..l4 + 4].copy_from_slice(&self.dst_port.to_be_bytes());
                pkt[l4 + 4..l4 + 8].copy_from_slice(&self.tcp_seq.to_be_bytes());
                pkt[l4 + 8..l4 + 12].copy_from_slice(&self.tcp_ack.to_be_bytes());
                pkt[l4 + 12] = 5 << 4; // data offset 5 words, no options
                pkt[l4 + 13] = self.tcp_flags;
            }
            PROTO_UDP => {
                pkt[l4..l4 + 2].copy_from_slice(&self.src_port.to_be_bytes());
                pkt[l4 + 2..l4 + 4].copy_from_slice(&self.dst_port.to_be_bytes());
                pkt[l4 + 4..l4 + 6].copy_from_slice(&(L4_LEN as u16).to_be_bytes());
            }
            PROTO_ICMPV4 | PROTO_ICMPV6 => {
                pkt[l4] = self.icmp_type;
                pkt[l4 + 4..l4 + 6].copy_from_slice(&self.icmp_id.to_be_bytes());
            }
            _ => {}
        }
        pkt
    }

    /// The `PacketInfo` a correct parser must produce for `encode()`. Fields
    /// the parser only fills in for the relevant protocol are zero elsewhere.
    pub fn expected(&self) -> PacketInfo {
        let has_ports = self.protocol == PROTO_TCP || self.protocol == PROTO_UDP;
        PacketInfo {
            src_ip: self.src,
            dst_ip: self.dst,
            protocol: self.protocol,
            src_port: if has_ports { self.src_port } else { 0 },
            dst_port: if has_ports { self.dst_port } else { 0 },
            tcp_flags: if self.protocol == PROTO_TCP {
                self.tcp_flags
            } else {
                0
            },
            icmp_type: if self.is_icmp() { self.icmp_type } else { 0 },
            icmp_id: if self.is_icmp() && self.is_icmp_echo() {
                self.icmp_id
            } else {
                0
            },
        }
    }
}

/// Field-by-field comparison, so a failure names the field that differs
/// rather than dumping two whole structs.
pub fn assert_info_eq(got: &PacketInfo, want: &PacketInfo) -> Result<(), TestCaseError> {
    prop_assert_eq!(got.src_ip, want.src_ip);
    prop_assert_eq!(got.dst_ip, want.dst_ip);
    prop_assert_eq!(got.protocol, want.protocol);
    prop_assert_eq!(got.src_port, want.src_port);
    prop_assert_eq!(got.dst_port, want.dst_port);
    prop_assert_eq!(got.tcp_flags, want.tcp_flags);
    prop_assert_eq!(got.icmp_type, want.icmp_type);
    prop_assert_eq!(got.icmp_id, want.icmp_id);
    Ok(())
}

/// Protocols the parser treats specially, plus a spread of ones it should
/// ignore. Weighted toward the interesting cases: uniform u8 would spend most
/// of its budget on protocols with no parsing logic at all.
pub fn protocol_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        4 => prop_oneof![Just(PROTO_TCP), Just(PROTO_UDP), Just(PROTO_ICMPV4), Just(PROTO_ICMPV6)],
        1 => any::<u8>(),
    ]
}

/// ICMP types, weighted toward echo request/reply since those carry an
/// identifier and drive the conntrack special case.
pub fn icmp_type_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        4 => prop_oneof![Just(8u8), Just(0), Just(128), Just(129)],
        1 => any::<u8>(),
    ]
}

/// A well-formed packet the parser is expected to accept.
///
/// IPv6 packets naming an extension header are filtered out rather than
/// generated: `parse_ipv6` deliberately refuses them (byte 6 is not the
/// upper-layer protocol and offset 40 is not the ports), so they are not
/// "well-formed" for the purposes of the round-trip property. That refusal has
/// its own property below.
pub fn packet_spec() -> impl Strategy<Value = PacketSpec> {
    (
        any::<bool>(),
        5u8..=15,
        protocol_strategy(),
        (any::<[u8; 4]>(), any::<[u8; 4]>()),
        (any::<[u8; 16]>(), any::<[u8; 16]>()),
        (any::<u16>(), any::<u16>()),
        (any::<u8>(), any::<u32>(), any::<u32>()),
        (icmp_type_strategy(), any::<u16>()),
    )
        .prop_map(
            |(
                v6,
                ihl,
                protocol,
                (v4a, v4b),
                (v6a, v6b),
                (src_port, dst_port),
                (tcp_flags, tcp_seq, tcp_ack),
                (icmp_type, icmp_id),
            )| {
                let (src, dst) = if v6 {
                    (
                        IpAddr::V6(Ipv6Addr::from(v6a)),
                        IpAddr::V6(Ipv6Addr::from(v6b)),
                    )
                } else {
                    (
                        IpAddr::V4(Ipv4Addr::from(v4a)),
                        IpAddr::V4(Ipv4Addr::from(v4b)),
                    )
                };
                PacketSpec {
                    v6,
                    ihl,
                    protocol,
                    src,
                    dst,
                    src_port,
                    dst_port,
                    tcp_flags,
                    tcp_seq,
                    tcp_ack,
                    icmp_type,
                    icmp_id,
                }
            },
        )
        .prop_filter(
            "an IPv6 extension header is deliberately unparseable",
            |spec| !(spec.v6 && rayfish::firewall::IPV6_EXTENSION_HEADERS.contains(&spec.protocol)),
        )
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// Sum 16-bit big-endian words, padding an odd trailing byte.
pub fn checksum_words(bytes: &[u8]) -> u32 {
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

pub fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// A one's-complement checksum verifies when the sum over the data, with the
/// checksum field still in place, folds to 0xffff.
pub fn checksum_valid(bytes: &[u8]) -> bool {
    fold(checksum_words(bytes)) == 0xffff
}

/// Verify a checksum computed over a pseudo-header: addresses, upper-layer
/// length, and protocol, followed by the payload.
pub fn pseudo_checksum_valid(src: &[u8], dst: &[u8], proto: u8, payload: &[u8]) -> bool {
    let mut sum = checksum_words(src) + checksum_words(dst);
    sum += payload.len() as u32;
    sum += proto as u32;
    sum += checksum_words(payload);
    fold(sum) == 0xffff
}
