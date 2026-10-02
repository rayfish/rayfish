//! IPv4 exit traffic uses a local client address and gateway-owned NAT leases.
//!
//! Leases belong to authenticated mesh identities and networks, not packet
//! source addresses. They are persisted and never reused: kernel conntrack can
//! outlive both a peer connection and the daemon. The mesh itself stays IPv6-only.

use std::collections::HashMap;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use thiserror::Error;
use tokio::task::JoinError;

use crate::peers::FastDashMap;

pub const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 2);
pub const SERVER_PREFIX: &str = "198.19.0.0/16";
const MAX_LEASES: usize = 65534;

pub fn is_server_addr(ip: Ipv4Addr) -> bool {
    ip.octets()[..2] == [198, 19]
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Lease {
    pub peer: Ipv6Addr,
    pub network: SmolStr,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("IPv4 exit leases are not initialized")]
    Uninitialized,
    #[error("IPv4 exit lease pool is exhausted")]
    Exhausted,
    #[error("invalid IPv4 exit lease file")]
    InvalidLeases,
    #[error("IPv4 exit lease lock was poisoned")]
    Poisoned,
    #[error("IPv4 exit lease I/O failed: {0}")]
    Io(#[from] IoError),
    #[error("IPv4 exit lease encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("saving IPv4 exit leases: {0}")]
    Save(String),
    #[error("IPv4 exit lease task failed: {0}")]
    Task(#[from] JoinError),
    #[error("malformed or fragmented IPv4 exit packet")]
    Packet,
}

#[derive(Default)]
struct Allocation {
    path: Option<PathBuf>,
    leases: Vec<Lease>,
}

#[derive(Clone, Default)]
pub struct Nat {
    allocation: Arc<Mutex<Allocation>>,
    outbound: Arc<FastDashMap<Lease, Ipv4Addr>>,
    inbound: Arc<FastDashMap<Ipv4Addr, Lease>>,
}

impl Nat {
    /// Called on the blocking pool before enabling forwarding.
    pub fn initialize(&self, path: PathBuf) -> Result<(), Error> {
        let mut allocation = self.allocation.lock().map_err(|_| Error::Poisoned)?;
        if allocation.path.is_some() {
            return Ok(());
        }
        let leases: Vec<Lease> = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let mut unique = HashMap::new();
        if leases.len() > MAX_LEASES {
            return Err(Error::InvalidLeases);
        }
        for (index, lease) in leases.iter().enumerate() {
            if unique.insert(lease.clone(), address(index)).is_some() {
                return Err(Error::InvalidLeases);
            }
        }
        for (lease, addr) in unique {
            self.inbound.insert(addr, lease.clone());
            self.outbound.insert(lease, addr);
        }
        allocation.leases = leases;
        allocation.path = Some(path);
        Ok(())
    }

    fn allocate(&self, lease: Lease) -> Result<Ipv4Addr, Error> {
        let mut allocation = self.allocation.lock().map_err(|_| Error::Poisoned)?;
        if let Some(addr) = self.outbound.get(&lease) {
            return Ok(*addr);
        }
        let path = allocation.path.as_ref().ok_or(Error::Uninitialized)?;
        if allocation.leases.len() >= MAX_LEASES {
            return Err(Error::Exhausted);
        }
        let addr = address(allocation.leases.len());
        let mut leases = allocation.leases.clone();
        leases.push(lease.clone());
        crate::config::write_file(path, &serde_json::to_vec(&leases)?, false)
            .map_err(|e| Error::Save(e.to_string()))?;
        allocation.leases = leases;
        self.inbound.insert(addr, lease.clone());
        self.outbound.insert(lease, addr);
        Ok(addr)
    }

    pub fn return_lease(&self, addr: Ipv4Addr) -> Option<Lease> {
        self.inbound.get(&addr).map(|entry| entry.clone())
    }

    /// The caller has already checked membership, source and exit permission.
    pub async fn outbound(
        &self,
        packet: Bytes,
        peer: Ipv6Addr,
        network: SmolStr,
    ) -> Result<Bytes, Error> {
        let lease = Lease { peer, network };
        let cached = self.outbound.get(&lease).map(|entry| *entry);
        let addr = match cached {
            Some(addr) => addr,
            None => {
                let nat = self.clone();
                tokio::task::spawn_blocking(move || nat.allocate(lease)).await??
            }
        };
        rewrite(packet, CLIENT_ADDR, addr)
    }
}

fn address(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 19, 0, 1)) + index as u32)
}

/// Rewrite matching addresses, including the original packet quoted by an ICMP
/// error. Incremental transport checksums also work on a truncated ICMP quote.
pub fn rewrite(packet: Bytes, old: Ipv4Addr, new: Ipv4Addr) -> Result<Bytes, Error> {
    let mut bytes = packet.to_vec();
    rewrite_inner(&mut bytes, old.octets(), new.octets(), false)?;
    Ok(Bytes::from(bytes))
}

fn rewrite_inner(p: &mut [u8], old: [u8; 4], new: [u8; 4], quoted: bool) -> Result<(), Error> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return Err(Error::Packet);
    }
    let header = usize::from(p[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    if header != 20
        || header > p.len()
        || total < header
        || (!quoted && total != p.len())
        || u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0
    {
        return Err(Error::Packet);
    }
    let checksum_offset = match p[9] {
        6 => Some(header + 16),
        17 => Some(header + 6),
        _ => None,
    };
    if !quoted && ((p[9] == 6 && p.len() < header + 20) || (p[9] == 17 && p.len() < header + 8)) {
        return Err(Error::Packet);
    }
    for offset in [12, 16] {
        if p[offset..offset + 4] != old {
            continue;
        }
        for word in [0, 2] {
            let before = u16::from_be_bytes([old[word], old[word + 1]]);
            let after = u16::from_be_bytes([new[word], new[word + 1]]);
            replace_checksum(p, 10, before, after, false);
            if let Some(off) = checksum_offset.filter(|off| off + 2 <= p.len()) {
                replace_checksum(p, off, before, after, p[9] == 17);
            }
        }
        p[offset..offset + 4].copy_from_slice(&new);
    }
    if !quoted && p[9] == 1 {
        if p.len() < header + 8 {
            return Err(Error::Packet);
        }
        if matches!(p[header], 3 | 11 | 12) {
            rewrite_inner(&mut p[header + 8..], old, new, true)?;
            p[header + 2..header + 4].fill(0);
            let sum = checksum(&p[header..]);
            p[header + 2..header + 4].copy_from_slice(&sum.to_be_bytes());
        }
    }
    Ok(())
}

fn replace_checksum(p: &mut [u8], off: usize, old: u16, new: u16, udp: bool) {
    let check = u16::from_be_bytes([p[off], p[off + 1]]);
    if udp && check == 0 {
        return;
    }
    let mut sum = u32::from(!check) + u32::from(!old) + u32::from(new);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let updated = !(sum as u16);
    let updated = if udp && updated == 0 {
        u16::MAX
    } else {
        updated
    };
    p[off..off + 2].copy_from_slice(&updated.to_be_bytes());
}

fn checksum(p: &[u8]) -> u16 {
    let mut sum: u32 = p
        .chunks(2)
        .map(|word| u32::from(word[0]) * 256 + u32::from(*word.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Defaults and split defaults do not claim local address space. Specific
/// routes overlapping our local source or gateway pool must remain untouched.
#[derive(Clone, Copy)]
pub enum AddressSpace {
    Client,
    Gateway,
}

pub fn conflicts_with_route(cidr: &str, space: AddressSpace) -> bool {
    let (ip, bits) = cidr.split_once('/').unwrap_or((cidr, "32"));
    // BSD route tables abbreviate network addresses, such as 198.19/16.
    let mut ip = ip.to_owned();
    while ip.bytes().filter(|b| *b == b'.').count() < 3 {
        ip.push_str(".0");
    }
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    if !(2..=32).contains(&bits) {
        return false;
    }
    let mask = u32::MAX << (32 - bits);
    let first = u32::from(ip) & mask;
    let last = first | !mask;
    let client = u32::from(CLIENT_ADDR);
    match space {
        AddressSpace::Client => first <= client && client <= last,
        AddressSpace::Gateway => {
            first <= u32::from(Ipv4Addr::new(198, 19, 255, 255))
                && last >= u32::from(Ipv4Addr::new(198, 19, 0, 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(protocol: u8) -> Bytes {
        let mut p = vec![0; if protocol == 6 { 40 } else { 28 }];
        p[0] = 0x45;
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p[8] = 64;
        p[9] = protocol;
        p[12..16].copy_from_slice(&CLIENT_ADDR.octets());
        p[16..20].copy_from_slice(&[203, 0, 113, 1]);
        p[20..22].copy_from_slice(&12345u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        if protocol == 6 {
            p[32] = 0x50;
            p[33] = 2;
        }
        if protocol == 17 {
            p[24..26].copy_from_slice(&8u16.to_be_bytes());
        }
        let check = transport_checksum(&p);
        let off = if protocol == 6 { 36 } else { 26 };
        p[off..off + 2].copy_from_slice(&check.to_be_bytes());
        let check = checksum(&p[..20]);
        p[10..12].copy_from_slice(&check.to_be_bytes());
        Bytes::from(p)
    }

    fn transport_checksum(p: &[u8]) -> u16 {
        let mut pseudo = p[12..20].to_vec();
        pseudo.extend([0, p[9]]);
        pseudo.extend(((p.len() - 20) as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        checksum(&pseudo)
    }

    #[test]
    fn tcp_and_udp_checksums_survive_both_translations() {
        for protocol in [6, 17] {
            let original = packet(protocol);
            assert_eq!(transport_checksum(&original), 0);
            let translated = rewrite(original.clone(), CLIENT_ADDR, address(7)).unwrap();
            assert_eq!(&translated[12..16], &address(7).octets());
            assert_eq!(checksum(&translated[..20]), 0);
            assert_eq!(transport_checksum(&translated), 0);
            assert_eq!(
                rewrite(translated, address(7), CLIENT_ADDR).unwrap(),
                original
            );
        }
        let mut no_checksum = packet(17).to_vec();
        no_checksum[26..28].fill(0);
        let translated = rewrite(Bytes::from(no_checksum), CLIENT_ADDR, address(2)).unwrap();
        assert_eq!(&translated[26..28], &[0, 0]);
    }

    #[test]
    fn icmp_errors_restore_the_quoted_flow_and_its_checksums() {
        for protocol in [6, 17] {
            let original = packet(protocol);
            let mapped = rewrite(original.clone(), CLIENT_ADDR, address(7)).unwrap();
            for quote_len in [28, mapped.len()] {
                let mut error = vec![0; 28];
                error[0] = 0x45;
                error[8] = 64;
                error[9] = 1;
                error[12..16].copy_from_slice(&[203, 0, 113, 1]);
                error[16..20].copy_from_slice(&address(7).octets());
                error[20] = 3;
                error[21] = 4;
                error[26..28].copy_from_slice(&1280u16.to_be_bytes());
                error.extend_from_slice(&mapped[..quote_len]);
                let len = error.len() as u16;
                error[2..4].copy_from_slice(&len.to_be_bytes());
                let check = checksum(&error[..20]);
                error[10..12].copy_from_slice(&check.to_be_bytes());
                let check = checksum(&error[20..]);
                error[22..24].copy_from_slice(&check.to_be_bytes());
                let restored = rewrite(Bytes::from(error), address(7), CLIENT_ADDR).unwrap();
                assert_eq!(checksum(&restored[..20]), 0);
                assert_eq!(checksum(&restored[20..]), 0);
                assert_eq!(&restored[16..20], &CLIENT_ADDR.octets());
                assert_eq!(&restored[28..], &original[..quote_len]);
            }
        }
    }

    #[test]
    fn rejects_fragments_source_routes_and_truncated_headers() {
        for flags in [0x2000u16, 1] {
            let mut p = packet(6).to_vec();
            p[6..8].copy_from_slice(&flags.to_be_bytes());
            assert!(rewrite(Bytes::from(p), CLIENT_ADDR, address(0)).is_err());
        }
        let mut p = packet(6).to_vec();
        p[0] = 0x46;
        assert!(rewrite(Bytes::from(p), CLIENT_ADDR, address(0)).is_err());
        for len in 0..40 {
            let mut p = packet(6).slice(..len).to_vec();
            if len >= 4 {
                p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            }
            // At least the full TCP header is required for unquoted packets.
            assert!(rewrite(Bytes::from(p), CLIENT_ADDR, address(0)).is_err());
        }
    }

    #[tokio::test]
    async fn identical_client_flows_get_separate_persistent_leases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.json");
        let nat = Nat::default();
        nat.initialize(path.clone()).unwrap();
        let first: Ipv6Addr = "200::1".parse().unwrap();
        let second: Ipv6Addr = "200::2".parse().unwrap();
        let a = nat
            .outbound(packet(6), first, "example".into())
            .await
            .unwrap();
        let b = nat
            .outbound(packet(6), second, "example".into())
            .await
            .unwrap();
        let other_network = nat
            .outbound(packet(6), first, "other".into())
            .await
            .unwrap();
        assert_ne!(&a[12..16], &b[12..16]);
        assert_ne!(&a[12..16], &other_network[12..16]);
        assert_eq!(nat.return_lease(address(0)).unwrap().peer, first);
        assert_eq!(nat.return_lease(address(1)).unwrap().peer, second);
        let restarted = Nat::default();
        restarted.initialize(path).unwrap();
        assert_eq!(
            restarted
                .outbound(packet(6), first, "example".into())
                .await
                .unwrap(),
            a
        );
        assert_eq!(restarted.return_lease(address(2)).unwrap().network, "other");
        let mut concurrent = Vec::new();
        for _ in 0..8 {
            let nat = restarted.clone();
            concurrent.push(tokio::spawn(async move {
                nat.outbound(packet(6), second, "new".into()).await.unwrap()
            }));
        }
        for packet in concurrent {
            assert_eq!(&packet.await.unwrap()[12..16], &address(3).octets());
        }
    }

    #[test]
    fn lease_failures_do_not_reuse_addresses() {
        let nat = Nat::default();
        let lease = Lease {
            peer: "200::1".parse().unwrap(),
            network: "example".into(),
        };
        assert!(matches!(
            nat.allocate(lease.clone()),
            Err(Error::Uninitialized)
        ));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.json");
        fs::write(&path, b"invalid").unwrap();
        assert!(nat.initialize(path.clone()).is_err());
        fs::write(
            &path,
            serde_json::to_vec(&vec![lease.clone(), lease.clone()]).unwrap(),
        )
        .unwrap();
        assert!(matches!(nat.initialize(path), Err(Error::InvalidLeases)));
        assert!(nat.return_lease(address(0)).is_none());
    }

    #[test]
    fn route_conflicts_leave_other_vpns_alone() {
        for prefix in [
            "198.19.0.0/16",
            "198.18.0.0/15",
            "198.19.2.3",
            "192.0.0.0/24",
            "192.0.0.2",
        ] {
            assert!(
                conflicts_with_route(prefix, AddressSpace::Client)
                    || conflicts_with_route(prefix, AddressSpace::Gateway),
                "{prefix}"
            );
        }
        for prefix in [
            "default",
            "0.0.0.0/0",
            "0.0.0.0/1",
            "128.0.0.0/1",
            "100.64.0.0/10",
            "192.168.0.0/16",
            "198.18.0.0/16",
        ] {
            assert!(
                !conflicts_with_route(prefix, AddressSpace::Client)
                    && !conflicts_with_route(prefix, AddressSpace::Gateway),
                "{prefix}"
            );
        }
    }
}
