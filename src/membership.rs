//! Network membership management: identity, IP derivation, member/approved lists, and policies.
//!
//! Virtual IPs are deterministically derived from [`EndpointId`] via FNV-1a hashing
//! into the 100.64.0.0/10 CGNAT range (22-bit host space, ~4M addresses).

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::control::DeviceCert;

/// A peer that has been admitted to the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub identity: EndpointId,
    pub ip: Ipv4Addr,
    pub is_coordinator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_identity: Option<EndpointId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_cert: Option<DeviceCert>,
}

impl Member {
    /// Returns the user identity this device belongs to.
    /// For device 0 / legacy nodes, this equals the transport identity.
    pub fn effective_user_identity(&self) -> EndpointId {
        self.user_identity.unwrap_or(self.identity)
    }
}

/// Controls who can approve new members joining the network.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupMode {
    Open,
    #[default]
    Restricted,
}

impl fmt::Display for GroupMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupMode::Open => write!(f, "open"),
            GroupMode::Restricted => write!(f, "restricted"),
        }
    }
}

impl std::str::FromStr for GroupMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(GroupMode::Open),
            "restricted" => Ok(GroupMode::Restricted),
            other => Err(format!("unknown group mode: {other}")),
        }
    }
}

/// Two different identities hashed to the same virtual IP (extremely rare with 22-bit space).
#[derive(Debug)]
pub struct IpCollision {
    pub ip: Ipv4Addr,
    pub existing_identity: EndpointId,
    pub new_identity: EndpointId,
}

impl fmt::Display for IpCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IP collision: {} already assigned to {}, cannot assign to {}",
            self.ip,
            self.existing_identity.fmt_short(),
            self.new_identity.fmt_short()
        )
    }
}

impl std::error::Error for IpCollision {}

/// Active members of a network, keyed by [`EndpointId`]. Rejects additions
/// that would create an IP collision with an existing member.
#[derive(Debug, Clone)]
pub struct MemberList {
    members: HashMap<EndpointId, Member>,
}

impl MemberList {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    pub fn add(&mut self, member: Member) -> Result<(), IpCollision> {
        if let Some(existing) = self.get_by_ip(member.ip)
            && existing.identity != member.identity
        {
            return Err(IpCollision {
                ip: member.ip,
                existing_identity: existing.identity,
                new_identity: member.identity,
            });
        }
        self.members.insert(member.identity, member);
        Ok(())
    }

    #[cfg(test)]
    pub fn remove(&mut self, identity: &EndpointId) -> Option<Member> {
        self.members.remove(identity)
    }

    pub fn get(&self, identity: &EndpointId) -> Option<&Member> {
        self.members.get(identity)
    }

    pub fn get_mut(&mut self, identity: &EndpointId) -> Option<&mut Member> {
        self.members.get_mut(identity)
    }

    pub fn get_by_ip(&self, ip: Ipv4Addr) -> Option<&Member> {
        self.members.values().find(|m| m.ip == ip)
    }

    pub fn is_member(&self, identity: &EndpointId) -> bool {
        self.members.contains_key(identity)
    }

    pub fn all(&self) -> Vec<&Member> {
        self.members.values().collect()
    }

    pub fn from_members(members: Vec<Member>) -> Self {
        let mut list = Self::new();
        for m in members {
            let _ = list.add(m);
        }
        list
    }
}

/// A peer that has been approved by the coordinator but hasn't connected yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedEntry {
    pub identity: EndpointId,
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_identity: Option<EndpointId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_cert: Option<DeviceCert>,
}

/// Pre-approved peers that the coordinator has broadcast but that haven't
/// connected yet. Any peer holding this list can welcome them.
#[derive(Debug, Clone)]
pub struct ApprovedList {
    entries: HashMap<EndpointId, ApprovedEntry>,
}

impl ApprovedList {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn approve(
        &mut self,
        entry: ApprovedEntry,
        members: &MemberList,
    ) -> Result<(), IpCollision> {
        if let Some(existing) = members.get_by_ip(entry.ip)
            && existing.identity != entry.identity
        {
            return Err(IpCollision {
                ip: entry.ip,
                existing_identity: existing.identity,
                new_identity: entry.identity,
            });
        }
        if let Some(existing) = self.get_by_ip(entry.ip)
            && existing.identity != entry.identity
        {
            return Err(IpCollision {
                ip: entry.ip,
                existing_identity: existing.identity,
                new_identity: entry.identity,
            });
        }
        self.entries.insert(entry.identity, entry);
        Ok(())
    }

    pub fn is_approved(&self, identity: &EndpointId) -> bool {
        self.entries.contains_key(identity)
    }

    pub fn remove(&mut self, identity: &EndpointId) -> Option<ApprovedEntry> {
        self.entries.remove(identity)
    }

    pub fn all(&self) -> Vec<&ApprovedEntry> {
        self.entries.values().collect()
    }

    pub fn get_by_ip(&self, ip: Ipv4Addr) -> Option<&ApprovedEntry> {
        self.entries.values().find(|e| e.ip == ip)
    }

    pub fn from_entries(entries: Vec<ApprovedEntry>) -> Self {
        let mut list = Self::new();
        for e in entries {
            list.entries.insert(e.identity, e);
        }
        list
    }
}

/// Determines whether a given member is allowed to approve new peers.
pub trait MembershipPolicy: Send + Sync {
    fn can_authorize(&self, acceptor: &Member) -> bool;
}

/// Any member can approve new peers.
pub struct OpenPolicy;

impl MembershipPolicy for OpenPolicy {
    fn can_authorize(&self, _acceptor: &Member) -> bool {
        true
    }
}

/// Only the coordinator can approve new peers.
pub struct RestrictedPolicy;

impl MembershipPolicy for RestrictedPolicy {
    fn can_authorize(&self, acceptor: &Member) -> bool {
        acceptor.is_coordinator
    }
}

pub fn policy_for_mode(mode: GroupMode) -> Box<dyn MembershipPolicy> {
    match mode {
        GroupMode::Open => Box::new(OpenPolicy),
        GroupMode::Restricted => Box::new(RestrictedPolicy),
    }
}

/// Abstracts identity and IP derivation so the membership system doesn't
/// depend directly on iroh types.
pub trait IdentityProvider: Send + Sync {
    fn local_ip(&self) -> Ipv4Addr;
    fn local_identity(&self) -> EndpointId;
    fn derive_ip(&self, peer_identity: &EndpointId) -> Ipv4Addr;
}

/// Derives a deterministic virtual IP from an [`EndpointId`] using FNV-1a.
/// Always produces an address in the 100.64.0.0/10 range, avoiding .0 and .1
/// (network address and TUN gateway).
pub fn derive_ip(identity: &EndpointId) -> Ipv4Addr {
    derive_ip_with_index(identity, 0)
}

/// Derives a virtual IPv4 with a collision index. Index 0 produces the same
/// result as [`derive_ip`]. Higher indices rotate the address to resolve
/// collisions in the 22-bit space. The index is local state — each node
/// resolves collisions independently.
pub fn derive_ip_with_index(identity: &EndpointId, index: u32) -> Ipv4Addr {
    let input = if index == 0 {
        identity.to_string()
    } else {
        format!("{identity}{index}")
    };
    let mut hash: u32 = 2_166_136_261; // FNV-1a offset basis
    for &b in input.as_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16_777_619); // FNV-1a prime
    }

    let base: u32 = 0x6440_0000; // 100.64.0.0
    let host_bits = hash & 0x003F_FFFF; // lower 22 bits
    // Reserve 0 (network) and 1 (TUN gateway)
    let host_bits = if host_bits <= 1 {
        host_bits + 2
    } else {
        host_bits
    };
    Ipv4Addr::from(base | host_bits)
}

/// Derives a stable IPv6 address from an [`EndpointId`] in the `200::/7` range.
/// Uses blake3 to hash the identity, takes 15 bytes, and prepends `0x02`.
/// The 120-bit address space makes collisions practically impossible.
pub fn derive_ipv6(identity: &EndpointId) -> Ipv6Addr {
    let hash = blake3::hash(identity.to_string().as_bytes());
    let bytes = hash.as_bytes();
    let octets: [u8; 16] = [
        0x02, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
    ];
    Ipv6Addr::from(octets)
}

/// [`IdentityProvider`] backed by an iroh [`EndpointId`].
#[derive(Clone)]
pub struct IrohIdentityProvider {
    endpoint_id: EndpointId,
    ip: Ipv4Addr,
}

impl IrohIdentityProvider {
    pub fn new(endpoint_id: EndpointId, collision_index: u32) -> Self {
        let ip = derive_ip_with_index(&endpoint_id, collision_index);
        Self { endpoint_id, ip }
    }
}

impl IdentityProvider for IrohIdentityProvider {
    fn local_ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn local_identity(&self) -> EndpointId {
        self.endpoint_id
    }

    fn derive_ip(&self, peer_identity: &EndpointId) -> Ipv4Addr {
        derive_ip(peer_identity)
    }
}

// ---------------------------------------------------------------------------
// Canonical membership serialization + hashing
// ---------------------------------------------------------------------------

use crate::acl::AclData;

/// The single authoritative blob for a network, published by the coordinator.
/// Contains all state a joiner needs: members, approved list, and ACL rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupBlob {
    pub members: Vec<Member>,
    pub approved: Vec<ApprovedEntry>,
    pub acl: AclData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Produces a deterministic msgpack encoding of a group blob.
/// Members and approved entries are sorted by identity string to ensure
/// identical output regardless of HashMap iteration order.
pub fn canonical_group_bytes(
    members: &MemberList,
    approved: &ApprovedList,
    acl: &AclData,
    name: Option<&str>,
) -> Vec<u8> {
    let mut sorted_members: Vec<Member> = members.all().into_iter().cloned().collect();
    sorted_members.sort_by_key(|m| m.identity.to_string());

    let mut sorted_approved: Vec<ApprovedEntry> = approved.all().into_iter().cloned().collect();
    sorted_approved.sort_by_key(|a| a.identity.to_string());

    let data = GroupBlob {
        members: sorted_members,
        approved: sorted_approved,
        acl: acl.clone(),
        name: name.map(|s| s.to_string()),
    };
    rmp_serde::to_vec_named(&data).expect("msgpack serialize")
}

pub fn group_blob_hash(
    members: &MemberList,
    approved: &ApprovedList,
    acl: &AclData,
    name: Option<&str>,
) -> blake3::Hash {
    let bytes = canonical_group_bytes(members, approved, acl, name);
    blake3::hash(&bytes)
}

/// Validates that a [`Member`]'s virtual IP is consistent with its identity and
/// lies in the CGNAT range, excluding the reserved network (`.0`) and gateway
/// (`.1`) addresses.
///
/// This is the invariant the network *should* enforce at every trust boundary
/// (GroupBlob decode, `Welcome`/`MemberSync` application, `MeshHello.ip`). Today
/// the daemon trusts the `ip` field carried in those messages, which permits IP
/// hijacking — see the security audit. This helper exists so enforcement can be
/// added at the data layer without changing the on-wire format.
pub fn validate_member(member: &Member) -> Result<()> {
    let expected = derive_ip(&member.identity);
    anyhow::ensure!(
        member.ip == expected,
        "member ip {} does not match identity-derived ip {}",
        member.ip,
        expected,
    );
    ensure_in_cgnat_range(member.ip)
}

/// Like [`validate_member`] but for [`ApprovedEntry`].
pub fn validate_approved(entry: &ApprovedEntry) -> Result<()> {
    let expected = derive_ip(&entry.identity);
    anyhow::ensure!(
        entry.ip == expected,
        "approved entry ip {} does not match identity-derived ip {}",
        entry.ip,
        expected,
    );
    ensure_in_cgnat_range(entry.ip)
}

fn ensure_in_cgnat_range(ip: Ipv4Addr) -> Result<()> {
    let o = ip.octets();
    anyhow::ensure!(
        o[0] == 100 && (o[1] & 0xC0) == 64,
        "ip {} is outside the 100.64.0.0/10 CGNAT range",
        ip,
    );
    anyhow::ensure!(
        !(o[1] == 64 && o[2] == 0 && o[3] == 0),
        "ip {} is the reserved network address",
        ip,
    );
    anyhow::ensure!(
        !(o[1] == 64 && o[2] == 0 && o[3] == 1),
        "ip {} is the reserved TUN gateway address",
        ip,
    );
    Ok(())
}

pub fn decode_group_blob(bytes: &[u8]) -> Result<GroupBlob> {
    let blob: GroupBlob =
        rmp_serde::from_slice(bytes).map_err(|e| anyhow::anyhow!("invalid group blob: {e}"))?;
    // Enforce the identity<->IP binding at the decode boundary. Any blob that
    // survives this check has self-consistent members/approved entries, so a
    // malicious or buggy publisher cannot inject a spoofed or reserved IP.
    for m in &blob.members {
        validate_member(m)?;
    }
    for a in &blob.approved {
        validate_approved(a)?;
    }
    Ok(blob)
}

pub fn verify_group_blob(bytes: &[u8], expected_hash: &blake3::Hash) -> Result<GroupBlob> {
    let actual = blake3::hash(bytes);
    if actual != *expected_hash {
        bail!("group blob hash mismatch: expected {expected_hash}, got {actual}");
    }
    decode_group_blob(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        let key = iroh::SecretKey::from(key_bytes);
        key.public()
    }

    #[test]
    fn test_derive_ip_deterministic() {
        let id = test_id(1);
        let ip1 = derive_ip(&id);
        let ip2 = derive_ip(&id);
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_derive_ip_in_cgnat_range() {
        let id = test_id(1);
        let ip = derive_ip(&id);
        let octets = ip.octets();
        assert_eq!(octets[0], 100);
        assert!(octets[1] >= 64 && octets[1] <= 127);
    }

    #[test]
    fn test_derive_ip_different_identities_differ() {
        let ip1 = derive_ip(&test_id(1));
        let ip2 = derive_ip(&test_id(2));
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_derive_ip_avoids_reserved() {
        let reserved1 = Ipv4Addr::new(100, 64, 0, 0);
        let reserved2 = Ipv4Addr::new(100, 64, 0, 1);
        for i in 0..=255u8 {
            let ip = derive_ip(&test_id(i));
            assert_ne!(ip, reserved1);
            assert_ne!(ip, reserved2);
        }
    }

    #[test]
    fn test_derive_ip_with_index_zero_matches_derive_ip() {
        for i in 0..=255u8 {
            let id = test_id(i);
            assert_eq!(derive_ip(&id), derive_ip_with_index(&id, 0));
        }
    }

    #[test]
    fn test_derive_ip_with_index_rotates() {
        let id = test_id(1);
        let ip0 = derive_ip_with_index(&id, 0);
        let ip1 = derive_ip_with_index(&id, 1);
        let ip2 = derive_ip_with_index(&id, 2);
        assert_ne!(ip0, ip1);
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_derive_ipv6_deterministic() {
        let id = test_id(1);
        assert_eq!(derive_ipv6(&id), derive_ipv6(&id));
    }

    #[test]
    fn test_derive_ipv6_in_200_range() {
        for i in 0..=255u8 {
            let ipv6 = derive_ipv6(&test_id(i));
            let octets = ipv6.octets();
            assert_eq!(octets[0], 0x02, "first byte must be 0x02 for 200::/7");
        }
    }

    #[test]
    fn test_derive_ipv6_different_identities_differ() {
        let a = derive_ipv6(&test_id(1));
        let b = derive_ipv6(&test_id(2));
        assert_ne!(a, b);
    }

    #[test]
    fn test_iroh_identity_provider() {
        let key = iroh::SecretKey::generate();
        let endpoint_id = key.public();
        let provider = IrohIdentityProvider::new(endpoint_id, 0);

        let ip = provider.local_ip();
        let octets = ip.octets();
        assert_eq!(octets[0], 100);
        assert!(octets[1] >= 64 && octets[1] <= 127);

        let id = provider.local_identity();
        assert_eq!(provider.derive_ip(&id), ip);
    }

    #[test]
    fn test_member_list_add_and_lookup() {
        let id = test_id(1);
        let mut list = MemberList::new();
        let member = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        list.add(member.clone()).unwrap();
        assert!(list.is_member(&id));
        assert!(!list.is_member(&test_id(2)));
        assert_eq!(list.get(&id).unwrap().ip, Ipv4Addr::new(100, 64, 10, 5));
    }

    #[test]
    fn test_member_list_lookup_by_ip() {
        let id = test_id(1);
        let mut list = MemberList::new();
        let member = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        list.add(member).unwrap();
        let found = list.get_by_ip(Ipv4Addr::new(100, 64, 10, 5)).unwrap();
        assert_eq!(found.identity, id);
        assert!(list.get_by_ip(Ipv4Addr::new(100, 64, 10, 6)).is_none());
    }

    #[test]
    fn test_member_list_ip_collision() {
        let mut list = MemberList::new();
        list.add(Member {
            identity: test_id(1),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        })
        .unwrap();
        let result = list.add(Member {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_member_list_same_identity_updates() {
        let id = test_id(1);
        let mut list = MemberList::new();
        list.add(Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        })
        .unwrap();
        list.add(Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: true,
            hostname: None,
            user_identity: None,
            device_cert: None,
        })
        .unwrap();
        assert!(list.get(&id).unwrap().is_coordinator);
    }

    #[test]
    fn test_member_list_remove() {
        let id = test_id(1);
        let mut list = MemberList::new();
        list.add(Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        })
        .unwrap();
        let removed = list.remove(&id);
        assert!(removed.is_some());
        assert!(!list.is_member(&id));
        assert!(list.remove(&id).is_none());
    }

    #[test]
    fn test_member_list_all() {
        let mut list = MemberList::new();
        list.add(Member {
            identity: test_id(1),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            is_coordinator: true,
            hostname: None,
            user_identity: None,
            device_cert: None,
        })
        .unwrap();
        list.add(Member {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 0, 3),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        })
        .unwrap();
        assert_eq!(list.all().len(), 2);
    }

    #[test]
    fn test_open_policy_anyone_can_authorize() {
        let policy = OpenPolicy;
        let member = Member {
            identity: test_id(1),
            ip: Ipv4Addr::new(100, 64, 0, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(policy.can_authorize(&member));
    }

    #[test]
    fn test_restricted_policy_only_coordinators() {
        let policy = RestrictedPolicy;
        let coordinator = Member {
            identity: test_id(1),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            is_coordinator: true,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        let regular = Member {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 0, 3),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(policy.can_authorize(&coordinator));
        assert!(!policy.can_authorize(&regular));
    }

    #[test]
    fn test_approved_list_add_and_check() {
        let id = test_id(1);
        let mut list = ApprovedList::new();
        let entry = ApprovedEntry {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 5, 10),
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        let members = MemberList::new();
        list.approve(entry, &members).unwrap();
        assert!(list.is_approved(&id));
        assert!(!list.is_approved(&test_id(2)));
    }

    #[test]
    fn test_approved_list_collision_with_member() {
        let mut approved = ApprovedList::new();
        let mut members = MemberList::new();
        members
            .add(Member {
                identity: test_id(1),
                ip: Ipv4Addr::new(100, 64, 5, 10),
                is_coordinator: false,
                hostname: None,
                user_identity: None,
                device_cert: None,
            })
            .unwrap();
        let entry = ApprovedEntry {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 5, 10),
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(approved.approve(entry, &members).is_err());
    }

    #[test]
    fn test_approved_list_collision_within_approved() {
        let mut approved = ApprovedList::new();
        let members = MemberList::new();
        approved
            .approve(
                ApprovedEntry {
                    identity: test_id(1),
                    ip: Ipv4Addr::new(100, 64, 5, 10),
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                },
                &members,
            )
            .unwrap();
        let result = approved.approve(
            ApprovedEntry {
                identity: test_id(2),
                ip: Ipv4Addr::new(100, 64, 5, 10),
                hostname: None,
                user_identity: None,
                device_cert: None,
            },
            &members,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_approved_list_same_identity_is_idempotent() {
        let id = test_id(1);
        let mut approved = ApprovedList::new();
        let members = MemberList::new();
        approved
            .approve(
                ApprovedEntry {
                    identity: id,
                    ip: Ipv4Addr::new(100, 64, 5, 10),
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                },
                &members,
            )
            .unwrap();
        approved
            .approve(
                ApprovedEntry {
                    identity: id,
                    ip: Ipv4Addr::new(100, 64, 5, 10),
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                },
                &members,
            )
            .unwrap();
        assert_eq!(approved.all().len(), 1);
    }

    #[test]
    fn test_approved_list_remove() {
        let id = test_id(1);
        let mut approved = ApprovedList::new();
        let members = MemberList::new();
        approved
            .approve(
                ApprovedEntry {
                    identity: id,
                    ip: Ipv4Addr::new(100, 64, 5, 10),
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                },
                &members,
            )
            .unwrap();
        let removed = approved.remove(&id);
        assert!(removed.is_some());
        assert!(!approved.is_approved(&id));
    }

    #[test]
    fn test_approved_list_from_entries() {
        let entries = vec![
            ApprovedEntry {
                identity: test_id(1),
                ip: Ipv4Addr::new(100, 64, 0, 2),
                hostname: None,
                user_identity: None,
                device_cert: None,
            },
            ApprovedEntry {
                identity: test_id(2),
                ip: Ipv4Addr::new(100, 64, 0, 3),
                hostname: None,
                user_identity: None,
                device_cert: None,
            },
        ];
        let list = ApprovedList::from_entries(entries);
        assert!(list.is_approved(&test_id(1)));
        assert!(list.is_approved(&test_id(2)));
        assert_eq!(list.all().len(), 2);
    }

    // -- Canonical serialization + hashing ------------------------------------

    fn make_member_list(seeds: &[u8]) -> MemberList {
        let mut list = MemberList::new();
        for &seed in seeds {
            let id = test_id(seed);
            let _ = list.add(Member {
                identity: id,
                ip: derive_ip(&id),
                is_coordinator: false,
                hostname: None,
                user_identity: None,
                device_cert: None,
            });
        }
        list
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let members = make_member_list(&[1, 2, 3]);
        let approved = ApprovedList::new();
        let acl = crate::acl::AclData::empty();
        let a = canonical_group_bytes(&members, &approved, &acl, None);
        let b = canonical_group_bytes(&members, &approved, &acl, None);
        assert_eq!(a, b);
    }

    #[test]
    fn test_canonical_bytes_order_independent() {
        let m1 = make_member_list(&[1, 2, 3]);
        let m2 = make_member_list(&[3, 1, 2]);
        let approved = ApprovedList::new();
        let acl = crate::acl::AclData::empty();
        assert_eq!(
            canonical_group_bytes(&m1, &approved, &acl, None),
            canonical_group_bytes(&m2, &approved, &acl, None),
        );
    }

    #[test]
    fn test_group_blob_hash_changes_on_mutation() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let acl = crate::acl::AclData::empty();
        let h1 = group_blob_hash(&members, &approved, &acl, None);
        let members2 = make_member_list(&[1, 2, 3]);
        let h2 = group_blob_hash(&members2, &approved, &acl, None);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_group_blob_roundtrip() {
        let members = make_member_list(&[1, 2]);
        let mut approved = ApprovedList::new();
        let id3 = test_id(3);
        approved
            .approve(
                ApprovedEntry {
                    identity: id3,
                    ip: derive_ip(&id3),
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                },
                &members,
            )
            .unwrap();
        let acl = crate::acl::AclData::empty();

        let bytes = canonical_group_bytes(&members, &approved, &acl, None);
        let data = decode_group_blob(&bytes).unwrap();
        assert_eq!(data.members.len(), 2);
        assert_eq!(data.approved.len(), 1);
    }

    #[test]
    fn test_verify_group_blob_ok() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let acl = crate::acl::AclData::empty();
        let bytes = canonical_group_bytes(&members, &approved, &acl, None);
        let hash = group_blob_hash(&members, &approved, &acl, None);
        let data = verify_group_blob(&bytes, &hash).unwrap();
        assert_eq!(data.members.len(), 2);
    }

    #[test]
    fn test_verify_group_blob_bad_hash() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let acl = crate::acl::AclData::empty();
        let bytes = canonical_group_bytes(&members, &approved, &acl, None);
        let bad_hash = blake3::hash(b"wrong data");
        let result = verify_group_blob(&bytes, &bad_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }

    #[test]
    fn test_group_blob_acl_changes_hash() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let acl_empty = crate::acl::AclData::empty();
        let acl_with_rule = crate::acl::AclData {
            tags: vec![],
            rules: vec![crate::acl::AclRule {
                src: crate::acl::Target::All,
                dst: crate::acl::Target::All,
            }],
        };
        let h1 = group_blob_hash(&members, &approved, &acl_empty, None);
        let h2 = group_blob_hash(&members, &approved, &acl_with_rule, None);
        assert_ne!(h1, h2);
    }

    // -- validate_member / validate_approved ---------------------------------

    #[test]
    fn validate_member_accepts_consistent_ip() {
        let id = test_id(7);
        let member = Member {
            identity: id,
            ip: derive_ip(&id),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(validate_member(&member).is_ok());
    }

    #[test]
    fn validate_member_rejects_mismatched_ip() {
        // A peer/ coordinator must not be able to assign an arbitrary IP to an
        // identity. This is the invariant that prevents IP hijacking.
        let id = test_id(7);
        let member = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5), // does NOT equal derive_ip(test_id(7))
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        let err = validate_member(&member).unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn validate_member_rejects_out_of_range_ip() {
        let id = test_id(7);
        let member = Member {
            identity: id,
            ip: Ipv4Addr::new(10, 0, 0, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(validate_member(&member).is_err());
    }

    #[test]
    fn validate_member_rejects_reserved_addresses() {
        // .0 (network) and .1 (gateway) are reserved even if derive_ip avoids them.
        let id = test_id(7);
        let net = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 0, 0),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        let gw = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 0, 1),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(validate_member(&net).is_err());
        assert!(validate_member(&gw).is_err());
    }

    #[test]
    fn validate_approved_rejects_mismatched_ip() {
        let id = test_id(9);
        let entry = ApprovedEntry {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 99, 99),
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(validate_approved(&entry).is_err());
    }

    #[test]
    fn validate_member_accepts_all_derived_ips_in_range() {
        // Every derive_ip() output for a spread of identities must pass validation.
        for seed in 0u8..=255 {
            let id = test_id(seed);
            let member = Member {
                identity: id,
                ip: derive_ip(&id),
                is_coordinator: false,
                hostname: None,
                user_identity: None,
                device_cert: None,
            };
            assert!(
                validate_member(&member).is_ok(),
                "seed {seed} -> {}",
                member.ip
            );
        }
    }

    #[test]
    fn decode_group_blob_rejects_mismatched_member_ip() {
        // A tampered blob carrying a member whose IP doesn't match its identity
        // must be rejected at the decode boundary, even if the bytes are
        // otherwise valid msgpack.
        let id = test_id(1);
        let bad_member = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5), // not derive_ip(test_id(1))
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        let blob = GroupBlob {
            members: vec![bad_member],
            approved: vec![],
            acl: crate::acl::AclData::empty(),
            name: None,
        };
        let bytes = rmp_serde::to_vec_named(&blob).unwrap();
        let err = decode_group_blob(&bytes).unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn decode_group_blob_rejects_reserved_gateway_ip() {
        let id = test_id(2);
        let bad_member = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 0, 1), // TUN gateway
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        let blob = GroupBlob {
            members: vec![bad_member],
            approved: vec![],
            acl: crate::acl::AclData::empty(),
            name: None,
        };
        let bytes = rmp_serde::to_vec_named(&blob).unwrap();
        assert!(decode_group_blob(&bytes).is_err());
    }
}
