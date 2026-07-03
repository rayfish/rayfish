//! Network membership management: identity, IP derivation, member/approved lists, and policies.
//!
//! Virtual IPs are deterministically derived from [`EndpointId`] via FNV-1a hashing
//! into the 100.64.0.0/10 CGNAT range (22-bit host space, ~4M addresses).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use iroh::EndpointId;
use ray_proto::SuggestedFirewall;
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
    /// Index used to resolve IPv4 collisions in the 22-bit CGNAT space.
    /// 0 for most peers; incremented only when `derive_ip_with_index(identity, 0)`
    /// collides with an already-assigned address.
    #[serde(default)]
    pub collision_index: u32,
}

/// Controls who can approve new members joining the network.
///
/// Defined in `ray-proto` (shared with GUI frontends); re-exported here so
/// existing `crate::membership::GroupMode` paths keep working.
pub use ray_proto::GroupMode;

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

impl Default for MemberList {
    fn default() -> Self {
        Self::new()
    }
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

    /// Resolve a firewall `--peer` **literal** against this roster: a mesh IPv4
    /// to the member holding that address, or a full identity string to a member
    /// by its device id or its paired `user_identity`. Returns the member's
    /// **device** endpoint id (the caller normalizes to the user identity for
    /// inbound rules). Hostname and short-id-prefix forms are resolved upstream
    /// (Magic DNS / `resolve_short_id_any_network`); this is the literal-IP and
    /// full-identity fallback used by `DaemonState::resolve_peer_flexible`.
    pub fn resolve_peer_literal(&self, name: &str) -> Option<EndpointId> {
        if let Ok(v4) = name.parse::<Ipv4Addr>()
            && let Some(m) = self.get_by_ip(v4)
        {
            return Some(m.identity);
        }
        if let Ok(id) = name.parse::<EndpointId>()
            && let Some(m) = self
                .members
                .values()
                .find(|m| m.identity == id || m.user_identity == Some(id))
        {
            return Some(m.identity);
        }
        None
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
    /// Index used to resolve IPv4 collisions. Mirrors `Member.collision_index`
    /// for the same identity; defaults to 0 for backward-compatible decoding.
    #[serde(default)]
    pub collision_index: u32,
}

/// Pre-approved peers that the coordinator has broadcast but that haven't
/// connected yet. Any peer holding this list can welcome them.
#[derive(Debug, Clone)]
pub struct ApprovedList {
    entries: HashMap<EndpointId, ApprovedEntry>,
}

impl Default for ApprovedList {
    fn default() -> Self {
        Self::new()
    }
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
///
/// Superseded at runtime by the per-network access mode gate in the daemon
/// (open auto-admits; closed routes through the invite/approval flow); retained
/// for reference and unit coverage.
#[allow(dead_code)]
pub trait MembershipPolicy: Send + Sync {
    fn can_authorize(&self, acceptor: &Member) -> bool;
}

/// Any member can approve new peers.
#[allow(dead_code)]
pub struct OpenPolicy;

impl MembershipPolicy for OpenPolicy {
    fn can_authorize(&self, _acceptor: &Member) -> bool {
        true
    }
}

/// Only the coordinator can approve new peers.
#[allow(dead_code)]
pub struct RestrictedPolicy;

impl MembershipPolicy for RestrictedPolicy {
    fn can_authorize(&self, acceptor: &Member) -> bool {
        acceptor.is_coordinator
    }
}

#[allow(dead_code)]
pub fn policy_for_mode(mode: GroupMode) -> Box<dyn MembershipPolicy> {
    match mode {
        GroupMode::Open => Box::new(OpenPolicy),
        GroupMode::Restricted => Box::new(RestrictedPolicy),
    }
}

/// Flag an existing member as a coordinator (idempotent; no-op if absent).
pub fn mark_coordinator(members: &mut MemberList, identity: &EndpointId) {
    if let Some(m) = members.get_mut(identity) {
        m.is_coordinator = true;
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

/// True if `ip` is reserved and must never be assigned to a member
/// (currently the Magic DNS resolver address).
fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    ip == crate::dns::MAGIC_DNS_V4
}

/// Finds the lowest collision index whose derived IPv4 is free in `members`.
///
/// An IP is considered free if no *different* identity holds it — a re-add of
/// the same identity at its existing index is always accepted. Returns the
/// `(ip, index)` pair that should be stored in `Member.ip` / `Member.collision_index`.
pub fn assign_ip(members: &MemberList, identity: &EndpointId) -> (Ipv4Addr, u32) {
    let mut index = 0u32;
    loop {
        let ip = derive_ip_with_index(identity, index);
        if is_reserved_ipv4(ip) {
            index += 1;
            continue;
        }
        match members.get_by_ip(ip) {
            Some(existing) if existing.identity != *identity => index += 1,
            _ => return (ip, index),
        }
    }
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

/// A reusable, expiring join key (Tailscale auth-key analog). Only the
/// `blake3(secret)` hash is published — the raw secret lives solely in the code
/// handed to a joiner. Because it rides the signed `GroupBlob`, *any* network-key
/// holder can verify-and-admit and revocation propagates to every admin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReusableKey {
    /// Short human id: the first 8 hex chars of the secret hash.
    pub id: String,
    /// Unix seconds when minted.
    pub created: u64,
    /// Unix seconds after which the key is no longer redeemable.
    pub expires: u64,
    /// Set by `ray invite revoke`; a revoked key admits no one.
    pub revoked: bool,
}

/// The single authoritative blob for a network, published by the coordinator.
/// Contains all state a joiner needs: members, the approved list, the
/// coordinator-suggested firewall rules, and any reusable join keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupBlob {
    pub members: Vec<Member>,
    pub approved: Vec<ApprovedEntry>,
    /// Coordinator-suggested firewall rules, keyed by subject hostname (the `*`
    /// subject targets every node). Advisory: each node queues them for
    /// `ray firewall accept`, or auto-installs them if it opted into
    /// `--auto-accept-firewall`. `BTreeMap` keys keep the encoding canonical.
    #[serde(default, skip_serializing_if = "SuggestedFirewall::is_empty")]
    pub suggested_firewall: SuggestedFirewall,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Reusable join keys, keyed by hex `blake3(secret)`. `BTreeMap` keeps the
    /// encoding canonical; the secret hash commits to the signed hash, so adding
    /// or revoking a key changes the blob hash and triggers reconvergence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reusable_keys: BTreeMap<String, ReusableKey>,
}

impl ReusableKey {
    /// Build a reusable key from a freshly generated secret. Returns the map key
    /// (hex `blake3(secret)`) and the entry. `created`/`ttl_secs` are Unix seconds;
    /// the raw secret is the caller's to encode into the join code and discard.
    pub fn from_secret(secret: &[u8], created: u64, ttl_secs: u64) -> (String, ReusableKey) {
        let hash = blake3::hash(secret).to_hex().to_string();
        let id = hash[..8].to_string();
        (
            hash,
            ReusableKey {
                id,
                created,
                expires: created.saturating_add(ttl_secs),
                revoked: false,
            },
        )
    }
}

/// Revoke a reusable key by id (exact match, or unambiguous prefix), setting its
/// `revoked` flag. A revoked key stays in the blob (so the revocation is part of
/// the signed content and propagates) but admits no one.
pub fn revoke_reusable(keys: &mut BTreeMap<String, ReusableKey>, id: &str) -> Result<()> {
    let matches: Vec<String> = keys
        .iter()
        .filter(|(_, k)| k.id == id || k.id.starts_with(id))
        .map(|(hash, _)| hash.clone())
        .collect();
    let hash = match matches.as_slice() {
        [] => bail!("no reusable key matching '{id}'"),
        [h] => h.clone(),
        _ => bail!("ambiguous reusable key id '{id}'"),
    };
    keys.get_mut(&hash)
        .expect("hash came from this map")
        .revoked = true;
    Ok(())
}

/// Verify a presented reusable-key secret against a key set. Returns the key iff
/// it is present, not revoked, and not expired (`now` is Unix seconds). This is
/// the (pure) admission decision for a reusable join — usable by any network-key
/// holder, since the key set comes from the network-key-signed blob.
pub fn validate_reusable_key<'a>(
    keys: &'a BTreeMap<String, ReusableKey>,
    secret: &[u8],
    now: u64,
) -> Option<&'a ReusableKey> {
    let hash = blake3::hash(secret).to_hex().to_string();
    let key = keys.get(&hash)?;
    if key.revoked || now >= key.expires {
        return None;
    }
    Some(key)
}

impl GroupBlob {
    /// Convenience wrapper over [`validate_reusable_key`] for a decoded blob.
    #[allow(dead_code)] // used in tests; the daemon calls the free function on NetworkState
    pub fn validate_reusable(&self, secret: &[u8], now: u64) -> Option<&ReusableKey> {
        validate_reusable_key(&self.reusable_keys, secret, now)
    }
}

/// Produces a deterministic msgpack encoding of a group blob.
/// Members and approved entries are sorted by identity string to ensure
/// identical output regardless of HashMap iteration order; the suggested
/// firewall is a `BTreeMap`, so it is already canonically ordered.
pub fn canonical_group_bytes(
    members: &MemberList,
    approved: &ApprovedList,
    suggested_firewall: &SuggestedFirewall,
    name: Option<&str>,
    reusable_keys: &BTreeMap<String, ReusableKey>,
) -> Vec<u8> {
    let mut sorted_members: Vec<Member> = members.all().into_iter().cloned().collect();
    sorted_members.sort_by_key(|m| m.identity.to_string());

    let mut sorted_approved: Vec<ApprovedEntry> = approved.all().into_iter().cloned().collect();
    sorted_approved.sort_by_key(|a| a.identity.to_string());

    let data = GroupBlob {
        members: sorted_members,
        approved: sorted_approved,
        suggested_firewall: suggested_firewall.clone(),
        name: name.map(|s| s.to_string()),
        reusable_keys: reusable_keys.clone(),
    };
    rmp_serde::to_vec_named(&data).expect("msgpack serialize")
}

pub fn group_blob_hash(
    members: &MemberList,
    approved: &ApprovedList,
    suggested_firewall: &SuggestedFirewall,
    name: Option<&str>,
    reusable_keys: &BTreeMap<String, ReusableKey>,
) -> blake3::Hash {
    let bytes = canonical_group_bytes(members, approved, suggested_firewall, name, reusable_keys);
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
    let expected = derive_ip_with_index(&member.identity, member.collision_index);
    anyhow::ensure!(
        member.ip == expected,
        "member ip {} does not match identity-derived ip {}",
        member.ip,
        expected,
    );
    anyhow::ensure!(
        !is_reserved_ipv4(member.ip),
        "member IP {} is the reserved Magic DNS address",
        member.ip
    );
    ensure_in_cgnat_range(member.ip)
}

/// Like [`validate_member`] but for [`ApprovedEntry`].
pub fn validate_approved(entry: &ApprovedEntry) -> Result<()> {
    let expected = derive_ip_with_index(&entry.identity, entry.collision_index);
    anyhow::ensure!(
        entry.ip == expected,
        "approved entry ip {} does not match identity-derived ip {}",
        entry.ip,
        expected,
    );
    ensure_in_cgnat_range(entry.ip)
}

/// Returns `Err` if any two members share the same IPv4 address.
///
/// This enforces the roster invariant that every member has a unique IP.
/// Call this at any trust boundary where a freshly-decoded roster is applied.
pub fn validate_no_duplicate_ips(members: &[Member]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for m in members {
        anyhow::ensure!(seen.insert(m.ip), "duplicate IP {} in roster", m.ip);
    }
    Ok(())
}

/// Resolve duplicate-IP rosters deterministically: for each clashing IP the
/// lowest identity keeps it; others re-roll to their next free index.
///
/// Two coordinators can independently admit a fresh joiner at the same collision
/// index, so a reconverged roster may carry duplicate IPs. Sorting by identity
/// bytes and re-seating every member through [`assign_ip`] makes the resolution
/// order independent of where the roster was assembled, so every node converges
/// on the same address map.
pub fn resolve_ip_tiebreak(mut members: Vec<Member>) -> Vec<Member> {
    members.sort_by_key(|m| m.identity.as_bytes().to_owned());
    let mut list = MemberList::new();
    for mut m in members {
        let (ip, idx) = assign_ip(&list, &m.identity);
        m.ip = ip;
        m.collision_index = idx;
        let _ = list.add(m);
    }
    list.all().into_iter().cloned().collect()
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

/// Decides whether to reconverge the local group state, and to which hash.
///
/// The network-key-signed pkarr record is the *sole* authority: `signed` is the
/// hash it commits to. Peer control messages (`MemberSync`, `BlobUpdated`) are
/// payload-free triggers — they carry no hash — so there is never any
/// peer-supplied value that could be fetched or applied. Returns `Some(signed)`
/// when it differs from what we already hold (`current`), else `None`.
pub fn trusted_reconverge_hash(
    current: Option<blake3::Hash>,
    signed: blake3::Hash,
) -> Option<blake3::Hash> {
    if current == Some(signed) {
        None
    } else {
        Some(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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
            collision_index: 0,
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
            collision_index: 0,
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
            collision_index: 0,
        })
        .unwrap();
        let result = list.add(Member {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
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
            collision_index: 0,
        })
        .unwrap();
        list.add(Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: true,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
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
            collision_index: 0,
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
            collision_index: 0,
        })
        .unwrap();
        list.add(Member {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 0, 3),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
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
            collision_index: 0,
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
            collision_index: 0,
        };
        let regular = Member {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 0, 3),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
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
            collision_index: 0,
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
                collision_index: 0,
            })
            .unwrap();
        let entry = ApprovedEntry {
            identity: test_id(2),
            ip: Ipv4Addr::new(100, 64, 5, 10),
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
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
                    collision_index: 0,
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
                collision_index: 0,
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
                    collision_index: 0,
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
                    collision_index: 0,
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
                    collision_index: 0,
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
                collision_index: 0,
            },
            ApprovedEntry {
                identity: test_id(2),
                ip: Ipv4Addr::new(100, 64, 0, 3),
                hostname: None,
                user_identity: None,
                device_cert: None,
                collision_index: 0,
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
                collision_index: 0,
            });
        }
        list
    }

    #[test]
    fn resolve_peer_literal_by_ip_and_identity() {
        let device = test_id(11);
        let user = test_id(22);
        let ip = derive_ip(&device);
        let mut list = MemberList::new();
        list.add(Member {
            identity: device,
            ip,
            is_coordinator: false,
            hostname: Some("alice-laptop".to_string()),
            user_identity: Some(user),
            device_cert: None,
            collision_index: 0,
        })
        .unwrap();

        // Mesh IPv4 literal -> the member's device id.
        assert_eq!(list.resolve_peer_literal(&ip.to_string()), Some(device));
        // Full device identity -> itself.
        assert_eq!(list.resolve_peer_literal(&device.to_string()), Some(device));
        // Paired user identity -> the user's joined device id (not the user id).
        assert_eq!(list.resolve_peer_literal(&user.to_string()), Some(device));

        // Non-member IP, an unrelated identity, and junk all miss.
        assert_eq!(list.resolve_peer_literal("100.64.0.1"), None);
        assert_eq!(list.resolve_peer_literal(&test_id(99).to_string()), None);
        assert_eq!(list.resolve_peer_literal("not-a-peer"), None);
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let members = make_member_list(&[1, 2, 3]);
        let approved = ApprovedList::new();
        let a = canonical_group_bytes(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
        let b = canonical_group_bytes(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_canonical_bytes_order_independent() {
        let m1 = make_member_list(&[1, 2, 3]);
        let m2 = make_member_list(&[3, 1, 2]);
        let approved = ApprovedList::new();
        assert_eq!(
            canonical_group_bytes(
                &m1,
                &approved,
                &ray_proto::SuggestedFirewall::default(),
                None,
                &BTreeMap::new()
            ),
            canonical_group_bytes(
                &m2,
                &approved,
                &ray_proto::SuggestedFirewall::default(),
                None,
                &BTreeMap::new()
            ),
        );
    }

    #[test]
    fn test_group_blob_hash_changes_on_mutation() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let h1 = group_blob_hash(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
        let members2 = make_member_list(&[1, 2, 3]);
        let h2 = group_blob_hash(
            &members2,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
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
                    collision_index: 0,
                },
                &members,
            )
            .unwrap();

        let bytes = canonical_group_bytes(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
        let data = decode_group_blob(&bytes).unwrap();
        assert_eq!(data.members.len(), 2);
        assert_eq!(data.approved.len(), 1);
    }

    #[test]
    fn test_verify_group_blob_ok() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let bytes = canonical_group_bytes(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
        let hash = group_blob_hash(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
        let data = verify_group_blob(&bytes, &hash).unwrap();
        assert_eq!(data.members.len(), 2);
    }

    #[test]
    fn no_reconverge_when_already_on_signed_hash() {
        // We already hold the authoritative (signed) blob — no work to do.
        let signed = blake3::hash(b"authoritative blob");
        assert_eq!(trusted_reconverge_hash(Some(signed), signed), None);
    }

    #[test]
    fn reconverge_targets_signed_hash_on_change() {
        // The signed record changed. We reconverge to the SIGNED hash.
        let current = blake3::hash(b"old blob");
        let signed = blake3::hash(b"new authoritative blob");
        assert_eq!(trusted_reconverge_hash(Some(current), signed), Some(signed));
    }

    #[test]
    fn reconverge_applies_signed_hash_when_no_current() {
        let signed = blake3::hash(b"authoritative blob");
        assert_eq!(trusted_reconverge_hash(None, signed), Some(signed));
    }

    #[test]
    fn test_verify_group_blob_bad_hash() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let bytes = canonical_group_bytes(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
        );
        let bad_hash = blake3::hash(b"wrong data");
        let result = verify_group_blob(&bytes, &bad_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }

    #[test]
    fn test_suggested_firewall_canonical_and_hashed() {
        use ray_proto::{HostSuggestions, SuggestedFirewall};
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let mut sf = SuggestedFirewall::new();
        let mut hs = HostSuggestions::default();
        hs.allows
            .insert("peer-a".to_string(), "9000,8123".to_string());
        sf.insert("subject".to_string(), hs);

        // Deterministic: BTreeMap keys canonicalize regardless of insert order.
        let a = canonical_group_bytes(&members, &approved, &sf, None, &BTreeMap::new());
        let b = canonical_group_bytes(&members, &approved, &sf, None, &BTreeMap::new());
        assert_eq!(a, b);

        // Suggestions are part of the signed content, so they change the hash.
        let h_empty = group_blob_hash(
            &members,
            &approved,
            &SuggestedFirewall::new(),
            None,
            &BTreeMap::new(),
        );
        let h_sf = group_blob_hash(&members, &approved, &sf, None, &BTreeMap::new());
        assert_ne!(h_empty, h_sf);
    }

    #[test]
    fn test_old_blob_without_suggested_firewall_decodes() {
        // A blob serialized before suggested firewall existed (no
        // `suggested_firewall` key) must still decode, defaulting it empty.
        #[derive(Serialize)]
        struct OldBlob {
            members: Vec<Member>,
            approved: Vec<ApprovedEntry>,
            name: Option<String>,
        }
        let members = make_member_list(&[1, 2]);
        let old = OldBlob {
            members: members.all().into_iter().cloned().collect(),
            approved: vec![],
            name: Some("net".to_string()),
        };
        let bytes = rmp_serde::to_vec_named(&old).unwrap();
        let blob = decode_group_blob(&bytes).unwrap();
        assert_eq!(blob.members.len(), 2);
        assert!(blob.suggested_firewall.is_empty());
        // A pre-reusable-keys blob decodes with an empty reusable_keys map.
        assert!(blob.reusable_keys.is_empty());
    }

    // -- reusable keys --------------------------------------------------------

    fn reusable_key_for(secret: &[u8], expires: u64, revoked: bool) -> (String, ReusableKey) {
        let hash = blake3::hash(secret).to_hex().to_string();
        let id = hash[..8].to_string();
        (
            hash,
            ReusableKey {
                id,
                created: 0,
                expires,
                revoked,
            },
        )
    }

    #[test]
    fn reusable_key_blob_roundtrips() {
        let members = make_member_list(&[1, 2]);
        let approved = ApprovedList::new();
        let secret = [7u8; 16];
        let (hash, key) = reusable_key_for(&secret, 9_999_999_999, false);
        let mut keys = BTreeMap::new();
        keys.insert(hash, key);

        let bytes = canonical_group_bytes(
            &members,
            &approved,
            &SuggestedFirewall::default(),
            None,
            &keys,
        );
        let blob = decode_group_blob(&bytes).unwrap();
        assert_eq!(blob.reusable_keys.len(), 1);
        // The decoded blob validates the secret it was built with.
        assert!(blob.validate_reusable(&secret, 1000).is_some());
    }

    #[test]
    fn reusable_key_changes_hash_when_added_or_revoked() {
        let members = make_member_list(&[1]);
        let approved = ApprovedList::new();
        let empty = BTreeMap::new();
        let h0 = group_blob_hash(
            &members,
            &approved,
            &SuggestedFirewall::default(),
            None,
            &empty,
        );

        let secret = [3u8; 16];
        let (hash, key) = reusable_key_for(&secret, 9_999_999_999, false);
        let mut keys = BTreeMap::new();
        keys.insert(hash.clone(), key);
        let h1 = group_blob_hash(
            &members,
            &approved,
            &SuggestedFirewall::default(),
            None,
            &keys,
        );
        assert_ne!(h0, h1, "adding a reusable key must change the signed hash");

        // Revoking is a content change → the hash must change again so peers reconverge.
        keys.get_mut(&hash).unwrap().revoked = true;
        let h2 = group_blob_hash(
            &members,
            &approved,
            &SuggestedFirewall::default(),
            None,
            &keys,
        );
        assert_ne!(
            h1, h2,
            "revoking a reusable key must change the signed hash"
        );
    }

    #[test]
    fn reusable_key_from_secret_sets_id_and_expiry() {
        let secret = [5u8; 16];
        let (hash, key) = ReusableKey::from_secret(&secret, 100, 50);
        assert_eq!(hash, blake3::hash(&secret).to_hex().to_string());
        assert_eq!(key.id, hash[..8]);
        assert_eq!(key.created, 100);
        assert_eq!(key.expires, 150);
        assert!(!key.revoked);
    }

    #[test]
    fn revoke_reusable_by_full_id_and_prefix() {
        let secret = [6u8; 16];
        let (hash, key) = ReusableKey::from_secret(&secret, 0, 100);
        let mut keys = BTreeMap::new();
        keys.insert(hash.clone(), key.clone());
        // Full id.
        revoke_reusable(&mut keys, &key.id).unwrap();
        assert!(keys[&hash].revoked);
        // Unambiguous prefix.
        keys.get_mut(&hash).unwrap().revoked = false;
        revoke_reusable(&mut keys, &key.id[..4]).unwrap();
        assert!(keys[&hash].revoked);
    }

    #[test]
    fn revoke_reusable_unknown_and_ambiguous_error() {
        let mut empty: BTreeMap<String, ReusableKey> = BTreeMap::new();
        assert!(revoke_reusable(&mut empty, "deadbeef").is_err());

        let mut keys = BTreeMap::new();
        keys.insert(
            "h1".to_string(),
            ReusableKey {
                id: "abcd0000".to_string(),
                created: 0,
                expires: 100,
                revoked: false,
            },
        );
        keys.insert(
            "h2".to_string(),
            ReusableKey {
                id: "abcd1111".to_string(),
                created: 0,
                expires: 100,
                revoked: false,
            },
        );
        assert!(
            revoke_reusable(&mut keys, "abcd").is_err(),
            "prefix matching two ids is ambiguous"
        );
    }

    #[test]
    fn validate_reusable_accepts_live_rejects_expired_revoked_unknown() {
        let secret = [9u8; 16];
        let mk = |expires, revoked| {
            let (hash, key) = reusable_key_for(&secret, expires, revoked);
            let mut keys = BTreeMap::new();
            keys.insert(hash, key);
            GroupBlob {
                members: vec![],
                approved: vec![],
                suggested_firewall: SuggestedFirewall::default(),
                name: None,
                reusable_keys: keys,
            }
        };
        // Live key: present, not revoked, now < expires.
        assert!(mk(100, false).validate_reusable(&secret, 50).is_some());
        // Expired: now >= expires.
        assert!(mk(100, false).validate_reusable(&secret, 100).is_none());
        // Revoked.
        assert!(mk(100, true).validate_reusable(&secret, 50).is_none());
        // Unknown secret.
        assert!(mk(100, false).validate_reusable(&[0u8; 16], 50).is_none());
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
            collision_index: 0,
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
            collision_index: 0,
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
            collision_index: 0,
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
            collision_index: 0,
        };
        let gw = Member {
            identity: id,
            ip: Ipv4Addr::new(100, 64, 0, 1),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
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
            collision_index: 0,
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
                collision_index: 0,
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
            collision_index: 0,
        };
        let blob = GroupBlob {
            members: vec![bad_member],
            approved: vec![],
            suggested_firewall: Default::default(),
            name: None,
            reusable_keys: BTreeMap::new(),
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
            collision_index: 0,
        };
        let blob = GroupBlob {
            members: vec![bad_member],
            approved: vec![],
            suggested_firewall: Default::default(),
            name: None,
            reusable_keys: BTreeMap::new(),
        };
        let bytes = rmp_serde::to_vec_named(&blob).unwrap();
        assert!(decode_group_blob(&bytes).is_err());
    }

    #[test]
    fn mark_coordinator_sets_flag_for_target() {
        let id = test_id(7);
        let mut list = MemberList::new();
        list.add(Member {
            identity: id,
            ip: derive_ip(&id),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
        })
        .unwrap();
        mark_coordinator(&mut list, &id);
        assert!(list.get(&id).unwrap().is_coordinator);
    }

    /// Brute-force (birthday approach) to find two distinct identities whose
    /// index-0 IPv4 collides. The 22-bit space makes this likely within ~a few
    /// thousand iterations. Bounded at 200_000 to avoid a runaway test.
    fn find_colliding_pair() -> Option<(EndpointId, EndpointId)> {
        let mut seen: HashMap<Ipv4Addr, EndpointId> = HashMap::new();
        for i in 0u32..200_000 {
            // Vary bytes across the whole 32-byte key to get good hash dispersion.
            let mut key_bytes = [0u8; 32];
            let b = i.to_le_bytes();
            key_bytes[0] = b[0];
            key_bytes[1] = b[1];
            key_bytes[2] = b[2];
            key_bytes[3] = b[3];
            let id = iroh::SecretKey::from(key_bytes).public();
            let ip = derive_ip(&id);
            if let Some(existing) = seen.get(&ip) {
                if *existing != id {
                    return Some((*existing, id));
                }
            } else {
                seen.insert(ip, id);
            }
        }
        None
    }

    #[test]
    fn validate_member_accepts_declared_index_rejects_mismatch() {
        let id = test_id(5);
        let good = Member {
            identity: id,
            ip: derive_ip_with_index(&id, 2),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 2,
        };
        assert!(validate_member(&good).is_ok());
        let bad = Member {
            collision_index: 1,
            ..good.clone()
        }; // ip is for index 2, claims 1
        assert!(validate_member(&bad).is_err());
    }

    #[test]
    fn validate_no_duplicate_ips_rejects_clash() {
        let a = test_id(1);
        let m = |id, ip| Member {
            identity: id,
            ip,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
        };
        let dup = derive_ip(&a);
        assert!(validate_no_duplicate_ips(&[m(a, dup), m(test_id(2), dup)]).is_err());
    }

    #[test]
    fn assign_ip_rotates_on_collision() {
        let (a, b) = find_colliding_pair()
            .expect("birthday bound: should find a collision within 200k identities");
        // Sanity: a and b both map to the same index-0 IP.
        assert_eq!(derive_ip(&a), derive_ip(&b));
        let ip0 = derive_ip(&a);

        // Add `a` to the list at its index-0 IP.
        let mut list = MemberList::new();
        let (assigned_a, idx_a) = assign_ip(&list, &a);
        assert_eq!(idx_a, 0, "first peer always gets index 0");
        assert_eq!(assigned_a, ip0);
        list.add(Member {
            identity: a,
            ip: assigned_a,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: idx_a,
        })
        .unwrap();

        // Now assign_ip for `b` must rotate to index >= 1.
        let (ip_b, idx_b) = assign_ip(&list, &b);
        assert!(idx_b >= 1, "colliding identity must rotate to index >= 1");
        assert_ne!(ip_b, ip0, "rotated IP must differ from the occupied slot");
        assert_eq!(
            ip_b,
            derive_ip_with_index(&b, idx_b),
            "assigned IP must equal derive_ip_with_index at that index"
        );
    }

    #[test]
    fn tiebreak_keeps_lower_identity_rerolls_other() {
        // Order two distinct identities by their canonical byte order so the
        // assertion ("lower identity keeps the shared ip") is deterministic
        // regardless of how the seeds map onto public keys.
        let (lo, hi) = {
            let (a, b) = (test_id(1), test_id(9));
            if a.as_bytes() <= b.as_bytes() {
                (a, b)
            } else {
                (b, a)
            }
        };
        let ip = derive_ip(&lo); // both initially claim this ip at index 0
        let mk = |id| Member {
            identity: id,
            ip,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
        };
        let resolved = resolve_ip_tiebreak(vec![mk(hi), mk(lo)]);
        // lower identity keeps `ip`; higher re-rolls to a free index.
        let lo_m = resolved.iter().find(|m| m.identity == lo).unwrap();
        let hi_m = resolved.iter().find(|m| m.identity == hi).unwrap();
        assert_eq!(lo_m.ip, ip);
        assert_ne!(hi_m.ip, ip);
        assert!(validate_no_duplicate_ips(&resolved).is_ok());
    }

    #[test]
    fn is_reserved_ipv4_covers_magic_dns() {
        // The predicate test isolates the guard: it fails if anyone removes the
        // magic DNS IP from the reserved set, independent of IP-derivation.
        assert!(is_reserved_ipv4(crate::dns::MAGIC_DNS_V4));
        assert!(!is_reserved_ipv4(Ipv4Addr::new(100, 64, 0, 7)));
    }

    #[test]
    fn validate_member_rejects_magic_dns_ip() {
        // Behavioral guard; the predicate test above is the one that isolates it.
        let mut kb = [0u8; 32];
        kb[0] = 9;
        let id = iroh::SecretKey::from(kb).public();
        let m = Member {
            identity: id,
            ip: crate::dns::MAGIC_DNS_V4,
            collision_index: 0,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        assert!(validate_member(&m).is_err());
    }
}
