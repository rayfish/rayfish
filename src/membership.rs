//! Network membership management: identity, IP derivation, member/approved lists, and policies.
//!
//! Mesh addresses are deterministically derived from [`EndpointId`] via blake3
//! into `200::/7`, so they are never carried on the wire: every node computes
//! every other node's address itself. See [`derive_ipv6`].

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use iroh::EndpointId;
use ray_proto::SuggestedFirewall;
use serde::{Deserialize, Serialize};

use crate::control::DeviceCert;

/// Current Unix time in whole seconds (0 if the clock predates the epoch).
/// Shared clock source for `Member::last_seen` stamping and the ephemeral pruner.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Which address families a member's exit node can actually egress, as recorded
/// on the signed roster.
///
/// Three-valued because "nobody told us" and "told us it cannot" are different
/// facts with different answers, and only a coordinator running a build that
/// knows this field can ever write it. A coordinator on an older release
/// deserializes `Member` into a struct without the key and republishes without
/// it, so a claim that passed through one arrives back as [`Self::Unknown`]
/// rather than as a denial. Collapsing the two is what made an offer that could
/// never converge look like a gateway with no IPv6: see
/// `NetworkRegistry::exit_offer_out_of_sync`.
///
/// [`Self::Unknown`] is the serde default, and it is written like any other
/// value: the roster is array-encoded, where a skipped field is not an absent key
/// but a missing slot that shifts everything after it. Absent means only "the
/// array ended before this field", which is what an older, shorter roster looks
/// like.
///
/// The variants are renamed to one character each because msgpack writes a unit
/// variant as its *name*, and this field sits on every roster entry whether or
/// not that member is a gateway: `Unknown` spelt out costs 8 bytes per member,
/// which on the largest thing we put on the wire is most of what array-encoding
/// the blob went and saved. The names never reach a user (this type is wire-only:
/// `ray exit-node status` carries display strings), so the tag is free to be
/// short.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ExitFamilies {
    /// No claim on the roster. Either the member never made one, or a
    /// coordinator that does not know this field republished over it.
    #[default]
    #[serde(rename = "?")]
    Unknown,
    /// The gateway can egress IPv4 only.
    #[serde(rename = "4")]
    V4,
    /// The gateway has an IPv6 uplink to masquerade onto. The only claim a
    /// gateway makes about itself now that the overlay carries no IPv4: there is
    /// no second family for it to offer, so "IPv6 only" is the whole of a working
    /// gateway rather than half of one.
    #[serde(rename = "6")]
    V6,
    /// The gateway can egress both families.
    #[serde(rename = "d")]
    Dual,
    /// The gateway can egress neither: it has no IPv6 uplink, and the overlay
    /// carries no IPv4 for it to offer instead.
    ///
    /// Distinct from [`Self::Unknown`], which is the absence of a claim. This is
    /// a claim, and the claim is "nothing". Every client refuses it.
    #[serde(rename = "n")]
    Neither,
}

impl ExitFamilies {
    /// Whether this claim says IPv6 egress works. False for [`Self::Unknown`]:
    /// callers that need to distinguish "no" from "nobody said" must ask
    /// [`Self::is_unknown`] first.
    pub fn carries_v6(self) -> bool {
        matches!(self, Self::Dual | Self::V6)
    }

    /// Whether this claim says IPv4 egress works, on the same terms as
    /// [`Self::carries_v6`].
    pub fn carries_v4(self) -> bool {
        matches!(self, Self::Dual | Self::V4)
    }

    /// Whether the roster carries no claim, as distinct from a claim of "no".
    /// Not a `skip_serializing_if`, and must not become one: see the type docs.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// What a client tunnel through this gateway actually carries.
    ///
    /// Only ever [`Self::V6`] or [`Self::Neither`]: the overlay carries no IPv4,
    /// so a client cannot source transit from a mesh IPv4 whatever the gateway
    /// claims, and a claim of [`Self::V4`] or [`Self::Dual`] narrows to its IPv6
    /// half. A tunnel that carries nothing is not a tunnel, so `Neither` is what
    /// the caller refuses on.
    ///
    /// [`Self::Unknown`] counts as "can carry": the claim is absent on every
    /// network whose coordinator predates the field, and narrowing a tunnel on
    /// the strength of nothing would quietly stop tunnelling a family that works.
    pub fn tunnelled(self) -> Self {
        if self.is_unknown() || self.carries_v6() {
            Self::V6
        } else {
            Self::Neither
        }
    }

    /// The claim a gateway makes about itself: whether it found an IPv6 default
    /// route to masquerade onto.
    ///
    /// Only [`Self::V6`] or [`Self::Neither`] is produced. The IPv4 half of the
    /// old claim is gone with the overlay's IPv4: a gateway assigns no mesh IPv4
    /// and installs no `100.64.0.0/10` route, so an un-NATted IPv4 reply has no
    /// way back into its TUN and it could never honestly claim to carry that
    /// family. `Neither` is not a theoretical corner: it is what a host with no
    /// IPv6 uplink is, and refusing it is the whole point of the type.
    ///
    /// [`Self::V4`] and [`Self::Dual`] survive as *decodable* variants because
    /// this rides the signed roster and a claim is read as well as written;
    /// [`Self::tunnelled`] narrows either to IPv6.
    pub fn from_uplink(has_v6: bool) -> Self {
        if has_v6 { Self::V6 } else { Self::Neither }
    }
}

/// A peer that has been admitted to the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub identity: EndpointId,
    pub is_coordinator: bool,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub user_identity: Option<EndpointId>,
    #[serde(default)]
    pub device_cert: Option<DeviceCert>,
    /// Unix seconds this peer was last observed going offline. `None` = never
    /// observed offline, so the ephemeral pruner never evicts it. Stamped on
    /// disconnect and seeded at admit; part of the hashed blob so it replicates
    /// to co-coordinators and survives a coordinator restart.
    #[serde(default)]
    pub last_seen: Option<u64>,
    /// This member offers itself as an exit node on the network (advertised so
    /// peers can discover it via `ray status` and `ray exit-node use`). Set by a
    /// coordinator when the node signals intent (`ControlMsg::ExitNodeOffer`); a
    /// self-claim that only advertises availability. The exit node still gates
    /// actual forwarding with its local `exit_allow` list, so a false claim just
    /// makes clients dial a node that drops them.
    #[serde(default)]
    pub exit_node: bool,
    /// Which families the exit node this member offers can egress, i.e. whether
    /// that host has an IPv6 default route to masquerade onto. Meaningless unless
    /// `exit_node`.
    ///
    /// Separate from `exit_node` because a client can only use a gateway that
    /// carries a family the client itself routes: the tunnel takes the
    /// intersection, and a gateway that cannot return one would take that
    /// family's traffic and have nowhere to send it. Without this that failure is
    /// a silent black hole, since nothing else on the roster says which families a
    /// gateway can egress. See [`ExitFamilies`] for why it is three-valued.
    ///
    /// **Last on purpose.** The wire is positional, so a field's declaration order
    /// *is* the wire format: appending is what makes an older build's shorter array
    /// fail on its length rather than mis-slot a value into the wrong field. Adding
    /// one mid-struct would shift every field after it one place left, which errors
    /// only when the two happen to differ in type and decodes clean and wrong when
    /// they do not.
    #[serde(default)]
    pub exit_families: ExitFamilies,
}

impl Member {
    /// Whether `id` names this member, matched the way the roster keys members:
    /// by device identity, or by the user identity a paired multi-device peer is
    /// stored under. The one matching rule for every "which member is this id"
    /// lookup, so a change to how paired devices fold stays in one place.
    pub fn matches_identity(&self, id: EndpointId) -> bool {
        self.identity == id || self.user_identity == Some(id)
    }
}

/// Controls who can approve new members joining the network.
///
/// Defined in `ray-proto` (shared with GUI frontends); re-exported here so
/// existing `crate::membership::GroupMode` paths keep working.
pub use ray_proto::GroupMode;

/// Active members of a network, keyed by [`EndpointId`].
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

    pub fn add(&mut self, member: Member) {
        self.members.insert(member.identity, member);
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

    pub fn is_member(&self, identity: &EndpointId) -> bool {
        self.members.contains_key(identity)
    }

    pub fn all(&self) -> Vec<&Member> {
        self.members.values().collect()
    }

    /// Resolve a firewall `--peer` **literal** against this roster: a mesh IPv6
    /// to the member holding that address, or a full identity string to a member
    /// by its device id or its paired `user_identity`. Returns the member's
    /// **device** endpoint id (the caller normalizes to the user identity for
    /// inbound rules). Hostname and short-id-prefix forms are resolved upstream
    /// (Magic DNS / `resolve_short_id_any_network`); this is the literal-IP and
    /// full-identity fallback used by `DaemonState::resolve_peer_flexible`.
    ///
    /// The address is not stored, so the match derives it per member. That is the
    /// same linear scan the old `get_by_ip` was, with one hash added per member.
    pub fn resolve_peer_literal(&self, name: &str) -> Option<EndpointId> {
        if let Ok(v6) = name.parse::<Ipv6Addr>()
            && let Some(m) = self
                .members
                .values()
                .find(|m| derive_ipv6(&m.identity) == v6)
        {
            return Some(m.identity);
        }
        if let Ok(id) = name.parse::<EndpointId>()
            && let Some(m) = self.members.values().find(|m| m.matches_identity(id))
        {
            return Some(m.identity);
        }
        None
    }

    pub fn from_members(members: Vec<Member>) -> Self {
        let mut list = Self::new();
        for m in members {
            list.add(m);
        }
        list
    }
}

/// A peer that has been approved by the coordinator but hasn't connected yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedEntry {
    pub identity: EndpointId,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub user_identity: Option<EndpointId>,
    #[serde(default)]
    pub device_cert: Option<DeviceCert>,
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

    pub fn approve(&mut self, entry: ApprovedEntry) {
        self.entries.insert(entry.identity, entry);
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

    pub fn from_entries(entries: Vec<ApprovedEntry>) -> Self {
        let mut list = Self::new();
        for e in entries {
            list.entries.insert(e.identity, e);
        }
        list
    }
}

/// Flag an existing member as a coordinator (idempotent; no-op if absent).
pub fn mark_coordinator(members: &mut MemberList, identity: &EndpointId) {
    if let Some(m) = members.get_mut(identity) {
        m.is_coordinator = true;
    }
}

/// Abstracts identity and address derivation so the membership system doesn't
/// depend directly on iroh types.
pub trait IdentityProvider: Send + Sync {
    fn local_ipv6(&self) -> Ipv6Addr;
    fn local_identity(&self) -> EndpointId;
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
    ipv6: Ipv6Addr,
}

impl IrohIdentityProvider {
    pub fn new(endpoint_id: EndpointId) -> Self {
        Self {
            endpoint_id,
            ipv6: derive_ipv6(&endpoint_id),
        }
    }
}

impl IdentityProvider for IrohIdentityProvider {
    fn local_ipv6(&self) -> Ipv6Addr {
        self.ipv6
    }

    fn local_identity(&self) -> EndpointId {
        self.endpoint_id
    }
}

// ---------------------------------------------------------------------------
// Canonical membership serialization + hashing
// ---------------------------------------------------------------------------

/// A reusable, expiring join key (Tailscale auth-key analog). Only the
/// `blake3(secret)` hash is published: the raw secret lives solely in the code
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
    #[serde(default)]
    pub suggested_firewall: SuggestedFirewall,
    #[serde(default)]
    pub name: Option<String>,
    /// Reusable join keys, keyed by hex `blake3(secret)`. `BTreeMap` keeps the
    /// encoding canonical; the secret hash commits to the signed hash, so adding
    /// or revoking a key changes the blob hash and triggers reconvergence.
    #[serde(default)]
    pub reusable_keys: BTreeMap<String, ReusableKey>,
    /// Device keys nullified on this network (`ray unpair`). A cert whose
    /// `device_key` is listed is no longer honored: admission rejects it, the
    /// coordinator drops it from `members`, and every node severs a live link to
    /// it on reconverge. `BTreeSet` keeps the encoding canonical, so adding or
    /// clearing a nullifier changes the blob hash and triggers reconvergence.
    /// Serde-default empty for back-compat with pre-nullifier blobs.
    #[serde(default)]
    pub nullifiers: BTreeSet<EndpointId>,
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
/// the (pure) admission decision for a reusable join, usable by any network-key
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
    nullifiers: &BTreeSet<EndpointId>,
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
        nullifiers: nullifiers.clone(),
    };
    rmp_serde::to_vec(&data).expect("msgpack serialize")
}

pub fn group_blob_hash(
    members: &MemberList,
    approved: &ApprovedList,
    suggested_firewall: &SuggestedFirewall,
    name: Option<&str>,
    reusable_keys: &BTreeMap<String, ReusableKey>,
    nullifiers: &BTreeSet<EndpointId>,
) -> blake3::Hash {
    let bytes = canonical_group_bytes(
        members,
        approved,
        suggested_firewall,
        name,
        reusable_keys,
        nullifiers,
    );
    blake3::hash(&bytes)
}

/// Whether `ip` is a rayfish overlay address: the IPv6 `200::/7` range mesh
/// addresses are derived into (see [`derive_ipv6`]). Used to keep the overlay's
/// own addresses out of iroh's advertised transport candidates, so the tunnel is
/// never asked to route over itself (a self-looping path that flaps open/closed
/// and can cascade into spurious roster evictions).
pub fn is_overlay_ip(ip: IpAddr) -> bool {
    // 200::/7: the top 7 bits of the first hextet are `0000001`.
    matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0x0200)
}

/// Whether `ip` is in the `100.64.0.0/10` CGNAT range.
///
/// **Not ours.** The overlay is IPv6-only, so this range belongs to whatever
/// other VPN shares the host, and the callers that ask are keeping *its*
/// addresses out of places they would do damage: iroh's advertised transport
/// candidates ([`crate::transport::OverlayAddrFilter`]) and the daemon's own
/// control-plane nameservers. Kept apart from [`is_overlay_ip`] because one
/// predicate answering both questions is what made this easy to get wrong.
pub fn is_cgnat_range(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

pub fn decode_group_blob(bytes: &[u8]) -> Result<GroupBlob> {
    let blob: GroupBlob =
        rmp_serde::from_slice(bytes).map_err(|e| anyhow::anyhow!("invalid group blob: {e}"))?;
    // Nothing to validate at this boundary any more: a member's mesh address is
    // derived from its identity rather than carried, so there is no field a
    // malicious publisher could set inconsistently.
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
/// payload-free triggers (they carry no hash) so there is never any
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
    use std::collections::{BTreeMap, BTreeSet};

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        let key = iroh::SecretKey::from(key_bytes);
        key.public()
    }

    #[test]
    fn overlay_ip_covers_mesh_ranges_only() {
        // The CGNAT range is not ours any more: it belongs to whatever other
        // VPN shares the host, and `is_cgnat_range` is what asks about it.
        assert!(!is_overlay_ip("100.64.0.1".parse().unwrap()));
        assert!(is_cgnat_range("100.64.0.1".parse().unwrap()));
        assert!(is_cgnat_range("100.127.255.255".parse().unwrap()));
        assert!(!is_cgnat_range("100.63.255.255".parse().unwrap()));
        assert!(!is_cgnat_range("100.128.0.0".parse().unwrap()));
        // Ordinary underlay addresses pass through.
        assert!(!is_overlay_ip("192.168.1.104".parse().unwrap()));
        assert!(!is_overlay_ip("51.15.139.151".parse().unwrap()));
        // IPv6 200::/7 (mesh range) vs a normal global v6.
        assert!(is_overlay_ip(IpAddr::V6(derive_ipv6(&test_id(9)))));
        assert!(is_overlay_ip("200::1".parse().unwrap()));
        assert!(is_overlay_ip("03ff::1".parse().unwrap()));
        assert!(!is_overlay_ip("2001:db8::1".parse().unwrap()));
        assert!(!is_overlay_ip("fe80::1".parse().unwrap()));
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
        let provider = IrohIdentityProvider::new(endpoint_id);

        let ip = provider.local_ipv6();
        // The provider hands back the identity's derived `200::/7` address,
        // and hands back the same one every time it is asked.
        assert_eq!(ip, derive_ipv6(&endpoint_id));
        assert!(is_overlay_ip(IpAddr::V6(ip)));
        assert_eq!(provider.local_ipv6(), ip);
    }

    #[test]
    fn test_member_list_add_and_lookup() {
        let id = test_id(1);
        let mut list = MemberList::new();
        let member = Member {
            identity: id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        };
        list.add(member.clone());
        assert!(list.is_member(&id));
        assert!(!list.is_member(&test_id(2)));
    }

    #[test]
    fn test_member_list_same_identity_updates() {
        let id = test_id(1);
        let mut list = MemberList::new();
        list.add(Member {
            identity: id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
        list.add(Member {
            identity: id,
            is_coordinator: true,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
        assert!(list.get(&id).unwrap().is_coordinator);
    }

    #[test]
    fn test_member_list_remove() {
        let id = test_id(1);
        let mut list = MemberList::new();
        list.add(Member {
            identity: id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
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
            is_coordinator: true,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
        list.add(Member {
            identity: test_id(2),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
        assert_eq!(list.all().len(), 2);
    }

    #[test]
    fn test_approved_list_add_and_check() {
        let id = test_id(1);
        let mut list = ApprovedList::new();
        let entry = ApprovedEntry {
            identity: id,
            hostname: None,
            user_identity: None,
            device_cert: None,
        };
        list.approve(entry);
        assert!(list.is_approved(&id));
        assert!(!list.is_approved(&test_id(2)));
    }

    #[test]
    fn test_approved_list_same_identity_is_idempotent() {
        let id = test_id(1);
        let mut approved = ApprovedList::new();
        approved.approve(ApprovedEntry {
            identity: id,
            hostname: None,
            user_identity: None,
            device_cert: None,
        });
        approved.approve(ApprovedEntry {
            identity: id,
            hostname: None,
            user_identity: None,
            device_cert: None,
        });
        assert_eq!(approved.all().len(), 1);
    }

    #[test]
    fn test_approved_list_remove() {
        let id = test_id(1);
        let mut approved = ApprovedList::new();
        approved.approve(ApprovedEntry {
            identity: id,
            hostname: None,
            user_identity: None,
            device_cert: None,
        });
        let removed = approved.remove(&id);
        assert!(removed.is_some());
        assert!(!approved.is_approved(&id));
    }

    #[test]
    fn test_approved_list_from_entries() {
        let entries = vec![
            ApprovedEntry {
                identity: test_id(1),
                hostname: None,
                user_identity: None,
                device_cert: None,
            },
            ApprovedEntry {
                identity: test_id(2),
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
            list.add(Member {
                identity: id,
                is_coordinator: false,
                hostname: None,
                user_identity: None,
                device_cert: None,
                last_seen: None,
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
            });
        }
        list
    }

    #[test]
    fn resolve_peer_literal_by_ip_and_identity() {
        let device = test_id(11);
        let user = test_id(22);
        let ip = derive_ipv6(&device);
        let mut list = MemberList::new();
        list.add(Member {
            identity: device,
            is_coordinator: false,
            hostname: Some("alice-laptop".to_string()),
            user_identity: Some(user),
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });

        // Mesh IPv6 literal -> the member's device id.
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
            &BTreeSet::new(),
        );
        let b = canonical_group_bytes(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
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
                &BTreeMap::new(),
                &BTreeSet::new(),
            ),
            canonical_group_bytes(
                &m2,
                &approved,
                &ray_proto::SuggestedFirewall::default(),
                None,
                &BTreeMap::new(),
                &BTreeSet::new(),
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
            &BTreeSet::new(),
        );
        let members2 = make_member_list(&[1, 2, 3]);
        let h2 = group_blob_hash(
            &members2,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_group_blob_roundtrip() {
        let members = make_member_list(&[1, 2]);
        let mut approved = ApprovedList::new();
        let id3 = test_id(3);
        approved.approve(ApprovedEntry {
            identity: id3,
            hostname: None,
            user_identity: None,
            device_cert: None,
        });

        let bytes = canonical_group_bytes(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
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
            &BTreeSet::new(),
        );
        let hash = group_blob_hash(
            &members,
            &approved,
            &ray_proto::SuggestedFirewall::default(),
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let data = verify_group_blob(&bytes, &hash).unwrap();
        assert_eq!(data.members.len(), 2);
    }

    #[test]
    fn no_reconverge_when_already_on_signed_hash() {
        // We already hold the authoritative (signed) blob, no work to do.
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
            &BTreeSet::new(),
        );
        let bad_hash = blake3::hash(b"wrong data");
        let result = verify_group_blob(&bytes, &bad_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }

    #[test]
    fn last_seen_survives_blob_roundtrip() {
        let id = test_id(7);
        let mut members = MemberList::new();
        members.add(Member {
            identity: id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: Some(12345),
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
        let approved = ApprovedList::new();
        let sf = ray_proto::SuggestedFirewall::default();
        let bytes = canonical_group_bytes(
            &members,
            &approved,
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let hash = group_blob_hash(
            &members,
            &approved,
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let data = verify_group_blob(&bytes, &hash).unwrap();
        assert_eq!(data.members[0].last_seen, Some(12345));
    }

    #[test]
    fn last_seen_absent_decodes_to_none() {
        // A member with no last_seen serializes it as nil, and a blob from a
        // build that predates the field is simply shorter; either way it must
        // decode to None with no mass eviction on upgrade.
        let id = test_id(8);
        let mut members = MemberList::new();
        members.add(Member {
            identity: id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
        let approved = ApprovedList::new();
        let sf = ray_proto::SuggestedFirewall::default();
        let bytes = canonical_group_bytes(
            &members,
            &approved,
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(!String::from_utf8_lossy(&bytes).contains("last_seen"));
        let hash = group_blob_hash(
            &members,
            &approved,
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let data = verify_group_blob(&bytes, &hash).unwrap();
        assert_eq!(data.members[0].last_seen, None);
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
        let a = canonical_group_bytes(
            &members,
            &approved,
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let b = canonical_group_bytes(
            &members,
            &approved,
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_eq!(a, b);

        // Suggestions are part of the signed content, so they change the hash.
        let h_empty = group_blob_hash(
            &members,
            &approved,
            &SuggestedFirewall::new(),
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let h_sf = group_blob_hash(
            &members,
            &approved,
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_ne!(h_empty, h_sf);
    }

    /// A deny-only suggestion must survive the blob round trip as a *deny*.
    ///
    /// The blob is array-encoded, so a `skip_serializing_if` on
    /// `HostSuggestions::allows` would drop slot 0 and slide `denies` into it.
    /// Both fields are `BTreeMap<String, String>`, so that decodes clean and
    /// silently inverted, and every member then materializes the blacklist as an
    /// allow rule. This is the one place the inversion is reachable from a
    /// signed, network-distributed value, so it is pinned here rather than left
    /// to the encoding convention.
    #[test]
    fn a_deny_only_suggestion_does_not_decode_as_an_allow() {
        use ray_proto::{HostSuggestions, SuggestedFirewall};
        let members = make_member_list(&[1, 2]);
        let mut hs = HostSuggestions::default();
        hs.denies.insert("eve".to_string(), "tcp:22".to_string());
        assert!(
            hs.allows.is_empty(),
            "the empty side is the one that is cut"
        );
        let mut sf = SuggestedFirewall::new();
        sf.insert("*".to_string(), hs.clone());

        let bytes = canonical_group_bytes(
            &members,
            &ApprovedList::new(),
            &sf,
            None,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let blob = decode_group_blob(&bytes).expect("blob decodes");
        assert_eq!(blob.suggested_firewall.get("*"), Some(&hs));
    }

    #[test]
    fn test_short_blob_defaults_its_trailing_fields() {
        // A blob from a build that stops after `approved`: on the compact wire
        // that is a two-element array, and every field after it takes its
        // default rather than failing the decode.
        #[derive(Serialize)]
        struct ShortBlob {
            members: Vec<Member>,
            approved: Vec<ApprovedEntry>,
        }
        let members = make_member_list(&[1, 2]);
        let old = ShortBlob {
            members: members.all().into_iter().cloned().collect(),
            approved: vec![],
        };
        let bytes = rmp_serde::to_vec(&old).unwrap();
        let blob = decode_group_blob(&bytes).unwrap();
        assert_eq!(blob.members.len(), 2);
        assert!(blob.suggested_firewall.is_empty());
        assert_eq!(blob.name, None);
        assert!(blob.reusable_keys.is_empty());
        assert!(blob.nullifiers.is_empty());
    }

    /// What "additive" means now that the wire is compact (positional arrays):
    /// a field may only ever be **appended**, and a shorter array from an older
    /// build fills the trailing fields with their defaults.
    ///
    /// This is the whole compatibility story for the control wire, and it is
    /// narrower than the map-encoded one it replaced. Under named encoding field
    /// order was irrelevant; here the declaration order *is* the wire format, so
    /// inserting a field anywhere but the end shifts every field after it into
    /// the wrong slot. The bytes below are what a build that predates the last
    /// two fields would send.
    #[test]
    fn member_fields_are_append_only_and_default_when_absent() {
        #[derive(Serialize)]
        struct ShorterMember {
            identity: EndpointId,
            is_coordinator: bool,
            hostname: Option<String>,
            user_identity: Option<EndpointId>,
            device_cert: Option<DeviceCert>,
            last_seen: Option<u64>,
            exit_node: bool,
            // `exit_families` and `ipv6_only` not yet declared.
        }
        let id = test_id(7);
        let bytes = rmp_serde::to_vec(&ShorterMember {
            identity: id,
            is_coordinator: false,
            hostname: Some("box".into()),
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: true,
        })
        .unwrap();

        let decoded: Member = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.identity, id);
        assert_eq!(decoded.hostname.as_deref(), Some("box"));
        assert!(decoded.exit_node);
        // The appended field takes its default rather than failing.
        assert_eq!(decoded.exit_families, ExitFamilies::Unknown);

        // Every field is now written, claimed or not: there is no key to omit.
        // A round-trip is the property that survives, not a byte comparison.
        for families in [ExitFamilies::Unknown, ExitFamilies::V4, ExitFamilies::Dual] {
            let mut m = decoded.clone();
            m.exit_families = families;
            let round: Member = rmp_serde::from_slice(&rmp_serde::to_vec(&m).unwrap()).unwrap();
            assert_eq!(round.exit_families, families);
        }
    }

    /// What array-encoding the blob actually saves, measured rather than claimed.
    ///
    /// The baseline is the *released* named encoding, not `to_vec_named` of the
    /// current struct: the released `Member` carried `skip_serializing_if` on
    /// every optional field, so an absent hostname or `last_seen` cost nothing
    /// there, while compact writes a slot for it either way. Comparing against
    /// today's struct (which cannot carry those attributes any more, see the type
    /// docs) would flatter the result by counting keys the old build never sent.
    ///
    /// A 50-member roster of joined-but-unpaired nodes measures 5194 bytes named
    /// against 3764 compact, about 28%. The heavier shape (every member paired,
    /// so `user_identity` and `last_seen` are set) is 9206 against 6476, about
    /// 30%. The assertion is the floor, not the figure, since any field added
    /// later moves both numbers.
    #[test]
    fn compact_encoding_takes_about_a_quarter_off_a_roster() {
        #[derive(Serialize)]
        struct ReleasedMember {
            identity: EndpointId,
            is_coordinator: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            hostname: Option<String>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            exit_node: bool,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            ipv6_only: bool,
        }
        #[derive(Serialize)]
        struct ReleasedBlob {
            members: Vec<ReleasedMember>,
            approved: Vec<ApprovedEntry>,
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<String>,
        }

        let mut members = Vec::new();
        let mut released = Vec::new();
        for i in 0..50u8 {
            let id = test_id(i);
            let hostname = Some(format!("host-{i}"));
            members.push(Member {
                identity: id,
                is_coordinator: i == 0,
                hostname: hostname.clone(),
                user_identity: None,
                device_cert: None,
                last_seen: None,
                exit_node: i == 1,
                exit_families: match i {
                    1 => ExitFamilies::Dual,
                    _ => ExitFamilies::Unknown,
                },
            });
            released.push(ReleasedMember {
                identity: id,
                is_coordinator: i == 0,
                hostname,
                exit_node: i == 1,
                ipv6_only: false,
            });
        }
        let compact = canonical_group_bytes(
            &MemberList::from_members(members),
            &ApprovedList::new(),
            &SuggestedFirewall::new(),
            Some("net"),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let named = rmp_serde::to_vec_named(&ReleasedBlob {
            members: released,
            approved: vec![],
            name: Some("net".to_string()),
        })
        .unwrap();

        let saved = 1.0 - compact.len() as f64 / named.len() as f64;
        assert!(
            saved > 0.25,
            "compact saved only {:.1}% ({} vs {} bytes)",
            saved * 100.0,
            compact.len(),
            named.len()
        );
    }

    /// An older build's blob is a msgpack *map*, and this build still reads it.
    ///
    /// rmp-serde's struct decoder accepts either shape, which is the only reason
    /// a node that upgrades ahead of its coordinator keeps converging: the blob
    /// rides the shared `iroh_blobs` ALPN, so the mesh version bump that
    /// separates the two builds does not separate them here. The reverse does not
    /// hold (an old build reads our array and rejects the length), so this is a
    /// one-way bridge and not a claim that the two encodings interoperate.
    ///
    /// It also explains a thing that looks like a bug: a member that reads a
    /// named blob re-encodes it compactly in `refresh_snapshot`, so its local
    /// hash never equals the one the record commits to, and the record's
    /// timestamp floor rather than the hash is what stops it re-applying on every
    /// poll.
    #[test]
    fn a_named_encoded_blob_from_an_older_build_still_decodes() {
        #[derive(Serialize)]
        struct OldMember {
            identity: EndpointId,
            is_coordinator: bool,
            hostname: Option<String>,
            exit_node: bool,
            // No `exit_families`: a key this build knows and that one never wrote.
        }
        #[derive(Serialize)]
        struct OldBlob {
            members: Vec<OldMember>,
            approved: Vec<ApprovedEntry>,
        }
        let id = test_id(12);
        let bytes = rmp_serde::to_vec_named(&OldBlob {
            members: vec![OldMember {
                identity: id,
                is_coordinator: true,
                hostname: Some("box".into()),
                exit_node: true,
            }],
            approved: vec![],
        })
        .unwrap();

        let blob = decode_group_blob(&bytes).expect("a named map still decodes");
        assert_eq!(blob.members.len(), 1);
        assert!(blob.members[0].exit_node);
        assert_eq!(blob.members[0].exit_families, ExitFamilies::Unknown);
        // And re-encoding it compactly gives different bytes, which is what makes
        // the local snapshot hash disagree with the signed one.
        assert_ne!(rmp_serde::to_vec(&blob).unwrap(), bytes);
    }

    /// A tunnel carries IPv6 or it carries nothing.
    ///
    /// The overlay routes no IPv4, so a client cannot source transit from a mesh
    /// IPv4 whatever the gateway claims. A claim that includes IPv4 narrows to
    /// its IPv6 half rather than being taken at face value.
    #[test]
    fn a_tunnel_carries_ipv6_or_nothing() {
        use ExitFamilies::{Dual, Neither, Unknown, V4, V6};

        assert_eq!(
            Dual.tunnelled(),
            V6,
            "the IPv4 half has nowhere to come back"
        );
        assert_eq!(V6.tunnelled(), V6);
        assert_eq!(V4.tunnelled(), Neither, "nothing left to install");
        assert_eq!(Neither.tunnelled(), Neither);

        // No claim means no narrowing: every network whose coordinator predates
        // the field would otherwise lose the one family that works.
        assert_eq!(Unknown.tunnelled(), V6);
    }

    /// The default claim rides every roster entry, so its tag is sized for that.
    ///
    /// msgpack writes a unit variant as its name, and `Unknown` is what almost
    /// every member carries: not a gateway, or a gateway whose coordinator
    /// predates the field. Spelt out that is 8 bytes each, which on a large
    /// roster is a good part of what array-encoding the blob saved in the first
    /// place.
    #[test]
    fn the_unknown_claim_costs_two_bytes_on_the_wire() {
        for (v, tag) in [
            (ExitFamilies::Unknown, "?"),
            (ExitFamilies::V4, "4"),
            (ExitFamilies::V6, "6"),
            (ExitFamilies::Dual, "d"),
            (ExitFamilies::Neither, "n"),
        ] {
            let bytes = rmp_serde::to_vec(&v).unwrap();
            assert_eq!(bytes.len(), 2, "{v:?} encodes as more than a one-char tag");
            assert!(bytes.ends_with(tag.as_bytes()), "{v:?} is not tagged {tag}");
            let back: ExitFamilies = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(back, v);
        }
    }

    /// The tolerance runs one way only, and the roster blob is where that bites.
    ///
    /// A build that predates an appended field reads a *longer* array than its
    /// struct has slots, and rmp-serde rejects the whole value rather than
    /// dropping the tail. So appending is what lets a new build read an old
    /// peer; it does nothing for the other direction. Everything else compact
    /// rides an ALPN we bump, which keeps the two builds off the same
    /// connection, but the blob rides the shared `iroh_blobs` ALPN and the group
    /// poll checks no version at all, so an appended `Member` field stops an old
    /// peer converging until it upgrades. That is a reason to bump the mesh
    /// version with the field, not a reason to trust the append.
    #[test]
    fn an_older_build_cannot_read_an_appended_field() {
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct OlderMember {
            identity: EndpointId,
            is_coordinator: bool,
            hostname: Option<String>,
            user_identity: Option<EndpointId>,
            device_cert: Option<DeviceCert>,
            last_seen: Option<u64>,
            // The older shape ends here. `exit_families` is appended after this,
            // so what an older build sees is simply one element too many: every
            // slot it does read still means what it meant. Inserted anywhere
            // above instead, the failure would depend on the types that happened
            // to line up, which is the thing the append rule exists to take off
            // the table.
        }
        let id = test_id(11);
        let bytes = rmp_serde::to_vec(&Member {
            identity: id,
            is_coordinator: false,
            hostname: Some("box".into()),
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: true,
            exit_families: ExitFamilies::Dual,
        })
        .unwrap();

        let err = rmp_serde::from_slice::<OlderMember>(&bytes)
            .expect_err("an 11-element array does not fit a 9-field struct");
        assert!(
            matches!(err, rmp_serde::decode::Error::LengthMismatch(_)),
            "expected a length mismatch, got {err:?}"
        );
    }

    /// Reordering two same-typed fields is the one way the compact wire fails
    /// without saying so.
    ///
    /// A shift between differently-typed fields errors loudly ("invalid type"),
    /// which is survivable. Between two fields of the same type there is nothing
    /// to detect: the bytes are valid, the struct decodes, and each field now
    /// holds what the other meant. Declaration order *is* the wire format here,
    /// and a diff that merely moves a line does not look like a protocol change,
    /// so this is recorded as a test rather than left to review.
    ///
    /// Pinned against a local pair rather than whichever `Member` fields happen
    /// to be adjacent today: the hazard belongs to the codec, and tying the test
    /// to one struct's current layout makes it vanish the moment that layout
    /// changes, which is exactly when it is needed.
    #[test]
    fn reordering_same_typed_fields_silently_swaps_them() {
        #[derive(Serialize)]
        struct Written {
            first: bool,
            second: bool,
        }
        #[derive(Deserialize, Debug, PartialEq)]
        struct Read {
            // The same two fields, declared the other way round.
            second: bool,
            first: bool,
        }
        let bytes = rmp_serde::to_vec(&Written {
            first: true,
            second: false,
        })
        .unwrap();

        let decoded: Read = rmp_serde::from_slice(&bytes).expect("decodes without complaint");
        // No error, and both booleans now say the opposite of what was sent.
        assert!(decoded.second, "`first` was read as `second`");
        assert!(!decoded.first, "`second` was read as `first`");
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
            &BTreeSet::new(),
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
            &BTreeSet::new(),
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
            &BTreeSet::new(),
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
            &BTreeSet::new(),
        );
        assert_ne!(
            h1, h2,
            "revoking a reusable key must change the signed hash"
        );
    }

    #[test]
    fn nullifier_changes_hash_and_is_backcompat() {
        let members = make_member_list(&[1]);
        let approved = ApprovedList::new();
        let sf = SuggestedFirewall::default();
        let keys = BTreeMap::new();

        let h0 = group_blob_hash(&members, &approved, &sf, None, &keys, &BTreeSet::new());
        let mut nullifiers = BTreeSet::new();
        nullifiers.insert(test_id(7));
        let h1 = group_blob_hash(&members, &approved, &sf, None, &keys, &nullifiers);
        assert_ne!(h0, h1, "adding a nullifier must change the signed hash");

        // A blob encoded without the field decodes with an empty nullifier set
        // (serde default), so pre-nullifier blobs stay valid.
        let bytes = canonical_group_bytes(&members, &approved, &sf, None, &keys, &BTreeSet::new());
        let blob = decode_group_blob(&bytes).unwrap();
        assert!(blob.nullifiers.is_empty());
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
                nullifiers: BTreeSet::new(),
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
    fn mark_coordinator_sets_flag_for_target() {
        let id = test_id(7);
        let mut list = MemberList::new();
        list.add(Member {
            identity: id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
        mark_coordinator(&mut list, &id);
        assert!(list.get(&id).unwrap().is_coordinator);
    }
}
