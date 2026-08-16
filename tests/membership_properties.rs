//! Property tests for address derivation, roster convergence, and hostname
//! assignment.
//!
//! These functions decide what address a peer holds and what name resolves to
//! it. Their correctness is only partly about any single result: what matters
//! is that every node computes the *same* result from the same roster, however
//! that roster happened to be assembled. Those are properties over whole input
//! spaces, not over examples, which is what this file covers.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;
use rayfish::hostname::{admission_hostname, is_valid_hostname, resolve_collision};
use rayfish::membership::{
    ApprovedList, ExitFamilies, Member, MemberList, assign_ip, canonical_group_bytes, derive_ip,
    derive_ip_with_index, derive_ipv6, group_blob_hash, is_overlay_ip, resolve_ip_tiebreak,
};

use iroh::EndpointId;

/// Distinct identities from a seed. Derived from a secret key so they are real
/// curve points, which `EndpointId` requires.
fn id_from_seed(seed: u32) -> EndpointId {
    let mut key_bytes = [0u8; 32];
    key_bytes[..4].copy_from_slice(&seed.to_le_bytes());
    iroh::SecretKey::from(key_bytes).public()
}

fn member(identity: EndpointId, ip: Ipv4Addr, collision_index: u32) -> Member {
    Member {
        identity,
        ip,
        is_coordinator: false,
        hostname: None,
        user_identity: None,
        device_cert: None,
        collision_index,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
        ipv6_only: false,
    }
}

/// A roster of distinct identities, each seated at its derived address. Seeds
/// are drawn from a small space so collisions in the 22-bit host space are
/// reachable, and deduplicated so no identity appears twice.
fn roster_strategy(max: usize) -> impl Strategy<Value = Vec<Member>> {
    prop::collection::vec(0u32..64, 0..max).prop_map(|seeds| {
        let mut seen = BTreeSet::new();
        seeds
            .into_iter()
            .filter(|s| seen.insert(*s))
            .map(|s| {
                let id = id_from_seed(s);
                member(id, derive_ip(&id), 0)
            })
            .collect()
    })
}

fn in_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

proptest! {
    /// Every derived IPv4, at any collision index, lands in the overlay's
    /// CGNAT range and avoids the network address and the TUN gateway. A
    /// derivation escaping the range would route mesh traffic off the tunnel.
    #[test]
    fn derived_ipv4_always_in_range(seed in any::<u32>(), index in any::<u32>()) {
        let ip = derive_ip_with_index(&id_from_seed(seed), index);
        prop_assert!(in_cgnat(ip), "{ip} outside 100.64.0.0/10");
        prop_assert!(is_overlay_ip(IpAddr::V4(ip)));

        let host_bits = u32::from(ip) & 0x003F_FFFF;
        prop_assert!(host_bits >= 2, "{ip} uses a reserved host address");
    }

    /// Every derived IPv6 lands in 200::/7.
    #[test]
    fn derived_ipv6_always_in_range(seed in any::<u32>()) {
        let ip = derive_ipv6(&id_from_seed(seed));
        prop_assert!(is_overlay_ip(IpAddr::V6(ip)), "{ip} outside 200::/7");
    }

    /// Derivation is a pure function of identity and index: two nodes deriving
    /// the same peer's address must agree, or they disagree about who is who.
    #[test]
    fn derivation_is_deterministic(seed in any::<u32>(), index in any::<u32>()) {
        let id = id_from_seed(seed);
        prop_assert_eq!(derive_ip_with_index(&id, index), derive_ip_with_index(&id, index));
        prop_assert_eq!(derive_ipv6(&id), derive_ipv6(&id));
        prop_assert_eq!(derive_ip(&id), derive_ip_with_index(&id, 0));
    }

    /// Distinct identities get distinct IPv6 addresses. The 120-bit space
    /// makes a collision astronomically unlikely, which is why there is no
    /// v6 collision index to fall back on.
    #[test]
    fn distinct_identities_get_distinct_ipv6(a in any::<u32>(), b in any::<u32>()) {
        prop_assume!(a != b);
        prop_assert_ne!(derive_ipv6(&id_from_seed(a)), derive_ipv6(&id_from_seed(b)));
    }
}

// ---------------------------------------------------------------------------
// Seating and convergence
// ---------------------------------------------------------------------------

proptest! {
    /// `assign_ip` returns an address no *other* member holds, and one this
    /// identity can be seated at: the returned index must reproduce it.
    #[test]
    fn assign_ip_never_collides(roster in roster_strategy(12), seed in 0u32..64) {
        let mut list = MemberList::new();
        for m in roster {
            let _ = list.add(m);
        }
        let id = id_from_seed(seed);
        let (ip, index) = assign_ip(&list, &id);

        prop_assert_eq!(derive_ip_with_index(&id, index), ip);
        prop_assert!(in_cgnat(ip));
        if let Some(existing) = list.get_by_ip(ip) {
            prop_assert_eq!(existing.identity, id, "assigned {} already held", ip);
        }
    }

    /// Re-seating an identity already in the roster returns the seat it holds
    /// rather than moving it, so a re-add (reconnect, roster merge) is stable.
    #[test]
    fn assign_ip_is_stable_for_existing_members(roster in roster_strategy(12)) {
        prop_assume!(!roster.is_empty());
        let mut list = MemberList::new();
        for m in roster.iter().cloned() {
            let _ = list.add(m);
        }
        for m in list.all().into_iter().cloned().collect::<Vec<_>>() {
            let (ip, _) = assign_ip(&list, &m.identity);
            prop_assert_eq!(ip, m.ip);
        }
    }

    /// The property the whole tiebreak exists for: the resolved address map
    /// depends only on the *set* of members, not on the order they arrived in.
    /// Two nodes that assembled the same roster from different directions must
    /// end up with the same seating, or they disagree about peer addresses.
    #[test]
    fn tiebreak_is_permutation_invariant(
        roster in roster_strategy(10),
        shuffle in prop::collection::vec(any::<usize>(), 0..20),
    ) {
        let mut permuted = roster.clone();
        // Fisher-Yates driven by the generated indices, so the permutation is
        // shrinkable rather than drawn from a hidden RNG.
        if !permuted.is_empty() {
            for (i, raw) in shuffle.iter().enumerate() {
                let a = i % permuted.len();
                let b = raw % permuted.len();
                permuted.swap(a, b);
            }
        }

        let a = resolve_ip_tiebreak(roster);
        let b = resolve_ip_tiebreak(permuted);

        let seat = |ms: Vec<Member>| {
            ms.into_iter()
                .map(|m| (m.identity.to_string(), (m.ip, m.collision_index)))
                .collect::<BTreeMap<_, _>>()
        };
        prop_assert_eq!(seat(a), seat(b));
    }

    /// Tiebreak output contains no duplicate address, whatever went in:
    /// that is the collision it is there to resolve.
    #[test]
    fn tiebreak_output_has_no_duplicate_ips(roster in roster_strategy(10)) {
        let resolved = resolve_ip_tiebreak(roster);
        let mut seen = BTreeSet::new();
        for m in &resolved {
            prop_assert!(seen.insert(m.ip), "duplicate address {} after tiebreak", m.ip);
        }
    }

    /// Tiebreak preserves the membership set and every member's seat is one
    /// its own identity derives, so nobody is dropped, added, or handed an
    /// address that isn't theirs.
    #[test]
    fn tiebreak_preserves_members(roster in roster_strategy(10)) {
        let before: BTreeSet<String> = roster.iter().map(|m| m.identity.to_string()).collect();
        let resolved = resolve_ip_tiebreak(roster);
        let after: BTreeSet<String> = resolved.iter().map(|m| m.identity.to_string()).collect();
        prop_assert_eq!(before, after);

        for m in &resolved {
            prop_assert_eq!(derive_ip_with_index(&m.identity, m.collision_index), m.ip);
        }
    }

    /// Tiebreak is idempotent: re-running it on its own output changes
    /// nothing. A roster that keeps re-seating on every reconverge would
    /// churn peer addresses forever.
    #[test]
    fn tiebreak_is_idempotent(roster in roster_strategy(10)) {
        let once = resolve_ip_tiebreak(roster);
        let twice = resolve_ip_tiebreak(once.clone());
        let seat = |ms: &[Member]| {
            ms.iter()
                .map(|m| (m.identity.to_string(), (m.ip, m.collision_index)))
                .collect::<BTreeMap<_, _>>()
        };
        prop_assert_eq!(seat(&once), seat(&twice));
    }
}

// ---------------------------------------------------------------------------
// Blob canonicalization
// ---------------------------------------------------------------------------

proptest! {
    /// The blob hash is what members compare to decide whether they have
    /// converged, so it must depend on roster *content* only. Feeding the same
    /// members in a different insertion order (different HashMap layout) must
    /// produce identical bytes.
    #[test]
    fn canonical_bytes_ignore_insertion_order(
        roster in roster_strategy(10),
        shuffle in prop::collection::vec(any::<usize>(), 0..20),
    ) {
        let roster = resolve_ip_tiebreak(roster);
        let mut permuted = roster.clone();
        if !permuted.is_empty() {
            for (i, raw) in shuffle.iter().enumerate() {
                let a = i % permuted.len();
                let b = raw % permuted.len();
                permuted.swap(a, b);
            }
        }

        let build = |ms: Vec<Member>| {
            let mut list = MemberList::new();
            for m in ms {
                let _ = list.add(m);
            }
            list
        };

        let approved = ApprovedList::new();
        let firewall = Default::default();
        let keys = BTreeMap::new();
        let nullifiers = BTreeSet::new();

        let a = canonical_group_bytes(
            &build(roster), &approved, &firewall, Some("net"), &keys, &nullifiers,
        );
        let b = canonical_group_bytes(
            &build(permuted), &approved, &firewall, Some("net"), &keys, &nullifiers,
        );
        prop_assert_eq!(a, b);
    }

    /// The hash is exactly the hash of the canonical bytes: the two entry
    /// points can't drift apart.
    #[test]
    fn blob_hash_matches_canonical_bytes(roster in roster_strategy(8)) {
        let mut list = MemberList::new();
        for m in resolve_ip_tiebreak(roster) {
            let _ = list.add(m);
        }
        let approved = ApprovedList::new();
        let firewall = Default::default();
        let keys = BTreeMap::new();
        let nullifiers = BTreeSet::new();

        let bytes = canonical_group_bytes(
            &list, &approved, &firewall, None, &keys, &nullifiers,
        );
        let hash = group_blob_hash(&list, &approved, &firewall, None, &keys, &nullifiers);
        prop_assert_eq!(hash, blake3::hash(&bytes));
    }
}

// ---------------------------------------------------------------------------
// Hostnames
// ---------------------------------------------------------------------------

/// Hostnames as the roster carries them: valid DNS labels, drawn short so
/// collisions between generated names actually happen.
fn hostname_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,6}".prop_filter("must be a valid hostname", |s| is_valid_hostname(s))
}

proptest! {
    /// Collision resolution must always produce a free name: the whole point
    /// is that two peers never end up answering to the same `*.ray` label.
    #[test]
    fn resolve_collision_returns_a_free_name(
        desired in hostname_strategy(),
        taken in prop::collection::vec(hostname_strategy(), 0..12),
    ) {
        let refs: Vec<&str> = taken.iter().map(String::as_str).collect();
        let assigned = resolve_collision(&desired, &refs);
        prop_assert!(!refs.contains(&assigned.as_str()), "{assigned} was already taken");
    }

    /// A free name is handed back unchanged: no gratuitous renaming.
    #[test]
    fn resolve_collision_keeps_free_names(
        desired in hostname_strategy(),
        taken in prop::collection::vec(hostname_strategy(), 0..12),
    ) {
        let refs: Vec<&str> = taken.iter().map(String::as_str).collect();
        prop_assume!(!refs.contains(&desired.as_str()));
        prop_assert_eq!(resolve_collision(&desired, &refs), desired);
    }

    /// The resolved name must still be a usable DNS label, or Magic DNS can't
    /// serve it.
    #[test]
    fn resolve_collision_returns_a_valid_hostname(
        desired in hostname_strategy(),
        taken in prop::collection::vec(hostname_strategy(), 0..12),
    ) {
        let refs: Vec<&str> = taken.iter().map(String::as_str).collect();
        let assigned = resolve_collision(&desired, &refs);
        prop_assert!(is_valid_hostname(&assigned), "{assigned} is not a valid hostname");
    }

    /// An invite-bound name is assigned exactly or rejected outright. Silently
    /// renaming it would let a peer inherit the firewall rules written for the
    /// name it was promised.
    #[test]
    fn authoritative_hostname_is_exact_or_rejected(
        desired in hostname_strategy(),
        taken in prop::collection::vec(hostname_strategy(), 0..12),
    ) {
        let refs: Vec<&str> = taken.iter().map(String::as_str).collect();
        match admission_hostname(&desired, &refs, true) {
            Ok(assigned) => {
                prop_assert_eq!(&assigned, &desired);
                prop_assert!(!refs.contains(&desired.as_str()));
            }
            Err(conflict) => {
                prop_assert_eq!(&conflict, &desired);
                prop_assert!(refs.contains(&desired.as_str()));
            }
        }
    }

    /// A joiner-chosen name never displaces an existing one: whatever comes
    /// back is free.
    #[test]
    fn non_authoritative_hostname_never_takes_an_existing_name(
        desired in hostname_strategy(),
        taken in prop::collection::vec(hostname_strategy(), 0..12),
    ) {
        let refs: Vec<&str> = taken.iter().map(String::as_str).collect();
        let assigned = admission_hostname(&desired, &refs, false).expect("never rejects");
        prop_assert!(!refs.contains(&assigned.as_str()));
    }
}
