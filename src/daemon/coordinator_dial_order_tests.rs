use super::*;
use crate::membership::{ExitFamilies, Member};

fn test_id(seed: u8) -> EndpointId {
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = seed;
    let key = SecretKey::from(key_bytes);
    key.public()
}

#[test]
fn dial_order_puts_minter_first_then_other_coordinators() {
    let (a, b, c, me) = (test_id(1), test_id(2), test_id(3), test_id(9));
    let mk = |id, coord| Member {
        identity: id,
        is_coordinator: coord,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    };
    let members = MemberList::from(vec![mk(a, true), mk(b, true), mk(c, false), mk(me, true)]);
    // minter = b: b first, then the other coordinator a, never c (not coord), never me.
    assert_eq!(super::coordinator_dial_order(b, &members, me), vec![b, a]);
}

#[test]
fn dial_order_edge_cases() {
    let (a, b, me) = (test_id(1), test_id(2), test_id(9));
    let mk = |id, coord| Member {
        identity: id,
        is_coordinator: coord,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    };

    // No coordinators in the roster ⇒ empty order (caller bails).
    let none_coord = MemberList::from(vec![mk(a, false), mk(b, false)]);
    assert!(super::coordinator_dial_order(a, &none_coord, me).is_empty());

    // Minter == me (the no-invite case where we pass our own id): we are
    // filtered out, leaving just the other coordinators.
    let members = MemberList::from(vec![mk(a, true), mk(me, true)]);
    assert_eq!(super::coordinator_dial_order(me, &members, me), vec![a]);

    // Minter isn't a coordinator in the blob: it is not promoted to the
    // front, but real coordinators still get dialed.
    let members = MemberList::from(vec![mk(a, true), mk(b, false)]);
    assert_eq!(super::coordinator_dial_order(b, &members, me), vec![a]);

    // Minter is a coordinator AND also appears in the member scan: listed
    // once (front), no duplicate.
    let members = MemberList::from(vec![mk(a, true), mk(b, true)]);
    assert_eq!(super::coordinator_dial_order(a, &members, me), vec![a, b]);
}

#[test]
fn admin_grant_key_accepted_only_when_public_matches_network() {
    // The real network key: its public half is the network pubkey.
    let net_secret = SecretKey::from({
        let mut b = [0u8; 32];
        b[0] = 42;
        b
    });
    let net_pubkey = net_secret.public();

    // A genuine grant carries the real secret → accepted.
    assert!(super::admin_grant_key_valid(
        net_secret.to_bytes(),
        net_pubkey
    ));

    // A forged grant carries an attacker-chosen key whose public half does
    // not match the network pubkey → rejected (no roster lookup needed).
    let forged = SecretKey::from({
        let mut b = [0u8; 32];
        b[0] = 7;
        b
    });
    assert!(!super::admin_grant_key_valid(forged.to_bytes(), net_pubkey));
}

#[test]
fn gossip_targets_are_coordinator_peers_only() {
    let (a, b, c) = (test_id(1), test_id(2), test_id(3));
    let mk = |id, coord| Member {
        identity: id,
        is_coordinator: coord,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    };
    let members = MemberList::from(vec![mk(a, true), mk(b, false), mk(c, true)]);
    let me = a;
    // gossip to other coordinators only: c (not b, not me).
    assert_eq!(super::gossip_targets(&members, me), vec![c]);
}

#[test]
fn gossip_targets_empty_when_sole_coordinator() {
    let me = test_id(1);
    let mk = |id, coord| Member {
        identity: id,
        is_coordinator: coord,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    };
    // Only members are us (coordinator) and a plain member: nobody to gossip to.
    let members = MemberList::from(vec![mk(me, true), mk(test_id(2), false)]);
    assert!(super::gossip_targets(&members, me).is_empty());
}
