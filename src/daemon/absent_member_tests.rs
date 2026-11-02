use super::*;
use iroh::SecretKey;

fn id(seed: u8) -> EndpointId {
    let mut b = [0u8; 32];
    b[0] = seed;
    SecretKey::from(b).public()
}

fn member(seed: u8) -> Member {
    Member {
        identity: id(seed),
        is_coordinator: false,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    }
}

/// The whole point of the dial fallback: a member that holds no live
/// connection is a dial candidate, because on-demand peers idle-close their
/// links while staying reachable.
#[test]
fn unconnected_member_is_a_dial_candidate() {
    let roster = MemberList::from(vec![member(1), member(2)]);
    let reached: HashSet<EndpointId> = [id(1)].into_iter().collect();
    let got = absent_member_ips(&roster, id(9), None, &reached, |_| false);
    assert_eq!(got, vec![derive_ipv6(&id(2))]);
}

/// Self, the excluded peer, and anyone already reached over a live
/// connection must never be dialed: the first is nonsense, the second is
/// the peer the caller deliberately skipped, the third already got it.
#[test]
fn self_excluded_and_reached_are_skipped() {
    let roster = MemberList::from(vec![member(1), member(2), member(3), member(4)]);
    let reached: HashSet<EndpointId> = [id(3)].into_iter().collect();
    let got = absent_member_ips(&roster, id(1), Some(derive_ipv6(&id(2))), &reached, |_| {
        false
    });
    assert_eq!(got, vec![derive_ipv6(&id(4))]);
}

/// A member whose last dial failed recently is offline for real, not
/// idle-closed. Re-dialing it on every roster edit would cost a timeout per
/// edit and teach us nothing.
#[test]
fn known_offline_member_is_not_redialed() {
    let roster = MemberList::from(vec![member(1), member(2)]);
    let offline = id(1);
    let got = absent_member_ips(&roster, id(9), None, &HashSet::new(), |i| *i == offline);
    assert_eq!(got, vec![derive_ipv6(&id(2))]);
}

fn coordinator(seed: u8) -> Member {
    Member {
        is_coordinator: true,
        ..member(seed)
    }
}

/// A leave must reach a coordinator, the only member that can prune it, so
/// the coordinators the live links missed are dialed and nobody else is:
/// ordinary members learn of the leave from the coordinator's republish.
#[test]
fn a_leave_dials_only_the_coordinators_it_missed() {
    let roster = MemberList::from(vec![
        coordinator(1),
        coordinator(2),
        member(3),
        coordinator(4),
    ]);
    let reached: HashSet<EndpointId> = [id(2)].into_iter().collect();
    let got = leave_recipients(&roster, id(4), &reached);
    assert_eq!(got, vec![derive_ipv6(&id(1))]);
}
