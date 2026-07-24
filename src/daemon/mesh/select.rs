//! Pure decision helpers for the join/gossip paths: coordinator dial order,
//! gossip targets, dial-fallback outcome selection, persisted-roster fallback,
//! and connection-path classification. No I/O, so these are unit-tested directly
//! (see the tests in `daemon/mod.rs`).

use super::super::*;

/// Compute the order in which a joiner should dial coordinators.
/// Returns the minter first (if present and not `me`), then every other
/// `is_coordinator` member except `me`, de-duplicated, preserving order.
/// Consumed by the join dial-fallback loop.
pub(crate) fn coordinator_dial_order(
    minter: EndpointId,
    members: &[Member],
    me: EndpointId,
) -> Vec<EndpointId> {
    let mut order = Vec::new();
    let is_coord = |id: EndpointId| members.iter().any(|m| m.identity == id && m.is_coordinator);
    if minter != me && is_coord(minter) {
        order.push(minter);
    }
    for m in members {
        if m.is_coordinator && m.identity != me && !order.contains(&m.identity) {
            order.push(m.identity);
        }
    }
    order
}

/// Pick the peers to gossip single-use invite state to: every other
/// `is_coordinator` member, excluding ourselves. Only coordinators (network-key
/// holders) can admit, so only they need the shared invite ledger; a
/// non-coordinator is never a target.
pub(crate) fn gossip_targets(members: &[Member], me: EndpointId) -> Vec<EndpointId> {
    members
        .iter()
        .filter(|m| m.is_coordinator && m.identity != me)
        .map(|m| m.identity)
        .collect()
}

/// Last-known roster from persisted config. Used only as a fallback when the
/// signed pkarr record is briefly unreachable during a reconnect, never trusts
/// peer-supplied membership.
pub(crate) fn persisted_roster(network_name: &str) -> Vec<Member> {
    config::load()
        .ok()
        .and_then(|c| c.networks.into_iter().find(|n| n.name == network_name))
        .map(|n| {
            n.members
                .into_iter()
                .map(|m| Member {
                    identity: m.identity,
                    ip: m.ip,
                    is_coordinator: m.is_coordinator,
                    hostname: m.hostname,
                    user_identity: None,
                    device_cert: None,
                    collision_index: 0,
                    last_seen: None,
                    exit_node: false,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Rebuild a network's DNS entries from its member roster (the single source of
/// truth) and persist our own (possibly coordinator-corrected) hostname. Called
/// whenever a roster update arrives so renames, joins, and departures all reflect
/// in `*.ray` resolution immediately.
/// Pick which connection path to report in `ray status`. Prefers the path iroh
/// has selected; otherwise falls back to the best concrete path so a live
/// connection never renders as `Unknown` (`?`). Priority Direct > Relay > Tor.
/// Returns the index into `classes`, or `None` only when there are no paths.
pub(crate) fn choose_path_index(classes: &[(ipc::ConnType, bool)]) -> Option<usize> {
    if let Some(i) = classes.iter().position(|(_, selected)| *selected) {
        return Some(i);
    }
    for want in [
        ipc::ConnType::Direct,
        ipc::ConnType::Relay,
        ipc::ConnType::Tor,
    ] {
        if let Some(i) = classes.iter().position(|(ct, _)| *ct == want) {
            return Some(i);
        }
    }
    // A path with no IP/relay/custom classification (none today) or, really,
    // only reached when `classes` is empty.
    (!classes.is_empty()).then_some(0)
}
