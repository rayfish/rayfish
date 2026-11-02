//! Pure decision helpers for the join/gossip paths: coordinator dial order,
//! gossip targets, and connection-path classification. No I/O, so these are unit
//! tested directly (see the tests in `daemon/mod.rs`).

use super::super::*;

/// Compute the order in which a joiner should dial coordinators.
/// Returns the minter first (if present and not `me`), then every other
/// `is_coordinator` member except `me`, de-duplicated, preserving order.
/// Consumed by the join dial-fallback loop.
pub(crate) fn coordinator_dial_order(
    minter: EndpointId,
    members: &MemberList,
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

/// The coordinator a fresh join was told to dial, from an invite or pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JoinCoordinator {
    /// Dial it first, then the roster's other coordinators. It is tried even
    /// when the fetched roster does not flag it, so a stale roster cannot
    /// strand an invite or pairing join.
    Preferred(EndpointId),
    /// Dial only it, and only when the signed roster flags it a coordinator.
    /// A controller's delegated join uses this: falling through to the
    /// network's other coordinators would let a controller that holds some
    /// network's invite secret enroll the machine in a network it does not run.
    Required(EndpointId),
}

impl JoinCoordinator {
    pub(crate) fn id(self) -> EndpointId {
        match self {
            Self::Preferred(id) | Self::Required(id) => id,
        }
    }
}

/// The coordinators a fresh join dials, in order. Errors when there is no one
/// to dial, or when a required coordinator is not one in the signed roster.
pub(crate) fn fresh_join_dial_order(
    coordinator: Option<JoinCoordinator>,
    members: &MemberList,
    me: EndpointId,
) -> Result<Vec<EndpointId>> {
    let order = match coordinator {
        Some(JoinCoordinator::Required(required)) => {
            anyhow::ensure!(
                required != me
                    && members
                        .iter()
                        .any(|m| m.identity == required && m.is_coordinator),
                "{} is not a coordinator of this network",
                required.fmt_short()
            );
            vec![required]
        }
        Some(JoinCoordinator::Preferred(preferred)) => {
            let mut order = coordinator_dial_order(preferred, members, me);
            if preferred != me && !order.contains(&preferred) {
                order.insert(0, preferred);
            }
            order
        }
        // No minter: every roster coordinator but us, in roster order.
        None => coordinator_dial_order(me, members, me),
    };
    anyhow::ensure!(!order.is_empty(), "no coordinator found in network record");
    Ok(order)
}

/// Pick the peers to gossip single-use invite state to: every other
/// `is_coordinator` member, excluding ourselves. Only coordinators (network-key
/// holders) can admit, so only they need the shared invite ledger; a
/// non-coordinator is never a target.
pub(crate) fn gossip_targets(members: &MemberList, me: EndpointId) -> Vec<EndpointId> {
    members
        .iter()
        .filter(|m| m.is_coordinator && m.identity != me)
        .map(|m| m.identity)
        .collect()
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
