//! `NetworkRegistry`: the service that owns the set of active networks.
//!
//! This is the seam that the `MeshManager` network methods (create / join /
//! leave / coordinator / reconverge / …) migrate onto over the course of the
//! decomposition. It owns the per-network runtime handles keyed by name; during
//! the transition it shares the same `Arc<DashMap>` the daemon still holds, so
//! methods can move here one at a time while the tree stays green.
//!
//! It is a control-plane service: never on the packet path. Membership queries
//! (like the file auto-accept gate) and the coordinator/member operations live
//! here so leaf tasks and other services can call them directly instead of
//! signalling the daemon through a channel.

use super::*;

pub(crate) struct NetworkRegistry {
    /// Per-network runtime handles, keyed by network name. Shared with
    /// `MeshManager` during the transition (same `Arc`), so a method can move to
    /// the registry without splitting the map.
    networks: Arc<DashMap<String, NetworkHandle>>,
}

impl NetworkRegistry {
    pub(crate) fn new(networks: Arc<DashMap<String, NetworkHandle>>) -> Self {
        Self { networks }
    }

    /// Whether `identity` is a current member of at least one network that has
    /// file auto-accept enabled. Backs the own-device file auto-accept gate.
    pub(crate) fn member_on_autoaccept_network(&self, identity: EndpointId) -> bool {
        for entry in self.networks.iter() {
            let enabled = config::load_network(entry.key())
                .ok()
                .flatten()
                .map(|nc| nc.auto_accept_files)
                .unwrap_or(false);
            if !enabled {
                continue;
            }
            let is_member = entry
                .value()
                .state
                .read()
                .map(|s| s.members.all().iter().any(|m| m.identity == identity))
                .unwrap_or(false);
            if is_member {
                return true;
            }
        }
        false
    }
}
