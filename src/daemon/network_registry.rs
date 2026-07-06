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
    /// Foundation handles (endpoint + blob store) for reseal/publish.
    transport: Arc<Transport>,
    /// Live peer routing table, for severing / notifying peers on roster change.
    peers: PeerTable,
}

impl NetworkRegistry {
    pub(crate) fn new(
        networks: Arc<DashMap<String, NetworkHandle>>,
        transport: Arc<Transport>,
        peers: PeerTable,
    ) -> Self {
        Self {
            networks,
            transport,
            peers,
        }
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

    /// Clear a re-paired device's nullifier (the inverse of `unpair`). Invoked
    /// directly by the pairing accept arm when it re-authorizes a device: drops
    /// it from the durable `revoked_devices` seed and from every coordinated
    /// network's blob nullifier set, republishing so the device's fresh cert is
    /// honored mesh wide again. Non-coordinated networks clear on their own
    /// coordinator's next reseal. Best-effort; a persist/publish failure is
    /// logged, not surfaced.
    pub(crate) async fn reauth_device(&self, device: EndpointId) {
        // Drop from the durable nullifier seed so a later reseal won't re-add it.
        let mut cfg = config::load().unwrap_or_default();
        let hex = device.to_string();
        if let Some(pos) = cfg.revoked_devices.iter().position(|d| *d == hex) {
            cfg.revoked_devices.remove(pos);
            if let Err(e) = config::save_settings(&cfg) {
                tracing::warn!(error = %e, "reauth: failed to clear device from nullifier seed");
            }
        }
        // Collect coordinated networks (clone the handles) before awaiting.
        let mut nets: Vec<(String, SharedNetworkState, Option<Arc<Notify>>)> = Vec::new();
        for entry in self.networks.iter() {
            if entry.value().state.read().unwrap().network_secret_key.is_some() {
                nets.push((
                    entry.key().clone(),
                    entry.value().state.clone(),
                    entry.value().dht_notify.clone(),
                ));
            }
        }
        let mut changed = false;
        for (net, state, dht_notify) in nets {
            let removed = {
                let mut s = state.write().unwrap();
                s.nullifiers.remove(&device)
            };
            if removed {
                changed = true;
                update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
                let net_pubkey = state.read().unwrap().network_public_key;
                broadcast_member_sync(&self.peers, net_pubkey, &net, None).await;
            }
        }
        if changed {
            tracing::info!(device = %device.fmt_short(), "re-authorized device (cleared nullifier)");
        }
    }
}
