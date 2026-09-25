use std::sync::Arc;

use iroh::EndpointId;

use super::FastDashMap;

/// Maps device transport keys to user identities for paired devices.
/// Used by the forwarding path to resolve ACL identities.
#[derive(Clone)]
pub struct DeviceUserMap {
    inner: Arc<FastDashMap<EndpointId, EndpointId>>,
}

impl Default for DeviceUserMap {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceUserMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FastDashMap::default()),
        }
    }

    pub fn insert(&self, device_key: EndpointId, user_identity: EndpointId) {
        self.inner.insert(device_key, user_identity);
    }

    pub fn resolve(&self, transport_key: &EndpointId) -> EndpointId {
        self.inner
            .get(transport_key)
            .map(|e| *e.value())
            .unwrap_or(*transport_key)
    }

    /// Every device key currently mapped to `user_identity`. The inverse of
    /// [`resolve`](Self::resolve), for callers holding a roster identity that
    /// need the device key used by the peer table.
    pub fn devices_for(&self, user_identity: &EndpointId) -> Vec<EndpointId> {
        self.inner
            .iter()
            .filter(|e| e.value() == user_identity)
            .map(|e| *e.key())
            .collect()
    }

    /// Drop a device's mapping so it stops resolving to a user identity.
    pub fn remove(&self, device_key: &EndpointId) {
        self.inner.remove(device_key);
    }
}
