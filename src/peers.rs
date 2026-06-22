use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dashmap::DashMap;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use smol_str::SmolStr;

#[derive(Clone)]
pub struct PeerTable {
    v4: Arc<DashMap<Ipv4Addr, PeerEntry>>,
    v6: Arc<DashMap<Ipv6Addr, PeerEntry>>,
}

/// A single peer's connection and identity.
pub struct PeerEntry {
    pub conn: Connection,
    pub endpoint_id: EndpointId,
    pub network: SmolStr,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            v4: Arc::new(DashMap::new()),
            v6: Arc::new(DashMap::new()),
        }
    }

    pub fn add(
        &self,
        ip: Ipv4Addr,
        ipv6: Ipv6Addr,
        conn: Connection,
        endpoint_id: EndpointId,
        network: &str,
    ) {
        let net = SmolStr::new(network);
        self.v4.insert(
            ip,
            PeerEntry {
                conn: conn.clone(),
                endpoint_id,
                network: net.clone(),
            },
        );
        self.v6.insert(
            ipv6,
            PeerEntry {
                conn,
                endpoint_id,
                network: net,
            },
        );
    }

    pub fn lookup_v4(&self, ip: &Ipv4Addr) -> Option<(Connection, EndpointId, SmolStr)> {
        self.v4
            .get(ip)
            .map(|e| (e.conn.clone(), e.endpoint_id, e.network.clone()))
    }

    pub fn lookup_v6(&self, ip: &Ipv6Addr) -> Option<(Connection, EndpointId, SmolStr)> {
        self.v6
            .get(ip)
            .map(|e| (e.conn.clone(), e.endpoint_id, e.network.clone()))
    }

    pub fn remove(&self, ip: &Ipv4Addr, ipv6: &Ipv6Addr) {
        self.v4.remove(ip);
        self.v6.remove(ipv6);
    }

    pub fn all_connections(&self) -> Vec<(Ipv4Addr, Connection)> {
        self.v4.iter().map(|e| (*e.key(), e.conn.clone())).collect()
    }

    pub fn remove_by_network(&self, network: &str) -> Vec<Ipv4Addr> {
        let mut removed = Vec::new();
        self.v4.retain(|ip, e| {
            if e.network == network {
                removed.push(*ip);
                false
            } else {
                true
            }
        });
        self.v6.retain(|_ip, e| e.network != network);
        removed
    }

    pub fn peers_for_network(&self, network: &str) -> Vec<(EndpointId, Ipv4Addr)> {
        self.v4
            .iter()
            .filter(|e| e.network == network)
            .map(|e| (e.endpoint_id, *e.key()))
            .collect()
    }

    pub fn peers_for_network_with_conn(
        &self,
        network: &str,
    ) -> Vec<(EndpointId, Ipv4Addr, Connection)> {
        self.v4
            .iter()
            .filter(|e| e.network == network)
            .map(|e| (e.endpoint_id, *e.key(), e.conn.clone()))
            .collect()
    }

    #[cfg(test)]
    pub fn all_peer_ids(&self) -> Vec<(Ipv4Addr, EndpointId)> {
        self.v4.iter().map(|e| (*e.key(), e.endpoint_id)).collect()
    }
}

/// Maps device transport keys to user identities for paired devices.
/// Used by the forwarding path to resolve ACL identities.
#[derive(Clone)]
pub struct DeviceUserMap {
    inner: Arc<DashMap<EndpointId, EndpointId>>,
}

impl DeviceUserMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_table_empty_lookup() {
        let table = PeerTable::new();
        assert!(table.lookup_v4(&Ipv4Addr::new(100, 64, 0, 5)).is_none());
        assert!(
            table
                .lookup_v6(&Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1))
                .is_none()
        );
    }

    #[test]
    fn test_peer_table_empty_ids() {
        let table = PeerTable::new();
        assert!(table.all_peer_ids().is_empty());
    }
}
