use std::net::Ipv4Addr;
use std::sync::Arc;

use dashmap::DashMap;
use iroh::EndpointId;
use iroh::endpoint::Connection;

#[derive(Clone)]
pub struct PeerTable {
    inner: Arc<DashMap<Ipv4Addr, PeerEntry>>,
}

/// A single peer's connection and identity.
pub struct PeerEntry {
    pub conn: Connection,
    pub endpoint_id: EndpointId,
    pub network: String,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn add(&self, ip: Ipv4Addr, conn: Connection, endpoint_id: EndpointId, network: &str) {
        self.inner.insert(ip, PeerEntry { conn, endpoint_id, network: network.to_string() });
    }

    pub fn lookup_full(&self, ip: &Ipv4Addr) -> Option<(Connection, EndpointId, String)> {
        self.inner
            .get(ip)
            .map(|e| (e.conn.clone(), e.endpoint_id, e.network.clone()))
    }

    pub fn remove(&self, ip: &Ipv4Addr) {
        self.inner.remove(ip);
    }

    pub fn all_connections(&self) -> Vec<(Ipv4Addr, Connection)> {
        self.inner
            .iter()
            .map(|e| (*e.key(), e.conn.clone()))
            .collect()
    }

    pub fn remove_by_network(&self, network: &str) -> Vec<Ipv4Addr> {
        let mut removed = Vec::new();
        self.inner.retain(|ip, e| {
            if e.network == network {
                removed.push(*ip);
                false
            } else {
                true
            }
        });
        removed
    }

    pub fn peers_for_network(&self, network: &str) -> Vec<(EndpointId, Ipv4Addr)> {
        self.inner
            .iter()
            .filter(|e| e.network == network)
            .map(|e| (e.endpoint_id, *e.key()))
            .collect()
    }

    pub fn peers_for_network_with_conn(&self, network: &str) -> Vec<(EndpointId, Ipv4Addr, Connection)> {
        self.inner
            .iter()
            .filter(|e| e.network == network)
            .map(|e| (e.endpoint_id, *e.key(), e.conn.clone()))
            .collect()
    }

    #[cfg(test)]
    pub fn all_peer_ids(&self) -> Vec<(Ipv4Addr, EndpointId)> {
        self.inner
            .iter()
            .map(|e| (*e.key(), e.endpoint_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_table_empty_lookup_full() {
        let table = PeerTable::new();
        let ip = Ipv4Addr::new(100, 64, 0, 5);
        assert!(table.lookup_full(&ip).is_none());
    }

    #[test]
    fn test_peer_table_empty_ids() {
        let table = PeerTable::new();
        assert!(table.all_peer_ids().is_empty());
    }
}
