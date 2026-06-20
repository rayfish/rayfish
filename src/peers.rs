//! Routing table mapping virtual IPs to peer QUIC connections.
//!
//! The [`PeerTable`] is the bridge between the TUN forwarding loop and the mesh.
//! It uses `RwLock` (not Mutex) for fast synchronous lookups — reads happen on
//! every packet, writes only on connect/disconnect.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use iroh::EndpointId;
use iroh::endpoint::Connection;

/// Thread-safe routing table: virtual IP → QUIC connection.
///
/// Cloning is cheap (inner `Arc`). Used by `run_mesh` to route outgoing packets
/// and by the accept/reconnect logic to register new peers.
#[derive(Clone)]
pub struct PeerTable {
    inner: Arc<RwLock<HashMap<Ipv4Addr, PeerEntry>>>,
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
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Inserts or replaces a peer's connection. Replacing a dead connection with a
    /// fresh one is how reconnection works — the TUN side sees the swap transparently.
    pub fn add(&self, ip: Ipv4Addr, conn: Connection, endpoint_id: EndpointId, network: &str) {
        self.inner
            .write()
            .unwrap()
            .insert(ip, PeerEntry { conn, endpoint_id, network: network.to_string() });
    }

    /// Returns (Connection, EndpointId, network_name) for a peer's virtual IP.
    /// Used by `run_mesh` for ACL-aware routing.
    pub fn lookup_full(&self, ip: &Ipv4Addr) -> Option<(Connection, EndpointId, String)> {
        self.inner
            .read()
            .unwrap()
            .get(ip)
            .map(|e| (e.conn.clone(), e.endpoint_id, e.network.clone()))
    }

    /// Removes a dead peer. Packets to this IP will be silently dropped until
    /// a new connection is added via [`PeerTable::add`].
    pub fn remove(&self, ip: &Ipv4Addr) {
        self.inner.write().unwrap().remove(ip);
    }

    /// Returns all (IP, Connection) pairs. Used for broadcasting control messages.
    pub fn all_connections(&self) -> Vec<(Ipv4Addr, Connection)> {
        self.inner
            .read()
            .unwrap()
            .iter()
            .map(|(ip, e)| (*ip, e.conn.clone()))
            .collect()
    }

    /// Removes all peers belonging to a network. Returns the IPs that were removed.
    pub fn remove_by_network(&self, network: &str) -> Vec<Ipv4Addr> {
        let mut inner = self.inner.write().unwrap();
        let to_remove: Vec<Ipv4Addr> = inner
            .iter()
            .filter(|(_, e)| e.network == network)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in &to_remove {
            inner.remove(ip);
        }
        to_remove
    }

    /// Returns (endpoint_id, ip) pairs for all peers in a given network.
    pub fn peers_for_network(&self, network: &str) -> Vec<(EndpointId, Ipv4Addr)> {
        self.inner
            .read()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.network == network)
            .map(|(ip, e)| (e.endpoint_id, *ip))
            .collect()
    }

    #[cfg(test)]
    pub fn all_peer_ids(&self) -> Vec<(Ipv4Addr, EndpointId)> {
        self.inner
            .read()
            .unwrap()
            .iter()
            .map(|(ip, e)| (*ip, e.endpoint_id))
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
