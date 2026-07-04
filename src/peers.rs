use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use iroh::EndpointId;
use iroh::endpoint::Connection;
use smol_str::SmolStr;

use crate::audit::AuditLog;

/// A `DashMap` using ahash instead of the default SipHash. Used for the
/// per-packet hot maps (routing table, conntrack, device→user resolution):
/// ahash is markedly faster for small keys while keeping a randomized seed, so
/// remote-controlled keys (peer IPs, flow tuples) can't be crafted to collide.
pub type FastDashMap<K, V> = dashmap::DashMap<K, V, ahash::RandomState>;

/// The data-plane routing table: virtual IP → peer, shared by every network.
///
/// Maps each peer's stable virtual IP (one per identity, identical across all
/// the networks that peer joins) to its [`PeerEntry`]. The forwarding loop in
/// `forward.rs` reads a packet's destination IP off the TUN and calls
/// [`lookup_v4`](Self::lookup_v4) / [`lookup_v6`](Self::lookup_v6) to find the
/// connection to send it over.
///
/// There is a single `PeerTable` for the whole daemon, not one per network — a
/// peer is reachable iff we share at least one network with it, and that fact is
/// captured by the peer holding a live connection in [`PeerEntry::conns`]. A
/// multi-homed peer therefore has one entry (one IP) with several connections,
/// not several entries.
///
/// Backed by [`FastDashMap`] for lock-free concurrent reads from the forwarding hot
/// path while accept/reconnect tasks mutate it; cloning the table is cheap
/// (shared `Arc`s), so it is handed to every per-network task by value.
#[derive(Clone)]
pub struct PeerTable {
    /// IPv4 virtual address → peer.
    v4: Arc<FastDashMap<Ipv4Addr, PeerEntry>>,
    /// IPv6 virtual address → peer (same peers as `v4`, keyed by their `200::/7`
    /// address so v6 packets resolve without a v4↔v6 translation step).
    v6: Arc<FastDashMap<Ipv6Addr, PeerEntry>>,
    /// Optional append-only audit log. When present, registering a peer's first
    /// connection in a network logs a `connect` event and dropping its last
    /// connection in a network logs a `disconnect` event. `None` in tests.
    audit: Option<Arc<AuditLog>>,
}

/// A single peer's identity and its per-network connections.
///
/// A peer has one virtual IP (derived from its identity, stable across every
/// network it joins), so the same peer can be reachable through several networks
/// at once — one QUIC connection per shared network. Reachability is simply
/// "we share at least one live connection", which is why connections are keyed
/// by network rather than overwriting a single slot.
pub struct PeerEntry {
    pub endpoint_id: EndpointId,
    /// network name -> connection within that network.
    pub conns: HashMap<SmolStr, Connection>,
}

/// Result of a routing lookup: a connection to send over and the network it
/// belongs to (used as firewall context on the forwarding path).
pub struct PeerRoute {
    pub conn: Connection,
    pub endpoint_id: EndpointId,
    /// The network whose connection was chosen to route over.
    pub network: SmolStr,
}

impl PeerEntry {
    /// Picks a connection deterministically (lexically-smallest network name) so
    /// routing for a multi-homed peer is stable across lookups.
    fn route(&self) -> Option<PeerRoute> {
        let (network, conn) = self.conns.iter().min_by(|a, b| a.0.cmp(b.0))?;
        Some(PeerRoute {
            conn: conn.clone(),
            endpoint_id: self.endpoint_id,
            network: network.clone(),
        })
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerTable {
    /// Creates an empty table with no audit logging (used in tests).
    pub fn new() -> Self {
        Self {
            v4: Arc::new(FastDashMap::default()),
            v6: Arc::new(FastDashMap::default()),
            audit: None,
        }
    }

    /// Creates an empty table that logs peer connect/disconnect events to the
    /// given audit log. The daemon constructs the table this way and clones it
    /// to every per-network task (clones share the same audit handle).
    pub fn with_audit(audit: Arc<AuditLog>) -> Self {
        Self {
            v4: Arc::new(FastDashMap::default()),
            v6: Arc::new(FastDashMap::default()),
            audit: Some(audit),
        }
    }

    /// Registers (or refreshes) the peer's connection for `network`. Other
    /// networks' connections to the same peer are preserved.
    pub fn add(
        &self,
        ip: Ipv4Addr,
        ipv6: Ipv6Addr,
        conn: Connection,
        endpoint_id: EndpointId,
        network: &str,
    ) {
        let net = SmolStr::new(network);
        // Whether this is the peer's *first* connection in `network` — a true
        // connect rather than a refresh of an existing link (which happens on
        // reconnect churn). Drives the audit `connect` event below.
        let newly_connected;
        {
            let mut e = self.v4.entry(ip).or_insert_with(|| PeerEntry {
                endpoint_id,
                conns: HashMap::new(),
            });
            e.endpoint_id = endpoint_id;
            newly_connected = e.conns.insert(net.clone(), conn.clone()).is_none();
        }
        {
            let mut e = self.v6.entry(ipv6).or_insert_with(|| PeerEntry {
                endpoint_id,
                conns: HashMap::new(),
            });
            e.endpoint_id = endpoint_id;
            e.conns.insert(net, conn);
        }
        if newly_connected && let Some(audit) = &self.audit {
            audit.log_connect(ip, &endpoint_id.to_string());
        }
    }

    /// Resolves an IPv4 destination to a [`PeerRoute`], or `None` if no peer with
    /// that address shares a live connection with us. This is the outbound hot
    /// path's lookup.
    pub fn lookup_v4(&self, ip: &Ipv4Addr) -> Option<PeerRoute> {
        self.v4.get(ip).and_then(|e| e.route())
    }

    /// IPv6 counterpart of [`lookup_v4`](Self::lookup_v4).
    pub fn lookup_v6(&self, ip: &Ipv6Addr) -> Option<PeerRoute> {
        self.v6.get(ip).and_then(|e| e.route())
    }

    /// Resolve a peer by its mesh source IP (v4 or v6) to its transport identity
    /// and the set of networks we currently share a live connection with it on.
    /// Used by the embedded mesh SSH server to authorize an incoming session: the
    /// peer is identified by which mesh IP the TCP connection came from (the
    /// ingress anti-spoof check in `forward.rs` guarantees that IP is the peer's
    /// own). Returns `None` if no peer holds that address.
    pub fn identity_and_networks(&self, ip: IpAddr) -> Option<(EndpointId, Vec<SmolStr>)> {
        match ip {
            IpAddr::V4(v4) => self
                .v4
                .get(&v4)
                .map(|e| (e.endpoint_id, e.conns.keys().cloned().collect())),
            IpAddr::V6(v6) => self
                .v6
                .get(&v6)
                .map(|e| (e.endpoint_id, e.conns.keys().cloned().collect())),
        }
    }

    /// Removes the peer entirely (all networks). Used for identity rotation.
    pub fn remove(&self, ip: &Ipv4Addr, ipv6: &Ipv6Addr) {
        let removed = self.v4.remove(ip);
        self.v6.remove(ipv6);
        if let (Some((_, entry)), Some(audit)) = (removed, &self.audit) {
            audit.log_disconnect(*ip, &entry.endpoint_id.to_string());
        }
    }

    /// Drops a peer's connection in a single `network`. The peer entry is removed
    /// only once it has no connections left in any network — so losing the `dev`
    /// link doesn't unroute a peer still reachable via `db`.
    pub fn remove_peer_from_network(&self, ip: &Ipv4Addr, ipv6: &Ipv6Addr, network: &str) {
        let mut dropped = None;
        if let Some(mut e) = self.v4.get_mut(ip)
            && e.conns.remove(network).is_some()
        {
            dropped = Some(e.endpoint_id);
        }
        self.v4.remove_if(ip, |_, e| e.conns.is_empty());
        if let Some(mut e) = self.v6.get_mut(ipv6) {
            e.conns.remove(network);
        }
        self.v6.remove_if(ipv6, |_, e| e.conns.is_empty());
        if let (Some(endpoint_id), Some(audit)) = (dropped, &self.audit) {
            audit.log_disconnect(*ip, &endpoint_id.to_string());
        }
    }

    /// Connection-aware variant of [`remove_peer_from_network`]: drops the
    /// peer's connection in `network` only if the one currently stored is the
    /// same connection identified by `stable_id`. Returns true when it removed a
    /// matching connection, false when the stored connection is a different
    /// (newer) one or the peer is already absent.
    ///
    /// This guards the ABA race described on [`forward::DisconnectEvent`]: a
    /// stale connection's delayed disconnect must not evict the fresh connection
    /// that already replaced it in the table after a peer re-dialed.
    pub fn remove_peer_from_network_if(
        &self,
        ip: &Ipv4Addr,
        ipv6: &Ipv6Addr,
        network: &str,
        stable_id: usize,
    ) -> bool {
        // Read-and-compare in its own statement so the DashMap read guard is
        // dropped before remove_peer_from_network takes a write guard on the
        // same shard.
        let matches = self
            .v4
            .get(ip)
            .and_then(|e| e.conns.get(network).map(|c| c.stable_id() == stable_id))
            .unwrap_or(false);
        if !matches {
            return false;
        }
        self.remove_peer_from_network(ip, ipv6, network);
        true
    }

    /// One connection per peer (deterministic pick), for global broadcasts.
    pub fn all_connections(&self) -> Vec<(Ipv4Addr, Connection)> {
        self.v4
            .iter()
            .filter_map(|e| e.route().map(|r| (*e.key(), r.conn)))
            .collect()
    }

    /// Removes `network`'s connection from every peer. Returns the IPs of peers
    /// that had no other network left (fully removed).
    pub fn remove_by_network(&self, network: &str) -> Vec<Ipv4Addr> {
        let mut removed = Vec::new();
        self.v4.retain(|ip, e| {
            e.conns.remove(network);
            if e.conns.is_empty() {
                removed.push(*ip);
                false
            } else {
                true
            }
        });
        self.v6.retain(|_ip, e| {
            e.conns.remove(network);
            !e.conns.is_empty()
        });
        removed
    }

    /// The identity + IP of every peer we currently share `network` with.
    pub fn peers_for_network(&self, network: &str) -> Vec<(EndpointId, Ipv4Addr)> {
        self.v4
            .iter()
            .filter(|e| e.conns.contains_key(network))
            .map(|e| (e.endpoint_id, *e.key()))
            .collect()
    }

    /// Like [`peers_for_network`](Self::peers_for_network) but also yields that
    /// network's connection per peer (e.g. for per-network control broadcasts).
    pub fn peers_for_network_with_conn(
        &self,
        network: &str,
    ) -> Vec<(EndpointId, Ipv4Addr, Connection)> {
        self.v4
            .iter()
            .filter_map(|e| {
                e.conns
                    .get(network)
                    .map(|c| (e.endpoint_id, *e.key(), c.clone()))
            })
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
