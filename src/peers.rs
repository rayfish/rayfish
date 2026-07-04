use std::collections::{HashMap, HashSet};
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
/// There is a single `PeerTable` for the whole daemon, not one per network. A
/// peer is reachable iff we share at least one network with it. Since the
/// transport now uses a single mesh ALPN, a peer has exactly **one** QUIC
/// connection regardless of how many networks it shares with us — [`PeerEntry`]
/// holds that connection plus the *set* of networks it carries. Datagrams over
/// the shared connection are tagged with a small per-connection network handle
/// (see [`PeerEntry::out_handles`]/[`in_handles`](PeerEntry::in_handles)) so the
/// receiver can recover which network each datagram belongs to.
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
    /// Endpoint id → the peer's mesh IPv4 (its `v4`/`v6` key). Lets the
    /// per-connection data reader resolve a peer's mesh addresses from the QUIC
    /// remote id alone — the reader is spawned when the connection opens, before
    /// the join handshake assigns the peer's (possibly collision-suffixed) roster
    /// IP, so it can't be handed the IP up front.
    by_id: Arc<FastDashMap<EndpointId, Ipv4Addr>>,
    /// Optional append-only audit log. When present, registering a peer's first
    /// connection logs a `connect` event and dropping its last shared network
    /// logs a `disconnect` event. `None` in tests.
    audit: Option<Arc<AuditLog>>,
}

/// A single peer's identity, its one shared connection, and the networks that
/// connection carries.
///
/// A peer has one virtual IP (derived from its identity, stable across every
/// network it joins) and one QUIC connection (single mesh ALPN). Reachability is
/// "we share at least one network", tracked by `networks`. The connection
/// multiplexes all shared networks; each datagram is prefixed with a `u16`
/// handle identifying its network.
pub struct PeerEntry {
    pub endpoint_id: EndpointId,
    /// The single shared connection to this peer.
    conn: Connection,
    /// Networks we currently share with this peer over `conn`.
    networks: HashSet<SmolStr>,
    /// Outbound tag table: network → the `u16` handle *we* stamp on datagrams we
    /// send to this peer for that network. We own this namespace and announce it
    /// to the peer (it becomes the peer's inbound decode table). Handle `0` is
    /// reserved as invalid, so assigned handles start at `1`.
    out_handles: HashMap<SmolStr, u16>,
    /// Inbound decode table: handle → network, taken from the peer's announced
    /// `NetworkHandles`. Used to resolve which network an inbound datagram from
    /// this peer belongs to.
    in_handles: HashMap<u16, SmolStr>,
}

/// Result of a routing lookup: the connection to send over, the peer identity,
/// the network the packet is attributed to (firewall context), and the outbound
/// handle to tag the datagram with.
pub struct PeerRoute {
    pub conn: Connection,
    pub endpoint_id: EndpointId,
    /// The network the outbound packet is attributed to (firewall context). A
    /// multi-homed peer has one IP, so an IP packet carries no network by itself;
    /// this is the deterministic pick (lexically-smallest shared network).
    pub network: SmolStr,
    /// The outbound datagram tag for `network` on this connection.
    pub handle: u16,
}

/// Lowest free handle (≥ 1; `0` is reserved as "invalid") not already assigned
/// in `used`.
fn next_free_handle(used: &HashMap<SmolStr, u16>) -> u16 {
    let taken: HashSet<u16> = used.values().copied().collect();
    (1u16..=u16::MAX)
        .find(|h| !taken.contains(h))
        .unwrap_or(u16::MAX)
}

impl PeerEntry {
    /// Picks the network a packet to this peer is attributed to (lexically
    /// smallest shared network) so routing/firewall context is stable across
    /// lookups, and returns the connection + that network's outbound handle.
    fn route(&self) -> Option<PeerRoute> {
        let network = self.networks.iter().min()?.clone();
        let handle = self.out_handles.get(&network).copied().unwrap_or(0);
        Some(PeerRoute {
            conn: self.conn.clone(),
            endpoint_id: self.endpoint_id,
            network,
            handle,
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
            by_id: Arc::new(FastDashMap::default()),
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
            by_id: Arc::new(FastDashMap::default()),
            audit: Some(audit),
        }
    }

    /// Registers the peer's shared connection and records that we share
    /// `network` with it. The connection is per-identity: if the peer already
    /// has an entry, `network` is unioned into its set and the stored connection
    /// is refreshed to `conn` (reconnect installs the fresh one; a same-identity
    /// re-add over the live connection is a no-op replace). Assigns an outbound
    /// handle for `network` if one isn't already held.
    ///
    /// Returns `true` if `conn` is genuinely new to the peer (first shared
    /// network, or a reconnect that replaced a different connection) — the
    /// caller uses this to decide whether to (re)announce the handle table.
    pub fn add(
        &self,
        ip: Ipv4Addr,
        ipv6: Ipv6Addr,
        conn: Connection,
        endpoint_id: EndpointId,
        network: &str,
    ) -> bool {
        let net = SmolStr::new(network);
        let stable = conn.stable_id();
        // Whether the peer had no prior connection at all (drives audit connect).
        let first_ever;
        // Whether the stored connection is (now) `conn` but wasn't before.
        let conn_changed;
        {
            let mut e = self.v4.entry(ip).or_insert_with(|| {
                first_conn_placeholder(endpoint_id, conn.clone(), net.clone())
            });
            first_ever = e.networks.is_empty();
            conn_changed = e.conn.stable_id() != stable || first_ever;
            e.endpoint_id = endpoint_id;
            e.conn = conn.clone();
            e.networks.insert(net.clone());
            if !e.out_handles.contains_key(&net) {
                let h = next_free_handle(&e.out_handles);
                e.out_handles.insert(net.clone(), h);
            }
        }
        {
            let mut e = self.v6.entry(ipv6).or_insert_with(|| {
                first_conn_placeholder(endpoint_id, conn.clone(), net.clone())
            });
            e.endpoint_id = endpoint_id;
            e.conn = conn.clone();
            e.networks.insert(net.clone());
            if !e.out_handles.contains_key(&net) {
                let h = next_free_handle(&e.out_handles);
                e.out_handles.insert(net.clone(), h);
            }
        }
        self.by_id.insert(endpoint_id, ip);
        if first_ever && let Some(audit) = &self.audit {
            audit.log_connect(ip, &endpoint_id.to_string());
        }
        conn_changed
    }

    /// The peer's mesh IPv4, resolved from its endpoint id. Used by the
    /// per-connection data reader (which knows only the QUIC remote id) to find
    /// the peer's routing entry. `None` until the peer is registered by the join
    /// handshake.
    pub fn v4_for_id(&self, peer_id: &EndpointId) -> Option<Ipv4Addr> {
        self.by_id.get(peer_id).map(|e| *e.value())
    }

    /// Resolve an inbound datagram from `peer_id` tagged with `handle` to the
    /// peer's mesh IPv4 and its arrival network, enforcing the in-band
    /// reachability wall in one lock pass: returns `Some` only when the peer is
    /// known, the handle maps to a network the peer announced, **and** our own
    /// shared-network set with this peer currently contains that network. An
    /// unknown peer/handle or a network we don't share drops the datagram
    /// (`None`).
    pub fn resolve_inbound_by_id(&self, peer_id: &EndpointId, handle: u16) -> Option<(Ipv4Addr, SmolStr)> {
        let ip = *self.by_id.get(peer_id)?.value();
        let e = self.v4.get(&ip)?;
        let network = e.in_handles.get(&handle)?;
        if !e.networks.contains(network) {
            return None;
        }
        Some((ip, network.clone()))
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

    /// Resolve the network an inbound datagram belongs to from the peer's mesh
    /// IPv4 and the `u16` handle the peer stamped on it (looked up in the peer's
    /// announced inbound table). `None` if the peer or handle is unknown.
    pub fn inbound_network_v4(&self, ip: &Ipv4Addr, handle: u16) -> Option<SmolStr> {
        self.v4.get(ip).and_then(|e| e.in_handles.get(&handle).cloned())
    }

    /// IPv6 counterpart of [`inbound_network_v4`](Self::inbound_network_v4).
    pub fn inbound_network_v6(&self, ip: &Ipv6Addr, handle: u16) -> Option<SmolStr> {
        self.v6.get(ip).and_then(|e| e.in_handles.get(&handle).cloned())
    }

    /// Replace a peer's inbound decode table from its announced `NetworkHandles`.
    /// `entries` is `(handle, network)` pairs. Applied to both address maps.
    pub fn set_inbound_handles(
        &self,
        ip: &Ipv4Addr,
        ipv6: &Ipv6Addr,
        entries: &[(u16, SmolStr)],
    ) {
        let table: HashMap<u16, SmolStr> = entries.iter().cloned().collect();
        if let Some(mut e) = self.v4.get_mut(ip) {
            e.in_handles = table.clone();
        }
        if let Some(mut e) = self.v6.get_mut(ipv6) {
            e.in_handles = table;
        }
    }

    /// Our outbound handle table for a peer as `(network, handle)` pairs, to send
    /// the peer in a `NetworkHandles` announcement (the peer stores it as its
    /// inbound decode table).
    pub fn outbound_handles(&self, ip: &Ipv4Addr) -> Vec<(SmolStr, u16)> {
        self.v4
            .get(ip)
            .map(|e| e.out_handles.iter().map(|(n, h)| (n.clone(), *h)).collect())
            .unwrap_or_default()
    }

    /// The `u16` handle we stamp on datagrams to `ip` for `network`, if assigned.
    /// Used to announce a single network's handle to the peer after we start
    /// sharing it (the announcement is per-network, not a full snapshot, so
    /// networks are added to the peer's decode table incrementally).
    pub fn out_handle(&self, ip: &Ipv4Addr, network: &str) -> Option<u16> {
        self.v4.get(ip).and_then(|e| e.out_handles.get(network).copied())
    }

    /// Merge one `(handle → network)` mapping into a peer's inbound decode table,
    /// keyed by the peer's endpoint id. Upsert (not replace), so announcing one
    /// network's handle doesn't clobber the decode entries for the peer's other
    /// shared networks. A stale entry for a network we no longer share is harmless
    /// (the reachability check in `resolve_inbound_by_id` drops its datagrams).
    pub fn add_inbound_handle_by_id(&self, peer_id: &EndpointId, handle: u16, network: SmolStr) {
        let Some(ip) = self.by_id.get(peer_id).map(|e| *e.value()) else {
            return;
        };
        let ipv6 = crate::membership::derive_ipv6(peer_id);
        if let Some(mut e) = self.v4.get_mut(&ip) {
            e.in_handles.insert(handle, network.clone());
        }
        if let Some(mut e) = self.v6.get_mut(&ipv6) {
            e.in_handles.insert(handle, network);
        }
    }

    /// Resolve a peer by its mesh source IP (v4 or v6) to its transport identity
    /// and the set of networks we currently share with it. Used by the embedded
    /// mesh SSH server to authorize an incoming session: the peer is identified by
    /// which mesh IP the TCP connection came from (the ingress anti-spoof check in
    /// `forward.rs` guarantees that IP is the peer's own). Returns `None` if no
    /// peer holds that address.
    pub fn identity_and_networks(&self, ip: IpAddr) -> Option<(EndpointId, Vec<SmolStr>)> {
        match ip {
            IpAddr::V4(v4) => self
                .v4
                .get(&v4)
                .map(|e| (e.endpoint_id, e.networks.iter().cloned().collect())),
            IpAddr::V6(v6) => self
                .v6
                .get(&v6)
                .map(|e| (e.endpoint_id, e.networks.iter().cloned().collect())),
        }
    }

    /// True if we currently share `network` with the peer at mesh IPv4 `ip`. The
    /// in-band reachability check for inbound datagrams: a datagram tagged for a
    /// network we don't share with this peer is dropped.
    pub fn shares_network_v4(&self, ip: &Ipv4Addr, network: &str) -> bool {
        self.v4
            .get(ip)
            .map(|e| e.networks.contains(network))
            .unwrap_or(false)
    }

    /// IPv6 counterpart of [`shares_network_v4`](Self::shares_network_v4).
    pub fn shares_network_v6(&self, ip: &Ipv6Addr, network: &str) -> bool {
        self.v6
            .get(ip)
            .map(|e| e.networks.contains(network))
            .unwrap_or(false)
    }

    /// The shared connection to a peer identified by mesh IPv4, if any.
    pub fn conn_for_ip(&self, ip: &Ipv4Addr) -> Option<Connection> {
        self.v4.get(ip).map(|e| e.conn.clone())
    }

    /// Removes the peer entirely (all networks + connection). Used for identity
    /// rotation and full roster removal.
    pub fn remove(&self, ip: &Ipv4Addr, ipv6: &Ipv6Addr) {
        let removed = self.v4.remove(ip);
        self.v6.remove(ipv6);
        if let Some((_, entry)) = &removed {
            self.by_id.remove(&entry.endpoint_id);
        }
        if let (Some((_, entry)), Some(audit)) = (removed, &self.audit) {
            audit.log_disconnect(*ip, &entry.endpoint_id.to_string());
        }
    }

    /// Stops sharing `network` with a peer. The peer entry (and its connection)
    /// is dropped only once it shares no network at all — so losing the `dev`
    /// membership doesn't unroute a peer still reachable via `db`. Returns the
    /// peer's connection **iff** this removed its last shared network (so the
    /// caller can close the now-unused connection); `None` otherwise.
    pub fn remove_peer_from_network(
        &self,
        ip: &Ipv4Addr,
        ipv6: &Ipv6Addr,
        network: &str,
    ) -> Option<Connection> {
        let mut last_conn = None;
        let mut dropped_id = None;
        if let Some(mut e) = self.v4.get_mut(ip) {
            e.networks.remove(network);
            e.out_handles.remove(network);
            if e.networks.is_empty() {
                last_conn = Some(e.conn.clone());
                dropped_id = Some(e.endpoint_id);
            }
        }
        self.v4.remove_if(ip, |_, e| e.networks.is_empty());
        if let Some(mut e) = self.v6.get_mut(ipv6) {
            e.networks.remove(network);
            e.out_handles.remove(network);
        }
        self.v6.remove_if(ipv6, |_, e| e.networks.is_empty());
        if let Some(endpoint_id) = dropped_id {
            self.by_id.remove(&endpoint_id);
        }
        if let (Some(endpoint_id), Some(audit)) = (dropped_id, &self.audit) {
            audit.log_disconnect(*ip, &endpoint_id.to_string());
        }
        last_conn
    }

    /// Connection-aware variant of [`remove_peer_from_network`]: drops the
    /// peer's membership in `network` only if the connection currently stored is
    /// the same one identified by `stable_id`. Returns the connection iff this
    /// removed the peer's last shared network (same contract as
    /// [`remove_peer_from_network`]); `None` if it did not act (stale connection)
    /// or other networks remain.
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
    ) -> Option<Connection> {
        // Read-and-compare in its own statement so the DashMap read guard is
        // dropped before remove_peer_from_network takes a write guard on the
        // same shard.
        let matches = self
            .v4
            .get(ip)
            .map(|e| e.networks.contains(network) && e.conn.stable_id() == stable_id)
            .unwrap_or(false);
        if !matches {
            return None;
        }
        self.remove_peer_from_network(ip, ipv6, network)
    }

    /// True if the stored connection for the peer at `ip` is the one identified
    /// by `stable_id`. Lets a disconnect consumer tell a live connection from a
    /// stale one before acting on a whole-peer removal.
    pub fn conn_is_current(&self, ip: &Ipv4Addr, stable_id: usize) -> bool {
        self.v4
            .get(ip)
            .map(|e| e.conn.stable_id() == stable_id)
            .unwrap_or(false)
    }

    /// One connection per peer, for global broadcasts.
    pub fn all_connections(&self) -> Vec<(Ipv4Addr, Connection)> {
        self.v4
            .iter()
            .map(|e| (*e.key(), e.conn.clone()))
            .collect()
    }

    /// Stops sharing `network` with every peer. Returns the IPs of peers left
    /// sharing no network (fully removed), each paired with its connection so the
    /// caller can close links that are now entirely unused.
    pub fn remove_by_network(&self, network: &str) -> Vec<(Ipv4Addr, Connection)> {
        let mut removed = Vec::new();
        self.v4.retain(|ip, e| {
            e.networks.remove(network);
            e.out_handles.remove(network);
            if e.networks.is_empty() {
                removed.push((*ip, e.conn.clone()));
                self.by_id.remove(&e.endpoint_id);
                false
            } else {
                true
            }
        });
        self.v6.retain(|_ip, e| {
            e.networks.remove(network);
            e.out_handles.remove(network);
            !e.networks.is_empty()
        });
        removed
    }

    /// The identity + IP of every peer we currently share `network` with.
    pub fn peers_for_network(&self, network: &str) -> Vec<(EndpointId, Ipv4Addr)> {
        self.v4
            .iter()
            .filter(|e| e.networks.contains(network))
            .map(|e| (e.endpoint_id, *e.key()))
            .collect()
    }

    /// Like [`peers_for_network`](Self::peers_for_network) but also yields the
    /// peer's shared connection (e.g. for per-network control broadcasts). Since
    /// the connection is per-identity, the returned connection carries every
    /// network that peer shares, not just `network`.
    pub fn peers_for_network_with_conn(
        &self,
        network: &str,
    ) -> Vec<(EndpointId, Ipv4Addr, Connection)> {
        self.v4
            .iter()
            .filter(|e| e.networks.contains(network))
            .map(|e| (e.endpoint_id, *e.key(), e.conn.clone()))
            .collect()
    }

    #[cfg(test)]
    pub fn all_peer_ids(&self) -> Vec<(Ipv4Addr, EndpointId)> {
        self.v4.iter().map(|e| (*e.key(), e.endpoint_id)).collect()
    }
}

/// Build a fresh [`PeerEntry`] for a peer's first shared network. Factored out so
/// the v4/v6 `or_insert_with` closures in [`PeerTable::add`] agree.
fn first_conn_placeholder(
    endpoint_id: EndpointId,
    conn: Connection,
    net: SmolStr,
) -> PeerEntry {
    let mut out_handles = HashMap::new();
    out_handles.insert(net.clone(), 1u16);
    let mut networks = HashSet::new();
    networks.insert(net);
    PeerEntry {
        endpoint_id,
        conn,
        networks,
        out_handles,
        in_handles: HashMap::new(),
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

    #[test]
    fn next_free_handle_skips_zero_and_taken() {
        let mut used = HashMap::new();
        assert_eq!(next_free_handle(&used), 1);
        used.insert(SmolStr::new("a"), 1u16);
        used.insert(SmolStr::new("b"), 2u16);
        assert_eq!(next_free_handle(&used), 3);
        used.insert(SmolStr::new("d"), 4u16);
        // 3 is free even though 4 is taken.
        assert_eq!(next_free_handle(&used), 3);
    }
}
