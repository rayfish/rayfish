use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashSet;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use smol_str::SmolStr;

use crate::audit::AuditLog;
use crate::membership;

/// Monotonic base for per-connection activity timestamps. Activity is stored as
/// milliseconds since this instant in a plain `AtomicU64` (cheap to bump on the
/// hot path); the idle reaper compares against [`now_ms`].
static ACTIVITY_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Milliseconds since [`ACTIVITY_EPOCH`]. Wraps far past any process lifetime.
fn now_ms() -> u64 {
    ACTIVITY_EPOCH.elapsed().as_millis() as u64
}

/// Whether a connection last active at `last_active` (ms) is idle for at least
/// `idle_ms` as of `now` (ms). Age-based (`now - last_active >= idle_ms`) so a
/// just-booted process, where `now` itself is smaller than `idle_ms`, never
/// reports a peer idle before it could possibly have been.
fn is_idle(now: u64, last_active: u64, idle_ms: u64) -> bool {
    now.saturating_sub(last_active) >= idle_ms
}

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
    /// Peers whose last mesh dial failed on the ALPN version gate (they run an
    /// incompatible mesh protocol). Node-wide: the mesh version is a per-node
    /// property, not per-network. Set by the dialer on an ALPN-mismatch failure,
    /// cleared automatically in [`Self::add`] on any successful (re)connection.
    /// `ray status` reads it to flag such peers instead of showing plain offline.
    version_incompatible: Arc<DashSet<EndpointId>>,
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
    /// Milliseconds ([`now_ms`]) of the last traffic on this connection in either
    /// direction (data or control). The on-demand idle reaper closes connections
    /// whose last activity is older than the idle timeout. Shared as an `Arc` so the
    /// hot send path can bump it via a cloned handle on [`PeerRoute`].
    last_active: Arc<AtomicU64>,
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
    /// Shared last-activity clock for this peer's connection; the sender bumps it
    /// after a successful send so the idle reaper sees the connection as active.
    last_active: Arc<AtomicU64>,
}

impl PeerRoute {
    /// Record that traffic just went out on this connection (resets its idle timer).
    pub fn note_activity(&self) {
        self.last_active.store(now_ms(), Ordering::Relaxed);
    }
}

/// Whether installing a connection with stable id `incoming` as a peer's data
/// connection makes the stored connection newly current — so a fresh
/// [`forward::spawn_peer_reader`](crate::forward::spawn_peer_reader) must be
/// started for it. A peer with no prior entry (`prior == None`) is always new; an
/// existing peer is new only when its stored connection's stable id differs (a
/// reconnect installed a different QUIC connection). Same id means a refresh of
/// the already-read live connection, so no new reader.
///
/// The decision must be taken from the entry's state *before* the add mutates it:
/// seeding a vacant entry with the incoming connection and then comparing would
/// always report "unchanged" and never start the reader.
fn connection_is_new(prior: Option<usize>, incoming: usize) -> bool {
    prior != Some(incoming)
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
            last_active: self.last_active.clone(),
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
            version_incompatible: Arc::new(DashSet::default()),
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
            version_incompatible: Arc::new(DashSet::default()),
        }
    }

    /// Flag `id` as running an incompatible mesh version (its last mesh dial hit
    /// the ALPN gate). Cleared automatically once the peer connects (see
    /// [`Self::add`]) or explicitly via [`Self::clear_incompatible`].
    pub fn mark_incompatible(&self, id: EndpointId) {
        self.version_incompatible.insert(id);
    }

    /// Clear the incompatible flag for `id` (e.g. a later dial failed for a
    /// different reason, so we can no longer attribute it to the version gate).
    pub fn clear_incompatible(&self, id: &EndpointId) {
        self.version_incompatible.remove(id);
    }

    /// Whether `id`'s last mesh dial failed on the version gate.
    pub fn is_incompatible(&self, id: &EndpointId) -> bool {
        self.version_incompatible.contains(id)
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
        // Whether the peer had no prior entry at all (drives the audit connect
        // event) and whether the stored connection just became current (tells the
        // dial side to drive a fresh control demux, which owns the data reader).
        // Both are read from the entry's state *before* this add mutates it: an
        // `or_insert_with` seeded with the incoming connection would report
        // "unchanged" on a brand-new peer and the demux would never start.
        let first_ever;
        let conn_changed;
        {
            use dashmap::mapref::entry::Entry;
            match self.v4.entry(ip) {
                Entry::Occupied(mut o) => {
                    let e = o.get_mut();
                    first_ever = false;
                    conn_changed = connection_is_new(Some(e.conn.stable_id()), stable);
                    e.endpoint_id = endpoint_id;
                    e.conn = conn.clone();
                    e.networks.insert(net.clone());
                    if !e.out_handles.contains_key(&net) {
                        let h = next_free_handle(&e.out_handles);
                        e.out_handles.insert(net.clone(), h);
                    }
                    // Registering a (re)connection counts as activity, so a fresh
                    // link isn't immediately reaped as idle.
                    e.last_active.store(now_ms(), Ordering::Relaxed);
                }
                Entry::Vacant(v) => {
                    first_ever = true;
                    conn_changed = connection_is_new(None, stable);
                    v.insert(first_conn_placeholder(
                        endpoint_id,
                        conn.clone(),
                        net.clone(),
                    ));
                }
            }
        }
        {
            let mut e = self
                .v6
                .entry(ipv6)
                .or_insert_with(|| first_conn_placeholder(endpoint_id, conn.clone(), net.clone()));
            e.endpoint_id = endpoint_id;
            e.conn = conn.clone();
            e.networks.insert(net.clone());
            if !e.out_handles.contains_key(&net) {
                let h = next_free_handle(&e.out_handles);
                e.out_handles.insert(net.clone(), h);
            }
        }
        self.by_id.insert(endpoint_id, ip);
        // A live connection just formed, so any prior version-incompatibility flag
        // is stale (the peer was updated / the ALPN now matches).
        self.version_incompatible.remove(&endpoint_id);
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

    /// Record inbound traffic from `peer_id`, resetting its connection's idle timer.
    /// Called by the per-connection data reader and control demux (which know only
    /// the QUIC remote id) on every frame, so a connection carrying only control
    /// traffic isn't reaped mid-exchange.
    pub fn note_activity_by_id(&self, peer_id: &EndpointId) {
        if let Some(ip) = self.by_id.get(peer_id).map(|e| *e.value())
            && let Some(e) = self.v4.get(&ip)
        {
            e.last_active.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// Peers whose connection has seen no traffic for at least `idle` — candidates
    /// for on-demand teardown. Returns `(ipv4, ipv6, stable_id)`; the reaper closes
    /// each via [`take_if_idle`](Self::take_if_idle), which re-checks under a lock so
    /// a send or reconnect between the scan and the close can't lose a live link.
    pub fn idle_candidates(&self, idle: Duration) -> Vec<(Ipv4Addr, Ipv6Addr, usize)> {
        let idle_ms = idle.as_millis() as u64;
        let now = now_ms();
        self.v4
            .iter()
            .filter(|e| is_idle(now, e.last_active.load(Ordering::Relaxed), idle_ms))
            .map(|e| {
                (
                    *e.key(),
                    membership::derive_ipv6(&e.endpoint_id),
                    e.conn.stable_id(),
                )
            })
            .collect()
    }

    /// Remove the peer at `ip` and return its connection to close, but only if its
    /// stored connection is still `stable_id` and still idle past `idle` — an atomic
    /// re-check that guards against a send that bumped activity, or a reconnect that
    /// installed a fresh connection, since the reaper's scan. `None` leaves the entry
    /// untouched.
    pub fn take_if_idle(
        &self,
        ip: &Ipv4Addr,
        ipv6: &Ipv6Addr,
        stable_id: usize,
        idle: Duration,
    ) -> Option<Connection> {
        let idle_ms = idle.as_millis() as u64;
        let now = now_ms();
        let (_, entry) = self.v4.remove_if(ip, |_, e| {
            e.conn.stable_id() == stable_id
                && is_idle(now, e.last_active.load(Ordering::Relaxed), idle_ms)
        })?;
        self.v6.remove(ipv6);
        self.by_id.remove(&entry.endpoint_id);
        if let Some(audit) = &self.audit {
            audit.log_disconnect(*ip, &entry.endpoint_id.to_string());
        }
        Some(entry.conn)
    }

    /// Resolve an inbound datagram from `peer_id` tagged with `handle` to the
    /// peer's mesh IPv4 and its arrival network, enforcing the in-band
    /// reachability wall in one lock pass: returns `Some` only when the peer is
    /// known, the handle maps to a network the peer announced, **and** our own
    /// shared-network set with this peer currently contains that network. An
    /// unknown peer/handle or a network we don't share drops the datagram
    /// (`None`).
    pub fn resolve_inbound_by_id(
        &self,
        peer_id: &EndpointId,
        handle: u16,
    ) -> Option<(Ipv4Addr, SmolStr)> {
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
        self.v4
            .get(ip)
            .and_then(|e| e.in_handles.get(&handle).cloned())
    }

    /// IPv6 counterpart of [`inbound_network_v4`](Self::inbound_network_v4).
    pub fn inbound_network_v6(&self, ip: &Ipv6Addr, handle: u16) -> Option<SmolStr> {
        self.v6
            .get(ip)
            .and_then(|e| e.in_handles.get(&handle).cloned())
    }

    /// Replace a peer's inbound decode table from its announced `NetworkHandles`.
    /// `entries` is `(handle, network)` pairs. Applied to both address maps.
    pub fn set_inbound_handles(&self, ip: &Ipv4Addr, ipv6: &Ipv6Addr, entries: &[(u16, SmolStr)]) {
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
        self.v4
            .get(ip)
            .and_then(|e| e.out_handles.get(network).copied())
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
        let ipv6 = membership::derive_ipv6(peer_id);
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

    /// Drop the peer identified by its transport `peer_id` from `network`. Used by
    /// the in-band `ControlMsg::LeaveNetwork` handler, which knows the connection's
    /// authenticated remote id but not the sender's (possibly collision-suffixed)
    /// roster IP. Same contract as [`remove_peer_from_network`]: returns the
    /// connection iff this removed the peer's last shared network (so the caller can
    /// close the now-unused link); `None` otherwise or if the id is unknown. Keys
    /// off the entry's stored `endpoint_id` for both maps, so no address derivation
    /// is needed.
    pub fn remove_peer_from_network_by_id(
        &self,
        peer_id: &EndpointId,
        network: &str,
    ) -> Option<Connection> {
        let ip = *self.by_id.get(peer_id)?.value();
        let mut last_conn = None;
        let mut dropped = false;
        if let Some(mut e) = self.v4.get_mut(&ip) {
            e.networks.remove(network);
            e.out_handles.remove(network);
            if e.networks.is_empty() {
                last_conn = Some(e.conn.clone());
                dropped = true;
            }
        }
        self.v4.remove_if(&ip, |_, e| e.networks.is_empty());
        // The v6 entry is keyed separately (by the peer's `200::/7` address); find
        // it by the same stored endpoint id and drop the network there too.
        let v6_key = self
            .v6
            .iter()
            .find(|e| e.endpoint_id == *peer_id)
            .map(|e| *e.key());
        if let Some(k) = v6_key {
            if let Some(mut e) = self.v6.get_mut(&k) {
                e.networks.remove(network);
                e.out_handles.remove(network);
            }
            self.v6.remove_if(&k, |_, e| e.networks.is_empty());
        }
        if dropped {
            self.by_id.remove(peer_id);
            if let Some(audit) = &self.audit {
                audit.log_disconnect(ip, &peer_id.to_string());
            }
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
        self.v4.iter().map(|e| (*e.key(), e.conn.clone())).collect()
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
                // A peer losing its last shared network is a full disconnect, so
                // audit it here too (matching `remove`/`remove_peer_from_network`);
                // the audit contract is one `disconnect` per peer that fully drops.
                if let Some(audit) = &self.audit {
                    audit.log_disconnect(*ip, &e.endpoint_id.to_string());
                }
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

/// A known roster member and the networks we share with it, resolvable by mesh IP
/// **without** a live connection. Returned by [`RosterRouteMap::resolve_v4`] so the
/// forwarding loop can turn a destination IP into the peer identity to lazily dial.
#[derive(Clone, Debug)]
pub struct RouteTarget {
    pub endpoint_id: EndpointId,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    /// Every network we currently share with this peer (so a lazy dial can
    /// `MeshHello` on each, like a reconnect).
    pub networks: Vec<SmolStr>,
}

/// A roster member's addresses + identity, the input unit to
/// [`RosterRouteMap::sync_network`]. Carries only what routing needs (no
/// hostname/roster metadata), built from a `Member` by the caller.
#[derive(Clone, Copy, Debug)]
pub struct RouteMember {
    pub endpoint_id: EndpointId,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

struct RouteEntry {
    endpoint_id: EndpointId,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    networks: HashSet<SmolStr>,
}

impl RouteEntry {
    fn to_target(&self) -> RouteTarget {
        RouteTarget {
            endpoint_id: self.endpoint_id,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            networks: self.networks.iter().cloned().collect(),
        }
    }
}

/// Node-wide map from a peer's stable mesh IP to its identity + shared networks,
/// built from the roster (not from live connections). It exists so an on-demand
/// node, which holds no connections while idle, can still turn an outgoing
/// packet's destination IP into the peer to dial. A peer has one IP across every
/// network it joins, so entries accumulate a per-peer network set; a network's
/// contribution is replaced wholesale on each roster apply (mirroring
/// [`dns::sync_network_hostnames`](crate::dns::sync_network_hostnames)).
///
/// Distinct from [`PeerTable`] on purpose: `PeerTable`'s invariant is "a lookup
/// hit implies a live connection", relied on by the whole data path. This map is
/// the opposite - it lists peers we could reach but currently don't.
#[derive(Clone, Default)]
pub struct RosterRouteMap {
    v4: Arc<FastDashMap<Ipv4Addr, RouteEntry>>,
    v6: Arc<FastDashMap<Ipv6Addr, RouteEntry>>,
}

impl RosterRouteMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace `network`'s contribution with `members`: peers no longer in
    /// `network` lose that membership, and any left sharing no network are dropped.
    /// Peers still reachable via another network keep their entry. Self is excluded
    /// by the caller.
    pub fn sync_network(&self, network: &str, members: &[RouteMember]) {
        let net = SmolStr::new(network);
        let fresh: HashSet<Ipv4Addr> = members.iter().map(|m| m.ipv4).collect();
        // Drop this network from peers that used to be in it but no longer are.
        let stale: Vec<(Ipv4Addr, Ipv6Addr)> = self
            .v4
            .iter()
            .filter(|e| e.networks.contains(&net) && !fresh.contains(e.key()))
            .map(|e| (*e.key(), e.ipv6))
            .collect();
        for (v4, v6) in stale {
            self.drop_network(&v4, &v6, &net);
        }
        // Upsert the current members.
        for m in members {
            self.upsert(m.ipv4, m.ipv6, m.endpoint_id, net.clone());
        }
    }

    fn upsert(&self, ipv4: Ipv4Addr, ipv6: Ipv6Addr, endpoint_id: EndpointId, net: SmolStr) {
        let mut v4 = self.v4.entry(ipv4).or_insert_with(|| RouteEntry {
            endpoint_id,
            ipv4,
            ipv6,
            networks: HashSet::new(),
        });
        v4.endpoint_id = endpoint_id;
        v4.ipv6 = ipv6;
        v4.networks.insert(net.clone());
        drop(v4);
        let mut v6 = self.v6.entry(ipv6).or_insert_with(|| RouteEntry {
            endpoint_id,
            ipv4,
            ipv6,
            networks: HashSet::new(),
        });
        v6.endpoint_id = endpoint_id;
        v6.ipv4 = ipv4;
        v6.networks.insert(net);
    }

    fn drop_network(&self, ipv4: &Ipv4Addr, ipv6: &Ipv6Addr, net: &SmolStr) {
        if let Some(mut e) = self.v4.get_mut(ipv4) {
            e.networks.remove(net);
        }
        self.v4.remove_if(ipv4, |_, e| e.networks.is_empty());
        if let Some(mut e) = self.v6.get_mut(ipv6) {
            e.networks.remove(net);
        }
        self.v6.remove_if(ipv6, |_, e| e.networks.is_empty());
    }

    /// Drop `network` entirely (all its members) from the map. Members still in
    /// another shared network keep their entry.
    pub fn remove_network(&self, network: &str) {
        let net = SmolStr::new(network);
        let affected: Vec<(Ipv4Addr, Ipv6Addr)> = self
            .v4
            .iter()
            .filter(|e| e.networks.contains(&net))
            .map(|e| (*e.key(), e.ipv6))
            .collect();
        for (v4, v6) in affected {
            self.drop_network(&v4, &v6, &net);
        }
    }

    /// Add or refresh a single member's membership in `network` (incremental,
    /// no replace). Used when we connect to a peer, so the map tracks it for a
    /// later idle re-dial before the next full roster sync.
    pub fn sync_add(&self, network: &str, ipv4: Ipv4Addr, ipv6: Ipv6Addr, endpoint_id: EndpointId) {
        self.upsert(ipv4, ipv6, endpoint_id, SmolStr::new(network));
    }

    /// Resolve a destination mesh IPv4 to its roster target, if known.
    pub fn resolve_v4(&self, ip: &Ipv4Addr) -> Option<RouteTarget> {
        self.v4.get(ip).map(|e| e.to_target())
    }

    /// IPv6 counterpart of [`resolve_v4`](Self::resolve_v4).
    pub fn resolve_v6(&self, ip: &Ipv6Addr) -> Option<RouteTarget> {
        self.v6.get(ip).map(|e| e.to_target())
    }
}

/// Per-peer reachability history, decoupled from live connections. The on-demand
/// dialer stamps an outcome on every dial attempt; `ray status` reads it to tell
/// an idle peer (never reached, or last reached fine) from an offline one (a
/// recent reach attempt failed). Also serves as the dialer cooldown so a hard-down
/// peer isn't re-dialed on every dropped packet.
#[derive(Clone, Default)]
pub struct Reachability {
    inner: Arc<FastDashMap<EndpointId, ReachState>>,
}

#[derive(Clone, Copy, Default)]
struct ReachState {
    last_ok: Option<Instant>,
    last_fail: Option<Instant>,
}

impl ReachState {
    /// True when the most recent outcome is a failure no older than `window`.
    fn failing_within(&self, window: Duration) -> bool {
        match self.last_fail {
            Some(f) => f.elapsed() < window && self.last_ok.is_none_or(|ok| ok < f),
            None => false,
        }
    }
}

impl Reachability {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note_ok(&self, id: EndpointId) {
        self.inner.entry(id).or_default().last_ok = Some(Instant::now());
    }

    pub fn note_fail(&self, id: EndpointId) {
        self.inner.entry(id).or_default().last_fail = Some(Instant::now());
    }

    /// Whether the peer counts as offline for status: its most recent reach
    /// attempt failed within `staleness`. A peer never dialed (or last reached
    /// successfully) is not offline; `ray status` renders it idle.
    pub fn is_offline(&self, id: &EndpointId, staleness: Duration) -> bool {
        self.inner
            .get(id)
            .is_some_and(|s| s.failing_within(staleness))
    }
}

/// Build a fresh [`PeerEntry`] for a peer's first shared network. Factored out so
/// the v4/v6 `or_insert_with` closures in [`PeerTable::add`] agree.
fn first_conn_placeholder(endpoint_id: EndpointId, conn: Connection, net: SmolStr) -> PeerEntry {
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
        last_active: Arc::new(AtomicU64::new(now_ms())),
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

    /// Drop a device's mapping so it stops resolving to a user identity. Used by
    /// `ray unpair` to demote a revoked device to a plain peer immediately (its
    /// user's firewall rules and own-device file auto-accept no longer apply).
    pub fn remove(&self, device_key: &EndpointId) {
        self.inner.remove(device_key);
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

    // ---- RosterRouteMap --------------------------------------------------

    fn member(seed: u8) -> RouteMember {
        let id = iroh::SecretKey::from_bytes(&[seed; 32]).public();
        RouteMember {
            endpoint_id: id,
            ipv4: crate::membership::derive_ip(&id),
            ipv6: crate::membership::derive_ipv6(&id),
        }
    }

    #[test]
    fn route_map_sync_resolve_and_shrink() {
        let map = RosterRouteMap::new();
        let a = member(1);
        let b = member(2);
        map.sync_network("net", &[a, b]);

        let ta = map.resolve_v4(&a.ipv4).expect("a resolvable");
        assert_eq!(ta.endpoint_id, a.endpoint_id);
        assert_eq!(ta.networks, vec![SmolStr::new("net")]);
        assert_eq!(
            map.resolve_v6(&b.ipv6).expect("b via v6").endpoint_id,
            b.endpoint_id
        );

        // Re-sync with a shrunk roster: b is gone.
        map.sync_network("net", &[a]);
        assert!(map.resolve_v4(&a.ipv4).is_some());
        assert!(
            map.resolve_v4(&b.ipv4).is_none(),
            "dropped member is unresolvable"
        );
        assert!(map.resolve_v6(&b.ipv6).is_none());
    }

    #[test]
    fn route_map_multi_network_keeps_entry_until_last_network() {
        let map = RosterRouteMap::new();
        let a = member(7);
        map.sync_network("dev", &[a]);
        map.sync_network("db", &[a]);
        let t = map.resolve_v4(&a.ipv4).expect("resolvable");
        let mut nets = t.networks.clone();
        nets.sort();
        assert_eq!(nets, vec![SmolStr::new("db"), SmolStr::new("dev")]);

        // Leaving one network keeps the peer reachable via the other.
        map.remove_network("dev");
        let t = map.resolve_v4(&a.ipv4).expect("still resolvable via db");
        assert_eq!(t.networks, vec![SmolStr::new("db")]);

        // Leaving the last network drops it entirely.
        map.remove_network("db");
        assert!(map.resolve_v4(&a.ipv4).is_none());
    }

    #[test]
    fn route_map_sync_add_is_incremental() {
        let map = RosterRouteMap::new();
        let a = member(3);
        let b = member(4);
        map.sync_network("net", &[a]);
        // Incremental add of b must not drop a (unlike a full sync_network).
        map.sync_add("net", b.ipv4, b.ipv6, b.endpoint_id);
        assert!(map.resolve_v4(&a.ipv4).is_some());
        assert!(map.resolve_v4(&b.ipv4).is_some());
    }

    #[test]
    fn reachability_offline_logic() {
        let r = Reachability::new();
        let id = member(9).endpoint_id;
        // Never dialed: not offline (status renders it idle).
        assert!(!r.is_offline(&id, Duration::from_secs(60)));
        // A failed reach makes it offline within the window.
        r.note_fail(id);
        assert!(r.is_offline(&id, Duration::from_secs(60)));
        // A later success clears it.
        r.note_ok(id);
        assert!(!r.is_offline(&id, Duration::from_secs(60)));
    }

    #[test]
    fn lazy_dial_dedup_via_in_flight_set() {
        // The forwarding loop dedups dials with an in-flight set keyed by peer id.
        let map = RosterRouteMap::new();
        let a = member(11);
        map.sync_network("net", &[a]);
        let in_flight: HashSet<EndpointId> = HashSet::new();
        let mut in_flight = in_flight;

        let t = map.resolve_v4(&a.ipv4).expect("known member resolves");
        // First packet claims the in-flight slot; a duplicate is rejected.
        assert!(in_flight.insert(t.endpoint_id));
        assert!(!in_flight.insert(t.endpoint_id), "duplicate dial is deduped");

        // Unknown destination doesn't resolve, so nothing is dialed.
        assert!(map.resolve_v4(&Ipv4Addr::new(100, 64, 9, 9)).is_none());
    }

    // ---- In-process real-connection tests --------------------------------
    //
    // These build two loopback iroh endpoints (relay + address-lookup disabled)
    // and drive the actual `PeerTable::add` / `forward::spawn_peer_reader` path
    // with genuine `Connection`s, so they catch wiring regressions the pure
    // helpers above can't — notably the bug where a brand-new peer's first `add`
    // reported the connection as "unchanged", so no data reader was ever spawned
    // and every inbound datagram was silently lost.

    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

    const MESH_TEST_ALPN: &[u8] = b"rayfish/test/mesh";

    async fn loopback_endpoint() -> Endpoint {
        Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![MESH_TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind loopback endpoint")
    }

    /// Establish one real mesh connection between two fresh endpoints and return
    /// `(server, client, server_side_conn, client_side_conn)`. `dial` re-uses the
    /// given client to open an additional connection to the same server.
    async fn connected_pair() -> (Endpoint, Endpoint, Connection, Connection) {
        let server = loopback_endpoint().await;
        let client = loopback_endpoint().await;
        let (conn_server, conn_client) = dial(&server, &client).await;
        (server, client, conn_server, conn_client)
    }

    /// Open one more connection from `client` to `server`; returns
    /// `(server_side, client_side)` `Connection`s.
    async fn dial(server: &Endpoint, client: &Endpoint) -> (Connection, Connection) {
        let server_addr: EndpointAddr = server.addr();
        let accept = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("accept connection")
            })
        };
        let conn_client = client
            .connect(server_addr, MESH_TEST_ALPN)
            .await
            .expect("client connect");
        let conn_server = accept.await.expect("accept task");
        (conn_server, conn_client)
    }

    #[tokio::test]
    async fn add_reports_first_connection_as_new_so_reader_spawns() {
        // Regression: the *first* registration of a brand-new peer must return
        // `true` (connection changed) so the dial side drives a fresh control
        // demux (which spawns the single data reader). The old placeholder-seeded
        // check returned `false` here, leaving the peer with no reader -> 100%
        // inbound loss.
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ip = crate::membership::derive_ip(&peer);
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();

        assert!(
            table.add(ip, ipv6, conn.clone(), peer, "n1"),
            "first add of a new peer must report the connection as new"
        );
        // Same connection, a second shared network: one reader already serves it,
        // so this must NOT report a new connection (no duplicate reader).
        assert!(
            !table.add(ip, ipv6, conn.clone(), peer, "n2"),
            "re-adding the same connection for another network must not respawn"
        );
        // Both networks route over the one connection.
        let route = table.lookup_v4(&ip).expect("peer routable");
        assert_eq!(route.conn.stable_id(), conn.stable_id());
    }

    #[tokio::test]
    async fn idle_candidates_and_guarded_take() {
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ip = crate::membership::derive_ip(&peer);
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        assert!(table.add(ip, ipv6, conn.clone(), peer, "n1"));
        let stable = conn.stable_id();

        // With a long idle window the freshly-added peer is not a candidate.
        assert!(
            table.idle_candidates(Duration::from_secs(3600)).is_empty(),
            "a just-registered peer is not idle"
        );
        // With a zero window it is stale immediately.
        let cands = table.idle_candidates(Duration::ZERO);
        assert_eq!(cands, vec![(ip, ipv6, stable)]);

        // A stale-id guard: a mismatched stable id never takes the entry.
        assert!(
            table
                .take_if_idle(&ip, &ipv6, stable.wrapping_add(1), Duration::ZERO)
                .is_none(),
            "a refreshed connection (different stable id) is not torn down"
        );
        assert!(table.lookup_v4(&ip).is_some(), "entry survives the guard");

        // Recorded activity moves it out of the idle set (bump then re-check).
        let route = table.lookup_v4(&ip).unwrap();
        route.note_activity();
        assert!(
            table
                .take_if_idle(&ip, &ipv6, stable, Duration::from_secs(3600))
                .is_none(),
            "an active connection past the guard window is kept"
        );

        // The matching id + zero window takes and returns the connection to close.
        let taken = table.take_if_idle(&ip, &ipv6, stable, Duration::ZERO);
        assert!(taken.is_some(), "idle entry with matching id is taken");
        assert!(table.lookup_v4(&ip).is_none(), "entry removed after take");
    }

    #[tokio::test]
    async fn add_reports_reconnect_as_new() {
        // A reconnect installs a different QUIC connection (new stable id) to the
        // same peer identity: `add` must report it new so the stale reader is
        // replaced.
        let (server, client, conn1, _c1) = connected_pair().await;
        let peer = conn1.remote_id();
        let ip = crate::membership::derive_ip(&peer);
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        assert!(table.add(ip, ipv6, conn1.clone(), peer, "n1"));

        // Second, distinct connection to the same server identity.
        let (conn2, _c2) = dial(&server, &client).await;
        assert_ne!(conn1.stable_id(), conn2.stable_id(), "distinct connections");
        assert!(
            table.add(ip, ipv6, conn2.clone(), peer, "n1"),
            "a reconnect (different connection) must report the connection as new"
        );
    }

    #[tokio::test]
    async fn peer_reader_delivers_inbound_datagram_to_tun() {
        use crate::firewall::{FirewallConfig, SharedFirewall};
        use crate::forward::{ForwardCtx, spawn_peer_reader, tag_datagram};
        use crate::stats::ForwardMetrics;
        use bytes::Bytes;
        use std::time::Duration;
        use tokio::sync::mpsc;
        use tokio_util::sync::CancellationToken;

        // R receives, S sends. Establish a real connection; `conn_r` is R's side.
        let (_srv, _cli, conn_r, conn_s) = connected_pair().await;
        let s_id = conn_r.remote_id();
        let s_ip = crate::membership::derive_ip(&s_id);
        let s_ipv6 = crate::membership::derive_ipv6(&s_id);
        let r_ip = crate::membership::derive_ip(&conn_s.remote_id());

        // Register S in R's table for "net" and teach R that S's tag 1 = "net".
        let peers = PeerTable::new();
        peers.add(s_ip, s_ipv6, conn_r.clone(), s_id, "net");
        peers.add_inbound_handle_by_id(&s_id, 1, SmolStr::new("net"));

        let (tun_tx, mut tun_rx) = mpsc::channel::<Bytes>(8);
        let ctx = ForwardCtx {
            firewall: SharedFirewall::new(FirewallConfig::default()),
            tun_tx: Arc::new(arc_swap::ArcSwap::new(Arc::new(tun_tx))),
            token: CancellationToken::new(),
            stats: Arc::new(ForwardMetrics::default()),
            device_user_map: DeviceUserMap::new(),
        };
        spawn_peer_reader(conn_r.clone(), s_id, peers.clone(), ctx);

        // S sends a tagged ICMP echo from its own mesh IP: default firewall
        // allows inbound ICMP, and the source matches S's assigned IP so the
        // anti-spoof check passes. The reader must untag, resolve the network via
        // the handle, and write the raw IP packet (tag stripped) to the TUN.
        let icmp = icmp_echo_packet(s_ip, r_ip);
        conn_s
            .send_datagram(tag_datagram(1, &icmp))
            .expect("send datagram");

        let got = tokio::time::timeout(Duration::from_secs(5), tun_rx.recv())
            .await
            .expect("reader forwarded a datagram before timeout")
            .expect("tun channel stayed open");
        assert_eq!(
            &got[..],
            &icmp[..],
            "TUN packet must be the untagged IP packet"
        );
    }

    /// Minimal IPv4/ICMP echo-request packet from `src` to `dst`, enough for
    /// `firewall::parse_packet_info` (version/IHL, protocol 1, src/dst) and the
    /// seeded inbound `allow icmp` rule.
    fn icmp_echo_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45; // IPv4, IHL=5
        p[3] = 28; // total length
        p[9] = 1; // ICMP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20] = 8; // ICMP type = echo request
        p
    }

    #[test]
    fn connection_is_new_starts_reader_for_brand_new_peer() {
        // A peer with no prior entry: `add` must report the connection as new so
        // the dial side drives a fresh control demux (which spawns the data
        // reader). Regression for the bug where a placeholder seeded with the
        // incoming connection made a first-ever add report "unchanged", leaving
        // the peer with no reader and 100% inbound loss.
        assert!(connection_is_new(None, 7));
    }

    #[test]
    fn connection_is_new_false_when_same_connection_refreshed() {
        // Re-adding the same live connection (e.g. a second shared network over the
        // one connection) must not spawn a duplicate reader.
        assert!(!connection_is_new(Some(7), 7));
    }

    #[test]
    fn connection_is_new_true_on_reconnect_to_different_connection() {
        // A reconnect installs a different QUIC connection (new stable id): the
        // stale reader is gone, so a fresh one must start.
        assert!(connection_is_new(Some(7), 8));
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
