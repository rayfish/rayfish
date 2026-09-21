use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashSet;
use iroh::EndpointId;
use iroh::endpoint::{Connection, VarInt};
use smol_str::SmolStr;

use crate::audit::AuditLog;
use crate::membership;

mod device_user_map;
mod reachability;
mod roster_routes;

pub use device_user_map::DeviceUserMap;
pub use reachability::Reachability;
pub use roster_routes::{RosterRouteMap, RouteMember, RouteTarget};

#[cfg(test)]
use std::collections::HashSet;

/// Monotonic base for per-connection activity timestamps. Activity is stored as
/// milliseconds since this instant in a plain `AtomicU64` (cheap to bump on the
/// hot path); the idle reaper compares against [`now_ms`].
static ACTIVITY_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Milliseconds since [`ACTIVITY_EPOCH`]. Wraps far past any process lifetime.
fn now_ms() -> u64 {
    ACTIVITY_EPOCH.elapsed().as_millis() as u64
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
/// holds that connection plus the set of networks encoded in its outbound-handle
/// map. Datagrams over
/// the shared connection are tagged with a small per-connection network handle
/// The outbound handles stay with the peer, while the inbound handles belong to
/// the active connection. Together they let the receiver recover which network
/// each datagram belongs to.
///
/// Backed by [`FastDashMap`] for lock-free concurrent reads from the forwarding hot
/// path while accept/reconnect tasks mutate it; cloning the table is cheap
/// (shared `Arc`s), so it is handed to every per-network task by value.
#[derive(Clone)]
pub struct PeerTable {
    /// Mesh IPv6 to peer. The only key: a peer's `200::/7` address is
    /// [`membership::derive_ipv6`] of its `EndpointId`, so an id resolves to its
    /// key with a hash and no side table. That is why the per-connection data
    /// reader needs nothing handed to it at spawn time: it knows the QUIC remote
    /// id, which is the address.
    peers: Arc<FastDashMap<Ipv6Addr, PeerEntry>>,
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
    /// Actual local TUN limit, shared with readers across TUN reattachments.
    local_mtu: Arc<AtomicU16>,
}

/// A single peer's identity, its one shared connection, and the network-handle
/// maps that connection carries.
///
/// A peer has one virtual IP (derived from its identity, stable across every
/// network it joins) and one QUIC connection (single mesh ALPN). Reachability is
/// "we share at least one network", tracked by `out_handles`. The connection
/// multiplexes all shared networks; each datagram is prefixed with a `u16`
/// handle identifying its network.
pub struct PeerEntry {
    pub endpoint_id: EndpointId,
    /// Outbound tag table: network → the `u16` handle *we* stamp on datagrams we
    /// send to this peer for that network. We own this namespace and announce it
    /// to the peer (it becomes the peer's inbound decode table). Its keys are also
    /// the source of truth for networks currently shared with this peer, avoiding
    /// a separate `HashSet` with duplicate keys. Handle `0` is reserved as invalid,
    /// so assigned handles start at `1`.
    out_handles: HashMap<SmolStr, u16>,
    /// State belonging to the currently selected QUIC connection. Replacing the
    /// connection replaces this whole value, so negotiated state cannot leak
    /// across reconnects.
    active: ActiveConnection,
}

struct ActiveConnection {
    conn: Connection,
    /// Identical at both ends of this TLS session, unlike `stable_id()` which
    /// only identifies a local connection object. Both peers keep the connection
    /// with the lowest ID, regardless of initiator or registration order.
    selection_id: [u8; 32],
    /// Inbound decode table: handle → network, taken from the peer's announced
    /// `NetworkHandles`. Used to resolve which network an inbound datagram from
    /// this peer belongs to.
    in_handles: HashMap<u16, SmolStr>,
    /// Milliseconds ([`now_ms`]) of the last traffic on this connection in either
    /// direction (data or control). The on-demand idle reaper closes connections
    /// whose last activity is older than the idle timeout. Shared as an `Arc` so the
    /// hot send path can bump it via a cloned handle on [`PeerRoute`].
    last_active: Arc<AtomicU64>,
    /// Whether this peer advertised [`transport::FEATURE_IDLE_CLOSE`](crate::transport::FEATURE_IDLE_CLOSE)
    /// in its `MeshHello`. We only idle-close a connection whose peer understands
    /// the idle close code; a peer on a build that predates it (default `false`) is
    /// held open like an eager node so it never flaps.
    supports_idle_close: Arc<AtomicBool>,
    receive_mtu: Arc<AtomicU16>,
}

impl ActiveConnection {
    fn new(conn: Connection) -> Self {
        Self {
            selection_id: connection_selection_id(&conn),
            conn,
            in_handles: HashMap::new(),
            last_active: Arc::new(AtomicU64::new(now_ms())),
            supports_idle_close: Arc::new(AtomicBool::new(false)),
            receive_mtu: Arc::new(AtomicU16::new(crate::tun::MIN_TUN_MTU)),
        }
    }

    fn matches(&self, conn: &Connection) -> bool {
        self.conn.stable_id() == conn.stable_id()
    }
}

/// Domain-separated session identifier for duplicate selection. Called only on
/// registration, never on the packet path. A completed iroh TLS handshake can
/// always export this fixed, small amount of material.
fn connection_selection_id(conn: &Connection) -> [u8; 32] {
    let mut id = [0; 32];
    conn.export_keying_material(&mut id, b"EXPORTER-rayfish-mesh-selection-v1", b"")
        .expect("established TLS session exports a 32-byte connection ID");
    id
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
    receive_mtu: Arc<AtomicU16>,
    /// Shared last-activity clock for this peer's connection; the sender bumps it
    /// after a successful send so the idle reaper sees the connection as active.
    last_active: Arc<AtomicU64>,
}

impl PeerRoute {
    /// The peer's advertised IP packet limit; conservative until it announces.
    pub fn receive_mtu(&self) -> u16 {
        self.receive_mtu.load(Ordering::Relaxed)
    }

    /// Record that traffic just went out on this connection (resets its idle timer).
    pub fn note_activity(&self) {
        self.last_active.store(now_ms(), Ordering::Relaxed);
    }
}

/// Lowest free handle (≥ 1; `0` is reserved as "invalid") not already assigned
/// in `used`.
fn next_free_handle(used: &HashMap<SmolStr, u16>) -> u16 {
    (1u16..=u16::MAX)
        // Network handles change only on membership updates, not in the packet
        // path. Avoid allocating a temporary HashSet for that infrequent work;
        // this preserves the existing "lowest available handle" behavior.
        .find(|h| !used.values().any(|taken| taken == h))
        .unwrap_or(u16::MAX)
}

impl PeerEntry {
    fn new(endpoint_id: EndpointId, conn: Connection, network: SmolStr) -> Self {
        let mut out_handles = HashMap::new();
        out_handles.insert(network, 1);
        Self {
            endpoint_id,
            out_handles,
            active: ActiveConnection::new(conn),
        }
    }

    /// Install `conn` if it differs from the current connection. Connection-level
    /// state is created and replaced as one value so none survives a reconnect.
    ///
    /// The lowest TLS session ID wins. Both ends rank every physical connection
    /// identically even when concurrent handshakes register in opposite orders.
    /// A closed connection never wins over a live replacement.
    fn install_connection(&mut self, conn: &Connection) -> bool {
        if self.active.matches(conn) {
            self.active.last_active.store(now_ms(), Ordering::Relaxed);
            return false;
        }
        if self.active.conn.close_reason().is_none()
            && self.active.selection_id <= connection_selection_id(conn)
        {
            conn.close(
                VarInt::from_u32(crate::forward::REPLACED_CONNECTION_CODE),
                b"noncanonical",
            );
            return false;
        }
        let old = std::mem::replace(&mut self.active, ActiveConnection::new(conn.clone()));
        old.conn.close(
            VarInt::from_u32(crate::forward::REPLACED_CONNECTION_CODE),
            b"replaced",
        );
        true
    }

    /// Picks the network a packet to this peer is attributed to (the lexically
    /// smallest one both ends still share) so routing/firewall context is stable
    /// across lookups, and returns the connection + that network's outbound
    /// handle.
    ///
    /// The pick is taken from the networks the peer *itself* announced a handle
    /// for, not from our shared set alone. The two can disagree: a peer that
    /// left a network while we were the coordinator, or without being able to
    /// tell us, stays in our set for good, since our own roster is the record
    /// nothing else corrects. The peer drops any datagram tagged with a network
    /// it does not share ([`PeerTable::resolve_inbound_by_id`]), so tagging one
    /// black-holes the peer entirely while its `.ray` names keep resolving from
    /// that same stale roster. `in_handles` is the peer's own statement of what
    /// this connection carries and is already on the wire, so preferring it
    /// costs nothing and routes over a network that actually works.
    ///
    /// Falls back to the plain pick when the peer has announced nothing yet (its
    /// `NetworkHandles` is still in flight), which is where every peer starts.
    fn route(&self) -> Option<PeerRoute> {
        // With one shared network there is nothing to choose between: the filter
        // below could only keep it or fall back to it, so the common case pays
        // nothing per packet for a guard that exists for multi-network peers.
        let network = if self.out_handles.len() < 2 {
            self.out_handles.keys().next()?.clone()
        } else {
            self.out_handles
                .keys()
                .filter(|n| {
                    self.active
                        .in_handles
                        .values()
                        .any(|announced| announced == *n)
                })
                .min()
                .or_else(|| self.out_handles.keys().min())?
                .clone()
        };
        let handle = self.out_handles.get(&network).copied().unwrap_or(0);
        Some(PeerRoute {
            conn: self.active.conn.clone(),
            endpoint_id: self.endpoint_id,
            network,
            handle,
            receive_mtu: Arc::clone(&self.active.receive_mtu),
            last_active: Arc::clone(&self.active.last_active),
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
            peers: Arc::new(FastDashMap::default()),
            audit: None,
            version_incompatible: Arc::new(DashSet::default()),
            local_mtu: Arc::new(AtomicU16::new(crate::tun::MIN_TUN_MTU)),
        }
    }

    /// Creates an empty table that logs peer connect/disconnect events to the
    /// given audit log. The daemon constructs the table this way and clones it
    /// to every per-network task (clones share the same audit handle).
    pub fn with_audit(audit: Arc<AuditLog>) -> Self {
        Self {
            peers: Arc::new(FastDashMap::default()),
            audit: Some(audit),
            version_incompatible: Arc::new(DashSet::default()),
            local_mtu: Arc::new(AtomicU16::new(crate::tun::MIN_TUN_MTU)),
        }
    }

    /// Receive limit advertised to peers and enforced before TUN delivery.
    pub fn local_mtu(&self) -> u16 {
        self.local_mtu.load(Ordering::Relaxed)
    }

    pub(crate) fn set_local_mtu(&self, mtu: u16) {
        self.local_mtu.store(mtu, Ordering::Relaxed);
    }

    fn update_current<R>(
        &self,
        ip: &Ipv6Addr,
        conn: &Connection,
        update: impl FnOnce(&mut PeerEntry) -> R,
    ) -> Option<R> {
        let mut entry = self.peers.get_mut(ip)?;
        entry.active.matches(conn).then(|| update(&mut entry))
    }

    /// Ignore stale announcements from replaced connections and constrain remote
    /// values to the IP packet sizes supported by this mesh protocol.
    pub(crate) fn note_receive_mtu(&self, peer_id: &EndpointId, conn: &Connection, mtu: u16) {
        self.update_current(&membership::derive_ipv6(peer_id), conn, |entry| {
            entry.active.receive_mtu.store(
                mtu.clamp(crate::tun::MIN_TUN_MTU, crate::tun::TUN_MTU),
                Ordering::Relaxed,
            );
        });
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
    /// is selected by the shared TLS session ID (lowest wins). A dead connection
    /// is always replaced; re-adding the selected connection is a no-op. Replacing a connection
    /// closes the old one so its task exits and cannot reclaim the route with a
    /// late control frame. Assigns an outbound handle for `network` if one isn't
    /// already held.
    ///
    /// Returns `true` if `conn` is genuinely new to the peer (first shared
    /// network, or a reconnect that replaced a different connection) — the
    /// caller uses this to decide whether to (re)announce the handle table.
    pub fn add(
        &self,
        ipv6: Ipv6Addr,
        conn: Connection,
        endpoint_id: EndpointId,
        network: &str,
    ) -> bool {
        let net = SmolStr::new(network);
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
            let entry = self.peers.entry(ipv6);
            // Check after taking the entry lock. A replaced connection can have a
            // queued control frame already entering this method, but the close
            // marks every clone before that frame can acquire this lock.
            if conn.close_reason().is_some() {
                return false;
            }
            match entry {
                Entry::Occupied(mut o) => {
                    let e = o.get_mut();
                    first_ever = false;
                    conn_changed = e.install_connection(&conn);
                    e.endpoint_id = endpoint_id;
                    if !e.out_handles.contains_key(&net) {
                        let h = next_free_handle(&e.out_handles);
                        e.out_handles.insert(net.clone(), h);
                    }
                }
                Entry::Vacant(v) => {
                    first_ever = true;
                    conn_changed = true;
                    v.insert(PeerEntry::new(endpoint_id, conn.clone(), net.clone()));
                }
            }
        }
        // A live connection just formed, so any prior version-incompatibility flag
        // is stale (the peer was updated / the ALPN now matches).
        self.version_incompatible.remove(&endpoint_id);
        if first_ever && let Some(audit) = &self.audit {
            audit.log_connect(ipv6, &endpoint_id.to_string());
        }
        conn_changed
    }

    /// The peer's mesh IPv6, resolved from its endpoint id. Used by the
    /// per-connection data reader (which knows only the QUIC remote id) to find
    /// the peer's routing entry.
    ///
    /// The address is a pure function of the id, so this is really a membership
    /// test: `None` until the peer is registered by the join handshake, which is
    /// the contract every caller relies on to tell a connected peer from a merely
    /// nameable one.
    pub fn ipv6_for_id(&self, peer_id: &EndpointId) -> Option<Ipv6Addr> {
        let ip = membership::derive_ipv6(peer_id);
        self.peers.contains_key(&ip).then_some(ip)
    }

    /// Record whether `peer_id` advertised idle-close support in its `MeshHello`
    /// (`features & FEATURE_IDLE_CLOSE`). Drives whether the per-connection idle
    /// timer is allowed to close this link.
    pub fn note_idle_support_by_id(
        &self,
        peer_id: &EndpointId,
        conn: &Connection,
        supported: bool,
    ) {
        self.update_current(&membership::derive_ipv6(peer_id), conn, |entry| {
            entry
                .active
                .supports_idle_close
                .store(supported, Ordering::Relaxed);
        });
    }

    /// Whether `peer_id` understands the idle close code. `false` when the peer is
    /// unknown or never advertised it, so an unregistered or pre-feature peer is
    /// never idle-closed.
    pub fn supports_idle_close(&self, peer_id: &EndpointId, conn: &Connection) -> bool {
        self.peers
            .get(&membership::derive_ipv6(peer_id))
            .filter(|e| e.active.matches(conn))
            .map(|e| e.active.supports_idle_close.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// The shared last-activity clock for `peer_id`'s connection, so the
    /// per-connection idle timer can watch it without repeated map lookups. `None`
    /// if the peer is not registered.
    pub fn last_active_of(
        &self,
        peer_id: &EndpointId,
        conn: &Connection,
    ) -> Option<Arc<AtomicU64>> {
        self.peers
            .get(&membership::derive_ipv6(peer_id))
            .filter(|e| e.active.matches(conn))
            .map(|e| Arc::clone(&e.active.last_active))
    }

    /// Time remaining until `peer_id`'s connection has been idle for `idle`
    /// (`Duration::ZERO` once it already has). `None` if the peer is not registered.
    /// Lets a per-connection idle timer sleep exactly the right amount and re-check
    /// on wake without reaching into the activity clock's internals.
    pub fn idle_remaining(
        &self,
        peer_id: &EndpointId,
        conn: &Connection,
        idle: Duration,
    ) -> Option<Duration> {
        let last = self.last_active_of(peer_id, conn)?;
        let elapsed_ms = now_ms().saturating_sub(last.load(Ordering::Relaxed));
        let idle_ms = idle.as_millis() as u64;
        Some(Duration::from_millis(idle_ms.saturating_sub(elapsed_ms)))
    }

    /// Resolve an inbound datagram from `peer_id` tagged with `handle` to the
    /// peer's mesh IPv6 and its arrival network, enforcing the in-band
    /// reachability wall in one lock pass: returns `Some` only when the peer is
    /// known, the handle maps to a network the peer announced, **and** our own
    /// shared-network set with this peer currently contains that network. An
    /// unknown peer/handle or a network we don't share drops the datagram
    /// (`None`).
    pub fn resolve_inbound_by_id(
        &self,
        peer_id: &EndpointId,
        conn: &Connection,
        handle: u16,
    ) -> Option<(Ipv6Addr, SmolStr)> {
        let ip = membership::derive_ipv6(peer_id);
        let e = self.peers.get(&ip)?;
        if !e.active.matches(conn) {
            return None;
        }
        let network = e.active.in_handles.get(&handle)?;
        if !e.out_handles.contains_key(network) {
            return None;
        }
        // Reset the idle timer on the same entry we already hold, so a valid
        // inbound datagram counts as activity with no extra lookup. Stamped only
        // past the reachability wall above, so spoofed or out-of-network traffic
        // can't hold an otherwise-idle connection open.
        e.active.last_active.store(now_ms(), Ordering::Relaxed);
        Some((ip, network.clone()))
    }

    /// Resolves a mesh IPv6 destination to a [`PeerRoute`], or `None` if no peer
    /// with that address shares a live connection with us. This is the outbound
    /// hot path's lookup.
    pub fn lookup_v6(&self, ip: &Ipv6Addr) -> Option<PeerRoute> {
        self.peers.get(ip).and_then(|e| e.route())
    }

    /// Route to the peer holding mesh IPv6 `ip`, pinned to a specific `network`
    /// (rather than [`route`](PeerEntry::route)'s lexically-smallest shared one).
    /// Used by exit-node client routing, which must tag the datagram with the exit
    /// network's handle so the exit peer attributes it to the network whose
    /// allow-list permits us. `None` if the peer isn't connected on `network`.
    pub fn route_on_network(&self, ip: &Ipv6Addr, network: &str) -> Option<PeerRoute> {
        let e = self.peers.get(ip)?;
        if !e.out_handles.contains_key(network) {
            return None;
        }
        let handle = e.out_handles.get(network).copied().unwrap_or(0);
        Some(PeerRoute {
            conn: e.active.conn.clone(),
            endpoint_id: e.endpoint_id,
            network: SmolStr::new(network),
            handle,
            receive_mtu: Arc::clone(&e.active.receive_mtu),
            last_active: Arc::clone(&e.active.last_active),
        })
    }

    /// Resolve the network an inbound datagram belongs to from the peer's mesh
    /// IPv6 and the `u16` handle the peer stamped on it (looked up in the peer's
    /// announced inbound table). `None` if the peer or handle is unknown.
    pub fn inbound_network_v6(&self, ip: &Ipv6Addr, handle: u16) -> Option<SmolStr> {
        self.peers
            .get(ip)
            .and_then(|e| e.active.in_handles.get(&handle).cloned())
    }

    /// Replace a peer's inbound decode table from its announced `NetworkHandles`.
    /// `entries` is `(handle, network)` pairs.
    ///
    /// Also the one place the two views of "what we share" can be compared, so a
    /// network we still hold the peer in and the peer no longer claims is
    /// reported here, once per announcement, rather than per dropped packet. See
    /// [`PeerEntry::route`] for what the disagreement does.
    fn replace_inbound_handles(e: &mut PeerEntry, table: HashMap<u16, SmolStr>) {
        let stale: Vec<&str> = e
            .out_handles
            .keys()
            .filter(|n| !table.values().any(|announced| announced == *n))
            .map(|n| n.as_str())
            .collect();
        if !stale.is_empty() {
            tracing::info!(
                peer = %e.endpoint_id.fmt_short(),
                networks = ?stale,
                "peer no longer shares these networks with us; routing over the ones \
                 it still holds"
            );
        }
        e.active.in_handles = table;
    }

    /// Replace the inbound handle table only when the announcement arrived on
    /// the connection currently used for this peer. A late announcement from a
    /// superseded connection must not change how datagrams on the live one are
    /// decoded.
    pub fn set_inbound_handles(
        &self,
        ip: &Ipv6Addr,
        conn: &Connection,
        entries: &[(u16, SmolStr)],
    ) {
        let table: HashMap<u16, SmolStr> = entries.iter().cloned().collect();
        self.update_current(ip, conn, |entry| {
            Self::replace_inbound_handles(entry, table);
        });
    }

    /// Our outbound handle table for a peer as `(network, handle)` pairs, to send
    /// the peer in a `NetworkHandles` announcement (the peer stores it as its
    /// inbound decode table).
    pub fn outbound_handles(&self, ip: &Ipv6Addr) -> Vec<(SmolStr, u16)> {
        self.peers
            .get(ip)
            .map(|e| e.out_handles.iter().map(|(n, h)| (n.clone(), *h)).collect())
            .unwrap_or_default()
    }

    /// The `u16` handle we stamp on datagrams to `ip` for `network`, if assigned.
    /// Used to announce a single network's handle to the peer after we start
    /// sharing it (the announcement is per-network, not a full snapshot, so
    /// networks are added to the peer's decode table incrementally).
    pub fn out_handle(&self, ip: &Ipv6Addr, network: &str) -> Option<u16> {
        self.peers
            .get(ip)
            .and_then(|e| e.out_handles.get(network).copied())
    }

    /// Resolve a roster identity to the live connection we hold for that device.
    /// The roster names a paired peer by its *user* identity while this table is
    /// keyed on the transport (device) id, so try the identity directly and then
    /// every device mapped to it. Returns the peer's addresses with its connection.
    pub fn connected_device_for(
        &self,
        identity: &EndpointId,
        device_user_map: &DeviceUserMap,
    ) -> Option<(Ipv6Addr, Connection)> {
        let by_id = |id: &EndpointId| {
            let ip = membership::derive_ipv6(id);
            let e = self.peers.get(&ip)?;
            Some((ip, e.active.conn.clone()))
        };
        by_id(identity).or_else(|| {
            device_user_map
                .devices_for(identity)
                .into_iter()
                .find_map(|dev| by_id(&dev))
        })
    }

    /// Add `network` to the shared set of a peer we already hold a live connection
    /// to, assigning it an outbound handle. Returns the handle if this call added
    /// the network (so the caller announces it), `None` if the peer has no entry
    /// or already shared the network.
    ///
    /// Repairs the ordering hole between the handshake and the roster: a peer's
    /// `MeshHello` for a network is only registered if that network's roster
    /// already lists the sender ([`handle_member_hello`]), so a hello that lands
    /// while the roster is still converging (a restart, a fresh join) leaves the
    /// connection carrying a network the peer table doesn't know about. Nothing
    /// else repairs that: the entry is only rebuilt by a fresh dial, and until
    /// then `resolve_inbound_by_id` drops the network's datagrams and `ray status`
    /// reports the peer `Idle` on it while it is plainly connected on another.
    ///
    /// [`handle_member_hello`]: crate::daemon::mesh
    pub fn attach_network(&self, ip: &Ipv6Addr, network: &str) -> Option<u16> {
        let net = SmolStr::new(network);
        let mut e = self.peers.get_mut(ip)?;
        if e.out_handles.contains_key(&net) {
            return None;
        }
        let handle = next_free_handle(&e.out_handles);
        e.out_handles.insert(net, handle);
        Some(handle)
    }

    /// Merge one `(handle → network)` mapping into a peer's inbound decode table,
    /// keyed by the peer's endpoint id. Upsert (not replace), so announcing one
    /// network's handle doesn't clobber the decode entries for the peer's other
    /// shared networks. A stale entry for a network we no longer share is harmless
    /// (the reachability check in `resolve_inbound_by_id` drops its datagrams).
    pub fn add_inbound_handle_by_id(
        &self,
        peer_id: &EndpointId,
        conn: &Connection,
        handle: u16,
        network: SmolStr,
    ) {
        self.update_current(&membership::derive_ipv6(peer_id), conn, |entry| {
            entry.active.in_handles.insert(handle, network);
        });
    }

    /// Resolve a peer by its mesh source IP to its transport identity
    /// and the set of networks we currently share with it. Used by the embedded
    /// mesh SSH server to authorize an incoming session: the peer is identified by
    /// which mesh IP the TCP connection came from (the ingress anti-spoof check in
    /// `forward.rs` guarantees that IP is the peer's own). Returns `None` if no
    /// peer holds that address.
    pub fn identity_and_networks(&self, ip: &Ipv6Addr) -> Option<(EndpointId, Vec<SmolStr>)> {
        self.peers
            .get(ip)
            .map(|e| (e.endpoint_id, e.out_handles.keys().cloned().collect()))
    }

    /// True if we currently share `network` with the peer at mesh IPv6 `ip`. The
    /// in-band reachability check for inbound datagrams: a datagram tagged for a
    /// network we don't share with this peer is dropped.
    pub fn shares_network_v6(&self, ip: &Ipv6Addr, network: &str) -> bool {
        self.peers
            .get(ip)
            .map(|e| e.out_handles.contains_key(network))
            .unwrap_or(false)
    }

    /// The shared connection to a peer identified by mesh IPv6, if any.
    pub fn conn_for_ip(&self, ip: &Ipv6Addr) -> Option<Connection> {
        self.peers.get(ip).map(|e| e.active.conn.clone())
    }

    /// Removes the peer entirely (all networks + connection). Used for identity
    /// rotation and full roster removal.
    pub fn remove(&self, ip: &Ipv6Addr) {
        let removed = self.peers.remove(ip);
        if let (Some((_, entry)), Some(audit)) = (removed, &self.audit) {
            audit.log_disconnect(*ip, &entry.endpoint_id.to_string());
        }
    }

    /// Atomically remove the connection named by a disconnect event and return
    /// its networks. A delayed event for a replaced connection cannot remove the
    /// new route, even if registration races with this operation.
    pub fn remove_connection(
        &self,
        ip: &Ipv6Addr,
        stable_id: Option<usize>,
    ) -> Option<Vec<SmolStr>> {
        let (_, entry) = self.peers.remove_if(ip, |_, e| {
            stable_id.is_none_or(|id| e.active.conn.stable_id() == id)
        })?;
        if let Some(audit) = &self.audit {
            audit.log_disconnect(*ip, &entry.endpoint_id.to_string());
        }
        Some(entry.out_handles.into_keys().collect())
    }

    /// Stops sharing `network` with a peer. The peer entry (and its connection)
    /// is dropped only once it shares no network at all — so losing the `dev`
    /// membership doesn't unroute a peer still reachable via `db`. Returns the
    /// peer's connection **iff** this removed its last shared network (so the
    /// caller can close the now-unused connection); `None` otherwise.
    pub fn remove_peer_from_network(&self, ip: &Ipv6Addr, network: &str) -> Option<Connection> {
        let mut last_conn = None;
        let mut dropped_id = None;
        if let Some(mut e) = self.peers.get_mut(ip) {
            e.out_handles.remove(network);
            if e.out_handles.is_empty() {
                last_conn = Some(e.active.conn.clone());
                dropped_id = Some(e.endpoint_id);
            }
        }
        self.peers.remove_if(ip, |_, e| e.out_handles.is_empty());
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
    /// close the now-unused link); `None` otherwise or if the id is unknown.
    pub fn remove_peer_from_network_by_id(
        &self,
        peer_id: &EndpointId,
        network: &str,
    ) -> Option<Connection> {
        self.remove_peer_from_network(&membership::derive_ipv6(peer_id), network)
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
        ip: &Ipv6Addr,
        network: &str,
        stable_id: usize,
    ) -> Option<Connection> {
        // Read-and-compare in its own statement so the DashMap read guard is
        // dropped before remove_peer_from_network takes a write guard on the
        // same shard.
        let matches = self
            .peers
            .get(ip)
            .map(|e| e.out_handles.contains_key(network) && e.active.conn.stable_id() == stable_id)
            .unwrap_or(false);
        if !matches {
            return None;
        }
        self.remove_peer_from_network(ip, network)
    }

    /// True if the stored connection for the peer at `ip` is the one identified
    /// by `stable_id`. Lets a disconnect consumer tell a live connection from a
    /// stale one before acting on a whole-peer removal.
    pub fn conn_is_current(&self, ip: &Ipv6Addr, stable_id: usize) -> bool {
        self.peers
            .get(ip)
            .map(|e| e.active.conn.stable_id() == stable_id)
            .unwrap_or(false)
    }

    /// One connection per peer, for global broadcasts.
    pub fn all_connections(&self) -> Vec<(Ipv6Addr, Connection)> {
        self.peers
            .iter()
            .map(|e| (*e.key(), e.active.conn.clone()))
            .collect()
    }

    /// Stops sharing `network` with every peer. Returns the IPs of peers left
    /// sharing no network (fully removed), each paired with its connection so the
    /// caller can close links that are now entirely unused.
    pub fn remove_by_network(&self, network: &str) -> Vec<(Ipv6Addr, Connection)> {
        let mut removed = Vec::new();
        self.peers.retain(|ip, e| {
            e.out_handles.remove(network);
            if e.out_handles.is_empty() {
                removed.push((*ip, e.active.conn.clone()));
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
        removed
    }

    /// The identity + IP of every peer we currently share `network` with.
    pub fn peers_for_network(&self, network: &str) -> Vec<(EndpointId, Ipv6Addr)> {
        self.peers
            .iter()
            .filter(|e| e.out_handles.contains_key(network))
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
    ) -> Vec<(EndpointId, Ipv6Addr, Connection)> {
        self.peers
            .iter()
            .filter(|e| e.out_handles.contains_key(network))
            .map(|e| (e.endpoint_id, *e.key(), e.active.conn.clone()))
            .collect()
    }

    #[cfg(test)]
    pub fn all_peer_ids(&self) -> Vec<(Ipv6Addr, EndpointId)> {
        self.peers
            .iter()
            .map(|e| (*e.key(), e.endpoint_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_table_empty_lookup() {
        let table = PeerTable::new();
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
            ipv6: crate::membership::derive_ipv6(&id),
        }
    }

    #[test]
    fn route_map_sync_resolve_and_shrink() {
        let map = RosterRouteMap::new();
        let a = member(1);
        let b = member(2);
        map.sync_network("net", &[a, b]);

        let ta = map.resolve_v6(&a.ipv6).expect("a resolvable");
        assert_eq!(ta.endpoint_id, a.endpoint_id);
        assert_eq!(ta.networks, vec![SmolStr::new("net")]);
        assert_eq!(
            map.resolve_v6(&b.ipv6).expect("b via v6").endpoint_id,
            b.endpoint_id
        );

        // Re-sync with a shrunk roster: b is gone.
        map.sync_network("net", &[a]);
        assert!(map.resolve_v6(&a.ipv6).is_some());
        assert!(
            map.resolve_v6(&b.ipv6).is_none(),
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
        let t = map.resolve_v6(&a.ipv6).expect("resolvable");
        let mut nets = t.networks.clone();
        nets.sort();
        assert_eq!(nets, vec![SmolStr::new("db"), SmolStr::new("dev")]);

        // Leaving one network keeps the peer reachable via the other.
        map.remove_network("dev");
        let t = map.resolve_v6(&a.ipv6).expect("still resolvable via db");
        assert_eq!(t.networks, vec![SmolStr::new("db")]);

        // Leaving the last network drops it entirely.
        map.remove_network("db");
        assert!(map.resolve_v6(&a.ipv6).is_none());
    }

    #[test]
    fn route_map_sync_add_is_incremental() {
        let map = RosterRouteMap::new();
        let a = member(3);
        let b = member(4);
        map.sync_network("net", &[a]);
        // Incremental add of b must not drop a (unlike a full sync_network).
        map.sync_add("net", b.ipv6, b.endpoint_id);
        assert!(map.resolve_v6(&a.ipv6).is_some());
        assert!(map.resolve_v6(&b.ipv6).is_some());
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

        let t = map.resolve_v6(&a.ipv6).expect("known member resolves");
        // First packet claims the in-flight slot; a duplicate is rejected.
        assert!(in_flight.insert(t.endpoint_id));
        assert!(
            !in_flight.insert(t.endpoint_id),
            "duplicate dial is deduped"
        );

        // Unknown destination doesn't resolve, so nothing is dialed.
        assert!(
            map.resolve_v6(&Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0x9999))
                .is_none()
        );
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
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();

        assert!(
            table.add(ipv6, conn.clone(), peer, "n1"),
            "first add of a new peer must report the connection as new"
        );
        // Same connection, a second shared network: one reader already serves it,
        // so this must NOT report a new connection (no duplicate reader).
        assert!(
            !table.add(ipv6, conn.clone(), peer, "n2"),
            "re-adding the same connection for another network must not respawn"
        );
        // Both networks route over the one connection.
        let route = table.lookup_v6(&ipv6).expect("peer routable");
        assert_eq!(route.conn.stable_id(), conn.stable_id());
    }

    #[tokio::test]
    async fn same_direction_duplicates_converge_despite_opposite_registration_order() {
        let (server, client, s1, c1) = connected_pair().await;
        let (s2, c2) = dial(&server, &client).await;
        assert_ne!(s1.stable_id(), s2.stable_id());
        assert_ne!(c1.stable_id(), c2.stable_id());
        assert_connection_selection_converges(&server, &client, s1, c1, s2, c2).await;
    }

    #[tokio::test]
    async fn opposite_direction_duplicates_converge_despite_opposite_registration_order() {
        let (server, client, s1, c1) = connected_pair().await;
        let (c2, s2) = dial(&client, &server).await;
        assert_connection_selection_converges(&server, &client, s1, c1, s2, c2).await;
    }

    async fn assert_connection_selection_converges(
        server: &Endpoint,
        client: &Endpoint,
        s1: Connection,
        c1: Connection,
        s2: Connection,
        c2: Connection,
    ) {
        let server_table = PeerTable::new();
        let client_table = PeerTable::new();
        let server_ip = membership::derive_ipv6(&server.id());
        let client_ip = membership::derive_ipv6(&client.id());
        let expected_id = connection_selection_id(&s1).min(connection_selection_id(&s2));
        // Two networks race to register different physical connections. Each end
        // sees the very same connections, but in the opposite order. Do not yield
        // here: both selections happen before QUIC delivers either close frame.
        for (table, ip, id, conn, network) in [
            (&server_table, client_ip, client.id(), s1, "net-a"),
            (&client_table, server_ip, server.id(), c2, "net-b"),
            (&server_table, client_ip, client.id(), s2, "net-b"),
            (&client_table, server_ip, server.id(), c1, "net-a"),
        ] {
            table.add(ip, conn, id, network);
        }
        let server_conn = server_table.conn_for_ip(&client_ip).unwrap();
        let client_conn = client_table.conn_for_ip(&server_ip).unwrap();
        assert_eq!(connection_selection_id(&server_conn), expected_id);
        assert_eq!(connection_selection_id(&client_conn), expected_id);
        // Local stable_id values cannot be compared across endpoints. The TLS
        // exporter identifies the physical session identically at both ends.
        let session_id = |conn: &Connection| {
            let mut id = [0; 32];
            conn.export_keying_material(&mut id, b"rayfish/test/session-id", b"")
                .unwrap();
            id
        };
        assert_eq!(
            session_id(&server_conn),
            session_id(&client_conn),
            "both peers must select the same physical connection"
        );

        // Verify that the chosen routes actually carry data in both directions,
        // including the per-network tags (the two registration orders differ).
        server_table.set_inbound_handles(
            &client_ip,
            &server_conn,
            &client_table
                .outbound_handles(&server_ip)
                .into_iter()
                .map(|(net, handle)| (handle, net))
                .collect::<Vec<_>>(),
        );
        client_table.set_inbound_handles(
            &server_ip,
            &client_conn,
            &server_table
                .outbound_handles(&client_ip)
                .into_iter()
                .map(|(net, handle)| (handle, net))
                .collect::<Vec<_>>(),
        );
        for network in ["net-a", "net-b"] {
            for (sender, receiver, destination, source_id, receiving_conn) in [
                (
                    &server_table,
                    &client_table,
                    client_ip,
                    server.id(),
                    &client_conn,
                ),
                (
                    &client_table,
                    &server_table,
                    server_ip,
                    client.id(),
                    &server_conn,
                ),
            ] {
                let route = sender.route_on_network(&destination, network).unwrap();
                route
                    .conn
                    .send_datagram(crate::forward::tag_datagram(route.handle, b"ping"))
                    .unwrap();
                let packet =
                    tokio::time::timeout(Duration::from_secs(5), receiving_conn.read_datagram())
                        .await
                        .expect("selected connection carries data")
                        .unwrap();
                let (handle, payload) = crate::forward::untag_datagram(&packet).unwrap();
                assert_eq!(payload, b"ping");
                assert_eq!(
                    receiver.resolve_inbound_by_id(&source_id, receiving_conn, handle),
                    Some((membership::derive_ipv6(&source_id), SmolStr::new(network)))
                );
            }
        }
    }

    #[tokio::test]
    async fn closed_winner_allows_reconnect_and_its_late_disconnect_preserves_replacement() {
        let (server, client, first, _c1) = connected_pair().await;
        let (second, _c2) = dial(&server, &client).await;
        let (lower, higher) = if connection_selection_id(&first) < connection_selection_id(&second)
        {
            (first, second)
        } else {
            (second, first)
        };
        let peer = client.id();
        let ip = membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        assert!(table.add(ip, lower.clone(), peer, "net-a"));
        lower.close(VarInt::from_u32(0), b"test disconnect");
        assert!(
            table.add(ip, higher.clone(), peer, "net-a"),
            "a dead connection cannot keep winning against live replacements"
        );
        assert!(
            table
                .remove_connection(&ip, Some(lower.stable_id()))
                .is_none()
        );
        assert!(table.conn_is_current(&ip, higher.stable_id()));
        assert_eq!(
            table.remove_connection(&ip, Some(higher.stable_id())),
            Some(vec![SmolStr::new("net-a")])
        );
        assert!(table.conn_for_ip(&ip).is_none());
    }

    #[tokio::test]
    async fn attach_network_admits_a_network_the_handshake_missed() {
        // A peer's `MeshHello` for "n2" is only registered if n2's roster already
        // lists the sender, so a hello that arrives mid-reconverge leaves the
        // connection carrying a network the table doesn't know. Reconverge repairs
        // it with `attach_network` once the roster names the peer.
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        table.add(ipv6, conn.clone(), peer, "n1");

        // Before the repair the peer is invisible on n2 (this is what shows as
        // `Idle` in `ray status` while it is Active on n1).
        assert!(table.peers_for_network_with_conn("n2").is_empty());

        let handle = table
            .attach_network(&ipv6, "n2")
            .expect("attaching an unshared network assigns a handle");
        assert_eq!(table.peers_for_network_with_conn("n2").len(), 1);
        assert_eq!(table.out_handle(&ipv6, "n2"), Some(handle));
        // n1 keeps its own distinct handle: the repair must not collide with or
        // clobber the networks already negotiated on this connection.
        assert_ne!(table.out_handle(&ipv6, "n1"), Some(handle));
        assert_eq!(table.peers_for_network_with_conn("n1").len(), 1);

        // Idempotent: a later reconverge re-running the repair changes nothing.
        assert_eq!(table.attach_network(&ipv6, "n2"), None);
        assert_eq!(table.out_handle(&ipv6, "n2"), Some(handle));
        // A peer we hold no connection to cannot be attached.
        let absent = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0x9999);
        assert_eq!(table.attach_network(&absent, "n2"), None);
    }

    #[tokio::test]
    async fn receive_mtu_tracks_announcements_and_resets_on_reconnect() {
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ip = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        table.add(ip, conn.clone(), peer, "net");
        let route = table.lookup_v6(&ip).unwrap();
        assert_eq!(route.receive_mtu(), 1280);
        table.note_receive_mtu(&peer, &conn, 1500);
        assert_eq!(route.receive_mtu(), 1500);
        table.note_receive_mtu(&peer, &conn, 0);
        assert_eq!(route.receive_mtu(), 1280);
        table.note_receive_mtu(&peer, &conn, u16::MAX);
        assert_eq!(route.receive_mtu(), 1500);
        table.add(ip, conn.clone(), peer, "another");
        assert_eq!(
            table
                .route_on_network(&ip, "another")
                .unwrap()
                .receive_mtu(),
            1500
        );

        // The table normally receives the same identity on a new connection.
        // A second test connection supplies a different stable id here.
        let (_srv2, _cli2, replacement, _client2) = connected_pair().await;
        conn.close(VarInt::from_u32(0), b"test reconnect");
        table.add(ip, replacement.clone(), peer, "net");
        let route = table.lookup_v6(&ip).unwrap();
        assert_eq!(route.receive_mtu(), 1280);
        table.note_receive_mtu(&peer, &conn, 1500);
        assert_eq!(
            route.receive_mtu(),
            1280,
            "stale connection cannot raise the limit"
        );
        table.note_receive_mtu(&peer, &replacement, 1400);
        assert_eq!(route.receive_mtu(), 1400);
    }

    #[tokio::test]
    async fn attach_network_reopens_the_reachability_wall_for_that_network() {
        // The missing network is not cosmetic: `resolve_inbound_by_id` drops every
        // datagram tagged with a network the peer entry does not list, so an
        // unrepaired entry silently blackholes that network's traffic.
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        table.add(ipv6, conn.clone(), peer, "n1");
        // The peer announced its handle for n2; we just never joined it to the
        // entry's shared set.
        table.add_inbound_handle_by_id(&peer, &conn, 7, SmolStr::new("n2"));

        assert_eq!(
            table.resolve_inbound_by_id(&peer, &conn, 7),
            None,
            "n2 datagrams must be dropped while the entry does not share n2"
        );

        table.attach_network(&ipv6, "n2");
        assert_eq!(
            table.resolve_inbound_by_id(&peer, &conn, 7),
            Some((ipv6, SmolStr::new("n2"))),
            "after the repair the same datagram must be accepted on n2"
        );
    }

    /// A network the peer has left but we still hold it in must not be the one
    /// we tag datagrams with: the peer drops anything tagged with a network it
    /// does not share, so the stale name black-holes a peer we have a working
    /// network with. Lexical order is what makes this reachable in practice —
    /// the stale name only has to sort first.
    #[tokio::test]
    async fn route_skips_a_network_the_peer_no_longer_announces() {
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        table.add(ipv6, conn.clone(), peer, "aaa");
        table.add(ipv6, conn.clone(), peer, "zzz");

        // The peer's announcement carries only zzz: it left aaa without us
        // hearing about it (offline, or we are aaa's coordinator so nothing else
        // ever corrects our roster).
        table.set_inbound_handles(&ipv6, &conn, &[(1, SmolStr::new("zzz"))]);

        let route = table.lookup_v6(&ipv6).expect("peer is reachable");
        assert_eq!(route.network, "zzz");
        assert_eq!(route.handle, table.out_handle(&ipv6, "zzz").unwrap());
        // The v6 address of the same peer routes the same way.
        assert_eq!(table.lookup_v6(&ipv6).unwrap().network, "zzz");
    }

    #[tokio::test]
    async fn route_keeps_the_lexical_pick_when_the_peer_agrees_or_is_silent() {
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        table.add(ipv6, conn.clone(), peer, "aaa");
        table.add(ipv6, conn.clone(), peer, "zzz");

        // Nothing announced yet (the handshake is still in flight): the plain
        // pick stands, so a fresh connection routes from its first packet.
        assert_eq!(table.lookup_v6(&ipv6).unwrap().network, "aaa");

        // Peer agrees on both: unchanged, and stable across lookups.
        table.set_inbound_handles(
            &ipv6,
            &conn,
            &[(1, SmolStr::new("aaa")), (2, SmolStr::new("zzz"))],
        );
        assert_eq!(table.lookup_v6(&ipv6).unwrap().network, "aaa");
    }

    #[tokio::test]
    async fn idle_support_capability_and_last_active_lookup() {
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();

        // Unknown peer: not idle-close-capable, and no activity clock to watch.
        assert!(!table.supports_idle_close(&peer, &conn));
        assert!(table.last_active_of(&peer, &conn).is_none());

        assert!(table.add(ipv6, conn.clone(), peer, "n1"));

        // Registered but has not announced its capability yet: default is
        // "unsupported" so we never idle-close a peer before it advertises.
        assert!(!table.supports_idle_close(&peer, &conn));
        assert!(table.last_active_of(&peer, &conn).is_some());

        table.note_idle_support_by_id(&peer, &conn, true);
        assert!(table.supports_idle_close(&peer, &conn));

        table.note_idle_support_by_id(&peer, &conn, false);
        assert!(!table.supports_idle_close(&peer, &conn));
    }

    #[tokio::test]
    async fn idle_remaining_tracks_activity_clock() {
        let (_srv, _cli, conn, _client_side) = connected_pair().await;
        let peer = conn.remote_id();
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        let window = Duration::from_secs(120);

        // Unknown peer has no activity clock to watch.
        assert!(table.idle_remaining(&peer, &conn, window).is_none());

        assert!(table.add(ipv6, conn.clone(), peer, "n1"));

        // Freshly registered: nearly the whole window remains (slack for wall time).
        let rem = table.idle_remaining(&peer, &conn, window).unwrap();
        assert!(
            rem > Duration::from_secs(115),
            "a fresh peer keeps ~the full window, got {rem:?}"
        );

        // A zero-length window means the connection is idle immediately (the same
        // arithmetic the timer uses to decide it's time to close).
        assert_eq!(
            table.idle_remaining(&peer, &conn, Duration::ZERO),
            Some(Duration::ZERO)
        );

        // A fresh activity bump keeps the full window (the timer would re-arm).
        table
            .last_active_of(&peer, &conn)
            .unwrap()
            .store(now_ms(), Ordering::Relaxed);
        assert!(table.idle_remaining(&peer, &conn, window).unwrap() > Duration::from_secs(115));
    }

    #[tokio::test]
    async fn add_reports_reconnect_as_new() {
        // A reconnect installs a different QUIC connection (new stable id) to the
        // same peer identity: `add` must report it new so the stale reader is
        // replaced.
        let (server, client, conn1, _c1) = connected_pair().await;
        let peer = conn1.remote_id();
        let ipv6 = crate::membership::derive_ipv6(&peer);
        let table = PeerTable::new();
        assert!(table.add(ipv6, conn1.clone(), peer, "n1"));
        table.note_idle_support_by_id(&peer, &conn1, true);
        table.set_inbound_handles(&ipv6, &conn1, &[(7, SmolStr::new("n1"))]);
        let old_activity = table
            .last_active_of(&peer, &conn1)
            .expect("the first connection has an activity clock");

        // Second, distinct connection to the same server identity.
        let (conn2, _c2) = dial(&server, &client).await;
        assert_ne!(conn1.stable_id(), conn2.stable_id(), "distinct connections");
        conn1.close(VarInt::from_u32(0), b"test reconnect");
        assert!(
            table.add(ipv6, conn2.clone(), peer, "n1"),
            "a reconnect (different connection) must report the connection as new"
        );
        assert_eq!(
            table.lookup_v6(&ipv6).unwrap().conn.stable_id(),
            conn2.stable_id()
        );
        assert!(
            conn1.close_reason().is_some(),
            "replacing a connection must close its task"
        );
        assert!(!table.supports_idle_close(&peer, &conn2));
        assert_eq!(table.inbound_network_v6(&ipv6, 7), None);
        let new_activity = table
            .last_active_of(&peer, &conn2)
            .expect("the replacement has an activity clock");
        assert!(!Arc::ptr_eq(&old_activity, &new_activity));

        // A delayed handshake from the connection that conn2 replaced must not
        // reclaim the route. That split the control and data planes: a Pong sent
        // on conn2 still arrived while TUN replies were sent into conn1.
        assert!(
            !table.add(ipv6, conn1.clone(), peer, "n1"),
            "a superseded connection must stay superseded"
        );
        assert_eq!(
            table.lookup_v6(&ipv6).unwrap().conn.stable_id(),
            conn2.stable_id()
        );

        table.set_inbound_handles(&ipv6, &conn2, &[(7, SmolStr::new("n1"))]);
        table.set_inbound_handles(&ipv6, &conn1, &[(9, SmolStr::new("n1"))]);
        assert_eq!(table.inbound_network_v6(&ipv6, 7), Some(SmolStr::new("n1")));
        assert_eq!(table.inbound_network_v6(&ipv6, 9), None);
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
        let s_ipv6 = crate::membership::derive_ipv6(&s_id);
        let r_ipv6 = crate::membership::derive_ipv6(&conn_s.remote_id());

        // Register S in R's table for "net" and teach R that S's tag 1 = "net".
        let peers = PeerTable::new();
        peers.add(s_ipv6, conn_r.clone(), s_id, "net");
        peers.add_inbound_handle_by_id(&s_id, &conn_r, 1, SmolStr::new("net"));

        let (tun_tx, mut tun_rx) = mpsc::channel::<Bytes>(8);
        let ctx = ForwardCtx {
            firewall: SharedFirewall::new(FirewallConfig::default()),
            tun_tx: Arc::new(arc_swap::ArcSwap::new(Arc::new(tun_tx))),
            token: CancellationToken::new(),
            stats: Arc::new(ForwardMetrics::default()),
            device_user_map: DeviceUserMap::new(),
            exit: crate::exit_node::ExitContext::default(),
        };
        spawn_peer_reader(conn_r.clone(), s_id, peers.clone(), ctx);

        // S sends a tagged ICMPv6 echo from its own mesh IP: default firewall
        // allows inbound ICMP, and the source matches S's assigned IP so the
        // anti-spoof check passes. The reader must untag, resolve the network via
        // the handle, and write the raw IP packet (tag stripped) to the TUN.
        let icmp = icmp6_echo_packet(s_ipv6, r_ipv6);
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

    /// Minimal IPv6/ICMPv6 echo-request packet from `src` to `dst`, enough for
    /// `firewall::parse_packet_info` (version, next header 58, src/dst) and the
    /// seeded inbound `allow icmp` rule, which covers ICMPv6 as well as ICMPv4.
    fn icmp6_echo_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 0x60; // IPv6, traffic class 0
        p[5] = 8; // payload length: the ICMPv6 header below
        p[6] = 58; // next header = ICMPv6
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40] = 128; // ICMPv6 type = echo request
        p
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
