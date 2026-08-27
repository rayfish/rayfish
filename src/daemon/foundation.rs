//! The process-lifetime network + storage foundation.
//!
//! Groups the handles every service needs but none owns: the shared iroh
//! endpoint, this node's identity, the blob store, forwarding metrics, and this
//! node's contact id. Services depend on `Arc<Transport>` (downward) instead of
//! reaching into the daemon god object. Every field is a cheap `Arc`-backed
//! clone, so `Transport` itself is `Clone`.
//!
//! Named `Transport` per the service-decomposition design; it lives in the
//! `foundation` module rather than `daemon::transport` to avoid clashing with
//! the crate-level `transport` module that owns iroh endpoint setup.

use super::*;

// Fields are read starting in M2 (extracted services consume `Arc<Transport>`);
// during M1 only the bundle is constructed, so silence the transitional warning.
#[derive(Clone)]
pub(crate) struct Transport {
    /// The one shared iroh endpoint (all ALPNs, all networks) for the process.
    pub(crate) endpoint: Endpoint,
    /// Whatever the endpoint's transports need kept alive, held for exactly as
    /// long as the endpoint itself. In a Tor posture this owns the control
    /// connection that the node's onion service exists on: drop it and the node
    /// goes silently unreachable while still looking healthy. Never read, which
    /// is the point, so it is named to say so. See
    /// [`crate::transport::TransportGuard`].
    pub(crate) _guard: crate::transport::TransportGuard,
    /// This node's persistent identity + derived mesh addresses.
    pub(crate) identity: IrohIdentityProvider,
    /// Content-addressed blob store backing file transfer and membership blobs.
    pub(crate) blob_store: FsStore,
    /// Forwarding metrics registry (per-packet counters), shared for export.
    pub(crate) stats: Arc<ForwardMetrics>,
    /// Public half of this node's rotatable `ray connect` contact key.
    pub(crate) contact_public: EndpointId,
    /// Nodes seen on the LAN over mDNS. Empty when mDNS is disabled.
    pub(crate) lan_peers: Arc<LanPeers>,
}

impl Transport {
    /// Takes the [`BoundEndpoint`](crate::transport::BoundEndpoint) whole rather
    /// than just its endpoint: the guard beside it is not optional bookkeeping,
    /// and splitting them at the call site is how it gets dropped by accident.
    pub(crate) fn new(
        bound: crate::transport::BoundEndpoint,
        identity: IrohIdentityProvider,
        blob_store: FsStore,
        stats: Arc<ForwardMetrics>,
        contact_public: EndpointId,
        lan_peers: Arc<LanPeers>,
    ) -> Self {
        Self {
            endpoint: bound.endpoint,
            _guard: bound.guard,
            identity,
            blob_store,
            stats,
            contact_public,
            lan_peers,
        }
    }
}
