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
use iroh::address_lookup::memory::MemoryLookup;
#[cfg(target_os = "android")]
use std::sync::atomic;
use url::Url;

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
    /// Bootstrap-only address hints from successful prior connections.  This is
    /// registered with iroh's lookup chain, so a stale hint simply falls through
    /// to normal discovery and can never impersonate its endpoint id.
    pub(crate) warm_lookup: MemoryLookup,
    /// The discovery relay selected for this daemon at startup. Keeping this
    /// with the endpoint prevents a later embedded daemon from inheriting a
    /// prior instance's process-global setting.
    pub(crate) pkarr_relay_url: Url,
    /// Android keeps the TUN/DNS plane alive while suspending mesh transport
    /// after an idle period. The first packet resumes it before dialing.
    #[cfg(target_os = "android")]
    pub(crate) suspended: Arc<AtomicBool>,
    #[cfg(target_os = "android")]
    pub(crate) activity_seq: Arc<AtomicU64>,
    #[cfg(target_os = "android")]
    pub(crate) relay_configs: Arc<Vec<(RelayUrl, Arc<RelayConfig>)>>,
}

/// Startup-only values bundled to keep [`Transport::new`] focused on its core
/// endpoint, identity, store, and metrics dependencies.
pub(crate) struct TransportBootstrap {
    pub(crate) contact_public: EndpointId,
    pub(crate) lan_peers: Arc<LanPeers>,
    pub(crate) warm_lookup: MemoryLookup,
    pub(crate) pkarr_relay_url: Url,
    #[cfg(target_os = "android")]
    pub(crate) relay_configs: Vec<(RelayUrl, Arc<RelayConfig>)>,
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
        bootstrap: TransportBootstrap,
    ) -> Self {
        Self {
            endpoint: bound.endpoint,
            _guard: bound.guard,
            identity,
            blob_store,
            stats,
            contact_public: bootstrap.contact_public,
            lan_peers: bootstrap.lan_peers,
            warm_lookup: bootstrap.warm_lookup,
            pkarr_relay_url: bootstrap.pkarr_relay_url,
            #[cfg(target_os = "android")]
            suspended: Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "android")]
            activity_seq: Arc::new(AtomicU64::new(0)),
            #[cfg(target_os = "android")]
            relay_configs: Arc::new(bootstrap.relay_configs),
        }
    }

    #[cfg(target_os = "android")]
    pub(crate) fn is_suspended(&self) -> bool {
        self.suspended.load(atomic::Ordering::Acquire)
    }

    #[cfg(target_os = "android")]
    pub(crate) fn mark_suspended(&self) -> bool {
        !self.suspended.swap(true, atomic::Ordering::AcqRel)
    }

    #[cfg(target_os = "android")]
    pub(crate) fn mark_awake(&self) -> bool {
        self.suspended.swap(false, atomic::Ordering::AcqRel)
    }

    #[cfg(target_os = "android")]
    pub(crate) fn record_outgoing_activity(&self) {
        self.activity_seq.fetch_add(1, atomic::Ordering::Relaxed);
    }
}
