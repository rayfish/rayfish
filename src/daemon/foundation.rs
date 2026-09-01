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
use url::Url;

// Fields are read starting in M2 (extracted services consume `Arc<Transport>`);
// during M1 only the bundle is constructed, so silence the transitional warning.
#[derive(Clone)]
pub(crate) struct Transport {
    /// The one shared iroh endpoint (all ALPNs, all networks) for the process.
    pub(crate) endpoint: Endpoint,
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
}

/// Startup-only values bundled to keep [`Transport::new`] focused on its core
/// endpoint, identity, store, and metrics dependencies.
pub(crate) struct TransportBootstrap {
    pub(crate) contact_public: EndpointId,
    pub(crate) lan_peers: Arc<LanPeers>,
    pub(crate) warm_lookup: MemoryLookup,
    pub(crate) pkarr_relay_url: Url,
}

impl Transport {
    pub(crate) fn new(
        endpoint: Endpoint,
        identity: IrohIdentityProvider,
        blob_store: FsStore,
        stats: Arc<ForwardMetrics>,
        bootstrap: TransportBootstrap,
    ) -> Self {
        Self {
            endpoint,
            identity,
            blob_store,
            stats,
            contact_public: bootstrap.contact_public,
            lan_peers: bootstrap.lan_peers,
            warm_lookup: bootstrap.warm_lookup,
            pkarr_relay_url: bootstrap.pkarr_relay_url,
        }
    }
}
