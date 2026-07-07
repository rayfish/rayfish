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
#[allow(dead_code)]
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
}

impl Transport {
    pub(crate) fn new(
        endpoint: Endpoint,
        identity: IrohIdentityProvider,
        blob_store: FsStore,
        stats: Arc<ForwardMetrics>,
        contact_public: EndpointId,
    ) -> Self {
        Self {
            endpoint,
            identity,
            blob_store,
            stats,
            contact_public,
        }
    }
}
