//! The process-lifetime network + storage foundation.
//!
//! Groups the handles every service needs but none owns: the shared iroh
//! endpoint, this node's identity, the blob store, and forwarding metrics.
//! Services depend on `Arc<Transport>` (downward) instead of
//! reaching into the daemon god object. Every field is a cheap `Arc`-backed
//! clone, so `Transport` itself is `Clone`.
//!
//! Named `Transport` per the service-decomposition design; it lives in the
//! `foundation` module rather than `daemon::transport` to avoid clashing with
//! the crate-level `transport` module that owns iroh endpoint setup.

use super::*;
use iroh::address_lookup::memory::MemoryLookup;
#[cfg(any(target_os = "android", target_os = "ios"))]
use iroh::{RelayMap, RelayUrl};
#[cfg(any(target_os = "android", target_os = "ios"))]
use std::sync::atomic;
use url::Url;

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
    /// Phones go outgoing-only after an idle period: mesh peer links close and
    /// the relay is dropped, so nothing unsolicited reaches the radio. Shared
    /// with mDNS, which skips its windows while this is set.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) suspended: Arc<AtomicBool>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) activity_seq: Arc<AtomicU64>,
    /// The configured relays, removed from the endpoint while suspended and
    /// restored on wake.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) relay_map: RelayMap,
    /// Serializes relay removal and restore so a wake racing a suspend cannot
    /// leave the relays in the wrong state.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) relay_toggle: Arc<AsyncMutex<()>>,
}

/// Startup-only values bundled to keep [`Transport::new`] focused on its core
/// endpoint, identity, store, and metrics dependencies.
pub(crate) struct TransportBootstrap {
    pub(crate) lan_peers: Arc<LanPeers>,
    pub(crate) warm_lookup: MemoryLookup,
    pub(crate) pkarr_relay_url: Url,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) suspended: Arc<AtomicBool>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) relay_map: RelayMap,
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
            lan_peers: bootstrap.lan_peers,
            warm_lookup: bootstrap.warm_lookup,
            pkarr_relay_url: bootstrap.pkarr_relay_url,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            suspended: bootstrap.suspended,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            activity_seq: Arc::new(AtomicU64::new(0)),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            relay_map: bootstrap.relay_map,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            relay_toggle: Arc::new(AsyncMutex::new(())),
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) fn is_suspended(&self) -> bool {
        self.suspended.load(atomic::Ordering::Acquire)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) fn mark_suspended(&self) -> bool {
        !self.suspended.swap(true, atomic::Ordering::AcqRel)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) fn mark_awake(&self) -> bool {
        self.suspended.swap(false, atomic::Ordering::AcqRel)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) fn record_outgoing_activity(&self) {
        self.activity_seq.fetch_add(1, atomic::Ordering::Relaxed);
    }

    /// Bring the endpoint's relays in line with the suspended flag: none while
    /// suspended, the configured set otherwise. Reading the flag under the lock
    /// makes the last caller win, whichever order a suspend and a wake land in.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) async fn sync_relays(&self) {
        let _guard = self.relay_toggle.lock().await;
        let suspended = self.is_suspended();
        for url in self.relay_map.urls::<Vec<RelayUrl>>() {
            if suspended {
                self.endpoint.remove_relay(&url).await;
            } else if let Some(config) = self.relay_map.get(&url) {
                self.endpoint.insert_relay(url, config).await;
            }
        }
    }
}
