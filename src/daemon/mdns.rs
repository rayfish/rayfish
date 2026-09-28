//! Runtime mDNS discovery on an endpoint that stays alive across setting changes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use futures::StreamExt;
use futures::stream::BoxStream;
use iroh::EndpointId;
use iroh::address_lookup::{AddressLookup, EndpointData, Error, Item};
use iroh::endpoint::Endpoint;
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use tokio::task::JoinHandle;

use super::LanPeers;

#[derive(Debug, Default)]
struct LookupSlot {
    current: ArcSwapOption<MdnsAddressLookup>,
    latest: ArcSwapOption<EndpointData>,
}

impl AddressLookup for LookupSlot {
    fn publish(&self, data: &EndpointData) {
        self.latest.store(Some(Arc::new(data.clone())));
        if let Some(provider) = self.current.load_full() {
            provider.publish(data);
        }
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<'static, Result<Item, Error>>> {
        self.current
            .load_full()
            .and_then(|provider| provider.resolve(endpoint_id))
    }
}

pub(super) struct MdnsDiscovery {
    endpoint_id: EndpointId,
    slot: Arc<LookupSlot>,
    peers: Arc<LanPeers>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl MdnsDiscovery {
    pub(super) fn new(endpoint: &Endpoint, peers: Arc<LanPeers>) -> Result<Self> {
        let slot = Arc::new(LookupSlot::default());
        endpoint
            .address_lookup()
            .context("mDNS requires an open endpoint")?
            .add(Arc::clone(&slot));
        Ok(Self {
            endpoint_id: endpoint.id(),
            slot,
            peers,
            worker: Mutex::new(None),
        })
    }

    pub(super) fn enabled(&self) -> bool {
        self.slot.current.load().is_some()
    }

    pub(super) async fn start(&self) -> Result<()> {
        if self.enabled() {
            return Ok(());
        }
        let previous_worker = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(worker) = previous_worker {
            worker.abort();
            let _ = worker.await;
        }
        let provider = MdnsAddressLookup::builder()
            .service_name("rayfish")
            .discovery_cadence(Duration::from_secs(30))
            .advertise(true)
            .build(self.endpoint_id)
            .context("failed to start mDNS discovery")?;
        let mut events = provider.subscribe().await;
        self.slot.current.store(Some(Arc::new(provider)));
        if let Some(data) = self.slot.latest.load_full()
            && let Some(provider) = self.slot.current.load_full()
        {
            provider.publish(&data);
        }
        let slot = Arc::clone(&self.slot);
        let peers = Arc::clone(&self.peers);
        let worker = tokio::spawn(async move {
            while let Some(event) = events.next().await {
                match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        tracing::info!(
                            peer = %endpoint_info.endpoint_id.fmt_short(),
                            "mDNS: peer discovered on LAN"
                        );
                        peers.discovered(
                            endpoint_info.endpoint_id,
                            endpoint_info.ip_addrs().copied().collect(),
                        );
                    }
                    DiscoveryEvent::Expired { endpoint_id } => {
                        tracing::info!(peer = %endpoint_id.fmt_short(), "mDNS: peer left LAN");
                        peers.expired(&endpoint_id);
                    }
                    _ => {}
                }
            }
            slot.current.store(None);
            peers.clear();
            tracing::warn!("mDNS discovery stopped unexpectedly");
        });
        *self.worker.lock().unwrap_or_else(|e| e.into_inner()) = Some(worker);
        tracing::info!("mDNS discovery enabled (advertising _rayfish._udp.local)");
        Ok(())
    }

    pub(super) async fn stop(&self) {
        self.slot.current.store(None);
        let worker = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(worker) = worker {
            worker.abort();
            let _ = worker.await;
        }
        self.peers.clear();
        tracing::info!("mDNS discovery disabled");
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        self.slot.current.store(None);
        if let Some(worker) = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            worker.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayMode;
    use iroh::endpoint::presets;
    use tokio::time::timeout;

    #[tokio::test]
    async fn toggles_detach_lookup_and_preserve_connection() {
        let alpn = b"mdns-toggle-test".to_vec();
        let local = Endpoint::builder(presets::N0)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let remote = Endpoint::builder(presets::N0)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let peers = Arc::new(LanPeers::new());
        let lookups = local.address_lookup().unwrap();
        let initial_lookup_count = lookups.len();
        let mdns = MdnsDiscovery::new(&local, Arc::clone(&peers)).unwrap();
        assert_eq!(lookups.len(), initial_lookup_count + 1);
        let (connection, other_connection) = timeout(Duration::from_secs(5), async {
            tokio::join!(local.connect(remote.addr(), &alpn), async {
                remote.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let connection = connection.unwrap();

        for (enabled, payload) in [(true, 1u8), (false, 2), (true, 3)] {
            if enabled {
                mdns.start().await.unwrap();
                assert!(mdns.slot.resolve(remote.id()).is_some());
                let provider = mdns.slot.current.load_full().unwrap();
                mdns.start().await.unwrap();
                assert!(Arc::ptr_eq(
                    &provider,
                    &mdns.slot.current.load_full().unwrap()
                ));
            } else {
                peers.discovered(remote.id(), Vec::new());
                mdns.stop().await;
                assert!(peers.snapshot().is_empty());
                assert!(mdns.slot.resolve(remote.id()).is_none());
            }
            assert_eq!(mdns.enabled(), enabled);
            assert_eq!(lookups.len(), initial_lookup_count + 1);
            let (mut send, _) = connection.open_bi().await.unwrap();
            send.write_all(&[payload]).await.unwrap();
            send.finish().unwrap();
            let (_, mut recv) = other_connection.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(1).await.unwrap(), [payload]);
        }

        mdns.stop().await;
        local.close().await;
        remote.close().await;
    }
}
