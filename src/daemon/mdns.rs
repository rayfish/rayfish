//! Runtime mDNS discovery on an endpoint that stays alive across setting changes.

use std::fmt::{Debug, Formatter};
use std::sync::Arc;
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
use tokio_util::sync::CancellationToken;

use super::LanPeers;
use crate::AsyncMutex;
use crate::config;

pub(super) struct MdnsDiscovery {
    endpoint_id: EndpointId,
    current: ArcSwapOption<MdnsAddressLookup>,
    latest: ArcSwapOption<EndpointData>,
    peers: Arc<LanPeers>,
    /// Serializes config writes, worker changes, and shutdown.
    worker: AsyncMutex<Option<JoinHandle<()>>>,
}

impl Debug for MdnsDiscovery {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsDiscovery")
            .field("enabled", &self.enabled())
            .finish()
    }
}

impl AddressLookup for MdnsDiscovery {
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

impl MdnsDiscovery {
    pub(super) fn new(endpoint: &Endpoint, peers: Arc<LanPeers>) -> Result<Arc<Self>> {
        let discovery = Arc::new(Self {
            endpoint_id: endpoint.id(),
            current: ArcSwapOption::empty(),
            latest: ArcSwapOption::empty(),
            peers,
            worker: AsyncMutex::new(None),
        });
        endpoint
            .address_lookup()
            .context("mDNS requires an open endpoint")?
            .add(Arc::clone(&discovery));
        Ok(discovery)
    }

    pub(super) fn enabled(&self) -> bool {
        self.current.load().is_some()
    }

    pub(super) async fn start(self: &Arc<Self>) -> Result<()> {
        let mut worker = self.worker.lock().await;
        self.start_locked(&mut worker).await
    }

    async fn start_locked(self: &Arc<Self>, worker: &mut Option<JoinHandle<()>>) -> Result<()> {
        if self.enabled() {
            return Ok(());
        }
        if let Some(previous) = worker.take() {
            previous.abort();
            let _ = previous.await;
        }
        let provider = MdnsAddressLookup::builder()
            .service_name("rayfish")
            .discovery_cadence(Duration::from_secs(30))
            .advertise(true)
            .build(self.endpoint_id)
            .context("failed to start mDNS discovery")?;
        let mut events = provider.subscribe().await;
        self.current.store(Some(Arc::new(provider)));
        if let Some(data) = self.latest.load_full()
            && let Some(provider) = self.current.load_full()
        {
            provider.publish(&data);
        }
        let discovery = Arc::downgrade(self);
        let peers = Arc::clone(&self.peers);
        *worker = Some(tokio::spawn(async move {
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
            if let Some(discovery) = discovery.upgrade() {
                discovery.current.store(None);
                peers.clear();
                tracing::warn!("mDNS discovery stopped unexpectedly");
            }
        }));
        tracing::info!("mDNS discovery enabled (advertising _rayfish._udp.local)");
        Ok(())
    }

    pub(super) async fn stop(&self) {
        let mut worker = self.worker.lock().await;
        self.stop_locked(&mut worker).await;
    }

    /// Stop discovery if the daemon is dropped without explicit shutdown.
    pub(super) fn abort(&self) {
        self.current.store(None);
        if let Ok(mut worker) = self.worker.try_lock()
            && let Some(running) = worker.take()
        {
            running.abort();
        }
        self.peers.clear();
    }

    async fn stop_locked(&self, worker: &mut Option<JoinHandle<()>>) {
        self.current.store(None);
        if let Some(running) = worker.take() {
            running.abort();
            let _ = running.await;
        }
        self.peers.clear();
        tracing::info!("mDNS discovery disabled");
    }

    pub(super) async fn set_enabled(
        self: &Arc<Self>,
        enabled: bool,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        let mut worker = self.worker.lock().await;
        anyhow::ensure!(!shutdown.is_cancelled(), "daemon is shutting down");
        let mut previous = false;
        config::update_settings(|cfg| {
            previous = cfg.mdns_enabled;
            cfg.mdns_enabled = enabled;
            Ok(())
        })?;
        if enabled {
            if let Err(error) = self.start_locked(&mut worker).await {
                if let Err(rollback) = config::update_settings(|cfg| {
                    cfg.mdns_enabled = previous;
                    Ok(())
                }) {
                    tracing::warn!(%rollback, "failed to restore mDNS setting after start failure");
                }
                return Err(error);
            }
        } else {
            self.stop_locked(&mut worker).await;
        }
        Ok(())
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
                assert!(mdns.resolve(remote.id()).is_some());
                let provider = mdns.current.load_full().unwrap();
                mdns.start().await.unwrap();
                assert!(Arc::ptr_eq(&provider, &mdns.current.load_full().unwrap()));
            } else {
                peers.discovered(remote.id(), Vec::new());
                mdns.stop().await;
                assert!(peers.snapshot().is_empty());
                assert!(mdns.resolve(remote.id()).is_none());
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
