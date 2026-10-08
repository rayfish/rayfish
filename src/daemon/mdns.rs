//! Runtime mDNS discovery on an endpoint that stays alive across setting changes.
//!
//! Discovery runs in short windows instead of keeping its sockets open. An
//! open mDNS socket receives every mDNS packet on the LAN, and a busy network
//! (hotel or office Wi-Fi) sends hundreds a second, which kept the radio and
//! CPU awake for nothing. A window opens at start, right away when the node's
//! LAN addresses change (it joined another network), and on every wall-clock
//! multiple of [`WINDOW_INTERVAL`] (:00, :05, :10, ...). Clock alignment is what
//! lets two nodes meet: windows on independent timers would rarely overlap.
//! Every platform uses the same interval, so every window is shared.
//! Sightings survive between windows and expire by age.

use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use futures::StreamExt;
use futures::stream::BoxStream;
use iroh::EndpointId;
use iroh::address_lookup::{AddressLookup, EndpointData, Error, Item};
use iroh::endpoint::Endpoint;
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::LanPeers;
use crate::AsyncMutex;
use crate::config;

/// How long each window keeps the mDNS sockets open.
const LISTEN_WINDOW: Duration = Duration::from_secs(30);

/// Query cadence inside a window, so one window sends a few queries.
const QUERY_CADENCE: Duration = Duration::from_secs(10);

/// Time between windows when nothing changed. Must divide an hour and be the
/// same on every platform, so windows land on the same minutes on every node.
const WINDOW_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A sighting missing from two windows in a row is dropped.
const SIGHTING_TTL: Duration = WINDOW_INTERVAL
    .saturating_mul(2)
    .saturating_add(LISTEN_WINDOW);

type Events = BoxStream<'static, DiscoveryEvent>;

pub(super) struct MdnsDiscovery {
    endpoint_id: EndpointId,
    /// The provider of the window open right now, if any.
    current: ArcSwapOption<MdnsAddressLookup>,
    latest: ArcSwapOption<EndpointData>,
    peers: Arc<LanPeers>,
    /// The setting, independent of whether a window is open.
    enabled: AtomicBool,
    /// Restarts the window now, after the LAN addresses changed.
    wake: Arc<Notify>,
    /// Serializes config writes, scheduler changes, and shutdown.
    worker: AsyncMutex<Option<JoinHandle<()>>>,
}

impl Debug for MdnsDiscovery {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsDiscovery")
            .field("enabled", &self.enabled())
            .field("listening", &self.current.load().is_some())
            .finish()
    }
}

impl AddressLookup for MdnsDiscovery {
    fn publish(&self, data: &EndpointData) {
        let moved = self
            .latest
            .load()
            .as_deref()
            .is_some_and(|previous| lan_ips(previous) != lan_ips(data));
        self.latest.store(Some(Arc::new(data.clone())));
        if let Some(provider) = self.current.load_full() {
            provider.publish(data);
        }
        if moved && self.enabled() {
            self.wake.notify_one();
        }
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<'static, Result<Item, Error>>> {
        self.current
            .load_full()
            .and_then(|provider| provider.resolve(endpoint_id))
    }
}

/// The addresses that identify which LAN this node is on. Public and
/// reflexive addresses are left out: they can change without a network
/// change, and each change would open a window.
fn lan_ips(data: &EndpointData) -> BTreeSet<IpAddr> {
    data.ip_addrs()
        .map(|addr| addr.ip())
        .filter(|ip| match ip {
            IpAddr::V4(v4) => {
                let [a, b, ..] = v4.octets();
                // 100.64.0.0/10 is carrier-grade NAT, the cellular case.
                v4.is_private() || v4.is_link_local() || (a == 100 && b & 0xc0 == 64)
            }
            IpAddr::V6(v6) => v6.is_unicast_link_local() || v6.is_unique_local(),
        })
        .collect()
}

impl MdnsDiscovery {
    pub(super) fn new(endpoint: &Endpoint, peers: Arc<LanPeers>) -> Result<Arc<Self>> {
        let discovery = Arc::new(Self {
            endpoint_id: endpoint.id(),
            current: ArcSwapOption::empty(),
            latest: ArcSwapOption::empty(),
            peers,
            enabled: AtomicBool::new(false),
            wake: Arc::new(Notify::new()),
            worker: AsyncMutex::new(None),
        });
        endpoint
            .address_lookup()
            .context("mDNS requires an open endpoint")?
            .add(Arc::clone(&discovery));
        Ok(discovery)
    }

    pub(super) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
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
        // The first window opens here so a failure reaches the caller.
        let events = self.open_window().await?;
        self.enabled.store(true, Ordering::Release);
        *worker = Some(tokio::spawn(run_windows(
            Arc::downgrade(self),
            Arc::clone(&self.peers),
            Arc::clone(&self.wake),
            events,
        )));
        tracing::info!(
            interval_secs = WINDOW_INTERVAL.as_secs(),
            window_secs = LISTEN_WINDOW.as_secs(),
            "mDNS discovery enabled (advertising _rayfish._udp.local)"
        );
        Ok(())
    }

    /// Bind the mDNS sockets and start advertising and browsing.
    async fn open_window(&self) -> Result<Events> {
        let provider = MdnsAddressLookup::builder()
            .service_name("rayfish")
            .discovery_cadence(QUERY_CADENCE)
            .advertise(true)
            .build(self.endpoint_id)
            .context("failed to start mDNS discovery")?;
        let events = provider.subscribe().await.boxed();
        if let Some(data) = self.latest.load_full() {
            provider.publish(&data);
        }
        self.current.store(Some(Arc::new(provider)));
        Ok(events)
    }

    pub(super) async fn stop(&self) {
        let mut worker = self.worker.lock().await;
        self.stop_locked(&mut worker).await;
    }

    /// Stop discovery if the daemon is dropped without explicit shutdown.
    pub(super) fn abort(&self) {
        self.enabled.store(false, Ordering::Release);
        self.current.store(None);
        if let Ok(mut worker) = self.worker.try_lock()
            && let Some(running) = worker.take()
        {
            running.abort();
        }
        self.peers.clear();
    }

    async fn stop_locked(&self, worker: &mut Option<JoinHandle<()>>) {
        self.enabled.store(false, Ordering::Release);
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

/// Run windows until stopped: listen, close the sockets, wait, reopen.
async fn run_windows(
    discovery: Weak<MdnsDiscovery>,
    peers: Arc<LanPeers>,
    wake: Arc<Notify>,
    first: Events,
) {
    let mut events = Some(first);
    loop {
        let reopen_now = match events.take() {
            Some(mut open) => {
                let reopen_now = listen(&peers, &wake, &mut open).await;
                let Some(discovery) = discovery.upgrade() else {
                    return;
                };
                discovery.current.store(None);
                peers.expire_unseen(SIGHTING_TTL);
                reopen_now
            }
            None => false,
        };
        if !reopen_now {
            tokio::select! {
                () = tokio::time::sleep(until_next_window(SystemTime::now())) => {}
                () = wake.notified() => {}
            }
        }
        let Some(discovery) = discovery.upgrade() else {
            return;
        };
        match discovery.open_window().await {
            Ok(open) => events = Some(open),
            Err(error) => tracing::warn!(%error, "failed to open mDNS discovery window"),
        }
    }
}

/// Time from `now` to the next wall-clock multiple of [`WINDOW_INTERVAL`].
fn until_next_window(now: SystemTime) -> Duration {
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let interval = WINDOW_INTERVAL.as_millis();
    let into_interval = since_epoch.as_millis() % interval;
    // Truncation is safe: the remainder is below one interval.
    Duration::from_millis((interval - into_interval) as u64)
}

/// Record sightings for one window. Returns true when the LAN addresses
/// changed mid-window, so the caller reopens on the new interfaces at once.
async fn listen(peers: &LanPeers, wake: &Notify, events: &mut Events) -> bool {
    let window = tokio::time::sleep(LISTEN_WINDOW);
    tokio::pin!(window);
    loop {
        tokio::select! {
            () = &mut window => return false,
            () = wake.notified() => {
                tracing::debug!("LAN addresses changed; restarting mDNS window");
                return true;
            }
            event = events.next() => match event {
                Some(DiscoveryEvent::Discovered { endpoint_info, .. }) => {
                    tracing::info!(
                        peer = %endpoint_info.endpoint_id.fmt_short(),
                        "mDNS: peer discovered on LAN"
                    );
                    peers.discovered(
                        endpoint_info.endpoint_id,
                        endpoint_info.ip_addrs().copied().collect(),
                    );
                }
                Some(DiscoveryEvent::Expired { endpoint_id }) => {
                    tracing::info!(peer = %endpoint_id.fmt_short(), "mDNS: peer left LAN");
                    peers.expired(&endpoint_id);
                }
                Some(_) => {}
                None => {
                    tracing::warn!("mDNS discovery window ended early");
                    return false;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayMode;
    use iroh::TransportAddr;
    use iroh::endpoint::presets;
    use tokio::time::timeout;

    /// Let spawned tasks run until `done` holds, without moving the paused clock.
    async fn settles(done: impl Fn() -> bool) -> bool {
        for _ in 0..1000 {
            if done() {
                return true;
            }
            tokio::task::yield_now().await;
        }
        done()
    }

    #[test]
    fn windows_land_on_wall_clock_boundaries() {
        let hour = UNIX_EPOCH + Duration::from_secs(1_800_000_000 / 3600 * 3600);
        assert_eq!(until_next_window(hour), WINDOW_INTERVAL);
        assert_eq!(
            until_next_window(hour + Duration::from_secs(61)),
            WINDOW_INTERVAL - Duration::from_secs(61)
        );
        assert_eq!(until_next_window(hour + WINDOW_INTERVAL), WINDOW_INTERVAL);
        assert_eq!(
            3600 % WINDOW_INTERVAL.as_secs(),
            0,
            "interval divides an hour"
        );
    }

    fn data(addrs: &[&str]) -> EndpointData {
        EndpointData::new(
            addrs
                .iter()
                .map(|a| TransportAddr::Ip(a.parse().unwrap()))
                .collect(),
        )
    }

    #[test]
    fn only_lan_addresses_identify_the_network() {
        let home = data(&["192.168.1.24:41641", "[fe80::1]:41641", "203.0.113.7:41641"]);
        let reflexive_moved = data(&[
            "192.168.1.24:41641",
            "[fe80::1]:41641",
            "198.51.100.9:41641",
        ]);
        let new_lan = data(&["10.0.0.5:41641", "[fe80::1]:41641", "203.0.113.7:41641"]);
        let cellular = data(&["100.72.3.4:41641"]);

        assert_eq!(lan_ips(&home), lan_ips(&reflexive_moved));
        assert_ne!(lan_ips(&home), lan_ips(&new_lan));
        assert_eq!(lan_ips(&cellular).len(), 1);
    }

    #[tokio::test]
    async fn window_closes_and_reopens_on_schedule() {
        let endpoint = Endpoint::builder(presets::N0)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let mdns = MdnsDiscovery::new(&endpoint, Arc::new(LanPeers::new())).unwrap();
        mdns.start().await.unwrap();
        assert!(
            mdns.current.load().is_some(),
            "the first window opens at start"
        );

        tokio::time::pause();
        // Let the scheduler start its window timer before moving the clock.
        settles(|| false).await;
        tokio::time::advance(LISTEN_WINDOW + Duration::from_secs(1)).await;
        assert!(
            settles(|| mdns.current.load().is_none()).await,
            "sockets close after the window"
        );
        assert!(mdns.enabled());

        tokio::time::advance(WINDOW_INTERVAL + Duration::from_secs(1)).await;
        assert!(
            settles(|| mdns.current.load().is_some()).await,
            "the next window opens after the interval"
        );

        mdns.stop().await;
        assert!(mdns.current.load().is_none());
        endpoint.close().await;
    }

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
