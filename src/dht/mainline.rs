//! Pkarr over the BitTorrent Mainline DHT (unsalted BEP 44 mutable items).

use std::{sync::Mutex, time::Duration};

use anyhow::{Context, Result, ensure};
use futures::stream::{self, BoxStream, StreamExt};
use iroh::{
    EndpointId, SecretKey,
    address_lookup::{AddrFilter, AddressLookup, EndpointData, Error, Item},
    endpoint_info::EndpointInfo,
};
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use n0_mainline::{Dht, MutableItem};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tokio_util::task::AbortOnDropHandle;

use super::{PUBLISH_TIMEOUT, RESOLVE_TIMEOUT};
use crate::config::ServerOverride;

#[derive(Clone, Debug)]
pub(crate) struct Mainline(watch::Receiver<Option<Dht>>);

impl Mainline {
    pub(crate) fn start(discovery: &ServerOverride) -> Option<Self> {
        if discovery.replace && !discovery.is_unset() {
            return None;
        }
        let (ready, client) = watch::channel(None);
        // Bootstrap hostname resolution is synchronous. Let iroh bind and the
        // daemon start while that runs.
        tokio::task::spawn_blocking(move || match Dht::builder().port(0).build() {
            Ok(dht) => {
                let _ = ready.send(Some(dht));
            }
            Err(error) => tracing::warn!(%error, "could not start Mainline DHT"),
        });
        Some(Self(client))
    }

    async fn client(&self) -> Result<Dht> {
        self.0
            .clone()
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|client| client.clone())
            .context("Mainline DHT client unavailable")
    }

    /// A DHT that stays unavailable for as long as the sender lives.
    #[cfg(test)]
    pub(super) fn never_ready() -> (watch::Sender<Option<Dht>>, Self) {
        let (sender, client) = watch::channel(None);
        (sender, Self(client))
    }

    #[cfg(test)]
    pub(super) fn for_test(dht: Dht) -> Self {
        Self(watch::channel(Some(dht)).1)
    }

    pub(super) async fn resolve(&self, key: EndpointId) -> Result<Option<SignedPacket>> {
        timeout(RESOLVE_TIMEOUT, async {
            let dht = self.client().await?;
            // Both requests use the same target. Mainline shares the in-flight
            // query and reports its responding nodes separately from its values.
            let target = MutableItem::target_from_key(key.as_bytes(), None);
            let (item, nodes) = tokio::try_join!(
                dht.get_mutable_most_recent(key.as_bytes(), None),
                dht.get_closest_nodes(target),
            )?;
            let Some(item) = item else {
                ensure!(!nodes.is_empty(), "no Mainline DHT nodes answered");
                return Ok(None);
            };
            ensure!(
                item.key() == key.as_bytes(),
                "wrong Mainline DHT record key"
            );
            let timestamp = Timestamp::from_micros(item.seq().try_into()?);
            // Mainline has already verified the BEP 44 signature.
            let packet = SignedPacket::from_parts_unchecked(
                item.key(),
                item.signature(),
                timestamp,
                item.value(),
            )?;
            Ok(Some(packet))
        })
        .await
        .context("timed out resolving Mainline DHT record")?
    }

    pub(super) async fn publish(&self, packet: &SignedPacket) -> Result<()> {
        let item = MutableItem::new_signed_unchecked(
            *packet.public_key().as_bytes(),
            packet.signature().to_bytes(),
            packet.encoded_packet(),
            packet.timestamp().as_micros().try_into()?,
            None,
        );
        timeout(PUBLISH_TIMEOUT, async {
            self.client().await?.put_mutable(item, None).await?;
            Ok(())
        })
        .await
        .context("timed out publishing Mainline DHT record")?
    }
}

/// Shares the daemon's DHT client with iroh's endpoint discovery.
#[derive(Debug)]
pub(crate) struct EndpointLookup {
    mainline: Mainline,
    key: SecretKey,
    publisher: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl EndpointLookup {
    pub(crate) fn new(mainline: Mainline, key: SecretKey) -> Self {
        Self {
            mainline,
            key,
            publisher: Mutex::new(None),
        }
    }
}

impl AddressLookup for EndpointLookup {
    fn publish(&self, data: &EndpointData) {
        // Match iroh's default public pkarr publisher.
        let data = data.apply_filter(&AddrFilter::relay_only()).into_owned();
        let Ok(mut publisher) = self.publisher.lock() else {
            return;
        };
        *publisher = None;
        if !data.has_addrs() {
            return;
        }
        let info = EndpointInfo::from_parts(self.key.public(), data);
        let packet = match info.to_pkarr_signed_packet(&self.key, 30) {
            Ok(packet) => packet,
            Err(error) => {
                tracing::debug!(%error, "could not sign Mainline endpoint record");
                return;
            }
        };
        let mainline = self.mainline.clone();
        *publisher = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            // Debounce address changes that arrive together during a rebind.
            sleep(Duration::from_millis(50)).await;
            loop {
                let delay = match mainline.publish(&packet).await {
                    Ok(()) => Duration::from_secs(60 * 60),
                    Err(error) => {
                        tracing::debug!(%error, "could not publish Mainline endpoint record");
                        Duration::from_secs(30)
                    }
                };
                sleep(delay).await;
            }
        })));
    }

    fn resolve(&self, key: EndpointId) -> Option<BoxStream<'static, Result<Item, Error>>> {
        let mainline = self.mainline.clone();
        Some(Box::pin(
            stream::once(async move {
                let packet = match mainline.resolve(key).await {
                    Ok(Some(packet)) => packet,
                    Ok(None) => return None,
                    Err(error) => {
                        tracing::debug!(%error, "could not resolve Mainline endpoint record");
                        return None;
                    }
                };
                let info = EndpointInfo::from_pkarr_signed_packet(&packet).ok()?;
                Some(Ok(Item::new(
                    info,
                    "mainline",
                    Some(packet.timestamp().as_micros()),
                )))
            })
            .filter_map(futures::future::ready),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayUrl, TransportAddr};
    use n0_mainline::Testnet;

    #[tokio::test]
    async fn endpoint_lookup_publishes_relay_address_on_mainline() {
        let testnet = Testnet::new(5).await.unwrap();
        let new_dht = || {
            Mainline::for_test(
                Dht::builder()
                    .bootstrap(&testnet.bootstrap)
                    .build()
                    .unwrap(),
            )
        };
        let key = SecretKey::generate();
        let id = key.public();
        let relay: RelayUrl = "https://relay.example.test".parse().unwrap();
        let publisher = EndpointLookup::new(new_dht(), key);
        let resolver = EndpointLookup::new(new_dht(), SecretKey::generate());
        publisher.publish(&EndpointData::new(vec![
            TransportAddr::Relay(relay.clone()),
            TransportAddr::Ip("192.0.2.1:1234".parse().unwrap()),
        ]));

        let item = timeout(Duration::from_secs(10), async {
            let mut poll = tokio::time::interval(Duration::from_millis(100));
            loop {
                poll.tick().await;
                if let Some(result) = resolver.resolve(id).unwrap().next().await {
                    break result.unwrap();
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(item.endpoint_id(), id);
        assert_eq!(
            item.to_endpoint_addr().addrs,
            [TransportAddr::Relay(relay)].into()
        );
    }
}
