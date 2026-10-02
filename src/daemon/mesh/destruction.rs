//! Destruction is terminal for a network key. Save the proof before forgetting
//! membership, stop roster publication under its commit lock, then notify peers.

use futures::{StreamExt, stream};
use iroh_dns::pkarr::SignedPacket;

use super::super::*;
use crate::dht::destruction;

#[cfg(test)]
mod tests;

impl NetworkRegistry {
    pub(crate) async fn forget_destroyed_key(&self, packet: &SignedPacket) -> Result<()> {
        config::destruction::save(packet, None)?;
        config::remove_pending_join(&packet.public_key().to_string())?;
        for net in config::load()?.networks {
            if net
                .network_public_key
                .or_else(|| net.network_secret_key.as_ref().map(SecretKey::public))
                == Some(packet.public_key())
            {
                self.destroy_network(&net.name, packet.clone()).await?;
            }
        }
        Ok(())
    }

    pub(crate) fn schedule_destruction(self: &Arc<Self>, name: &str, packet: SignedPacket) {
        let registry = Arc::clone(self);
        let name = name.to_owned();
        tokio::spawn(async move {
            if let Err(error) = registry.destroy_network(&name, packet).await {
                tracing::warn!(network = %name, %error, "failed to finish network destruction");
            }
        });
    }

    pub(crate) async fn destroy_network(&self, name: &str, packet: SignedPacket) -> Result<()> {
        anyhow::ensure!(
            destruction::is_destroyed(&packet),
            "not a destruction record"
        );
        let network = packet.public_key();
        let state = self.networks.get(name).map(|h| Arc::clone(&h.state));
        let commit = match &state {
            Some(state) => Some(Arc::clone(
                &state
                    .read()
                    .map_err(|_| anyhow::anyhow!("network state lock poisoned"))?
                    .snapshot_commit,
            )),
            None => None,
        };
        let guard = match &commit {
            Some(commit) => Some(commit.lock().await),
            None => None,
        };
        let saved = config::load_network(name)?;
        let live_key = if let Some(state) = &state {
            let s = state
                .read()
                .map_err(|_| anyhow::anyhow!("network state lock poisoned"))?;
            anyhow::ensure!(
                s.network_public_key == network,
                "destruction is for a different network"
            );
            if s.destroyed {
                return Ok(());
            }
            s.network_secret_key.clone()
        } else if let Some(saved) = &saved {
            anyhow::ensure!(
                saved
                    .network_public_key
                    .or_else(|| saved.network_secret_key.as_ref().map(SecretKey::public))
                    == Some(network),
                "destruction is for a different network"
            );
            None
        } else {
            return Ok(());
        };
        let key = live_key.or_else(|| saved.as_ref().and_then(|s| s.network_secret_key.clone()));
        config::destruction::save(&packet, key.as_ref())?;
        if let Some(state) = &state {
            let mut s = state
                .write()
                .map_err(|_| anyhow::anyhow!("network state lock poisoned"))?;
            s.destroyed = true;
            s.network_secret_key = None;
        }
        drop(guard);

        // Notify every connected peer before closing any links. Wait for stream
        // delivery; enqueueing a FIN alone does not survive connection teardown.
        let mut targets = Vec::new();
        if key.is_some() {
            targets.extend(
                self.peers
                    .peers_for_network_with_conn(name)
                    .into_iter()
                    .map(|(id, _, conn)| (id, Some(conn))),
            );
            if let Some(state) = &state {
                for member in state
                    .read()
                    .map_err(|_| anyhow::anyhow!("network state lock poisoned"))?
                    .members
                    .all()
                {
                    if member.identity != self.transport.endpoint.id()
                        && !targets.iter().any(|(id, _)| *id == member.identity)
                    {
                        targets.push((member.identity, None));
                    }
                }
            }
        }
        let msg = ControlMsg::SignedRecord {
            packet: packet.as_bytes().to_vec(),
        };
        stream::iter(targets)
            .for_each_concurrent(16, |(id, conn)| {
                let msg = &msg;
                async move {
                    let delivered = tokio::time::timeout(Duration::from_secs(10), async {
                        let dialed = conn.is_none();
                        let conn = match conn {
                            Some(conn) => conn,
                            None => {
                                transport::connect_to_peer_with_alpn(
                                    &self.transport.endpoint,
                                    id,
                                    &transport::mesh_alpn(),
                                )
                                .await?
                            }
                        };
                        let (mut send, _) = conn.open_bi().await?;
                        control::send_msg(&mut send, Some(network), msg).await?;
                        let _ = send.stopped().await?;
                        if dialed {
                            let _ =
                                tokio::time::timeout(Duration::from_secs(1), conn.closed()).await;
                        }
                        anyhow::Ok(())
                    })
                    .await;
                    if !matches!(delivered, Ok(Ok(()))) {
                        tracing::debug!(
                            "destruction delivery missed; peer will discover the signed record"
                        );
                    }
                }
            })
            .await;

        // Keep the durable proof even when discovery is temporarily unavailable.
        // The daemon-wide publisher retries after membership has been removed.
        let removal = config::delete_network(name);
        let pending_removal = config::remove_pending_join(&network.to_string());
        self.teardown_network_runtime(name).await;
        let publication = async {
            let client = dht::create_pkarr_client(
                &self.transport.endpoint,
                &self.transport.pkarr_relay_url,
            )?;
            if let Some(key) = &key {
                destruction::publish(&client, &destruction::encode_index(key, &packet)?).await?;
            }
            destruction::publish(&client, &packet).await
        }
        .await;
        removal?;
        pending_removal?;
        publication.context(
            "network removed locally; destruction publication failed and will be retried",
        )?;
        tracing::info!(network = %name, "destroyed network");
        Ok(())
    }

    /// Local proofs survive restart. Key holders also consult the independent
    /// deletion record before restoring even when their roster cache is intact.
    pub(crate) async fn check_destruction(
        &self,
        name: &str,
        network: EndpointId,
        key: Option<&SecretKey>,
    ) -> Result<()> {
        let mut packet = config::destruction::load(network)?;
        if packet.is_none()
            && let Some(key) = key
        {
            let client = dht::create_pkarr_client(
                &self.transport.endpoint,
                &self.transport.pkarr_relay_url,
            )?;
            packet =
                destruction::resolve(&client, destruction::discovery_key(key).public(), network)
                    .await?;
        }
        if let Some(packet) = packet {
            self.destroy_network(name, packet).await?;
            anyhow::bail!("network has been destroyed");
        }
        Ok(())
    }

    pub(crate) async fn republish_destructions(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs((dht::RECORD_TTL / 2) as u64));
        loop {
            tokio::select! {
                _ = self.shutdown_token.cancelled() => return,
                _ = tick.tick() => {},
            }
            let result = async {
                let client = dht::create_pkarr_client(
                    &self.transport.endpoint,
                    &self.transport.pkarr_relay_url,
                )?;
                for packet in config::destruction::all()? {
                    tokio::select! {
                        _ = self.shutdown_token.cancelled() => return Ok(()),
                        result = destruction::publish(&client, &packet) => {
                            if let Err(error) = result {
                                tracing::debug!(%error, "will retry destruction record");
                            }
                        }
                    }
                }
                anyhow::Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%error, "will retry destruction publication");
            }
        }
    }
}
