//! DHT publishers for the mesh core: the notify-driven network-record
//! publisher, the contact-record publisher (`ray connect`), the lazy
//! co-coordinator publisher, and the shared snapshot-refresh + publish step.

use super::super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_network_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let hash = {
                let s = state.read().unwrap();
                s.snapshot
                    .as_ref()
                    .map(|snap| snap.hash)
                    .unwrap_or_else(|| {
                        group_blob_hash(
                            &s.members,
                            &s.approved,
                            &s.suggested_firewall,
                            s.network_name.as_deref(),
                            &s.reusable_keys,
                        )
                    })
            };
            let mut seed_peers: Vec<EndpointId> = peers
                .peers_for_network(&network_name)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            seed_peers.push(endpoint_id);
            seed_peers.sort_by_key(|id| id.to_string());
            seed_peers.dedup();

            match dht::publish_network(&client, &net_secret_key, &hash, &seed_peers).await {
                Ok(()) => tracing::info!(peers = seed_peers.len(), "published network record"),
                Err(e) => tracing::warn!(error = %e, "failed to publish network record"),
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(300)) => {},
            }
        }
    })
}

/// Publish this node's contact record (`ray connect`).
/// Publishes the `contact_key -> current endpoint` pkarr record on a TTL/2
/// interval (record TTL is 300s). Runs for the lifetime of the daemon (control
/// plane), not gated by the data-plane `active` flag, so standby nodes stay
/// reachable for `ray connect` requests. Reads `contact_secret` fresh from
/// config each cycle so a `RotateContact` takes effect without a restart.
pub(crate) fn spawn_contact_publisher(
    client: PkarrRelayClient,
    endpoint_id: EndpointId,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let secret = config::load().ok().and_then(|c| c.contact_secret_key);
            if let Some(secret) = secret {
                match dht::publish_contact(&client, &secret, endpoint_id).await {
                    Ok(()) => {
                        tracing::debug!(contact = %secret.public().fmt_short(), "published contact record")
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to publish contact record"),
                }
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(150)) => {},
            }
        }
    })
}

/// Republish this user's revoked device set (`ray unpair`). Publishes
/// `user_key -> {version, devices}` on a TTL/2 interval so the set stays
/// resolvable while this daemon runs (not gated by the data-plane `active` flag,
/// so a standby node still advertises it). Only the primary signs it — its
/// endpoint secret *is* the user identity that signed the certs. A secondary
/// never revokes, so its set stays empty and nothing is published. Reads config
/// fresh each cycle so a new revoke/re-auth takes effect without a restart.
pub(crate) fn spawn_revocation_publisher(
    client: PkarrRelayClient,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let is_primary = crate::identity::load_device_cert().ok().flatten().is_none();
            let cfg = config::load().unwrap_or_default();
            let devices = config::revoked_device_ids(&cfg);
            // Publish whenever we have ever revoked (version > 0), even if the set
            // is now empty: a re-auth clears the set at a newer version, and remote
            // peers only un-revoke when they see that newer (empty) record.
            if is_primary
                && cfg.revocation_version > 0
                && let Ok(secret) = crate::identity::load_or_create()
            {
                match dht::publish_revoked(&client, &secret, cfg.revocation_version, &devices).await
                {
                    Ok(()) => tracing::debug!(
                        version = cfg.revocation_version,
                        count = devices.len(),
                        "published revoked-device set"
                    ),
                    Err(e) => tracing::warn!(error = %e, "failed to publish revoked-device record"),
                }
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(150)) => {},
            }
        }
    })
}

/// Keep the [`RevocationCache`] warm. Every 60s, resolve the revoked device set
/// for each user identity visible in any roster (plus our own), so a revoked
/// device's cert is rejected at admission and severed on the next reconverge even
/// when the revoking user is a *different* user we share a network with. This only
/// supplies the facts; the per-network group poller's reconverge does the actual
/// pruning (`prune_departed_peers`).
pub(crate) fn spawn_revocation_poller(
    daemon: Arc<MeshManager>,
    client: PkarrRelayClient,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(60)) => {},
            }
            let mut users: std::collections::HashSet<EndpointId> = std::collections::HashSet::new();
            let own_user = daemon
                .device_cert
                .as_ref()
                .map(|c| c.user_identity)
                .unwrap_or_else(|| daemon.endpoint.id());
            users.insert(own_user);
            for handle in daemon.networks.iter() {
                let roster = handle.state.read().unwrap().roster();
                for m in roster {
                    if let Some(u) = m.user_identity {
                        users.insert(u);
                    }
                }
            }
            let mut raised = false;
            for user in users {
                if !daemon.revocation.needs_refresh(&user) {
                    continue;
                }
                match dht::resolve_revoked(&client, user).await {
                    // A newer version means the revoked set changed (a device was
                    // just unpaired): prune any now-revoked peer right away instead
                    // of waiting for the next 60s group poll on each network.
                    Ok((version, devices)) => {
                        raised |= daemon
                            .revocation
                            .record(user, version, devices.into_iter().collect())
                    }
                    // No record (never published / TTL-expired) is the common case;
                    // fail open (leave the cache as-is) rather than clear it.
                    Err(e) => tracing::trace!(user = %user.fmt_short(), error = %e, "no revoked-device record"),
                }
            }
            if raised {
                daemon.prune_revoked_across_networks();
            }
        }
    })
}

/// A polling publisher for a *granted* co-coordinator (a member that received
/// the network key via `AdminGrant`). Unlike [`spawn_network_publisher`] (which
/// is notify-driven and spawned at create/restore time), this is spawned at
/// runtime when a member is promoted: it has no `dht_notify` handle, so it
/// re-reads the snapshot hash every few seconds and republishes on change.
/// Latency is bounded by `LAZY_PUBLISH_INTERVAL`; members' 60s group poller is
/// the downstream backstop regardless.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_lazy_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    token: CancellationToken,
) -> JoinHandle<()> {
    const LAZY_PUBLISH_INTERVAL: Duration = Duration::from_secs(10);
    tokio::spawn(async move {
        let mut last_hash: Option<blake3::Hash> = None;
        loop {
            let hash = {
                let s = state.read().unwrap();
                s.snapshot
                    .as_ref()
                    .map(|snap| snap.hash)
                    .unwrap_or_else(|| {
                        group_blob_hash(
                            &s.members,
                            &s.approved,
                            &s.suggested_firewall,
                            s.network_name.as_deref(),
                            &s.reusable_keys,
                        )
                    })
            };
            if last_hash != Some(hash) {
                let mut seed_peers: Vec<EndpointId> = peers
                    .peers_for_network(&network_name)
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect();
                seed_peers.push(endpoint_id);
                seed_peers.sort_by_key(|id| id.to_string());
                seed_peers.dedup();
                match dht::publish_network(&client, &net_secret_key, &hash, &seed_peers).await {
                    Ok(()) => {
                        tracing::info!(
                            network = %network_name,
                            "lazy publisher: published network record"
                        );
                        last_hash = Some(hash);
                    }
                    Err(e) => tracing::warn!(error = %e, "lazy publisher: publish failed"),
                }
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(LAZY_PUBLISH_INTERVAL) => {},
            }
        }
    })
}

pub(crate) async fn update_snapshot_and_publish(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
) {
    let snap_bytes = {
        let mut s = state.write().unwrap();
        s.refresh_snapshot();
        s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
    };
    if let Some(bytes) = snap_bytes {
        let _ = blob_store.blobs().add_slice(&bytes).await;
    }
    if let Some(notify) = dht_notify {
        notify.notify_one();
    }
}
