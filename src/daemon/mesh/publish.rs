//! DHT publishers for the mesh core: the notify-driven network-record
//! publisher, the contact-record publisher (`ray connect`), the lazy
//! co-coordinator publisher, and the shared snapshot-refresh + publish step.
//! Also holds the thin `Daemon` direct-connection (`ray connect`) handlers that
//! delegate to `ConnectService`.

use super::super::*;

/// Renew records with enough margin for scheduler/network delay that a healthy
/// coordinator never lets its five-minute pkarr lease expire.
const RECORD_REPUBLISH_INTERVAL: Duration = Duration::from_secs((dht::RECORD_TTL / 2) as u64);

async fn snapshot_is_publishable(blob_store: &FsStore, network: &str, hash: blake3::Hash) -> bool {
    let hash_is_persisted = config::load_network(network)
        .ok()
        .flatten()
        .is_some_and(|net| net.last_group_hash == Some(hash));
    if !hash_is_persisted {
        tracing::warn!(network, %hash, "not publishing a group snapshot without a recovery pointer");
        return false;
    }
    let blob_hash = iroh_blobs::Hash::from_bytes(*hash.as_bytes());
    if blob_store.blobs().get_bytes(blob_hash).await.is_err() {
        tracing::warn!(network, %hash, "not publishing a group snapshot absent from local storage");
        return false;
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_network_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    blob_store: FsStore,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            {
                let commit = state.read().unwrap().snapshot_commit.clone();
                let _commit = commit.lock().await;
                if let Some(hash) = config::load_network(&network_name)
                    .ok()
                    .flatten()
                    .and_then(|net| net.last_group_hash)
                    && snapshot_is_publishable(&blob_store, &network_name, hash).await
                {
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
                            tracing::info!(peers = seed_peers.len(), "published network record")
                        }
                        Err(e) => tracing::warn!(error = %e, "failed to publish network record"),
                    }
                }
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = notify.notified() => {},
                _ = tokio::time::sleep(RECORD_REPUBLISH_INTERVAL) => {},
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
                _ = tokio::time::sleep(RECORD_REPUBLISH_INTERVAL) => {},
            }
        }
    })
}

/// A polling publisher for a *granted* co-coordinator (a member that received
/// the network key via `AdminGrant`). Unlike [`spawn_network_publisher`] (which
/// is notify-driven and spawned at create/restore time), this is spawned at
/// runtime when a member is promoted: it has no `dht_notify` handle, so it
/// re-reads the snapshot hash every few seconds and republishes on change.
/// Latency is bounded by `LAZY_PUBLISH_INTERVAL`; members' group poller is
/// the downstream backstop regardless.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_lazy_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    blob_store: FsStore,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    token: CancellationToken,
) -> JoinHandle<()> {
    const LAZY_PUBLISH_INTERVAL: Duration = Duration::from_secs(10);
    tokio::spawn(async move {
        let mut last_publish: Option<(blake3::Hash, Instant)> = None;
        loop {
            let hash = config::load_network(&network_name)
                .ok()
                .flatten()
                .and_then(|net| net.last_group_hash);
            let publish_due = hash.is_some_and(|hash| {
                last_publish.is_none_or(|(last_hash, published_at)| {
                    last_hash != hash || published_at.elapsed() >= RECORD_REPUBLISH_INTERVAL
                })
            });
            if let Some(hash) = hash
                && publish_due
            {
                let commit = state.read().unwrap().snapshot_commit.clone();
                let _commit = commit.lock().await;
                if snapshot_is_publishable(&blob_store, &network_name, hash).await {
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
                            last_publish = Some((hash, Instant::now()));
                        }
                        Err(e) => tracing::warn!(error = %e, "lazy publisher: publish failed"),
                    }
                }
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(LAZY_PUBLISH_INTERVAL) => {},
            }
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotPersist {
    Persisted,
    Superseded,
    Failed,
}

fn persist_current_snapshot_hash(
    state: &SharedNetworkState,
    network: &str,
    hash: blake3::Hash,
) -> SnapshotPersist {
    let mut current = false;
    match config::update_network(network, |net| {
        current = state
            .read()
            .unwrap()
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.hash == hash);
        if current {
            net.last_group_hash = Some(hash);
        }
        Ok(())
    }) {
        Ok(Some(_)) if current => SnapshotPersist::Persisted,
        Ok(Some(_)) => SnapshotPersist::Superseded,
        Ok(None) => {
            tracing::warn!(
                network,
                "failed to persist group snapshot hash: network was deleted"
            );
            SnapshotPersist::Failed
        }
        Err(e) => {
            tracing::warn!(network, error = %e, "failed to persist complete group snapshot hash");
            SnapshotPersist::Failed
        }
    }
}

pub(crate) fn persist_group_hash_locked(
    state: &SharedNetworkState,
    network: &str,
    hash: blake3::Hash,
) -> bool {
    let mut current = false;
    match config::update_network(network, |net| {
        current = state.read().unwrap().converged_hash == Some(hash);
        if current {
            net.last_group_hash = Some(hash);
        }
        Ok(())
    }) {
        Ok(Some(_)) => current,
        Ok(None) => {
            tracing::warn!(
                network,
                "failed to persist group snapshot hash: network was deleted"
            );
            false
        }
        Err(e) => {
            tracing::warn!(network, error = %e, "failed to persist complete group snapshot hash");
            false
        }
    }
}

/// Commit the latest snapshot while the caller holds this state's
/// `snapshot_commit` guard.
pub(crate) async fn commit_current_snapshot(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
) -> bool {
    let ready_to_publish = loop {
        let snapshot = {
            let mut s = state.write().unwrap();
            s.refresh_snapshot();
            if s.network_secret_key.is_some() {
                s.converged_hash = None;
            }
            s.snapshot.as_ref().map(|snap| {
                (
                    s.network_name.clone(),
                    snap.hash,
                    snap.msgpack_bytes.clone(),
                )
            })
        };
        let Some((network, hash, bytes)) = snapshot else {
            break false;
        };
        if let Err(e) = blob_store.blobs().add_slice(&bytes).await {
            tracing::warn!(error = %e, "failed to store complete group snapshot");
            break false;
        }
        let outcome = match network.as_deref() {
            Some(network) => persist_current_snapshot_hash(state, network, hash),
            None => {
                if state
                    .read()
                    .unwrap()
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.hash == hash)
                {
                    SnapshotPersist::Persisted
                } else {
                    SnapshotPersist::Superseded
                }
            }
        };
        match outcome {
            SnapshotPersist::Persisted => break true,
            SnapshotPersist::Superseded => continue,
            SnapshotPersist::Failed => break false,
        }
    };
    if ready_to_publish && let Some(notify) = dht_notify {
        notify.notify_one();
    }
    ready_to_publish
}

pub(crate) async fn update_snapshot_and_publish(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
) -> bool {
    let commit = state.read().unwrap().snapshot_commit.clone();
    let _commit = commit.lock().await;
    commit_current_snapshot(state, blob_store, dht_notify).await
}

impl Daemon {
    /// `ray connect <contact-id>`: request a direct connection by contact id.
    pub(crate) async fn connect(&self, contact_id: &str, hostname: Option<String>) -> IpcMessage {
        self.connect.connect(contact_id, hostname).await
    }

    /// `ray connect`: list pending incoming connect requests.
    pub fn list_connections(&self) -> IpcMessage {
        self.connect.list_connections()
    }

    /// Decline a pending connect request: drop it without minting a network. The
    /// requester's retry loop eventually times out.
    pub fn reject_connect(&self, id_prefix: &str) -> IpcMessage {
        self.connect.reject_connect(id_prefix)
    }

    /// `ray connect approve <id>`: approve a pending connect request, minting
    /// a 2-peer network with the requester pre-approved.
    pub async fn approve_connection(&self, id_prefix: &str) -> IpcMessage {
        self.connect.approve_connection(id_prefix).await
    }

    /// `ray contact rotate`: replace this node's contact key. The old contact id
    /// stops resolving once its pkarr record expires (~5 min).
    pub(crate) async fn rotate_contact(&self) -> IpcMessage {
        self.connect.rotate_contact().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CONFIG_ENV_LOCK;

    fn state_with_snapshot(hash: blake3::Hash) -> SharedNetworkState {
        Arc::new(RwLock::new(NetworkState {
            members: MemberList::new(),
            approved: ApprovedList::new(),
            snapshot: Some(GroupSnapshot {
                hash,
                msgpack_bytes: Vec::new(),
            }),
            snapshot_commit: Arc::new(AsyncMutex::new(())),
            converged_hash: None,
            network_secret_key: None,
            network_public_key: SecretKey::generate().public(),
            network_name: Some("test".to_string()),
            mode: GroupMode::Restricted,
            suggested_firewall: SuggestedFirewall::default(),
            reusable_keys: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            last_record_timestamp: None,
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        }))
    }

    #[test]
    fn superseded_snapshot_cannot_replace_the_newer_recovery_pointer() {
        let _lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let config_dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", config_dir.path()) };

        let old = blake3::hash(b"old snapshot");
        let current = blake3::hash(b"current snapshot");
        let state = state_with_snapshot(current);
        let mut net = config::empty_network_config("test");
        net.last_group_hash = Some(current);
        config::save_network(&net).unwrap();

        assert_eq!(
            persist_current_snapshot_hash(&state, "test", old),
            SnapshotPersist::Superseded
        );
        assert_eq!(
            config::load_network("test")
                .unwrap()
                .unwrap()
                .last_group_hash,
            Some(current)
        );

        unsafe {
            match previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)] // serializes this process-global env override
    async fn publication_requires_both_the_recovery_pointer_and_blob() {
        let _lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let config_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", config_dir.path()) };

        let store = FsStore::load(blobs_dir.path()).await.unwrap();
        let bytes = b"complete signed group";
        let hash = blake3::hash(bytes);
        let mut net = config::empty_network_config("test");
        net.last_group_hash = Some(hash);
        config::save_network(&net).unwrap();

        assert!(!snapshot_is_publishable(&store, "test", hash).await);
        store.blobs().add_slice(bytes).await.unwrap();
        assert!(snapshot_is_publishable(&store, "test", hash).await);

        config::update_network("test", |net| {
            net.last_group_hash = Some(blake3::hash(b"newer complete group"));
            Ok(())
        })
        .unwrap();
        assert!(!snapshot_is_publishable(&store, "test", hash).await);

        unsafe {
            match previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}
