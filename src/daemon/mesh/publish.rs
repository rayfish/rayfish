//! DHT publishers for the mesh core: the notify-driven network-record
//! publisher, the contact-record publisher (`ray connect`), the lazy
//! co-coordinator publisher, and the shared snapshot-refresh + publish step.
//! Also holds the thin `Daemon` direct-connection (`ray connect`) handlers that
//! delegate to `ConnectService`.

use super::super::*;

/// Renew records with enough margin for scheduler/network delay that a healthy
/// coordinator never lets its five-minute pkarr lease expire.
const RECORD_REPUBLISH_INTERVAL: Duration = Duration::from_secs((dht::RECORD_TTL / 2) as u64);

/// Re-import verified bytes to mint the permanent tag that protects membership
/// snapshots from blob GC. Remote fetches populate the store without a tag.
pub(crate) async fn retain_group_blob(blob_store: &FsStore, bytes: &[u8]) -> Result<()> {
    blob_store
        .blobs()
        .add_slice(bytes)
        .await
        .context("retain verified group blob")?;
    Ok(())
}

pub(crate) async fn snapshot_is_publishable(
    blob_store: &FsStore,
    state: &SharedNetworkState,
    network: &str,
    hash: blake3::Hash,
) -> bool {
    let publishable_generation = {
        let live = state.read().unwrap();
        if live.converged_hash != Some(hash) {
            tracing::warn!(network, %hash, "not publishing a group snapshot that differs from live state");
            false
        } else if live.unconfirmed_durable_hash.is_some() {
            tracing::warn!(network, %hash, "not publishing a group snapshot before its durability retry succeeds");
            false
        } else {
            true
        }
    };
    if !publishable_generation {
        return false;
    }
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

/// Retry a failed persistence/publication attempt well before the existing
/// five-minute record can expire. The deadline is absolute: notifications wake
/// the loop to inspect changed state but do not push this retry back.
const RECORD_PUBLISH_RETRY_INTERVAL: Duration = Duration::from_secs(5);

fn mark_group_hash_durability_pending(
    state: &SharedNetworkState,
    hash: blake3::Hash,
    published: bool,
) {
    let mut state = state.write().unwrap();
    if state.converged_hash == Some(hash) {
        let published = state
            .unconfirmed_durable_hash
            .filter(|pending| pending.hash == hash)
            .is_some_and(|pending| pending.published)
            || published;
        state.unconfirmed_durable_hash = Some(PendingSnapshotDurability { hash, published });
    }
}

fn confirm_current_group_hash_durable(state: &SharedNetworkState, hash: blake3::Hash) {
    let mut state = state.write().unwrap();
    if state.converged_hash == Some(hash) {
        // A durable current generation supersedes every older rename outcome.
        state.unconfirmed_durable_hash = None;
    }
}

fn configured_group_hash(network: &str) -> Option<blake3::Hash> {
    config::load_network(network)
        .ok()
        .flatten()
        .and_then(|net| net.last_group_hash)
}

fn group_hash_needing_persistence(
    state: &SharedNetworkState,
    network: &str,
    published: bool,
) -> Option<blake3::Hash> {
    let (converged, durability_pending) = {
        let state = state.read().unwrap();
        (state.converged_hash?, state.unconfirmed_durable_hash)
    };
    let configured = config::load_network(network).ok().flatten();
    let needs_write = durability_pending.is_some()
        || configured.as_ref().is_none_or(|net| {
            net.last_group_hash != Some(converged) || published && !net.last_group_hash_published
        });
    needs_write.then_some(converged)
}

pub(crate) fn pending_authored_group_hash(
    state: &SharedNetworkState,
    network: &str,
) -> Option<blake3::Hash> {
    let converged = {
        let state = state.read().unwrap();
        state.network_secret_key.as_ref()?;
        state.converged_hash?
    };
    let net = config::load_network(network).ok().flatten()?;
    (net.last_group_hash == Some(converged) && !net.last_group_hash_published).then_some(converged)
}

fn attempt_is_due(
    hash: blake3::Hash,
    last_publish: Option<(blake3::Hash, Instant)>,
    retry: Option<(blake3::Hash, Instant)>,
    now: Instant,
) -> bool {
    if retry.is_some_and(|(retry_hash, deadline)| retry_hash == hash && now < deadline) {
        return false;
    }
    last_publish.is_none_or(|(last_hash, published_at)| {
        last_hash != hash || now.duration_since(published_at) >= RECORD_REPUBLISH_INTERVAL
    })
}

fn next_attempt_deadline(
    target: Option<blake3::Hash>,
    last_publish: Option<(blake3::Hash, Instant)>,
    retry: Option<(blake3::Hash, Instant)>,
    now: Instant,
) -> Instant {
    let Some(hash) = target else {
        return now + RECORD_REPUBLISH_INTERVAL;
    };
    if let Some((retry_hash, deadline)) = retry
        && retry_hash == hash
        && deadline > now
    {
        return deadline;
    }
    match last_publish {
        Some((last_hash, published_at)) if last_hash == hash => {
            published_at + RECORD_REPUBLISH_INTERVAL
        }
        _ => now,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_network_publisher(
    client: PkarrClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    blob_store: FsStore,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    initially_published: Option<blake3::Hash>,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_publish: Option<(blake3::Hash, Instant)> =
            initially_published.map(|hash| (hash, Instant::now()));
        let mut retry: Option<(blake3::Hash, Instant)> = None;
        loop {
            let now = Instant::now();
            let needs_persistence = group_hash_needing_persistence(&state, &network_name, false);
            let configured = configured_group_hash(&network_name);
            let target = needs_persistence.or(configured);
            let due = target.is_some_and(|hash| {
                let retry_blocked = retry
                    .is_some_and(|(retry_hash, deadline)| retry_hash == hash && now < deadline);
                !retry_blocked
                    && (needs_persistence.is_some()
                        || attempt_is_due(hash, last_publish, retry, now))
            });

            if due {
                let commit = state.read().unwrap().snapshot_commit.clone();
                let _commit = commit.lock().await;
                let mut persistence_ready = true;
                if let Some(hash) = group_hash_needing_persistence(&state, &network_name, false) {
                    persistence_ready =
                        persist_group_hash_locked(&state, &blob_store, &network_name, hash, false)
                            .await;
                    if !persistence_ready {
                        retry = Some((hash, Instant::now() + RECORD_PUBLISH_RETRY_INTERVAL));
                    }
                }

                if persistence_ready
                    && let Some(hash) = configured_group_hash(&network_name)
                    && attempt_is_due(hash, last_publish, retry, Instant::now())
                {
                    if snapshot_is_publishable(&blob_store, &state, &network_name, hash).await {
                        let mut seed_peers: Vec<EndpointId> = peers
                            .peers_for_network(&network_name)
                            .into_iter()
                            .map(|(id, _)| id)
                            .collect();
                        seed_peers.push(endpoint_id);
                        seed_peers.sort_by_key(|id| id.to_string());
                        seed_peers.dedup();

                        match dht::publish_network(&client, &net_secret_key, &hash, &seed_peers)
                            .await
                        {
                            Ok(_) => {
                                if mark_group_hash_published(&network_name, hash) {
                                    tracing::info!(
                                        peers = seed_peers.len(),
                                        "published network record"
                                    );
                                    last_publish = Some((hash, Instant::now()));
                                    retry = None;
                                } else {
                                    retry = Some((
                                        hash,
                                        Instant::now() + RECORD_PUBLISH_RETRY_INTERVAL,
                                    ));
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to publish network record");
                                retry =
                                    Some((hash, Instant::now() + RECORD_PUBLISH_RETRY_INTERVAL));
                            }
                        }
                    } else {
                        retry = Some((hash, Instant::now() + RECORD_PUBLISH_RETRY_INTERVAL));
                    }
                }
            }

            let now = Instant::now();
            let target = group_hash_needing_persistence(&state, &network_name, false)
                .or_else(|| configured_group_hash(&network_name));
            let deadline = next_attempt_deadline(target, last_publish, retry, now);
            tokio::select! {
                _ = token.cancelled() => break,
                _ = notify.notified() => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {},
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
    client: PkarrClient,
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
    // The caller holds `snapshot_commit`, so this generation cannot change while
    // the config transaction runs. Read it before taking the process-wide config
    // lock to preserve the state -> config lock order used by mutation paths.
    let current = state
        .read()
        .unwrap()
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.hash == hash);
    if !current {
        return SnapshotPersist::Superseded;
    }
    match config::update_network(network, |net| {
        net.last_group_hash = Some(hash);
        net.last_group_hash_published = false;
        Ok(())
    }) {
        Ok(Some(_)) => {
            confirm_current_group_hash_durable(state, hash);
            SnapshotPersist::Persisted
        }
        Ok(None) => {
            mark_group_hash_durability_pending(state, hash, false);
            tracing::warn!(
                network,
                "failed to persist group snapshot hash: network was deleted"
            );
            SnapshotPersist::Failed
        }
        Err(e) => {
            // Atomic rename may have installed this exact generation before the
            // parent-directory sync failed. Treat every such error as ambiguous
            // until an exact retry completes its durability barrier.
            mark_group_hash_durability_pending(state, hash, false);
            tracing::warn!(network, error = %e, "failed to persist complete group snapshot hash");
            SnapshotPersist::Failed
        }
    }
}

pub(crate) async fn persist_group_hash_locked(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    network: &str,
    hash: blake3::Hash,
    published: bool,
) -> bool {
    // Every caller holds `snapshot_commit`, so capture all state before entering
    // the config transaction. Config callbacks must never take a NetworkState
    // guard: mutation paths use the opposite (state -> config) lock order.
    let (current, snapshot_bytes, pending_published) = {
        let state = state.read().unwrap();
        (
            state.converged_hash == Some(hash),
            state
                .snapshot
                .as_ref()
                .filter(|snapshot| snapshot.hash == hash)
                .map(|snapshot| snapshot.msgpack_bytes.clone()),
            state
                .unconfirmed_durable_hash
                .filter(|pending| pending.hash == hash)
                .map(|pending| pending.published),
        )
    };
    if !current {
        return false;
    }
    // An exact retry preserves the provenance of the failed write rather than
    // letting whichever caller noticed it reinterpret a fetched generation as
    // locally authored (or vice versa).
    let published = pending_published.unwrap_or(published);
    let blob_hash = iroh_blobs::Hash::from_bytes(*hash.as_bytes());
    if let Err(missing_error) = blob_store.blobs().get_bytes(blob_hash).await {
        // A transient store failure may have left the authored snapshot live but
        // not imported. Its bytes remain in state, so retry the missing first
        // step instead of waiting forever for a blob that no task recreates.
        let Some(bytes) = snapshot_bytes else {
            mark_group_hash_durability_pending(state, hash, published);
            tracing::warn!(
                network,
                %hash,
                error = %missing_error,
                "failed to persist recovery pointer for a group snapshot absent from local storage"
            );
            return false;
        };
        if let Err(e) = blob_store.blobs().add_slice(&bytes).await {
            mark_group_hash_durability_pending(state, hash, published);
            tracing::warn!(
                network,
                %hash,
                error = %e,
                "failed to retry storing complete group snapshot"
            );
            return false;
        }
    }
    match config::update_network(network, |net| {
        net.last_group_hash = Some(hash);
        net.last_group_hash_published = published;
        Ok(())
    }) {
        Ok(Some(_)) => {
            confirm_current_group_hash_durable(state, hash);
            true
        }
        Ok(None) => {
            mark_group_hash_durability_pending(state, hash, published);
            tracing::warn!(
                network,
                "failed to persist group snapshot hash: network was deleted"
            );
            false
        }
        Err(e) => {
            mark_group_hash_durability_pending(state, hash, published);
            tracing::warn!(network, error = %e, "failed to persist complete group snapshot hash");
            false
        }
    }
}

pub(crate) fn mark_group_hash_published(network: &str, hash: blake3::Hash) -> bool {
    let mut current = false;
    match config::update_network(network, |net| {
        current = net.last_group_hash == Some(hash);
        if current {
            net.last_group_hash_published = true;
        }
        Ok(())
    }) {
        Ok(Some(_)) => current,
        Ok(None) => {
            tracing::warn!(
                network,
                "failed to mark published group hash: network was deleted"
            );
            false
        }
        Err(e) => {
            tracing::warn!(network, error = %e, "failed to mark group hash as published");
            false
        }
    }
}

pub(crate) async fn confirm_pending_snapshot_durability(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    network: &str,
) -> bool {
    let commit = state.read().unwrap().snapshot_commit.clone();
    let _commit = commit.lock().await;
    // Re-read the complete marker under the generation lock. Carrying only H2's
    // provenance across this await could otherwise mark a newly authored H3 as
    // already published.
    let pending = { state.read().unwrap().unconfirmed_durable_hash };
    let Some(pending) = pending else {
        return true;
    };
    persist_group_hash_locked(state, blob_store, network, pending.hash, pending.published).await
}

pub(crate) async fn persist_group_hash_if_needed(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    network: &str,
    hash: blake3::Hash,
    published: bool,
) -> bool {
    let commit = state.read().unwrap().snapshot_commit.clone();
    let _commit = commit.lock().await;
    let (current, pending) = {
        let state = state.read().unwrap();
        (
            state.converged_hash == Some(hash),
            state.unconfirmed_durable_hash,
        )
    };
    if !current {
        return false;
    }
    let effective_published = pending
        .filter(|pending| pending.hash == hash)
        .map(|pending| pending.published)
        .unwrap_or(published);
    let already_durable = pending.is_none()
        && config::load_network(network)
            .ok()
            .flatten()
            .is_some_and(|net| {
                net.last_group_hash == Some(hash)
                    && (!effective_published || net.last_group_hash_published)
            });
    if already_durable {
        return true;
    }
    persist_group_hash_locked(state, blob_store, network, hash, effective_published).await
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
            mark_group_hash_durability_pending(state, hash, false);
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
    // Success wakes publication; failure wakes the same tracked task to retry
    // storage or the exact config durability barrier on its short deadline.
    if let Some(notify) = dht_notify {
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
            unconfirmed_durable_hash: None,
            network_secret_key: None,
            network_public_key: SecretKey::generate().public(),
            network_name: Some("test".to_string()),
            group_name: Some("test".to_string()),
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
    fn durable_current_generation_supersedes_an_older_ambiguous_rename() {
        let old = blake3::hash(b"ambiguous old generation");
        let current = blake3::hash(b"durable current generation");
        let state = state_with_snapshot(current);
        {
            let mut state = state.write().unwrap();
            state.converged_hash = Some(current);
            state.unconfirmed_durable_hash = Some(PendingSnapshotDurability {
                hash: old,
                published: false,
            });
        }

        confirm_current_group_hash_durable(&state, current);

        assert_eq!(state.read().unwrap().unconfirmed_durable_hash, None);
    }

    #[test]
    fn persistence_error_marks_only_the_current_generation_ambiguous() {
        let old = blake3::hash(b"old generation");
        let current = blake3::hash(b"current generation");
        let state = state_with_snapshot(current);
        state.write().unwrap().converged_hash = Some(current);

        mark_group_hash_durability_pending(&state, old, false);
        assert_eq!(state.read().unwrap().unconfirmed_durable_hash, None);

        mark_group_hash_durability_pending(&state, current, false);
        assert_eq!(
            state.read().unwrap().unconfirmed_durable_hash,
            Some(PendingSnapshotDurability {
                hash: current,
                published: false,
            })
        );
    }

    #[test]
    fn renewal_deadline_is_absolute_across_notifications() {
        let hash = blake3::hash(b"group");
        let published_at = Instant::now();
        let expected = published_at + RECORD_REPUBLISH_INTERVAL;

        assert_eq!(
            next_attempt_deadline(
                Some(hash),
                Some((hash, published_at)),
                None,
                published_at + Duration::from_secs(1),
            ),
            expected
        );
        assert_eq!(
            next_attempt_deadline(
                Some(hash),
                Some((hash, published_at)),
                None,
                published_at + Duration::from_secs(2),
            ),
            expected
        );
    }

    #[test]
    fn failed_publication_retries_on_its_short_deadline() {
        let hash = blake3::hash(b"group");
        let now = Instant::now();
        let retry_at = now + RECORD_PUBLISH_RETRY_INTERVAL;
        let retry = Some((hash, retry_at));

        assert!(!attempt_is_due(hash, None, retry, now));
        assert_eq!(
            next_attempt_deadline(Some(hash), None, retry, now),
            retry_at
        );
        assert!(attempt_is_due(hash, None, retry, retry_at));
    }

    #[tokio::test]
    async fn authored_snapshot_remains_converged_after_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::load(tmp.path()).await.unwrap();
        let state = state_with_snapshot(blake3::hash(b"stale"));
        {
            let mut s = state.write().unwrap();
            s.network_name = None;
            s.network_secret_key = Some(SecretKey::generate());
        }

        assert!(commit_current_snapshot(&state, &store, &None).await);

        let s = state.read().unwrap();
        assert_eq!(
            s.converged_hash,
            s.snapshot.as_ref().map(|snapshot| snapshot.hash)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)] // serializes this process-global env override
    async fn pointer_retry_recreates_a_locally_authored_blob_after_store_failure() {
        let _lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let config_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", config_dir.path()) };

        let bytes = b"authored complete group".to_vec();
        let hash = blake3::hash(&bytes);
        let state = state_with_snapshot(hash);
        {
            let mut s = state.write().unwrap();
            s.snapshot.as_mut().unwrap().msgpack_bytes = bytes.clone();
            s.converged_hash = Some(hash);
        }
        config::save_network(&config::empty_network_config("test")).unwrap();
        let store = FsStore::load(blobs_dir.path()).await.unwrap();
        let blob_hash = iroh_blobs::Hash::from_bytes(*hash.as_bytes());
        assert!(!store.blobs().has(blob_hash).await.unwrap());

        assert!(persist_group_hash_if_needed(&state, &store, "test", hash, false).await);

        assert_eq!(store.blobs().get_bytes(blob_hash).await.unwrap(), bytes);
        let net = config::load_network("test").unwrap().unwrap();
        assert_eq!(net.last_group_hash, Some(hash));
        assert!(!net.last_group_hash_published);

        unsafe {
            match previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)] // serializes this process-global env override
    async fn published_provenance_is_bound_to_the_expected_generation() {
        let _lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let config_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", config_dir.path()) };

        let published = blake3::hash(b"published generation");
        let authored = blake3::hash(b"new authored generation");
        let state = state_with_snapshot(authored);
        state.write().unwrap().converged_hash = Some(authored);
        let mut net = config::empty_network_config("test");
        net.last_group_hash = Some(authored);
        net.last_group_hash_published = false;
        config::save_network(&net).unwrap();
        let store = FsStore::load(blobs_dir.path()).await.unwrap();

        assert!(
            !persist_group_hash_if_needed(&state, &store, "test", published, true).await,
            "a published H2 must not mark a newer authored H3 as published"
        );
        let net = config::load_network("test").unwrap().unwrap();
        assert_eq!(net.last_group_hash, Some(authored));
        assert!(!net.last_group_hash_published);

        unsafe {
            match previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
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

    #[tokio::test]
    async fn retained_group_blob_survives_gc() {
        let tmp = tempfile::tempdir().unwrap();
        let mut opts = iroh_blobs::store::fs::options::Options::new(tmp.path());
        opts.gc = Some(iroh_blobs::store::GcConfig {
            interval: Duration::from_millis(100),
            add_protected: None,
        });
        let store = FsStore::load_with_opts(tmp.path().join("blobs.db"), opts)
            .await
            .unwrap();

        let bytes = vec![7u8; 64 * 1024];
        let retained = iroh_blobs::Hash::from_bytes(*blake3::hash(&bytes).as_bytes());
        retain_group_blob(&store, &bytes).await.unwrap();

        let canary_path = tmp.path().join("canary.bin");
        std::fs::write(&canary_path, vec![3u8; 64 * 1024]).unwrap();
        let canary_tag = store
            .blobs()
            .add_path(&canary_path)
            .temp_tag()
            .await
            .unwrap();
        let canary = canary_tag.hash();
        drop(canary_tag);

        tokio::time::timeout(Duration::from_secs(30), async {
            while store.blobs().has(canary).await.unwrap() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("gc never collected the untagged canary");
        assert!(
            store.blobs().has(retained).await.unwrap(),
            "a retained group blob must survive gc"
        );
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
        let state = state_with_snapshot(hash);
        state.write().unwrap().converged_hash = Some(hash);
        let mut net = config::empty_network_config("test");
        net.last_group_hash = Some(hash);
        config::save_network(&net).unwrap();

        assert!(!snapshot_is_publishable(&store, &state, "test", hash).await);
        store.blobs().add_slice(bytes).await.unwrap();
        assert!(snapshot_is_publishable(&store, &state, "test", hash).await);

        let new_bytes = b"new live state";
        let new_hash = blake3::hash(new_bytes);
        state.write().unwrap().converged_hash = Some(new_hash);
        assert!(
            !snapshot_is_publishable(&store, &state, "test", hash).await,
            "a stale durable pointer must not override newer live state"
        );
        assert!(
            !persist_group_hash_if_needed(&state, &store, "test", new_hash, false).await,
            "a recovery pointer must not advance before its blob is stored"
        );
        assert_eq!(configured_group_hash("test"), Some(hash));

        store.blobs().add_slice(new_bytes).await.unwrap();
        assert!(persist_group_hash_if_needed(&state, &store, "test", new_hash, false).await);
        let pending = config::load_network("test").unwrap().unwrap();
        assert_eq!(pending.last_group_hash, Some(new_hash));
        assert!(!pending.last_group_hash_published);
        assert!(mark_group_hash_published("test", new_hash));
        assert!(
            config::load_network("test")
                .unwrap()
                .unwrap()
                .last_group_hash_published
        );

        state.write().unwrap().converged_hash = Some(hash);
        config::update_network("test", |net| {
            net.last_group_hash = Some(blake3::hash(b"newer complete group"));
            Ok(())
        })
        .unwrap();
        assert!(!snapshot_is_publishable(&store, &state, "test", hash).await);

        unsafe {
            match previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}
