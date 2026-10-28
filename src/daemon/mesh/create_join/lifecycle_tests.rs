//! How a network comes to be live and who owns what runs for it: pending-join
//! retries, the restore sweep racing a fresh join, warm resume, promotion.

use std::ffi::OsString;

use super::*;

/// Points the daemon's config directory at a fresh temporary one, holding the
/// process-wide config lock, until dropped.
struct ConfigDir {
    _lock: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    previous: Option<OsString>,
}

impl ConfigDir {
    fn new() -> Self {
        let lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", dir.path()) };
        Self {
            _lock: lock,
            _dir: dir,
            previous,
        }
    }
}

impl Drop for ConfigDir {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}

fn empty_state(net_pubkey: EndpointId, name: &str) -> SharedNetworkState {
    let mut state = NetworkState {
        members: MemberList::new(),
        approved: ApprovedList::new(),
        snapshot: None,
        snapshot_commit: Arc::new(AsyncMutex::new(())),
        destroyed: false,
        converged_hash: None,
        unconfirmed_durable_hash: None,
        network_secret_key: None,
        network_public_key: net_pubkey,
        network_name: Some(name.to_string()),
        group_name: Some(name.to_string()),
        mode: GroupMode::Restricted,
        suggested_firewall: SuggestedFirewall::default(),
        reusable_keys: BTreeMap::new(),
        nullifiers: BTreeSet::new(),
        pending_suggestions: Vec::new(),
        pending: HashMap::new(),
        last_record_timestamp: None,
    };
    state.refresh_snapshot();
    Arc::new(std::sync::RwLock::new(state))
}

/// Install a live member handle for `name`, as a finished join leaves one.
fn hold_live(registry: &NetworkRegistry, name: &str, net_pubkey: EndpointId) -> CancellationToken {
    let cancel = CancellationToken::new();
    registry.networks.insert(
        name.to_string(),
        NetworkHandle {
            name: name.to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Member,
            state: empty_state(net_pubkey, name),
            dht_notify: None,
            cancel: cancel.clone(),
            tasks: vec![],
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    cancel
}

/// A pending join for a network that is already live, under a local name that
/// is not its key, is stale. Startup used to look the key up in the
/// name-keyed map, miss, and queue a join that could only fail.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn startup_drops_a_pending_join_for_a_live_network() {
    let _config = ConfigDir::new();
    let daemon = build_headless(false).await.unwrap();
    let key = SecretKey::generate().public();
    config::add_pending_join(config::PendingJoinEntry {
        network_key: key.to_string(),
        name: Some("home".into()),
    })
    .unwrap();
    hold_live(&daemon.registry, "home", key);

    daemon.registry.connect_all_networks().await;

    assert!(config::load().unwrap().pending_joins.is_empty());
    daemon.shutdown_and_close().await;
}

/// Discovery pointed at a port nothing listens on, so a publisher fails fast
/// instead of reaching a public relay.
fn offline_discovery() {
    config::update_settings(|cfg| {
        cfg.mdns_enabled = false;
        cfg.discovery_dns = config::ServerOverride {
            servers: vec!["http://127.0.0.1:1/pkarr".into()],
            replace: true,
        };
        Ok(())
    })
    .unwrap();
}

fn roster_row(identity: EndpointId, is_coordinator: bool, last_seen: Option<u64>) -> Member {
    Member {
        identity,
        is_coordinator,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    }
}

/// A member promoted by an admin grant coordinates from then on, so it runs
/// what every coordinator runs. Promotion used to start only the publisher:
/// an ephemeral network that lost its original coordinator kept offline
/// members forever.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_promoted_member_prunes_stale_members() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let registry = Arc::clone(&daemon.registry);
    let network_key = SecretKey::generate();
    let me = registry.transport.identity.local_identity();
    let stale = SecretKey::generate().public();
    config::save_network(&config::NetworkConfig {
        network_public_key: Some(network_key.public()),
        ephemeral_ttl_secs: Some(3_600),
        ..config::empty_network_config("home")
    })
    .unwrap();
    hold_live(&registry, "home", network_key.public());
    let state = Arc::clone(&registry.networks.get("home").unwrap().state);
    {
        let mut state = state.write().unwrap();
        state.members.add(roster_row(me, true, None));
        state.members.add(roster_row(stale, false, Some(1)));
        state.network_secret_key = Some(network_key.clone());
        state.refresh_snapshot();
    }
    let client = dht::create_pkarr_client(
        &registry.transport.endpoint,
        &registry.transport.pkarr_relay_url,
    )
    .unwrap();

    // The pruner needs no transport. Stopping it first keeps the endpoint's
    // own timers from spinning once the clock is paused.
    daemon.shutdown_and_close().await;
    tokio::time::pause();
    assert!(registry.promote_to_coordinator(&registry.mesh_ctx(), "home", network_key, client));
    // The pruner's first sweep runs a minute after it starts. Advance the
    // clock by hand: auto-advance waits on blocking-pool work in real time.
    // Let the pruner start its timer first, or the advance happens before it.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    let mut polls = 0;
    while state.read().unwrap().members.get(&stale).is_some() {
        polls += 1;
        assert!(
            polls < 10_000,
            "the promoted coordinator prunes a member offline past the TTL"
        );
        tokio::task::yield_now().await;
    }
    registry.networks.get("home").unwrap().cancel.cancel();
}

fn retry_for(key: EndpointId) -> PendingJoinRetry {
    PendingJoinRetry {
        key,
        name: Some("home".into()),
        hostname: None,
        invite: None,
        coordinator: None,
        auto_accept_firewall: false,
        auto_accept_files: false,
    }
}

/// A join queued twice retries once. Each `ray join`, startup resume and paired
/// primary used to start its own loop, and none of them stopped once another
/// had landed the join: they kept retrying into "already in network".
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_queued_join_has_one_retry_loop() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let key = SecretKey::generate().public();

    let first = daemon.registry.spawn_pending_join_retry(retry_for(key));
    assert!(first.is_some());
    assert!(
        daemon
            .registry
            .spawn_pending_join_retry(retry_for(key))
            .is_none(),
        "a second loop for the same network"
    );
    daemon.shutdown_and_close().await;
    first.unwrap().await.unwrap();
    assert!(
        !daemon.registry.pending_join_retries.contains(&key),
        "the key is released when the loop ends"
    );
}

/// A retry stops once its network is live, and drops the restart marker.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_queued_join_stops_retrying_once_the_network_is_live() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let key = SecretKey::generate().public();
    config::add_pending_join(config::PendingJoinEntry {
        network_key: key.to_string(),
        name: Some("home".into()),
    })
    .unwrap();
    hold_live(&daemon.registry, "home", key);

    let retry = daemon
        .registry
        .spawn_pending_join_retry(retry_for(key))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), retry)
        .await
        .expect("the retry ends once the network is live")
        .unwrap();
    assert!(config::load().unwrap().pending_joins.is_empty());
    daemon.shutdown_and_close().await;
}
