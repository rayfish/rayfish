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
        transport: None,
    })
    .unwrap();
    hold_live(&daemon.registry, "home", key);

    daemon.registry.connect_all_networks().await;

    assert!(config::load().unwrap().pending_joins.is_empty());
    daemon.shutdown_and_close().await;
}

/// A discovery relay that has no records and reports each lookup it serves.
async fn watching_relay() -> tokio::sync::mpsc::UnboundedReceiver<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    config::update_settings(|cfg| {
        cfg.mdns_enabled = false;
        cfg.discovery_dns = config::ServerOverride {
            servers: vec![url],
            replace: true,
        };
        Ok(())
    })
    .unwrap();
    let (lookups, seen) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let lookups = lookups.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                if request.starts_with(b"GET") {
                    let _ = lookups.send(());
                }
                let reply =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    seen
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
        transport: None,
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

/// A second `ray join` for a network whose retry already runs is told so, and
/// the saved entry keeps the running retry's options. A second `--tor` join
/// used to report a fresh request while the running loop dropped its transport.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_second_queued_join_is_told_a_retry_runs() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let key = SecretKey::generate().public();

    let first = daemon.registry.queue_pending_join(retry_for(key));
    let Done(message) = first;
    assert!(
        message.contains("waiting for coordinator approval"),
        "{message}"
    );
    let second = daemon.registry.queue_pending_join(PendingJoinRetry {
        transport: Some(config::TransportMode::Tor),
        ..retry_for(key)
    });
    let Done(message) = second;
    assert!(message.contains("already queued"), "{message}");
    let saved = config::load().unwrap().pending_joins;
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].transport, None);
    daemon.shutdown_and_close().await;
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
        transport: None,
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

/// A fresh join of a network live under another name is refused before it
/// dials. It used to pass the name check, and the dial replaced the live
/// network's accept handler before `finalize_join` noticed.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_fresh_join_refuses_a_network_live_under_another_name() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let key = SecretKey::generate().public();
    hold_live(&daemon.registry, "home", key);

    let joined = daemon
        .registry
        .join_network_inner(
            &key.to_string(),
            Some("other"),
            None,
            None,
            None,
            false,
            false,
            true,
        )
        .await;
    let Err(error) = joined else {
        panic!("a second join of a live network");
    };
    assert_eq!(error.to_string(), "already in this network as 'home'");
    daemon.shutdown_and_close().await;
}

fn member_handler(registry: &Arc<NetworkRegistry>, name: &str, key: EndpointId) -> AcceptHandler {
    AcceptHandler::Member(Arc::new(MemberAcceptState {
        ctx: registry.mesh_ctx(),
        network_name: name.to_string(),
        state: empty_state(key, name),
        net_pubkey: key,
        my_identity: registry.transport.endpoint.id(),
        endpoint: registry.transport.endpoint.clone(),
        registry: Arc::clone(registry),
        invite_lock: Arc::new(AsyncMutex::new(())),
        reconverge_notify: Arc::new(tokio::sync::Notify::new()),
    }))
}

/// A join that loses to a live network drops the handler it registered,
/// unless a live network has the same key and so owns that handler.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn an_abandoned_join_drops_only_what_no_live_network_owns() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let registry = &daemon.registry;

    let losing = SecretKey::generate().public();
    hold_live(registry, "home", SecretKey::generate().public());
    registry
        .conn
        .register(losing, member_handler(registry, "home", losing));
    let cancel = CancellationToken::new();
    registry.abandon_join("home", losing, &cancel);
    assert!(cancel.is_cancelled());
    assert!(!registry.conn.is_registered(&losing));

    let live = SecretKey::generate().public();
    hold_live(registry, "work", live);
    registry
        .conn
        .register(live, member_handler(registry, "work", live));
    registry.abandon_join("work", live, &CancellationToken::new());
    assert!(registry.conn.is_registered(&live));
    daemon.shutdown_and_close().await;
}

/// Save `name` as a member network whose last published roster (this node plus
/// `others`) is in the local blob store, as a warm resume finds it at startup.
async fn cache_member_network(
    registry: &NetworkRegistry,
    name: &str,
    network_key: EndpointId,
    others: &[EndpointId],
) -> SavedMemberNetwork {
    let me = registry.transport.identity.local_identity();
    let mut members = MemberList::new();
    members.add(roster_row(me, false, None));
    for other in others {
        members.add(roster_row(*other, true, None));
    }
    let bytes = crate::membership::canonical_group_bytes(
        &members,
        &ApprovedList::new(),
        &SuggestedFirewall::default(),
        Some(name),
        &BTreeMap::new(),
        &BTreeSet::new(),
    );
    let hash = blake3::hash(&bytes);
    registry
        .transport
        .blob_store
        .blobs()
        .add_slice(&bytes)
        .await
        .unwrap();
    config::save_network(&config::NetworkConfig {
        network_public_key: Some(network_key),
        last_group_hash: Some(hash),
        last_group_hash_published: true,
        my_hostname: Some("studio".into()),
        ..config::empty_network_config(name)
    })
    .unwrap();
    SavedMemberNetwork {
        name: name.to_string(),
        net_pubkey: network_key.to_string(),
        persisted_hostname: Some("studio".into()),
        auto_accept_firewall: false,
        auto_accept_files: false,
        cached_hash: Some(hash),
        cached_is_published: true,
    }
}

/// A fresh join claims its name the way create and restore do. Without the
/// claim a restore sweep could start on the config the join had just saved
/// and register a second live state beside the join's.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_fresh_join_waits_out_a_restore_of_the_same_name() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let key = SecretKey::generate().public();
    let restoring = daemon.registry.claim_registration("home").unwrap();

    let joined = daemon
        .registry
        .join_network_inner(
            &key.to_string(),
            Some("home"),
            None,
            None,
            None,
            false,
            false,
            true,
        )
        .await;
    let error = joined.err().expect("the name is being restored");
    assert!(
        format!("{error:#}").contains("already being joined or restored"),
        "{error:#}"
    );
    drop(restoring);
    daemon.shutdown_and_close().await;
}

/// Registration never replaces a live handle. A restore that lost the race to
/// another path used to overwrite it, leaving the first handle's tasks running
/// forever on a state nothing could reach.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_warm_resume_never_replaces_a_live_network() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let registry = Arc::clone(&daemon.registry);
    let key = SecretKey::generate().public();
    let saved = cache_member_network(&registry, "home", key, &[]).await;
    let live_cancel = hold_live(&registry, "home", key);
    let live_state = Arc::clone(&registry.networks.get("home").unwrap().state);

    let resumed = registry.warm_resume_member_network(&saved, key).await;

    assert!(resumed.is_err(), "the network is already live");
    let handle = registry.networks.get("home").unwrap();
    assert!(Arc::ptr_eq(&handle.state, &live_state));
    assert!(!live_cancel.is_cancelled());
    drop(handle);
    daemon.shutdown_and_close().await;
}

/// A member network registered from its cached roster still reconverges when
/// a peer says the roster changed. Warm resume used to register its accept
/// handler with a notify nothing listened on, so every `MemberSync` and
/// `BlobUpdated` was dropped until the next poll, and a queued rename was
/// never retried.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_warm_resumed_member_reconverges_on_a_trigger() {
    let _config = ConfigDir::new();
    let mut lookups = watching_relay().await;
    let daemon = build_headless(false).await.unwrap();
    let registry = Arc::clone(&daemon.registry);
    let key = SecretKey::generate().public();
    let saved = cache_member_network(&registry, "home", key, &[]).await;

    assert!(
        registry
            .warm_resume_member_network(&saved, key)
            .await
            .unwrap()
    );
    // The group poller resolves the record once at start.
    tokio::time::timeout(Duration::from_secs(10), lookups.recv())
        .await
        .expect("the poller looks the record up")
        .unwrap();
    let Some(AcceptHandler::Member(handler)) = registry.conn.handler_for(&key) else {
        panic!("a member accept handler is registered");
    };
    handler.reconverge_notify.notify_one();

    tokio::time::timeout(Duration::from_secs(10), lookups.recv())
        .await
        .expect("the trigger reconverges against the signed record")
        .unwrap();
    daemon.shutdown_and_close().await;
}

/// A warm resume gives up its claim on the name while the record it checks
/// the mesh version against is unreadable. It used to hold the claim until the
/// record was read, so on an offline boot `ray network rename` was refused as
/// "still being restored" for as long as the boot stayed offline.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_warm_resume_releases_its_claim_while_the_record_is_unreadable() {
    let _config = ConfigDir::new();
    // Every lookup is a 404, so the version check keeps retrying.
    let mut lookups = watching_relay().await;
    let daemon = build_headless(false).await.unwrap();
    let registry = Arc::clone(&daemon.registry);
    let key = SecretKey::generate().public();
    cache_member_network(&registry, "home", key, &[]).await;

    let restore = registry
        .spawn_member_restore(&config::load_network("home").unwrap().unwrap())
        .unwrap();
    // One lookup is the group poller's first, the other the version check's.
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(10), lookups.recv())
            .await
            .expect("the record is looked up")
            .unwrap();
    }
    assert!(registry.networks.contains_key("home"));
    assert!(
        registry.claim_registration("home").is_some(),
        "the name is free while the version check retries"
    );
    daemon.shutdown_and_close().await;
    restore.await.unwrap();
}

/// A warm resume marks a network whose record advertises a mesh version this
/// build does not speak, as the cold restore of the same record does. It used
/// to register it as healthy: `ray status` showed a network no peer on it could
/// reach, and nothing watched for the coordinator to republish.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_warm_resume_records_an_incompatible_mesh_version() {
    let _config = ConfigDir::new();
    let relay = super::super::destruction::tests::Relay::start().await;
    config::update_settings(|cfg| {
        cfg.mdns_enabled = false;
        cfg.discovery_dns = config::ServerOverride {
            servers: vec![relay.url.to_string()],
            replace: true,
        };
        Ok(())
    })
    .unwrap();
    let daemon = build_headless(false).await.unwrap();
    let registry = Arc::clone(&daemon.registry);
    let network_key = SecretKey::generate();
    let saved = cache_member_network(&registry, "home", network_key.public(), &[]).await;
    let old = transport::MESH_PROTOCOL_VERSION - 3;
    assert!(!mesh_version_is_speakable(
        Some(old),
        transport::MESH_PROTOCOL_VERSION
    ));
    let record = dht::encode_foreign_network_record(
        &network_key,
        &saved.cached_hash.unwrap(),
        &[SecretKey::generate().public()],
        old,
    )
    .unwrap();
    let client = dht::create_pkarr_client(
        &registry.transport.endpoint,
        &registry.transport.pkarr_relay_url,
    )
    .unwrap();
    dht::publish_record(&client, &record).await.unwrap();

    // The two steps a warm restore takes, run in turn so the check's result
    // is awaited rather than polled for.
    assert!(
        registry
            .warm_resume_member_network(&saved, network_key.public())
            .await
            .unwrap()
    );
    let flagged = tokio::time::timeout(
        Duration::from_secs(10),
        registry.warm_resume_mismatch("home", &network_key.public().to_string()),
    )
    .await
    .expect("the record is read")
    .expect("the version is incompatible");
    let expected = MeshVersionMismatch {
        network: old,
        ours: transport::MESH_PROTOCOL_VERSION,
    };
    assert_eq!(flagged, expected);
    assert_eq!(
        registry
            .networks
            .get("home")
            .and_then(|h| h.incompatible.clone()),
        Some(expected),
        "the warm-resumed network is marked incompatible"
    );
    daemon.shutdown_and_close().await;
}

fn member_install(name: &str, key: EndpointId, state: SharedNetworkState) -> NetworkInstall<'_> {
    NetworkInstall {
        name,
        network_key: key,
        state,
        cancel: CancellationToken::new(),
        invite_lock: Arc::new(AsyncMutex::new(())),
        incompatible: None,
        authority: None,
        poll_record: false,
        reconverge_worker: None,
        my_hostname: None,
        dial: None,
    }
}

/// A handshake that fails after registering its member handler leaves that
/// handler on a state no network owns. Registering the network from the blob
/// used to keep it, because a handler was already there, so every trigger
/// woke a worker reconverging the dead state.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_member_registered_from_the_blob_replaces_a_failed_handshakes_handler() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let registry = &daemon.registry;
    let key = SecretKey::generate().public();
    registry
        .conn
        .register(key, member_handler(registry, "home", key));

    let state = empty_state(key, "home");
    assert!(
        registry
            .install_network(member_install("home", key, Arc::clone(&state)))
            .await
    );

    let Some(AcceptHandler::Member(handler)) = registry.conn.handler_for(&key) else {
        panic!("a member accept handler is registered");
    };
    assert!(Arc::ptr_eq(&handler.state, &state));
    daemon.shutdown_and_close().await;
}

/// Installing over a live network stops what it spawned and leaves the live
/// handle and its handler alone.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn an_install_gives_way_to_a_live_network() {
    let _config = ConfigDir::new();
    offline_discovery();
    let daemon = build_headless(false).await.unwrap();
    let registry = &daemon.registry;
    let key = SecretKey::generate().public();
    let live_cancel = hold_live(registry, "home", key);
    let live_handler = member_handler(registry, "home", key);
    let AcceptHandler::Member(ref live_member) = live_handler else {
        unreachable!("member_handler builds a member handler");
    };
    let live_handler_state = Arc::clone(&live_member.state);
    registry.conn.register(key, live_handler);
    let live_state = Arc::clone(&registry.networks.get("home").unwrap().state);

    let install = member_install("home", key, empty_state(key, "home"));
    let cancel = install.cancel.clone();
    assert!(!registry.install_network(install).await);

    assert!(cancel.is_cancelled());
    assert!(!live_cancel.is_cancelled());
    assert!(Arc::ptr_eq(
        &registry.networks.get("home").unwrap().state,
        &live_state
    ));
    let Some(AcceptHandler::Member(handler)) = registry.conn.handler_for(&key) else {
        panic!("the live handler stays registered");
    };
    assert!(Arc::ptr_eq(&handler.state, &live_handler_state));
    daemon.shutdown_and_close().await;
}
