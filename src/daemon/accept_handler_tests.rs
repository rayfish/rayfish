use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

// Build a minimal NetworkState for use in test AcceptHandler construction.
pub(crate) fn make_network_state() -> SharedNetworkState {
    let net_secret = SecretKey::from_bytes(&[1u8; 32]);
    let net_pub = net_secret.public();
    Arc::new(RwLock::new(NetworkState {
        members: MemberList::new(),
        approved: ApprovedList::new(),
        snapshot: None,
        snapshot_commit: Arc::new(AsyncMutex::new(())),
        destroyed: false,
        converged_hash: None,
        unconfirmed_durable_hash: None,
        network_secret_key: None,
        network_public_key: net_pub,
        network_name: Some("test-net".to_string()),
        group_name: Some("test-net".to_string()),
        mode: GroupMode::Restricted,
        suggested_firewall: SuggestedFirewall::default(),
        reusable_keys: BTreeMap::new(),
        nullifiers: BTreeSet::new(),
        pending_suggestions: Vec::new(),
        pending: HashMap::new(),
        last_record_timestamp: None,
    }))
}

#[test]
fn local_network_alias_never_rewrites_the_signed_group_name() {
    let state = make_network_state();
    let bytes = {
        let mut state = state.write().unwrap();
        state.network_name = Some("my-local-alias".to_string());
        state.group_name = Some("signed-network-name".to_string());
        state.refresh_snapshot();
        state.snapshot.as_ref().unwrap().msgpack_bytes.clone()
    };

    let blob = crate::membership::decode_group_blob(&bytes).unwrap();
    assert_eq!(blob.name.as_deref(), Some("signed-network-name"));
}

#[test]
fn roster_refresh_clears_requests_approved_by_another_coordinator() {
    let state = make_network_state();
    let mut state = state.write().unwrap();
    let approved = SecretKey::from_bytes(&[41; 32]).public();
    let joined = SecretKey::from_bytes(&[42; 32]).public();
    let waiting = SecretKey::from_bytes(&[43; 32]).public();
    for identity in [approved, joined, waiting] {
        state.pending.insert(
            identity,
            PendingJoin {
                denied: false,
                hostname: None,
                device_cert: None,
                requested_at: Instant::now(),
            },
        );
    }
    state.approved.approve(ApprovedEntry {
        identity: approved,
        hostname: None,
        user_identity: None,
        device_cert: None,
    });
    state.members.add(seated(joined));
    state.refresh_snapshot();
    assert_eq!(state.pending.len(), 1);
    assert!(state.pending.contains_key(&waiting));
}

/// Convergence is tracked as the hash we accepted, not the hash of our own
/// re-encoding, and the two differ whenever the publisher writes bytes we
/// would not.
///
/// The case that produces it is an upgrade: rmp-serde reads a struct from a
/// map as well as an array, so a node on this build converges fine from a
/// coordinator still writing the old named blob, and then re-encodes it
/// compactly. Comparing the record against the snapshot hash there says "a
/// different blob" on every poll forever, which refetches, reapplies, and
/// skips the converged branch's steady-state work (self-nullify check,
/// pending rename, exit-offer sync) for as long as the skew lasts.
#[test]
fn convergence_is_tracked_as_the_hash_we_accepted() {
    let state = make_network_state();
    let mut s = state.write().unwrap();
    let member_id = SecretKey::from_bytes(&[9u8; 32]).public();
    s.members = MemberList::from_members(vec![seated(member_id)]);
    s.refresh_snapshot();

    // The mismatch this exists for needs no version skew: `network_name` is
    // hashed into the blob and is a *local* string, so a member that joined
    // with `ray join <code> --name <alias>` re-encodes a name the coordinator
    // never published and can never match its record.
    let published = canonical_group_bytes(
        &s.members,
        &s.approved,
        &s.suggested_firewall,
        Some("what the coordinator published"),
        &s.reusable_keys,
        &s.nullifiers,
    );
    assert_ne!(
        blake3::hash(&published),
        s.snapshot.as_ref().unwrap().hash,
        "a local alias alone puts our re-encoding out of step with the record"
    );

    // Our own encoding is what we are converged on, so a coordinator (which
    // publishes exactly these bytes) sees the two agree.
    let ours = s.snapshot.as_ref().unwrap().hash;
    assert_eq!(s.converged_hash, Some(ours));

    // Applying a record whose bytes we cannot reproduce: the snapshot stays
    // what we would publish, and convergence follows the record.
    let published = blake3::hash(b"the publisher's bytes, not ours");
    s.converged_hash = Some(published);
    assert_eq!(
        s.snapshot.as_ref().unwrap().hash,
        ours,
        "the snapshot is still our own encoding, which is what we would publish"
    );

    // The decision every caller actually makes. This is the assertion that
    // fails if `needs_reconverge` reads the snapshot: polling the record we
    // just applied has to read as converged, or the poller refetches and
    // reapplies the whole roster on every tick for as long as the two
    // encodings differ.
    assert!(
        !s.needs_reconverge(published),
        "the record we applied is not a change"
    );
    assert!(
        s.needs_reconverge(blake3::hash(b"a genuinely newer blob")),
        "a record we have not applied still is one"
    );
}

/// The live state and context behind a handler, whichever role it is. Lets a
/// test seat members and device bindings on a handler it just built.
fn handler_parts(h: &AcceptHandler) -> (&SharedNetworkState, &Arc<NetworkRegistry>) {
    match h {
        AcceptHandler::Coordinator(s) => (&s.state, &s.registry),
        AcceptHandler::Member(s) => (&s.state, &s.registry),
    }
}

fn seated(id: EndpointId) -> Member {
    Member {
        identity: id,
        is_coordinator: false,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    }
}

/// The demux wall: a peer on the roster may speak for this network.
#[tokio::test]
async fn knows_sender_accepts_a_seated_member() {
    let h = sample_coordinator_handler().await;
    let (state, _) = handler_parts(&h);
    let member = SecretKey::from_bytes(&[9u8; 32]).public();
    state.write().unwrap().members.add(seated(member));
    assert!(h.knows_sender(member));
}

/// A peer approved but not yet seated is still accounted for: it is mid-join
/// and its `MeshHello` is what completes the admission.
#[tokio::test]
async fn knows_sender_accepts_an_approved_peer() {
    let h = sample_coordinator_handler().await;
    let (state, _) = handler_parts(&h);
    let peer = SecretKey::from_bytes(&[10u8; 32]).public();
    {
        let mut s = state.write().unwrap();
        s.approved.approve(ApprovedEntry {
            identity: peer,
            hostname: None,
            user_identity: None,
            device_cert: None,
        });
    }
    assert!(h.knows_sender(peer));
}

/// The branch the doc comment calls out: a paired peer can be on the roster
/// under its *user* identity while its frames arrive under a device key, so
/// the lookup has to try the resolved identity too.
#[tokio::test]
async fn knows_sender_resolves_a_device_to_its_roster_user() {
    let h = sample_coordinator_handler().await;
    let (state, registry) = handler_parts(&h);
    let user = SecretKey::from_bytes(&[11u8; 32]).public();
    let device = SecretKey::from_bytes(&[12u8; 32]).public();
    state.write().unwrap().members.add(seated(user));
    // Unmapped, the device key is a stranger.
    assert!(!h.knows_sender(device));
    registry.device_user_map.insert(device, user);
    assert!(h.knows_sender(device));
}

/// The case the wall exists for: knowing the room id is not being in the room.
#[tokio::test]
async fn knows_sender_refuses_a_stranger() {
    let h = sample_coordinator_handler().await;
    let (state, _) = handler_parts(&h);
    let member = SecretKey::from_bytes(&[13u8; 32]).public();
    state.write().unwrap().members.add(seated(member));
    let stranger = SecretKey::from_bytes(&[14u8; 32]).public();
    assert!(!h.knows_sender(stranger));
}

async fn sample_coordinator_handler() -> AcceptHandler {
    let tmp = tempfile::tempdir().unwrap();
    let blob_store = FsStore::load(tmp.path()).await.unwrap();
    let my_key = SecretKey::from_bytes(&[2u8; 32]);
    let my_id = my_key.public();
    let registry = sample_registry(
        sample_test_endpoint().await,
        IrohIdentityProvider::new(my_id),
        blob_store.clone(),
    );
    AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
        registry,
        network_name: "test-net".to_string(),
        state: make_network_state(),
        dht_notify: None,
        invite_lock: Arc::new(AsyncMutex::new(())),
    }))
}

/// Throwaway [`NetworkRegistry`] for accept-handler tests: empty networks map
/// and dummy foundation handles, none of which the constructed handlers touch.
pub(crate) fn sample_registry(
    endpoint: Endpoint,
    identity: IrohIdentityProvider,
    blob_store: FsStore,
) -> Arc<NetworkRegistry> {
    use crate::endpoint_hints::WarmLookup;

    let transport = Arc::new(Transport::new(
        endpoint,
        identity,
        blob_store,
        Arc::new(ForwardMetrics::default()),
        TransportBootstrap {
            lan_peers: Arc::new(LanPeers::new()),
            warm_lookup: WarmLookup::default(),
            pkarr_relay_url: dht::pkarr_relay_url(&config::ServerOverride::default()),
        },
    ));
    let hostname_table = dns::new_hostname_table();
    let reverse_table = dns::new_reverse_table();
    let dns_resolver = Arc::new(crate::dns::resolver::Resolver::new(
        Arc::clone(&hostname_table),
        Arc::clone(&reverse_table),
    ));
    let dns = Arc::new(DnsService::new(
        hostname_table,
        reverse_table,
        dns_resolver,
        // No OS-DNS configuration runs in these tests, so the address the
        // macOS backend would publish is never read.
        std::net::Ipv6Addr::UNSPECIFIED,
    ));
    let (disconnect_tx, _disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(1);
    let (placeholder_tx, _placeholder_rx) = mpsc::channel::<Bytes>(1);
    Arc::new(NetworkRegistry::new(RegistryHandles {
        transport,
        peers: PeerTable::new(),
        conn: Arc::new(ConnectionManager::new()),
        dns,
        tun_name: Arc::new(arc_swap::ArcSwap::from_pointee(String::from("test"))),
        device_cert: None,
        shutdown_token: CancellationToken::new(),
        firewall: SharedFirewall::new(firewall::FirewallConfig::default()),
        device_user_map: peers::DeviceUserMap::new(),
        tun_tx: Arc::new(arc_swap::ArcSwap::from_pointee(placeholder_tx)),
        disconnect_tx,
        on_demand: false,
        idle_timeout: Duration::from_secs(config::DEFAULT_IDLE_TIMEOUT_SECS),
    }))
}

#[cfg(feature = "desktop")]
#[tokio::test]
async fn authorization_uses_identity_memberships_not_connection_handles() {
    let tmp = tempfile::tempdir().unwrap();
    let endpoint = sample_test_endpoint().await;
    let registry = sample_registry(
        endpoint.clone(),
        IrohIdentityProvider::new(endpoint.id()),
        FsStore::load(tmp.path()).await.unwrap(),
    );
    let user = SecretKey::from_bytes(&[41; 32]).public();
    let device = SecretKey::from_bytes(&[42; 32]).public();
    let stranger = SecretKey::from_bytes(&[43; 32]).public();
    registry.device_user_map.insert(device, user);
    let box_state = make_network_state();
    let field_state = make_network_state();
    for (name, state) in [("box", &box_state), ("field", &field_state)] {
        state.write().unwrap().members.add(seated(user));
        registry.networks.insert(
            name.into(),
            NetworkHandle {
                name: name.into(),
                network_key: state.read().unwrap().network_public_key,
                role: NetworkRole::Coordinator,
                state: Arc::clone(state),
                dht_notify: None,
                cancel: CancellationToken::new(),
                tasks: Vec::new(),
                invite_lock: Arc::new(AsyncMutex::new(())),
                incompatible: None,
            },
        );
    }
    // No transport handles are needed to decide this identity's scope.
    let networks = || {
        let mut names = registry.authorization_networks(device);
        names.sort();
        names
    };
    assert_eq!(networks(), ["box", "field"]);
    assert!(registry.authorization_networks(stranger).is_empty());

    // An immediate prune overrides even a roster not yet republished.
    registry.pruned_peers.insert(("box".into(), device));
    assert_eq!(networks(), ["field"]);
    registry.pruned_peers.remove(&("box".into(), device));

    // A revoked device cannot inherit its still-authorized user's grant.
    box_state.write().unwrap().nullifiers.insert(device);
    assert_eq!(networks(), ["field"]);
    box_state.write().unwrap().nullifiers.remove(&device);
    assert_eq!(networks(), ["box", "field"]);

    box_state.write().unwrap().members = MemberList::new();
    assert_eq!(networks(), ["field"]);
    registry.networks.remove("field");
    assert!(networks().is_empty());
    endpoint.close().await;
}

/// `ray firewall test` matches the identity the data path would: a paired
/// device's user inbound, the device itself outbound. The device is offline,
/// so the network-scoped rule matching at all shows that its roster stands
/// in for the live connection.
#[tokio::test]
async fn firewall_test_matches_the_identity_the_data_path_sees() {
    use firewall::{Action, Direction, PeerFilter, PortRange, Protocol, RuleOrigin};

    let tmp = tempfile::tempdir().unwrap();
    let endpoint = sample_test_endpoint().await;
    let registry = sample_registry(
        endpoint.clone(),
        IrohIdentityProvider::new(endpoint.id()),
        FsStore::load(tmp.path()).await.unwrap(),
    );
    let user = SecretKey::from_bytes(&[51; 32]).public();
    let device = SecretKey::from_bytes(&[52; 32]).public();
    registry.device_user_map.insert(device, user);
    let state = make_network_state();
    state.write().unwrap().members.add(Member {
        hostname: Some("phone".into()),
        user_identity: Some(user),
        ..seated(device)
    });
    registry.networks.insert(
        "home".into(),
        NetworkHandle {
            name: "home".into(),
            network_key: state.read().unwrap().network_public_key,
            role: NetworkRole::Coordinator,
            state: Arc::clone(&state),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    let ssh_rule = |direction, action, peer, network: Option<&str>| firewall::FirewallRule {
        direction,
        action,
        protocol: Protocol::Tcp,
        port: Some(PortRange { start: 22, end: 22 }),
        peer: PeerFilter::Identity(peer),
        network: network.map(str::to_string),
        origin: RuleOrigin::Local,
    };
    registry.firewall.update(firewall::FirewallConfig {
        rules: vec![
            ssh_rule(Direction::In, Action::Allow, user, Some("home")),
            ssh_rule(Direction::Out, Action::Deny, device, None),
        ],
        ..firewall::FirewallConfig::default()
    });
    let test = |peer: String, direction, network: Option<&'static str>| {
        let registry = Arc::clone(&registry);
        async move {
            registry
                .firewall_test(&peer, direction, Protocol::Tcp, Some(22), network)
                .await
        }
    };

    match test(device.to_string(), Direction::In, None).await {
        IpcMessage::FirewallTestResult {
            peer_name,
            identity,
            action,
            rule_index,
            networks,
            connected,
            ..
        } => {
            assert_eq!(peer_name, "phone");
            assert_eq!(identity, user.fmt_short().to_string());
            assert_eq!((action, rule_index), (Action::Allow, Some(0)));
            assert_eq!(networks, ["home"]);
            assert!(!connected);
        }
        other => panic!("expected a result, got {other:?}"),
    }
    // By hostname, scoped to the network that names it.
    match test("phone".into(), Direction::Out, Some("home")).await {
        IpcMessage::FirewallTestResult {
            identity,
            action,
            rule_index,
            ..
        } => {
            assert_eq!(identity, device.fmt_short().to_string());
            assert_eq!((action, rule_index), (Action::Deny, Some(1)));
        }
        other => panic!("expected a result, got {other:?}"),
    }

    for (peer, network) in [
        ("phone".to_string(), Some("work")),
        ("nobody".to_string(), None),
        ("self".to_string(), None),
    ] {
        assert!(matches!(
            test(peer, Direction::In, network).await,
            IpcMessage::Error { .. }
        ));
    }
    endpoint.close().await;
}

async fn sample_member_handler() -> AcceptHandler {
    let tmp = tempfile::tempdir().unwrap();
    let blob_store = FsStore::load(tmp.path()).await.unwrap();
    let my_key = SecretKey::from_bytes(&[3u8; 32]);
    let my_id = my_key.public();
    let endpoint = sample_test_endpoint().await;
    let registry = sample_registry(
        endpoint.clone(),
        IrohIdentityProvider::new(my_id),
        blob_store.clone(),
    );
    AcceptHandler::Member(Arc::new(MemberAcceptState {
        network_name: "test-net".to_string(),
        state: make_network_state(),
        net_pubkey: SecretKey::from_bytes(&[1u8; 32]).public(),
        my_identity: my_id,
        endpoint,
        registry,
        invite_lock: Arc::new(AsyncMutex::new(())),
        reconverge_notify: Arc::new(tokio::sync::Notify::new()),
    }))
}

/// A throwaway bound endpoint for constructing a `MemberAcceptState` in tests
/// (the handler is only inspected for its variant, never driven).
async fn sample_test_endpoint() -> Endpoint {
    Endpoint::bind(iroh::endpoint::presets::N0).await.unwrap()
}

// The env lock only serializes whole tests; nothing it guards changes across
// the awaits.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn own_identity_is_the_cert_user_or_this_endpoint() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let me = endpoint.id();
    assert_eq!(registry.own_identity(), me);
    let user = SecretKey::from_bytes(&[9u8; 32]);
    crate::identity::store_device_cert(&control::DeviceCert::create(&user, &me, 0)).unwrap();
    assert_eq!(registry.own_identity(), user.public());
    endpoint.close().await;
}

/// Pairing or unpairing at runtime changes which file senders count as our
/// own devices, without a restart.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn own_device_sender_follows_pairing_at_runtime() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let me = endpoint.id();
    let files = FileService::new(
        SecretKey::generate(),
        Arc::clone(&registry.transport),
        Arc::clone(&registry),
        registry.device_user_map.clone(),
        Arc::new(transfers::TransferRegistry::new()),
    );
    let user = SecretKey::from_bytes(&[9u8; 32]);
    let sibling = SecretKey::generate().public();
    registry.device_user_map.insert(sibling, user.public());
    assert!(!files.is_own_device_sender(sibling));
    crate::identity::store_device_cert(&control::DeviceCert::create(&user, &me, 0)).unwrap();
    assert!(files.is_own_device_sender(sibling));
    crate::identity::delete_device_cert().unwrap();
    assert!(!files.is_own_device_sender(sibling));
    endpoint.close().await;
}

/// Serializes a test that points `RAYFISH_CONFIG_DIR` at a temp dir and
/// restores it on drop, even if the test panics.
struct TestConfigDir {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
    dir: tempfile::TempDir,
}

impl TestConfigDir {
    fn new() -> Self {
        let lock = crate::config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe {
            std::env::set_var("RAYFISH_CONFIG_DIR", dir.path());
        }
        Self {
            _lock: lock,
            previous,
            dir,
        }
    }
}

impl Drop for TestConfigDir {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}

fn roster_member(identity: EndpointId, user: Option<EndpointId>) -> Member {
    Member {
        identity,
        is_coordinator: false,
        hostname: None,
        user_identity: user,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    }
}

/// Register a member-role network holding `members` and `approved`.
pub(crate) fn hold_network(
    registry: &NetworkRegistry,
    name: &str,
    role: NetworkRole,
    members: Vec<Member>,
    approved: Vec<ApprovedEntry>,
) -> SharedNetworkState {
    let state = make_network_state();
    {
        let mut state = state.write().unwrap();
        for member in members {
            state.members.add(member);
        }
        for entry in approved {
            state.approved.approve(entry);
        }
    }
    let network_key = state.read().unwrap().network_public_key;
    registry.networks.insert(
        name.to_string(),
        NetworkHandle {
            name: name.to_string(),
            network_key,
            role,
            state: Arc::clone(&state),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: vec![],
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    state
}

async fn test_registry(dir: &std::path::Path) -> (Endpoint, Arc<NetworkRegistry>) {
    let endpoint = sample_test_endpoint().await;
    let registry = registry_on(&endpoint, &dir.join("blobs")).await;
    (endpoint, registry)
}

/// A registry over `endpoint`, its blob store at `blobs`.
async fn registry_on(endpoint: &Endpoint, blobs: &std::path::Path) -> Arc<NetworkRegistry> {
    let store = FsStore::load(blobs).await.unwrap();
    sample_registry(
        endpoint.clone(),
        IrohIdentityProvider::new(endpoint.id()),
        store,
    )
}

/// A short id resolves only when it names one peer. Empty and ambiguous
/// prefixes resolve to nothing, while a peer seen on two networks is still
/// one peer.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn short_id_resolution_rejects_empty_and_ambiguous_prefixes() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    // Two peers whose ids share a first character, and one that does not.
    let ids: Vec<EndpointId> = (1..=u8::MAX)
        .map(|seed| SecretKey::from_bytes(&[seed; 32]).public())
        .collect();
    let first = |id: &EndpointId| id.to_string().chars().next().unwrap();
    let alice = ids[0];
    let bob = *ids[1..]
        .iter()
        .find(|id| first(id) == first(&alice))
        .unwrap();
    let carol = *ids.iter().find(|id| first(id) != first(&alice)).unwrap();
    hold_network(
        &registry,
        "home",
        NetworkRole::Member,
        vec![seated(alice), seated(bob), seated(carol)],
        Vec::new(),
    );
    hold_network(
        &registry,
        "work",
        NetworkRole::Member,
        vec![seated(carol)],
        Vec::new(),
    );
    let shared = first(&alice).to_string();
    assert_eq!(registry.resolve_short_id_any_network(&shared), None);
    assert_eq!(registry.resolve_short_id_any_network(""), None);
    assert_eq!(
        registry.resolve_short_id_any_network(&alice.to_string()),
        Some(alice)
    );
    assert_eq!(
        registry.resolve_short_id_any_network(&first(&carol).to_string()),
        Some(carol)
    );
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn classify_marks_blocked_known_and_strangers() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let device = SecretKey::from_bytes(&[21u8; 32]).public();
    let user = SecretKey::from_bytes(&[22u8; 32]).public();
    let approved = SecretKey::from_bytes(&[23u8; 32]).public();
    let primary = SecretKey::from_bytes(&[24u8; 32]);
    let stranger = SecretKey::from_bytes(&[25u8; 32]).public();
    hold_network(
        &registry,
        "sample-net",
        NetworkRole::Member,
        vec![roster_member(device, Some(user))],
        vec![ApprovedEntry {
            identity: approved,
            hostname: None,
            user_identity: None,
            device_cert: None,
        }],
    );
    crate::identity::store_device_cert(&control::DeviceCert::create(&primary, &endpoint.id(), 0))
        .unwrap();
    let mut cfg = AppConfig::default();
    let classify = |cfg: &AppConfig, id| inbound::classify(&registry, &cfg.blocked, id);
    assert_eq!(classify(&cfg, device), inbound::Inbound::Known);
    assert_eq!(classify(&cfg, user), inbound::Inbound::Known);
    assert_eq!(classify(&cfg, approved), inbound::Inbound::Known);
    assert_eq!(classify(&cfg, primary.public()), inbound::Inbound::Known);
    assert_eq!(classify(&cfg, stranger), inbound::Inbound::Stranger);
    cfg.blocked = vec![stranger];
    assert_eq!(classify(&cfg, stranger), inbound::Inbound::Blocked);
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn blocking_a_user_identity_covers_its_roster_devices() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let primary = SecretKey::from_bytes(&[28u8; 32]).public();
    let laptop = SecretKey::from_bytes(&[29u8; 32]).public();
    let unrelated = SecretKey::from_bytes(&[36u8; 32]).public();
    hold_network(
        &registry,
        "sample-net",
        NetworkRole::Member,
        vec![
            roster_member(laptop, Some(primary)),
            roster_member(unrelated, None),
        ],
        vec![],
    );
    let cfg = AppConfig {
        blocked: vec![primary],
        ..Default::default()
    };
    assert_eq!(
        inbound::classify(&registry, &cfg.blocked, laptop),
        inbound::Inbound::Blocked
    );
    assert_eq!(
        inbound::classify(&registry, &cfg.blocked, unrelated),
        inbound::Inbound::Known
    );
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn blocked_member_is_refused_on_connect_but_stays_known_elsewhere() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let member = SecretKey::from_bytes(&[26u8; 32]).public();
    hold_network(
        &registry,
        "sample-net",
        NetworkRole::Member,
        vec![roster_member(member, None)],
        vec![],
    );
    let cfg = AppConfig {
        blocked: vec![member],
        ..Default::default()
    };
    assert_eq!(
        inbound::classify(&registry, &cfg.blocked, member),
        inbound::Inbound::Blocked
    );
    assert!(registry.roster_standing(member).known);
    assert!(registry.networks.get("sample-net").is_some());
    endpoint.close().await;
}

/// The app Reject buttons have no way to unblock, so they only drop.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn rejecting_from_an_app_drops_without_blocking() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let connect = ConnectService::new(registry);
    let requester = SecretKey::from_bytes(&[37u8; 32]).public();
    connect.pending_connects.insert(
        requester,
        connect_service::PendingConnect {
            from_endpoint: requester,
            hostname: Some("tablet".to_string()),
            requested_at: Instant::now(),
            stranger: true,
        },
    );
    let reply = connect.reject_connection("tablet");
    assert!(reply.is_ok(), "{reply:?}");
    assert!(connect.pending_connects.is_empty());
    assert!(config::load().unwrap().blocked.is_empty());
    endpoint.close().await;
}

/// `ray block <user>` covers that user's devices for what they already
/// queued, not only for new dials.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn blocking_a_user_drops_what_its_devices_queued() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let primary = SecretKey::from_bytes(&[42u8; 32]).public();
    let laptop = SecretKey::from_bytes(&[43u8; 32]).public();
    let other = SecretKey::from_bytes(&[44u8; 32]).public();
    hold_network(
        &registry,
        "sample-net",
        NetworkRole::Member,
        vec![
            roster_member(laptop, Some(primary)),
            roster_member(other, None),
        ],
        vec![],
    );
    let connect = ConnectService::new(registry);
    for requester in [laptop, other] {
        connect.pending_connects.insert(
            requester,
            connect_service::PendingConnect {
                from_endpoint: requester,
                hostname: None,
                requested_at: Instant::now(),
                stranger: false,
            },
        );
        assert!(
            connect
                .receive_offer(
                    requester,
                    inbound::Inbound::Known,
                    sample_net(),
                    invite_from(requester)
                )
                .await
        );
    }
    connect.block(primary).await.unwrap();
    assert!(!connect.pending_connects.contains_key(&laptop));
    assert!(connect.pending_connects.contains_key(&other));
    let coordinators: Vec<_> = invitations_of(&connect)
        .await
        .into_iter()
        .map(|i| i.coordinator)
        .collect();
    assert_eq!(coordinators, vec![other]);
    endpoint.close().await;
}

/// A dialer admitted when it connected, then blocked while it held its
/// stream open, must not get its request queued.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_made_mid_dial_refuses_the_request() {
    use iroh::address_lookup::memory::MemoryLookup;
    let env = TestConfigDir::new();
    let lookup = MemoryLookup::new();
    let receiver = loopback_endpoint(MemoryLookup::new()).await;
    let dialer = loopback_endpoint(lookup.clone()).await;
    lookup.add_endpoint_info(receiver.addr());
    let registry = registry_on(&receiver, &env.dir.path().join("blobs")).await;
    let connect = Arc::new(ConnectService::new(registry));
    let server = tokio::spawn({
        let connect = Arc::clone(&connect);
        let receiver = receiver.clone();
        async move {
            let conn = receiver.accept().await.unwrap().await.unwrap();
            connect.accept_connect_request(conn).await;
        }
    });
    let conn =
        transport::connect_to_peer_with_alpn(&dialer, receiver.id(), transport::CONNECT_ALPN)
            .await
            .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    // Let the handler pass its first gate and wait on the stream.
    tokio::time::sleep(Duration::from_millis(300)).await;
    config::update_settings(|cfg| {
        cfg.blocked = vec![dialer.id()];
        Ok(())
    })
    .unwrap();
    control::send_framed(
        &mut send,
        &control::ConnectMsg::Request {
            from_identity: dialer.id(),
            from_endpoint: dialer.id(),
            hostname: None,
        },
    )
    .await
    .unwrap();
    let reply = control::recv_framed::<control::ConnectMsg>(&mut recv).await;
    server.await.unwrap();
    assert!(
        matches!(reply, Ok(control::ConnectMsg::Denied { .. })),
        "{reply:?}"
    );
    assert!(connect.pending_connects.is_empty());
    receiver.close().await;
    dialer.close().await;
}

#[tokio::test]
async fn a_dialer_that_never_opens_a_stream_is_dropped() {
    use iroh::address_lookup::memory::MemoryLookup;
    let env = TestConfigDir::new();
    let lookup = MemoryLookup::new();
    let receiver = loopback_endpoint(MemoryLookup::new()).await;
    let dialer = loopback_endpoint(lookup.clone()).await;
    lookup.add_endpoint_info(receiver.addr());
    let registry = registry_on(&receiver, &env.dir.path().join("blobs")).await;
    let connect = Arc::new(ConnectService::new(registry));
    let server = tokio::spawn({
        let receiver = receiver.clone();
        async move {
            let conn = receiver.accept().await.unwrap().await.unwrap();
            connect.accept_connect_request(conn).await;
        }
    });
    let _conn =
        transport::connect_to_peer_with_alpn(&dialer, receiver.id(), transport::CONNECT_ALPN)
            .await
            .unwrap();
    let done = tokio::time::timeout(
        connect_service::CONNECT_READ_TIMEOUT + Duration::from_secs(5),
        server,
    )
    .await;
    assert!(done.is_ok(), "the handler still waits on an idle dialer");
    receiver.close().await;
    dialer.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn deny_removes_the_request_and_blocks_the_sender() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let connect = ConnectService::new(registry);
    let requester = SecretKey::from_bytes(&[27u8; 32]).public();
    connect.pending_connects.insert(
        requester,
        connect_service::PendingConnect {
            from_endpoint: requester,
            hostname: Some("laptop".to_string()),
            requested_at: Instant::now(),
            stranger: true,
        },
    );
    let reply = connect.deny_connection("laptop").await;
    assert!(reply.is_ok(), "{reply:?}");
    assert!(connect.pending_connects.is_empty());
    assert_eq!(config::load().unwrap().blocked, vec![requester]);
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_uses_the_dialing_endpoint_not_the_claimed_identity() {
    use iroh::address_lookup::memory::MemoryLookup;
    let env = TestConfigDir::new();
    let lookup = MemoryLookup::new();
    let receiver = loopback_endpoint(MemoryLookup::new()).await;
    let blocked = loopback_endpoint(lookup.clone()).await;
    let allowed = loopback_endpoint(lookup.clone()).await;
    lookup.add_endpoint_info(receiver.addr());
    let registry = registry_on(&receiver, &env.dir.path().join("blobs")).await;
    let connect = Arc::new(ConnectService::new(registry));
    config::update_settings(|cfg| {
        cfg.blocked = vec![blocked.id()];
        Ok(())
    })
    .unwrap();
    let server = tokio::spawn({
        let connect = Arc::clone(&connect);
        let receiver = receiver.clone();
        async move {
            for _ in 0..2 {
                let conn = receiver.accept().await.unwrap().await.unwrap();
                connect.accept_connect_request(conn).await;
            }
        }
    });
    let ask = |from: &Endpoint, claimed: EndpointId| {
        let from = from.clone();
        let to = receiver.id();
        async move {
            let conn =
                transport::connect_to_peer_with_alpn(&from, to, transport::CONNECT_ALPN).await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            control::send_framed(
                &mut send,
                &control::ConnectMsg::Request {
                    from_identity: claimed,
                    from_endpoint: from.id(),
                    hostname: None,
                },
            )
            .await?;
            control::recv_framed::<control::ConnectMsg>(&mut recv).await
        }
    };
    // The blocked endpoint receives a refusal, whatever it claims to be.
    let refused = ask(&blocked, allowed.id()).await;
    // A different endpoint claiming the blocked key is judged on itself.
    let admitted = ask(&allowed, blocked.id()).await;
    server.await.unwrap();
    assert!(
        matches!(refused, Ok(control::ConnectMsg::Denied { .. })),
        "{refused:?}"
    );
    assert_eq!(admitted.unwrap(), control::ConnectMsg::Pending);
    assert!(connect.pending_connects.contains_key(&allowed.id()));
    assert!(!connect.pending_connects.contains_key(&blocked.id()));
    for endpoint in [receiver, blocked, allowed] {
        endpoint.close().await;
    }
}

/// A connect service whose pkarr relay refuses connections, so a join fails
/// fast instead of reaching the public DHT.
async fn offline_connect_service(dir: &std::path::Path) -> (Endpoint, ConnectService) {
    let (endpoint, mut registry) = test_registry(dir).await;
    let mut transport = (*registry.transport).clone();
    transport.pkarr_relay_url = "http://127.0.0.1:1/pkarr".parse().unwrap();
    Arc::get_mut(&mut registry).unwrap().transport = Arc::new(transport);
    let connect = ConnectService::new(registry);
    (endpoint, connect)
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn approved_connect_retries_after_join_failure() {
    use iroh::address_lookup::memory::MemoryLookup;

    let env = TestConfigDir::new();
    let lookup = MemoryLookup::new();
    let dialer = loopback_endpoint(lookup.clone()).await;
    let receiver = loopback_endpoint(MemoryLookup::new()).await;
    lookup.add_endpoint_info(receiver.addr());
    let mut registry = registry_on(&dialer, &env.dir.path().join("blobs")).await;
    let mut transport = (*registry.transport).clone();
    transport.pkarr_relay_url = "http://127.0.0.1:1/pkarr".parse().unwrap();
    Arc::get_mut(&mut registry).unwrap().transport = Arc::new(transport);
    let connect = Arc::new(ConnectService::new(registry));
    connect.outgoing_connects.insert(receiver.id());
    connect.spawn_connect_retry(receiver.id(), None);

    let retried = tokio::time::timeout(Duration::from_secs(10), async {
        for attempt in 0..2 {
            let conn = receiver.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            assert!(matches!(
                control::recv_framed::<control::ConnectMsg>(&mut recv)
                    .await
                    .unwrap(),
                control::ConnectMsg::Request { .. }
            ));
            assert!(connect.outgoing_connects.contains(&receiver.id()));
            let reply = if attempt == 0 {
                control::ConnectMsg::Approved {
                    room_id: SecretKey::from_bytes(&[26; 32]).public(),
                    coordinator: receiver.id(),
                }
            } else {
                control::ConnectMsg::Denied {
                    reason: "request withdrawn".into(),
                }
            };
            control::send_framed(&mut send, &reply).await.unwrap();
            conn.closed().await;
        }
    })
    .await;
    connect.registry.shutdown_token.cancel();
    receiver.close().await;
    dialer.close().await;
    assert!(
        retried.is_ok(),
        "an approved request must retry a failed join"
    );
    assert!(
        connect
            .connection_errors
            .get(&receiver.id())
            .is_some_and(|error| error.contains("request withdrawn"))
    );
}

fn sample_net() -> ipc::NetworkName {
    ipc::NetworkName::new("sample-net".into())
}

async fn invitations_of(connect: &ConnectService) -> Vec<ipc::InvitationInfo> {
    match connect.list_invitations().await {
        Ok(invitations) => invitations,
        Err(e) => panic!("expected invitations, got {e}"),
    }
}

fn invite_from(coordinator: EndpointId) -> crate::invite::InviteCode {
    let network = SecretKey::from_bytes(&[30u8; 32]).public();
    crate::invite::InviteCode::encode(&network, &coordinator, &[7; 16])
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn offer_from_another_coordinator_is_refused() {
    let env = TestConfigDir::new();
    let (endpoint, connect) = offline_connect_service(env.dir.path()).await;
    let sender = SecretKey::from_bytes(&[31u8; 32]).public();
    let real_coordinator = SecretKey::from_bytes(&[32u8; 32]).public();
    let label = ipc::NetworkName::new("sample-net".into());
    assert!(
        !connect
            .receive_offer(
                sender,
                inbound::Inbound::Known,
                label.clone(),
                invite_from(real_coordinator)
            )
            .await
    );
    assert!(
        connect
            .receive_offer(sender, inbound::Inbound::Known, label, invite_from(sender))
            .await
    );
    let invitations = invitations_of(&connect).await;
    assert_eq!(invitations.len(), 1);
    assert_eq!(invitations[0].coordinator, sender);
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn malformed_offer_is_refused_without_echo() {
    let env = TestConfigDir::new();
    let (endpoint, connect) = offline_connect_service(env.dir.path()).await;
    let sender = SecretKey::from_bytes(&[33u8; 32]).public();
    let garbage: crate::invite::InviteCode =
        serde_json::from_str("\"secret-looking-garbage\"").unwrap();
    let stored = connect
        .receive_offer(
            sender,
            inbound::Inbound::Stranger,
            ipc::NetworkName::new("sample-net".into()),
            garbage,
        )
        .await;
    assert!(!stored);
    assert!(!env.dir.path().join("invitations.toml").exists());
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn decline_marks_and_blocks_the_sender() {
    let env = TestConfigDir::new();
    let (endpoint, connect) = offline_connect_service(env.dir.path()).await;
    let sender = SecretKey::from_bytes(&[34u8; 32]).public();
    assert!(
        connect
            .receive_offer(
                sender,
                inbound::Inbound::Known,
                sample_net(),
                invite_from(sender)
            )
            .await
    );
    let invitations = invitations_of(&connect).await;
    let id = invitations[0].id.clone();
    assert!(connect.decline_invitation(&id).await.is_ok());
    assert_eq!(config::load().unwrap().blocked, vec![sender]);
    let invitations = invitations_of(&connect).await;
    assert_eq!(invitations[0].status, ipc::InvitationStatus::Declined);
    assert!(connect.accept_invitation(&id, None).await.is_err());
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn failed_join_leaves_the_invitation_pending() {
    let env = TestConfigDir::new();
    let (endpoint, connect) = offline_connect_service(env.dir.path()).await;
    let sender = SecretKey::from_bytes(&[35u8; 32]).public();
    assert!(
        connect
            .receive_offer(
                sender,
                inbound::Inbound::Known,
                sample_net(),
                invite_from(sender)
            )
            .await
    );
    let invitations = invitations_of(&connect).await;
    let reply = connect.accept_invitation(&invitations[0].id, None).await;
    assert!(reply.is_err(), "{reply:?}");
    let invitations = invitations_of(&connect).await;
    assert_eq!(invitations[0].status, ipc::InvitationStatus::Pending);
    endpoint.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_repeated_offer_does_not_rewrite_the_inbox() {
    let env = TestConfigDir::new();
    let (endpoint, connect) = offline_connect_service(env.dir.path()).await;
    let sender = SecretKey::from_bytes(&[46u8; 32]).public();
    let code = invite_from(sender);
    let offer = || {
        connect.receive_offer(
            sender,
            inbound::Inbound::Stranger,
            sample_net(),
            code.clone(),
        )
    };
    assert!(offer().await);
    let path = config::config_dir().unwrap().join("invitations.toml");
    let modified = || path.metadata().unwrap().modified().unwrap();
    let written = modified();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(offer().await);
    assert_eq!(modified(), written);
    assert_eq!(invitations_of(&connect).await.len(), 1);
    endpoint.close().await;
}

/// A coordinator that refuses the code (revoked, used, expired) ends the
/// invitation; any other failed join leaves it to retry.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_rejected_invite_leaves_the_inbox() {
    let env = TestConfigDir::new();
    let (endpoint, connect) = offline_connect_service(env.dir.path()).await;
    let sender = SecretKey::from_bytes(&[45u8; 32]).public();
    assert!(
        connect
            .receive_offer(
                sender,
                inbound::Inbound::Known,
                sample_net(),
                invite_from(sender)
            )
            .await
    );
    let id = invitations_of(&connect).await[0].id.clone();
    let entry = connect.invitation_entry(&id).await;
    // Unreachable, or refused by a co-coordinator that never saw it: the
    // invite may still be good.
    for kept in [
        "failed to reach the coordinator".to_string(),
        format!(
            "join denied: {}: invalid invite",
            crate::invite::INVITE_REJECTED
        ),
    ] {
        let reply = connect.settle_accept(&entry, Err(OpError::msg(kept))).await;
        assert!(reply.is_err(), "{reply:?}");
        assert_eq!(invitations_of(&connect).await.len(), 1);
    }
    let revoked = Err(OpError::msg(format!(
        "join denied: {}: invite revoked",
        crate::invite::INVITE_REJECTED
    )));
    let reply = connect.settle_accept(&entry, revoked).await;
    assert!(
        matches!(&reply, Err(e) if e.message().contains("revoked or has expired")),
        "{reply:?}"
    );
    assert!(invitations_of(&connect).await.is_empty());
    endpoint.close().await;
}

/// A recipient that predates invite delivery shares no ALPN for it: the
/// sender is told to share the code, and the sweep stops dialing it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_recipient_is_recorded_and_not_retried() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let (sender, connect, _) = delivering_service(env.dir.path(), lookup.clone()).await;
    let old = loopback_endpoint_on(
        iroh::address_lookup::memory::MemoryLookup::new(),
        vec![transport::CONNECT_ALPN.to_vec()],
    )
    .await;
    lookup.add_endpoint_info(old.addr());
    // Accept like an old node's router, which fails the handshake.
    let accepting = tokio::spawn({
        let old = old.clone();
        async move {
            while let Some(incoming) = old.accept().await {
                let _ = incoming.await;
            }
        }
    });
    let message = reply_text(connect.deliver_invite("sample-net", old.id()).await);
    assert!(message.contains("older Rayfish"), "{message}");
    let store = crate::invite::InviteStore::load("sample-net").unwrap();
    assert!(store.pending_deliveries().is_empty());
    assert_eq!(store.list().len(), 1);
    // A manual retry dials again (it may have upgraded) and reuses the invite.
    let message = reply_text(connect.deliver_invite("sample-net", old.id()).await);
    assert!(message.contains("older Rayfish"), "{message}");
    assert_eq!(
        crate::invite::InviteStore::load("sample-net")
            .unwrap()
            .list()
            .len(),
        1
    );
    sender.close().await;
    old.close().await;
    accepting.abort();
}

/// An offer is only taken on the invite ALPN, a request only on connect.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offer_on_the_connect_channel_is_refused() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let (receiver, inbox) = receiving_service(env.dir.path()).await;
    let dialer = loopback_endpoint(lookup.clone()).await;
    lookup.add_endpoint_info(receiver.addr());
    let server = tokio::spawn({
        let inbox = Arc::clone(&inbox);
        let receiver = receiver.clone();
        async move {
            let conn = receiver.accept().await.unwrap().await.unwrap();
            inbox.accept_connect_request(conn).await;
        }
    });
    let conn =
        transport::connect_to_peer_with_alpn(&dialer, receiver.id(), transport::CONNECT_ALPN)
            .await
            .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    control::send_framed(
        &mut send,
        &control::ConnectMsg::InviteOffer {
            network: sample_net(),
            code: invite_from(dialer.id()),
        },
    )
    .await
    .unwrap();
    let reply = control::recv_framed::<control::ConnectMsg>(&mut recv).await;
    server.await.unwrap();
    assert!(reply.is_err(), "{reply:?}");
    assert!(invitations_of(&inbox).await.is_empty());
    receiver.close().await;
    dialer.close().await;
}

/// A loopback-only endpoint on the connect and invite ALPNs, found through
/// `lookup`.
async fn loopback_endpoint(lookup: iroh::address_lookup::memory::MemoryLookup) -> Endpoint {
    loopback_endpoint_on(
        lookup,
        vec![
            transport::CONNECT_ALPN.to_vec(),
            transport::INVITE_ALPN.to_vec(),
        ],
    )
    .await
}

async fn loopback_endpoint_on(
    lookup: iroh::address_lookup::memory::MemoryLookup,
    alpns: Vec<Vec<u8>>,
) -> Endpoint {
    Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(alpns)
        .address_lookup(lookup)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .bind()
        .await
        .unwrap()
}

/// A coordinator-side connect service for `sample-net`, dialing through
/// `lookup`. Returns the network's shared state so tests can add members.
async fn delivering_service(
    dir: &std::path::Path,
    lookup: iroh::address_lookup::memory::MemoryLookup,
) -> (Endpoint, Arc<ConnectService>, SharedNetworkState) {
    let endpoint = loopback_endpoint(lookup).await;
    let registry = registry_on(&endpoint, &dir.join("sender-blobs")).await;
    let state = hold_network(
        &registry,
        "sample-net",
        NetworkRole::Coordinator,
        vec![],
        vec![],
    );
    let connect = Arc::new(ConnectService::new(registry));
    (endpoint, connect, state)
}

async fn receiving_service(dir: &std::path::Path) -> (Endpoint, Arc<ConnectService>) {
    let endpoint = loopback_endpoint(iroh::address_lookup::memory::MemoryLookup::new()).await;
    let registry = registry_on(&endpoint, &dir.join("receiver-blobs")).await;
    let connect = Arc::new(ConnectService::new(registry));
    (endpoint, connect)
}

fn reply_text(reply: OpResult<Done>) -> String {
    match reply {
        Ok(Done(message)) => message,
        Err(e) => panic!("expected Ok, got {e}"),
    }
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_delivery_reuses_one_invite_and_reports_queued() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let (sender, connect, _) = delivering_service(env.dir.path(), lookup).await;
    // Nobody knows where this recipient is, so the dial fails.
    let recipient = SecretKey::from_bytes(&[40u8; 32]).public();
    for _ in 0..2 {
        let message = reply_text(connect.deliver_invite("sample-net", recipient).await);
        assert!(message.contains("queued"), "{message}");
    }
    let store = crate::invite::InviteStore::load("sample-net").unwrap();
    assert_eq!(store.list().len(), 1);
    assert_eq!(store.pending_deliveries(), [recipient]);
    sender.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn delivery_to_a_member_is_skipped() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let (sender, connect, state) = delivering_service(env.dir.path(), lookup).await;
    let device = SecretKey::from_bytes(&[41u8; 32]).public();
    let user = SecretKey::from_bytes(&[42u8; 32]).public();
    state
        .write()
        .unwrap()
        .members
        .add(roster_member(device, Some(user)));
    let message = reply_text(connect.deliver_invite("sample-net", user).await);
    assert!(message.contains("already has a device"), "{message}");
    assert!(
        crate::invite::InviteStore::load("sample-net")
            .unwrap()
            .list()
            .is_empty()
    );
    sender.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn sweep_never_mints() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let (sender, connect, _) = delivering_service(env.dir.path(), lookup).await;
    let recipient = SecretKey::from_bytes(&[43u8; 32]).public();
    // Nothing queued: the sweep step has nothing to send.
    assert_eq!(
        connect
            .deliver_locked("sample-net", recipient, invite_delivery::Mint::Never)
            .await
            .unwrap()
            .into_message(),
        "no pending delivery"
    );
    connect
        .deliver_invite("sample-net", recipient)
        .await
        .unwrap();
    // Revoked after the sweep picked it: still nothing new is minted.
    let id = crate::invite::InviteStore::load("sample-net")
        .unwrap()
        .list()[0]
        .id
        .clone();
    crate::invite::InviteStore::load("sample-net")
        .unwrap()
        .revoke(&id)
        .unwrap();
    assert_eq!(
        connect
            .deliver_locked("sample-net", recipient, invite_delivery::Mint::Never)
            .await
            .unwrap()
            .into_message(),
        "no pending delivery"
    );
    connect.sweep_deliveries(&CancellationToken::new()).await;
    let store = crate::invite::InviteStore::load("sample-net").unwrap();
    assert_eq!(store.list().len(), 1);
    assert_eq!(store.list()[0].status, "revoked");
    sender.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_then_online_then_delivered_without_duplicates() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let (sender, connect, _) = delivering_service(env.dir.path(), lookup.clone()).await;
    let (receiver, inbox) = receiving_service(env.dir.path()).await;
    // Offline: the sender cannot find the recipient yet.
    let message = reply_text(connect.deliver_invite("sample-net", receiver.id()).await);
    assert!(message.contains("queued"), "{message}");
    let first = crate::invite::InviteStore::load("sample-net")
        .unwrap()
        .list();
    lookup.add_endpoint_info(receiver.addr());
    let server = tokio::spawn({
        let inbox = Arc::clone(&inbox);
        let receiver = receiver.clone();
        async move {
            // Store the first offer, then drop the ack.
            let conn = receiver.accept().await.unwrap().await.unwrap();
            let remote = conn.remote_id();
            let (_send, mut recv) = conn.accept_bi().await.unwrap();
            let control::ConnectMsg::InviteOffer { network, code } =
                control::recv_framed(&mut recv).await.unwrap()
            else {
                panic!("expected an offer");
            };
            assert!(
                inbox
                    .receive_offer(remote, inbound::Inbound::Stranger, network, code)
                    .await
            );
            conn.close(0u32.into(), b"lost ack");
            // The retry goes through the real handler and is acked.
            let conn = receiver.accept().await.unwrap().await.unwrap();
            inbox.accept_connect_request(conn).await;
        }
    });
    let message = reply_text(connect.deliver_invite("sample-net", receiver.id()).await);
    assert!(message.contains("queued"), "{message}");
    connect.sweep_deliveries(&CancellationToken::new()).await;
    server.await.unwrap();
    let store = crate::invite::InviteStore::load("sample-net").unwrap();
    assert!(store.pending_deliveries().is_empty());
    assert_eq!(store.list().len(), 1);
    assert_eq!(store.list()[0].id, first[0].id);
    let invitations = invitations_of(&inbox).await;
    assert_eq!(invitations.len(), 1);
    assert_eq!(invitations[0].coordinator, sender.id());
    assert_eq!(invitations[0].status, ipc::InvitationStatus::Pending);
    sender.close().await;
    receiver.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn connecting_to_yourself_is_refused() {
    let env = TestConfigDir::new();
    let (endpoint, registry) = test_registry(env.dir.path()).await;
    let me = endpoint.id();
    let connect = ConnectService::new(registry);
    assert!(connect.resolve_connect_target(&me.to_string()).is_err());
    let user = SecretKey::from_bytes(&[9u8; 32]);
    crate::identity::store_device_cert(&control::DeviceCert::create(&user, &me, 0)).unwrap();
    assert!(
        connect
            .resolve_connect_target(&user.public().to_string())
            .is_err()
    );
    let other = SecretKey::from_bytes(&[10u8; 32]).public();
    assert_eq!(
        connect.resolve_connect_target(&other.to_string()),
        Ok(other)
    );
    endpoint.close().await;
}

mod disconnect_recovery_tests {
    use super::*;
    use iroh::RelayMode;
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::presets;
    use tokio::time::timeout;

    #[derive(Clone, Copy)]
    enum Successor {
        Missing,
        BeforeDisconnect,
        DuringBackoff,
    }

    async fn check_recovery(reason: forward::CloseReason, successor: Successor, expect_dial: bool) {
        let alpn = transport::mesh_alpn();
        let lookup = MemoryLookup::new();
        let local = Endpoint::builder(presets::N0)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();
        let remote = Endpoint::builder(presets::N0)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(remote.addr());
        let (conn, remote_conn) = timeout(Duration::from_secs(5), async {
            tokio::join!(local.connect(remote.addr(), &alpn), async {
                remote.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .expect("initial loopback connection completes");
        let conn = conn.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::load(tmp.path()).await.unwrap();
        let registry = sample_registry(
            local.clone(),
            IrohIdentityProvider::new(local.id()),
            store.clone(),
        );
        let peer_ip = derive_ipv6(&remote.id());
        registry
            .peers
            .add(peer_ip, conn.clone(), remote.id(), "test-net");
        let state = make_network_state();
        state.write().unwrap().members.add(seated(remote.id()));
        registry.networks.insert(
            "test-net".to_string(),
            NetworkHandle {
                name: "test-net".to_string(),
                network_key: state.read().unwrap().network_public_key,
                role: NetworkRole::Member,
                state: Arc::clone(&state),
                dht_notify: None,
                cancel: CancellationToken::new(),
                tasks: Vec::new(),
                invite_lock: Arc::new(AsyncMutex::new(())),
                incompatible: None,
            },
        );
        let code = match reason {
            forward::CloseReason::Replaced => forward::REPLACED_CONNECTION_CODE,
            forward::CloseReason::Idle => forward::IDLE_CODE,
            _ => 0,
        };
        remote_conn.close(VarInt::from_u32(code), b"disconnect recovery test");
        timeout(Duration::from_secs(2), conn.closed())
            .await
            .unwrap();

        // Keep both ends of the successor alive through the retry window.
        let register_successor = async {
            let (new_conn, peer_conn) = timeout(Duration::from_secs(5), async {
                tokio::join!(local.connect(remote.addr(), &alpn), async {
                    remote.accept().await.unwrap().await.unwrap()
                })
            })
            .await
            .expect("successor connects");
            let new_conn = new_conn.unwrap();
            registry
                .peers
                .add(peer_ip, new_conn.clone(), remote.id(), "test-net");
            (new_conn, peer_conn)
        };
        tokio::pin!(register_successor);
        let mut replacement = if matches!(successor, Successor::BeforeDisconnect) {
            Some(register_successor.as_mut().await)
        } else {
            None
        };
        let (tx, rx) = mpsc::channel(1);
        let token = registry.shutdown_token.clone();
        let supervisor = tokio::spawn(Arc::clone(&registry).run_connection_supervisor(rx, token));
        tx.send(forward::DisconnectEvent {
            endpoint_id: remote.id(),
            ipv6: peer_ip,
            reason,
            conn_stable_id: Some(conn.stable_id()),
        })
        .await
        .unwrap();
        drop(tx);
        timeout(Duration::from_secs(2), supervisor)
            .await
            .unwrap()
            .unwrap();

        if replacement.is_none() {
            assert!(
                registry.peers.conn_for_ip(&peer_ip).is_none(),
                "closed route is removed"
            );
        }
        if matches!(successor, Successor::DuringBackoff) {
            replacement = Some(register_successor.as_mut().await);
        }
        // With no packet traffic, only the supervisor can start this dial.
        // Observe the incoming attempt without accepting it: the test does
        // not need a second protocol router or a real TUN interface.
        let incoming = timeout(Duration::from_secs(3), remote.accept()).await;
        let attempted = matches!(&incoming, Ok(Some(_)));
        if let Ok(Some(incoming)) = incoming {
            incoming.refuse();
        }
        if let Some((new_conn, _)) = &replacement {
            assert!(
                registry
                    .peers
                    .conn_is_current(&peer_ip, new_conn.stable_id())
            );
            assert!(new_conn.close_reason().is_none(), "successor stays live");
        }
        registry.shutdown_token.cancel();
        local.close().await;
        remote.close().await;
        store.shutdown().await.unwrap();
        assert_eq!(attempted, expect_dial, "recovery after {reason:?}");
    }

    #[tokio::test]
    async fn replaced_without_a_successor_retries() {
        check_recovery(forward::CloseReason::Replaced, Successor::Missing, true).await;
    }

    #[tokio::test]
    async fn transient_disconnect_still_retries() {
        check_recovery(forward::CloseReason::Transient, Successor::Missing, true).await;
    }

    #[tokio::test]
    async fn stale_disconnect_preserves_ready_successor() {
        check_recovery(
            forward::CloseReason::Replaced,
            Successor::BeforeDisconnect,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn retry_reuses_successor_that_arrives_during_backoff() {
        check_recovery(
            forward::CloseReason::Replaced,
            Successor::DuringBackoff,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn deliberate_idle_disconnect_does_not_retry() {
        check_recovery(forward::CloseReason::Idle, Successor::Missing, false).await;
    }
}

#[tokio::test]
async fn authorized_rejoin_clears_reconnect_suppression() {
    let alpn = transport::mesh_alpn();
    let local = Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![alpn.clone()])
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let remote = Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![alpn.clone()])
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let accept = {
        let remote = remote.clone();
        tokio::spawn(async move { remote.accept().await.unwrap().await.unwrap() })
    };
    let conn = local.connect(remote.addr(), &alpn).await.unwrap();
    let remote_conn = accept.await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let store = FsStore::load(tmp.path()).await.unwrap();
    let registry = sample_registry(
        local.clone(),
        IrohIdentityProvider::new(local.id()),
        store.clone(),
    );
    let peer_id = conn.remote_id();
    registry
        .pruned_peers
        .insert(("test-network".to_string(), peer_id));

    registry.register_peer_conn(&conn, peer_id, "test-network");

    assert!(
        !registry
            .pruned_peers
            .contains(&("test-network".to_string(), peer_id))
    );
    conn.close(VarInt::from_u32(0), b"test done");
    remote_conn.close(VarInt::from_u32(0), b"test done");
    local.close().await;
    remote.close().await;
}

#[tokio::test]
async fn reconnect_reuses_the_selected_connection_and_reports_success() {
    let alpn = transport::mesh_alpn();
    let local = Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![alpn.clone()])
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let remote = Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![alpn.clone()])
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let (conn, remote_conn) = tokio::join!(local.connect(remote.addr(), &alpn), async {
        remote.accept().await.unwrap().await.unwrap()
    },);
    let conn = conn.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let store = FsStore::load(tmp.path()).await.unwrap();
    let registry = sample_registry(local.clone(), IrohIdentityProvider::new(local.id()), store);
    let peer_ip = derive_ipv6(&remote.id());
    registry
        .peers
        .add(peer_ip, conn.clone(), remote.id(), "net-a");
    let targets = ["net-a", "net-b"].map(|network| DialTarget {
        network: network.to_string(),
        network_key: SecretKey::generate().public(),
    });
    // Previously an unchanged connection was reported as failure, so a
    // reconnect loop kept dialing forever. It must also reuse this session
    // when announcing another network instead of opening another connection.
    for _ in 0..2 {
        let (connected, ()) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(5),
                registry.dial_peer_once(remote.id(), &targets)
            ),
            async {
                for target in &targets {
                    loop {
                        let (send, mut recv) =
                            tokio::time::timeout(Duration::from_secs(5), remote_conn.accept_bi())
                                .await
                                .unwrap()
                                .unwrap();
                        let control::FrameRead::Frame(frame) =
                            control::recv_frame(&mut recv).await.unwrap()
                        else {
                            panic!("expected a known control frame");
                        };
                        match frame.msg {
                            ControlMsg::NetworkHandles { .. } => continue,
                            ControlMsg::MeshHello { .. } => {
                                assert_eq!(frame.net, Some(target.network_key));
                                // A known member finishes its optional reply
                                // without a body, as the real demux does.
                                drop(send);
                                break;
                            }
                            other => panic!("expected MeshHello, got {other:?}"),
                        }
                    }
                }
            },
        );
        assert!(connected.expect("reuse completes without another dial"));
        assert!(registry.peers.conn_is_current(&peer_ip, conn.stable_id()));
    }
}

#[tokio::test]
async fn cancelling_a_second_hello_keeps_the_first_network_connection_driven() {
    let alpn = transport::mesh_alpn();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let local = Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![alpn.clone()])
        .relay_mode(iroh::RelayMode::Disabled)
        .address_lookup(lookup.clone())
        .bind()
        .await
        .unwrap();
    let remote = Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![alpn])
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    lookup.add_endpoint_info(remote.addr());
    let tmp = tempfile::tempdir().unwrap();
    let store = FsStore::load(tmp.path()).await.unwrap();
    let registry = sample_registry(
        local.clone(),
        IrohIdentityProvider::new(local.id()),
        store.clone(),
    );
    let router = Arc::new(ProtocolRouter::new(
        BlobsProtocol::new(&store, None),
        Arc::new(FileService::new(
            SecretKey::generate(),
            Arc::clone(&registry.transport),
            Arc::clone(&registry),
            registry.device_user_map.clone(),
            Arc::new(transfers::TransferRegistry::new()),
        )),
        Arc::new(ConnectService::new(Arc::clone(&registry))),
        Arc::new(ManagementService::new(
            Arc::clone(&registry.transport),
            Arc::clone(&registry),
            SecretKey::generate(),
        )),
        Arc::clone(&registry.conn),
    ));
    router.set_mesh_dispatch(MeshDispatch {
        registry: Arc::downgrade(&registry),
        token: registry.shutdown_token.clone(),
        on_peer_connected: Arc::new(|_| {}),
    });
    registry.set_protocol_router(&router);
    let targets = ["net-a", "net-b"].map(|network| DialTarget {
        network: network.to_string(),
        network_key: SecretKey::generate().public(),
    });
    let remote_id = remote.id();
    let dial = {
        let registry = Arc::clone(&registry);
        let targets = targets.clone();
        tokio::spawn(async move { registry.dial_peer_once(remote_id, &targets).await })
    };
    let (second_hello_tx, second_hello_rx) = tokio::sync::oneshot::channel();
    let accepting = {
        let remote = remote.clone();
        tokio::spawn(async move {
            let conn = remote.accept().await.unwrap().await.unwrap();
            for (index, target) in targets.iter().enumerate() {
                loop {
                    let (send, mut recv) = conn.accept_bi().await.unwrap();
                    let control::FrameRead::Frame(frame) =
                        control::recv_frame(&mut recv).await.unwrap()
                    else {
                        panic!("expected a known control frame");
                    };
                    match frame.msg {
                        ControlMsg::NetworkHandles { .. } => continue,
                        ControlMsg::MeshHello { .. } => {
                            assert_eq!(frame.net, Some(target.network_key));
                            if index == 0 {
                                drop(send);
                                break;
                            }
                            // Keep the second reply unfinished while the
                            // caller cancels the dial, without sleeping for
                            // its production deadline.
                            second_hello_tx.send((conn, send)).unwrap();
                            return;
                        }
                        other => panic!("expected MeshHello, got {other:?}"),
                    }
                }
            }
        })
    };
    let (remote_conn, second_reply) = tokio::time::timeout(Duration::from_secs(5), second_hello_rx)
        .await
        .expect("the first hello completes and the second starts")
        .unwrap();
    dial.abort();
    assert!(dial.await.unwrap_err().is_cancelled());
    accepting.await.unwrap();
    let peer_ip = derive_ipv6(&remote_id);
    assert!(registry.peers.shares_network_v6(&peer_ip, "net-a"));
    assert!(!registry.peers.shares_network_v6(&peer_ip, "net-b"));
    open_and_send(&remote_conn, None, &ControlMsg::Ping { nonce: 7 })
        .await
        .unwrap();
    let nonce = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let (_, mut recv) = remote_conn.accept_bi().await.unwrap();
            match control::recv_msg(&mut recv).await.unwrap() {
                ControlMsg::NetworkHandles { .. } => continue,
                ControlMsg::Pong { nonce } => break nonce,
                other => panic!("expected Pong from the connection driver, got {other:?}"),
            }
        }
    })
    .await
    .expect("cancelling the second hello must preserve the first network's driver");
    assert_eq!(nonce, 7);
    drop(second_reply);
    registry.shutdown_token.cancel();
    local.close().await;
    remote.close().await;
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn reconnect_registration_survives_a_stopped_welcome_reply() {
    for stop_reply in [false, true] {
        let alpn = transport::mesh_alpn();
        let server = Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![alpn.clone()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![alpn.clone()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let (outgoing, incoming) = tokio::join!(client.connect(server.addr(), &alpn), async {
            server.accept().await.unwrap().await.unwrap()
        },);
        let outgoing = outgoing.unwrap();
        let handler = sample_coordinator_handler().await;
        let (state, registry) = handler_parts(&handler);
        let mut member = seated(client.id());
        member.hostname = Some("member".to_string());
        state.write().unwrap().members.add(member);
        let ip = derive_ipv6(&client.id());
        // The first network has already registered and announced itself.
        // The coordinator's hello adds a second network to this connection.
        registry
            .peers
            .add(ip, incoming.clone(), client.id(), "other-net");
        let net_key = state.read().unwrap().network_public_key;
        let (mut send, recv) = outgoing.open_bi().await.unwrap();
        let mut recv = Some(recv);
        if stop_reply {
            // A legacy peer can discard the receive half immediately.
            drop(recv.take());
        }
        control::send_msg(
            &mut send,
            Some(net_key),
            &ControlMsg::MeshHello {
                identity: client.id(),
                hostname: Some("member".to_string()),
                device_cert: None,
            },
        )
        .await
        .unwrap();
        let (reply, mut request) = incoming.accept_bi().await.unwrap();
        let control::FrameRead::Frame(frame) = control::recv_frame(&mut request).await.unwrap()
        else {
            panic!("expected MeshHello");
        };
        if stop_reply {
            // Ensure STOP_SENDING arrives before the handler writes Welcome,
            // making the failure deterministic rather than timing-dependent.
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), reply.stopped())
                    .await
                    .unwrap()
                    .unwrap(),
                Some(VarInt::from_u32(0))
            );
        }
        let registered = handler
            .handle_frame(&incoming, reply, client.id(), frame.msg)
            .await;
        assert!(registry.peers.shares_network_v6(&ip, "other-net"));
        assert!(registry.peers.shares_network_v6(&ip, "test-net"));
        assert_eq!(
            registered,
            Some(ip),
            "the demux must announce handles for the registered network even if Welcome fails"
        );
        assert_eq!(
            registry.dns.hostname_table.read().await["test-net"]["member"],
            ip,
            "a failed reply must not skip the peer's DNS refresh"
        );
        if let Some(mut recv) = recv {
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(3), control::recv_msg(&mut recv))
                    .await
                    .unwrap()
                    .unwrap(),
                ControlMsg::Welcome { .. }
            ));
        }
    }
}

#[tokio::test]
async fn register_replaces_member_handler_with_coordinator() {
    // AcceptHandler exposes whether it is the coordinator variant.
    assert!(!sample_member_handler().await.is_coordinator());
    assert!(sample_coordinator_handler().await.is_coordinator());
}

#[tokio::test]
async fn exit_offer_is_recorded_by_every_handler_role() {
    // `ExitNodeOffer` must be handled identically by both accept-handler
    // roles: it once reached only the Member dispatch, so a plain
    // coordinator (the one node that can record the offer on the signed
    // roster) silently discarded it and no exit node was ever advertised.
    use crate::membership::{ExitFamilies, Member};
    for handler in [
        sample_coordinator_handler().await,
        sample_member_handler().await,
    ] {
        let (registry, state) = match &handler {
            AcceptHandler::Coordinator(s) => (Arc::clone(&s.registry), Arc::clone(&s.state)),
            AcceptHandler::Member(s) => (Arc::clone(&s.registry), Arc::clone(&s.state)),
        };
        // Hold the network key (recording needs it) and list the sender.
        let sender = SecretKey::from_bytes(&[9u8; 32]).public();
        {
            let mut s = state.write().unwrap();
            s.network_secret_key = Some(SecretKey::from_bytes(&[1u8; 32]));
            s.members.add(Member {
                identity: sender,
                is_coordinator: false,
                hostname: None,
                user_identity: None,
                device_cert: None,
                last_seen: None,
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
            });
        }
        registry.networks.insert(
            "test-net".to_string(),
            NetworkHandle {
                name: "test-net".to_string(),
                network_key: state.read().unwrap().network_public_key,
                role: NetworkRole::Coordinator,
                state: Arc::clone(&state),
                dht_notify: None,
                cancel: CancellationToken::new(),
                tasks: Vec::new(),
                invite_lock: Arc::new(AsyncMutex::new(())),
                incompatible: None,
            },
        );
        assert!(
            handler.handle_common(
                sender,
                &ControlMsg::ExitNodeOffer {
                    enabled: true,
                    exit_families: ExitFamilies::Dual,
                },
            ),
            "ExitNodeOffer must be consumed by the role-independent dispatch"
        );
        // The recording runs off the demux loop; wait for it to land.
        let mut recorded = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            // Both halves of the offer: the IPv6 claim rides the same message
            // and has to reach the signed roster with it, or an IPv6-only
            // client sees a gateway it will refuse to select.
            let done = state
                .read()
                .unwrap()
                .members
                .get(&sender)
                .is_some_and(|m| m.exit_node && m.exit_families.carries_v6());
            if done {
                recorded = true;
                break;
            }
        }
        assert!(
            recorded,
            "exit offer not recorded (coordinator variant: {})",
            handler.is_coordinator()
        );
    }
}

/// One network the coordinator in [`serve_coordinator`] accepts frames for.
struct ServedNetwork {
    key: EndpointId,
    name: &'static str,
    state: SharedNetworkState,
}

/// Accept one mesh connection on `coord_ep` and drive its demux, with a
/// coordinator handler for each of `networks` backed by `registry`.
fn serve_coordinator(
    coord_ep: &Endpoint,
    registry: &Arc<NetworkRegistry>,
    networks: Vec<ServedNetwork>,
) -> tokio::task::JoinHandle<()> {
    let connmgr = Arc::new(ConnectionManager::new());
    connmgr.set_mesh_dispatch(MeshDispatch {
        registry: Arc::downgrade(registry),
        token: CancellationToken::new(),
        on_peer_connected: Arc::new(|_| {}),
    });
    for network in networks {
        connmgr.register(
            network.key,
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                registry: Arc::clone(registry),
                network_name: network.name.to_string(),
                state: network.state,
                dht_notify: None,
                invite_lock: Arc::new(AsyncMutex::new(())),
            })),
        );
    }
    let coord_ep = coord_ep.clone();
    tokio::spawn(async move {
        let conn = coord_ep
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("accept connection");
        connmgr.drive_mesh_connection(conn, false).await;
    })
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_offer_over_the_wire_reaches_the_coordinator_roster() {
    // End-to-end replication of the original bug: a member opens a real mesh
    // connection to a coordinator and sends `ExitNodeOffer` over it. The frame
    // has to travel through the connection demux into the coordinator's
    // recording path and flip the member's roster `exit_node` flag. Before the
    // fix the coordinator's accept handler dropped the frame on its catch-all,
    // so nothing was recorded and no exit node was ever advertised.
    use crate::membership::{ExitFamilies, Member};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode, SecretKey};

    let alpn = transport::mesh_alpn();

    // Coordinator (accepts) and member (dials), on loopback with relay
    // disabled for a deterministic direct connection.
    let coord_key = SecretKey::from_bytes(&[7u8; 32]);
    let coord_id = coord_key.public();
    let coord_ep = Endpoint::builder(presets::N0)
        .secret_key(coord_key)
        .alpns(vec![alpn.clone()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let member_ep = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&[8u8; 32]))
        .alpns(vec![alpn.clone()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let member_id = member_ep.id();

    // Coordinator registry holding the network key, member already in roster.
    let tmp = tempfile::tempdir().unwrap();
    let blob_store = FsStore::load(tmp.path()).await.unwrap();
    let registry = sample_registry(
        coord_ep.clone(),
        IrohIdentityProvider::new(coord_id),
        blob_store.clone(),
    );
    let state = make_network_state();
    let net_pubkey = state.read().unwrap().network_public_key;
    {
        let mut s = state.write().unwrap();
        s.network_secret_key = Some(SecretKey::from_bytes(&[1u8; 32]));
        s.members.add(Member {
            identity: member_id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
    }
    registry.networks.insert(
        "test-net".to_string(),
        NetworkHandle {
            name: "test-net".to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Coordinator,
            state: Arc::clone(&state),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );

    // Coordinator accepts and drives the demux; member dials.
    let coord_addr = coord_ep.addr();
    let accept = serve_coordinator(
        &coord_ep,
        &registry,
        vec![ServedNetwork {
            key: net_pubkey,
            name: "test-net",
            state: Arc::clone(&state),
        }],
    );
    let conn = member_ep
        .connect(coord_addr, &alpn)
        .await
        .expect("member dials coordinator");

    // Member advertises its exit-node offer over the wire.
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    control::send_msg(
        &mut send,
        Some(net_pubkey),
        &ControlMsg::ExitNodeOffer {
            enabled: true,
            exit_families: ExitFamilies::V4,
        },
    )
    .await
    .unwrap();

    // The coordinator's roster must reflect the offer.
    let mut recorded = false;
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if state
            .read()
            .unwrap()
            .members
            .get(&member_id)
            .is_some_and(|m| m.exit_node)
        {
            recorded = true;
            break;
        }
    }
    accept.abort();
    assert!(
        recorded,
        "coordinator did not record the member's exit-node offer received over the wire"
    );
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_exit_offers_delivers_over_the_retained_connection() {
    // Full replication of the live failure: an offering member runs the real
    // `sync_exit_offers` and the coordinator's roster must end up flagged.
    // The member delivers over its retained mesh connection (the one the
    // ConnectionManager owns); the earlier bug dialed a throwaway connection
    // and dropped it, so the frame never flushed and the coordinator's
    // roster never changed even though the sender logged "delivered".
    use crate::membership::{ExitFamilies, Member, derive_ipv6};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode, SecretKey};

    let alpn = transport::mesh_alpn();
    let net_secret = SecretKey::from_bytes(&[1u8; 32]);
    let net_pubkey = net_secret.public();

    let coord_key = SecretKey::from_bytes(&[7u8; 32]);
    let coord_id = coord_key.public();
    let coord_ep = Endpoint::builder(presets::N0)
        .secret_key(coord_key)
        .alpns(vec![alpn.clone()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let member_key = SecretKey::from_bytes(&[8u8; 32]);
    let member_id = member_key.public();
    let member_ep = Endpoint::builder(presets::N0)
        .secret_key(member_key)
        .alpns(vec![alpn.clone()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();

    // A roster both sides share: the coordinator (key holder) and the member.
    let roster = || {
        vec![
            Member {
                identity: coord_id,
                is_coordinator: true,
                hostname: None,
                user_identity: None,
                device_cert: None,
                last_seen: None,
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
            },
            Member {
                identity: member_id,
                is_coordinator: false,
                hostname: None,
                user_identity: None,
                device_cert: None,
                last_seen: None,
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
            },
        ]
    };

    // --- Coordinator side: holds the key, drives the demux. ---
    let coord_tmp = tempfile::tempdir().unwrap();
    let coord_blobs = FsStore::load(coord_tmp.path()).await.unwrap();
    let coord_reg = sample_registry(
        coord_ep.clone(),
        IrohIdentityProvider::new(coord_id),
        coord_blobs.clone(),
    );
    let coord_state = make_network_state();
    {
        let mut s = coord_state.write().unwrap();
        s.network_secret_key = Some(net_secret.clone());
        s.members = MemberList::from_members(roster());
    }
    coord_reg.networks.insert(
        "test-net".to_string(),
        NetworkHandle {
            name: "test-net".to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Coordinator,
            state: Arc::clone(&coord_state),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    let accept = serve_coordinator(
        &coord_ep,
        &coord_reg,
        vec![ServedNetwork {
            key: net_pubkey,
            name: "test-net",
            state: Arc::clone(&coord_state),
        }],
    );

    // --- Member side: offers an exit, holds a retained connection to coord. ---
    let member_tmp = tempfile::tempdir().unwrap();
    let member_blobs = FsStore::load(member_tmp.path()).await.unwrap();
    let member_reg = sample_registry(
        member_ep.clone(),
        IrohIdentityProvider::new(member_id),
        member_blobs.clone(),
    );
    let member_state = make_network_state();
    {
        let mut s = member_state.write().unwrap();
        s.network_secret_key = None; // plain member
        s.members = MemberList::from_members(roster());
    }
    member_reg.networks.insert(
        "test-net".to_string(),
        NetworkHandle {
            name: "test-net".to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Member,
            state: Arc::clone(&member_state),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    // Offering an exit, and the data plane is up so sync is enabled.
    member_reg
        .exit_server
        .reload([("test-net", ["*".to_string()].as_slice())]);
    member_reg
        .exit_sync_enabled
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // The member dials the coordinator and retains the connection in its
    // PeerTable, exactly like the live daemon keeps its coordinator link.
    let member_conn = member_ep
        .connect(coord_ep.addr(), &alpn)
        .await
        .expect("member dials coordinator");
    member_reg.peers.add(
        derive_ipv6(&coord_id),
        member_conn.clone(),
        coord_id,
        "test-net",
    );

    // Run the real reconcile: it must deliver the offer over the retained link.
    member_reg.sync_exit_offers().await;

    let mut recorded = false;
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if coord_state
            .read()
            .unwrap()
            .members
            .get(&member_id)
            .is_some_and(|m| m.exit_node)
        {
            recorded = true;
            break;
        }
    }
    accept.abort();
    assert!(
        recorded,
        "sync_exit_offers did not get the offer recorded on the coordinator over the retained connection"
    );
}

/// A hostname that cannot be saved is reported, and the running network
/// keeps its old name instead of drifting from the saved config.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_hostname_reports_a_failed_save() {
    let env = TestConfigDir::new();
    let daemon = build_headless(false).await.unwrap();
    let state = make_network_state();
    let me = daemon.transport.endpoint.id();
    state.write().unwrap().members.add(seated(me));
    let network_key = state.read().unwrap().network_public_key;
    daemon.registry.networks.insert(
        "test-net".into(),
        NetworkHandle {
            name: "test-net".into(),
            network_key,
            role: NetworkRole::Member,
            state: Arc::clone(&state),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    // A directory where the network's file belongs makes the save fail.
    std::fs::create_dir_all(env.dir.path().join("networks/test-net.toml")).unwrap();
    let before = state
        .read()
        .unwrap()
        .members
        .get(&me)
        .unwrap()
        .hostname
        .clone();
    let reply = daemon.set_hostname("test-net", "renamed").await;
    assert!(reply.is_err(), "{reply:?}");
    assert_eq!(
        state.read().unwrap().members.get(&me).unwrap().hostname,
        before
    );
    daemon.registry.networks.remove("test-net");
    daemon.shutdown_and_close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_counts_only_join_requests_waiting_for_approval() {
    let _env = TestConfigDir::new();
    let daemon = build_headless(false).await.unwrap();
    let state = make_network_state();
    let network_key = state.read().unwrap().network_public_key;
    for seed in [2, 3] {
        state.write().unwrap().pending.insert(
            SecretKey::from_bytes(&[seed; 32]).public(),
            PendingJoin {
                denied: false,
                hostname: Some(format!("joining-peer-{seed}")),
                device_cert: None,
                requested_at: Instant::now(),
            },
        );
    }
    daemon.registry.networks.insert(
        "test-net".into(),
        NetworkHandle {
            name: "test-net".into(),
            network_key,
            role: NetworkRole::Coordinator,
            state,
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    for expected in [2, 1, 0] {
        let requests = daemon.registry.list_requests("test-net").unwrap();
        assert_eq!(requests.len(), expected);
        let networks = daemon.status().networks;
        let network = networks.iter().find(|net| net.name == "test-net").unwrap();
        assert_eq!(network.pending_requests, expected);
        if expected > 0 {
            assert!(
                daemon
                    .registry
                    .deny_request("test-net", &requests[0].short_id)
                    .is_ok()
            );
        }
    }
    daemon.shutdown_and_close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn denied_request_is_delivered_on_retry_instead_of_being_queued_again() {
    use iroh::address_lookup::memory::MemoryLookup;

    let env = TestConfigDir::new();
    let alpn = transport::mesh_alpn();
    let coordinator = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let joiner = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let store = FsStore::load(env.dir.path().join("blobs")).await.unwrap();
    let registry = sample_registry(
        coordinator.clone(),
        IrohIdentityProvider::new(coordinator.id()),
        store.clone(),
    );
    let state = make_network_state();
    let network_key = state.read().unwrap().network_public_key;
    registry.networks.insert(
        "test-net".into(),
        NetworkHandle {
            name: "test-net".into(),
            network_key,
            role: NetworkRole::Coordinator,
            state: Arc::clone(&state),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    let accepting = serve_coordinator(
        &coordinator,
        &registry,
        vec![ServedNetwork {
            key: network_key,
            name: "test-net",
            state: Arc::clone(&state),
        }],
    );
    let connection = joiner.connect(coordinator.addr(), &alpn).await.unwrap();
    for attempt in 0..2 {
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        control::send_msg(
            &mut send,
            Some(network_key),
            &ControlMsg::JoinRequest {
                invite_secret: None,
                hostname: Some("joining-peer".into()),
                device_cert: None,
            },
        )
        .await
        .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), control::recv_msg(&mut recv))
            .await
            .unwrap()
            .unwrap();
        // Consume FIN so the handler knows the decision reached the joiner.
        assert!(recv.read_to_end(0).await.unwrap().is_empty());
        if attempt == 1 {
            assert!(matches!(reply, ControlMsg::JoinDenied { .. }), "{reply:?}");
        } else {
            assert!(matches!(reply, ControlMsg::JoinPending), "{reply:?}");
            assert!(registry.deny_request("test-net", "joining-peer").is_ok());
            assert!(registry.list_requests("test-net").unwrap().is_empty());
        }
    }
    accepting.abort();
    joiner.close().await;
    coordinator.close().await;
    store.shutdown().await.unwrap();
}

/// Pairing sends one join per shared network over a single connection to
/// the primary. A frame that is slow on one network (here: waiting on that
/// network's snapshot commit) must not hold up another network's frame on
/// the same connection, and the slow one still completes afterwards.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demux_handles_frames_for_different_networks_side_by_side() {
    use iroh::address_lookup::memory::MemoryLookup;

    let env = TestConfigDir::new();
    let alpn = transport::mesh_alpn();
    let coord_ep = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let member_ep = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let member_id = member_ep.id();
    let coord_id = coord_ep.id();
    let blob_store = FsStore::load(env.dir.path().join("blobs")).await.unwrap();
    let registry = sample_registry(
        coord_ep.clone(),
        IrohIdentityProvider::new(coord_id),
        blob_store.clone(),
    );

    // Network A seats the member, so its MeshHello is a reconnect that takes
    // A's snapshot commit lock. On network B the member is a stranger, so its
    // JoinRequest is queued for approval and answered with JoinPending.
    let state_a = make_network_state();
    let net_a = state_a.read().unwrap().network_public_key;
    state_a.write().unwrap().members.add(seated(member_id));
    let state_b = make_network_state();
    let net_b = SecretKey::from_bytes(&[3u8; 32]).public();
    {
        let mut s = state_b.write().unwrap();
        s.network_public_key = net_b;
        s.network_name = Some("net-b".to_string());
    }

    let accept = serve_coordinator(
        &coord_ep,
        &registry,
        vec![
            ServedNetwork {
                key: net_a,
                name: "net-a",
                state: Arc::clone(&state_a),
            },
            ServedNetwork {
                key: net_b,
                name: "net-b",
                state: Arc::clone(&state_b),
            },
        ],
    );
    let conn = member_ep
        .connect(coord_ep.addr(), &alpn)
        .await
        .expect("member dials coordinator");

    // Stall network A behind its commit lock, then send A's frame first.
    let commit_a = Arc::clone(&state_a.read().unwrap().snapshot_commit);
    let commit_guard = commit_a.lock().await;
    let (mut send_a, mut recv_a) = conn.open_bi().await.unwrap();
    control::send_msg(
        &mut send_a,
        Some(net_a),
        &ControlMsg::MeshHello {
            identity: member_id,
            hostname: None,
            device_cert: None,
        },
    )
    .await
    .unwrap();
    let (mut send_b, mut recv_b) = conn.open_bi().await.unwrap();
    control::send_msg(
        &mut send_b,
        Some(net_b),
        &ControlMsg::JoinRequest {
            invite_secret: None,
            hostname: None,
            device_cert: None,
        },
    )
    .await
    .unwrap();

    let reply_b = tokio::time::timeout(Duration::from_secs(5), control::recv_msg(&mut recv_b))
        .await
        .expect("network B must be answered while network A is still busy")
        .unwrap();
    assert!(matches!(reply_b, ControlMsg::JoinPending), "{reply_b:?}");

    drop(commit_guard);
    let reply_a = tokio::time::timeout(Duration::from_secs(5), control::recv_msg(&mut recv_a))
        .await
        .expect("network A completes once its commit lock is free")
        .unwrap();
    assert!(matches!(reply_a, ControlMsg::Welcome { .. }), "{reply_a:?}");
    drop(recv_a);

    accept.abort();
    coord_ep.close().await;
    member_ep.close().await;
    blob_store.shutdown().await.unwrap();
}

#[test]
fn holds_key_implies_coordinator_role() {
    assert_eq!(role_for_key_holder(true), NetworkRole::Coordinator);
    assert_eq!(role_for_key_holder(false), NetworkRole::Member);
}

#[test]
fn choose_path_prefers_selected() {
    use ipc::ConnType::*;
    // The selected path wins even when it isn't the "best" type.
    let classes = [(Relay, false), (Direct, true)];
    assert_eq!(super::choose_path_index(&classes), Some(1));
}

#[test]
fn choose_path_falls_back_to_best_unselected() {
    use ipc::ConnType::*;
    // No path selected: report a concrete path (Direct > Relay > Tor)
    // instead of Unknown, so a live connection never shows `?`.
    let classes = [(Relay, false), (Direct, false), (Tor, false)];
    assert_eq!(super::choose_path_index(&classes), Some(1));

    let only_relay = [(Relay, false)];
    assert_eq!(super::choose_path_index(&only_relay), Some(0));
}

#[test]
fn choose_path_empty_is_none() {
    assert_eq!(super::choose_path_index(&[]), None);
}

#[test]
fn rename_satisfied_exact_and_collision_forms() {
    // Exact match confirms the rename.
    assert!(super::rename_satisfied("scw-iroh", Some("scw-iroh")));
    // Coordinator-assigned collision suffix still confirms it.
    assert!(super::rename_satisfied("alice", Some("alice-1")));
    assert!(super::rename_satisfied("alice", Some("alice-42")));
    // A different name (still the old one, or someone else's) does not.
    assert!(!super::rename_satisfied("scw-iroh", Some("bell")));
    // A look-alike that isn't `name-<digits>` does not.
    assert!(!super::rename_satisfied("alice", Some("alice-bob")));
    assert!(!super::rename_satisfied("alice", Some("alicex")));
    assert!(!super::rename_satisfied("alice", Some("alice-")));
    // No blob entry yet: not satisfied.
    assert!(!super::rename_satisfied("alice", None));
}

include!("mesh_request_replies_tests.rs");
include!("protocol_replies_tests.rs");

#[test]
fn promote_is_idempotent_decision() {
    // Re-registering an already-coordinator network is a no-op decision.
    assert!(should_promote(NetworkRole::Member));
    assert!(!should_promote(NetworkRole::Coordinator));
}
