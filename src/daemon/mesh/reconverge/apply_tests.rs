//! The shared apply routine, run on a real headless daemon that holds a network
//! as a plain member or as one of its coordinators. The blob fetch needs a
//! serving peer, so most member tests hand a verified blob straight to
//! `commit_group_blob`, the half of the routine every source of records goes
//! through after the fetch. The coordinator tests run a second coordinator that
//! serves its blob.

use std::sync::MutexGuard;

use iroh::SecretKey;
use iroh::protocol::Router;
use iroh_dns::pkarr::SignedPacket;

use super::*;
use crate::daemon::mesh::destruction::tests::{ConfigDir, Relay, create};

pub(in crate::daemon::mesh) const NETWORK: &str = "home";

/// A record timestamp (microseconds) later than any record the fixture's own
/// coordinator publishes. Its group poller raises the floor to each renewal of
/// the current record it sees, so a hand-set floor must sit above wall-clock
/// time to stay put while a test runs.
const FUTURE: u64 = 1 << 62;

/// A daemon that joined `NETWORK` as a member. Holds the config lock and the
/// config directory for as long as it lives.
pub(in crate::daemon::mesh) struct MemberFixture {
    pub(in crate::daemon::mesh) daemon: Arc<Daemon>,
    pub(in crate::daemon::mesh) state: SharedNetworkState,
    /// The network key, kept so a test can sign records for the network.
    pub(in crate::daemon::mesh) key: SecretKey,
    _relay: Relay,
    _env: ConfigDir,
    _dir: tempfile::TempDir,
    _lock: MutexGuard<'static, ()>,
}

impl MemberFixture {
    #[allow(clippy::await_holding_lock)]
    pub(in crate::daemon::mesh) async fn start() -> Self {
        let lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("temporary config directory");
        let env = ConfigDir::set(dir.path());
        let relay = Relay::start().await;
        relay.configure();
        let daemon = build_headless(false).await.expect("headless daemon");
        let net = create(&daemon, NETWORK).await;
        let key = net
            .network_secret_key
            .expect("a created network holds its key");
        // Demote to a member, so nothing here counts as locally authored.
        config::update_network(NETWORK, |net| {
            net.network_secret_key = None;
            Ok(())
        })
        .expect("demote the network config");
        let state = {
            let mut handle = daemon
                .registry
                .networks
                .get_mut(NETWORK)
                .expect("network is live");
            handle.role = NetworkRole::Member;
            handle.state.write().unwrap().network_secret_key = None;
            Arc::clone(&handle.state)
        };
        Self {
            daemon,
            state,
            key,
            _relay: relay,
            _env: env,
            _dir: dir,
            _lock: lock,
        }
    }

    pub(in crate::daemon::mesh) fn registry(&self) -> Arc<NetworkRegistry> {
        Arc::clone(&self.daemon.registry)
    }

    /// The live roster with `edit` applied, as the verified blob a coordinator
    /// would publish, stored locally the way `fetch_verified_blob` leaves it.
    async fn blob_with(
        &self,
        edit: impl FnOnce(&mut MemberList),
    ) -> (crate::membership::GroupBlob, blake3::Hash) {
        let bytes = {
            let s = self.state.read().unwrap();
            let mut members = s.group.members.clone();
            edit(&mut members);
            crate::membership::canonical_group_bytes(&GroupBlob {
                members: members.clone(),
                approved: s.group.approved.clone(),
                suggested_firewall: s.group.suggested_firewall.clone(),
                name: s.group.name.clone(),
                reusable_keys: s.group.reusable_keys.clone(),
                nullifiers: s.group.nullifiers.clone(),
            })
        };
        self.registry()
            .transport
            .blob_store
            .blobs()
            .add_slice(&bytes)
            .await
            .expect("store the blob");
        let blob = crate::membership::decode_group_blob(&bytes).expect("a canonical blob decodes");
        (blob, blake3::hash(&bytes))
    }

    /// A record for `hash` authored after the last one applied.
    fn newer_record(&self, hash: blake3::Hash) -> SignedGroupRecord {
        let floor = self.state.read().unwrap().last_record_timestamp;
        SignedGroupRecord {
            hash,
            seeds: Vec::new(),
            timestamp: floor.map_or(1, |f| f + 1),
        }
    }

    fn generation(&self) -> blake3::Hash {
        current_group_hash(&self.state.read().unwrap())
    }

    pub(in crate::daemon::mesh) async fn finish(self) {
        self.daemon.shutdown_and_close().await;
    }
}

fn laptop(identity: EndpointId) -> Member {
    Member {
        identity,
        is_coordinator: false,
        hostname: Some("laptop".to_string()),
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    }
}

/// A member learned from a record gets its `.ray` name and its lazy-dial route
/// whichever path delivered the record. The poller and the fast path skipped
/// both, and a later trigger saw "already converged" and never repaired it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn applying_a_record_publishes_dns_and_routes() {
    let fx = MemberFixture::start().await;
    let registry = fx.registry();
    let peer = SecretKey::generate().public();
    let (blob, hash) = fx.blob_with(|m| m.add(laptop(peer))).await;
    let record = fx.newer_record(hash);

    let outcome = commit_group_blob(
        &registry,
        NETWORK,
        &fx.state,
        &None,
        &record,
        fx.generation(),
        blob,
    )
    .await;

    assert_eq!(outcome, ReconvergeOutcome::Applied);
    let v6 = derive_ipv6(&peer);
    assert_eq!(
        registry
            .dns
            .hostname_table
            .read()
            .await
            .get(NETWORK)
            .and_then(|hosts| hosts.get("laptop"))
            .copied(),
        Some(v6)
    );
    assert!(registry.route_map.resolve_v6(&v6).is_some());
    assert_eq!(
        fx.state.read().unwrap().last_record_timestamp,
        Some(record.timestamp)
    );
    fx.finish().await;
}

/// A record older than the last one applied is refused before anything is
/// fetched. The poller had no floor, so a relay serving an old copy rolled the
/// roster back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_older_record_is_refused_on_every_path() {
    let fx = MemberFixture::start().await;
    fx.state.write().unwrap().last_record_timestamp = Some(FUTURE + 1_000);
    let before = fx.generation();
    let (_, hash) = fx
        .blob_with(|m| m.add(laptop(SecretKey::generate().public())))
        .await;
    let record = SignedGroupRecord {
        hash,
        seeds: Vec::new(),
        timestamp: FUTURE + 500,
    };

    let outcome = apply_group_record(
        &fx.daemon.transport.endpoint,
        &fx.registry(),
        NETWORK,
        &fx.state,
        &None,
        &record,
    )
    .await;

    assert_eq!(outcome, ReconvergeOutcome::Stale);
    assert_eq!(fx.generation(), before);
    assert_eq!(
        fx.state.read().unwrap().last_record_timestamp,
        Some(FUTURE + 1_000)
    );
    fx.finish().await;
}

/// A blob that no longer lists this node is our removal, not a roster to adopt,
/// whichever path fetched it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_blob_without_us_departs_instead_of_adopting() {
    let fx = MemberFixture::start().await;
    let me = fx.daemon.transport.endpoint.id();
    let coordinator = SecretKey::generate().public();
    let (blob, hash) = fx
        .blob_with(|m| {
            m.remove(&me);
            m.add(Member {
                is_coordinator: true,
                ..laptop(coordinator)
            });
        })
        .await;
    let record = fx.newer_record(hash);

    let outcome = commit_group_blob(
        &fx.registry(),
        NETWORK,
        &fx.state,
        &None,
        &record,
        fx.generation(),
        blob,
    )
    .await;

    assert_eq!(outcome, ReconvergeOutcome::Departed);
    assert_ne!(fx.state.read().unwrap().converged_hash, Some(hash));
    fx.finish().await;
}

/// A renewal of the record we already hold fetches nothing but raises the replay
/// floor, so an older record for a different roster is refused afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn renewing_the_current_record_raises_the_floor() {
    let fx = MemberFixture::start().await;
    let current = fx.generation();
    {
        let mut s = fx.state.write().unwrap();
        s.converged_hash = Some(current);
        s.last_record_timestamp = Some(FUTURE + 10);
    }
    let renewal = SignedGroupRecord {
        hash: current,
        seeds: Vec::new(),
        timestamp: FUTURE + 50,
    };
    let outcome = apply_group_record(
        &fx.daemon.transport.endpoint,
        &fx.registry(),
        NETWORK,
        &fx.state,
        &None,
        &renewal,
    )
    .await;
    assert_eq!(outcome, ReconvergeOutcome::Current);
    assert_eq!(
        fx.state.read().unwrap().last_record_timestamp,
        Some(FUTURE + 50)
    );

    let (_, other) = fx
        .blob_with(|m| m.add(laptop(SecretKey::generate().public())))
        .await;
    let older = SignedGroupRecord {
        hash: other,
        seeds: Vec::new(),
        timestamp: FUTURE + 30,
    };
    let outcome = apply_group_record(
        &fx.daemon.transport.endpoint,
        &fx.registry(),
        NETWORK,
        &fx.state,
        &None,
        &older,
    )
    .await;
    assert_eq!(outcome, ReconvergeOutcome::Stale);
    assert_eq!(fx.generation(), current);
    fx.finish().await;
}

/// An older signed record that drops this node changes nothing: membership and
/// the saved network survive, whether it is refused before the fetch or after.
/// A newer one is our removal and forgets the saved network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_older_removal_keeps_membership_and_the_saved_network() {
    let fx = MemberFixture::start().await;
    let me = fx.daemon.transport.endpoint.id();
    fx.state.write().unwrap().last_record_timestamp = Some(FUTURE + 20);
    let (blob, hash) = fx
        .blob_with(|m| {
            m.remove(&me);
        })
        .await;
    let older = SignedGroupRecord {
        hash,
        seeds: Vec::new(),
        timestamp: FUTURE + 19,
    };

    let outcome = apply_group_record(
        &fx.daemon.transport.endpoint,
        &fx.registry(),
        NETWORK,
        &fx.state,
        &None,
        &older,
    )
    .await;
    assert_eq!(outcome, ReconvergeOutcome::Stale);
    let outcome = commit_group_blob(
        &fx.registry(),
        NETWORK,
        &fx.state,
        &None,
        &older,
        fx.generation(),
        blob.clone(),
    )
    .await;
    assert_eq!(outcome, ReconvergeOutcome::Superseded);
    assert!(fx.state.read().unwrap().group.members.is_member(&me));
    assert!(config::load_network(NETWORK).unwrap().is_some());
    assert_eq!(
        fx.state.read().unwrap().last_record_timestamp,
        Some(FUTURE + 20)
    );

    let newer = SignedGroupRecord {
        timestamp: FUTURE + 21,
        ..older
    };
    let outcome = commit_group_blob(
        &fx.registry(),
        NETWORK,
        &fx.state,
        &None,
        &newer,
        fx.generation(),
        blob,
    )
    .await;
    assert_eq!(outcome, ReconvergeOutcome::Departed);
    tokio::time::timeout(Duration::from_secs(3), async {
        while config::load_network(NETWORK).unwrap().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the confirmed removal deletes the saved network");
    fx.finish().await;
}

/// A daemon that created `NETWORK` and so coordinates it, next to a second
/// coordinator of the same network that only serves blobs. Holds the config lock
/// and the config directory for as long as it lives.
struct CoordinatorFixture {
    daemon: Arc<Daemon>,
    state: SharedNetworkState,
    key: SecretKey,
    second: Router,
    second_store: FsStore,
    _second_dir: tempfile::TempDir,
    _relay: Relay,
    _env: ConfigDir,
    _dir: tempfile::TempDir,
    _lock: MutexGuard<'static, ()>,
}

impl CoordinatorFixture {
    #[allow(clippy::await_holding_lock)]
    async fn start() -> Self {
        let lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("temporary config directory");
        let env = ConfigDir::set(dir.path());
        let relay = Relay::start().await;
        relay.configure();
        let daemon = build_headless(false).await.expect("headless daemon");
        let net = create(&daemon, NETWORK).await;
        let key = net
            .network_secret_key
            .expect("a created network holds its key");
        let state = Arc::clone(&daemon.registry.networks.get(NETWORK).expect("live").state);

        let second_dir = tempfile::tempdir().expect("temporary blob directory");
        let second_store = FsStore::load(second_dir.path())
            .await
            .expect("second coordinator blob store");
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("loopback address")
            .bind()
            .await
            .expect("second coordinator endpoint");
        daemon
            .transport
            .warm_lookup
            .add_endpoint_info(endpoint.addr());
        let second = Router::builder(endpoint)
            .accept(
                iroh_blobs::protocol::ALPN,
                BlobsProtocol::new(&second_store, None),
            )
            .spawn();
        Self {
            daemon,
            state,
            key,
            second,
            second_store,
            _second_dir: second_dir,
            _relay: relay,
            _env: env,
            _dir: dir,
            _lock: lock,
        }
    }

    /// The edit the second coordinator authors: the live roster plus itself as
    /// a coordinator, stored where only the second coordinator can serve it.
    async fn second_coordinators_edit(&self) -> blake3::Hash {
        let bytes = {
            let s = self.state.read().unwrap();
            let mut group = s.group.clone();
            group.members.add(Member {
                is_coordinator: true,
                ..laptop(self.second.endpoint().id())
            });
            crate::membership::canonical_group_bytes(&group)
        };
        self.second_store
            .blobs()
            .add_slice(&bytes)
            .await
            .expect("store the edit");
        blake3::hash(&bytes)
    }

    fn signed_by_second(&self, hash: blake3::Hash) -> SignedPacket {
        dht::encode_network_record(&self.key, &hash, &[self.second.endpoint().id()])
            .expect("sign the second coordinator's record")
    }

    async fn finish(self) {
        self.second
            .shutdown()
            .await
            .expect("stop the second coordinator");
        self.daemon.shutdown_and_close().await;
    }
}

/// A coordinator learns an edit another coordinator published from its own
/// group poller, with no `MemberSync` or `BlobUpdated` to prompt it. Created
/// and restored coordinators ran no poller, so they missed such an edit until
/// a trigger happened to reach them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_coordinator_polls_an_edit_another_coordinator_published() {
    let fx = CoordinatorFixture::start().await;
    let edit = fx.second_coordinators_edit().await;
    let record = fx.signed_by_second(edit);
    dht::publish_record(&fx.daemon.registry.transport.pkarr, &record)
        .await
        .expect("the second coordinator publishes");

    let converged = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if fx.state.read().unwrap().converged_hash == Some(edit) {
                break;
            }
            // Cut the poll interval short; the poller does the resolve.
            fx.daemon.registry.poll_nudge.notify_waiters();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(converged.is_ok(), "the poller never applied the edit");
    assert!(
        fx.state
            .read()
            .unwrap()
            .group
            .members
            .is_member(&fx.second.endpoint().id())
    );
    fx.finish().await;
}

/// A record signed before this coordinator's own latest publish is stale, even
/// though it names a blob this node does not hold and can fetch. A coordinator
/// kept no floor, so once it polled its own record, a relay serving an older
/// copy would roll back its edit and the publisher would sign the rollback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_coordinator_refuses_a_record_older_than_its_own_publish() {
    let fx = CoordinatorFixture::start().await;
    let registry = Arc::clone(&fx.daemon.registry);
    let edit = fx.second_coordinators_edit().await;
    let stale = fx.signed_by_second(edit);
    let own = fx
        .state
        .read()
        .unwrap()
        .converged_hash
        .expect("a created network has a converged hash");
    assert!(
        registry
            .publish_group_hash(NETWORK, &fx.key, own, &fx.state)
            .await
            .is_some(),
        "the coordinator republishes after the stale record was signed"
    );

    let record = SignedGroupRecord {
        hash: edit,
        seeds: vec![fx.second.endpoint().id()],
        timestamp: stale.timestamp().as_micros(),
    };
    let outcome = apply_group_record(
        &fx.daemon.transport.endpoint,
        &registry,
        NETWORK,
        &fx.state,
        &None,
        &record,
    )
    .await;

    assert_eq!(outcome, ReconvergeOutcome::Stale);
    assert_eq!(fx.state.read().unwrap().converged_hash, Some(own));
    fx.finish().await;
}
