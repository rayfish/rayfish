//! The shared apply routine, run on a real headless daemon that holds a network
//! as a plain member. The blob fetch needs a serving peer, so most tests hand a
//! verified blob straight to `commit_group_blob`, the half of the routine every
//! source of records goes through after the fetch.

use std::sync::MutexGuard;

use iroh::SecretKey;

use super::*;
use crate::daemon::mesh::destruction::tests::{ConfigDir, Relay, create};

pub(in crate::daemon::mesh) const NETWORK: &str = "home";

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

    pub(in crate::daemon::mesh) fn ctx(&self) -> MeshCtx {
        self.daemon.registry.mesh_ctx()
    }

    /// The live roster with `edit` applied, as the verified blob a coordinator
    /// would publish, stored locally the way `fetch_verified_blob` leaves it.
    async fn blob_with(
        &self,
        edit: impl FnOnce(&mut MemberList),
    ) -> (crate::membership::GroupBlob, blake3::Hash) {
        let bytes = {
            let s = self.state.read().unwrap();
            let mut members = s.members.clone();
            edit(&mut members);
            crate::membership::canonical_group_bytes(
                &members,
                &s.approved,
                &s.suggested_firewall,
                s.group_name.as_deref(),
                &s.reusable_keys,
                &s.nullifiers,
            )
        };
        self.ctx()
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
    let ctx = fx.ctx();
    let peer = SecretKey::generate().public();
    let (blob, hash) = fx.blob_with(|m| m.add(laptop(peer))).await;
    let record = fx.newer_record(hash);

    let outcome = commit_group_blob(
        &ctx,
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
        ctx.hostname_table
            .read()
            .await
            .get(NETWORK)
            .and_then(|hosts| hosts.get("laptop"))
            .copied(),
        Some(v6)
    );
    assert!(ctx.route_map.resolve_v6(&v6).is_some());
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
    fx.state.write().unwrap().last_record_timestamp = Some(1_000);
    let before = fx.generation();
    let (_, hash) = fx
        .blob_with(|m| m.add(laptop(SecretKey::generate().public())))
        .await;
    let record = SignedGroupRecord {
        hash,
        seeds: Vec::new(),
        timestamp: 500,
    };

    let outcome = apply_group_record(
        &fx.daemon.transport.endpoint,
        &fx.ctx(),
        NETWORK,
        &fx.state,
        &None,
        &record,
    )
    .await;

    assert_eq!(outcome, ReconvergeOutcome::Stale);
    assert_eq!(fx.generation(), before);
    assert_eq!(fx.state.read().unwrap().last_record_timestamp, Some(1_000));
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
        &fx.ctx(),
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
