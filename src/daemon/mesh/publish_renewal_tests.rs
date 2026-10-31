//! A coordinator's lease renewal first adopts a newer canonical record, so it
//! cannot republish over another coordinator's edit. The daemon's own pkarr
//! client talks to a local relay whose reply each scenario picks.

use std::sync::Mutex;

use iroh::{RelayMode, endpoint::presets, protocol::Router};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use url::Url;

use super::*;
use crate::daemon::mesh::destruction::tests::ConfigDir;

enum CanonicalReply {
    Record(SignedPacket),
    Missing,
    Unavailable,
}

/// The canonical reply is set after the daemon starts, since the record names
/// a blob that holds the daemon's own identity.
type Canonical = Arc<Mutex<CanonicalReply>>;

struct TestRelay {
    url: Url,
    canonical: Canonical,
    published: oneshot::Receiver<SignedPacket>,
    task: JoinHandle<()>,
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestRelay {
    async fn start(network: EndpointId) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let (published, receiver) = oneshot::channel();
        let published = Arc::new(Mutex::new(Some(published)));
        let canonical: Canonical = Arc::new(Mutex::new(CanonicalReply::Missing));
        let task = tokio::spawn({
            let canonical = Arc::clone(&canonical);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        continue;
                    };
                    let canonical = Arc::clone(&canonical);
                    let published = Arc::clone(&published);
                    // The daemon's other discovery traffic shares this relay; one
                    // connection it drops must not stop the others being served.
                    tokio::spawn(async move {
                        let _ = serve(stream, network, &canonical, &published).await;
                    });
                }
            }
        });
        Self {
            url,
            canonical,
            published: receiver,
            task,
        }
    }

    fn reply(&self, reply: CanonicalReply) {
        *self.canonical.lock().unwrap() = reply;
    }

    /// Point the daemon's discovery (and so its pkarr client) at this relay.
    fn configure(&self) {
        config::update_settings(|cfg| {
            cfg.mdns_enabled = false;
            cfg.discovery_dns = config::ServerOverride {
                servers: vec![self.url.to_string()],
                replace: true,
            };
            Ok(())
        })
        .unwrap();
    }
}

async fn serve(
    mut stream: TcpStream,
    network: EndpointId,
    canonical: &Mutex<CanonicalReply>,
    published: &Mutex<Option<oneshot::Sender<SignedPacket>>>,
) -> Result<()> {
    let mut request = Vec::new();
    let body_start = loop {
        if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        let mut chunk = [0; 2048];
        let count = stream.read(&mut chunk).await?;
        anyhow::ensure!(count != 0, "an HTTP request must include its headers");
        request.extend_from_slice(&chunk[..count]);
        anyhow::ensure!(request.len() <= 8192, "oversized test request");
    };
    let header = String::from_utf8(request[..body_start].to_vec())?;
    let body_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    anyhow::ensure!(
        body_length <= SignedPacket::MAX_BYTES,
        "oversized test body"
    );
    while request.len() < body_start + body_length {
        let mut chunk = [0; 2048];
        let count = stream.read(&mut chunk).await?;
        anyhow::ensure!(count != 0, "an HTTP body must be complete");
        request.extend_from_slice(&chunk[..count]);
    }
    let first = header.lines().next().unwrap_or_default();
    let is_network = first
        .split_whitespace()
        .nth(1)
        .is_some_and(|path| path.ends_with(&network.to_z32()));
    let (status, body) = if first.starts_with("PUT ") && is_network {
        let packet = SignedPacket::from_relay_payload(
            &network,
            &request[body_start..body_start + body_length],
        )?;
        if let Some(sender) = published.lock().unwrap().take() {
            let _ = sender.send(packet);
        }
        ("200 OK", Vec::new())
    } else if first.starts_with("PUT ") {
        ("200 OK", Vec::new())
    } else if is_network {
        match &*canonical.lock().unwrap() {
            CanonicalReply::Record(packet) => ("200 OK", packet.to_relay_payload().to_vec()),
            CanonicalReply::Missing => ("404 Not Found", Vec::new()),
            CanonicalReply::Unavailable => ("503 Service Unavailable", Vec::new()),
        }
    } else {
        // The separate destruction-discovery record is absent.
        ("404 Not Found", Vec::new())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

fn member(identity: EndpointId, coordinator: bool) -> Member {
    Member {
        identity,
        is_coordinator: coordinator,
        hostname: None,
        user_identity: None,
        device_cert: None,
        last_seen: None,
        exit_node: false,
        exit_families: ExitFamilies::Unknown,
    }
}

fn network_state(key: &SecretKey, members: Vec<Member>) -> SharedNetworkState {
    let mut state = NetworkState {
        group: GroupBlob {
            members: MemberList::from(members),
            approved: ApprovedList::new(),
            suggested_firewall: SuggestedFirewall::default(),
            name: Some("test".into()),
            reusable_keys: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        },
        snapshot: None,
        snapshot_commit: Arc::new(AsyncMutex::new(())),
        destroyed: false,
        converged_hash: None,
        unconfirmed_durable_hash: None,
        network_secret_key: Some(key.clone()),
        network_public_key: key.public(),
        network_name: Some("test".into()),
        mode: GroupMode::Restricted,
        last_record_timestamp: None,
        pending_suggestions: Vec::new(),
        pending: HashMap::new(),
    };
    state.refresh_snapshot();
    Arc::new(RwLock::new(state))
}

#[derive(Clone, Copy)]
enum Scenario {
    NewCanonical,
    UnpublishedLocal,
    MissingCanonical,
    UnavailableCanonical,
}

#[allow(clippy::await_holding_lock)] // serializes the process-wide config override
async fn renewal_scenario(scenario: Scenario) {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let directory = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(directory.path());
    let key = SecretKey::generate();
    let mut relay = TestRelay::start(key.public()).await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    let me = daemon.transport.endpoint.id();
    let admitted = SecretKey::generate().public();
    let local = network_state(&key, vec![member(me, true)]);
    let canonical = network_state(&key, vec![member(me, true), member(admitted, false)]);
    let old_bytes = local
        .read()
        .unwrap()
        .snapshot
        .as_ref()
        .unwrap()
        .msgpack_bytes
        .clone();
    let new_bytes = canonical
        .read()
        .unwrap()
        .snapshot
        .as_ref()
        .unwrap()
        .msgpack_bytes
        .clone();
    let old_hash = blake3::hash(&old_bytes);
    let new_hash = blake3::hash(&new_bytes);
    for bytes in [&old_bytes, &new_bytes] {
        daemon
            .transport
            .blob_store
            .blobs()
            .add_slice(bytes)
            .await
            .unwrap();
    }
    let provider = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let provider_id = provider.id();
    daemon
        .transport
        .warm_lookup
        .add_endpoint_info(provider.addr());
    let router = Router::builder(provider)
        .accept(
            iroh_blobs::protocol::ALPN,
            BlobsProtocol::new(&daemon.transport.blob_store, None),
        )
        .spawn();
    let record = dht::encode_network_record(&key, &new_hash, &[provider_id]).unwrap();
    relay.reply(match scenario {
        Scenario::NewCanonical | Scenario::UnpublishedLocal => CanonicalReply::Record(record),
        Scenario::MissingCanonical => CanonicalReply::Missing,
        Scenario::UnavailableCanonical => CanonicalReply::Unavailable,
    });
    config::save_network(&config::NetworkConfig {
        network_public_key: Some(key.public()),
        network_secret_key: Some(key.clone()),
        last_group_hash: Some(old_hash),
        last_group_hash_published: !matches!(scenario, Scenario::UnpublishedLocal),
        ..config::empty_network_config("test")
    })
    .unwrap();
    let notify = Arc::new(tokio::sync::Notify::new());
    let token = daemon.registry.shutdown_token.child_token();
    daemon.registry.networks.insert(
        "test".into(),
        NetworkHandle {
            name: "test".into(),
            network_key: key.public(),
            role: NetworkRole::Coordinator,
            state: Arc::clone(&local),
            dht_notify: Some(Arc::clone(&notify)),
            cancel: token.clone(),
            tasks: Vec::new(),
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    if matches!(scenario, Scenario::UnavailableCanonical) {
        assert!(
            synchronize_before_renewal(&local, &daemon.registry, "test", key.public())
                .await
                .is_err()
        );
        assert_eq!(local.read().unwrap().converged_hash, Some(old_hash));
        assert_eq!(
            config::load_network("test")
                .unwrap()
                .unwrap()
                .last_group_hash,
            Some(old_hash)
        );
    } else {
        let mut publication = daemon.registry.records_published.subscribe();
        let publisher = spawn_network_publisher(
            key.clone(),
            Arc::clone(&local),
            Arc::clone(&daemon.registry),
            "test".into(),
            None,
            notify,
            token.clone(),
        );
        let packet = tokio::time::timeout(Duration::from_secs(5), &mut relay.published)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), publication.changed())
            .await
            .unwrap()
            .unwrap();
        let expected = if matches!(scenario, Scenario::NewCanonical) {
            new_hash
        } else {
            old_hash
        };
        assert_eq!(dht::decode_network_record(&packet).unwrap().0, expected);
        assert_eq!(local.read().unwrap().converged_hash, Some(expected));
        assert_eq!(
            local.read().unwrap().last_record_timestamp,
            Some(packet.timestamp().as_micros())
        );
        assert_eq!(
            config::load_network("test")
                .unwrap()
                .unwrap()
                .last_group_hash,
            Some(expected)
        );
        if matches!(scenario, Scenario::NewCanonical) {
            assert!(local.read().unwrap().group.members.is_member(&admitted));
            // The pre-renewal roster, authored before what this node then
            // published, cannot roll the admission back.
            assert_eq!(
                apply_group_record(
                    &daemon.transport.endpoint,
                    &daemon.registry,
                    "test",
                    &local,
                    &None,
                    &SignedGroupRecord {
                        hash: old_hash,
                        seeds: vec![provider_id],
                        timestamp: packet.timestamp().as_micros().checked_sub(1).unwrap(),
                    },
                )
                .await,
                ReconvergeOutcome::Stale
            );
            assert!(local.read().unwrap().group.members.is_member(&admitted));
            assert_eq!(
                config::load_network("test")
                    .unwrap()
                    .unwrap()
                    .last_group_hash,
                Some(new_hash)
            );
        }
        token.cancel();
        publisher.await.unwrap();
    }
    drop(relay);
    router.shutdown().await.unwrap();
    daemon.shutdown_and_close().await;
}

#[tokio::test]
async fn clean_publisher_adopts_canonical_admission_before_renewing() {
    renewal_scenario(Scenario::NewCanonical).await;
}

#[tokio::test]
async fn unpublished_local_snapshot_keeps_publication_priority() {
    renewal_scenario(Scenario::UnpublishedLocal).await;
}

#[tokio::test]
async fn missing_canonical_record_allows_expired_lease_recovery() {
    renewal_scenario(Scenario::MissingCanonical).await;
}

#[tokio::test]
async fn unavailable_canonical_record_defers_clean_renewal() {
    renewal_scenario(Scenario::UnavailableCanonical).await;
}
