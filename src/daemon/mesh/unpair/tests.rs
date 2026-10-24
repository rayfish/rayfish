//! Unpairs between real daemons: a primary and its paired device, each built
//! from a config tree of its own and run on a runtime whose threads read that
//! tree (`config::set_thread_config_dir`), since the config directory is
//! otherwise process-wide. A local discovery relay stands in for the public
//! one, and a daemon learns the other's address as a warm hint, the way an
//! earlier connection leaves it.

use iroh::RelayMode;
use iroh::endpoint::presets;

use super::super::destruction::tests::Relay;
use super::*;

/// A daemon with a config tree of its own. Anything that reads config runs
/// through [`Node::run`], on the node's runtime.
struct Node {
    /// The node's identity, stored before its daemon first starts.
    key: SecretKey,
    runtime: Option<tokio::runtime::Runtime>,
    daemon: Option<Arc<Daemon>>,
    _dir: tempfile::TempDir,
}

impl Node {
    async fn new(relay: &Relay) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().to_path_buf();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_start(move || config::set_thread_config_dir(tree.clone()))
            .build()
            .unwrap();
        let node = Self {
            key: SecretKey::generate(),
            runtime: Some(runtime),
            daemon: None,
            _dir: dir,
        };
        let key = node.key.clone();
        let relay = relay.url.to_string();
        node.run(async move {
            identity::store_secret_key(&key).unwrap();
            config::update_settings(|cfg| {
                cfg.mdns_enabled = false;
                cfg.discovery_dns = config::ServerOverride {
                    servers: vec![relay],
                    replace: true,
                };
                Ok(())
            })
            .unwrap();
        })
        .await;
        node
    }

    fn id(&self) -> EndpointId {
        self.key.public()
    }

    /// Run `task` on this node, where config reads go to its tree.
    async fn run<T: Send + 'static>(&self, task: impl Future<Output = T> + Send + 'static) -> T {
        self.spawn(task).await.unwrap()
    }

    /// Start `task` on this node, as [`Node::run`] does, without waiting for it.
    fn spawn<T: Send + 'static>(
        &self,
        task: impl Future<Output = T> + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        self.runtime.as_ref().unwrap().spawn(task)
    }

    async fn start(&mut self) {
        let daemon = self
            .run(async { build_headless(false).await.unwrap() })
            .await;
        self.daemon = Some(daemon);
    }

    /// Shut the daemon down: the node is offline until started again.
    async fn stop(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            self.run(async move { daemon.shutdown_and_close().await })
                .await;
        }
    }

    fn daemon(&self) -> Arc<Daemon> {
        Arc::clone(self.daemon.as_ref().expect("daemon is running"))
    }

    async fn settings(&self) -> config::AppConfig {
        self.run(async { config::load().unwrap() }).await
    }

    async fn cert(&self) -> Option<control::DeviceCert> {
        self.run(async { identity::load_device_cert().unwrap() })
            .await
    }

    async fn has_network(&self, name: &'static str) -> bool {
        self.run(async move { config::load_network(name).unwrap().is_some() })
            .await
    }

    /// Whether the live `name` nullifies `device`.
    fn nullifies(&self, name: &str, device: EndpointId) -> bool {
        let daemon = self.daemon();
        let handle = daemon.registry.networks.get(name).expect("network is live");
        handle.state.read().unwrap().nullifiers.contains(&device)
    }

    async fn unpair_self(&self) -> IpcMessage {
        let daemon = self.daemon();
        self.run(async move { daemon.unpair_self().await }).await
    }

    /// Wait for whatever holds this device's unpair lock to finish, such as a
    /// notice being handled: that runs on a task of its own, which takes the
    /// lock as soon as it runs.
    async fn unpair_settled(&self) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let daemon = self.daemon();
        self.run(async move { drop(daemon.registry.unpair_lock.lock().await) })
            .await;
    }

    /// One attempt at this device's saved unpairs. Returns whether any is left.
    async fn attempt_requests(&self) -> bool {
        let daemon = self.daemon();
        self.run(async move { daemon.registry.attempt_unpair_requests().await })
            .await
    }

    /// Wait, at most 30 s, until `check` holds for this node's settings.
    async fn eventually(
        &self,
        what: &str,
        check: impl Fn(&config::AppConfig) -> bool + Clone + Send + 'static,
    ) {
        for _ in 0..300 {
            let check = check.clone();
            if self
                .run(async move { config::load().is_ok_and(|cfg| check(&cfg)) })
                .await
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for {what}");
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // From inside the test's runtime, where a blocking shutdown panics.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Hand `from` the address `to` listens on, as a warm hint would.
fn introduce(from: &Node, to: &Node) {
    from.daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(to.daemon().transport.endpoint.addr());
}

async fn create(daemon: &Daemon, name: &str) {
    let result = daemon
        .create_network(
            GroupMode::Restricted,
            Some(name.to_string()),
            Some("test-node".to_string()),
        )
        .await;
    assert!(matches!(result, IpcMessage::Created { .. }), "{result:?}");
}

/// Give `device` the certificate `primary_key` signs for it and "home", a
/// network it first joined with that certificate. Returns the certificate.
async fn hold_certificate(device: &Node, primary_key: &SecretKey) -> control::DeviceCert {
    let cert = control::DeviceCert::create(primary_key, &device.id(), 0);
    let daemon = device.daemon();
    let stored = cert.clone();
    let primary = primary_key.public();
    device
        .run(async move {
            identity::store_device_cert(&stored).unwrap();
            create(&daemon, "home").await;
            config::update_network("home", |net| {
                net.join_certificate_issuer = Some(primary);
                Ok(())
            })
            .unwrap();
        })
        .await;
    cert
}

/// Pair `device` with `primary` as a completed pairing leaves them: the device
/// holds the primary's certificate and a network joined with it, and the
/// primary coordinates "home" with the device on its roster as its own device,
/// named "phone". Returns the certificate.
async fn paired(primary: &Node, device: &Node) -> control::DeviceCert {
    let cert = hold_certificate(device, &primary.key).await;
    listed(primary, device.id(), cert.clone()).await;
    cert
}

/// Have `primary` coordinate "home" with `device`, which holds `cert`, on its
/// roster as its own device, named "phone".
async fn listed(primary: &Node, device: EndpointId, cert: control::DeviceCert) {
    let daemon = primary.daemon();
    let primary_id = primary.id();
    primary
        .run(async move {
            create(&daemon, "home").await;
            let handle = daemon.registry.networks.get("home").unwrap();
            let mut state = handle.state.write().unwrap();
            let template = state.members.all()[0].clone();
            state.members.add(Member {
                identity: device,
                is_coordinator: false,
                hostname: Some("phone".to_string()),
                user_identity: Some(primary_id),
                device_cert: Some(cert),
                ..template
            });
        })
        .await;
}

/// A ticket for a pairing `primary` opens now, as `ray pair` shows it: the
/// primary's id and the secret.
async fn ticket(primary: &Node) -> (EndpointId, [u8; 32]) {
    let daemon = primary.daemon();
    match primary.run(async move { daemon.start_pairing() }).await {
        IpcMessage::PairingTicket { ticket } => control::decode_pairing_ticket(&ticket).unwrap(),
        other => panic!("{other:?}"),
    }
}

/// Pair `device` with `primary` for real. Returns the certificate it stored.
async fn pair(primary: &Node, device: &Node) -> control::DeviceCert {
    let (primary_id, secret) = ticket(primary).await;
    let daemon = device.daemon();
    let result = device
        .run(async move { daemon.pair_with_device(primary_id, secret.to_vec()).await })
        .await;
    assert!(
        matches!(result, IpcMessage::PairingComplete { .. }),
        "{result:?}"
    );
    device
        .cert()
        .await
        .expect("the pairing stored a certificate")
}

/// Pair the device `key` with `primary` as the device would, over the pairing
/// protocol, confirming that it saved the certificate when `saved`, as a device
/// does once it has. Returns the certificate the primary signed.
async fn pair_as(primary: &Node, key: &SecretKey, saved: bool) -> control::DeviceCert {
    let (_, secret) = ticket(primary).await;
    let request = control::PairMsg::Request {
        secret,
        device_pubkey: key.public(),
    };
    let addr = primary.daemon().transport.endpoint.addr();
    let endpoint = dialer(key.clone()).await;
    let cert = tokio::time::timeout(Duration::from_secs(15), async {
        let conn = endpoint.connect(addr, PAIR_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        control::send_framed(&mut send, &request).await.unwrap();
        let cert = match control::recv_framed(&mut recv).await.unwrap() {
            control::PairMsg::Response { cert, .. } => cert,
            other => panic!("{other:?}"),
        };
        if saved {
            let (mut send, _recv) = conn.open_bi().await.unwrap();
            let confirmation = control::PairMsg::CertificateSaved {
                generation: cert.generation,
            };
            control::send_framed(&mut send, &confirmation)
                .await
                .unwrap();
            // The primary closes once it has saved that.
            conn.closed().await;
        } else {
            conn.close(VarInt::from_u32(0), b"not saved");
        }
        cert
    })
    .await
    .unwrap();
    endpoint.close().await;
    cert
}

fn waiting(cert: &control::DeviceCert) -> Vec<PendingUnpair> {
    vec![PendingUnpair {
        cert: cert.clone(),
        phase: UnpairPhase::Request,
    }]
}

fn revoked(cfg: &config::AppConfig, device: EndpointId) -> bool {
    config::revoked_device_ids(cfg).contains(&device)
}

fn notice(device: EndpointId, generation: u64) -> PendingUnpairNotice {
    PendingUnpairNotice { device, generation }
}

/// A device that unpairs itself while its primary is offline keeps the request,
/// across a restart of its own, until the primary is back and confirms that it
/// saved the revocation, nullifier included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_primary_records_the_unpair_once_it_is_back() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    primary.stop().await;
    // Lookups fail at once while the primary is away, as for one never seen.
    relay.fail.store(true, Ordering::Relaxed);

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert_eq!(device.cert().await, None);
    assert!(!device.has_network("home").await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    assert!(device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    device.stop().await;
    device.start().await;
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));

    relay.fail.store(false, Ordering::Relaxed);
    primary.start().await;
    introduce(&device, &primary);
    assert!(!device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, []);
    assert!(revoked(&primary.settings().await, device.id()));
    assert!(primary.nullifies("home", device.id()));
    device.stop().await;
    primary.stop().await;
}

/// The primary records an unpair asked for after its roster dropped the device,
/// as a departure processed by another coordinator leaves it: the certificate,
/// not the roster, shows the pairing (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_primary_records_an_unpair_after_its_roster_dropped_the_device() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    paired(&primary, &device).await;
    let daemon = primary.daemon();
    let device_id = device.id();
    primary
        .run(async move {
            let handle = daemon.registry.networks.get("home").unwrap();
            handle.state.write().unwrap().members.remove(&device_id);
        })
        .await;
    introduce(&device, &primary);

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    device
        .eventually("the primary to confirm", |cfg| {
            cfg.pending_unpairs.is_empty()
        })
        .await;
    assert!(revoked(&primary.settings().await, device.id()));
    assert!(primary.nullifies("home", device.id()));
    device.stop().await;
    primary.stop().await;
}

/// An unpair interrupted after it was saved, with the certificate still on
/// disk, is finished at the next start: the certificate and its networks go
/// before anything restores them, and the request is kept and sent, not taken
/// for a new pairing (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_during_cleanup_finishes_the_unpair() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    // As an unpair interrupted right after it was saved leaves the device,
    // which also knows where its primary is from earlier connections.
    let saved = cert.clone();
    let hint = primary.daemon().transport.endpoint.addr();
    device
        .run(async move {
            config::update_settings(|cfg| {
                cfg.pending_unpairs.push(PendingUnpair {
                    cert: saved,
                    phase: UnpairPhase::Cleanup,
                });
                cfg.endpoint_hints.clear();
                cfg.endpoint_hint_timestamps.clear();
                crate::endpoint_hints::remember(
                    &mut cfg.endpoint_hints,
                    &mut cfg.endpoint_hint_timestamps,
                    hint.id,
                    hint.addrs.clone(),
                    crate::endpoint_hints::now_secs(),
                );
                Ok(())
            })
            .unwrap();
        })
        .await;
    device.stop().await;

    device.start().await;
    // Gone before the daemon read the certificate, not just by now.
    assert_eq!(device.daemon().registry.device_cert, None);
    assert_eq!(device.cert().await, None);
    assert!(!device.has_network("home").await);
    assert!(!device.daemon().registry.networks.contains_key("home"));
    // Sent, not dropped: the primary has it.
    device
        .eventually("the primary to confirm", |cfg| {
            cfg.pending_unpairs.is_empty()
        })
        .await;
    assert!(revoked(&primary.settings().await, device.id()));
    device.stop().await;
    primary.stop().await;
}

/// A primary answers again for a revocation it already saved, so a device whose
/// answer was lost asks again safely, and keeps its request until it gets one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_confirmation_is_answered_again() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    // The device is offline until it asks again, holding what its unpair
    // leaves: the request, with the certificate and its network gone. Its own
    // attempts would race the test, and the link below speaks with its key.
    device.stop().await;
    let saved = waiting(&cert);
    device
        .run(async move {
            identity::delete_device_cert().unwrap();
            config::delete_network("home").unwrap();
            config::update_settings(|cfg| {
                cfg.pending_unpairs = saved;
                Ok(())
            })
            .unwrap();
        })
        .await;

    // The device's request reaches the primary, which records it, but the
    // answer is lost: the link drops before the device reads it.
    let link = dialer(device.key.clone()).await;
    let conn = link
        .connect(primary.daemon().transport.endpoint.addr(), PAIR_ALPN)
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    control::send_framed(
        &mut send,
        &control::PairMsg::UnpairRequest { cert: cert.clone() },
    )
    .await
    .unwrap();
    let device_id = device.id();
    primary
        .eventually("the revocation to be saved", move |cfg| {
            revoked(cfg, device_id)
        })
        .await;
    link.close().await;
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));

    device.start().await;
    introduce(&device, &primary);
    assert!(!device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, []);
    let revocations = primary.settings().await.revoked_devices;
    assert_eq!(revocations, [device.id().to_string()]);
    device.stop().await;
    primary.stop().await;
}

/// Pairing again with the same primary cancels the request, which would
/// otherwise revoke the new pairing, once the new certificate is saved. A
/// restart between the two cancels it too. The new pairing is signed at a
/// higher generation, so neither a notice nor a nullified blob about the
/// earlier one, acted on only now, ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_again_cancels_the_unpair_request() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    // The primary coordinates no network the device is on, so nothing links the
    // two before the device pairs again: the request cannot reach the primary
    // while lookups fail, and the pairing shares no network to join.
    let cert = hold_certificate(&device, &primary.key).await;
    relay.fail.store(true, Ordering::Relaxed);
    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));

    relay.fail.store(false, Ordering::Relaxed);
    introduce(&device, &primary);
    let renewed = pair(&primary, &device).await;
    assert_eq!(renewed.generation, cert.generation + 1);
    assert_eq!(
        primary.settings().await.device_generations,
        [DeviceGeneration {
            device: device.id(),
            issued: renewed.generation,
            confirmed: Some(renewed.generation),
        }]
    );
    assert_eq!(device.settings().await.pending_unpairs, []);
    assert!(!device.attempt_requests().await);
    assert!(!revoked(&primary.settings().await, device.id()));

    // As a restart between saving the certificate and cancelling leaves it.
    // That restart also loses the confirmation, after which the primary would
    // revoke on the request, so the device cancels it without asking: the
    // primary is away here, and an attempt that asked would keep it.
    primary.stop().await;
    let saved = waiting(&cert);
    device
        .run(async move {
            config::update_settings(|cfg| {
                cfg.pending_unpairs = saved;
                Ok(())
            })
            .unwrap();
        })
        .await;
    assert!(!device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, []);
    assert_eq!(device.cert().await, Some(renewed.clone()));
    assert!(!revoked(&primary.settings().await, device.id()));

    // About the earlier pairing, and acted on after this one.
    let daemon = device.daemon();
    let (primary_id, earlier) = (primary.id(), cert.clone());
    device
        .run(async move {
            let registry = &daemon.registry;
            registry
                .on_unpaired_notice(primary_id, Some(earlier.generation))
                .await;
            registry.unpair_nullified(earlier).await;
        })
        .await;
    assert_eq!(device.cert().await, Some(renewed));
    device.stop().await;
    primary.stop().await;
}

/// A device paired again joins the network its primary shares with it at once,
/// reading the network's record first. The pairing completes only once the
/// primary has lifted the earlier revocation and published the record without
/// it, even when another revocation holds the primary up: the earlier record
/// would have the device take the new pairing for revoked (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_again_completes_once_the_revocation_is_lifted() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    let home = unpaired_from_shared_network(&primary, &device).await;

    // Another revocation holds the primary up while the device pairs again.
    let registry = Arc::clone(&primary.daemon().registry);
    let revoking = registry.revocation_lock.lock().await;
    let (primary_id, secret) = ticket(&primary).await;
    let daemon = device.daemon();
    let pairing = device
        .runtime
        .as_ref()
        .unwrap()
        .spawn(async move { daemon.pair_with_device(primary_id, secret.to_vec()).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!pairing.is_finished());
    assert_eq!(device.cert().await, None);
    drop(revoking);
    let result = pairing.await.unwrap();
    assert!(
        matches!(result, IpcMessage::PairingComplete { .. }),
        "{result:?}"
    );
    let renewed = device
        .cert()
        .await
        .expect("the pairing stored a certificate");
    assert_eq!(renewed.generation, cert.generation + 1);

    rejoined(&device, home).await;
    assert_eq!(device.cert().await, Some(renewed));
    assert!(!revoked(&primary.settings().await, device.id()));
    assert!(!primary.nullifies("home", device.id()));
    device.stop().await;
    primary.stop().await;
}

/// A primary that cannot publish, in time, the record that lifts the revocation
/// of a device pairing again refuses the pairing and puts the revocation back,
/// saving nothing about the pairing. The next attempt lifts it again and
/// completes once the record is out (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_again_is_refused_until_the_lifted_revocation_is_published() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    let home = unpaired_from_shared_network(&primary, &device).await;

    relay.fail.store(true, Ordering::Relaxed);
    let (primary_id, secret) = ticket(&primary).await;
    let daemon = device.daemon();
    let result = device
        .run(async move { daemon.pair_with_device(primary_id, secret.to_vec()).await })
        .await;
    assert!(matches!(result, IpcMessage::Error { .. }), "{result:?}");
    assert_eq!(device.cert().await, None);
    let settings = primary.settings().await;
    assert!(revoked(&settings, device.id()));
    assert_eq!(settings.device_generations, []);
    assert!(primary.nullifies("home", device.id()));

    relay.fail.store(false, Ordering::Relaxed);
    let renewed = pair(&primary, &device).await;
    assert_eq!(renewed.generation, cert.generation + 1);
    rejoined(&device, home).await;
    assert_eq!(device.cert().await, Some(renewed));
    assert!(!revoked(&primary.settings().await, device.id()));
    device.stop().await;
    primary.stop().await;
}

/// A primary refuses to pair a revoked device again while a network it
/// coordinates is not running, as while its restore is in progress or after
/// one failed. That network publishes nothing until it runs, so its last
/// record still nullifies the device, which joins every saved network as soon
/// as it has the certificate. Once the network runs again, the pairing
/// completes. A device that is not revoked pairs regardless.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_again_is_refused_while_a_network_is_not_running() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    let cert = paired(&primary, &device).await;
    let home = unpaired_from_shared_network(&primary, &device).await;

    let restoring = stopped(&primary, "home").await;
    let (primary_id, secret) = ticket(&primary).await;
    let daemon = device.daemon();
    let result = device
        .run(async move { daemon.pair_with_device(primary_id, secret.to_vec()).await })
        .await;
    assert!(matches!(result, IpcMessage::Error { .. }), "{result:?}");
    assert_eq!(device.cert().await, None);
    let settings = primary.settings().await;
    assert!(revoked(&settings, device.id()));
    assert_eq!(settings.device_generations, []);

    drop(restoring);
    restored(&primary, "home").await;
    assert!(primary.nullifies("home", device.id()));
    let renewed = pair(&primary, &device).await;
    assert_eq!(renewed.generation, cert.generation + 1);
    rejoined(&device, home).await;
    assert_eq!(device.cert().await, Some(renewed.clone()));
    assert!(!revoked(&primary.settings().await, device.id()));
    assert!(!primary.nullifies("home", device.id()));

    let _restoring = stopped(&primary, "home").await;
    let again = pair(&primary, &device).await;
    assert_eq!(again.generation, renewed.generation + 1);
    device.stop().await;
    primary.stop().await;
}

/// A rename of a network the primary coordinates waits for a pairing that
/// lifts the revocation of the device. Were it to stop the network after the
/// pairing checked that every network it coordinates runs, the pairing would
/// skip that network, which would come back under its new name still
/// nullifying the device (#258 review).
// The held state is what holds the pairing; nothing else the test awaits
// reads it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_waits_for_a_pairing_that_lifts_a_revocation() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    revoked_on_two_networks(&primary, &device).await;

    let registry = Arc::clone(&primary.daemon().registry);
    let state = Arc::clone(&registry.networks.get("home").unwrap().state);
    let held = state.write().unwrap();
    let pairing = lifting(&primary, device.id()).await;
    // Not restored under the new name until the test lets it.
    let restoring = registry
        .claim_registration("office")
        .expect("no restore of the network runs");
    let renaming = {
        let registry = Arc::clone(&registry);
        primary.spawn(async move { registry.rename_network("work", "office").await })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!renaming.is_finished());
    assert!(registry.networks.contains_key("work"));
    drop(held);
    pairing
        .await
        .unwrap()
        .expect("the pairing lifted the revocation");
    let result = renaming.await.unwrap();
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");

    drop(restoring);
    restored(&primary, "office").await;
    assert!(!primary.nullifies("office", device.id()));
    assert!(!primary.nullifies("home", device.id()));
    assert!(!revoked(&primary.settings().await, device.id()));
    device.stop().await;
    primary.stop().await;
}

/// Leaving a network the primary coordinates waits for a pairing that lifts
/// the revocation of the device. Were it to stop the network after the pairing
/// checked that every network it coordinates runs, the pairing would skip that
/// network, yet share it with the device until it is deleted, and the record
/// the device reads first would still nullify it (#258 review).
// The held state is what holds the pairing; nothing else the test awaits
// reads it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_a_network_waits_for_a_pairing_that_lifts_a_revocation() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    revoked_on_two_networks(&primary, &device).await;

    let registry = Arc::clone(&primary.daemon().registry);
    let state = Arc::clone(&registry.networks.get("home").unwrap().state);
    let held = state.write().unwrap();
    let pairing = lifting(&primary, device.id()).await;
    let leaving = {
        let registry = Arc::clone(&registry);
        primary.spawn(async move { registry.leave_network("work").await })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!leaving.is_finished());
    assert!(registry.networks.contains_key("work"));
    drop(held);
    pairing
        .await
        .unwrap()
        .expect("the pairing lifted the revocation");
    let result = leaving.await.unwrap();
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert!(!primary.has_network("work").await);
    assert!(!primary.nullifies("home", device.id()));
    device.stop().await;
    primary.stop().await;
}

/// A pairing that lifts the revocation of the device waits while a network the
/// primary coordinates is destroyed, until the network is no longer saved.
/// Once the network gives up its key the pairing would skip it, yet share it
/// with the device while it is saved, and its record still nullifies the
/// device until the destruction is published (#258 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_waits_for_a_network_being_destroyed() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    revoked_on_two_networks(&primary, &device).await;
    // A member of "work" that never answers, so telling the members that the
    // network is destroyed takes as long as the primary waits for it.
    let member = unanswering_member().await;
    let registry = Arc::clone(&primary.daemon().registry);
    {
        let handle = registry.networks.get("work").unwrap();
        let mut state = handle.state.write().unwrap();
        let template = state.members.all()[0].clone();
        state.members.add(Member {
            identity: member.id(),
            is_coordinator: false,
            hostname: Some("laptop".to_string()),
            ..template
        });
    }
    primary
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(member.addr());

    let destroying = {
        let registry = Arc::clone(&registry);
        primary.spawn(async move { registry.nuke_network("work", true).await })
    };
    let mut gave_up_its_key = false;
    for _ in 0..300 {
        gave_up_its_key = registry
            .networks
            .get("work")
            .is_some_and(|handle| handle.state.read().unwrap().destroyed);
        if gave_up_its_key {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(gave_up_its_key, "the destruction did not start");
    let pairing = {
        let registry = Arc::clone(&registry);
        let device = device.id();
        primary.spawn(async move { registry.save_new_pairing(device).await })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!pairing.is_finished());
    pairing
        .await
        .unwrap()
        .expect("the pairing lifted the revocation");
    assert!(!primary.has_network("work").await);
    let result = destroying.await.unwrap();
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert!(!primary.nullifies("home", device.id()));
    member.close().await;
    device.stop().await;
    primary.stop().await;
}

/// Pair `device` with `primary`, which coordinates "work" as well as "home",
/// and have the device unpair itself, so that the published records of both
/// networks nullify the device.
async fn revoked_on_two_networks(primary: &Node, device: &Node) {
    paired(primary, device).await;
    let daemon = primary.daemon();
    primary
        .run(async move { create(&daemon, "work").await })
        .await;
    unpaired_from_shared_network(primary, device).await;
    primary
        .eventually("the record of work to be published", |cfg| {
            cfg.networks
                .iter()
                .any(|net| net.name == "work" && net.last_group_hash_published)
        })
        .await;
    assert!(primary.nullifies("work", device.id()));
}

/// Start lifting the revocation of `device` on `primary`, as a pairing of the
/// device does before the primary signs its certificate, and wait until the
/// saved revocation is lifted. By then the pairing has checked that every
/// network the primary coordinates runs, and goes on to read the state of each:
/// a caller holding the state of one holds the pairing there.
async fn lifting(
    primary: &Node,
    device: EndpointId,
) -> tokio::task::JoinHandle<Result<u64, String>> {
    let registry = Arc::clone(&primary.daemon().registry);
    let pairing = primary.spawn(async move { registry.save_new_pairing(device).await });
    primary
        .eventually("the saved revocation to be lifted", move |cfg| {
            !revoked(cfg, device)
        })
        .await;
    pairing
}

/// Have `device`, paired to `primary`, unpair itself, and wait until the
/// primary has recorded that and published the record of "home", the network
/// it coordinates with the device on: the record a joiner reads first now
/// names the device nullified. Returns the key of "home".
async fn unpaired_from_shared_network(primary: &Node, device: &Node) -> EndpointId {
    let home = primary
        .daemon()
        .registry
        .networks
        .get("home")
        .unwrap()
        .network_key;
    introduce(device, primary);
    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    device
        .eventually("the primary to confirm", |cfg| {
            cfg.pending_unpairs.is_empty()
        })
        .await;
    assert!(primary.nullifies("home", device.id()));
    primary
        .eventually("the record of home to be published", |cfg| {
            cfg.networks
                .iter()
                .any(|net| net.name == "home" && net.last_group_hash_published)
        })
        .await;
    home
}

/// Wait until `device` has joined the network `home` again, and for any unpair
/// that joining set off to finish.
async fn rejoined(device: &Node, home: EndpointId) {
    device
        .eventually("the device to join the shared network", move |cfg| {
            cfg.networks
                .iter()
                .any(|net| net.network_public_key == Some(home))
        })
        .await;
    device.unpair_settled().await;
}

/// Stop the network `name` on `primary`, claimed as a restore in progress
/// claims it, so that the restore supervisor leaves it stopped until the claim
/// is dropped.
async fn stopped(primary: &Node, name: &'static str) -> network_registry::RegistrationClaim {
    let registry = Arc::clone(&primary.daemon().registry);
    let claim = registry
        .claim_registration(name)
        .expect("no restore of the network runs");
    assert!(
        primary
            .run(async move { registry.teardown_network_runtime(name).await })
            .await
    );
    claim
}

/// Have the restore supervisor of `primary` bring the network `name` back, and
/// wait, at most a minute, until that restore is over: the network runs, and
/// the restore has dropped its claim, which it holds a while longer, through
/// the DNS update (slow on Windows).
async fn restored(primary: &Node, name: &'static str) {
    let registry = Arc::clone(&primary.daemon().registry);
    registry.nudge_restore();
    for _ in 0..600 {
        if registry.networks.contains_key(name) && !registry.restoring.contains(name) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for the restore of {name}");
}

/// A notice read by the device only after it paired again: it waited on the
/// link behind a stream whose frame had not all arrived, though the primary
/// saw it delivered. It names the earlier pairing, so the device keeps the new
/// one (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notice_read_after_pairing_again_leaves_the_new_pairing() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    introduce(&device, &primary);
    let first = pair(&primary, &device).await;

    // A link from the primary whose control reader on the device waits on an
    // incomplete frame, with a notice about the first pairing queued behind it.
    let link = primary
        .daemon()
        .transport
        .endpoint
        .connect(
            device.daemon().transport.endpoint.addr(),
            &transport::mesh_alpn(),
        )
        .await
        .unwrap();
    let held_frame = control::encode_msg(None, &ControlMsg::Ping { nonce: 1 });
    let (mut held, _) = link.open_bi().await.unwrap();
    held.write_all(&held_frame[..2]).await.unwrap();
    let revoked = ControlMsg::PairingRevoked {
        generation: first.generation,
    };
    send_confirmed(&link, None, &revoked).await.unwrap();

    let second = pair(&primary, &device).await;
    assert!(second.generation > first.generation);
    held.write_all(&held_frame[2..]).await.unwrap();
    held.finish().unwrap();
    pinged(&link, 2).await;
    device.unpair_settled().await;
    assert_eq!(device.cert().await, Some(second));
    link.close(VarInt::from_u32(0), b"done");
    device.stop().await;
    primary.stop().await;
}

/// `ray unpair` of an offline device saves the revocation and the notice,
/// keeps the notice across the primary's restart, and tells the device once it
/// is back. The device cleans up and confirms, which ends the notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_device_is_told_once_it_is_back() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    let mut device = Node::new(&relay).await;
    primary.start().await;
    device.start().await;
    paired(&primary, &device).await;
    device.stop().await;
    relay.fail.store(true, Ordering::Relaxed);

    let daemon = primary.daemon();
    let target = device.id().to_string();
    let result = primary
        .run(async move { daemon.unpair(&target).await })
        .await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let settings = primary.settings().await;
    assert!(revoked(&settings, device.id()));
    assert_eq!(settings.pending_unpair_notices, [notice(device.id(), 0)]);
    assert!(primary.nullifies("home", device.id()));
    primary.stop().await;
    primary.start().await;
    assert_eq!(
        primary.settings().await.pending_unpair_notices,
        [notice(device.id(), 0)]
    );

    relay.fail.store(false, Ordering::Relaxed);
    device.start().await;
    assert!(device.cert().await.is_some());
    introduce(&primary, &device);
    introduce(&device, &primary);
    primary.daemon().registry.notice_nudge.notify_one();
    device
        .eventually("the device to finish its unpair", |cfg| {
            cfg.pending_unpairs.is_empty() && cfg.networks.is_empty()
        })
        .await;
    assert_eq!(device.cert().await, None);
    primary
        .eventually("the device to confirm", |cfg| {
            cfg.pending_unpair_notices.is_empty()
        })
        .await;
    device.stop().await;
    primary.stop().await;
}

/// Delivering the notice does not end it: it stays until the device confirms
/// with its request, or until it pairs again. It names the pairing it ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notice_stays_until_the_device_confirms_or_pairs_again() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    primary.start().await;
    let device_key = SecretKey::generate();
    let device_id = device_key.public();
    let cert = pair_as(&primary, &device_key, true).await;
    let (device, mut told, accept) =
        notice_taker(device_key.clone(), &transport::mesh_alpn()).await;
    listed(&primary, device_id, cert.clone()).await;
    primary
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(device.addr());

    let daemon = primary.daemon();
    let target = device_id.to_string();
    let result = primary
        .run(async move { daemon.unpair(&target).await })
        .await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let revoked = ControlMsg::PairingRevoked {
        generation: cert.generation,
    };
    assert_eq!(next_told(&mut told).await, revoked);
    // Told again, with the attempt run to its end: still waiting.
    let daemon = primary.daemon();
    assert!(
        primary
            .run(async move { daemon.registry.attempt_unpair_notices().await })
            .await
    );
    assert_eq!(next_told(&mut told).await, revoked);
    assert_eq!(
        primary.settings().await.pending_unpair_notices,
        [notice(device_id, cert.generation)]
    );

    let addr = primary.daemon().transport.endpoint.addr();
    let request = control::PairMsg::UnpairRequest { cert: cert.clone() };
    let reply = exchange(&device_key, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::UnpairRecorded)),
        "{reply:?}"
    );
    assert_eq!(primary.settings().await.pending_unpair_notices, []);

    // Told again, as after another `ray unpair`, then paired again.
    let pending = notice(device_id, cert.generation);
    primary
        .run(async move {
            config::update_settings(|cfg| {
                cfg.pending_unpair_notices.push(pending);
                Ok(())
            })
            .unwrap();
        })
        .await;
    let renewed = pair_as(&primary, &device_key, true).await;
    assert!(renewed.generation > cert.generation);
    assert_eq!(primary.settings().await.pending_unpair_notices, []);
    accept.abort();
    device.close().await;
    primary.stop().await;
}

/// A device on mesh version 6 is told with the bare `ControlMsg::Unpaired`,
/// the only notice it knows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_device_is_told_with_the_bare_notice() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    primary.start().await;
    let device_key = SecretKey::generate();
    let cert = pair_as(&primary, &device_key, false).await;
    let (device, mut told, accept) =
        notice_taker(device_key.clone(), transport::MESH_V6_ALPN).await;
    listed(&primary, device_key.public(), cert).await;
    primary
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(device.addr());

    let daemon = primary.daemon();
    let target = device_key.public().to_string();
    let result = primary
        .run(async move { daemon.unpair(&target).await })
        .await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert_eq!(next_told(&mut told).await, ControlMsg::Unpaired);
    accept.abort();
    device.close().await;
    primary.stop().await;
}

/// A notice that names no pairing is acted on only over mesh version 6 or 5,
/// where an older primary sends it. A primary on version 7 always names one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bare_notice_counts_only_from_an_older_primary() {
    let relay = Relay::start().await;
    let mut device = Node::new(&relay).await;
    device.start().await;
    let primary_key = SecretKey::generate();
    let cert = hold_certificate(&device, &primary_key).await;
    let primary = dialer(primary_key).await;
    let addr = device.daemon().transport.endpoint.addr();

    let link = primary
        .connect(addr.clone(), &transport::mesh_alpn())
        .await
        .unwrap();
    send_confirmed(&link, None, &ControlMsg::Unpaired)
        .await
        .unwrap();
    pinged(&link, 1).await;
    device.unpair_settled().await;
    assert_eq!(device.cert().await, Some(cert.clone()));
    link.close(VarInt::from_u32(0), b"done");

    let link = primary
        .connect(addr, transport::MESH_V6_ALPN)
        .await
        .unwrap();
    send_confirmed(&link, None, &ControlMsg::Unpaired)
        .await
        .unwrap();
    device
        .eventually("the device to unpair", move |cfg| {
            cfg.pending_unpairs == waiting(&cert)
        })
        .await;
    assert_eq!(device.cert().await, None);
    link.close(VarInt::from_u32(0), b"done");
    primary.close().await;
    device.stop().await;
}

/// A request about a pairing the device has since replaced, and confirmed the
/// replacement of, revokes nothing: it can reach the primary, or still be
/// under way there, after the device paired again. A request about the
/// current pairing still revokes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_about_a_replaced_pairing_revokes_nothing() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    primary.start().await;
    let daemon = primary.daemon();
    primary
        .run(async move { create(&daemon, "home").await })
        .await;
    let device = SecretKey::generate();
    let first = pair_as(&primary, &device, true).await;
    let second = pair_as(&primary, &device, true).await;
    assert_eq!((first.generation, second.generation), (1, 2));
    assert_eq!(
        primary.settings().await.device_generations,
        [DeviceGeneration {
            device: device.public(),
            issued: 2,
            confirmed: Some(2),
        }]
    );
    let addr = primary.daemon().transport.endpoint.addr();

    let request = control::PairMsg::UnpairRequest { cert: first };
    let reply = exchange(&device, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::UnpairRecorded)),
        "{reply:?}"
    );
    assert!(!revoked(&primary.settings().await, device.public()));
    assert!(!primary.nullifies("home", device.public()));

    let request = control::PairMsg::UnpairRequest { cert: second };
    let reply = exchange(&device, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::UnpairRecorded)),
        "{reply:?}"
    );
    assert!(revoked(&primary.settings().await, device.public()));
    assert!(primary.nullifies("home", device.public()));
    primary.stop().await;
}

/// A replacement the device never confirmed saving leaves the request about its
/// earlier pairing a revocation: the reply carrying the replacement can be lost,
/// or fail to save, and leave the device on the earlier certificate, which must
/// not stay valid (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_after_an_unsaved_replacement_still_revokes() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    primary.start().await;
    let device = SecretKey::generate();
    let first = pair_as(&primary, &device, true).await;
    listed(&primary, device.public(), first.clone()).await;
    let second = pair_as(&primary, &device, false).await;
    assert!(second.generation > first.generation);
    let addr = primary.daemon().transport.endpoint.addr();

    let request = control::PairMsg::UnpairRequest { cert: first };
    let reply = exchange(&device, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::UnpairRecorded)),
        "{reply:?}"
    );
    assert!(revoked(&primary.settings().await, device.public()));
    assert!(primary.nullifies("home", device.public()));
    primary.stop().await;
}

/// A request that reaches the primary is not enough: the device keeps it until
/// the primary answers that the revocation is saved (#239 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unanswered_request_stays_pending() {
    let relay = Relay::start().await;
    let mut device = Node::new(&relay).await;
    device.start().await;
    let primary_key = SecretKey::generate();
    // The primary's end: it reads each request, then closes without an answer.
    let primary = Endpoint::builder(presets::N0)
        .secret_key(primary_key.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![PAIR_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
    let accept = tokio::spawn({
        let primary = primary.clone();
        async move {
            while let Some(incoming) = primary.accept().await {
                let Ok(conn) = incoming.await else { continue };
                if let Ok((_send, mut recv)) = conn.accept_bi().await
                    && let Ok(request) = control::recv_framed::<control::PairMsg>(&mut recv).await
                {
                    let _ = requests.send(request);
                }
                conn.close(VarInt::from_u32(0), b"no answer");
            }
        }
    });
    let cert = hold_certificate(&device, &primary_key).await;
    device
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(primary.addr());

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let request = tokio::time::timeout(Duration::from_secs(15), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(&request, control::PairMsg::UnpairRequest { cert: sent } if *sent == cert),
        "{request:?}"
    );
    assert!(device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    accept.abort();
    primary.close().await;
    device.stop().await;
}

/// A primary on pairing version 2 cannot record an unpair: the device sends it
/// the earlier `ControlMsg::RequestUnpair` and keeps its own request, which
/// that sends nothing back to confirm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_primary_gets_the_earlier_request_and_the_unpair_stays() {
    let relay = Relay::start().await;
    let mut device = Node::new(&relay).await;
    device.start().await;
    let primary_key = SecretKey::generate();
    let primary = Endpoint::builder(presets::N0)
        .secret_key(primary_key.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![
            PAIR_V2_ALPN.to_vec(),
            transport::MESH_V6_ALPN.to_vec(),
        ])
        .bind()
        .await
        .unwrap();
    let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
    let accept = tokio::spawn({
        let primary = primary.clone();
        async move {
            while let Some(incoming) = primary.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let requests = requests.clone();
                tokio::spawn(async move {
                    while let Ok((_send, mut recv)) = conn.accept_bi().await {
                        if let Ok(control::FrameRead::Frame(frame)) =
                            control::recv_frame(&mut recv).await
                        {
                            let _ = requests.send((conn.alpn().to_vec(), frame.msg));
                        }
                    }
                });
            }
        }
    });
    let cert = hold_certificate(&device, &primary_key).await;
    device
        .daemon()
        .transport
        .warm_lookup
        .add_endpoint_info(primary.addr());

    let result = device.unpair_self().await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let (alpn, msg) = tokio::time::timeout(Duration::from_secs(15), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alpn, transport::MESH_V6_ALPN);
    assert!(matches!(msg, ControlMsg::RequestUnpair), "{msg:?}");
    assert!(device.attempt_requests().await);
    assert_eq!(device.settings().await.pending_unpairs, waiting(&cert));
    accept.abort();
    primary.close().await;
    device.stop().await;
}

/// A primary records an unpair only for a certificate it issued to the key
/// that asks, and only over pairing version 3. Version 2 still answers an
/// older device's network list request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_primary_refuses_an_unpair_it_cannot_verify() {
    let relay = Relay::start().await;
    let mut primary = Node::new(&relay).await;
    primary.start().await;
    let daemon = primary.daemon();
    primary
        .run(async move { create(&daemon, "home").await })
        .await;
    let device = SecretKey::generate();
    let stranger = SecretKey::generate();
    let ours = control::DeviceCert::create(&primary.key, &device.public(), 0);
    let addr = primary.daemon().transport.endpoint.addr();

    let list = control::PairMsg::NetworkListRequest { cert: ours.clone() };
    let reply = exchange(&device, &addr, PAIR_V2_ALPN, &list).await;
    assert!(
        matches!(reply, Some(control::PairMsg::NetworkListResponse { .. })),
        "{reply:?}"
    );
    let mut forged = control::DeviceCert::create(&stranger, &device.public(), 0);
    forged.user_identity = primary.id();
    for (cert, alpn) in [
        // Signed by someone else.
        (
            control::DeviceCert::create(&stranger, &device.public(), 0),
            PAIR_ALPN,
        ),
        // Names us, but someone else signed it.
        (forged, PAIR_ALPN),
        // Ours, for another key than the one asking.
        (
            control::DeviceCert::create(&primary.key, &stranger.public(), 0),
            PAIR_ALPN,
        ),
        // Over version 2.
        (ours.clone(), PAIR_V2_ALPN),
    ] {
        let request = control::PairMsg::UnpairRequest { cert };
        let reply = exchange(&device, &addr, alpn, &request).await;
        assert!(reply.is_none(), "{reply:?}");
    }
    assert_eq!(
        primary.settings().await.revoked_devices,
        Vec::<String>::new()
    );

    let request = control::PairMsg::UnpairRequest { cert: ours };
    let reply = exchange(&device, &addr, PAIR_ALPN, &request).await;
    assert!(
        matches!(reply, Some(control::PairMsg::UnpairRecorded)),
        "{reply:?}"
    );
    assert!(revoked(&primary.settings().await, device.public()));
    primary.stop().await;
}

/// Ping the daemon at the other end of `link` and wait for its answer. Its
/// control reader takes frames in the order they were sent, so by then it has
/// read every one sent on `link` before.
async fn pinged(link: &Connection, nonce: u64) {
    send_confirmed(link, None, &ControlMsg::Ping { nonce })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let (_send, mut recv) = link.accept_bi().await.unwrap();
            if let Ok(control::FrameRead::Frame(frame)) = control::recv_frame(&mut recv).await
                && frame.msg == (ControlMsg::Pong { nonce })
            {
                return;
            }
        }
    })
    .await
    .unwrap();
}

/// A device's end that takes notices and never confirms one: an endpoint for
/// `key` offering the mesh `alpn`, which passes on each control message it
/// reads. Abort the task when done.
async fn notice_taker(
    key: SecretKey,
    alpn: &[u8],
) -> (
    Endpoint,
    tokio::sync::mpsc::UnboundedReceiver<ControlMsg>,
    tokio::task::JoinHandle<()>,
) {
    let device = Endpoint::builder(presets::N0)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![alpn.to_vec()])
        .bind()
        .await
        .unwrap();
    let (notices, told) = tokio::sync::mpsc::unbounded_channel();
    let accept = tokio::spawn({
        let device = device.clone();
        async move {
            while let Some(incoming) = device.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let notices = notices.clone();
                tokio::spawn(async move {
                    while let Ok((_send, mut recv)) = conn.accept_bi().await {
                        if let Ok(control::FrameRead::Frame(frame)) =
                            control::recv_frame(&mut recv).await
                        {
                            let _ = notices.send(frame.msg);
                        }
                    }
                });
            }
        }
    });
    (device, told, accept)
}

/// An endpoint that never takes a connection, so a peer dialing it waits for
/// the handshake until the peer gives up. One that took the connection would
/// acknowledge what is sent on it, read or not.
async fn unanswering_member() -> Endpoint {
    Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![transport::mesh_alpn()])
        .bind()
        .await
        .unwrap()
}

/// The next message a [`notice_taker`] passes on.
async fn next_told(told: &mut tokio::sync::mpsc::UnboundedReceiver<ControlMsg>) -> ControlMsg {
    tokio::time::timeout(Duration::from_secs(15), told.recv())
        .await
        .unwrap()
        .unwrap()
}

/// An endpoint for `key` that only dials, without a relay. Bound like a
/// daemon's, so it reaches the addresses a daemon's endpoint lists.
async fn dialer(key: SecretKey) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

/// Send `msg` as `key` over `alpn` and return the answer, or `None` when the
/// other side closes without one.
async fn exchange(
    key: &SecretKey,
    addr: &iroh::EndpointAddr,
    alpn: &[u8],
    msg: &control::PairMsg,
) -> Option<control::PairMsg> {
    let endpoint = dialer(key.clone()).await;
    let reply = tokio::time::timeout(Duration::from_secs(15), async {
        let conn = endpoint.connect(addr.clone(), alpn).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        control::send_framed(&mut send, msg).await.unwrap();
        let reply = control::recv_framed(&mut recv).await.ok();
        conn.close(VarInt::from_u32(0), b"done");
        reply
    })
    .await
    .unwrap();
    endpoint.close().await;
    reply
}
