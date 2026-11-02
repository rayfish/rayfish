use super::*;

/// `build_headless()` constructs a usable `Arc<DaemonState>` (identity,
/// endpoint, blob store, DNS, pollers) in an isolated config dir and answers a
/// `status()` call, all without binding the Unix-socket IPC server that
/// `run_daemon`/`serve_ipc` would.
///
/// Multi-threaded flavor: `build_headless` builds an iroh endpoint and an
/// iroh-blobs `FsStore` whose background actor tasks must make progress while
/// the builder awaits, matching the daemon binary's `#[tokio::main]` runtime.
/// The `timeout` guard turns a future startup regression into a fast failure
/// instead of a hung test.
/// Process-wide lock serializing tests that mutate `RAYFISH_CONFIG_DIR` (or
/// any other env var read by `config::config_dir()`), since lib tests share
/// one process and run on parallel threads. Shared with `identity::tests`
/// via `crate::config::CONFIG_ENV_LOCK` so neither module's tests observe a
/// `RAYFISH_CONFIG_DIR` bled through from the other.
use crate::config::CONFIG_ENV_LOCK as ENV_LOCK;

/// RAII guard that restores a previous env var value (or removes it if it
/// was unset) on drop, so the var is restored even if the test body panics.
struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

// `ENV_LOCK` is a `Mutex<()>` used only to serialize whole tests against each
// other; it guards no data mutated across the awaits, so holding it across
// them is intentional (that is the point) and safe.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_headless_returns_usable_state_without_ipc_socket() {
    // Serialize against any other test that touches env vars read by
    // `config::config_dir()`, so no concurrent test observes a bled-through
    // `RAYFISH_CONFIG_DIR`.
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let tmp = tempfile::tempdir().unwrap();
    // Isolate identity/config/blobs from the system config dir. The guard
    // restores the previous value (or removes the var) on drop, including
    // on panic, so this can't poison later tests.
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

    let daemon = tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
        .await
        .expect("build_headless should not hang")
        .expect("build_headless should succeed");

    // It returns a shared `Arc<DaemonState>`.
    assert!(Arc::strong_count(&daemon) >= 1);

    // The embedding `status()` API answers without a socket ever being bound.
    daemon.status();
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_auto_accept_persists_exact_peers_without_a_network() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());
    let daemon = build_headless(false).await.unwrap();
    let first = SecretKey::from([41; 32]).public();
    let second = SecretKey::from([42; 32]).public();
    assert!(!daemon.files.should_auto_accept_file(first));
    assert!(!daemon.files.should_auto_accept_file(second));
    assert!(
        daemon
            .set_file_auto_accept(&first.to_string(), true)
            .await
            .is_ok()
    );
    assert!(
        daemon
            .set_file_auto_accept(&second.to_string(), true)
            .await
            .is_ok()
    );
    assert_eq!(
        config::load().unwrap().file_auto_accept_peers,
        vec![first, second]
    );
    assert!(daemon.files.should_auto_accept_file(first));
    assert!(daemon.files.should_auto_accept_file(second));
    assert!(
        !daemon
            .files
            .should_auto_accept_file(SecretKey::from([43; 32]).public())
    );
    assert!(
        daemon
            .set_file_auto_accept("unknown-peer", true)
            .await
            .is_err()
    );
    assert!(daemon.set_file_auto_accept("", true).await.is_err());
    assert_eq!(
        config::load().unwrap().file_auto_accept_peers,
        vec![first, second]
    );
    assert!(
        daemon
            .set_file_auto_accept(&first.to_string(), false)
            .await
            .is_ok()
    );
    assert_eq!(config::load().unwrap().file_auto_accept_peers, vec![second]);
    assert!(!daemon.files.should_auto_accept_file(first));
    assert!(daemon.files.should_auto_accept_file(second));
}

/// The app bridges block, unblock and set the inbound policy through
/// `config_set`, the same arm `ray block` and `ray config set` use.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedder_config_set_blocks_unblocks_and_sets_inbound() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());
    let daemon = tokio::time::timeout(Duration::from_secs(30), build_headless(false))
        .await
        .expect("build_headless should not hang")
        .expect("build_headless should succeed");
    let peer = SecretKey::from_bytes(&[41u8; 32]).public();

    let msg = daemon
        .config_set(GlobalKey::Blocked, &peer.to_string())
        .await;
    assert!(msg.is_ok(), "{msg:?}");
    assert_eq!(config::load_inbound().unwrap().blocked, vec![peer]);

    let msg = daemon
        .config_set(GlobalKey::Blocked, &format!("-{peer}"))
        .await;
    assert!(msg.is_ok(), "{msg:?}");
    assert!(config::load_inbound().unwrap().blocked.is_empty());

    let msg = daemon
        .config_set(GlobalKey::Inbound, config::InboundPolicy::Known.as_ref())
        .await;
    assert!(msg.is_ok(), "{msg:?}");
    assert_eq!(
        config::load_inbound().unwrap().inbound,
        config::InboundPolicy::Known
    );

    // One-peer edits refuse what a raw list value would treat as
    // "clear" or "remove", so a stray comma cannot empty the list.
    daemon
        .config_set(GlobalKey::Blocked, &peer.to_string())
        .await
        .unwrap();
    for bad in [",", " ", "-x", "a,b"] {
        let msg = daemon.edit_peer_list(GlobalKey::Blocked, bad, false).await;
        assert!(msg.is_err(), "{bad:?}: {msg:?}");
    }
    assert_eq!(config::load_inbound().unwrap().blocked, vec![peer]);
    let msg = daemon
        .edit_peer_list(GlobalKey::Blocked, &peer.to_string(), true)
        .await;
    assert!(msg.is_ok(), "{msg:?}");
    assert!(config::load_inbound().unwrap().blocked.is_empty());
    let msg = daemon
        .edit_peer_list(GlobalKey::Inbound, &peer.to_string(), false)
        .await;
    assert!(msg.is_err(), "{msg:?}");

    let msg = daemon.config_set(GlobalKey::Blocked, "no-such-peer").await;
    assert!(
        matches!(&msg, Err(error) if error.message().contains("unknown peer")),
        "{msg:?}"
    );
}

/// `net_config_apply` gates on the network's presence ON DISK, not in the
/// live network map: the old `NetworkRegistry::contains` check it replaced
/// gated on the live map instead, so a saved-but-inactive network used to
/// error here. That drift was reviewed and kept deliberately (the daemon
/// connects every saved network at startup, so "on disk" and "live" agree
/// in practice); this test pins the disk-presence semantics so any future
/// change to that gate is a deliberate decision, not an accident.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn net_config_apply_gates_on_the_network_existing_on_disk() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

    let daemon = tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
        .await
        .expect("build_headless should not hang")
        .expect("build_headless should succeed");

    // No network saved yet: not-found, matching the old live-map check.
    let msg = daemon
        .net_config_apply("gaming", NetworkKey::AutoAcceptFiles, "off")
        .await;
    assert!(
        matches!(&msg, Err(error) if error.message().contains("not found")),
        "{msg:?}"
    );

    // Save the network to disk without registering it in the live map
    // (nothing here calls `create_network`/`join_network`), i.e. exactly
    // the "saved but inactive" case the review flagged.
    config::save_network(&config::empty_network_config("gaming")).unwrap();

    let msg = daemon
        .net_config_apply("gaming", NetworkKey::AutoAcceptFiles, "off")
        .await;
    assert!(msg.is_ok(), "{msg:?}");

    let msg = daemon
        .net_config_apply("gaming", NetworkKey::EphemeralTtl, "3599")
        .await;
    assert!(
        matches!(&msg, Err(error)
            if error.message() == "ttl must be at least 3600 seconds (1 hour)"),
        "validation errors must not be mislabeled as save failures: {msg:?}"
    );
}

/// A signed roster is the authority for membership. When it no longer lists
/// this node, the network must disappear from saved state as well as the live
/// runtime, or the dashboard keeps showing it and startup tries to restore it.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kicked_network_is_removed_from_saved_state() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

    let daemon = tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
        .await
        .expect("build_headless should not hang")
        .expect("build_headless should succeed");
    config::save_network(&config::empty_network_config("test-network")).unwrap();

    daemon.registry.remove_kicked_network("test-network").await;

    let saved = config::load().unwrap();
    assert!(saved.networks.iter().all(|net| net.name != "test-network"));
    daemon.shutdown_and_close().await;
}

/// A mobile rebuild drops the old daemon. Nothing it built may keep its
/// registry alive afterwards through a reference cycle.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_and_close_frees_the_registry() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

    let daemon = build_headless(false).await.unwrap();
    let registry = Arc::downgrade(&daemon.registry);
    daemon.shutdown_and_close().await;
    drop(daemon);
    // Background tasks end on their own after shutdown and drop their
    // clones as they go; wait for that rather than guessing a delay.
    let freed = tokio::time::timeout(Duration::from_secs(10), async {
        while registry.strong_count() > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        freed.is_ok(),
        "{} references still hold the registry",
        registry.strong_count()
    );
}

/// A stopped node must be rebuildable in the same process, which is the
/// mobile disable/enable cycle (`Node::stop` then `Node::start`, both in one
/// app process).
///
/// What makes this sharp: two `FsStore`s over the same directory do not
/// error, they *block*. redb waits for the lock on `blobs/blobs.db` rather
/// than returning `DatabaseAlreadyOpen`, so a rebuild that overlaps a store
/// the previous daemon has not released yet never returns at all, and on
/// Android that wedges the thread `Node::start` was called on for the life of
/// the process. Before `shutdown_and_close` shut the protocol router down,
/// nothing in it released the store: the release happened later, if at all,
/// when the router's accept task noticed the closed endpoint and dropped its
/// handlers. This asserts the router is shut down before the call returns
/// (which is what drives `BlobsProtocol::shutdown` -> `Store::shutdown`) and
/// then reopens the store immediately, with the daemon `Arc` still held.
///
/// See `build_headless_returns_usable_state_without_ipc_socket`: `ENV_LOCK`
/// only serializes tests and guards no data across the awaits.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_and_close_releases_the_blob_store_for_a_rebuild() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // One config dir throughout: sharing `blobs/blobs.db` is the whole point,
    // so a per-build tempdir would pass even with the bug.
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

    let first = tokio::time::timeout(Duration::from_secs(30), build_headless(false))
        .await
        .expect("first build_headless should not hang")
        .expect("first build_headless should succeed");
    tokio::time::timeout(Duration::from_secs(30), first.shutdown_and_close())
        .await
        .expect("shutdown_and_close should not hang");
    assert!(
        first.router.is_shutdown(),
        "shutdown_and_close must shut the protocol router down, which is what \
         releases the blob store, rather than leaving it to the accept task"
    );

    // Still holding `first`, and reopening on the very next line. Waiting for
    // the last `Arc` to drop is not something a caller can arrange
    // (background tasks hold their own clones and wind down on their own
    // schedule), so releasing the store has to be something the call itself
    // guarantees before it returns.
    let blobs_dir = config::blobs_dir().unwrap();
    let reopened = tokio::time::timeout(
        Duration::from_secs(10),
        iroh_blobs::store::fs::FsStore::load(&blobs_dir),
    )
    .await
    .expect("the blob store is still locked after shutdown_and_close")
    .expect("reopening the blob store should succeed");
    let _ = reopened.shutdown().await;

    // And the whole rebuild works, which is what the app actually does.
    tokio::time::timeout(Duration::from_secs(30), build_headless(false))
        .await
        .expect("rebuild should not hang")
        .expect("rebuilding after shutdown_and_close should succeed");
}

// See `build_headless_returns_usable_state_without_ipc_socket`: `ENV_LOCK`
// only serializes tests and guards no data across the awaits.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lan_peers_reach_status_and_the_scan_reply() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

    let daemon = tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
        .await
        .expect("build_headless should not hang")
        .expect("build_headless should succeed");

    // Nothing seen yet: the scan reply is empty and status counts nothing.
    match daemon.list_lan_peers() {
        IpcMessage::LanPeersList { peers, .. } => assert!(peers.is_empty()),
        other => panic!("expected LanPeersList, got {other:?}"),
    }

    // Feed the map the way the mDNS browse loop does.
    let peer = SecretKey::from_bytes(&[42u8; 32]).public();
    let addr = SocketAddr::from(([192, 168, 1, 24], 41641));
    daemon.transport.lan_peers.discovered(peer, vec![addr]);

    match daemon.list_lan_peers() {
        IpcMessage::LanPeersList {
            peers,
            mdns_enabled: _,
        } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].endpoint_id, peer);
            assert_eq!(peers[0].addrs, vec![addr.to_string()]);
            // We share no network with this sighting, so it is connectable.
            assert_eq!(peers[0].shared_network, None);
        }
        other => panic!("expected LanPeersList, got {other:?}"),
    }

    // The same sighting is listed in `ray status`, with its addresses.
    let lan_peers = daemon.status().lan_peers;
    assert_eq!(lan_peers.len(), 1);
    assert_eq!(lan_peers[0].endpoint_id, peer);
    assert_eq!(lan_peers[0].addrs, vec![addr.to_string()]);

    // An expiry clears it from both.
    daemon.transport.lan_peers.expired(&peer);
    assert!(daemon.status().lan_peers.is_empty());
}

/// In-memory TUN writer that records every written packet into a shared
/// buffer, so a test can observe which writer the data plane routed to.
#[derive(Clone, Default)]
struct FakeTunWriter {
    written: Arc<Mutex<Vec<Vec<u8>>>>,
    mtu: Option<u16>,
}

impl crate::tun::TunWrite for FakeTunWriter {
    fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(crate::tun::TUN_MTU)
    }

    async fn write_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        self.written.lock().unwrap().push(packet.to_vec());
        Ok(())
    }
}

/// In-memory TUN reader that never yields a packet, so `run_mesh` parks in
/// its read and only exits when its task is cancelled/aborted. It carries an
/// `Arc<()>` liveness token: the reader is owned solely by the spawned
/// `run_mesh` future, so the token's strong count drops back to the caller's
/// single reference the moment that task's future is dropped on abort. That
/// makes "the old data plane was torn down" directly observable.
struct FakeTunReader {
    _alive: Arc<()>,
}

impl crate::tun::TunRead for FakeTunReader {
    async fn read_packet(&mut self) -> anyhow::Result<bytes::Bytes> {
        std::future::pending::<()>().await;
        unreachable!("FakeTunReader never returns");
    }
}

/// Poll `sink` until it holds `want` packets. Bounded (~2s total) so a real
/// failure fails fast instead of hanging; the short poll interval leaves room
/// for the cross-thread wakeup of the writer task without a fixed sleep that
/// would either flake (too short) or slow the suite (too long).
async fn wait_for_len(sink: &Arc<Mutex<Vec<Vec<u8>>>>, want: usize) -> bool {
    for _ in 0..400 {
        if sink.lock().unwrap().len() >= want {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    false
}

#[cfg(feature = "desktop")]
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_tun_v4_bridge_follows_settings_and_tunnel_lifetime() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().expect("create config directory");
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());
    let daemon = tokio::time::timeout(Duration::from_secs(30), build_headless(false))
        .await
        .expect("headless startup must finish")
        .expect("build the headless node");

    for enabled in [true, false, true] {
        config::update_settings(|cfg| {
            cfg.v4_bridge = enabled;
            Ok(())
        })
        .expect("save the bridge setting");
        daemon
            .attach_external_tun(
                FakeTunReader {
                    _alive: Arc::new(()),
                },
                FakeTunWriter::default(),
            )
            .await;
        let mut token = daemon.v4_bridge_token.lock().unwrap().clone();
        assert_eq!(token.is_some(), enabled, "startup follows the setting");
        if let Some(token) = &token {
            assert!(!token.is_cancelled(), "the bridge is running");
        }

        if enabled {
            assert!(daemon.v4_bridge_config_set("off").is_ok());
            assert!(
                token
                    .as_ref()
                    .expect("the bridge was running")
                    .is_cancelled()
            );
            assert!(daemon.v4_bridge_token.lock().unwrap().is_none());
            assert!(daemon.v4_bridge_config_set("on").is_ok());
            token = daemon.v4_bridge_token.lock().unwrap().clone();
            assert!(!token.as_ref().expect("the bridge restarted").is_cancelled());
        }

        daemon.detach_tun();
        assert!(daemon.v4_bridge_token.lock().unwrap().is_none());
        if let Some(token) = token {
            assert!(token.is_cancelled(), "disconnect stops the bridge");
        }
    }
}

/// Re-attaching the TUN after a `detach_tun` must resume forwarding to the
/// new writer (the VPN off/on toggle path), and a second `attach_tun`
/// WITHOUT an intervening detach must stop the previous writer instead of
/// leaking it (two live writers on two fds).
// See `build_headless_returns_usable_state_without_ipc_socket`: `ENV_LOCK`
// only serializes tests and guards no data across the awaits.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_tun_is_self_healing_on_reattach_and_double_attach() {
    let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

    let daemon = tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
        .await
        .expect("build_headless should not hang")
        .expect("build_headless should succeed");

    // Helper: send one packet through the same `tun_tx` cell the peer-reader
    // and DNS-injection paths use, then wait for the given writer to see it.
    async fn send_pkt(daemon: &Arc<DaemonState>, pkt: &'static [u8]) {
        daemon
            .registry
            .tun_tx
            .load_full()
            .send(Bytes::from_static(pkt))
            .await
            .expect("tun_tx send should reach the live writer");
    }

    // Poll until `token`'s strong count falls back to 1 (only this test
    // holds it), i.e. the `run_mesh` task that owned the matching reader was
    // dropped. Bounded so a leak fails fast instead of hanging.
    async fn wait_for_reader_dropped(token: &Arc<()>) -> bool {
        for _ in 0..400 {
            if Arc::strong_count(token) == 1 {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        false
    }

    // 1. First attach: reader1 + writer1, forwarding active.
    #[cfg(all(target_os = "macos", feature = "desktop"))]
    assert!(!daemon.app_ssh_helper.load(Ordering::SeqCst));
    let writer1 = FakeTunWriter::default();
    let sink1 = Arc::clone(&writer1.written);
    daemon
        .attach_external_tun(
            FakeTunReader {
                _alive: Arc::new(()),
            },
            writer1,
        )
        .await;
    assert!(daemon.status().active);

    #[cfg(all(target_os = "macos", feature = "desktop"))]
    assert!(daemon.app_ssh_helper.load(Ordering::SeqCst));

    send_pkt(&daemon, b"packet-1").await;
    assert!(
        wait_for_len(&sink1, 1).await,
        "writer1 should receive the first packet"
    );

    // 2. Toggle: detach, then re-attach reader2 + writer2. This is the path
    //    that used to silently break before the fresh-channel-per-attach fix.
    daemon.detach_tun();
    assert!(!daemon.status().active);
    let writer2 = FakeTunWriter {
        mtu: Some(1280),
        ..Default::default()
    };
    let sink2 = Arc::clone(&writer2.written);
    let alive2 = Arc::new(());
    daemon
        .attach_external_tun(
            FakeTunReader {
                _alive: Arc::clone(&alive2),
            },
            writer2,
        )
        .await;

    // A packet queued across the MTU change must not reach the smaller TUN.
    // The small packet acts as a barrier after the oversized packet.
    send_pkt(&daemon, &[0; 1500]).await;
    send_pkt(&daemon, b"packet-2").await;
    assert_eq!(daemon.registry.peers.local_mtu(), 1280);
    assert!(
        wait_for_len(&sink2, 1).await,
        "writer2 should receive the packet after a detach->attach toggle"
    );
    assert_eq!(*sink2.lock().unwrap(), vec![b"packet-2".to_vec()]);

    // 3. Double-attach guard: attach writer3 WITHOUT detaching first. The
    //    previous data plane (writer2's mesh loop + writer) must be aborted,
    //    not leaked. Observe both halves of "no two live data planes":
    //    - writer3 receives the packet (the cell now routes to writer3), and
    //    - reader2's `run_mesh` task was dropped (`alive2` count back to 1),
    //      which without the self-healing guard would leak and stay at 2.
    let writer3 = FakeTunWriter::default();
    let sink3 = Arc::clone(&writer3.written);
    daemon
        .attach_external_tun(
            FakeTunReader {
                _alive: Arc::new(()),
            },
            writer3,
        )
        .await;

    send_pkt(&daemon, b"packet-3").await;
    assert_eq!(daemon.registry.peers.local_mtu(), 1500);
    assert!(
        wait_for_len(&sink3, 1).await,
        "writer3 should receive the packet after a double-attach"
    );
    assert!(
        wait_for_reader_dropped(&alive2).await,
        "the prior mesh loop must be aborted on a second attach without detach (no leak)"
    );

    daemon.detach_tun();
}
