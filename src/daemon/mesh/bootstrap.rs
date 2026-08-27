//! Daemon process bootstrap and the IPC server. Moved out of `daemon/mod.rs`.
//!
//! `run_daemon` is the process entry point (called by the `ray daemon`
//! command): it builds the shared [`Daemon`], reconnects saved networks,
//! and runs the IPC accept loop until shutdown. `build_daemon` wires the endpoint
//! / TUN / protocol router / metrics; `serve_ipc` + `handle_ipc_client` answer
//! `ray` CLI requests over the Unix socket. These live in a `mesh/` submodule
//! (a descendant of `daemon`) so they can still construct `Daemon` and reach
//! its private fields without widening visibility.

use std::sync::Mutex;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

use iroh_blobs::provider::events::{
    ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate,
};

use super::super::*;
#[cfg(windows)]
use crate::windows_identity;

/// How often the blob store sweeps untagged blobs. This is reclaim latency, not
/// correctness: a finished transfer's bytes linger at most this long after its
/// tag goes away. Kept coarse because a sweep walks the whole store, and on a
/// phone that is a wakeup nobody asked for.
const BLOB_GC_INTERVAL: Duration = Duration::from_secs(600);

pub async fn run_daemon(token: CancellationToken, stats: Arc<ForwardMetrics>) -> Result<()> {
    let overrides = Overrides::default();

    // Repair a leftover `/etc/resolv.conf` before anything reads it. A hard kill
    // or reboot leaves ours in place (nameserver = our own Magic DNS), and the
    // endpoint's DNS resolver snapshots the file once at construction, so
    // building first would point every pkarr lookup at a resolver that has no
    // upstreams until `activate` configures them. `DnsService::configure` calls
    // this again later; it is idempotent (the backup is consumed here).
    crate::dns::config::restore_stale_backups();

    // Build the always-on infrastructure without a packet interface, then attach
    // the desktop OS TUN device below. The headless builder is the same one
    // `build_headless()` exposes to embedders (mobile), so both paths share
    // identical construction.
    // Desktop honors the persisted `on_demand` config (default off); the mobile
    // embedder forces it on via `build_headless`.
    let daemon = build_daemon(token.clone(), stats, overrides).await?;

    // Attach the real OS TUN device: create it, record its name, and spawn the
    // writer + `run_mesh` forwarding loop. On Android the packet interface is a
    // `VpnService` fd attached later by `ray-mobile` via `attach_tun`, so this is
    // skipped here.
    #[cfg(not(target_os = "android"))]
    {
        let my_ipv6 = derive_ipv6(&daemon.transport.identity.local_identity());
        let (tun_reader, tun_writer, tun_name) = tun::create(my_ipv6)
            .await
            .context("failed to create TUN device")?;
        daemon.tun_name.store(Arc::new(tun_name));
        daemon.attach_tun(tun_reader, tun_writer).await;
    }

    // Connect the control plane (mesh connections) once, for the daemon's
    // whole lifetime, then bring the data plane up. `ray up`/`ray down` toggle
    // only the data plane after this; connections persist across `down` so the
    // node stays online to peers.
    daemon.registry.connect_all_networks().await;
    tokio::spawn(Arc::clone(&daemon.registry).run_restore_supervisor());
    daemon.spawn_exit_reapply_listener();
    daemon.activate(None).await;

    // Opt-in automatic updates: a single daemon-wide task that periodically
    // checks for a newer stable release and swaps + restarts onto it. Desktop-only
    // (the self-replacing updater is not built into the Android lib).
    #[cfg(feature = "desktop")]
    if daemon.auto_update {
        spawn_auto_update(daemon.shutdown_token.clone());
    }

    let result = serve_ipc(&daemon, token).await;

    // Shut the protocol Router down, then close the iroh endpoint, before
    // returning. `Router::shutdown` stops accepting, drains its handlers, and
    // closes the endpoint itself; the explicit close is a harmless idempotent
    // backstop. Dropping the endpoint without closing logs "Endpoint dropped
    // without calling `Endpoint::close`. Aborting ungracefully." and can leave
    // the process lingering until the service manager escalates to SIGKILL, which
    // delays the relaunch on `ray restart`/`ray update` past the client's
    // reachability probe. A clean close lets QUIC connections terminate and the
    // process exit promptly so the new daemon comes up fast.
    let _ = daemon.router.shutdown().await;
    daemon.transport.endpoint.close().await;

    result
}

/// Construct all always-on daemon infrastructure: identity, iroh endpoint, blob
/// store, TUN device, forwarding loop, DNS resolver, mDNS discovery, protocol
/// router, and metrics server. Returns the shared [`Daemon`] (still on
/// standby, so the caller is expected to run [`Daemon::activate`]) and the
/// metrics-server guard, which must outlive the process.
/// The ALPNs the endpoint advertises at boot: one per saved network plus the
/// network-independent blobs / file-transfer / pairing / connect ALPNs. A
/// freshly-started daemon with no active network must still accept `ray pair` /
/// `ray send` / `ray connect`, otherwise the initial handshake fails with "peer
/// doesn't support any known protocol" until the first create/join triggers
/// `refresh_alpns()`. Mirrors `ProtocolRouter::alpns()`.
fn initial_alpns(_app_config: &config::AppConfig) -> Vec<Vec<u8>> {
    // A single mesh ALPN now carries every network (network selection is in-band),
    // so the advertised set is static and independent of the saved networks.
    vec![
        transport::mesh_alpn(),
        iroh_blobs::protocol::ALPN.to_vec(),
        transport::FILES_ALPN.to_vec(),
        PAIR_ALPN.to_vec(),
        transport::CONNECT_ALPN.to_vec(),
    ]
}

/// Settings an embedder decides for itself instead of reading from
/// `settings.toml`. `None` means "take the config value" (the desktop daemon
/// passes [`Overrides::default`], so its behavior is entirely config-driven).
///
/// These exist because the config file is not the embedder's source of truth:
/// on Android the user's choice lives in the app's own preferences and the
/// config directory is app-private, so the value has to arrive as an argument
/// at construction time.
#[derive(Default)]
struct Overrides {
    /// Force on-demand mode (mobile always forces it on; desktop honors config).
    on_demand: Option<bool>,
}

/// Construct a headless [`Daemon`] for an embedder (used by `ray-mobile`
/// and future embedders). Builds the same infrastructure as `run_daemon` minus
/// the OS TUN device and the Unix-socket IPC server: the caller supplies a
/// packet interface via [`Daemon::attach_tun`]. The returned daemon is on
/// standby (no data plane), with its saved networks' control plane connected.
pub async fn build_headless(on_demand: bool) -> Result<Arc<Daemon>> {
    let token = CancellationToken::new();
    let stats = Arc::new(ForwardMetrics::default());
    let overrides = Overrides {
        on_demand: Some(on_demand),
    };
    let daemon = build_daemon(token, stats, overrides).await?;
    // Bring the saved networks' control plane up, matching `run_daemon`.
    daemon.registry.connect_all_networks().await;
    tokio::spawn(Arc::clone(&daemon.registry).run_restore_supervisor());
    daemon.spawn_exit_reapply_listener();
    // Control readers and the join path now run their network ops (promotion,
    // self-unpair) directly via NetworkRegistry, so a headless embedder needs no
    // hand-off drain loop.
    Ok(daemon)
}

/// Build all always-on daemon infrastructure WITHOUT a packet interface or the
/// Unix-socket IPC server. The returned [`Daemon`] is on standby (no data
/// plane); attach a TUN with [`Daemon::attach_tun`], connect saved networks,
/// then bring the data plane up with [`Daemon::activate`]. The promotion
/// receiver and metrics-server guard are stashed on the state for the caller.
///
/// Shared by [`run_daemon`] (desktop) and [`build_headless`] (embedders).
///
/// The endpoint is built long before the rest of the infrastructure, so every
/// `?` after that point would drop a live endpoint (iroh logs "Endpoint dropped
/// without calling `Endpoint::close`. Aborting ungracefully."). That is only
/// noise for the desktop binary, which exits anyway, but an embedder retries:
/// `Node::start` is called again on every enable, so a failing build would stack
/// one abandoned endpoint per attempt for the life of the process. Close it here
/// instead, on the way out.
async fn build_daemon(
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    overrides: Overrides,
) -> Result<Arc<Daemon>> {
    let mut endpoint = None;
    let result = build_daemon_inner(token, stats, overrides, &mut endpoint).await;
    if result.is_err()
        && let Some(ep) = endpoint
    {
        tracing::warn!("daemon build failed; closing the endpoint it had already created");
        ep.close().await;
    }
    result
}

/// The body of [`build_daemon`]. `endpoint_out` is filled the moment the iroh
/// endpoint exists, so the caller can close it if any later step fails.
async fn build_daemon_inner(
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    overrides: Overrides,
    endpoint_out: &mut Option<Endpoint>,
) -> Result<Arc<Daemon>> {
    // Relocate a pre-/etc config tree into /etc/rayfish (Linux upgrade path)
    // before anything reads identity or config. No-op on macOS / once migrated.
    config::migrate_location();

    // --- Identity (persistent transport key + optional device certificate) ---
    let key = identity::load_or_create()?;
    let public_key = key.public();
    let device_cert = identity::load_device_cert()?;
    if let Some(ref cert) = device_cert {
        tracing::info!(user = %cert.user_identity.fmt_short(), "loaded device certificate");
    }
    let identity = IrohIdentityProvider::new(public_key);
    let my_ip = identity.local_ipv6();
    // Register our mesh address for the userspace SSH port NAT (mesh `:22`
    // <-> the embedded server's listen port). Stays inactive until `ssh on`.
    forward::init_ssh_nat(my_ip, crate::forward::SSH_LISTEN_PORT);

    // --- iroh endpoint (one ALPN per saved network + the blobs ALPN) ---
    let mut app_config = config::load()?;
    // On-demand mode: the platform (mobile embedder) may force it; otherwise honor
    // config (on by default). Computed here so it can thread into the registry.
    let on_demand = overrides.on_demand.unwrap_or(app_config.on_demand);
    // Point the pkarr client at the configured discovery-DNS server (if any)
    // before any record publish/resolve happens.
    dht::set_discovery_override(&app_config.discovery_dns);
    // Lazily generate + persist this node's contact key (`ray connect`). The
    // secret stays in config; only its public id is held in `Daemon`.
    let mut contact_public = None;
    match config::update_settings(|cfg| {
        contact_public = Some(config::contact_secret(cfg).public());
        Ok(())
    }) {
        Ok(cfg) => app_config = cfg,
        Err(e) => tracing::warn!(error = %e, "failed to persist contact key"),
    }
    // The callback did not run if the update failed before it. Fall back to an
    // in-memory key so the node still starts.
    let contact_public = match contact_public {
        Some(id) => id,
        None => config::contact_secret(&mut app_config).public(),
    };
    // Refuse to bind rather than quietly falling back to n0's servers. Both
    // write paths (`ray up --private`, `ray config set private on`) already
    // check this, so reaching here means `settings.toml` was hand-edited, and
    // for a setting whose entire promise is "nothing else is contacted",
    // starting anyway with the promise broken is the wrong failure.
    if app_config.private_mode {
        private_mode_servers_ok(&app_config)?;
    }
    let alpns = initial_alpns(&app_config);
    // The node-wide `tor` setting, OR'd with the older per-network
    // `TransportMode::Tor` so `ray create/join --tor` keeps working. One endpoint
    // serves every network, so a single network asking for Tor puts the whole node
    // in it: that was already true before the node-wide setting existed.
    let use_tor = app_config.tor
        || app_config
            .networks
            .iter()
            .any(|net| net.transport.as_ref().is_some_and(|t| t.is_tor()));
    let posture = transport::NodePosture::new(app_config.private_mode, use_tor);
    let bound = transport::create_endpoint_with_alpns(
        key.clone(),
        alpns,
        posture,
        &app_config.relay,
        &app_config.discovery_dns,
        &app_config.dns_upstreams,
    )
    .await?;
    // `bound` is moved into `Transport` below, which is what discharges the
    // guard's single job: stay alive as long as the endpoint (see
    // `transport::TransportGuard`). Everything up to there works off this clone.
    let ep = bound.endpoint.clone();
    *endpoint_out = Some(ep.clone());
    // Tell the record plane how it is allowed to reach the pkarr server before
    // anything publishes or resolves (see `dht::set_posture`).
    crate::dht::set_posture(posture);

    // Built before the blob store below, because the provider event pump that
    // feeds it (a bit further down, once `blobs_proto` exists) needs the
    // registry to already be there to hand transfer updates to.
    let transfers = Arc::new(transfers::TransferRegistry::new());

    // --- Content-addressed blob store (membership/file transfer) ---
    let blobs_dir = config::config_dir()?.join("blobs");
    std::fs::create_dir_all(&blobs_dir)?;
    // GC is what actually frees a transfer's bytes: `Blobs::delete` is private
    // ("users should rely only on garbage collection"), so dropping a tag only
    // marks the blob collectable and this periodic sweep is what reclaims it.
    // Without it the store grew forever, keeping every file ever sent next to the
    // original and every file ever received next to the copy in Downloads.
    //
    // Membership snapshots share this store but are added with a permanent tag,
    // so a sweep never touches them; only untagged transfer blobs are collected.
    let mut blob_opts = iroh_blobs::store::fs::options::Options::new(&blobs_dir);
    blob_opts.gc = Some(iroh_blobs::store::GcConfig {
        interval: BLOB_GC_INTERVAL,
        add_protected: None,
    });
    let blob_store = FsStore::load_with_opts(blobs_dir.join("blobs.db"), blob_opts)
        .await
        .context("failed to open blob store")?;
    // Provider events tell us when a peer actually reads a blob out of our store,
    // which is the only signal a sender gets that its file arrived: `send_file`
    // returns when the *offer* lands, not when the bytes move. `NotifyLog` gives
    // us per-request transfer events with no interception; `get` is the only
    // request-mode field this crate version actually reads, so it gates
    // notifications for all four request kinds (get, get_many, push, observe),
    // not just get. What this actually guarantees: our pump body below never
    // awaits anything except `recv` (each request's update stream is drained by
    // a task spawned immediately), and transfer progress is sent with `try_send`
    // and dropped rather than blocking, so a slow pump cannot itself stall the
    // provider. It does not mean the provider can never block on us:
    // `client_connected` and `notify_streaming` do await on this channel (64
    // slots), so a wedged pump would still backpressure connection setup.
    // `connected: Notify` (also non-intercepting) is the only way to learn *who*
    // is pulling: a `GetRequestReceivedNotify` carries a connection id, not a
    // peer id, so without this we could only match on hash, which can't tell two
    // recipients of the same file apart.
    let (blob_events, mut blob_event_rx) = EventSender::channel(
        64,
        EventMask {
            connected: ConnectMode::Notify,
            get: RequestMode::NotifyLog,
            ..EventMask::DEFAULT
        },
    );
    let blobs_proto = BlobsProtocol::new(&blob_store, Some(blob_events));

    // A completed pull is also the sender's cue to release its copy of the blob,
    // but `FileService` does not exist yet at this point in the wiring and the
    // service graph stays acyclic, so the pump reports completions over a channel
    // that a drain task hands to `FileService` once it has been built.
    let (send_done_tx, mut send_done_rx) =
        tokio::sync::mpsc::channel::<(iroh_blobs::Hash, EndpointId)>(64);

    // Pump provider events into the transfer registry. Roster (group blob) fetches
    // ride the same blobs ALPN, so events for hashes we never registered as an
    // outgoing file send are dropped by the registry regardless of who pulled them.
    {
        let transfers = transfers.clone();
        let token = token.clone();
        let send_done_tx = send_done_tx.clone();
        tokio::spawn(async move {
            // Connection id -> resolved peer, built from `ClientConnected` and
            // pruned on `ConnectionClosed`. Only ever touched from this single
            // task, so a plain map needs no lock.
            let mut connections: HashMap<u64, EndpointId> = HashMap::new();
            loop {
                let msg = tokio::select! {
                    _ = token.cancelled() => break,
                    msg = blob_event_rx.recv() => match msg {
                        Some(msg) => msg,
                        None => break,
                    },
                };
                match msg {
                    ProviderMessage::ClientConnectedNotify(msg) => {
                        if let Some(endpoint_id) = msg.inner.endpoint_id {
                            connections.insert(msg.inner.connection_id, endpoint_id);
                        }
                    }
                    ProviderMessage::ConnectionClosed(msg) => {
                        connections.remove(&msg.inner.connection_id);
                    }
                    // Only the notify variant arrives under `NotifyLog`, and only for
                    // get requests: everything else in the mask is off.
                    ProviderMessage::GetRequestReceivedNotify(msg) => {
                        let hash = msg.inner.request.hash;
                        let connection_id = msg.inner.connection_id;
                        // Resolved now, synchronously, while still on the single task
                        // that owns `connections`; the request-tracking task below
                        // only needs the already-resolved value.
                        let peer = connections.get(&connection_id).copied();
                        let transfers = transfers.clone();
                        let mut updates = msg.rx;
                        let send_done_tx = send_done_tx.clone();
                        tokio::spawn(async move {
                            let Some(peer) = peer else {
                                // No resolved peer for this connection (a roster
                                // fetch, or a connection whose `ClientConnected` we
                                // missed): drain without matching, so we never fall
                                // back to hash-only matching and never stall the
                                // provider by leaving its update channel unread.
                                // Warn, not debug: every drop here is a pull whose
                                // transfer can never be marked finished and whose
                                // blob is never reclaimed, so the sender is left
                                // showing "waiting to accept" forever. If this is
                                // firing for real file transfers it is a bug, not
                                // noise.
                                tracing::warn!(
                                    connection_id,
                                    %hash,
                                    "provider event with no resolved peer; dropping"
                                );
                                while let Ok(Some(_)) = updates.recv().await {}
                                return;
                            };
                            while let Ok(Some(update)) = updates.recv().await {
                                match update {
                                    RequestUpdate::Started(_) => {
                                        transfers.provider_started(hash, peer)
                                    }
                                    RequestUpdate::Progress(p) => {
                                        transfers.provider_progress(hash, peer, p.end_offset)
                                    }
                                    RequestUpdate::Completed(_) => {
                                        // Once per transfer, and the only signal a
                                        // sender gets that its file actually landed:
                                        // worth an info line on both ends.
                                        tracing::info!(
                                            peer = %peer.fmt_short(),
                                            %hash,
                                            "peer finished pulling a blob from us"
                                        );
                                        transfers.provider_finished(hash, peer, true);
                                        // Full pull: the receiver has the bytes, so
                                        // our copy can go. Dropped rather than
                                        // awaited so a wedged drain cannot stall
                                        // the provider's update stream.
                                        let _ = send_done_tx.try_send((hash, peer));
                                    }
                                    RequestUpdate::Aborted(_) => {
                                        transfers.provider_finished(hash, peer, false)
                                    }
                                }
                            }
                        });
                    }
                    // Not something we track (Rayfish only issues single-blob
                    // Gets today), but `get: RequestMode::NotifyLog` above gates
                    // all four request kinds in this crate version, not just
                    // Get, so these three CAN arrive (e.g. from a future
                    // get_many/HashSeq fetch). Each carries an `rx` update
                    // channel the provider writes progress into; if we drop it
                    // unread, the provider's `transfer_progress` gets
                    // `SendError::ReceiverClosed` and aborts the request. Drain
                    // it to completion and discard, same as the Get arm, but
                    // without touching the registry.
                    ProviderMessage::GetManyRequestReceivedNotify(msg) => {
                        let mut updates = msg.rx;
                        tokio::spawn(
                            async move { while let Ok(Some(_)) = updates.recv().await {} },
                        );
                    }
                    ProviderMessage::PushRequestReceivedNotify(msg) => {
                        let mut updates = msg.rx;
                        tokio::spawn(
                            async move { while let Ok(Some(_)) = updates.recv().await {} },
                        );
                    }
                    ProviderMessage::ObserveRequestReceivedNotify(msg) => {
                        let mut updates = msg.rx;
                        tokio::spawn(
                            async move { while let Ok(Some(_)) = updates.recv().await {} },
                        );
                    }
                    _ => {}
                }
            }
        });
    }

    // --- Packet interface: deferred to `attach_tun` ---
    // No OS TUN device or forwarding loop is created here. On desktop `run_daemon`
    // creates the real device and calls `attach_tun`; on embedders (mobile) the
    // `VpnService` fd is attached the same way. `tun_name` starts as a placeholder
    // and is overwritten when a real interface is attached.
    // Shared with NetworkRegistry (for the leave/teardown DNS search-domain
    // refresh); run_daemon overwrites the string in place once the real TUN is up.
    let tun_name = Arc::new(arc_swap::ArcSwap::from_pointee(String::from("rayfish")));
    // Append-only audit log of peer connect/disconnect events. If it can't be
    // opened (e.g. unwritable config dir) the daemon still runs without auditing.
    let peers = match audit::AuditLog::open() {
        Ok(log) => PeerTable::with_audit(Arc::new(log)),
        Err(e) => {
            tracing::warn!(error = %e, "failed to open audit log; peer events will not be audited");
            PeerTable::new()
        }
    };
    let fw_config = firewall::load_firewall().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load firewall config, using defaults");
        firewall::FirewallConfig::default()
    });
    let shared_firewall = SharedFirewall::new(fw_config);
    shared_firewall.clone().spawn_evictor(token.clone());
    let active = Arc::new(AtomicBool::new(false));
    // Placeholder sender whose receiver is dropped immediately: no real channel
    // exists until `attach_tun` creates one and swaps it in. `attach_tun`
    // (desktop: once at boot; mobile: on each `up()`) recreates the channel, spawns
    // the TUN writer + `run_mesh` forwarding loop, and stores the live sender here.
    let tun_tx = {
        let (placeholder_tx, _placeholder_rx) = mpsc::channel::<Bytes>(1);
        Arc::new(arc_swap::ArcSwap::from_pointee(placeholder_tx))
    };
    let device_user_map = peers::DeviceUserMap::new();

    // --- Magic DNS resolver + optional mDNS local discovery ---
    let hostname_table = dns::new_hostname_table();
    let reverse_table = dns::new_reverse_table();
    let dns_resolver = std::sync::Arc::new(crate::dns::resolver::Resolver::new(
        hostname_table.clone(),
        reverse_table.clone(),
    ));
    // Built here (not in the struct literal) so NetworkRegistry can share it for
    // the leave/teardown DNS cleanup.
    let dns = Arc::new(DnsService::new(
        hostname_table,
        reverse_table,
        dns_resolver.clone(),
        derive_ipv6(&identity.local_identity()),
    ));
    // mDNS is silenced by private mode rather than merely defaulted off: an mDNS
    // announcement hands this node's identity to every other device on whatever
    // LAN it is attached to, which is the one exposure a private node cannot fix
    // by choosing its own servers.
    let mdns_enabled = app_config.mdns_enabled && !app_config.private_mode;
    // Stays empty when mDNS is off, so `ray mdns scan` reports nothing rather
    // than stale sightings from a previous run.
    let lan_peers = Arc::new(LanPeers::new());
    if mdns_enabled {
        spawn_mdns_discovery(&ep, token.clone(), lan_peers.clone());
    } else {
        tracing::info!("mDNS discovery disabled");
    }

    // --- Protocol router + the shared Daemon ---
    // Group the foundation handles so extracted services can depend on
    // `Arc<Transport>`. Clones here are cheap (all fields are `Arc`-backed); the
    // loose `Daemon` fields below still hold the originals until the daemon
    // god object is dissolved.
    let transport = Arc::new(Transport::new(
        bound,
        identity.clone(),
        blob_store.clone(),
        stats.clone(),
        contact_public,
        lan_peers,
    ));
    // The per-peer connection driver is built once here and shared by the
    // ProtocolRouter (which delegates the mesh ALPN to it) and the
    // NetworkRegistry (which re-registers a network's handler on promotion).
    let conn = Arc::new(ConnectionManager::new());
    // Networks map is shared with the NetworkRegistry service (M5 seam): both
    // hold the same `Arc<DashMap>` so methods migrate to the registry gradually.
    let networks = Arc::new(DashMap::new());
    // Daemon-wide disconnect channel: every per-connection data reader reports
    // peer drops here, drained by the single connection supervisor. Built here
    // (before the registry) so both the registry's MeshCtx builder and the
    // Daemon literal share the one sender.
    let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(256);
    let pruned_peers = Arc::new(DashSet::new());
    let registry = Arc::new(NetworkRegistry::new(
        networks.clone(),
        transport.clone(),
        peers.clone(),
        conn.clone(),
        dns.clone(),
        tun_name.clone(),
        device_cert.clone(),
        token.clone(),
        shared_firewall.clone(),
        device_user_map.clone(),
        tun_tx.clone(),
        pruned_peers.clone(),
        disconnect_tx.clone(),
        on_demand,
        app_config.idle_timeout(),
    ));
    // FileService owns file transfer + pairing. It evaluates own-device auto-accept
    // directly (no worker channel) and clears a re-paired device's nullifier by
    // calling NetworkRegistry directly (was the reauth_tx hand-off channel), so it
    // depends on Transport (endpoint + blobs) and NetworkRegistry.
    let files = Arc::new(FileService::new(
        key.clone(),
        transport.clone(),
        registry.clone(),
        device_cert.clone(),
        device_user_map.clone(),
        transfers.clone(),
    ));
    // Drain completed pulls into the blob reclaim (see the channel above).
    tokio::spawn({
        let files = files.clone();
        let token = token.clone();
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    msg = send_done_rx.recv() => match msg {
                        Some((hash, peer)) => files.note_send_completed(hash, peer),
                        None => break,
                    },
                }
            }
        }
    });

    let connect = Arc::new(ConnectService::new(
        transport.clone(),
        active.clone(),
        registry.clone(),
    ));
    let protocol_router = Arc::new(ProtocolRouter::new(
        blobs_proto,
        files.clone(),
        connect.clone(),
        conn.clone(),
    ));
    // The registry (re)connect paths drive a dialed connection's demux through the
    // router; install it now that it exists (the registry was built before it).
    registry.set_protocol_router(protocol_router.clone());
    // Single daemon-wide connection supervisor: consumes every data reader's
    // disconnect and, per dropped identity, prunes departed peers we coordinate and
    // reconnects the rest across all their shared networks. Spawned here (not in
    // `run_daemon`) so embedders built via `build_headless` (mobile) get it too;
    // without it a transient QUIC drop between two mobile peers would never
    // reconnect and the bounded disconnect channel would eventually back up.
    {
        let registry = registry.clone();
        let token = token.clone();
        tokio::spawn(async move {
            registry
                .run_connection_supervisor(disconnect_rx, token)
                .await;
        });
    }

    // Idle teardown is per-connection now: each `MeshConnection` closes itself when
    // it goes idle (see its run loop), gated on `on_demand` + the peer advertising
    // support. No separate reaper task.

    // Install the daemon-wide mesh dispatch context and spawn the protocol Router
    // *before* building the Daemon. The dispatch is built from the registry (the
    // single `MeshCtx` builder), and the Router only needs the services
    // (registry/files/connect/blobs), not the Daemon struct, so ordering it here
    // lets `router` be a plain owned field instead of a set-after-construction
    // `Option`. Dispatch must be installed before the accept loop starts handing
    // out connections, hence the order.
    protocol_router.set_mesh_dispatch(MeshDispatch {
        ctx: registry.mesh_ctx(),
        token: token.clone(),
        on_peer_connected: {
            // Deliver queued `ray send` offers the moment their peer connects.
            let files = files.clone();
            Arc::new(move |peer| {
                let files = files.clone();
                tokio::spawn(async move { files.flush_outbox_for(peer).await });
            })
        },
    });
    // Slow safety net for offers whose delivery failed transiently while the
    // peer connection stayed up (the connect hook won't refire until the peer
    // reconnects). `outbox_peers` only yields currently connected peers, so
    // this never dials into the void.
    tokio::spawn({
        let files = files.clone();
        let token = token.clone();
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(file_service::OUTBOX_SWEEP_INTERVAL) => {}
                }
                for peer in files.outbox_peers() {
                    let files = files.clone();
                    tokio::spawn(async move { files.flush_outbox_for(peer).await });
                }
            }
        }
    });
    // The Router owns the endpoint accept loop and dispatches by ALPN. It aborts on
    // drop, so the Daemon owns it for the process lifetime and shuts it down on exit.
    let router = protocol_router.build_router(transport.endpoint.clone());

    // Prometheus metrics server. Its guard is kept alive by the Daemon (dropping it
    // stops the export); built here from the local handles so it can be a plain
    // owned field. `None` if it failed to bind.
    #[cfg(not(target_os = "android"))]
    let metrics_server = spawn_metrics_server(
        stats.clone(),
        peers.clone(),
        &transport.endpoint,
        token.clone(),
    )
    .await;
    // A phone has no Prometheus scraper and no way to reach one, and the server
    // brings a 60s per-peer sampling loop with it (`PeerMetrics::spawn_collector`):
    // a wakeup a minute, forever, for an endpoint nobody reads.
    #[cfg(target_os = "android")]
    let metrics_server: Option<MetricsServer> = None;

    // Same treatment as mDNS: the update checker reaches GitHub directly, so it
    // does not run while private. `apply_global` also refuses to turn it on, so
    // this is the backstop for a config that was already `on` when private mode
    // went on.
    let auto_update = app_config.auto_update && !app_config.private_mode;
    let daemon = Arc::new(Daemon {
        transport,
        registry,
        stats: stats.clone(),
        start: Instant::now(),
        tun_tx,
        shutdown_token: token.clone(),
        protocol_router: protocol_router.clone(),
        dns,
        mdns_enabled,
        private_mode: app_config.private_mode,
        tor: use_tor,
        auto_update,
        tun_name,
        tun_tasks: Mutex::new(None),
        exit_reconcile: AsyncMutex::new(()),
        _metrics_server: metrics_server,
        router,
        files,
        transfers,
        connect,
        device_cert,
        contact_public,
        active: active.clone(),
        #[cfg(feature = "desktop")]
        ssh_authz: crate::ssh::new_authz(),
        #[cfg(feature = "desktop")]
        ssh_token: Mutex::new(None),
        #[cfg(feature = "desktop")]
        v4_bridge_token: Mutex::new(None),
    });

    // File auto-accept is evaluated inline by `FileService::accept_file_offer`
    // (no worker channel), so nothing to spawn here.

    // --- Contact record publisher (ray connect) ---
    if let Ok(pkarr_client) = dht::create_pkarr_client(&daemon.transport.endpoint) {
        spawn_contact_publisher(pkarr_client, daemon.transport.endpoint.id(), token.clone());
    }

    // Device-cert revocation is now carried per-network in the signed blob's
    // nullifier set (`ray unpair`); no separate pkarr record or background
    // publisher/poller is needed. Coordinated networks seed their nullifiers from
    // the persisted `revoked_devices` set at seal time (see `seal_and_publish`).

    tracing::info!(ip = %my_ip, id = %daemon.transport.endpoint.id().fmt_short(), "daemon started");
    Ok(daemon)
}

/// Advertise this endpoint over mDNS (`_rayfish._udp.local`) and log LAN peer
/// discovery events until cancellation. Non-fatal: a failure just means no
/// local discovery.
fn spawn_mdns_discovery(ep: &Endpoint, token: CancellationToken, lan_peers: Arc<LanPeers>) {
    let mdns = match iroh_mdns_address_lookup::MdnsAddressLookup::builder()
        .service_name("rayfish")
        .advertise(true)
        .build(ep.id())
    {
        Ok(mdns) => mdns,
        Err(e) => {
            tracing::warn!(error = %e, "failed to start mDNS discovery");
            return;
        }
    };
    let Ok(lookups) = ep.address_lookup() else {
        return;
    };
    lookups.add(mdns.clone());
    tracing::info!("mDNS discovery enabled (advertising _rayfish._udp.local)");

    tokio::spawn(async move {
        use futures::StreamExt;
        let mut events = mdns.subscribe().await;
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                event = events.next() => match event {
                    Some(iroh_mdns_address_lookup::DiscoveryEvent::Discovered { endpoint_info, .. }) => {
                        tracing::info!(
                            peer = %endpoint_info.endpoint_id.fmt_short(),
                            "mDNS: peer discovered on LAN"
                        );
                        lan_peers.discovered(
                            endpoint_info.endpoint_id,
                            endpoint_info.ip_addrs().copied().collect(),
                        );
                    }
                    Some(iroh_mdns_address_lookup::DiscoveryEvent::Expired { endpoint_id }) => {
                        tracing::info!(
                            peer = %endpoint_id.fmt_short(),
                            "mDNS: peer left LAN"
                        );
                        lan_peers.expired(&endpoint_id);
                    }
                    None => break,
                    _ => {}
                }
            }
        }
    });
}

/// Register rayfish counters, per-peer gauges, and iroh endpoint metrics, then
/// start the Prometheus HTTP endpoint on `127.0.0.1:9090`. The returned guard
/// must be kept alive for the process lifetime; `None` means metrics export is
/// disabled. Not built on Android: see the call site.
#[cfg(not(target_os = "android"))]
async fn spawn_metrics_server(
    stats: Arc<ForwardMetrics>,
    peers: PeerTable,
    endpoint: &Endpoint,
    token: CancellationToken,
) -> Option<iroh_metrics::service::MetricsServer> {
    let mut registry = iroh_metrics::Registry::default();
    registry.register(stats);
    let peer_metrics = Arc::new(crate::stats::PeerMetrics::default());
    registry.register(peer_metrics.clone());
    peer_metrics.spawn_collector(peers, token);
    registry.register_all(endpoint.metrics());

    // Loopback, not `0.0.0.0`. These counters name every peer by mesh IP along
    // with its RTT and traffic volumes, which is a map of who this node talks to
    // and when: not something to serve to whatever else is on the cafe Wi-Fi.
    // Local scraping (the usual case) is unaffected; remote scraping should go
    // over the mesh rather than the LAN.
    let metrics_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 9090).into();
    match iroh_metrics::service::MetricsServer::spawn(metrics_addr, Arc::new(registry)).await {
        Ok(server) => {
            tracing::info!(addr = %server.local_addr(), "metrics server started");
            Some(server)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start metrics server (Prometheus export disabled)");
            None
        }
    }
}

/// Bind the IPC Unix socket and serve client requests until the daemon-wide
/// `token` is cancelled. On shutdown, put the VPN on standby (revert DNS, drop
/// connections, bring the TUN down) and remove the socket file. Each request is
/// handled on its own task so a slow client can't block the accept loop.
#[cfg(unix)]
async fn serve_ipc(daemon: &Arc<Daemon>, token: CancellationToken) -> Result<()> {
    let socket_path = ipc::socket_path();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path).context("failed to bind IPC socket")?;
    set_socket_permissions(&socket_path);
    tracing::info!(path = %socket_path.display(), "IPC socket listening");

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!("daemon shutting down");
                daemon.deactivate().await;
                let _ = std::fs::remove_file(&socket_path);
                return Ok(());
            }
            result = listener.accept() => match result {
                Ok((stream, _)) => {
                    let daemon = daemon.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_ipc_client(stream, &daemon).await {
                            tracing::debug!(error = %e, "IPC client error");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "IPC accept error"),
            }
        }
    }
}

/// Make the IPC socket connectable by any local user. Authority is not granted
/// by reaching the socket: every mutating request is authorized per-connection
/// in `check_authorized` via `SO_PEERCRED` (root or the configured operator
/// UID), Tailscale's model, so the file mode only has to permit the connect().
#[cfg(unix)]
fn set_socket_permissions(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
        unsafe { libc::chmod(c_path.as_ptr(), 0o666) };
        tracing::info!("IPC socket mode 0666 (per-request authorization via peer creds)");
    }
}

/// Cap on an error reply that quotes the request back. Comfortably fits the
/// longest real one (the unknown-key error names every valid key, ~300 bytes)
/// and any socket buffer, so the write completes even if nobody reads.
const MAX_DECODE_ERROR_LEN: usize = 512;

/// Truncate on a char boundary, marking that it happened.
fn truncate(s: &str) -> String {
    if s.len() <= MAX_DECODE_ERROR_LEN {
        return s.to_string();
    }
    let end = (0..=MAX_DECODE_ERROR_LEN)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0);
    format!("{}... (truncated)", &s[..end])
}

#[cfg(unix)]
async fn handle_ipc_client(stream: UnixStream, daemon: &Arc<Daemon>) -> Result<()> {
    let peer_cred = stream.peer_cred().ok().map(|c| PeerIdentity::Unix {
        uid: c.uid(),
        gid: c.gid(),
    });
    // The request is read fd-aware: `SendFileFd` arrives with the file as
    // SCM_RIGHTS ancillary data, which a plain framed read would drop.
    let (req, fds) = match ipc::recv_with_fds(&stream).await {
        Ok(v) => v,
        // A request this build cannot decode (a settings key it does not know, a
        // variant from a newer `ray`) gets the reason back rather than a bare
        // hangup, which the client can only report as "connection closed". The
        // send is best-effort: the common cause is a client that has already
        // gone away.
        //
        // The reason is truncated once, before it reaches either sink, because
        // it quotes the request: an unknown key is reported as `unknown config
        // key: <what the client sent>`, and a frame may carry a megabyte of it.
        // Unbounded, any local user (the socket is 0666 by design) could size
        // the reply and then never read it, parking a task and an fd on a write
        // that cannot complete, and could flood the rolling log `ray report`
        // bundles. This bounds the one reply attacker-sized input can generate;
        // it is not a general cap on how long a client can hold a task.
        Err(e) => {
            let msg = truncate(&format!("{e:#}"));
            tracing::debug!(error = %msg, "undecodable IPC request");
            let mut framed = ipc::framed(stream);
            let _ = ipc::send(&mut framed, ipc_err(msg)).await;
            return Ok(());
        }
    };
    // `Logs` is the one request whose answer is a run of frames rather than a
    // single message (a day of debug logs does not fit the frame cap, and
    // `--follow` never ends), so it takes the stream instead of going through
    // `handle_request`. Authorization is still the same check: it sits in the
    // open read tier, alongside `Status` and `Report`.
    if let IpcMessage::Logs { since, follow } = &req {
        let (since, follow) = (*since, *follow);
        let mut framed = ipc::framed(stream);
        if let Some(denied) = Daemon::check_authorized(&req, peer_cred.as_ref()) {
            let _ = ipc::send(&mut framed, denied).await;
            return Ok(());
        }
        return super::diagnostics::stream_logs(
            &crate::logdir::log_dir(),
            &mut framed,
            since,
            follow,
            &daemon.shutdown_token,
        )
        .await;
    }

    let resp = daemon.handle_request(req, peer_cred, fds).await;
    let mut framed = ipc::framed(stream);
    ipc::send(&mut framed, resp).await?;
    Ok(())
}

#[cfg(windows)]
async fn serve_ipc(daemon: &Arc<Daemon>, token: CancellationToken) -> Result<()> {
    let pipe_name = ipc::socket_path();
    let pipe_name = pipe_name.to_string_lossy().into_owned();
    let staging_dir = prepare_ipc_upload_dir()?;
    sweep_ipc_upload_orphans(&staging_dir);
    let mut server = create_named_pipe(&pipe_name, true)?;
    let mut standby = create_named_pipe(&pipe_name, false)?;
    tracing::info!(pipe = %pipe_name, "IPC named pipe listening");
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                daemon.deactivate().await;
                return Ok(());
            }
            result = server.connect() => {
                if let Err(error) = result {
                    tracing::warn!(error = %error, "IPC named pipe accept failed; recovering listener");
                    match recreate_named_pipe(&pipe_name, &token).await {
                        Some(replacement) => server = replacement,
                        None => {
                            daemon.deactivate().await;
                            return Ok(());
                        }
                    }
                    continue;
                }
                let client = server;
                let client_daemon = daemon.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc_client(client, &client_daemon).await {
                        tracing::debug!(error = %e, "IPC client error");
                    }
                });
                match recreate_named_pipe(&pipe_name, &token).await {
                    Some(replacement) => server = replacement,
                    None => {
                        daemon.deactivate().await;
                        return Ok(());
                    }
                }
            }
            result = standby.connect() => {
                if let Err(error) = result {
                    tracing::warn!(error = %error, "standby IPC named pipe accept failed; recovering listener");
                    match recreate_named_pipe(&pipe_name, &token).await {
                        Some(replacement) => standby = replacement,
                        None => {
                            daemon.deactivate().await;
                            return Ok(());
                        }
                    }
                    continue;
                }
                let client = standby;
                let client_daemon = daemon.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc_client(client, &client_daemon).await {
                        tracing::debug!(error = %e, "IPC client error");
                    }
                });
                match recreate_named_pipe(&pipe_name, &token).await {
                    Some(replacement) => standby = replacement,
                    None => {
                        daemon.deactivate().await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
const IPC_UPLOAD_PREFIX: &str = "rayfish-ipc-upload-";
#[cfg(windows)]
const IPC_UPLOAD_SUFFIX: &str = ".part";
#[cfg(windows)]
const IPC_MAX_TRANSFER: u64 = 4 * 1024 * 1024 * 1024;

#[cfg(windows)]
fn prepare_ipc_upload_dir() -> Result<PathBuf> {
    let dir = crate::config::config_dir()?.join("ipc-upload");
    crate::windows_security::ensure_protected_dir(&dir)?;
    Ok(dir)
}

#[cfg(windows)]
fn is_ipc_upload_temp_name(name: &str) -> bool {
    name.starts_with(IPC_UPLOAD_PREFIX) && name.ends_with(IPC_UPLOAD_SUFFIX)
}

#[cfg(windows)]
fn is_internal_file_frame(message: &IpcMessage) -> bool {
    matches!(
        message,
        IpcMessage::SendFileStaged { .. } | IpcMessage::SendFileChunk { .. }
    )
}

/// Reclaim `.part` files left by an upload the daemon died in the middle of.
///
/// Infallible on purpose. Every failure here is per-entry and survivable: a
/// leftover whose handle is still held (an AV scanner mid-scan is the usual
/// one), or a reparse point we refuse to follow. This runs on the startup path,
/// so returning an error would take the daemon down before it ever listens, and
/// the service's restart actions would turn that into a restart loop SCM gives
/// up on after three attempts, leaving the VPN down with no obvious cause. An
/// orphan surviving one boot costs nothing; the next sweep gets it.
#[cfg(windows)]
fn sweep_ipc_upload_orphans(dir: &Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(
                dir = %dir.display(),
                %error,
                "could not enumerate the IPC upload staging directory; skipping the orphan sweep"
            );
            return;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !is_ipc_upload_temp_name(name) {
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        // FILE_ATTRIBUTE_REPARSE_POINT. Something planted a link where only our
        // own staging files belong, so leave it alone and say so.
        if metadata.file_attributes() & 0x400 != 0 {
            tracing::warn!(
                path = %path.display(),
                "refusing to sweep a reparse point in the IPC upload staging directory"
            );
            continue;
        }
        if metadata.is_file()
            && let Err(error) = std::fs::remove_file(&path)
        {
            tracing::warn!(path = %path.display(), %error, "could not remove an orphaned IPC upload");
        }
    }
}

#[cfg(all(test, windows))]
mod windows_ipc_tests {
    use super::{IpcMessage, is_internal_file_frame, is_ipc_upload_temp_name};

    #[test]
    fn only_rayfish_partial_upload_names_are_sweep_candidates() {
        assert!(is_ipc_upload_temp_name("rayfish-ipc-upload-a.part"));
        assert!(!is_ipc_upload_temp_name("rayfish-ipc-upload-a"));
        assert!(!is_ipc_upload_temp_name("unrelated.part"));
    }

    #[test]
    fn staged_and_chunk_frames_are_internal_only() {
        assert!(is_internal_file_frame(&IpcMessage::SendFileStaged {
            path: "x".into(),
            filename: "x".into(),
            peer: "p".into(),
        }));
        assert!(is_internal_file_frame(&IpcMessage::SendFileChunk {
            data: vec![1],
            done: false,
        }));
        assert!(!is_internal_file_frame(&IpcMessage::Status));
    }
}

#[cfg(windows)]
async fn recreate_named_pipe(name: &str, token: &CancellationToken) -> Option<NamedPipeServer> {
    loop {
        match create_named_pipe(name, false) {
            Ok(pipe) => return Some(pipe),
            Err(error) => {
                tracing::warn!(error = %error, "failed to recreate IPC named pipe; retrying");
                tokio::select! {
                    _ = token.cancelled() => return None,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
        }
    }
}

#[cfg(windows)]
fn create_named_pipe(name: &str, first: bool) -> Result<NamedPipeServer> {
    let operator = crate::config::operator_sid()?;
    let mut descriptor = crate::windows_security::pipe_descriptor(operator.as_deref())?;
    let mut attributes = descriptor.attributes();
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first);
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
        )
    }
    .context("create protected IPC named pipe")
}

#[cfg(windows)]
async fn handle_ipc_client(stream: NamedPipeServer, daemon: &Arc<Daemon>) -> Result<()> {
    let identity = windows_identity::named_pipe_client_identity(stream.as_raw_handle() as HANDLE)?;
    let peer = Some(PeerIdentity::Windows {
        sid: identity.sid,
        is_local_system: identity.is_local_system,
        is_elevated_admin: identity.is_elevated_admin,
    });
    let mut framed = ipc::framed(stream);
    // A request this build cannot decode gets the reason back, the same as on
    // Unix. Dropping the connection instead leaves the client reporting a dead
    // daemon, and `cmd_up` acts on that by trying to install the service.
    let req = match ipc::recv(&mut framed).await {
        Ok(req) => req,
        Err(e) => {
            let msg = truncate(&format!("{e:#}"));
            tracing::debug!(error = %msg, "undecodable IPC request");
            let _ = ipc::send(&mut framed, ipc_err(msg)).await;
            return Ok(());
        }
    };
    if is_internal_file_frame(&req) {
        ipc::send(
            &mut framed,
            IpcMessage::Error {
                message: "internal file-transfer frame is not accepted at the IPC boundary"
                    .to_owned(),
            },
        )
        .await?;
        return Ok(());
    }
    // `Logs` answers with a run of frames rather than one message, so it keeps
    // the connection instead of going through `handle_request`. Same open-read
    // authorization tier as `Status` and `Report`, and the same handler the Unix
    // path uses.
    if let IpcMessage::Logs { since, follow } = &req {
        let (since, follow) = (*since, *follow);
        if let Some(denied) = Daemon::check_authorized(&req, peer.as_ref()) {
            let _ = ipc::send(&mut framed, denied).await;
            return Ok(());
        }
        return super::diagnostics::stream_logs(
            &crate::logdir::log_dir(),
            &mut framed,
            since,
            follow,
            &daemon.shutdown_token,
        )
        .await;
    }
    if matches!(req, ipc::IpcMessage::SendFileBegin { .. })
        && let Some(error) = Daemon::check_authorized(&req, peer.as_ref())
    {
        ipc::send(&mut framed, error).await?;
        return Ok(());
    }
    let resp = if let ipc::IpcMessage::SendFileBegin {
        filename,
        peer: target,
        size: _declared_size,
    } = req
    {
        const CHUNK: usize = 256 * 1024;
        let result: Result<IpcMessage> = async {
            anyhow::ensure!(
                !filename.is_empty() && filename.len() <= 255,
                "invalid file name"
            );
            let staging_dir = prepare_ipc_upload_dir()?;
            let staged = tempfile::Builder::new()
                .prefix(IPC_UPLOAD_PREFIX)
                .suffix(IPC_UPLOAD_SUFFIX)
                .tempfile_in(&staging_dir)?;
            crate::windows_security::protect_file(staged.path())?;
            let temp = staged.path().to_path_buf();
            let mut output = tokio::fs::File::from_std(staged.reopen()?);
            let mut received = 0u64;
            let response = loop {
                match tokio::time::timeout(Duration::from_secs(30), ipc::recv(&mut framed))
                    .await
                    .context("timed out waiting for in-band file chunk")??
                {
                    ipc::IpcMessage::SendFileChunk { data, done } => {
                        anyhow::ensure!(data.len() <= CHUNK, "in-band file chunk exceeds 256 KiB");
                        anyhow::ensure!(done || !data.is_empty(), "empty non-final file chunk");
                        received = received
                            .checked_add(data.len() as u64)
                            .context("in-band file size overflow")?;
                        anyhow::ensure!(
                            received <= IPC_MAX_TRANSFER,
                            "in-band file exceeds 4 GiB limit"
                        );
                        tokio::io::AsyncWriteExt::write_all(&mut output, &data).await?;
                        if done {
                            tokio::io::AsyncWriteExt::flush(&mut output).await?;
                            drop(output);
                            break daemon
                                .handle_request(
                                    ipc::IpcMessage::SendFileStaged {
                                        path: temp.to_string_lossy().into_owned(),
                                        filename,
                                        peer: target,
                                    },
                                    peer.clone(),
                                    Vec::new(),
                                )
                                .await;
                        }
                    }
                    other => anyhow::bail!("unexpected in-band file frame: {other:?}"),
                }
            };
            drop(staged);
            Ok(response)
        }
        .await;
        match result {
            Ok(response) => response,
            Err(error) => IpcMessage::Error {
                message: format!("in-band file upload failed: {error:#}"),
            },
        }
    } else {
        daemon.handle_request(req, peer, Vec::new()).await
    };
    ipc::send(&mut framed, resp).await
}

/// First auto-update check runs ~5 min after boot (jittered), then every 6h.
#[cfg(feature = "desktop")]
const AUTO_UPDATE_INITIAL_DELAY: Duration = Duration::from_secs(300);
#[cfg(feature = "desktop")]
const AUTO_UPDATE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// Restart-loop guard: refuse a repeat of the same target inside this window.
#[cfg(feature = "desktop")]
const AUTO_UPDATE_BACKOFF_SECS: i64 = 24 * 60 * 60;

/// Opt-in automatic updates: a single daemon-wide task that periodically checks
/// GitHub for a newer stable release and, when found, swaps the binary and
/// restarts the service onto it. All errors are logged and swallowed so the task
/// never crashes the daemon.
#[cfg(feature = "desktop")]
fn spawn_auto_update(token: CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Jitter each tick so a fleet upgraded together doesn't hit the GitHub
        // API in lockstep (anonymous limit is 60/hr per IP).
        let first = AUTO_UPDATE_INITIAL_DELAY + Duration::from_secs(rand::random::<u64>() % 300);
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tokio::time::sleep(first) => {}
        }
        loop {
            if let Err(e) = auto_update_once(&token).await {
                tracing::warn!(error = %e, "auto-update check failed");
            }
            let next = AUTO_UPDATE_INTERVAL + Duration::from_secs(rand::random::<u64>() % 300);
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(next) => {}
            }
        }
    })
}

/// One auto-update cycle: check for a newer stable release and, if found and not
/// backed off, swap the binary and trigger a self-restart. `Ok(())` means nothing
/// needed doing (or the swap+restart was scheduled, the daemon is torn down and
/// relaunched onto the new binary shortly after).
#[cfg(feature = "desktop")]
async fn auto_update_once(shutdown: &CancellationToken) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let asset = crate::update::release_asset_name(std::env::consts::OS, std::env::consts::ARCH)?;
    let client = crate::update::build_http_client()?;
    let token = crate::update::github_token();

    let release = crate::update::resolve_stable_release(&client, &token).await?;
    let tag = release.tag_name.clone();
    let latest = crate::update::normalize_version(&tag).to_string();
    if !crate::update::version_is_newer(&latest, current) {
        tracing::debug!(current, latest = %latest, "auto-update: already on latest stable");
        return Ok(());
    }

    // Restart-loop guard: refuse a repeat of the same target inside the backoff
    // window so a bad build that keeps mis-reporting its version can't tight-loop
    // download + restart.
    let cfg = config::load()?;
    let now = unix_now();
    if !crate::update::should_attempt_target(
        &tag,
        cfg.auto_update_last_target.as_deref(),
        cfg.auto_update_last_attempt,
        now,
        AUTO_UPDATE_BACKOFF_SECS,
    ) {
        tracing::warn!(target = %tag, "auto-update: recently attempted this target, backing off");
        return Ok(());
    }

    // Record the attempt *before* swapping so a crash mid-swap still counts
    // against the backoff; it survives the restart via settings.toml.
    let attempted = tag.clone();
    if let Err(e) = config::update_settings(|cfg| {
        cfg.auto_update_last_target = Some(attempted);
        cfg.auto_update_last_attempt = Some(now);
        Ok(())
    }) {
        tracing::warn!(error = %e, "auto-update: failed to persist attempt marker");
    }

    tracing::info!(current, target = %tag, "auto-update: found newer stable release, swapping");
    let expected = crate::update::fetch_checksum(&client, &tag, &asset).await?;
    let bin_url = crate::update::asset_download_url(&tag, &asset);
    #[cfg(windows)]
    {
        let msi = crate::update::download_msi_to_temp(&client, &bin_url, &expected, &asset).await?;
        let identity = crate::update::fetch_version_manifest(&client, &tag, &asset).await?;
        crate::update::schedule_msi_update(&msi, &identity, &expected)?;
        tracing::info!(target = %identity, path = %msi.display(), "auto-update: detached Windows MSI installation scheduled");
        shutdown.cancel();
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = shutdown;
        crate::update::download_and_swap(&client, &bin_url, &expected, &asset).await?;

        tracing::info!(target = %tag, "auto-update: binary swapped, restarting service onto it");
        crate::update::trigger_detached_restart();
        Ok(())
    }
}

/// Current unix time in whole seconds (best-effort; 0 before the epoch, which
/// never happens in practice).
#[cfg(feature = "desktop")]
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Private mode's precondition: both server lists name the operator's own
/// servers and only those (`replace` mode, non-empty).
///
/// Split out from the check in `config::settings::apply_global` because the two
/// answer different questions. That one rejects a bad *write*; this one rejects
/// a bad *state*, which is what a hand-edited `settings.toml` produces.
fn private_mode_servers_ok(cfg: &config::AppConfig) -> Result<()> {
    use crate::config::settings::is_own_servers;
    let missing: Vec<&str> = [("relay", &cfg.relay), ("discovery-dns", &cfg.discovery_dns)]
        .into_iter()
        .filter(|(_, o)| !is_own_servers(o))
        .map(|(name, _)| name)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "private mode is on but {} {} not set to a server of your own\n    \
         fix the config, or leave private mode: ray up --no-private",
        missing.join(" and "),
        if missing.len() == 1 { "is" } else { "are" },
    )
}

#[cfg(test)]
mod tests {
    /// The startup guard is the backstop for a hand-edited `settings.toml`: both
    /// write paths already refuse this state, so reaching it means the file was
    /// changed behind them, and starting anyway would leave the node claiming a
    /// privacy it does not have.
    #[test]
    fn private_mode_startup_guard_names_every_missing_server() {
        use super::private_mode_servers_ok;
        use crate::config::{AppConfig, ServerOverride};

        let own = || ServerOverride {
            servers: vec!["http://s.example".to_string()],
            replace: true,
        };

        let mut cfg = AppConfig {
            private_mode: true,
            ..AppConfig::default()
        };
        let err = private_mode_servers_ok(&cfg).unwrap_err().to_string();
        assert!(err.contains("relay and discovery-dns"), "{err}");
        assert!(err.contains("are not set"), "plural reads right: {err}");

        cfg.relay = own();
        let err = private_mode_servers_ok(&cfg).unwrap_err().to_string();
        assert!(err.contains("discovery-dns is not set"), "singular: {err}");

        cfg.discovery_dns = own();
        assert!(private_mode_servers_ok(&cfg).is_ok());

        // `augment` keeps n0's servers alongside these, so it does not satisfy it.
        cfg.relay.replace = false;
        assert!(private_mode_servers_ok(&cfg).is_err());
    }

    use super::*;

    /// The decode-error reply quotes the request, and a frame may carry up to
    /// `MAX_FRAME_LEN` of it. Bounding the reply is what keeps a client that
    /// sends a megabyte key and then never reads from parking a daemon task on
    /// a write that cannot finish.
    #[test]
    fn a_decode_error_reply_is_bounded_however_long_the_request_was() {
        let huge = format!("unknown config key: {}", "A".repeat(900_000));
        let out = truncate(&huge);
        assert!(out.len() < MAX_DECODE_ERROR_LEN + 32, "{}", out.len());
        assert!(out.ends_with("... (truncated)"), "{out}");
        // The useful prefix survives: the reader still learns what went wrong.
        assert!(out.starts_with("unknown config key: AAA"), "{out}");
    }

    /// A real error is well under the cap and must come through untouched.
    #[test]
    fn a_normal_error_is_not_truncated() {
        let msg = format!(
            "decode IPC message: {}",
            "unknown config key: bogus (mdns, relay, discovery-dns, dns-upstreams, \
             auto-update, on-demand, ssh, download-dir, download-user, firewall.enabled, \
             firewall.reject, firewall.default-in, net.auto-accept-firewall, \
             net.auto-accept-files, net.ephemeral-ttl)"
        );
        assert!(msg.len() < MAX_DECODE_ERROR_LEN, "{}", msg.len());
        assert_eq!(truncate(&msg), msg);
    }

    /// Truncation lands on a char boundary: a multi-byte char straddling the cap
    /// would panic the slice.
    #[test]
    fn truncation_never_splits_a_multibyte_char() {
        // 3 bytes per char, and the cap is not a multiple of 3, so the cut
        // lands mid-char and the backtrack has to run. A 2-byte char would
        // leave byte 512 already on a boundary and test nothing.
        assert_ne!(MAX_DECODE_ERROR_LEN % 3, 0);
        let s = "€".repeat(MAX_DECODE_ERROR_LEN);
        let out = truncate(&s);
        assert!(out.ends_with("... (truncated)"), "{out}");
        let kept = out.strip_suffix("... (truncated)").unwrap();
        assert_eq!(kept.len(), MAX_DECODE_ERROR_LEN - MAX_DECODE_ERROR_LEN % 3);
    }
}
