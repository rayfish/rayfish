//! Daemon process bootstrap and the IPC server. Moved out of `daemon/mod.rs`.
//!
//! `run_daemon` is the process entry point (called by the `ray daemon`
//! command): it builds the shared [`MeshManager`], reconnects saved networks,
//! and runs the IPC accept loop until shutdown. `build_daemon` wires the endpoint
//! / TUN / protocol router / metrics; `serve_ipc` + `handle_ipc_client` answer
//! `ray` CLI requests over the Unix socket. These live in a `mesh/` submodule
//! (a descendant of `daemon`) so they can still construct `MeshManager` and reach
//! its private fields without widening visibility.

use super::super::*;

pub async fn run_daemon(token: CancellationToken, stats: Arc<ForwardMetrics>) -> Result<()> {
    // Bail early on a CGNAT clash (e.g. Tailscale) before touching anything.
    #[cfg(not(target_os = "android"))]
    check_cgnat_conflict()?;

    // Build the always-on infrastructure without a packet interface, then attach
    // the desktop OS TUN device below. The headless builder is the same one
    // `build_headless()` exposes to embedders (mobile), so both paths share
    // identical construction.
    let daemon = build_daemon(token.clone(), stats).await?;

    // Attach the real OS TUN device: create it, record its name, and spawn the
    // writer + `run_mesh` forwarding loop. On Android the packet interface is a
    // `VpnService` fd attached later by `ray-mobile` via `attach_tun`, so this is
    // skipped here.
    #[cfg(not(target_os = "android"))]
    {
        let my_ipv6 = derive_ipv6(&daemon.transport.identity.local_identity());
        let (tun_reader, tun_writer, tun_name) = tun::create(daemon.transport.identity.local_ip(), my_ipv6)
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
    daemon.activate(None).await;

    // Single daemon-wide connection supervisor: consumes every data reader's
    // disconnect and, per dropped identity, prunes departed peers we coordinate
    // and reconnects the rest across all their shared networks.
    let disconnect_rx = daemon
        .disconnect_rx
        .lock()
        .unwrap()
        .take()
        .expect("disconnect_rx present after build");
    {
        let daemon = daemon.clone();
        let token = token.clone();
        tokio::spawn(async move {
            daemon
                .registry
                .clone()
                .run_connection_supervisor(disconnect_rx, token)
                .await;
        });
    }

    // Opt-in automatic updates: a single daemon-wide task that periodically
    // checks for a newer stable release and swaps + restarts onto it. Desktop-only
    // (the self-replacing updater is not built into the Android lib).
    #[cfg(feature = "desktop")]
    if daemon.auto_update {
        spawn_auto_update(daemon.shutdown_token.clone());
    }

    let result = serve_ipc(&daemon, token).await;

    // Close the iroh endpoint before returning. Dropping it on return logs
    // "Endpoint dropped without calling `Endpoint::close`. Aborting
    // ungracefully." and can leave the process lingering until the service
    // manager escalates to SIGKILL, which delays the relaunch on
    // `ray restart`/`ray update` past the client's reachability probe. Closing
    // it here lets QUIC connections terminate cleanly and the process exit
    // promptly so the new daemon comes up fast.
    daemon.transport.endpoint.close().await;

    result
}

/// Construct all always-on daemon infrastructure: identity, iroh endpoint, blob
/// store, TUN device, forwarding loop, DNS resolver, mDNS discovery, protocol
/// router, and metrics server. Returns the shared [`MeshManager`] (still on
/// standby, so the caller is expected to run [`MeshManager::activate`]) and the
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

/// Construct a headless [`MeshManager`] for an embedder (used by `ray-mobile`
/// and future embedders). Builds the same infrastructure as `run_daemon` minus
/// the OS TUN device and the Unix-socket IPC server: the caller supplies a
/// packet interface via [`MeshManager::attach_tun`]. The returned daemon is on
/// standby (no data plane), with its saved networks' control plane connected.
pub async fn build_headless() -> Result<Arc<MeshManager>> {
    let token = CancellationToken::new();
    let stats = Arc::new(ForwardMetrics::default());
    let daemon = build_daemon(token, stats).await?;
    // Bring the saved networks' control plane up, matching `run_daemon`.
    daemon.registry.connect_all_networks().await;
    // Control readers and the join path now run their network ops (promotion,
    // self-unpair) directly via NetworkRegistry, so a headless embedder needs no
    // hand-off drain loop.
    Ok(daemon)
}

/// Build all always-on daemon infrastructure WITHOUT a packet interface or the
/// Unix-socket IPC server. The returned [`MeshManager`] is on standby (no data
/// plane); attach a TUN with [`MeshManager::attach_tun`], connect saved networks,
/// then bring the data plane up with [`MeshManager::activate`]. The promotion
/// receiver and metrics-server guard are stashed on the state for the caller.
///
/// Shared by [`run_daemon`] (desktop) and [`build_headless`] (embedders).
async fn build_daemon(
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
) -> Result<Arc<MeshManager>> {
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
    let collision_index = identity::load_collision_index()?;
    let identity = IrohIdentityProvider::new(public_key, collision_index);
    let my_ip = identity.local_ip();
    // Register our mesh addresses for the userspace SSH port NAT (mesh `:22`
    // <-> the embedded server's listen port). Stays inactive until `ssh on`.
    forward::init_ssh_nat(
        my_ip,
        derive_ipv6(&identity.local_identity()),
        crate::forward::SSH_LISTEN_PORT,
    );

    // --- iroh endpoint (one ALPN per saved network + the blobs ALPN) ---
    let mut app_config = config::load()?;
    // Point the pkarr client at the configured discovery-DNS server (if any)
    // before any record publish/resolve happens.
    dht::set_discovery_override(&app_config.discovery_dns);
    // Lazily generate + persist this node's contact key (`ray connect`). The
    // secret stays in config; only its public id is held in `MeshManager`.
    let contact_public = config::contact_secret(&mut app_config).public();
    if let Err(e) = config::save_settings(&app_config) {
        tracing::warn!(error = %e, "failed to persist contact key");
    }
    let alpns = initial_alpns(&app_config);
    let use_tor = app_config
        .networks
        .iter()
        .any(|net| net.transport.as_ref().is_some_and(|t| t.is_tor()));
    let ep = transport::create_endpoint_with_alpns(
        key.clone(),
        alpns,
        use_tor,
        &app_config.relay,
        &app_config.discovery_dns,
    )
    .await?;

    // --- Content-addressed blob store (membership/file transfer) ---
    let blobs_dir = config::config_dir()?.join("blobs");
    std::fs::create_dir_all(&blobs_dir)?;
    let blob_store = FsStore::load(&blobs_dir)
        .await
        .context("failed to open blob store")?;
    let blobs_proto = BlobsProtocol::new(&blob_store, None);

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
    let dns_resolver = std::sync::Arc::new(crate::dns_resolver::Resolver::new(
        hostname_table.clone(),
        reverse_table.clone(),
    ));
    // Built here (not in the struct literal) so NetworkRegistry can share it for
    // the leave/teardown DNS cleanup.
    let dns = Arc::new(DnsService::new(
        hostname_table,
        reverse_table,
        dns_resolver.clone(),
    ));
    let mdns_enabled = app_config.mdns_enabled;
    if mdns_enabled {
        spawn_mdns_discovery(&ep, token.clone());
    } else {
        tracing::info!("mDNS discovery disabled");
    }

    // --- Protocol router + the shared MeshManager ---
    // Group the foundation handles so extracted services can depend on
    // `Arc<Transport>`. Clones here are cheap (all fields are `Arc`-backed); the
    // loose `MeshManager` fields below still hold the originals until the daemon
    // god object is dissolved.
    let transport = Arc::new(Transport::new(
        ep.clone(),
        identity.clone(),
        blob_store.clone(),
        stats.clone(),
        contact_public,
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
    // MeshManager literal share the one sender.
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
    ));
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
    let auto_update = app_config.auto_update;
    let daemon = Arc::new(MeshManager {
        transport,
        registry,
        stats: stats.clone(),
        start: Instant::now(),
        tun_tx,
        shutdown_token: token.clone(),
        protocol_router: protocol_router.clone(),
        dns,
        mdns_enabled,
        auto_update,
        tun_name,
        tun_tasks: std::sync::Mutex::new(None),
        _metrics_server: std::sync::Mutex::new(None),
        files,
        connect,
        device_cert,
        contact_public,
        active: active.clone(),
        #[cfg(feature = "desktop")]
        ssh_authz: crate::ssh::new_authz(),
        ssh_token: std::sync::Mutex::new(None),
        disconnect_rx: std::sync::Mutex::new(Some(disconnect_rx)),
    });

    // Install the daemon-wide mesh dispatch context so the per-connection demux
    // (`drive_mesh_connection`) can build peer readers + route disconnects. Must
    // happen before the accept loop starts handing it connections.
    protocol_router.set_mesh_dispatch(MeshDispatch {
        ctx: daemon.mesh_ctx(),
        token: token.clone(),
    });

    // --- Accept loop (ALPN dispatch) + Prometheus metrics ---
    protocol_router.spawn_accept_loop(daemon.transport.endpoint.clone(), token.clone());

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
    let metrics_server =
        spawn_metrics_server(stats, daemon.registry.peers.clone(), &daemon.transport.endpoint, token).await;
    // Keep the metrics-server guard alive for the daemon's whole lifetime.
    *daemon._metrics_server.lock().unwrap() = metrics_server;

    tracing::info!(ip = %my_ip, id = %daemon.transport.endpoint.id().fmt_short(), "daemon started");
    Ok(daemon)
}

/// Advertise this endpoint over mDNS (`_rayfish._udp.local`) and log LAN peer
/// discovery events until cancellation. Non-fatal: a failure just means no
/// local discovery.
fn spawn_mdns_discovery(ep: &Endpoint, token: CancellationToken) {
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
                    }
                    Some(iroh_mdns_address_lookup::DiscoveryEvent::Expired { endpoint_id }) => {
                        tracing::info!(
                            peer = %endpoint_id.fmt_short(),
                            "mDNS: peer left LAN"
                        );
                    }
                    None => break,
                    _ => {}
                }
            }
        }
    });
}

/// Register rayfish counters, per-peer gauges, and iroh endpoint metrics, then
/// start the Prometheus HTTP endpoint on `:9090`. The returned guard must be
/// kept alive for the process lifetime; `None` means metrics export is disabled.
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

    let metrics_addr: SocketAddr = ([0, 0, 0, 0], 9090).into();
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
async fn serve_ipc(daemon: &Arc<MeshManager>, token: CancellationToken) -> Result<()> {
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
fn set_socket_permissions(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
        unsafe { libc::chmod(c_path.as_ptr(), 0o666) };
        tracing::info!("IPC socket mode 0666 (per-request authorization via peer creds)");
    }
}

async fn handle_ipc_client(stream: UnixStream, daemon: &Arc<MeshManager>) -> Result<()> {
    let peer_cred = stream.peer_cred().ok().map(|c| (c.uid(), c.gid()));
    let mut framed = ipc::framed(stream);
    let req = ipc::recv(&mut framed).await?;
    let resp = daemon.handle_request(req, peer_cred).await;
    ipc::send(&mut framed, resp).await?;
    Ok(())
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
            if let Err(e) = auto_update_once().await {
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
async fn auto_update_once() -> Result<()> {
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
    let mut cfg = config::load()?;
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
    cfg.auto_update_last_target = Some(tag.clone());
    cfg.auto_update_last_attempt = Some(now);
    if let Err(e) = config::save_settings(&cfg) {
        tracing::warn!(error = %e, "auto-update: failed to persist attempt marker");
    }

    tracing::info!(current, target = %tag, "auto-update: found newer stable release, swapping");
    let expected = crate::update::fetch_checksum(&client, &tag, &asset).await?;
    let bin_url = crate::update::asset_download_url(&tag, &asset);
    crate::update::download_and_swap(&client, &bin_url, &expected, &asset).await?;

    tracing::info!(target = %tag, "auto-update: binary swapped, restarting service onto it");
    crate::update::trigger_detached_restart();
    Ok(())
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
