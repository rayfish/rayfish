//! Mesh join handshake and reconnect loop. Moved out of `daemon/mod.rs` to keep
//! the core module focused on type definitions and process wiring.
//!
//! `join_mesh_shared` runs one coordinator handshake (fresh join sends
//! `JoinRequest` first; reconnect/restore lets the coordinator speak first) and,
//! on admission, registers the peer and starts its data-plane reader.
//! `spawn_reconnect_loop` keeps a member's connection alive with backoff.

use super::super::*;

/// Result of the initial join handshake against the coordinator.
pub(crate) enum JoinResult {
    /// Admitted (open network, valid invite, or pre-approved): live network state.
    Joined(SharedNetworkState),
    /// Queued for live approval on a closed network; the caller should retry.
    Pending,
}

/// Outcome of one `join_network_inner` attempt.
pub(crate) enum TryJoin {
    Joined(IpcMessage),
    Pending,
}

/// Result of [`perform_join_handshake`]: the admitted roster, or a closed-network
/// queue signal the caller turns into [`JoinResult::Pending`].
enum HandshakeOutcome {
    Admitted {
        members: Vec<crate::membership::Member>,
        approved: Vec<ApprovedEntry>,
    },
    Pending,
}

/// By-value parameters for one [`join_mesh_shared`] handshake, grouped so the
/// function's argument list stays manageable. These are all decided once, at the
/// call site, per join: the joiner's chosen hostname and cert, the invite secret
/// it presents, the blob-derived `suggested_firewall`/`reusable_keys` it
/// inherits, its firewall consent, and whether this is a fresh join or a
/// reconnect.
pub(crate) struct JoinParams {
    pub(crate) my_hostname: Option<String>,
    pub(crate) net_pubkey: EndpointId,
    pub(crate) device_cert: Option<control::DeviceCert>,
    pub(crate) invite_secret: Option<Vec<u8>>,
    /// From the fetched blob: the current coordinator-suggested firewall rules,
    /// persisted so a member inherits them.
    pub(crate) suggested_firewall: SuggestedFirewall,
    /// From the fetched blob: reusable join keys, so this node can validate
    /// redemptions if it later holds the network key (HA admission).
    pub(crate) reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    /// Consent: auto-install suggested rules without a manual review queue.
    pub(crate) auto_accept_firewall: bool,
    /// Seed for per-network auto-accept of file offers from own devices
    /// (`--auto-accept-files`). Persisted config wins on reconnect/restore; this
    /// is only the first-join seed.
    pub(crate) auto_accept_files: bool,
    /// Fresh join (send `JoinRequest` first) vs reconnect/restore (coordinator
    /// speaks first).
    pub(crate) initial: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn join_mesh_shared(
    initial_conn: Connection,
    ep: &Endpoint,
    network_name: &str,
    alpn: &[u8],
    ctx: MeshCtx,
    params: JoinParams,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    // Promotion signal: the per-peer control reader sends this network's name
    // here after persisting an `AdminGrant` key, so the daemon loop can swap in
    // the coordinator accept handler (see `MeshManager::promote_to_coordinator`).
    promote_tx: mpsc::Sender<String>,
    // Guards the single-use invite ledger. Shared with the NetworkHandle so the
    // control listener's `InviteShare`/`InviteUsed` handling (a co-coordinator
    // learning of invites it didn't mint) is serialized with mint/redeem.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    // Shared with the router; lets the member control reader resolve `ray ping`
    // Pongs back to the waiting handler.
    pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
) -> Result<JoinResult> {
    // A whole-bundle clone for the debounced reconverge worker, which forwards
    // the ctx straight to `reconverge_and_apply`.
    let worker_ctx = ctx.clone();
    let MeshCtx {
        identity,
        peers,
        blob_store,
        firewall,
        ..
    } = ctx;
    let JoinParams {
        my_hostname,
        net_pubkey,
        device_cert,
        invite_secret,
        suggested_firewall,
        reusable_keys,
        auto_accept_firewall,
        auto_accept_files,
        initial,
    } = params;
    let my_identity = identity.local_identity();
    let my_ip = identity.local_ip();

    let (members, approved) = match perform_join_handshake(
        &initial_conn,
        ep,
        network_name,
        &blob_store,
        &peers,
        net_pubkey,
        my_ip,
        my_identity,
        initial,
        invite_secret,
        &my_hostname,
        &device_cert,
    )
    .await?
    {
        HandshakeOutcome::Admitted { members, approved } => (members, approved),
        HandshakeOutcome::Pending => return Ok(JoinResult::Pending),
    };

    persist_join_config(
        network_name,
        &members,
        &approved,
        my_identity,
        my_ip,
        net_pubkey,
        &my_hostname,
        auto_accept_firewall,
        auto_accept_files,
    )?;

    // On reconnect/restore the coordinator hasn't seen our hostname this session,
    // so send a MeshHello. A fresh join already conveyed it in the JoinRequest.
    if !initial {
        send_reconnect_hello(
            &initial_conn,
            my_identity,
            my_ip,
            network_name,
            &device_cert,
        )
        .await?;
    }

    // Register the coordinator connection as our first peer, then dial the rest
    // of the roster.
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);
    crate::spawn_path_logger(initial_conn.clone(), remote_id.fmt_short().to_string());
    register_mesh_peer(
        &peers,
        &worker_ctx,
        &disconnect_tx,
        &token,
        initial_conn.clone(),
        remote_id,
        remote_ip,
        network_name,
    );
    connect_to_roster_peers(
        ep,
        alpn,
        &members,
        network_name,
        my_identity,
        my_ip,
        remote_id,
        &device_cert,
        &peers,
        &worker_ctx,
        &disconnect_tx,
        &token,
    )
    .await?;

    let live_state = build_member_state(
        members,
        approved,
        net_pubkey,
        network_name,
        suggested_firewall,
        reusable_keys,
        &blob_store,
    )
    .await;

    // Materialize this node's suggested rules from the blob we just joined with.
    // Re-runs on every roster/blob update from the control listener below.
    apply_suggested_firewall(&firewall, my_identity, network_name, &live_state);

    // Reconverge worker: `MemberSync`/`BlobUpdated` triggers fan into this single
    // debounced task (see `spawn_reconverge_worker`).
    let reconverge_notify = Arc::new(tokio::sync::Notify::new());
    spawn_reconverge_worker(
        reconverge_notify.clone(),
        token.clone(),
        live_state.clone(),
        network_name.to_string(),
        worker_ctx,
        ep.clone(),
        my_identity,
        net_pubkey,
        alpn.to_vec(),
        my_ip,
        device_cert.clone(),
    );

    spawn_member_control_listener(
        initial_conn.clone(),
        remote_id,
        token.clone(),
        live_state.clone(),
        network_name.to_string(),
        peers.clone(),
        ep.clone(),
        my_identity,
        net_pubkey,
        promote_tx.clone(),
        invite_lock.clone(),
        reconverge_notify.clone(),
        pending_pongs.clone(),
    );

    Ok(JoinResult::Joined(live_state))
}

/// Persist this network's membership to config after a successful handshake.
/// Preserves the `direct` flag and any queued `pending_hostname` rename intent
/// from the existing config (the freshly fetched blob won't carry the rename yet,
/// so keeping it alive lets the drain re-send until a coordinator confirms it).
#[allow(clippy::too_many_arguments)]
fn persist_join_config(
    network_name: &str,
    members: &[crate::membership::Member],
    approved: &[ApprovedEntry],
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    net_pubkey: EndpointId,
    my_hostname: &Option<String>,
    auto_accept_firewall: bool,
    auto_accept_files: bool,
) -> Result<()> {
    let persisted_hostname = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone())
        .or(my_hostname.clone());
    // Preserve across reconnects/restores state the just-fetched blob doesn't
    // carry: the direct-connection flag, a queued rename intent, the SSH allow
    // list, and node-local aliases.
    let (direct, pending_hostname, ssh_allow, aliases, prev_auto_accept_files) =
        config::load_network(network_name)?
            .map(|n| {
                (
                    n.direct,
                    n.pending_hostname,
                    n.ssh_allow,
                    n.aliases,
                    n.auto_accept_files,
                )
            })
            .unwrap_or((false, None, vec![], BTreeMap::new(), false));
    // The toggle command (`ray files auto-accept`) is authoritative, so preserve
    // a previously-persisted value; the join-time `--auto-accept-files` seed only
    // needs to take effect on the first join (no prior config).
    let auto_accept_files = prev_auto_accept_files || auto_accept_files;
    config::save_network(&config::NetworkConfig {
        name: network_name.to_string(),
        group_mode: GroupMode::Restricted,
        my_ip: Some(my_ip),
        my_hostname: persisted_hostname,
        pending_hostname,
        members: to_member_entries(members.iter()),
        approved: to_approved_entries(approved.iter()),
        network_secret_key: None,
        network_public_key: Some(net_pubkey),
        transport: None,
        auto_accept_firewall,
        auto_accept_files,
        admins: vec![],
        direct,
        ssh_allow,
        aliases,
    })
}

/// Send a `MeshHello` to the coordinator on reconnect/restore (a fresh join
/// already conveyed the hostname in its `JoinRequest`). Reads the hostname fresh
/// from config so a rename done since startup is announced now, not a stale name.
async fn send_reconnect_hello(
    conn: &Connection,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    network_name: &str,
    device_cert: &Option<control::DeviceCert>,
) -> Result<()> {
    let (mut send, _recv) = conn.open_bi().await?;
    control::send_msg(
        &mut send,
        &ControlMsg::MeshHello {
            identity: my_identity,
            ip: my_ip,
            hostname: outgoing_hostname(network_name),
            device_cert: device_cert.clone(),
        },
    )
    .await
}

/// Build the in-memory `NetworkState` cell for a joined member from the admitted
/// roster + blob-derived firewall/keys, refresh its snapshot, and seed the local
/// blob store with those bytes.
async fn build_member_state(
    members: Vec<crate::membership::Member>,
    approved: Vec<ApprovedEntry>,
    net_pubkey: EndpointId,
    network_name: &str,
    suggested_firewall: SuggestedFirewall,
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    blob_store: &FsStore,
) -> SharedNetworkState {
    let mut ns = NetworkState {
        members: MemberList::from_members(members),
        approved: ApprovedList::from_entries(approved),
        snapshot: None,
        network_secret_key: None,
        network_public_key: net_pubkey,
        network_name: Some(network_name.to_string()),
        mode: GroupMode::Restricted,
        suggested_firewall,
        reusable_keys,
        pending_suggestions: Vec::new(),
        pending: HashMap::new(),
    };
    ns.refresh_snapshot();
    if let Some(snap) = &ns.snapshot {
        let _ = blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
    }
    Arc::new(std::sync::RwLock::new(ns))
}

/// Add a peer's route to the table and start its data-plane reader. Shared by the
/// initial coordinator connection and each roster member dialed afterward.
#[allow(clippy::too_many_arguments)]
fn register_mesh_peer(
    peers: &PeerTable,
    ctx: &MeshCtx,
    disconnect_tx: &mpsc::Sender<forward::DisconnectEvent>,
    token: &CancellationToken,
    conn: Connection,
    peer_id: EndpointId,
    peer_ip: Ipv4Addr,
    network_name: &str,
) {
    let peer_ipv6 = derive_ipv6(&peer_id);
    peers.add(peer_ip, peer_ipv6, conn.clone(), peer_id, network_name);
    forward::spawn_peer_reader(
        conn,
        peer_id,
        peer_ip,
        peer_ipv6,
        network_name.to_string(),
        ctx.forward_ctx(disconnect_tx.clone(), token.clone()),
    );
}

/// Dial every other roster member (skipping ourselves and the already-connected
/// coordinator), send each a `MeshHello`, and register it as a peer. A member
/// that's offline is logged and skipped; a stream-open/send failure aborts the
/// join (propagated to the caller).
#[allow(clippy::too_many_arguments)]
async fn connect_to_roster_peers(
    ep: &Endpoint,
    alpn: &[u8],
    members: &[crate::membership::Member],
    network_name: &str,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    skip_id: EndpointId,
    device_cert: &Option<control::DeviceCert>,
    peers: &PeerTable,
    ctx: &MeshCtx,
    disconnect_tx: &mpsc::Sender<forward::DisconnectEvent>,
    token: &CancellationToken,
) -> Result<()> {
    for member in members {
        if member.identity == my_identity || member.identity == skip_id {
            continue;
        }
        match transport::connect_to_peer_with_alpn(ep, member.identity, alpn).await {
            Ok(conn) => {
                let (mut send, _recv) = conn.open_bi().await?;
                control::send_msg(
                    &mut send,
                    &ControlMsg::MeshHello {
                        identity: my_identity,
                        ip: my_ip,
                        hostname: outgoing_hostname(network_name),
                        device_cert: device_cert.clone(),
                    },
                )
                .await?;
                register_mesh_peer(
                    peers,
                    ctx,
                    disconnect_tx,
                    token,
                    conn,
                    member.identity,
                    member.ip,
                    network_name,
                );
                tracing::info!(peer_ip = %member.ip, "connected to mesh peer");
            }
            Err(e) => {
                tracing::warn!(peer_ip = %member.ip, error = %e, "mesh peer unavailable");
            }
        }
    }
    Ok(())
}

/// Run one coordinator handshake. A fresh join (`initial`) opens a stream, sends
/// a `JoinRequest` (invite secret + hostname), and reads the verdict on the same
/// stream. A reconnect/restore keeps the legacy handshake where the coordinator
/// speaks first (Welcome/JoinApproved/MemberSync) — on a `MemberSync` trigger the
/// roster comes from the network-key-signed pkarr record, never peer-supplied
/// membership. Returns the admitted roster, or `Pending` on a closed network.
#[allow(clippy::too_many_arguments)]
async fn perform_join_handshake(
    initial_conn: &Connection,
    ep: &Endpoint,
    network_name: &str,
    blob_store: &FsStore,
    peers: &PeerTable,
    net_pubkey: EndpointId,
    my_ip: Ipv4Addr,
    my_identity: EndpointId,
    initial: bool,
    invite_secret: Option<Vec<u8>>,
    my_hostname: &Option<String>,
    device_cert: &Option<control::DeviceCert>,
) -> Result<HandshakeOutcome> {
    if initial {
        let (mut send, mut recv) = initial_conn
            .open_bi()
            .await
            .context("open join control stream")?;
        control::send_msg(
            &mut send,
            &ControlMsg::JoinRequest {
                invite_secret,
                hostname: my_hostname.clone(),
                device_cert: device_cert.clone(),
            },
        )
        .await
        .context("send join request")?;
        let msg = tokio::time::timeout(Duration::from_secs(30), control::recv_msg(&mut recv))
            .await
            .context("timeout awaiting join response")??;
        match msg {
            ControlMsg::Welcome { members, approved } => {
                tracing::info!(network = %network_name, "welcomed to network");
                if let Some(existing) = members
                    .iter()
                    .find(|m| m.ip == my_ip && m.identity != my_identity)
                {
                    anyhow::bail!(
                        "IP collision: {} is already assigned to {}",
                        my_ip,
                        existing.identity
                    );
                }
                Ok(HandshakeOutcome::Admitted { members, approved })
            }
            ControlMsg::JoinPending => {
                tracing::info!(network = %network_name, "join pending operator approval");
                Ok(HandshakeOutcome::Pending)
            }
            ControlMsg::JoinDenied { reason } => anyhow::bail!("join denied: {reason}"),
            other => anyhow::bail!("expected Welcome or JoinPending, got {other:?}"),
        }
    } else {
        let (_send, mut recv) = initial_conn
            .accept_bi()
            .await
            .context("accept control stream")?;
        let msg = control::recv_msg(&mut recv).await?;
        let (members, approved) = match msg {
            ControlMsg::Welcome { members, approved } => {
                tracing::info!(network = %network_name, "welcomed to network");
                (members, approved)
            }
            ControlMsg::JoinApproved { your_ip, members } => {
                tracing::info!(ip = %your_ip, network = %network_name, "joined network (legacy)");
                (members, vec![])
            }
            ControlMsg::MemberSync => {
                // Reconnected via a peer. The message is only a trigger — fetch
                // the authoritative roster from the network-key-signed pkarr
                // record. If it's briefly unreachable, fall back to our last
                // persisted roster rather than trusting peer-supplied membership.
                tracing::info!(network = %network_name, "reconnected via peer; reconverging from signed record");
                match resolve_signed(ep, net_pubkey).await {
                    Some((signed, seeds)) => {
                        match fetch_verified_blob(
                            ep,
                            blob_store,
                            peers,
                            signed,
                            network_name,
                            &seeds,
                        )
                        .await
                        {
                            Some(data) => (data.members, data.approved),
                            None => (persisted_roster(network_name), vec![]),
                        }
                    }
                    None => (persisted_roster(network_name), vec![]),
                }
            }
            ControlMsg::JoinDenied { reason } => anyhow::bail!("join denied: {reason}"),
            other => anyhow::bail!("expected Welcome or MemberSync, got {other:?}"),
        };
        Ok(HandshakeOutcome::Admitted { members, approved })
    }
}

/// Debounced reconverge worker for a joined member. `MemberSync`/`BlobUpdated`
/// triggers (and a 30s backstop tick while a rename is outstanding) fan into this
/// single task instead of each driving a reconverge inline: a burst of triggers
/// collapses into one pkarr resolve + reconverge, and a slow reconverge never
/// blocks the control listener's accept loop. The network-key-signed record stays
/// the source of truth, so converging once per burst suffices.
#[allow(clippy::too_many_arguments)]
fn spawn_reconverge_worker(
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
    live_state: SharedNetworkState,
    network_name: String,
    ctx_w: MeshCtx,
    endpoint_w: Endpoint,
    my_identity_w: EndpointId,
    net_pubkey_w: EndpointId,
    alpn_w: Vec<u8>,
    my_ip_w: Ipv4Addr,
    device_cert_w: Option<control::DeviceCert>,
) {
    tokio::spawn(async move {
        // Backstop tick so a queued rename is retried even on a quiet
        // network that sends no `MemberSync`/`BlobUpdated` triggers. It does
        // a reconverge only while a rename is outstanding, so steady state
        // stays trigger-driven (no extra pkarr traffic).
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                _ = notify.notified() => {}
                _ = tick.tick() => {
                    // Only the pending-rename backstop wants the periodic
                    // wake; otherwise idle until the next real trigger.
                    if !has_pending_hostname(&network_name) {
                        continue;
                    }
                    tracing::debug!(
                        network = %network_name,
                        "backstop tick: pending rename outstanding, reconverging to retry delivery"
                    );
                }
            }
            // Debounce: absorb a burst of triggers into a single reconverge.
            // A trigger that arrives during the sleep or the reconverge is
            // retained by `Notify` and handled on the next iteration.
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
            }
            reconverge_and_apply(
                &endpoint_w,
                &ctx_w,
                net_pubkey_w,
                &network_name,
                &live_state,
                my_identity_w,
                &alpn_w,
                my_ip_w,
                &device_cert_w,
            )
            .await;
        }
    });
}

/// Per-connection control listener for a joined member: reads control messages
/// off the coordinator connection under a [`ControlGate`] rate limit and applies
/// each (approval, reconverge triggers, `AdminGrant` promotion, invite gossip,
/// ping/pong). Roster/firewall state comes only from the signed pkarr record, so
/// `MemberSync`/`BlobUpdated` are mere triggers into the reconverge worker.
#[allow(clippy::too_many_arguments)]
fn spawn_member_control_listener(
    initial_conn: Connection,
    remote_id: EndpointId,
    token: CancellationToken,
    live_state: SharedNetworkState,
    network_name: String,
    peers_c: PeerTable,
    endpoint_c: Endpoint,
    my_identity_c: EndpointId,
    net_pubkey_c: EndpointId,
    promote_tx: mpsc::Sender<String>,
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    reconverge_notify: Arc<tokio::sync::Notify>,
    pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
) {
    tokio::spawn(async move {
        let mut gate = crate::ratelimit::ControlGate::new();
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                result = initial_conn.accept_bi() => {
                    match result {
                        Ok((_send, mut recv)) => {
                            let msg = match control::recv_msg(&mut recv).await {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            // Throttle inbound control messages per connection:
                            // drop over-budget ones, drop the peer on a flood.
                            match gate.check() {
                                crate::ratelimit::Verdict::Allow => {}
                                crate::ratelimit::Verdict::Drop => continue,
                                crate::ratelimit::Verdict::Close => {
                                    tracing::warn!(peer = %remote_id.fmt_short(), "control-plane flood; closing connection");
                                    initial_conn.close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                                    return;
                                }
                            }
                            match msg {
                                ControlMsg::MemberApproved { identity, ip, hostname, .. } => {
                                    let entry = ApprovedEntry { identity, ip, hostname, user_identity: None, device_cert: None, collision_index: 0 };
                                    let mut s = live_state.write().unwrap();
                                    let members = s.members.clone();
                                    let _ = s.approved.approve(entry, &members);
                                }
                                ControlMsg::MemberSync => {
                                    // Trigger only. The roster/firewall come exclusively
                                    // from the network-key-signed pkarr record, never from
                                    // peer-supplied membership. Coalesced into the debounced
                                    // reconverge worker.
                                    reconverge_notify.notify_one();
                                }
                                ControlMsg::BlobUpdated => {
                                    // Trigger only. Reconverge from the network-key-signed
                                    // pkarr record — a malicious member can't inject a
                                    // forged roster/firewall blob via this message. Coalesced
                                    // into the debounced reconverge worker.
                                    reconverge_notify.notify_one();
                                }
                                ControlMsg::AdminGrant { network_pubkey, secret_key } => {
                                    // Coordinator granted us the per-network key.
                                    // Verify it targets this network (the stream is
                                    // already ALPN-scoped, but defense in depth).
                                    if network_pubkey != net_pubkey_c {
                                        tracing::warn!(
                                            peer = %remote_id.fmt_short(),
                                            "admin grant for a different network; ignoring"
                                        );
                                        continue;
                                    }
                                    // Self-authenticating: only adopt a key
                                    // that genuinely is this network's key
                                    // (its public half must equal the network
                                    // pubkey). Defeats a forged AdminGrant
                                    // from a non-coordinator member without
                                    // relying on reconverge timing for the
                                    // granter's is_coordinator flag.
                                    if !admin_grant_key_valid(secret_key, net_pubkey_c) {
                                        tracing::warn!(
                                            peer = %remote_id.fmt_short(),
                                            "admin grant key does not match network pubkey; ignoring"
                                        );
                                        continue;
                                    }
                                    let key = SecretKey::from(secret_key);
                                    // Persist + take local publish capability.
                                    if let Ok(Some(mut net)) = config::load_network(&network_name) {
                                        net.network_secret_key = Some(key.clone());
                                        let _ = config::save_network(&net);
                                    }
                                    let endpoint_id = endpoint_c.id();
                                    {
                                        let mut s = live_state.write().unwrap();
                                        s.network_secret_key = Some(key.clone());
                                        if let Some(m) = s.members.get_mut(&my_identity_c) {
                                            m.is_coordinator = true;
                                        }
                                        s.refresh_snapshot();
                                    }
                                    // Spawn a lazy publisher (this node can now
                                    // publish the signed blob / suggest rules).
                                    if let Ok(client) = dht::create_pkarr_client(&endpoint_c) {
                                        spawn_lazy_publisher(
                                            client,
                                            key,
                                            live_state.clone(),
                                            endpoint_id,
                                            peers_c.clone(),
                                            network_name.clone(),
                                            token.clone(),
                                        );
                                        tracing::info!(
                                            network = %network_name,
                                            "promoted to co-coordinator; lazy publisher started"
                                        );
                                    }
                                    // Signal the daemon loop to swap this
                                    // network's accept handler to coordinator
                                    // so it can admit fresh joiners (not just
                                    // welcome pre-approved peers). The loop
                                    // holds the `Arc<MeshManager>` this task
                                    // does not. Best-effort: a closed channel
                                    // only means the daemon is shutting down.
                                    let _ = promote_tx.send(network_name.clone()).await;
                                }
                                ControlMsg::InviteShare { id, secret_hash, expires } => {
                                    // Another coordinator minted a single-use
                                    // invite; record its hash so we can redeem
                                    // it too. Only honor it from a peer that is
                                    // a coordinator in our verified roster.
                                    if !sender_is_coordinator(&live_state, remote_id) {
                                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteShare from non-coordinator");
                                        continue;
                                    }
                                    let Ok(hash) = String::from_utf8(secret_hash) else {
                                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteShare with non-utf8 hash");
                                        continue;
                                    };
                                    let _guard = invite_lock.lock().await;
                                    if let Ok(mut store) = crate::invite::InviteStore::load(&network_name) {
                                        let _ = store.record_shared(id, hash, expires);
                                    }
                                }
                                ControlMsg::InviteUsed { secret_hash } => {
                                    // Another coordinator redeemed a single-use
                                    // invite; burn it locally so it can't be
                                    // reused here. Coordinator-only.
                                    if !sender_is_coordinator(&live_state, remote_id) {
                                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteUsed from non-coordinator");
                                        continue;
                                    }
                                    let Ok(hash) = String::from_utf8(secret_hash) else {
                                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteUsed with non-utf8 hash");
                                        continue;
                                    };
                                    let _guard = invite_lock.lock().await;
                                    if let Ok(mut store) = crate::invite::InviteStore::load(&network_name) {
                                        let _ = store.burn_by_hash(&hash);
                                    }
                                }
                                ControlMsg::Ping { nonce } => {
                                    respond_pong(&initial_conn, nonce).await;
                                }
                                ControlMsg::Pong { nonce } => {
                                    if let Some((_, tx)) = pending_pongs.remove(&nonce) {
                                        let _ = tx.send(());
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_reconnect_loop(
    mut disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
    ep: Endpoint,
    alpn: Vec<u8>,
    network_name: String,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    ctx: MeshCtx,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    device_cert: Option<control::DeviceCert>,
) -> JoinHandle<()> {
    // The reconnect MeshHello reads the current hostname fresh from config
    // (`outgoing_hostname`), so no captured hostname is threaded through.
    let MeshCtx {
        peers,
        tun_tx,
        stats,
        firewall,
        device_user_map,
        pruned_peers,
        ..
    } = ctx;
    use tracing::Instrument as _;
    // Tag all reconnect-loop logs for this network so they correlate in reports.
    let span = tracing::info_span!("reconnect", net = %network_name);
    let reconnect_loop = async move {
        loop {
            let event = tokio::select! {
                _ = token.cancelled() => return,
                event = disconnect_rx.recv() => match event {
                    Some(ev) => ev,
                    None => return,
                },
            };
            let peer_id = event.endpoint_id;
            let peer_ip = event.ip;
            let peer_ipv6 = event.ipv6;
            // Drop only this network's route, and only if the stored connection
            // is still the one that died. If the peer already re-dialed and a
            // fresh connection is registered, this is a stale disconnect for the
            // old connection: ignore it entirely rather than tearing down the
            // live link and redialing on top of it (see conn_stable_id).
            let removed = match event.conn_stable_id {
                Some(id) => peers.remove_peer_from_network_if(&peer_ip, &peer_ipv6, &event.network, id),
                None => {
                    // Synthetic cold-restore kick: nothing is registered yet, so
                    // force the reconnect dial below.
                    peers.remove_peer_from_network(&peer_ip, &peer_ipv6, &event.network);
                    true
                }
            };
            if !removed {
                tracing::debug!(peer = %peer_id.fmt_short(), ip = %peer_ip, "ignoring stale disconnect; peer already reconnected");
                continue;
            }

            // A deliberate `ray leave` (graceful close with the leave code) means
            // the peer is gone for good — don't spin a reconnect task against it.
            // The coordinator's MemberSync will prune it from our roster.
            if event.intentional {
                tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer left, not reconnecting");
                continue;
            }
            // We just pruned this peer from the roster (it was kicked or departed)
            // and closed the connection ourselves — that close is what woke this
            // loop. The peer still lists us, so re-dialing would re-form the link.
            // Consume the one-shot suppression entry and skip.
            if pruned_peers
                .remove(&(network_name.clone(), peer_id))
                .is_some()
            {
                tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer removed from roster, not reconnecting");
                continue;
            }
            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer disconnected, will reconnect");

            let ep = ep.clone();
            let alpn = alpn.clone();
            let network_name = network_name.clone();
            let peers = peers.clone();
            let tun_tx = tun_tx.clone();
            let disconnect_tx = disconnect_tx.clone();
            let token = token.clone();
            let stats = stats.clone();
            let firewall = firewall.clone();
            let device_cert = device_cert.clone();
            let device_user_map = device_user_map.clone();

            tokio::spawn(async move {
                let mut backoff = BACKOFF_INITIAL;
                loop {
                    if token.is_cancelled() {
                        return;
                    }
                    tracing::info!(peer = %peer_id.fmt_short(), secs = backoff.as_secs(), "reconnecting in");
                    tokio::select! {
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);

                    match transport::connect_to_peer_with_alpn(&ep, peer_id, &alpn).await {
                        Ok(conn) => {
                            let (mut send, _) = match conn.open_bi().await {
                                Ok(bi) => bi,
                                Err(e) => {
                                    tracing::warn!(error = %e, "reconnect handshake failed");
                                    continue;
                                }
                            };
                            if let Err(e) = control::send_msg(
                                &mut send,
                                &ControlMsg::MeshHello {
                                    identity: my_identity,
                                    ip: my_ip,
                                    hostname: outgoing_hostname(&network_name),
                                    device_cert: device_cert.clone(),
                                },
                            )
                            .await
                            {
                                tracing::warn!(error = %e, "reconnect MeshHello failed");
                                continue;
                            }
                            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "reconnected to peer");
                            peers.add(peer_ip, peer_ipv6, conn.clone(), peer_id, &network_name);
                            forward::spawn_peer_reader(
                                conn,
                                peer_id,
                                peer_ip,
                                peer_ipv6,
                                network_name,
                                forward::ForwardCtx {
                                    firewall,
                                    tun_tx,
                                    disconnect_tx,
                                    token,
                                    stats,
                                    device_user_map,
                                },
                            );
                            return;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "reconnect attempt failed");
                        }
                    }
                }
            });
        }
    };
    tokio::spawn(reconnect_loop.instrument(span))
}
