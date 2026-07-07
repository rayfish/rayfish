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
    // The network-owning service: the per-peer control reader calls
    // `registry.promote_to_coordinator` on itself after persisting an
    // `AdminGrant` key (was the `promote_tx` hand-off to the daemon loop).
    registry: Arc<NetworkRegistry>,
    // Guards the single-use invite ledger. Shared with the NetworkHandle so the
    // member accept handler's `InviteShare`/`InviteUsed` handling (a co-coordinator
    // learning of invites it didn't mint) is serialized with mint/redeem.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    // The router this network's member accept handler is registered in, and whose
    // per-connection demux dispatches control frames (incl. ping/pong).
    protocol_router: Arc<ProtocolRouter>,
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

    let _ = disconnect_tx; // readers use the daemon-wide sender via `ctx`.
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);

    let live_state = build_member_state(
        &members,
        approved,
        net_pubkey,
        network_name,
        suggested_firewall,
        reusable_keys,
        &blob_store,
    )
    .await;

    // Materialize this node's suggested rules from the blob we just joined with.
    // Re-runs on every verified reconverge triggered from the demux.
    apply_suggested_firewall(&firewall, my_identity, network_name, &live_state);

    // Reconverge worker: `MemberSync`/`BlobUpdated` triggers fan into this single
    // debounced task. The notify is shared with the member accept handler below.
    let reconverge_notify = Arc::new(tokio::sync::Notify::new());
    spawn_reconverge_worker(
        reconverge_notify.clone(),
        token.clone(),
        live_state.clone(),
        network_name.to_string(),
        worker_ctx.clone(),
        ep.clone(),
        my_identity,
        net_pubkey,
        alpn.to_vec(),
        my_ip,
        device_cert.clone(),
    );

    // Register this network's member accept handler so the per-connection demux
    // dispatches coordinator broadcasts + other members' hellos to it. A node that
    // already holds the network key is overwritten with a coordinator handler by
    // `finalize_join`.
    protocol_router.register(
        net_pubkey,
        AcceptHandler::Member(Arc::new(MemberAcceptState {
            ctx: worker_ctx.clone(),
            network_name: network_name.to_string(),
            state: live_state.clone(),
            token: token.clone(),
            net_pubkey,
            my_identity,
            endpoint: ep.clone(),
            registry: registry.clone(),
            invite_lock: invite_lock.clone(),
            reconverge_notify: reconverge_notify.clone(),
        })),
    );

    // Register the coordinator connection + drive its control demux, then dial the
    // rest of the roster the same way (one connection per peer identity).
    crate::spawn_path_logger(initial_conn.clone(), remote_id.fmt_short().to_string());
    register_dialed_peer(
        &worker_ctx,
        &protocol_router,
        initial_conn,
        remote_id,
        remote_ip,
        network_name,
    )
    .await;
    connect_to_roster_peers(
        ep,
        &members,
        network_name,
        net_pubkey,
        my_identity,
        my_ip,
        remote_id,
        &device_cert,
        &worker_ctx,
        &protocol_router,
    )
    .await?;

    Ok(JoinResult::Joined(live_state))
}

/// Register a peer we dialed: add its route, drive the control demux for the new
/// connection (which owns the data reader), and announce our handle table so it
/// can decode our tagged datagrams. Shared by the coordinator connection and each
/// roster peer.
async fn register_dialed_peer(
    ctx: &MeshCtx,
    router: &Arc<ProtocolRouter>,
    conn: Connection,
    peer_id: EndpointId,
    ip: Ipv4Addr,
    network_name: &str,
) {
    let conn_changed = ctx.register_peer_conn(&conn, peer_id, ip, network_name);
    if conn_changed {
        let router = router.clone();
        let dconn = conn.clone();
        tokio::spawn(async move { router.drive_mesh_connection(dconn, true).await });
    }
    announce_network_handles(&ctx.peers, &conn, ip).await;
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
        ephemeral_ttl_secs: None,
    })
}

/// Build the in-memory `NetworkState` cell for a joined member from the admitted
/// roster + blob-derived firewall/keys, refresh its snapshot, and seed the local
/// blob store with those bytes.
async fn build_member_state(
    members: &[crate::membership::Member],
    approved: Vec<ApprovedEntry>,
    net_pubkey: EndpointId,
    network_name: &str,
    suggested_firewall: SuggestedFirewall,
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    blob_store: &FsStore,
) -> SharedNetworkState {
    let mut ns = NetworkState {
        members: MemberList::from_members(members.to_vec()),
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
        // A joining member starts with an empty nullifier set and adopts the
        // coordinator's from the signed blob on its first reconverge.
        nullifiers: BTreeSet::new(),
    };
    ns.refresh_snapshot();
    if let Some(snap) = &ns.snapshot {
        let _ = blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
    }
    Arc::new(std::sync::RwLock::new(ns))
}

/// Dial every other roster member (skipping ourselves and the already-connected
/// coordinator), send each a `MeshHello` over the single mesh ALPN, and register
/// it as a peer (route + data reader + control demux). A member that's offline is
/// logged and skipped; a stream-open/send failure aborts the join.
#[allow(clippy::too_many_arguments)]
async fn connect_to_roster_peers(
    ep: &Endpoint,
    members: &[crate::membership::Member],
    network_name: &str,
    net_pubkey: EndpointId,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    skip_id: EndpointId,
    device_cert: &Option<control::DeviceCert>,
    ctx: &MeshCtx,
    router: &Arc<ProtocolRouter>,
) -> Result<()> {
    for member in members {
        if member.identity == my_identity || member.identity == skip_id {
            continue;
        }
        match transport::connect_to_peer_with_alpn(ep, member.identity, &transport::mesh_alpn())
            .await
        {
            Ok(conn) => {
                let (mut send, _recv) = conn.open_bi().await?;
                control::send_msg(
                    &mut send,
                    Some(net_pubkey),
                    &ControlMsg::MeshHello {
                        identity: my_identity,
                        ip: my_ip,
                        hostname: outgoing_hostname(network_name),
                        device_cert: device_cert.clone(),
                    },
                )
                .await?;
                register_dialed_peer(ctx, router, conn, member.identity, member.ip, network_name)
                    .await;
                tracing::info!(peer_ip = %member.ip, "connected to mesh peer");
            }
            Err(e) => {
                tracing::warn!(peer_ip = %member.ip, error = %e, "mesh peer unavailable");
            }
        }
    }
    Ok(())
}

/// Run one coordinator handshake. Both paths are member-speaks-first now (the
/// coordinator side is a passive demux that only replies to streams we open). A
/// fresh join (`initial`) opens a stream, sends a `JoinRequest` (invite secret +
/// hostname), and reads the verdict on the same stream. A reconnect/restore sends
/// a `MeshHello` to re-announce itself, then reconverges the roster from the
/// network-key-signed pkarr record (never peer-supplied membership), falling back
/// to the last persisted roster. Returns the admitted roster, or `Pending` on a
/// closed network.
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
            Some(net_pubkey),
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
        // Reconnect/restore: re-announce ourselves so the coordinator's demux
        // re-registers our route, then fetch the authoritative roster from the
        // signed pkarr record.
        let (mut send, _recv) = initial_conn
            .open_bi()
            .await
            .context("open reconnect control stream")?;
        control::send_msg(
            &mut send,
            Some(net_pubkey),
            &ControlMsg::MeshHello {
                identity: my_identity,
                ip: my_ip,
                hostname: outgoing_hostname(network_name),
                device_cert: device_cert.clone(),
            },
        )
        .await
        .context("send reconnect hello")?;
        tracing::info!(network = %network_name, "reconnected; reconverging roster from signed record");
        let (members, approved) = match resolve_signed(ep, net_pubkey).await {
            Some((signed, seeds)) => {
                match fetch_verified_blob(ep, blob_store, peers, signed, network_name, &seeds).await
                {
                    Some(data) => (data.members, data.approved),
                    None => (persisted_roster(network_name), vec![]),
                }
            }
            None => (persisted_roster(network_name), vec![]),
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
