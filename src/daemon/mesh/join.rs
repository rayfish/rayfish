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
    Joined {
        state: SharedNetworkState,
        /// Exact signed hash bound to a direct admission's coordinator key.
        direct_exact_hash: Option<blake3::Hash>,
        /// Publication provenance for that exact signed hash.
        direct_hash_published: Option<bool>,
    },
    /// Queued for live approval on a closed network; the caller should retry.
    Pending,
}

/// Outcome of one `join_network_inner` attempt. The reply is boxed because
/// `IpcMessage` is far larger than the `Pending` case, and this enum is returned
/// through the whole join/retry path.
pub(crate) enum TryJoin {
    Joined(Box<IpcMessage>),
    Pending,
}

struct DirectAdmissionRecord {
    hash: blake3::Hash,
    seeds: Vec<EndpointId>,
    timestamp: u64,
    published: bool,
}

fn verify_direct_admission(
    direct_key: Option<[u8; 32]>,
    direct_record: Option<Vec<u8>>,
    direct_record_published: bool,
    net_pubkey: EndpointId,
) -> Result<(Option<[u8; 32]>, Option<DirectAdmissionRecord>)> {
    if let Some(key) = direct_key {
        anyhow::ensure!(
            admin_grant_key_valid(key, net_pubkey),
            "direct-network key in Welcome does not match network public key"
        );
    }
    let direct_record = match (direct_key.as_ref(), direct_record) {
        (Some(_), Some(bytes)) => {
            let packet = dht::verify_network_record(&bytes, net_pubkey)
                .context("verify direct-network admission record")?;
            let (hash, seeds) = dht::decode_network_record(&packet)
                .context("decode direct-network admission record")?;
            Some(DirectAdmissionRecord {
                hash,
                seeds,
                timestamp: packet.timestamp().as_micros(),
                published: direct_record_published,
            })
        }
        (Some(_), None) => {
            anyhow::bail!("direct-network Welcome omitted its signed admission record")
        }
        (None, _) => None,
    };
    Ok((direct_key, direct_record))
}

/// Result of [`perform_join_handshake`]: the admitted roster, or a closed-network
/// queue signal the caller turns into [`JoinResult::Pending`].
enum HandshakeOutcome {
    Admitted {
        /// Complete verified blob state. Welcome may replace its roster slots,
        /// but every signed field travels together so a later promotion cannot
        /// publish a lossy projection.
        blob: Box<crate::membership::GroupBlob>,
        /// The per-network secret key, present only when we were admitted onto a
        /// `direct` (`ray connect`) network as a co-coordinator. Already verified
        /// against the network pubkey (`admin_grant_key_valid`); adopting it makes
        /// this node a key-holder so `finalize_join` registers it as a coordinator.
        direct_key: Option<[u8; 32]>,
        /// Exact signed admission record paired with `direct_key`.
        direct_record: Option<DirectAdmissionRecord>,
        /// Author timestamp of the signed record this roster came from, when it
        /// came from one. Seeds `NetworkState::last_record_timestamp` so the
        /// replay floor is set from the first roster the node adopts rather than
        /// starting open. `None` when the roster came from persisted config.
        record_ts: Option<u64>,
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
    /// Complete verified blob fetched before dialing. It is the reconnect
    /// fallback and seeds every signed field; the lossy config projection must
    /// never become live state that a later promotion could publish.
    pub(crate) group_blob: crate::membership::GroupBlob,
    /// Consent: auto-install suggested rules without a manual review queue.
    pub(crate) auto_accept_firewall: bool,
    /// Seed for per-network auto-accept of file offers from own devices
    /// (`--auto-accept-files`). Persisted config wins on reconnect/restore; this
    /// is only the first-join seed.
    pub(crate) auto_accept_files: bool,
    /// Roles this join asks for. Forwarded in the `JoinRequest` and granted only
    /// where the presented credential already permits them.
    pub(crate) requested_roles: Vec<String>,
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
    token: CancellationToken,
    // The network-owning service: the per-peer control reader calls
    // `registry.promote_to_coordinator` on itself after persisting an
    // `AdminGrant` key (was the `promote_tx` hand-off to the daemon loop).
    registry: Arc<NetworkRegistry>,
    // Guards the single-use invite ledger. Shared with the NetworkHandle so the
    // member accept handler's `InviteShare`/`InviteUsed` handling (a co-coordinator
    // learning of invites it didn't mint) is serialized with mint/redeem.
    invite_lock: Arc<AsyncMutex<()>>,
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
        ..
    } = ctx;
    let JoinParams {
        my_hostname,
        net_pubkey,
        device_cert,
        invite_secret,
        group_blob,
        auto_accept_firewall,
        auto_accept_files,
        requested_roles,
        initial,
    } = params;
    let my_identity = identity.local_identity();

    let (mut admitted_blob, direct_key, direct_record, mut record_ts) =
        match perform_join_handshake(
            &initial_conn,
            ep,
            network_name,
            &blob_store,
            &peers,
            net_pubkey,
            my_identity,
            initial,
            invite_secret,
            &my_hostname,
            &device_cert,
            &requested_roles,
            &group_blob,
        )
        .await?
        {
            HandshakeOutcome::Admitted {
                blob,
                direct_key,
                direct_record,
                record_ts,
            } => (
                *blob,
                direct_key.map(SecretKey::from),
                direct_record,
                record_ts,
            ),
            HandshakeOutcome::Pending => return Ok(JoinResult::Pending),
        };

    // A direct join adopts coordinator authority. Welcome binds the key to the
    // exact network-key-signed admission record, so fetch that generation rather
    // than racing a second DHT resolve that could return either its predecessor
    // or a later publication.
    let (exact_group_hash, exact_hash_published) = if let Some(record) = direct_record {
        anyhow::ensure!(
            direct_key.is_some(),
            "direct admission record arrived without a coordinator key"
        );
        let data = fetch_verified_blob(
            ep,
            &blob_store,
            &peers,
            record.hash,
            network_name,
            &record.seeds,
        )
        .await
        .context("fetch admitted direct-network roster")?;
        anyhow::ensure!(
            data.members
                .iter()
                .any(|member| member.identity == my_identity && member.is_coordinator),
            "signed direct-network roster does not contain this node's coordinator admission"
        );
        admitted_blob = data;
        record_ts = Some(record.timestamp);
        (Some(record.hash), Some(record.published))
    } else {
        anyhow::ensure!(
            direct_key.is_none(),
            "direct-network coordinator key arrived without its exact signed admission record"
        );
        (None, None)
    };
    let crate::membership::GroupBlob {
        members,
        approved,
        suggested_firewall,
        name: group_name,
        reusable_keys,
        nullifiers,
    } = admitted_blob;

    persist_join_config(
        network_name,
        &members,
        &approved,
        my_identity,
        net_pubkey,
        &my_hostname,
        auto_accept_firewall,
        auto_accept_files,
        initial,
    )?;

    let remote_id = initial_conn.remote_id();

    let live_state = build_member_state(
        &members,
        approved,
        net_pubkey,
        network_name,
        group_name,
        suggested_firewall,
        reusable_keys,
        nullifiers,
        &blob_store,
        direct_key.as_ref(),
        record_ts,
        exact_group_hash,
    )
    .await;

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
        network_name,
    )
    .await;
    connect_to_roster_peers(
        ep,
        &members,
        network_name,
        net_pubkey,
        my_identity,
        remote_id,
        &device_cert,
        &worker_ctx,
        &protocol_router,
    )
    .await?;

    Ok(JoinResult::Joined {
        state: live_state,
        direct_exact_hash: exact_group_hash,
        direct_hash_published: exact_hash_published,
    })
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
    network_name: &str,
) {
    let conn_changed = ctx.register_peer_conn(&conn, peer_id, network_name);
    if conn_changed {
        let router = router.clone();
        let dconn = conn.clone();
        tokio::spawn(async move { router.drive_mesh_connection(dconn, true).await });
    }
    announce_network_handles(&ctx.peers, &conn, derive_ipv6(&peer_id)).await;
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
    net_pubkey: EndpointId,
    my_hostname: &Option<String>,
    auto_accept_firewall: bool,
    auto_accept_files: bool,
    initial: bool,
) -> Result<()> {
    let persisted_hostname = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone())
        .or(my_hostname.clone());
    // Reconnects replace only data learned from the join. Node-local policy is
    // updated against the latest saved config so an unrelated concurrent write
    // cannot be lost; a fresh join inserts these defaults atomically.
    let member_entries = to_member_entries(members.iter());
    let approved_entries = to_approved_entries(approved.iter());
    let initial_config = config::NetworkConfig {
        name: network_name.to_string(),
        group_mode: GroupMode::Restricted,
        my_hostname: persisted_hostname.clone(),
        members: member_entries.clone(),
        approved: approved_entries.clone(),
        network_secret_key: None,
        network_public_key: Some(net_pubkey),
        auto_accept_firewall,
        auto_accept_files,
        ..Default::default()
    };
    let update = |net: &mut config::NetworkConfig| {
        net.group_mode = GroupMode::Restricted;
        // A rename requested while the handshake was in flight is newer than
        // the roster projection we just received.
        if net.pending_hostname.is_none() {
            net.my_hostname = persisted_hostname;
        }
        net.members = member_entries;
        net.approved = approved_entries;
        if initial {
            // Coordinator authority is persisted only during finalization, in the
            // same transaction as the exact complete recovery hash it governs.
            net.network_secret_key = None;
        }
        net.network_public_key = Some(net_pubkey);
        if initial {
            net.auto_accept_firewall = auto_accept_firewall;
            net.auto_accept_files |= auto_accept_files;
        }
        Ok(())
    };
    if initial {
        config::update_network_or_insert(network_name, initial_config, update)?;
    } else {
        let updated = config::update_network(network_name, update)?;
        anyhow::ensure!(
            updated.is_some(),
            "network config was deleted while reconnecting"
        );
    }
    Ok(())
}

/// Build the in-memory `NetworkState` cell for a joined member from the admitted
/// roster + blob-derived firewall/keys, refresh its snapshot, and seed the local
/// blob store with those bytes.
#[allow(clippy::too_many_arguments)]
async fn build_member_state(
    members: &[crate::membership::Member],
    approved: Vec<ApprovedEntry>,
    net_pubkey: EndpointId,
    network_name: &str,
    group_name: Option<String>,
    suggested_firewall: SuggestedFirewall,
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    nullifiers: BTreeSet<EndpointId>,
    blob_store: &FsStore,
    // Present when we joined a `direct` network as a co-coordinator: seed the live
    // state with the network key so `finalize_join` registers us as a coordinator
    // (starts a publisher, admits future peers). `None` for a plain member.
    direct_key: Option<&SecretKey>,
    // Replay floor seeded from the record this roster came out of, if any.
    record_ts: Option<u64>,
    // Exact hash of the complete signed generation adopted by a direct joiner.
    // Its locally re-encoded snapshot may differ, so convergence tracks this.
    exact_group_hash: Option<blake3::Hash>,
) -> SharedNetworkState {
    let mut ns = NetworkState {
        members: MemberList::from_members(members.to_vec()),
        approved: ApprovedList::from_entries(approved),
        snapshot: None,
        snapshot_commit: Arc::new(AsyncMutex::new(())),
        converged_hash: None,
        unconfirmed_durable_hash: None,
        network_secret_key: direct_key.cloned(),
        network_public_key: net_pubkey,
        network_name: Some(network_name.to_string()),
        group_name,
        mode: GroupMode::Restricted,
        suggested_firewall,
        reusable_keys,
        pending_suggestions: Vec::new(),
        pending: HashMap::new(),
        nullifiers,
        last_record_timestamp: record_ts,
    };
    ns.refresh_snapshot();
    if let Some(hash) = exact_group_hash {
        ns.converged_hash = Some(hash);
    }
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
                        hostname: outgoing_hostname(network_name),
                        device_cert: device_cert.clone(),
                    },
                )
                .await?;
                register_dialed_peer(ctx, router, conn, member.identity, network_name).await;
                tracing::info!(peer_ip = %derive_ipv6(&member.identity), "connected to mesh peer");
            }
            Err(e) => {
                tracing::warn!(peer_ip = %derive_ipv6(&member.identity), error = %e, "mesh peer unavailable");
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
/// network-key-signed pkarr record, falling back to the already-verified complete
/// blob supplied by the restore path. Returns the admitted roster, or `Pending`
/// on a closed network.
#[allow(clippy::too_many_arguments)]
async fn perform_join_handshake(
    initial_conn: &Connection,
    ep: &Endpoint,
    network_name: &str,
    blob_store: &FsStore,
    peers: &PeerTable,
    net_pubkey: EndpointId,
    my_identity: EndpointId,
    initial: bool,
    invite_secret: Option<Vec<u8>>,
    my_hostname: &Option<String>,
    device_cert: &Option<control::DeviceCert>,
    requested_roles: &[String],
    fallback_blob: &crate::membership::GroupBlob,
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
                roles: requested_roles.iter().cloned().collect(),
            },
        )
        .await
        .context("send join request")?;
        let msg = tokio::time::timeout(Duration::from_secs(30), control::recv_msg(&mut recv))
            .await
            .context("timeout awaiting join response")??;
        match msg {
            ControlMsg::Welcome {
                members,
                approved,
                direct_key,
                direct_record,
                direct_record_published,
            } => {
                tracing::info!(network = %network_name, "welcomed to network");
                let (direct_key, direct_record) = verify_direct_admission(
                    direct_key,
                    direct_record,
                    direct_record_published,
                    net_pubkey,
                )?;
                let mut blob = fallback_blob.clone();
                blob.members = members;
                blob.approved = approved;
                Ok(HandshakeOutcome::Admitted {
                    blob: Box::new(blob),
                    direct_key,
                    direct_record,
                    // A fresh join takes its roster from the coordinator's
                    // Welcome, not from a record, so there is no floor to set.
                    record_ts: None,
                })
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
        let (mut send, mut recv) = initial_conn
            .open_bi()
            .await
            .context("open reconnect control stream")?;
        control::send_msg(
            &mut send,
            Some(net_pubkey),
            &ControlMsg::MeshHello {
                identity: my_identity,
                hostname: outgoing_hostname(network_name),
                device_cert: device_cert.clone(),
            },
        )
        .await
        .context("send reconnect hello")?;
        let response = tokio::time::timeout(Duration::from_secs(30), control::recv_msg(&mut recv))
            .await
            .context("timeout awaiting reconnect response")??;
        let (welcome_members, welcome_approved, direct_key, direct_record) = match response {
            ControlMsg::Welcome {
                members,
                approved,
                direct_key,
                direct_record,
                direct_record_published,
            } => {
                let (direct_key, direct_record) = verify_direct_admission(
                    direct_key,
                    direct_record,
                    direct_record_published,
                    net_pubkey,
                )?;
                (members, approved, direct_key, direct_record)
            }
            other => anyhow::bail!("expected Welcome after reconnect hello, got {other:?}"),
        };
        if direct_key.is_some() {
            let mut blob = fallback_blob.clone();
            blob.members = welcome_members;
            blob.approved = welcome_approved;
            return Ok(HandshakeOutcome::Admitted {
                blob: Box::new(blob),
                direct_key,
                direct_record,
                record_ts: None,
            });
        }
        anyhow::ensure!(
            !fallback_blob
                .members
                .iter()
                .any(|member| member.identity == my_identity && member.is_coordinator),
            "coordinator authority is temporarily unavailable; retrying exact key grant"
        );
        tracing::info!(network = %network_name, "reconnected; reconverging roster from signed record");
        // Seed the replay floor from the record this roster came out of. If a
        // second resolve/fetch fails, retain the complete blob already verified
        // by `join_network_inner`; the config roster is a lossy display cache and
        // must never become publishable after a later promotion.
        let (blob, record_ts) = match resolve_signed(ep, net_pubkey).await {
            Some((signed, seeds, ts)) => {
                match fetch_verified_blob(ep, blob_store, peers, signed, network_name, &seeds).await
                {
                    Some(data) => (data, Some(ts)),
                    None => (fallback_blob.clone(), None),
                }
            }
            None => (fallback_blob.clone(), None),
        };
        // Reconnect/restore: a co-coordinator's key is restored from config on the
        // cold path, never re-granted here.
        Ok(HandshakeOutcome::Admitted {
            blob: Box::new(blob),
            direct_key: None,
            direct_record: None,
            record_ts,
        })
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
                    // Only outstanding deliveries want the periodic wake: a
                    // pending rename, or an exit offer the signed roster does
                    // not reflect yet (its delivery missed every coordinator).
                    // Otherwise idle until the next real trigger.
                    if !has_pending_hostname(&network_name)
                        && !ctx_w.registry.exit_offer_out_of_sync(&network_name)
                    {
                        continue;
                    }
                    tracing::debug!(
                        network = %network_name,
                        "backstop tick: pending rename or exit offer outstanding, reconverging to retry delivery"
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
                &device_cert_w,
            )
            .await;
        }
    });
}

#[cfg(test)]
mod persist_config_tests {
    use super::*;
    use crate::config::{self, CONFIG_ENV_LOCK, MemberEntry, NetworkConfig};
    use crate::membership::Member;
    use iroh::SecretKey;
    use std::collections::BTreeMap;

    fn id(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        SecretKey::from(b).public()
    }

    fn member(seed: u8, coordinator: bool) -> Member {
        Member {
            identity: id(seed),
            is_coordinator: coordinator,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
        }
    }

    #[test]
    fn direct_grant_is_bound_to_its_signed_exact_hash() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"exact admitted group");
        let packet = dht::encode_network_record(&key, &hash, &[id(3)])
            .unwrap()
            .as_bytes()
            .to_vec();

        let (granted, record) =
            verify_direct_admission(Some(key.to_bytes()), Some(packet), true, key.public())
                .unwrap();
        let record = record.unwrap();

        assert_eq!(granted, Some(key.to_bytes()));
        assert_eq!(record.hash, hash);
        assert_eq!(record.seeds, vec![id(3)]);
        assert!(record.published);
    }

    #[test]
    fn direct_grant_without_a_signed_record_is_rejected() {
        let key = SecretKey::generate();
        assert!(verify_direct_admission(Some(key.to_bytes()), None, false, key.public()).is_err());
    }

    /// Regression: a member daemon reconnecting must not erase the node-local
    /// exit-node policy. `persist_join_config` rewrites the network config from
    /// the freshly fetched blob roster, which does not carry `exit_allow` /
    /// `exit_node_use`; before the fix it wrote empty values, so every restart
    /// silently withdrew the gateway's offer and dropped the client's selection.
    #[test]
    fn reconnect_preserves_local_exit_node_policy() {
        let _lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", tmp.path()) };

        let net_pubkey = id(1);
        let me = id(2);

        // Pre-existing config: this node offers an exit (`*`) and routes its own
        // traffic through a chosen peer. This is the state a restart must keep.
        let exit_peer = id(3).to_string();
        let admin_key = SecretKey::generate();
        let cached_hash = blake3::hash(b"complete signed roster");
        config::save_network(&NetworkConfig {
            name: "homelab".to_string(),
            group_mode: GroupMode::Restricted,
            my_hostname: Some("new-name".to_string()),
            pending_hostname: Some("new-name".to_string()),
            members: vec![MemberEntry {
                identity: me,
                is_coordinator: false,
                hostname: Some("umbrel".to_string()),
            }],
            approved: vec![],
            network_secret_key: Some(admin_key.clone()),
            network_public_key: Some(net_pubkey),
            last_group_hash: Some(cached_hash),
            last_group_hash_published: true,
            transport: None,
            auto_accept_firewall: true,
            auto_accept_files: true,
            admins: vec![],
            direct: false,
            direct_peer: None,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec!["*".to_string()],
            exit_node_use: Some(exit_peer.clone()),
        })
        .unwrap();

        // Reconnect: re-persist from a blob roster that carries no exit policy.
        let roster = vec![member(2, false), member(4, true)];
        persist_join_config(
            "homelab",
            &roster,
            &[],
            me,
            net_pubkey,
            &Some("umbrel".to_string()),
            false,
            false,
            false,
        )
        .unwrap();

        let after = config::load_network("homelab").unwrap().unwrap();
        assert_eq!(
            after.exit_allow,
            vec!["*".to_string()],
            "exit allow-list must survive a reconnect"
        );
        assert_eq!(
            after.exit_node_use,
            Some(exit_peer),
            "selected exit peer must survive a reconnect"
        );
        assert_eq!(
            after.last_group_hash,
            Some(cached_hash),
            "the last complete roster hash must survive a partial reconnect write"
        );
        assert!(after.auto_accept_firewall);
        assert!(after.auto_accept_files);
        assert_eq!(
            after.network_secret_key.as_ref().map(SecretKey::to_bytes),
            Some(admin_key.to_bytes()),
            "a reconnect without a direct key must not demote a saved co-coordinator"
        );
        assert_eq!(after.my_hostname.as_deref(), Some("new-name"));
        assert_eq!(after.pending_hostname.as_deref(), Some("new-name"));

        persist_join_config(
            "homelab",
            &[member(2, false), member(4, true)],
            &[],
            me,
            net_pubkey,
            &Some("umbrel".to_string()),
            false,
            false,
            true,
        )
        .unwrap();
        let after_fresh_join = config::load_network("homelab").unwrap().unwrap();
        assert!(
            !after_fresh_join.auto_accept_firewall,
            "a fresh join's firewall-consent flag must replace a saved value"
        );
        assert!(
            after_fresh_join.auto_accept_files,
            "a fresh join must not turn off an existing file-auto-accept opt-in"
        );
        assert!(
            after_fresh_join.network_secret_key.is_none(),
            "a fresh member join must clear a stale coordinator key"
        );

        unsafe {
            match prev {
                Some(v) => std::env::set_var("RAYFISH_CONFIG_DIR", v),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }

    #[test]
    fn reconnect_does_not_recreate_a_deleted_network_config() {
        let _lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", tmp.path()) };

        let net_pubkey = id(1);
        let me = id(2);
        let result = persist_join_config(
            "homelab",
            &[member(2, false), member(4, true)],
            &[],
            me,
            net_pubkey,
            &Some("umbrel".to_string()),
            false,
            false,
            false,
        );

        assert!(result.is_err());
        assert!(config::load_network("homelab").unwrap().is_none());

        unsafe {
            match prev {
                Some(v) => std::env::set_var("RAYFISH_CONFIG_DIR", v),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}
