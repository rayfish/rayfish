//! Coordinator-side background loops: the per-member control reader (renames,
//! invite gossip, ping/pong), the dead-peer cleanup loop, and the invite-gossip
//! send helpers.

use super::super::*;


/// Extra context a coordinator needs to prune the canonical member list when a
/// peer leaves deliberately (`ray leave`). Members pass `None` and only ever
/// drop the connection from the [`PeerTable`].
pub(crate) struct CoordinatorCleanup {
    pub(crate) state: SharedNetworkState,
    pub(crate) blob_store: FsStore,
    pub(crate) dht_notify: Option<Arc<tokio::sync::Notify>>,
    pub(crate) hostname_table: dns::HostnameTable,
    pub(crate) reverse_table: dns::ReverseLookupTable,
    pub(crate) device_user_map: peers::DeviceUserMap,
    pub(crate) network_name: String,
}


pub(crate) fn spawn_peer_cleanup(
    mut disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
    peers: PeerTable,
    token: CancellationToken,
    coordinator: Option<CoordinatorCleanup>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                event = disconnect_rx.recv() => {
                    match event {
                        Some(ev) => {
                            tracing::info!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, network = %ev.network, intentional = ev.intentional, "removing dead peer");
                            // Drop only this network's route; a multi-homed peer
                            // stays reachable via its other networks.
                            peers.remove_peer_from_network(&ev.ip, &ev.ipv6, &ev.network);

                            // A deliberate `ray leave` (graceful close with the
                            // leave code) prunes the member from the roster and
                            // propagates the change; a transient drop only clears
                            // the green dot above. Only the coordinator is
                            // authoritative, so members pass `coordinator = None`.
                            if ev.intentional && let Some(c) = &coordinator {
                                let member_id = c.device_user_map.resolve(&ev.endpoint_id);
                                c.state.write().unwrap().members.remove(&member_id);
                                dns::remove_hostname_by_ip(
                                    &c.hostname_table,
                                    &c.reverse_table,
                                    &c.network_name,
                                    ev.ip,
                                )
                                .await;
                                update_snapshot_and_publish(&c.state, &c.blob_store, &c.dht_notify).await;
                                broadcast_member_sync(&peers, None).await;
                                tracing::info!(peer = %member_id.fmt_short(), "pruned member after leave");
                            }
                        }
                        None => return,
                    }
                }
            }
        }
    })
}


/// Coordinator-side per-member control reader. Continuously accepts control
/// streams from one member and processes `MeshHello`s as live create-or-update
/// signals — the only path by which a member's hostname (or device cert) reaches
/// the coordinator after the initial handshake. On a hostname that differs from
/// the stored one, the coordinator resolves collisions authoritatively, updates
/// the roster + DNS, republishes the group blob, and broadcasts `MemberSync` so
/// every peer reflects the change immediately. Runs until the network token is
/// cancelled or the connection drops.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_coordinator_control_reader(
    conn: Connection,
    remote_id: EndpointId,
    peer_ip: Ipv4Addr,
    network_name: String,
    state: SharedNetworkState,
    ctx: MeshCtx,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    token: CancellationToken,
    // Serializes single-use invite ledger access for the invite-gossip arms.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    // Fires the waiting `ray ping` handler when a matching `Pong` arrives.
    pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
) {
    let MeshCtx {
        peers,
        blob_store,
        hostname_table,
        reverse_table,
        device_user_map,
        ..
    } = ctx;
    tokio::spawn(async move {
        let mut gate = crate::ratelimit::ControlGate::new();
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => return,
                r = conn.accept_bi() => r,
            };
            let mut recv = match accepted {
                Ok((_send, recv)) => recv,
                Err(_) => return, // connection closed
            };
            let msg = match control::recv_msg(&mut recv).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Throttle inbound control messages per connection: drop over-budget
            // ones, and drop the peer entirely if it sustains a flood.
            match gate.check() {
                crate::ratelimit::Verdict::Allow => {}
                crate::ratelimit::Verdict::Drop => continue,
                crate::ratelimit::Verdict::Close => {
                    tracing::warn!(peer = %remote_id.fmt_short(), "control-plane flood; closing connection");
                    conn.close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                    return;
                }
            }
            // Invite gossip from another coordinator: a co-coordinator that minted
            // or redeemed an invite tells us so our ledger stays in sync. Honor it
            // only from a coordinator peer in our verified roster.
            match msg {
                ControlMsg::InviteShare {
                    id,
                    secret_hash,
                    expires,
                } => {
                    if !sender_is_coordinator(&state, remote_id) {
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
                    continue;
                }
                ControlMsg::InviteUsed { secret_hash } => {
                    if !sender_is_coordinator(&state, remote_id) {
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
                    continue;
                }
                ControlMsg::Ping { nonce } => {
                    respond_pong(&conn, nonce).await;
                    continue;
                }
                ControlMsg::Pong { nonce } => {
                    if let Some((_, tx)) = pending_pongs.remove(&nonce) {
                        let _ = tx.send(());
                    }
                    continue;
                }
                _ => {}
            }
            let ControlMsg::MeshHello {
                hostname,
                device_cert,
                ..
            } = msg
            else {
                continue;
            };

            // Verify and store device cert if present.
            if let Some(ref cert) = device_cert
                && cert.verify()
                && cert.device_key == remote_id
            {
                {
                    let mut s = state.write().unwrap();
                    if let Some(m) = s.members.get_mut(&remote_id) {
                        m.user_identity = Some(cert.user_identity);
                        m.device_cert = Some(cert.clone());
                    }
                }
                device_user_map.insert(remote_id, cert.user_identity);
            }

            let Some(desired) = hostname else { continue };
            tracing::info!(
                network = %network_name,
                peer = %remote_id.fmt_short(),
                desired = %desired,
                "coordinator received MeshHello hostname"
            );

            // Resolve collisions authoritatively against the rest of the roster,
            // then detect whether this is a genuine change for this member.
            let (final_hostname, changed) = {
                let s = state.read().unwrap();
                let taken: Vec<String> = s
                    .members
                    .all()
                    .iter()
                    .filter(|m| m.identity != remote_id)
                    .filter_map(|m| m.hostname.clone())
                    .collect();
                let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
                let final_hostname = crate::hostname::resolve_collision(&desired, &taken_refs);
                let old = s
                    .members
                    .all()
                    .iter()
                    .find(|m| m.identity == remote_id)
                    .and_then(|m| m.hostname.clone());
                let changed = old.as_deref() != Some(final_hostname.as_str());
                (final_hostname, changed)
            };

            if changed {
                let mut s = state.write().unwrap();
                if let Some(m) = s.members.get_mut(&remote_id) {
                    m.hostname = Some(final_hostname.clone());
                }
            }

            // Re-assert this peer's DNS entry (idempotent; clears any stale name
            // sharing its IP before inserting the current one).
            dns::remove_hostname_by_ip(&hostname_table, &reverse_table, &network_name, peer_ip)
                .await;
            let ipv6 = derive_ipv6(&remote_id);
            dns::update_hostname(
                &hostname_table,
                &reverse_table,
                &network_name,
                &final_hostname,
                peer_ip,
                ipv6,
            )
            .await;

            if changed {
                tracing::info!(peer = %remote_id.fmt_short(), network = %network_name, hostname = %final_hostname, "peer hostname changed; republishing blob + broadcasting MemberSync");
                update_snapshot_and_publish(&state, &blob_store, &dht_notify).await;
                broadcast_member_sync(&peers, None).await;
            } else {
                tracing::debug!(peer = %remote_id.fmt_short(), network = %network_name, hostname = %final_hostname, "peer hostname unchanged; no republish (idempotent MeshHello)");
            }
        }
    });
}


/// Send `msg` to each coordinator peer (per [`gossip_targets`]) that has a live
/// connection on `network`. Best-effort: a target without a live connection is
/// skipped (it will reconverge invite state from a future share/redeem or, for
/// reusable keys, the signed blob). Never carries the raw secret — only its hash.
pub(crate) async fn gossip_to_coordinators(
    peers: &PeerTable,
    network: &str,
    members: &[Member],
    me: EndpointId,
    msg: &ControlMsg,
) {
    let targets = gossip_targets(members, me);
    if targets.is_empty() {
        return;
    }
    for (eid, _ip, conn) in peers.peers_for_network_with_conn(network) {
        if !targets.contains(&eid) {
            continue;
        }
        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(&mut send, msg).await;
        }
    }
}


/// Whether `peer` is a coordinator in our verified roster. Invite-gossip arms
/// (`InviteShare`/`InviteUsed`) act only on messages from a coordinator peer, so
/// a non-coordinator member can't inject or burn invite state.
pub(crate) fn sender_is_coordinator(state: &SharedNetworkState, peer: EndpointId) -> bool {
    state
        .read()
        .unwrap()
        .members
        .all()
        .iter()
        .any(|m| m.identity == peer && m.is_coordinator)
}
