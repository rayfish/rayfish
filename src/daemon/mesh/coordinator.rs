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
                            // Drop only this network's route, and only if the
                            // stored connection is still the one that died. A
                            // peer that was killed and re-dialed with the same
                            // identity already has a fresh connection registered;
                            // the stale connection's delayed disconnect must not
                            // evict it (see DisconnectEvent::conn_stable_id).
                            let removed = match ev.conn_stable_id {
                                Some(id) => peers.remove_peer_from_network_if(&ev.ip, &ev.ipv6, &ev.network, id),
                                None => {
                                    peers.remove_peer_from_network(&ev.ip, &ev.ipv6, &ev.network);
                                    true
                                }
                            };
                            if !removed {
                                tracing::debug!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, network = %ev.network, "ignoring stale disconnect; peer already reconnected");
                                continue;
                            }
                            tracing::info!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, network = %ev.network, intentional = ev.intentional, "removing dead peer");

                            // A deliberate `ray leave` (graceful close) prunes the
                            // member from the roster; any other drop stamps the
                            // member's `last_seen` so the ephemeral pruner can age
                            // it out. Both republish the signed blob and broadcast
                            // a MemberSync so co-coordinators converge. Only the
                            // coordinator is authoritative, so members pass
                            // `coordinator = None` and do neither.
                            if let Some(c) = &coordinator {
                                let member_id = c.device_user_map.resolve(&ev.endpoint_id);
                                let mut changed = false;
                                {
                                    let mut st = c.state.write().unwrap();
                                    if ev.intentional {
                                        st.members.remove(&member_id);
                                        changed = true;
                                    } else if let Some(m) = st.members.get_mut(&member_id) {
                                        m.last_seen = Some(crate::membership::now_secs());
                                        changed = true;
                                    }
                                }
                                if ev.intentional {
                                    dns::remove_hostname_by_ip(
                                        &c.hostname_table,
                                        &c.reverse_table,
                                        &c.network_name,
                                        ev.ip,
                                    )
                                    .await;
                                }
                                if changed {
                                    update_snapshot_and_publish(&c.state, &c.blob_store, &c.dht_notify).await;
                                    broadcast_member_sync(&peers, None).await;
                                    if ev.intentional {
                                        tracing::info!(peer = %member_id.fmt_short(), "pruned member after leave");
                                    } else {
                                        tracing::debug!(peer = %member_id.fmt_short(), network = %c.network_name, "stamped last_seen on member disconnect");
                                    }
                                }
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
        identity,
        peers,
        blob_store,
        hostname_table,
        reverse_table,
        device_user_map,
        revocation,
        ..
    } = ctx;
    let my_identity = identity.local_identity();
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
                ControlMsg::Unpaired => {
                    // The peer claims to be our primary unpairing us. Verified
                    // inside against our own cert's signer, so a stranger is a
                    // no-op.
                    wipe_cert_if_unpaired_by(remote_id);
                    continue;
                }
                ControlMsg::CertRefresh { cert } => {
                    // Our primary rotated and re-issued us. Verified inside
                    // against our own cert (signer + device key + generation).
                    store_refreshed_cert(&cert);
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

            // Verify and store device cert if present, unless it is below the
            // issuing user's generation floor (`ray unpair`) — a revoked/stale
            // cert is not recorded as a paired device, so it stops resolving to
            // the user's identity. (A `Reissue` verdict — our own stale device —
            // is treated as fine to record; the admission path pushes its refresh.)
            let cert_ok = device_cert.as_ref().is_some_and(|cert| {
                if !cert.verify() || cert.device_key != remote_id {
                    return false;
                }
                let (issuing, my_gen, revoked) = cert_authority(my_identity);
                revocation::cert_decision(cert, issuing, my_gen, &|d| revoked.contains(d), &revocation)
                    != revocation::CertDecision::Reject
            });
            if let Some(ref cert) = device_cert
                && cert_ok
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

/// Pure prune decision for one member under the ephemeral policy. Never prunes
/// a coordinator, self, a currently-connected peer, or one with no `last_seen`.
/// Otherwise prunes once the offline window exceeds the TTL. `saturating_sub`
/// guards a clock that moved backwards.
pub(crate) fn should_prune(
    m: &Member,
    connected: bool,
    is_self: bool,
    ttl_secs: u64,
    now: u64,
) -> bool {
    if m.is_coordinator || is_self || connected {
        return false;
    }
    match m.last_seen {
        None => false,
        Some(t) => now.saturating_sub(t) > ttl_secs,
    }
}
/// Interval between stale-member sweeps. Well under the 1-hour TTL floor so a
/// member that crosses the threshold is evicted within one interval.
const PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Remove one identity from the roster + approved list and drop its DNS
/// entries. Does NOT publish or broadcast; the caller batches that via
/// [`finalize_removal`] so several removals collapse into one publish. Shared by
/// the manual kick handler and the ephemeral pruner.
pub(crate) async fn remove_member_roster_only(
    ctx: &MeshCtx,
    network: &str,
    state: &SharedNetworkState,
    member_id: EndpointId,
    member_ip: Ipv4Addr,
) {
    {
        let mut s = state.write().unwrap();
        s.members.remove(&member_id);
        s.approved.remove(&member_id);
    }
    dns::remove_hostname_by_ip(&ctx.hostname_table, &ctx.reverse_table, network, member_ip).await;
}

/// Republish the signed blob, broadcast a payload-free `MemberSync`, and sever
/// our own link(s) to every `victim` with `KICK_CODE`. Call once after one or
/// more [`remove_member_roster_only`] edits. Other members drop the victims when
/// they reconverge from the freshly published record (`prune_departed_peers`).
pub(crate) async fn finalize_removal(
    ctx: &MeshCtx,
    network: &str,
    state: &SharedNetworkState,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
    victims: &[EndpointId],
) {
    update_snapshot_and_publish(state, &ctx.blob_store, dht_notify).await;
    broadcast_member_sync(&ctx.peers, None).await;
    for (pid, ip, conn) in ctx.peers.peers_for_network_with_conn(network) {
        let resolved = ctx.device_user_map.resolve(&pid);
        if victims.iter().any(|v| *v == pid || *v == resolved) {
            conn.close(VarInt::from_u32(forward::KICK_CODE), b"kicked from network");
            ctx.peers
                .remove_peer_from_network(&ip, &derive_ipv6(&pid), network);
        }
    }
}

/// Coordinator-only: periodically evict members that have been offline longer
/// than the network's `ephemeral_ttl_secs` (off by default). Ticks every
/// [`PRUNE_INTERVAL`] plus once shortly after spawn, reading the TTL fresh from
/// config each tick so `ray ephemeral` takes effect without a restart. Reuses
/// the exact kick teardown, batched into one publish per sweep.
pub(crate) fn spawn_stale_member_pruner(
    ctx: MeshCtx,
    network: String,
    state: SharedNetworkState,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut first = true;
        loop {
            let delay = if first {
                std::time::Duration::from_secs(60)
            } else {
                PRUNE_INTERVAL
            };
            first = false;
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(delay) => {}
            }
            let ttl = match config::load_network(&network) {
                Ok(Some(c)) => c.ephemeral_ttl_secs,
                _ => None,
            };
            let Some(ttl) = ttl else { continue };
            let now = crate::membership::now_secs();
            let me = ctx.identity.local_identity();
            let connected: std::collections::HashSet<EndpointId> = ctx
                .peers
                .peers_for_network_with_conn(&network)
                .into_iter()
                .map(|(eid, _, _)| eid)
                .collect();
            let victims: Vec<(EndpointId, Ipv4Addr)> = {
                let s = state.read().unwrap();
                s.members
                    .all()
                    .into_iter()
                    .filter(|m| {
                        should_prune(m, connected.contains(&m.identity), m.identity == me, ttl, now)
                    })
                    .map(|m| (m.identity, m.ip))
                    .collect()
            };
            if victims.is_empty() {
                continue;
            }
            for (id, ip) in &victims {
                remove_member_roster_only(&ctx, &network, &state, *id, *ip).await;
                tracing::info!(peer = %id.fmt_short(), network = %network, ttl_secs = ttl, "auto-kicked stale member (ephemeral TTL)");
            }
            let ids: Vec<EndpointId> = victims.iter().map(|(id, _)| *id).collect();
            finalize_removal(&ctx, &network, &state, &dht_notify, &ids).await;
        }
    })
}

#[cfg(test)]
mod prune_tests {
    use super::*;

    fn mk(seed: u8, is_coordinator: bool, last_seen: Option<u64>) -> Member {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        let id = SecretKey::from(key_bytes).public();
        Member {
            identity: id,
            ip: std::net::Ipv4Addr::new(100, 64, 0, 2),
            is_coordinator,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
            last_seen,
        }
    }

    const TTL: u64 = 3600;
    const NOW: u64 = 1_000_000;

    #[test]
    fn never_prunes_coordinator_self_or_connected() {
        // coordinator, even if long offline
        assert!(!should_prune(&mk(1, true, Some(0)), false, false, TTL, NOW));
        // self
        assert!(!should_prune(&mk(2, false, Some(0)), false, true, TTL, NOW));
        // currently connected
        assert!(!should_prune(&mk(3, false, Some(0)), true, false, TTL, NOW));
    }

    #[test]
    fn never_prunes_when_last_seen_none() {
        assert!(!should_prune(&mk(4, false, None), false, false, TTL, NOW));
    }

    #[test]
    fn prunes_only_past_the_ttl_strictly() {
        // exactly at TTL boundary -> not yet (strict `>`)
        assert!(!should_prune(&mk(5, false, Some(NOW - TTL)), false, false, TTL, NOW));
        // one second past the TTL -> prune
        assert!(should_prune(&mk(6, false, Some(NOW - TTL - 1)), false, false, TTL, NOW));
    }

    #[test]
    fn backwards_clock_does_not_prune() {
        // last_seen in the "future" (clock went backwards) -> saturating_sub = 0
        assert!(!should_prune(&mk(7, false, Some(NOW + 100)), false, false, TTL, NOW));
    }
}
