//! The daemon-wide connection supervisor (dead-peer prune + reconnect) and the
//! invite-gossip send helper. Under one mesh connection per identity, a dropped
//! connection tears the peer down across every shared network at once, so
//! teardown/reconnect is node-wide rather than per-network. The per-member rename
//! reader and coordinator/member accept handlers now live in the per-connection
//! demux (`ProtocolRouter::drive_mesh_connection` → `AcceptHandler::handle_frame`).

use std::net::IpAddr;

use super::super::*;

impl NetworkRegistry {
    /// Single daemon-wide loop consuming every [`MeshConnection`]'s disconnect
    /// report. For each dropped identity it removes the peer from the table, prunes
    /// it from every network we coordinate on a deliberate leave, and otherwise
    /// reconnects it across all its shared networks.
    pub(crate) async fn run_connection_supervisor(
        self: Arc<Self>,
        mut disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
        token: CancellationToken,
    ) {
        loop {
            let ev = tokio::select! {
                _ = token.cancelled() => return,
                ev = disconnect_rx.recv() => match ev {
                    Some(ev) => ev,
                    None => return,
                },
            };
            self.clone().handle_disconnect(ev).await;
        }
    }

    async fn handle_disconnect(self: Arc<Self>, ev: forward::DisconnectEvent) {
        // ABA guard: if the stored connection is newer than the one that died,
        // the peer already re-dialed. Ignore the stale event rather than tearing
        // down the live link (see DisconnectEvent::conn_stable_id).
        if let Some(id) = ev.conn_stable_id
            && !self.peers.conn_is_current(&ev.ip, id)
        {
            tracing::debug!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, "ignoring stale disconnect; peer already reconnected");
            return;
        }

        // The networks this peer was reachable on, captured before removal.
        let nets: Vec<SmolStr> = self
            .peers
            .identity_and_networks(IpAddr::V4(ev.ip))
            .map(|(_, nets)| nets)
            .unwrap_or_default();

        // One connection carried every network, so the drop removes the peer
        // everywhere at once.
        self.peers.remove(&ev.ip, &ev.ipv6);
        tracing::info!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, reason = ?ev.reason, "peer connection dropped");

        if ev.reason.prunes_member() {
            // Deliberate `ray leave` (graceful close with the leave code): prune
            // the member from every network we coordinate. Nobody reconnects it.
            for net in &nets {
                self.prune_member_on_leave(net, &ev).await;
            }
            return;
        }

        if matches!(ev.reason, forward::CloseReason::Idle) {
            // The peer let an idle connection go (on-demand teardown). Never
            // reconnect on any node; the link comes back lazily on the next packet.
            return;
        }

        if matches!(ev.reason, forward::CloseReason::Kicked) {
            // A kick-coded close is transport teardown, not authority: we never
            // evict the peer or leave a network on the close code. Membership is the
            // signed roster's call, and the authoritative kick is the in-band,
            // network-scoped `KickedFromNetwork` message, which drives a
            // signed-record-confirmed leave. Here we only decide whether to
            // reconnect: on a network we coordinate the kick is bogus (a member
            // cannot evict the coordinator, e.g. a flapping link's mutual prune), so
            // reconnect to heal; on one where we are a plain member we may have been
            // kicked, so we don't reconnect (avoid churning the coordinator's pending
            // queue) and let the in-band message plus reconverge settle it.
            let reconnect_nets: Vec<SmolStr> = nets
                .iter()
                .filter(|net| {
                    self.networks
                        .get(net.as_str())
                        .is_some_and(|h| h.role.is_coordinator())
                })
                .cloned()
                .collect();
            // A non-idle drop reconnects to heal even on on-demand nodes: we
            // eager-connect the roster, and only an explicit idle close (handled
            // above) is allowed to leave a peer disconnected. The idle timer will
            // close the healed link again if it stays quiet.
            if !reconnect_nets.is_empty() {
                self.clone()
                    .spawn_reconnect(ev.endpoint_id, ev.ip, reconnect_nets);
            }
            return;
        }

        // Transient drop: stamp `last_seen` on each network we coordinate so the
        // ephemeral pruner ages the member from when it actually went offline
        // (not its admit time), then reconnect across every shared network,
        // skipping any we just pruned this peer from (one-shot via pruned_peers).
        // Reconnect runs on every node, on-demand included: a transient drop is a
        // real link failure, not an idle teardown (which is handled above and never
        // reconnects), so we heal it and let the idle timer close it again if quiet.
        let member_id = self.device_user_map.resolve(&ev.endpoint_id);
        let now = crate::membership::now_secs();
        for net in &nets {
            if let Some(h) = self.networks.get(net.as_str())
                && h.role.is_coordinator()
                && let Some(m) = h.state.write().unwrap().members.get_mut(&member_id)
            {
                m.last_seen = Some(now);
            }
        }

        self.spawn_reconnect(ev.endpoint_id, ev.ip, nets);
    }

    /// Confirm a coordinator's `ControlMsg::KickedFromNetwork` against `network`'s
    /// signed record and leave the network (runtime teardown + local config removal,
    /// so a re-invite is needed to return) only if the record no longer lists us.
    /// Never leaves on the message alone: the network-key-signed blob is the sole
    /// authority, so a stale or spurious kick cannot evict us. Reached from the
    /// member frame handler; a coordinator's handler ignores the message, so a node
    /// can never be made to leave a network it coordinates.
    pub(crate) async fn confirm_kick_and_leave(&self, network: &str) {
        let Some(net_pubkey) = self.networks.get(network).map(|h| h.network_key) else {
            return; // no longer active locally; nothing to settle
        };
        let my_id = self.transport.endpoint.id();
        // Resolve + fetch the current signed blob and leave only on a positive
        // confirmation that it no longer lists us; on any failure (can't
        // resolve/fetch) we stay, never leaving on uncertainty.
        let removed = match resolve_signed(&self.transport.endpoint, net_pubkey).await {
            Some((signed, seeds)) => fetch_verified_blob(
                &self.transport.endpoint,
                &self.transport.blob_store,
                &self.peers,
                signed,
                network,
                &seeds,
            )
            .await
            .is_some_and(|data| {
                !data.members.iter().any(|m| m.identity == my_id)
                    && !data.approved.iter().any(|a| a.identity == my_id)
            }),
            None => false,
        };
        if removed {
            tracing::info!(network = %network, "coordinator kicked us and the signed record confirms removal; leaving network");
            self.leave_network(network).await;
        }
    }

    /// Coordinator-authoritative prune of a member that left `network`: drop it
    /// from the roster + DNS, republish the signed blob, and broadcast a
    /// `MemberSync` trigger. A no-op on a network we don't coordinate.
    async fn prune_member_on_leave(&self, network: &str, ev: &forward::DisconnectEvent) {
        let (state, net_pubkey, dht_notify) = {
            let Some(h) = self.networks.get(network) else {
                return;
            };
            if !h.role.is_coordinator() {
                return;
            }
            (h.state.clone(), h.network_key, h.dht_notify.clone())
        };
        let member_id = self.device_user_map.resolve(&ev.endpoint_id);
        state.write().unwrap().members.remove(&member_id);
        dns::remove_hostname_by_ip(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            network,
            ev.ip,
        )
        .await;
        update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
        broadcast_member_sync(&self.peers, net_pubkey, network, None).await;
        tracing::info!(peer = %member_id.fmt_short(), network, "pruned member after leave");
    }

    /// Handle a member's deliberate in-band departure from one shared network
    /// (`ControlMsg::LeaveNetwork`, `ray leave`). Drops it from this network's
    /// routing, closing the shared connection only if this was the last network the
    /// two peers had in common (so a multi-network link stays up on the rest). If we
    /// coordinate the network, also prune it from the roster + `.ray` DNS, republish
    /// the signed blob, and broadcast a `MemberSync` trigger; a plain member takes
    /// no roster action and learns of the departure from the coordinator's republish
    /// on its next reconverge. Mirrors [`prune_member_on_leave`], keyed by the
    /// connection's remote id instead of a `DisconnectEvent`.
    pub(crate) async fn handle_member_leave(&self, network: &str, peer_id: EndpointId) {
        // Capture the leaver's mesh IP before removal (needed for the DNS prune);
        // the by-id lookup is gone once this was its last shared network.
        let leaver_ip = self.peers.v4_for_id(&peer_id);
        if let Some(conn) = self.peers.remove_peer_from_network_by_id(&peer_id, network) {
            conn.close(VarInt::from_u32(forward::LEAVE_CODE), b"leave");
        }

        let (state, net_pubkey, dht_notify) = {
            let Some(h) = self.networks.get(network) else {
                return;
            };
            if !h.role.is_coordinator() {
                return;
            }
            (h.state.clone(), h.network_key, h.dht_notify.clone())
        };
        let member_id = self.device_user_map.resolve(&peer_id);
        state.write().unwrap().members.remove(&member_id);
        if let Some(ip) = leaver_ip {
            dns::remove_hostname_by_ip(
                &self.dns.hostname_table,
                &self.dns.reverse_table,
                network,
                ip,
            )
            .await;
        }
        update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
        broadcast_member_sync(&self.peers, net_pubkey, network, None).await;
        tracing::info!(peer = %member_id.fmt_short(), network, "pruned member after in-band leave");
    }

    /// Nullify a paired secondary device across every network we coordinate: add
    /// its key to the signed blob's nullifier set, drop it from the roster + `.ray`
    /// DNS, republish, and sever its links; persist the key in `revoked_devices`
    /// (the durable nullifier seed that survives a restart). Shared by `ray unpair
    /// <device>` (primary-initiated) and the `ControlMsg::RequestUnpair` handler (a
    /// secondary asking its primary to revoke it). Returns the device's display
    /// name, or an error string if `target` is not one of our paired devices, so a
    /// stranger's request is rejected. Only a network-key holder writes nullifiers,
    /// so on a network we don't coordinate this is a no-op for that network.
    pub(crate) async fn nullify_device(&self, target: EndpointId) -> Result<String, String> {
        let own_user = self.transport.endpoint.id();
        // Confirm the target is one of our paired devices, grab a display name, and
        // snapshot each network's handles (cloning the Arc state) so the DashMap
        // guards drop before any await.
        let mut display = target.fmt_short().to_string();
        let mut is_paired = false;
        let mut nets: Vec<(String, SharedNetworkState, Option<Arc<Notify>>, bool)> = Vec::new();
        for entry in self.networks.iter() {
            let s = entry.value().state.read().unwrap();
            if let Some(m) = s.members.all().iter().find(|m| m.identity == target)
                && m.user_identity == Some(own_user)
            {
                is_paired = true;
                if let Some(h) = &m.hostname {
                    display = h.clone();
                }
            }
            let has_key = s.network_secret_key.is_some();
            drop(s);
            nets.push((
                entry.key().clone(),
                entry.value().state.clone(),
                entry.value().dht_notify.clone(),
                has_key,
            ));
        }
        if !is_paired {
            return Err(format!(
                "'{}' is not one of your paired devices (see `ray pair list`)",
                target.fmt_short()
            ));
        }

        // Persist the nullifier seed so it survives a restart and is unioned into
        // every coordinated network's blob at seal time.
        let mut cfg = config::load().unwrap_or_default();
        let hex = target.to_string();
        if !cfg.revoked_devices.contains(&hex) {
            cfg.revoked_devices.push(hex);
        }
        if let Err(e) = config::save_settings(&cfg) {
            return Err(format!("failed to persist nullifier: {e}"));
        }
        self.device_user_map.remove(&target);

        // Nullify on every network we coordinate (add to the signed blob's
        // nullifier set + drop it from the roster), republish, and sever links.
        for (net, state, dht_notify, has_key) in nets {
            if has_key {
                let member_ip = {
                    let mut s = state.write().unwrap();
                    s.nullifiers.insert(target);
                    let ip = s
                        .members
                        .all()
                        .iter()
                        .find(|m| m.identity == target)
                        .map(|m| m.ip);
                    s.members.remove(&target);
                    s.approved.remove(&target);
                    ip
                };
                if let Some(ip) = member_ip {
                    dns::remove_hostname_by_ip(
                        &self.dns.hostname_table,
                        &self.dns.reverse_table,
                        &net,
                        ip,
                    )
                    .await;
                }
                update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
                let net_pubkey = state.read().unwrap().network_public_key;
                broadcast_member_sync(&self.peers, net_pubkey, &net, None).await;
            }
            for (pid, ip, conn) in self.peers.peers_for_network_with_conn(&net) {
                if pid == target {
                    self.pruned_peers.insert((net.clone(), pid));
                    conn.close(VarInt::from_u32(forward::KICK_CODE), b"unpaired");
                    self.peers
                        .remove_peer_from_network(&ip, &derive_ipv6(&pid), &net);
                }
            }
        }

        tracing::info!(device = %target.fmt_short(), "nullified device");
        Ok(display)
    }

    /// Dial a peer once (no backoff) over the mesh ALPN, send `MeshHello` on every
    /// `target` network, register its route, and if the connection is newly stored
    /// drive its control demux + announce handles. `targets` is one [`DialTarget`]
    /// per shared network. Returns whether a live connection was established. Shared
    /// by the reconnect loop and the on-demand lazy dialer.
    pub(crate) async fn dial_peer_once(
        self: &Arc<Self>,
        peer_id: EndpointId,
        peer_ip: Ipv4Addr,
        targets: &[DialTarget],
    ) -> bool {
        let my_identity = self.transport.identity.local_identity();
        let device_cert = self.current_device_cert();
        let conn = match transport::connect_to_peer_with_alpn(
            &self.transport.endpoint,
            peer_id,
            &transport::mesh_alpn(),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                // Flag an incompatible-version peer (ALPN gate) so `ray status`
                // shows it instead of plain offline; a different failure can't be
                // attributed to the version, so clear any prior flag. Success clears
                // it in `PeerTable::add`.
                if transport::is_alpn_mismatch(&format!("{e:#}")) {
                    self.peers.mark_incompatible(peer_id);
                } else {
                    self.peers.clear_incompatible(&peer_id);
                }
                tracing::debug!(peer = %peer_id.fmt_short(), error = %e, "dial attempt failed");
                return false;
            }
        };
        // Announce ourselves on every still-shared network over the one connection
        // and register the peer's route per network. `conn_changed` accumulates
        // whether the connection became newly current (it always is for a fresh
        // dial / reconnect), which gates driving its demux.
        let mut conn_changed = false;
        for t in targets {
            let Ok((mut send, _)) = conn.open_bi().await else {
                continue;
            };
            let hello = ControlMsg::MeshHello {
                identity: my_identity,
                ip: t.my_ip,
                hostname: outgoing_hostname(&t.network),
                device_cert: device_cert.clone(),
            };
            if control::send_msg(&mut send, Some(t.network_key), &hello)
                .await
                .is_err()
            {
                continue;
            }
            conn_changed |= self
                .mesh_ctx()
                .register_peer_conn(&conn, peer_id, peer_ip, &t.network);
        }
        if !conn_changed {
            return false;
        }
        tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "dialed peer");
        // Drive the new connection's control demux + announce handles.
        let router = self.protocol_router().clone();
        let dconn = conn.clone();
        tokio::spawn(router.drive_mesh_connection(dconn, true));
        announce_network_handles(&self.peers, &conn, peer_ip).await;
        true
    }

    /// Reconnect a dropped peer with one dial that re-establishes every network we
    /// still share with it. Backs off exponentially; on success re-registers the
    /// peer per network and drives the new connection's control demux. Also used
    /// by cold restore (coordinator offline at boot) to dial members from the
    /// verified blob before any live connection exists.
    pub(crate) fn spawn_reconnect(
        self: Arc<Self>,
        peer_id: EndpointId,
        peer_ip: Ipv4Addr,
        nets: Vec<SmolStr>,
    ) {
        // Networks to re-handshake: those we haven't pruned this peer from
        // (kick/departure records a one-shot suppression here).
        let mut candidate_nets: Vec<SmolStr> = Vec::new();
        for net in &nets {
            // Consume the one-shot prune suppression exactly once, here, so a later
            // dial iteration can't re-include a net we deliberately dropped.
            if self
                .pruned_peers
                .remove(&(net.to_string(), peer_id))
                .is_some()
            {
                tracing::info!(peer = %peer_id.fmt_short(), network = %net, "peer removed from roster, not reconnecting");
                continue;
            }
            candidate_nets.push(net.clone());
        }
        if candidate_nets.is_empty() {
            return;
        }

        let this = self.clone();
        let token = self.shutdown_token.clone();
        use tracing::Instrument as _;
        let span = tracing::info_span!("reconnect", peer = %peer_id.fmt_short());
        tokio::spawn(
            async move {
                let mut backoff = BACKOFF_INITIAL;
                // Bounds how long we keep waiting for a network handle that never
                // registers (e.g. the network was left mid-reconnect).
                let mut empty_tries = 0u32;
                loop {
                    if token.is_cancelled() {
                        return;
                    }
                    tokio::select! {
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);

                    // Re-resolve the live network handles each iteration: on cold
                    // restore the `NetworkHandle` is inserted just after the dial
                    // was scheduled, so it may be absent on the first pass.
                    let targets: Vec<DialTarget> = candidate_nets
                        .iter()
                        .filter_map(|net| {
                            this.networks.get(net.as_str()).map(|h| DialTarget {
                                network: net.to_string(),
                                network_key: h.network_key,
                                my_ip: h.my_ip,
                            })
                        })
                        .collect();
                    if targets.is_empty() {
                        empty_tries += 1;
                        if empty_tries > 6 {
                            return;
                        }
                        continue;
                    }

                    if this.dial_peer_once(peer_id, peer_ip, &targets).await {
                        return;
                    }
                    // Dial failed; back off and retry.
                }
            }
            .instrument(span),
        );
    }
}

/// Send `msg` to each coordinator peer (per [`gossip_targets`]) that has a live
/// connection on `network`. Best-effort: a target without a live connection is
/// skipped (it will reconverge invite state from a future share/redeem or, for
/// reusable keys, the signed blob). Never carries the raw secret, only its hash.
pub(crate) async fn gossip_to_coordinators(
    peers: &PeerTable,
    network: &str,
    net_pubkey: EndpointId,
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
            let _ = control::send_msg(&mut send, Some(net_pubkey), msg).await;
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

/// Republish the signed blob, broadcast a payload-free `MemberSync`, and send each
/// `victim` a network-scoped `ControlMsg::KickedFromNetwork` so it confirms against
/// the signed record and leaves this network. Call once after one or more
/// [`remove_member_roster_only`] edits. Other members drop the victims when they
/// reconverge from the freshly published record (`prune_departed_peers`).
pub(crate) async fn finalize_removal(
    ctx: &MeshCtx,
    network: &str,
    state: &SharedNetworkState,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
    victims: &[EndpointId],
) {
    update_snapshot_and_publish(state, &ctx.blob_store, dht_notify).await;
    let net_pubkey = state.read().unwrap().network_public_key;
    broadcast_member_sync(&ctx.peers, net_pubkey, network, None).await;
    for (pid, ip, conn) in ctx.peers.peers_for_network_with_conn(network) {
        let resolved = ctx.device_user_map.resolve(&pid);
        if victims.iter().any(|v| *v == pid || *v == resolved) {
            // Authoritative, network-scoped kick: tell the victim in-band that it
            // was removed from *this* network, so it can confirm against the signed
            // record and leave just this one (a connection close code cannot name
            // the network). Best-effort; a missed message falls back to the victim's
            // reconverge.
            if let Ok((mut send, _recv)) = conn.open_bi().await {
                let _ =
                    control::send_msg(&mut send, Some(net_pubkey), &ControlMsg::KickedFromNetwork)
                        .await;
                let _ = send.finish();
            }
            // Drop this network's route to the victim. We do not close the
            // connection: not closing keeps the kick message we just sent from
            // racing a connection close, and the victim's message-triggered leave
            // (or idle timeout) tears the link down. A link the victim still shares
            // another network on stays up for those.
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
                        should_prune(
                            m,
                            connected.contains(&m.identity),
                            m.identity == me,
                            ttl,
                            now,
                        )
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
        assert!(!should_prune(
            &mk(5, false, Some(NOW - TTL)),
            false,
            false,
            TTL,
            NOW
        ));
        // one second past the TTL -> prune
        assert!(should_prune(
            &mk(6, false, Some(NOW - TTL - 1)),
            false,
            false,
            TTL,
            NOW
        ));
    }

    #[test]
    fn backwards_clock_does_not_prune() {
        // last_seen in the "future" (clock went backwards) -> saturating_sub = 0
        assert!(!should_prune(
            &mk(7, false, Some(NOW + 100)),
            false,
            false,
            TTL,
            NOW
        ));
    }
}
