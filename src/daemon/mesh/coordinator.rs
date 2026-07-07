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
        tracing::info!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, intentional = ev.intentional, "peer connection dropped");

        if ev.intentional {
            // Deliberate `ray leave` (graceful close with the leave code): prune
            // the member from every network we coordinate.
            for net in &nets {
                self.prune_member_on_leave(net, &ev).await;
            }
            return;
        }
        // Transient drop: stamp `last_seen` on each network we coordinate so the
        // ephemeral pruner ages the member from when it actually went offline
        // (not its admit time), then reconnect across every shared network,
        // skipping any we just pruned this peer from (one-shot via pruned_peers).
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
        let my_identity = self.transport.identity.local_identity();
        let device_cert = self.current_device_cert();
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
                    let targets: Vec<(String, EndpointId, Ipv4Addr)> = candidate_nets
                        .iter()
                        .filter_map(|net| {
                            this.networks
                                .get(net.as_str())
                                .map(|h| (net.to_string(), h.network_key, h.my_ip))
                        })
                        .collect();
                    if targets.is_empty() {
                        empty_tries += 1;
                        if empty_tries > 6 {
                            return;
                        }
                        continue;
                    }

                    let conn = match transport::connect_to_peer_with_alpn(
                        &this.transport.endpoint,
                        peer_id,
                        &transport::mesh_alpn(),
                    )
                    .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!(error = %e, "reconnect attempt failed");
                            continue;
                        }
                    };
                    // Announce ourselves on every still-shared network over the one
                    // connection, and register the peer's route per network.
                    let mut any = false;
                    for (name, net_pubkey, my_ip) in &targets {
                        let Ok((mut send, _)) = conn.open_bi().await else {
                            continue;
                        };
                        let hello = ControlMsg::MeshHello {
                            identity: my_identity,
                            ip: *my_ip,
                            hostname: outgoing_hostname(name),
                            device_cert: device_cert.clone(),
                        };
                        if control::send_msg(&mut send, Some(*net_pubkey), &hello)
                            .await
                            .is_err()
                        {
                            continue;
                        }
                        this.mesh_ctx()
                            .register_peer_conn(&conn, peer_id, peer_ip, name);
                        any = true;
                    }
                    if !any {
                        continue;
                    }
                    tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "reconnected to peer");
                    // Drive the new connection's control demux + announce handles.
                    let router = this.protocol_router().clone();
                    let dconn = conn.clone();
                    tokio::spawn(async move { router.drive_mesh_connection(dconn, true).await });
                    announce_network_handles(&this.peers, &conn, peer_ip).await;
                    return;
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
    let net_pubkey = state.read().unwrap().network_public_key;
    broadcast_member_sync(&ctx.peers, net_pubkey, network, None).await;
    for (pid, ip, _conn) in ctx.peers.peers_for_network_with_conn(network) {
        let resolved = ctx.device_user_map.resolve(&pid);
        if victims.iter().any(|v| *v == pid || *v == resolved) {
            // One connection carries every shared network, so only close it when
            // this was the peer's last network with us; otherwise just drop this
            // network's route (`remove_peer_from_network` returns the connection
            // iff its network set emptied).
            if let Some(conn) = ctx
                .peers
                .remove_peer_from_network(&ip, &derive_ipv6(&pid), network)
            {
                conn.close(VarInt::from_u32(forward::KICK_CODE), b"kicked from network");
            }
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
