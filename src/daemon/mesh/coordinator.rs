//! The daemon-wide connection supervisor (dead-peer prune + reconnect) and the
//! invite-gossip send helper. Under one mesh connection per identity, a dropped
//! connection tears the peer down across every shared network at once, so
//! teardown/reconnect is node-wide rather than per-network. The per-member rename
//! reader and coordinator/member accept handlers now live in the per-connection
//! demux (`ProtocolRouter::drive_mesh_connection` → `AcceptHandler::handle_frame`).

use super::super::*;

impl MeshManager {
    /// Single daemon-wide loop consuming every data reader's disconnect. For each
    /// dropped identity it removes the peer from the table, prunes it from every
    /// network we coordinate on a deliberate leave, and otherwise reconnects it
    /// across all its shared networks.
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
            .identity_and_networks(std::net::IpAddr::V4(ev.ip))
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
        // Transient drop: reconnect across every shared network, skipping any we
        // just pruned this peer from (a one-shot suppression via pruned_peers).
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
        update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
        broadcast_member_sync(&self.peers, net_pubkey, network, None).await;
        tracing::info!(peer = %member_id.fmt_short(), network, "pruned member after leave");
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
        let my_identity = self.identity.local_identity();
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
                        &this.endpoint,
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
                            .register_peer_conn(&conn, peer_id, peer_ip, name, &token);
                        any = true;
                    }
                    if !any {
                        continue;
                    }
                    tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "reconnected to peer");
                    // Drive the new connection's control demux + announce handles.
                    let router = this.protocol_router.clone();
                    let dconn = conn.clone();
                    tokio::spawn(async move { router.drive_mesh_connection(dconn).await });
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
/// reusable keys, the signed blob). Never carries the raw secret — only its hash.
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
