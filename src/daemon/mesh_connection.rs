//! `MeshConnection`: one live mesh connection, driven for its whole lifetime.
//!
//! Built by [`ConnectionManager::drive_mesh_connection`] on both the accept and
//! dial paths. It owns **both planes** of the connection: the control-plane demux
//! loop (this file's `run`) and the single data-plane reader
//! (`forward::spawn_peer_reader`), which it spawns on entry and tears down on
//! exit. When the connection closes, `run` is the one place that reports the
//! [`forward::DisconnectEvent`] to the supervisor, so there is exactly one report
//! per dropped connection and no data/control race over who reports.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;

use iroh::endpoint::{ConnectionError, SendStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::*;

/// One live mesh connection, driven for its whole lifetime. Owns the
/// per-connection demux state (the QUIC `conn`, the peer identity, the
/// control-plane rate `gate`) and carries the daemon-wide dispatch it needs to
/// route frames: `manager` for the per-network handler registry and the ping
/// map, `ctx` for the shared handles, `token` for shutdown.
///
/// `pre_registered` records whether the peer was already registered before the
/// demux started (the dial side registers first, then drives; the accept side
/// registers as membership frames land). It seeds the "was this connection ever a
/// member" guard that gates the disconnect report: an unregistered probe that
/// connects and dies is not a peer drop and must not be reported.
pub(crate) struct MeshConnection {
    conn: Connection,
    peer_id: EndpointId,
    manager: Arc<ConnectionManager>,
    ctx: MeshCtx,
    token: CancellationToken,
    gate: crate::ratelimit::ControlGate,
    nacks: NackGate,
    pre_registered: bool,
}

/// A missing handler can be a restore still in progress, so joining remains
/// retryable. Grants need an explicit failure because their sender records success.
async fn reply_network_unavailable(mut send: SendStream, net: EndpointId, msg: &ControlMsg) {
    let reply = match msg {
        ControlMsg::JoinRequest { .. } | ControlMsg::MeshHello { .. } => {
            ControlMsg::JoinUnavailable {
                reason: "network is not active on this peer".to_string(),
            }
        }
        ControlMsg::AdminGrant { .. } => ControlMsg::AdminGrantResult {
            network_pubkey: net,
            error: Some("network is not active on this peer".to_string()),
        },
        _ => return,
    };
    if let Err(error) = control::send_msg(&mut send, Some(net), &reply).await {
        tracing::debug!(%error, "could not reply for unavailable network");
    }
}

/// Bounds [`ControlMsg::NotSupported`] nacks on one connection: each unknown
/// kind is nacked once, at most [`NackGate::LIMIT`] distinct kinds, and never a
/// `NotSupported` itself, so two mismatched builds cannot ping-pong.
#[derive(Default)]
struct NackGate {
    sent: HashSet<String>,
}

impl NackGate {
    const LIMIT: usize = 8;

    fn should_send(&mut self, msg_kind: &str) -> bool {
        if msg_kind == "NotSupported" || self.sent.len() >= Self::LIMIT {
            return false;
        }
        self.sent.insert(msg_kind.to_string())
    }
}

/// Runs queued items one at a time per key, and different keys side by side.
///
/// Each key gets one worker task that drains its own queue in arrival order.
/// Nothing is locked while an item runs, so a slow item delays only the items
/// queued behind it under the same key. A lane holds at most
/// [`Self::LANE_DEPTH`] items; a push to a full lane waits, which holds the
/// caller back the way handling each item inline did.
struct SerialLanes<K, T, R> {
    lanes: HashMap<K, mpsc::Sender<Queued<T>>>,
    workers: JoinSet<()>,
    /// Handles one item; each lane's worker keeps its own clone.
    run: R,
    /// Items queued or running across every lane.
    pending: Arc<watch::Sender<usize>>,
}

/// An item waiting in, or running from, a lane.
struct Queued<T> {
    item: T,
    _pending: Pending,
}

/// Counts one item in [`SerialLanes::pending`] until dropped, whether the item
/// ran or its lane went away with it still queued.
struct Pending(Arc<watch::Sender<usize>>);

impl Pending {
    fn new(count: &Arc<watch::Sender<usize>>) -> Self {
        count.send_modify(|n| *n += 1);
        Self(Arc::clone(count))
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

impl<K, T, R> SerialLanes<K, T, R> {
    const LANE_DEPTH: usize = 4;

    fn new(run: R) -> Self {
        Self {
            lanes: HashMap::new(),
            workers: JoinSet::new(),
            run,
            pending: Arc::new(watch::channel(0).0),
        }
    }

    /// The number of items queued or running, for waiting until it is zero.
    fn pending(&self) -> watch::Receiver<usize> {
        self.pending.subscribe()
    }

    /// Stop taking items and wait until every queued one has run.
    async fn finish(mut self) {
        self.lanes.clear();
        while self.workers.join_next().await.is_some() {}
    }

    /// Stop taking items and let the queued ones finish on their own.
    fn detach(mut self) {
        self.lanes.clear();
        self.workers.detach_all();
    }
}

impl<K, T, R, Fut> SerialLanes<K, T, R>
where
    K: Eq + Hash,
    T: Send + 'static,
    R: Fn(T) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Queue `item` behind the earlier items under `key`.
    async fn push(&mut self, key: K, item: T) {
        let item = Queued {
            item,
            _pending: Pending::new(&self.pending),
        };
        let item = match self.lanes.get(&key) {
            Some(lane) => match lane.send(item).await {
                Ok(()) => return,
                // The lane's worker is gone (a handler panicked). Start a new
                // one rather than dropping this key's items for good.
                Err(mpsc::error::SendError(item)) => item,
            },
            None => item,
        };
        let (lane, mut queue) = mpsc::channel(Self::LANE_DEPTH);
        // The receiver is alive and the channel empty, so the send cannot fail.
        let _ = lane.try_send(item);
        let run = self.run.clone();
        self.workers.spawn(async move {
            while let Some(Queued { item, _pending }) = queue.recv().await {
                run(item).await;
            }
        });
        self.lanes.insert(key, lane);
    }
}

/// Wait for the queued frames to run, then whether any of them registered the
/// peer, so a registration just before the connection drops is not missed.
async fn drain_lanes<R>(
    lanes: SerialLanes<EndpointId, LaneFrame, R>,
    registered_rx: &mut mpsc::UnboundedReceiver<()>,
) -> bool {
    lanes.finish().await;
    registered_rx.try_recv().is_ok()
}

/// One network-scoped control frame, queued on its network's lane.
struct LaneFrame {
    net: EndpointId,
    send: SendStream,
    msg: ControlMsg,
}

/// The peer's latest `NetworkHandles` announcement. Applying it needs the peer
/// registered on this connection, so it is applied again each time a network
/// frame registers the peer.
struct PeerAnnouncement {
    entries: Vec<control::NetworkHandle>,
    features: u64,
    receive_mtu: u16,
}

impl MeshConnection {
    /// Assemble a driver from the daemon-wide dispatch. `conn` is the freshly
    /// accepted or dialed mesh connection; the rest come from the manager's
    /// installed [`MeshDispatch`]. See the struct docs for `pre_registered`.
    pub(crate) fn new(
        conn: Connection,
        manager: Arc<ConnectionManager>,
        ctx: MeshCtx,
        token: CancellationToken,
        pre_registered: bool,
    ) -> Self {
        Self {
            peer_id: conn.remote_id(),
            conn,
            manager,
            ctx,
            token,
            gate: crate::ratelimit::ControlGate::new(),
            nacks: NackGate::default(),
            pre_registered,
        }
    }

    /// Drive the connection for its whole life: spawn the single data reader, then
    /// loop accepting control streams and routing each `ControlFrame` to the right
    /// per-network handler by `net`, or handling connection-level messages
    /// (`NetworkHandles`, `Ping`/`Pong`, the unpair notices, `CertRefresh`)
    /// inline. On any exit that isn't daemon shutdown, stop the reader and, if
    /// this connection was ever a registered member, report the drop to the
    /// supervisor.
    pub(crate) async fn run(mut self) {
        // Feed the warm-start cache from the authenticated connection.  A later
        // restart can try its selected relay or direct path immediately instead
        // of waiting for discovery to rediscover it.
        self.ctx.registry.remember_connection_hints(&self.conn);
        // A connection to this peer now exists (either side dialed): let the
        // composition-root hook flush anything queued for it (send outbox).
        self.manager.notify_peer_connected(self.peer_id);
        // The connection's single data reader. One reader serves every network the
        // connection carries; `MeshConnection` owns it for the connection's
        // lifetime and aborts it when the loop below ends.
        let reader = forward::spawn_peer_reader(
            self.conn.clone(),
            self.peer_id,
            self.ctx.peers.clone(),
            self.ctx.forward_ctx(self.token.clone()),
        );
        // Whether this connection ever became a registered member (see struct docs).
        let mut registered = self.pre_registered;
        let mut announcement: Option<PeerAnnouncement> = None;

        // Network-scoped frames run on one lane per network, so a slow frame on
        // one network does not hold up the others on this connection. Pairing
        // sends one `JoinRequest` per shared network over a single connection,
        // and each admission writes a roster snapshot and waits on the relay;
        // handled inline they ran one after another.
        //
        // Ordering that still holds:
        // - Frames for one network run in arrival order, as before. Membership
        //   frames (`MeshHello`, `JoinRequest`, `MemberApproved`, `LeaveNetwork`,
        //   `KickedFromNetwork`) only depend on earlier frames for that network.
        // - Connection-level frames (`NetworkHandles`, `Ping`, ...) stay inline.
        //   A `NetworkHandles` that overtakes the frame registering the peer
        //   would be dropped by the peer table, so the latest one is kept and
        //   applied again whenever a lane reports a registration.
        // - `registered` is only read when the loop exits, after the lanes have
        //   drained, so a frame that registers the peer just before the
        //   connection drops still gets its disconnect reported.
        let (registered_tx, mut registered_rx) = mpsc::unbounded_channel::<()>();
        let mut lanes = SerialLanes::new({
            let conn = self.conn.clone();
            let peers = self.ctx.peers.clone();
            let manager = Arc::clone(&self.manager);
            let peer_id = self.peer_id;
            move |frame: LaneFrame| {
                let conn = conn.clone();
                let peers = peers.clone();
                let manager = Arc::clone(&manager);
                let registered_tx = registered_tx.clone();
                async move {
                    // Look the handler up now, not when the frame arrived: while
                    // it waited, the network may have been left, or a finished
                    // join may have replaced the member handler with a
                    // coordinator's.
                    let Some(handler) = manager.handler_for(&frame.net) else {
                        tracing::debug!(
                            peer = %peer_id.fmt_short(),
                            net = %frame.net.fmt_short(),
                            "network gone before its queued control frame ran; dropping"
                        );
                        reply_network_unavailable(frame.send, frame.net, &frame.msg).await;
                        return;
                    };
                    // The reachability wall for the control plane, mirroring
                    // what `resolve_inbound_by_id` does for datagrams: a frame
                    // is dispatched to a network's handler on the strength of
                    // the network id it names, and that id is public, so the
                    // sender has to be someone this network's roster accounts
                    // for. The exceptions are the messages by which a peer that
                    // is legitimately not on the roster yet reaches us; see
                    // `stranger_may_send`. Checked here rather than on arrival
                    // so it sees the roster as the earlier frames on this lane
                    // left it, as it did when frames ran inline. Lanes belong
                    // to this connection, so a stranger's queued frames only
                    // ever wait behind its own.
                    if !stranger_may_send(&frame.msg) && !handler.knows_sender(peer_id) {
                        tracing::debug!(
                            peer = %peer_id.fmt_short(),
                            network = %handler.network_name(),
                            "control frame from a peer this network's roster does not list; ignoring"
                        );
                        return;
                    }
                    // `handle_frame` registers the peer (route) as a side effect
                    // and returns its mesh address once it is a member on this
                    // network.
                    let Some(peer_ip) = handler
                        .handle_frame(&conn, frame.send, peer_id, frame.msg)
                        .await
                    else {
                        return;
                    };
                    let _ = registered_tx.send(());
                    // (Re)announce our outbound handle table so the peer can
                    // decode datagrams we tag for this (possibly newly-shared)
                    // network. Look it up by the address `handle_frame`
                    // registered it under, not by one derived from the transport
                    // key: a device whose `MeshHello` claims a cert-bound
                    // identity is keyed on *that* identity's address, and a
                    // recompute would find an empty handle table.
                    announce_network_handles(&peers, &conn, peer_ip).await;
                }
            }
        });
        let mut lanes_pending = lanes.pending();

        loop {
            // On-demand idle teardown. Armed only when we run on-demand *and* the
            // peer advertised idle-close support (recorded from its NetworkHandles):
            // a peer on a build that predates the idle close code is held open, never
            // flapped. Recomputed each iteration because the peer registers its
            // capability just after connect and the clock advances as traffic flows.
            // Never idle-close the selected exit peer: it carries all our
            // internet traffic, and an internet-bound packet cannot lazily
            // re-dial it (the destination is not a roster member), so a reaped
            // exit link blackholes until the next reconverge. Keep it warm.
            // Checked only when on-demand, so other nodes skip the lookups.
            let sleep_for = (self.ctx.registry.on_demand
                && !self.is_exit_peer()
                && self
                    .ctx
                    .peers
                    .supports_idle_close(&self.peer_id, &self.conn))
            .then(|| {
                self.ctx.peers.idle_remaining(
                    &self.peer_id,
                    &self.conn,
                    self.ctx.registry.idle_timeout,
                )
            })
            .flatten();

            let accepted = tokio::select! {
                // Daemon shutdown: drop the reader and leave without reporting a
                // disconnect (the peer isn't gone, we are).
                _ = self.token.cancelled() => {
                    lanes.detach();
                    reader.abort();
                    return;
                }
                // A lane registered the peer on one of its networks: the
                // connection now counts as a member's, and a handle announcement
                // that arrived before the registration can take effect.
                Some(()) = registered_rx.recv() => {
                    registered = true;
                    if let Some(announcement) = &announcement {
                        self.apply_announcement(announcement);
                    }
                    continue;
                }
                // Idle timer. When disarmed (`None`) this branch parks forever, so it
                // costs nothing. When it fires we re-check: a send or read may have
                // bumped activity while we slept, in which case we re-arm.
                _ = async {
                    match sleep_for {
                        Some(d) => {
                            tokio::time::sleep(d).await;
                            // A frame still queued or running (an admission
                            // mid-roster-write) holds the close off until it is
                            // done, as it did when frames ran inline.
                            let _ = lanes_pending.wait_for(|pending| *pending == 0).await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let still_idle = self
                        .ctx
                        .peers
                        .idle_remaining(
                            &self.peer_id,
                            &self.conn,
                            self.ctx.registry.idle_timeout,
                        )
                        .is_some_and(|d| d.is_zero());
                    if !still_idle {
                        continue;
                    }
                    tracing::info!(peer = %self.peer_id.fmt_short(), "closing idle connection (on-demand teardown)");
                    self.conn.close(VarInt::from_u32(forward::IDLE_CODE), b"idle");
                    reader.abort();
                    self.ctx.stats.record_idle_teardown();
                    registered |= drain_lanes(lanes, &mut registered_rx).await;
                    // We close, so our own loop only ever sees `LocallyClosed`, never
                    // our IDLE_CODE. Report `Idle` explicitly so the supervisor removes
                    // the peer and does not reconnect, matching the remote (which does
                    // see IDLE_CODE). The link re-forms lazily on the next packet.
                    if registered {
                        self.report_disconnect(forward::CloseReason::Idle).await;
                    }
                    return;
                }
                r = self.conn.accept_bi() => r,
            };
            let (send, mut recv) = match accepted {
                Ok(pair) => pair,
                // Connection closed. Tear down the reader and report the drop.
                Err(e) => {
                    reader.abort();
                    registered |= drain_lanes(lanes, &mut registered_rx).await;
                    if registered {
                        self.report_disconnect(close_reason(&e)).await;
                    }
                    return;
                }
            };
            let frame = match control::recv_frame(&mut recv).await {
                Ok(control::FrameRead::Frame(f)) => *f,
                // A frame from a newer build. Tell the sender once so its
                // feature fails loudly on its side instead of silently here.
                Ok(control::FrameRead::Unknown { msg_kind }) => {
                    self.nack_unknown(msg_kind).await;
                    continue;
                }
                Err(_) => continue,
            };
            // Control traffic deliberately does NOT count as activity: "idle" means
            // no data-plane (TUN) traffic. Counting control frames would let periodic
            // chatter (pings, roster-sync/blob-update triggers) hold a connection open
            // forever, defeating on-demand teardown. A control exchange racing the idle
            // close is safe: frames are atomic and control is only ever a trigger, so a
            // dropped push re-forms on the next lazy dial or the group poll reconverge.
            match self.gate.check() {
                crate::ratelimit::Verdict::Allow => {}
                crate::ratelimit::Verdict::Drop => continue,
                crate::ratelimit::Verdict::Close => {
                    tracing::warn!(peer = %self.peer_id.fmt_short(), "control-plane flood; closing connection");
                    self.conn
                        .close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                    reader.abort();
                    registered |= drain_lanes(lanes, &mut registered_rx).await;
                    // A flood close is not a graceful leave, so the supervisor
                    // treats it as a transient drop and reconnects.
                    if registered {
                        self.report_disconnect(forward::CloseReason::Transient)
                            .await;
                    }
                    return;
                }
            }
            // Connection-level messages (not scoped to a network).
            match &frame.msg {
                ControlMsg::NetworkHandles {
                    entries,
                    features,
                    receive_mtu,
                } => {
                    let latest = PeerAnnouncement {
                        entries: entries.clone(),
                        features: *features,
                        receive_mtu: *receive_mtu,
                    };
                    self.apply_announcement(&latest);
                    announcement = Some(latest);
                    continue;
                }
                ControlMsg::Ping { nonce } => {
                    respond_pong(&self.conn, *nonce).await;
                    continue;
                }
                ControlMsg::Pong { nonce } => {
                    if let Some((_, tx)) = self.manager.pending_pongs.remove(nonce) {
                        let _ = tx.send(());
                    }
                    continue;
                }
                ControlMsg::Unpaired | ControlMsg::PairingRevoked { .. } => {
                    // Our primary is unpairing this device, or repeating it until
                    // we confirm. Acted on only if the sender signed our cert (a
                    // stranger is a no-op), and judged against the cert stored
                    // when it is acted on, not now: a notice read now may have
                    // waited behind another stream while this device paired
                    // again. Leaving every network is heavy, so spawn it off the
                    // demux loop rather than awaiting inline.
                    let revoked = match frame.msg {
                        ControlMsg::PairingRevoked { generation } => Some(generation),
                        _ => None,
                    };
                    // A primary on version 7 names the pairing; only an older
                    // one sends the bare notice.
                    if revoked.is_none() && !predates_pairing_generations(self.conn.alpn()) {
                        tracing::debug!(peer = %self.peer_id.fmt_short(), "ignoring an unpair notice that names no pairing");
                        continue;
                    }
                    let registry = Arc::clone(&self.ctx.registry);
                    let sender = self.peer_id;
                    tokio::spawn(async move {
                        registry.on_unpaired_notice(sender, revoked).await;
                    });
                    continue;
                }
                ControlMsg::CertRefresh { cert } => {
                    // Our primary rotated and re-issued us; verified inside against
                    // our own cert (signer + device key + generation).
                    store_refreshed_cert(cert);
                    continue;
                }
                ControlMsg::RequestUnpair => {
                    // A paired secondary on an older build is unpairing itself and
                    // asks us (its primary) to write the authoritative nullifier.
                    // Act only if we are a primary (hold the network keys);
                    // `nullify_device` rejects a requester that is not one of our
                    // paired devices, so a stranger is a no-op. Off the demux loop:
                    // republish + prune is heavy.
                    if self.ctx.registry.current_device_cert().is_none() {
                        let registry = Arc::clone(&self.ctx.registry);
                        let requester = self.peer_id;
                        tokio::spawn(async move {
                            if let Err(reason) = registry.nullify_device(requester, false).await {
                                tracing::debug!(peer = %requester.fmt_short(), %reason, "ignoring unpair request");
                            }
                        });
                    }
                    continue;
                }
                ControlMsg::NotSupported { msg_kind } => {
                    // Advisory: the peer could not decode a `msg_kind` we sent
                    // (it runs an older build). Nothing to act on; the feature
                    // simply does not reach this peer until it updates.
                    tracing::warn!(
                        peer = %self.peer_id.fmt_short(),
                        kind = %msg_kind,
                        "peer runs an older build without this control message"
                    );
                    continue;
                }
                _ => {}
            }
            let Some(net_pubkey) = frame.net else {
                continue;
            };
            if self.manager.handler_for(&net_pubkey).is_none() {
                tracing::debug!(peer = %self.peer_id.fmt_short(), net = %net_pubkey.fmt_short(), "control frame for unknown network; ignoring");
                // A peer talking to us about a network we have saved but never
                // registered means our restore of it is still owed: the network
                // is plainly reachable, since its traffic just arrived. Nudge the
                // supervisor to retry now rather than at its next tick.
                // Joining remains pending until the handler is restored.
                self.ctx.registry.nudge_restore();
                reply_network_unavailable(send, net_pubkey, &frame.msg).await;
                continue;
            }
            drop(recv); // one message per stream; the reply rides `send`
            lanes
                .push(
                    net_pubkey,
                    LaneFrame {
                        net: net_pubkey,
                        send,
                        msg: frame.msg,
                    },
                )
                .await;
        }
    }

    /// Apply the peer's handle announcement: its inbound decode table, receive
    /// MTU and idle-close capability. Each is a no-op until the peer is
    /// registered on this connection.
    fn apply_announcement(&self, announcement: &PeerAnnouncement) {
        self.manager
            .apply_network_handles(&self.conn, self.peer_id, &announcement.entries);
        self.ctx
            .peers
            .note_receive_mtu(&self.peer_id, &self.conn, announcement.receive_mtu);
        // The handle announcement is the one control message both ends send
        // right after connect, so it is where we learn the peer's idle-close
        // capability (the MeshHello handshake is one-way). Gate the
        // per-connection idle timer on it: a peer that does not advertise
        // support is held open, never idle-closed.
        self.ctx.peers.note_idle_support_by_id(
            &self.peer_id,
            &self.conn,
            announcement.features & crate::transport::FEATURE_IDLE_CLOSE != 0,
        );
        self.ctx.peers.note_exit_ipv4_support(
            &self.peer_id,
            &self.conn,
            announcement.features & crate::transport::FEATURE_EXIT_IPV4 != 0,
        );
    }

    /// Whether this peer is the selected exit node.
    fn is_exit_peer(&self) -> bool {
        self.ctx
            .registry
            .exit_client
            .selection()
            .and_then(|s| {
                self.ctx
                    .peers
                    .ipv6_for_id(&self.peer_id)
                    .map(|v6| v6 == s.ipv6)
            })
            .unwrap_or(false)
    }

    /// Best-effort `NotSupported` nack for a control frame this build could not
    /// decode, bounded by [`NackGate`].
    async fn nack_unknown(&mut self, msg_kind: String) {
        if !self.nacks.should_send(&msg_kind) {
            return;
        }
        tracing::info!(
            peer = %self.peer_id.fmt_short(),
            kind = %msg_kind,
            "control message from a newer build; nacking"
        );
        let _ = open_and_send(&self.conn, None, &ControlMsg::NotSupported { msg_kind }).await;
    }

    /// Report this connection's drop to the daemon-wide supervisor. The peer's
    /// mesh address is derived from its identity, so it needs no roster lookup;
    /// `conn_stable_id` lets the supervisor's ABA guard ignore this event if the
    /// peer has since reconnected.
    async fn report_disconnect(&self, reason: forward::CloseReason) {
        let ipv6 = crate::membership::derive_ipv6(&self.peer_id);
        tracing::warn!(peer = %self.peer_id.fmt_short(), ip = %ipv6, reason = ?reason, "peer connection lost");
        let _ = self
            .ctx
            .disconnect_tx
            .send(forward::DisconnectEvent {
                endpoint_id: self.peer_id,
                ipv6,
                reason,
                conn_stable_id: Some(self.conn.stable_id()),
            })
            .await;
    }
}

/// Classify a connection close: [`forward::LEAVE_CODE`] is a deliberate leave,
/// [`forward::KICK_CODE`] is the peer removing us from its view, and anything else
/// (idle timeout, reset, local flood close) is a transient drop.
fn close_reason(e: &ConnectionError) -> forward::CloseReason {
    match e {
        ConnectionError::ApplicationClosed(ac)
            if ac.error_code == VarInt::from_u32(forward::LEAVE_CODE) =>
        {
            forward::CloseReason::Left
        }
        ConnectionError::ApplicationClosed(ac)
            if ac.error_code == VarInt::from_u32(forward::KICK_CODE) =>
        {
            forward::CloseReason::Kicked
        }
        ConnectionError::ApplicationClosed(ac)
            if ac.error_code == VarInt::from_u32(forward::IDLE_CODE) =>
        {
            forward::CloseReason::Idle
        }
        ConnectionError::ApplicationClosed(ac)
            if ac.error_code == VarInt::from_u32(forward::REPLACED_CONNECTION_CODE) =>
        {
            forward::CloseReason::Replaced
        }
        _ => forward::CloseReason::Transient,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::{ApplicationClose, VarInt};

    fn app_close(code: u32) -> ConnectionError {
        ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: VarInt::from_u32(code),
            reason: Vec::new().into(),
        })
    }

    /// Items under one key run in arrival order; a key whose item is stuck does
    /// not hold up another key's items.
    #[tokio::test]
    async fn serial_lanes_keep_order_per_key_and_overlap_keys() {
        let (log_tx, mut log) = mpsc::unbounded_channel::<&'static str>();
        let gate = Arc::new(tokio::sync::Notify::new());
        let run = {
            let gate = Arc::clone(&gate);
            move |(label, wait): (&'static str, bool)| {
                let gate = Arc::clone(&gate);
                let log_tx = log_tx.clone();
                async move {
                    if wait {
                        gate.notified().await;
                    }
                    let _ = log_tx.send(label);
                }
            }
        };
        let mut lanes = SerialLanes::new(run);
        lanes.push("a", ("a1", true)).await;
        lanes.push("a", ("a2", false)).await;
        lanes.push("b", ("b1", false)).await;

        async fn next(log: &mut mpsc::UnboundedReceiver<&'static str>) -> &'static str {
            tokio::time::timeout(Duration::from_secs(2), log.recv())
                .await
                .expect("an item ran")
                .expect("log open")
        }
        assert_eq!(next(&mut log).await, "b1");
        // a2 waits behind a1 even though it could run immediately.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), log.recv())
                .await
                .is_err()
        );
        gate.notify_one();
        assert_eq!(next(&mut log).await, "a1");
        assert_eq!(next(&mut log).await, "a2");
        lanes.finish().await;
    }

    /// The pending count covers queued and running items, so the idle close
    /// can wait for a frame that is still being handled.
    #[tokio::test]
    async fn serial_lanes_count_pending_items_until_they_finish() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let run = {
            let gate = Arc::clone(&gate);
            move |wait: bool| {
                let gate = Arc::clone(&gate);
                async move {
                    if wait {
                        gate.notified().await;
                    }
                }
            }
        };
        let mut lanes = SerialLanes::new(run);
        let mut pending = lanes.pending();
        lanes.push("a", true).await;
        lanes.push("a", false).await;
        assert_eq!(*pending.borrow(), 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), pending.wait_for(|n| *n == 0))
                .await
                .is_err(),
            "a running item keeps the lanes busy"
        );
        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(2), pending.wait_for(|n| *n == 0))
            .await
            .expect("the lanes go idle")
            .expect("lanes alive");
        lanes.finish().await;
    }

    #[test]
    fn nack_gate_bounds_and_dedups() {
        let mut gate = NackGate::default();
        // First sighting of a kind passes, repeats do not.
        assert!(gate.should_send("ExitNodeTeleport"));
        assert!(!gate.should_send("ExitNodeTeleport"));
        // A NotSupported is never nacked back: two mismatched builds must not
        // ping-pong.
        assert!(!gate.should_send("NotSupported"));
        // Distinct kinds pass until the per-connection cap, then nothing does.
        for i in 1..NackGate::LIMIT {
            assert!(gate.should_send(&format!("Future{i}")));
        }
        assert!(!gate.should_send("OneTooMany"));
    }

    #[test]
    fn close_code_classification() {
        assert!(matches!(
            close_reason(&app_close(forward::LEAVE_CODE)),
            forward::CloseReason::Left
        ));
        assert!(matches!(
            close_reason(&app_close(forward::KICK_CODE)),
            forward::CloseReason::Kicked
        ));
        assert!(matches!(
            close_reason(&app_close(forward::IDLE_CODE)),
            forward::CloseReason::Idle
        ));
        assert!(matches!(
            close_reason(&app_close(forward::REPLACED_CONNECTION_CODE)),
            forward::CloseReason::Replaced
        ));
        // An unrelated application code is a transient drop (reconnected).
        assert!(matches!(
            close_reason(&app_close(0xdead)),
            forward::CloseReason::Transient
        ));
        // A non-application close (timeout, reset) is transient too.
        assert!(matches!(
            close_reason(&ConnectionError::TimedOut),
            forward::CloseReason::Transient
        ));
    }
}
