//! `ray connect` (direct-connection) state and its ALPN accept arm, owned as one
//! unit instead of living loose inside `ProtocolRouter`.
//!
//! Holds the three connect maps (pending/approved/outgoing) and the
//! `CONNECT_ALPN` and `INVITE_ALPN` accept arm. The `ProtocolRouter` accept loop holds an
//! `Arc<ConnectService>` and delegates to it; `Daemon` holds the same handle
//! for the IPC-side connect commands (`connect`/`connections approve`/…), which
//! mint and join networks over the core registry.

use super::*;

/// Cap on the queue of unapproved incoming `ray connect` requests.
///
/// The dial that fills it is unauthenticated (a stranger needs only our
/// identity) and every entry is keyed by an endpoint id the requester generates, so
/// without a bound the map is memory anyone can allocate on this daemon. Same
/// policy and same size as [`MAX_PENDING_JOINS`](super::mesh::accept::MAX_PENDING_JOINS):
/// at the cap the oldest unanswered request makes way, on the grounds that a
/// request nobody approved in that long is the one least likely to be waited on.
pub(crate) const MAX_PENDING_CONNECTS: usize = 256;

/// How long a dialer past the gate has to send its one message. A stream held
/// open and idle otherwise ties up a handler task indefinitely.
pub(super) const CONNECT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A pending incoming `ray connect` request, awaiting `ray connect approve`.
/// Keyed by the requester's authenticated transport endpoint id.
#[derive(Clone)]
pub(crate) struct PendingConnect {
    pub(crate) from_endpoint: EndpointId,
    pub(crate) hostname: Option<String>,
    pub(crate) requested_at: Instant,
    /// Not known when it arrived: counts toward the stranger quota.
    pub(crate) stranger: bool,
}

/// Make room for a connect request from `incoming`: once the requests that
/// `counts` selects reach `cap`, drop the oldest of them and return its id. A
/// no-op (returns `None`) when `incoming` is already queued (a re-dial must not
/// cost anyone their slot) or there is spare capacity. Mirrors
/// `mesh::accept::evict_oldest_pending`, over a `DashMap`.
///
/// The oldest id is bound before the removal so no map reference is alive across
/// it: `DashMap` is sharded and holding one while mutating can deadlock.
pub(crate) fn evict_oldest_connect(
    pending: &DashMap<EndpointId, PendingConnect>,
    incoming: EndpointId,
    cap: usize,
    counts: impl Fn(&PendingConnect) -> bool,
) -> Option<EndpointId> {
    if pending.contains_key(&incoming) || pending.iter().filter(|e| counts(e.value())).count() < cap
    {
        return None;
    }
    let oldest = pending
        .iter()
        .filter(|e| counts(e.value()))
        .min_by_key(|e| e.value().requested_at)
        .map(|e| *e.key())?;
    pending.remove(&oldest);
    tracing::warn!(
        evicted = %oldest.fmt_short(),
        "pending connect-request queue full; evicted oldest request"
    );
    Some(oldest)
}

struct ConnectDecision {
    reply: control::ConnectMsg,
    rejection: Option<Instant>,
}

pub(crate) struct ConnectService {
    /// `ray connect` requests received on `CONNECT_ALPN`, awaiting approval.
    /// Keyed by the requester's transport endpoint id.
    pub(crate) pending_connects: DashMap<EndpointId, PendingConnect>,
    /// Approved connect requests: requester endpoint id → (room id, coordinator).
    /// The `CONNECT_ALPN` handler replies `Approved` from here when the requester
    /// re-dials after `ray connect approve`.
    pub(crate) approved_connects: DashMap<EndpointId, (EndpointId, EndpointId)>,
    /// Peer endpoints we have sent an outgoing `ray connect` request to. Used by
    /// the concurrency tie-break: if both peers requested *and* approved each
    /// other, only the higher endpoint id mints, avoiding a duplicate network.
    pub(crate) outgoing_connects: DashSet<EndpointId>,
    /// Rejected requests remain terminal when a cooperative requester polls.
    rejected_connects: DashMap<EndpointId, Instant>,
    connect_decision_lock: Mutex<()>,
    pub(crate) connection_errors: DashMap<EndpointId, String>,
    /// Foundation handles (endpoint, LAN sightings) for the connect handshake.
    pub(super) transport: Arc<Transport>,
    /// The network-owning service, for minting/joining the 2-peer direct network
    /// once a connect request is approved.
    pub(super) registry: Arc<NetworkRegistry>,
    /// One load-modify-save of the invitation inbox at a time.
    pub(super) inbox_lock: AsyncMutex<()>,
    /// Spans a whole invitation accept or decline.
    pub(super) answer_lock: AsyncMutex<()>,
    /// One invite delivery per recipient at a time.
    pub(super) delivery_locks: DashMap<EndpointId, Arc<AsyncMutex<()>>>,
}

impl ConnectService {
    pub(crate) fn new(registry: Arc<NetworkRegistry>) -> Self {
        let transport = Arc::clone(&registry.transport);
        Self {
            pending_connects: DashMap::new(),
            approved_connects: DashMap::new(),
            outgoing_connects: DashSet::new(),
            rejected_connects: DashMap::new(),
            connect_decision_lock: Mutex::new(()),
            connection_errors: DashMap::new(),
            transport,
            registry,
            inbox_lock: AsyncMutex::new(()),
            answer_lock: AsyncMutex::new(()),
            delivery_locks: DashMap::new(),
        }
    }

    /// Turn a `ray connect` argument into the peer endpoint to dial.
    ///
    /// A LAN sighting (a prefix from `ray mdns scan`) wins. Otherwise the
    /// argument is an identity, dialed directly: iroh's address lookup finds the
    /// endpoint and QUIC proves who answers, so nothing is looked up here.
    ///
    /// The error is the message, not a whole `IpcMessage`: every failure here is
    /// an `ipc_err`, and the one caller is what turns it into a reply.
    pub(crate) fn resolve_connect_target(&self, arg: &str) -> Result<EndpointId, String> {
        let me = self.transport.endpoint.id();
        if let Some(peer) = self.transport.lan_peers.resolve(arg, me) {
            return Ok(peer);
        }
        let peer = arg
            .parse::<EndpointId>()
            .map_err(|e| format!("invalid identity: {e}"))?;
        if peer == me || peer == self.registry.own_identity() {
            return Err("cannot connect to yourself".to_string());
        }
        Ok(peer)
    }

    /// Approve a pending `ray connect` request by hostname or endpoint prefix: mint a
    /// restricted 2-peer network with the requester pre-approved (idempotent if
    /// already linked; defers to the higher endpoint id on a simultaneous
    /// cross-connect). The initiator's connect-retry loop then joins it.
    pub(crate) async fn approve_connection(&self, selector: &str) -> IpcMessage {
        let req = match self.find_pending(selector) {
            Ok(req) => req,
            Err(message) => return ipc_err(message),
        };
        let peer = req.from_endpoint;

        // Idempotency: already linked on a direct network -> reuse it.
        if let Some(name) = self.registry.existing_direct_network_with(&peer) {
            self.pending_connects.remove(&peer);
            return IpcMessage::Ok {
                message: format!("already connected to this peer on '{name}'"),
            };
        }

        // Concurrency tie-break: if we also initiated a connect to this peer and
        // our endpoint id is the lower one, let the higher-id peer mint the
        // network; our own connect retry loop will join it.
        let we_initiated = self.outgoing_connects.contains(&peer);
        if we_initiated && self.transport.endpoint.id().to_string() < peer.to_string() {
            self.pending_connects.remove(&peer);
            return IpcMessage::Ok {
                message: "connection will be established by the other peer".to_string(),
            };
        }

        // Decide our own hostname once so the network name (`<me>-<peer>`) and our
        // member hostname on it agree, instead of generating two different names.
        // The peer's name is the whole roster of a 2-peer network, so it is
        // also the only thing our default can collide with, and it will when
        // both ends are called `laptop`.
        let my_host = crate::hostname::default_hostname(
            config::load().ok().and_then(|c| c.default_hostname),
            req.hostname.as_deref().as_slice(),
        );
        let name = match self
            .registry
            .direct_network_name(&my_host, req.hostname.as_deref())
        {
            Ok(name) => name,
            Err(e) => return ipc_err(format!("{e:#}")),
        };
        match self
            .registry
            .create_network_inner(
                GroupMode::Restricted,
                Some(name),
                Some(my_host),
                true,
                Some((peer, req.hostname.clone())),
            )
            .await
        {
            Ok(IpcMessage::Created {
                name, network_key, ..
            }) => {
                self.pending_connects.remove(&peer);
                self.approved_connects
                    .insert(peer, (network_key, self.transport.endpoint.id()));
                IpcMessage::Ok {
                    message: format!("approved — direct connection '{name}' created"),
                }
            }
            Ok(other) => other,
            Err(e) => ipc_err(format!("failed to create direct network: {e:#}")),
        }
    }

    /// `ray connect <identity>`: dial that identity over CONNECT_ALPN and send a
    /// request. If approved immediately we join the minted direct network; if
    /// pending we retry on a backoff.
    ///
    /// The argument may also be a neighbour from `ray mdns scan`, which works on
    /// a LAN with no internet. Approval is recipient-only either way.
    pub(crate) async fn connect(
        self: &Arc<Self>,
        peer: &str,
        hostname: Option<String>,
    ) -> IpcMessage {
        let peer = match self.resolve_connect_target(peer) {
            Ok(peer) => peer,
            Err(message) => return ipc_err(message),
        };
        self.connection_errors.remove(&peer);
        if let Some(name) = self.registry.existing_direct_network_with(&peer) {
            return IpcMessage::Ok {
                message: format!("already connected to this peer on '{name}'"),
            };
        }
        self.outgoing_connects.insert(peer);
        match self.send_connect_request(peer, hostname.clone()).await {
            Ok(control::ConnectMsg::Approved {
                room_id,
                coordinator,
            }) => {
                self.outgoing_connects.remove(&peer);
                self.join_direct(room_id, coordinator, hostname).await
            }
            Ok(control::ConnectMsg::Pending) => {
                self.spawn_connect_retry(peer, hostname);
                IpcMessage::Ok {
                    message: "connect request sent — waiting for approval".to_string(),
                }
            }
            Ok(control::ConnectMsg::Denied { reason }) => {
                self.outgoing_connects.remove(&peer);
                ipc_err(format!("connection denied: {reason}"))
            }
            Ok(_) => ipc_err("unexpected response from peer".to_string()),
            Err(e) => {
                self.outgoing_connects.remove(&peer);
                ipc_err(format!("failed to reach peer: {e}"))
            }
        }
    }

    /// Send a single connect request to `peer` over `CONNECT_ALPN` and return the
    /// reply.
    pub(crate) async fn send_connect_request(
        &self,
        peer: EndpointId,
        hostname: Option<String>,
    ) -> Result<control::ConnectMsg> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let conn = transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
                peer,
                transport::CONNECT_ALPN,
            )
            .await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            control::send_framed(
                &mut send,
                &control::ConnectMsg::Request {
                    from_identity: self.registry.own_identity(),
                    from_endpoint: self.transport.endpoint.id(),
                    hostname,
                },
            )
            .await?;
            control::recv_framed::<control::ConnectMsg>(&mut recv).await
        })
        .await
        .context("connect request timed out")?
    }

    /// Join a direct network the remote peer minted for us (flags it `direct` in
    /// config so `ray status` tags it).
    pub(crate) async fn join_direct(
        &self,
        room_id: EndpointId,
        coordinator: EndpointId,
        hostname: Option<String>,
    ) -> IpcMessage {
        let resp = self
            .registry
            .join_network(
                &room_id.to_string(),
                None,
                hostname,
                None,
                Some(coordinator),
                false,
                false,
            )
            .await;
        if let IpcMessage::Joined { name, .. } = &resp {
            let _ = config::update_network(name, |net| {
                net.direct = true;
                Ok(())
            });
        }
        resp
    }

    /// Retry a pending connect request on a backoff until approved/denied.
    pub(crate) fn spawn_connect_retry(
        self: &Arc<Self>,
        peer: EndpointId,
        hostname: Option<String>,
    ) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut backoff = BACKOFF_INITIAL;
            loop {
                tokio::select! {
                    _ = me.registry.shutdown_token.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                match me.send_connect_request(peer, hostname.clone()).await {
                    Ok(control::ConnectMsg::Approved {
                        room_id,
                        coordinator,
                    }) => match me.join_direct(room_id, coordinator, hostname.clone()).await {
                        IpcMessage::Joined { .. } | IpcMessage::Ok { .. } => {
                            tracing::info!(peer = %peer.fmt_short(), "direct connect join ok");
                            me.connection_errors.remove(&peer);
                            me.outgoing_connects.remove(&peer);
                            return;
                        }
                        IpcMessage::Error { message } => {
                            tracing::warn!(peer = %peer.fmt_short(), error = %message, "direct connect join failed");
                        }
                        other => {
                            tracing::warn!(peer = %peer.fmt_short(), response = ?other, "direct connect join: unexpected response");
                        }
                    },
                    Ok(control::ConnectMsg::Denied { reason }) => {
                        tracing::warn!(reason, peer = %peer.fmt_short(), "connect request denied");
                        me.record_connection_error(peer, format!("connection denied: {reason}"));
                        me.outgoing_connects.remove(&peer);
                        return;
                    }
                    _ => {} // Pending or transient error, keep retrying.
                }
            }
        });
    }

    /// List pending incoming `ray connect` requests awaiting approval.
    pub(crate) fn list_connections(&self) -> IpcMessage {
        let now = Instant::now();
        let requests = self
            .pending_connects
            .iter()
            .map(|p| ipc::PendingRequestInfo {
                short_id: p.from_endpoint.fmt_short().to_string(),
                hostname: p.hostname.clone(),
                waiting_secs: now.saturating_duration_since(p.requested_at).as_secs(),
            })
            .collect();
        IpcMessage::PendingRequests { requests }
    }

    /// Forget anything queued from a now-blocked identity, including the
    /// devices a roster binds to a blocked user.
    pub(crate) async fn drop_blocked(&self, blocked: &[EndpointId]) {
        let is_blocked = |remote| {
            inbound::classify(&self.registry, blocked, remote) == inbound::Inbound::Blocked
        };
        self.pending_connects
            .retain(|endpoint, _| !is_blocked(*endpoint));
        self.drop_blocked_invitations(is_blocked).await;
    }

    /// Add `remote` to the block list and forget what it has queued.
    pub(crate) async fn block(&self, remote: EndpointId) -> Result<()> {
        // The same settings arm `ray block` writes through, so there is one
        // rule for adding to the list.
        let cfg = config::update_settings(|cfg| {
            config::config_set(cfg, GlobalKey::Blocked, &remote.to_string(), false)
        })?;
        self.drop_blocked(&cfg.blocked).await;
        Ok(())
    }

    /// Drop a pending request without blocking the requester. The app Reject
    /// buttons use this: they have no way to unblock, so they must not block.
    pub(crate) fn reject_connection(&self, selector: &str) -> IpcMessage {
        if let Err(message) = self.reject_pending_with(selector, || {}) {
            return ipc_err(message);
        }
        IpcMessage::Ok {
            message: format!("declined connection request '{selector}'"),
        }
    }

    /// `ray connect deny`: drop a pending request by hostname or endpoint
    /// prefix and block the requester, so it cannot simply ask again.
    pub(crate) async fn deny_connection(&self, selector: &str) -> IpcMessage {
        let req = match self.reject_pending_with(selector, || {}) {
            Ok(req) => req,
            Err(message) => return ipc_err(message),
        };
        let rejection = self
            .rejected_connects
            .get(&req.from_endpoint)
            .map(|entry| *entry.value());
        if let Err(e) = self.block(req.from_endpoint).await {
            return ipc_err(format!("request dropped, but blocking failed: {e:#}"));
        }
        if let Some(rejection) = rejection {
            self.rejected_connects
                .remove_if(&req.from_endpoint, |_, remembered| *remembered == rejection);
        }
        IpcMessage::Ok {
            message: format!(
                "denied and blocked {} (undo with: ray unblock {})",
                req.from_endpoint.fmt_short(),
                req.from_endpoint
            ),
        }
    }

    fn connect_reply(
        &self,
        from_endpoint: EndpointId,
        hostname: Option<String>,
        stranger: bool,
    ) -> Result<ConnectDecision, String> {
        let _decision = self
            .connect_decision_lock
            .lock()
            .map_err(|_| "connection decision lock poisoned".to_string())?;
        // Recheck inside the decision lock: a block may have completed after
        // the stream handler passed its gate but before it reached this queue.
        if self.admitted(from_endpoint).is_none() {
            return Ok(ConnectDecision {
                reply: control::ConnectMsg::Denied {
                    reason: "recipient refuses connections from this peer".to_string(),
                },
                rejection: None,
            });
        }
        let already = self
            .approved_connects
            .get(&from_endpoint)
            .map(|r| *r.value());
        let rejection = self
            .rejected_connects
            .get(&from_endpoint)
            .map(|entry| *entry.value());
        let reply = if rejection.is_some() {
            control::ConnectMsg::Denied {
                reason: "operator declined the connection request".to_string(),
            }
        } else if let Some((room_id, coordinator)) = already {
            control::ConnectMsg::Approved {
                room_id,
                coordinator,
            }
        } else {
            if stranger {
                evict_oldest_connect(
                    &self.pending_connects,
                    from_endpoint,
                    inbound::MAX_STRANGER_CONNECTS,
                    |p| p.stranger,
                );
            }
            evict_oldest_connect(
                &self.pending_connects,
                from_endpoint,
                MAX_PENDING_CONNECTS,
                |_| true,
            );
            self.pending_connects.insert(
                from_endpoint,
                PendingConnect {
                    from_endpoint,
                    hostname,
                    requested_at: Instant::now(),
                    stranger,
                },
            );
            tracing::info!(endpoint = %from_endpoint.fmt_short(), "connect request received");
            control::ConnectMsg::Pending
        };
        Ok(ConnectDecision { reply, rejection })
    }

    fn reject_pending_with(
        &self,
        selector: &str,
        after_removed: impl FnOnce(),
    ) -> Result<PendingConnect, String> {
        let _decision = self
            .connect_decision_lock
            .lock()
            .map_err(|_| "connection decision lock poisoned".to_string())?;
        let request = self.take_pending(selector)?;
        after_removed();
        self.remember_rejection(request.from_endpoint);
        Ok(request)
    }

    fn record_connection_error(&self, peer: EndpointId, message: String) {
        self.connection_errors.insert(peer, message);
        while self.connection_errors.len() > MAX_PENDING_CONNECTS {
            let evicted = self
                .connection_errors
                .iter()
                .find(|entry| *entry.key() != peer)
                .map(|entry| *entry.key());
            let Some(evicted) = evicted else { break };
            self.connection_errors.remove(&evicted);
        }
    }

    fn remember_rejection(&self, peer: EndpointId) {
        if self.rejected_connects.len() >= MAX_PENDING_CONNECTS {
            let oldest = self
                .rejected_connects
                .iter()
                .min_by_key(|entry| *entry.value())
                .map(|entry| *entry.key());
            if let Some(oldest) = oldest {
                self.rejected_connects.remove(&oldest);
            }
        }
        self.rejected_connects.insert(peer, Instant::now());
    }

    async fn send_denial(conn: &Connection, reason: &str) {
        if let Ok(Ok((mut send, _recv))) =
            tokio::time::timeout(CONNECT_READ_TIMEOUT, conn.accept_bi()).await
            && control::send_framed(
                &mut send,
                &control::ConnectMsg::Denied {
                    reason: reason.to_string(),
                },
            )
            .await
            .is_ok()
        {
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        }
    }

    /// The dialer's class when the inbound gate admits it right now. An
    /// unreadable settings file must not quietly lift a block, so it refuses
    /// everyone until it is fixed.
    fn admitted(&self, remote: EndpointId) -> Option<inbound::Inbound> {
        let cfg = match config::load_inbound() {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(error = %e, "connect channel closed: settings unreadable");
                return None;
            }
        };
        let class = inbound::classify(&self.registry, &cfg.blocked, remote);
        if !inbound::admits(cfg.inbound, class) {
            tracing::debug!(peer = %remote.fmt_short(), ?class, "connect dial refused");
            return None;
        }
        Some(class)
    }

    /// Remove and return the pending request named by `selector`.
    fn take_pending(&self, selector: &str) -> Result<PendingConnect, String> {
        let req = self.find_pending(selector)?;
        self.pending_connects.remove(&req.from_endpoint);
        Ok(req)
    }

    /// The pending request named by `selector` (hostname or endpoint
    /// prefix), or the error message for a miss. Requests are keyed by
    /// `from_endpoint`, so the returned request's `from_endpoint` is its key.
    fn find_pending(&self, selector: &str) -> Result<PendingConnect, String> {
        let identity = match resolve_named_identity(
            selector,
            self.pending_connects
                .iter()
                .map(|request| (request.from_endpoint, request.hostname.clone())),
        ) {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                return Err(format!(
                    "no pending connection request matching '{selector}'"
                ));
            }
            Err(()) => {
                return Err(format!(
                    "pending connection request '{selector}' is ambiguous"
                ));
            }
        };
        self.pending_connects
            .iter()
            .find(|request| request.from_endpoint == identity)
            .map(|request| request.value().clone())
            .ok_or_else(|| format!("pending connection request '{selector}' disappeared"))
    }

    /// `CONNECT_ALPN`: handle a `ray connect` friend request. Binds the request
    /// to the dialing identity, replies `Approved` if already accepted
    /// (idempotent), else queues it as `Pending` for `ray connect approve`.
    /// `INVITE_ALPN`: store an invitation offer. Each channel takes only its
    /// own message.
    ///
    /// The inbound gate runs first, on the authenticated `remote_id`: a blocked
    /// or refused dialer receives a terminal denial without queuing its request.
    pub(crate) async fn accept_connect_request(&self, conn: Connection) {
        let remote_id = conn.remote_id();
        if self.admitted(remote_id).is_none() {
            Self::send_denial(&conn, "recipient refuses connections from this peer").await;
            return;
        }
        // One deadline covers opening the stream and reading it: a dialer
        // that never writes would otherwise park `accept_bi` for good.
        let deadline = tokio::time::Instant::now() + CONNECT_READ_TIMEOUT;
        match tokio::time::timeout_at(deadline, conn.accept_bi()).await {
            Ok(Ok((mut send, mut recv))) => {
                let read = tokio::time::timeout_at(
                    deadline,
                    control::recv_framed::<control::ConnectMsg>(&mut recv),
                )
                .await;
                let request = match read {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read connect request");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(peer = %remote_id.fmt_short(), "connect request timed out");
                        return;
                    }
                };
                // Gate again: a block or policy change made while this dialer
                // held its stream open must apply to what it sends.
                let Some(class) = self.admitted(remote_id) else {
                    if control::send_framed(
                        &mut send,
                        &control::ConnectMsg::Denied {
                            reason: "recipient refuses connections from this peer".to_string(),
                        },
                    )
                    .await
                    .is_ok()
                    {
                        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                    }
                    return;
                };
                let stranger = class == inbound::Inbound::Stranger;
                // Each message has its own channel: offers ride `INVITE_ALPN`
                // and requests `CONNECT_ALPN`.
                let invite_channel = conn.alpn() == transport::INVITE_ALPN;
                if matches!(request, control::ConnectMsg::InviteOffer { .. }) != invite_channel {
                    tracing::debug!(peer = %remote_id.fmt_short(), "connect message on the wrong channel");
                    conn.close(0u32.into(), b"");
                    return;
                }
                if let control::ConnectMsg::InviteOffer { network, code } = request {
                    let reply = match self
                        .receive_offer_result(remote_id, class, network, code)
                        .await
                    {
                        Ok(()) => control::ConnectMsg::Pending,
                        Err(reason) => control::ConnectMsg::Denied { reason },
                    };
                    if control::send_framed(&mut send, &reply).await.is_ok() {
                        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                    }
                    return;
                }
                if let control::ConnectMsg::Request {
                    from_identity: _,
                    from_endpoint,
                    hostname,
                } = request
                {
                    // Bind the request to the dialing identity: the
                    // endpoint we pre-approve must be the one that dialed.
                    if from_endpoint != remote_id {
                        tracing::warn!(claimed = %from_endpoint.fmt_short(), actual = %remote_id.fmt_short(), "connect request endpoint mismatch");
                        let _ = control::send_framed(
                            &mut send,
                            &control::ConnectMsg::Denied {
                                reason: "endpoint mismatch".to_string(),
                            },
                        )
                        .await;
                        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                        return;
                    }
                    let ConnectDecision { reply, rejection } =
                        match self.connect_reply(from_endpoint, hostname, stranger) {
                            Ok(decision) => decision,
                            Err(error) => {
                                tracing::warn!(%error, "could not decide connect request");
                                return;
                            }
                        };
                    if let Err(e) = control::send_framed(&mut send, &reply).await {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to send connect reply");
                        return;
                    }
                    if let Some(rejection) = rejection {
                        let delivered =
                            tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;
                        if matches!(delivered, Ok(Ok(None)))
                            || matches!(delivered, Ok(Ok(Some(code))) if code == VarInt::from_u32(0))
                        {
                            self.rejected_connects
                                .remove_if(&remote_id, |_, remembered| *remembered == rejection);
                        }
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                } else {
                    tracing::warn!(peer = %remote_id.fmt_short(), "unexpected connect message type");
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for connect");
            }
            Err(_) => {
                tracing::debug!(peer = %remote_id.fmt_short(), "connect request timed out");
                conn.close(0u32.into(), b"");
            }
        }
    }
}

#[cfg(test)]
mod pending_connect_cap_tests {
    use super::*;
    use iroh::SecretKey;

    fn eid(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        SecretKey::from(b).public()
    }

    fn queued_at(id: EndpointId, t: Instant) -> PendingConnect {
        PendingConnect {
            from_endpoint: id,
            hostname: None,
            requested_at: t,
            stranger: false,
        }
    }

    #[tokio::test]
    async fn rejection_and_concurrent_poll_make_one_atomic_decision() {
        use std::sync::mpsc;
        use std::thread;

        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .bind()
            .await
            .unwrap();
        let store = FsStore::load(tmp.path().join("blobs")).await.unwrap();
        let registry = crate::daemon::accept_handler_tests::sample_registry(
            endpoint.clone(),
            IrohIdentityProvider::new(endpoint.id()),
            store,
        );
        let service = ConnectService::new(registry);
        let requester = eid(42);
        service
            .pending_connects
            .insert(requester, queued_at(requester, Instant::now()));
        thread::scope(|scope| {
            let (removed_tx, removed_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let rejecting_service = &service;
            let rejecting = scope.spawn(move || {
                rejecting_service.reject_pending_with(&requester.to_string(), || {
                    removed_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
            });
            removed_rx.recv().unwrap();
            assert!(service.pending_connects.is_empty());
            assert!(service.rejected_connects.is_empty());
            assert!(service.connect_decision_lock.try_lock().is_err());
            let polling = scope.spawn(|| service.connect_reply(requester, None, true));
            release_tx.send(()).unwrap();
            rejecting.join().unwrap().unwrap();
            let decision = polling.join().unwrap().unwrap();
            assert!(matches!(decision.reply, control::ConnectMsg::Denied { .. }));
            assert!(service.pending_connects.is_empty());
        });
        endpoint.close().await;
    }

    #[test]
    fn no_eviction_below_cap() {
        let pending = DashMap::new();
        pending.insert(eid(1), queued_at(eid(1), Instant::now()));
        assert_eq!(evict_oldest_connect(&pending, eid(2), 4, |_| true), None);
        assert_eq!(pending.len(), 1);
    }

    /// The regression. `CONNECT_ALPN` takes a request from anyone holding our
    /// identity, keyed by an endpoint id the requester mints, so an unbounded
    /// queue was memory a stranger could allocate here without limit.
    #[test]
    fn full_queue_evicts_the_oldest() {
        let base = Instant::now();
        let pending = DashMap::new();
        for s in 0..4u8 {
            pending.insert(
                eid(s),
                queued_at(eid(s), base + Duration::from_millis(s as u64)),
            );
        }
        assert_eq!(
            evict_oldest_connect(&pending, eid(99), 4, |_| true),
            Some(eid(0))
        );
        assert_eq!(pending.len(), 3);
        assert!(!pending.contains_key(&eid(0)));
    }

    /// A requester re-dialing (the `Pending` reply tells it to) must not cost
    /// anyone else their slot, or a patient peer could be starved by a polite one.
    #[test]
    fn re_dial_from_a_queued_peer_evicts_nobody() {
        let base = Instant::now();
        let pending = DashMap::new();
        for s in 0..4u8 {
            pending.insert(
                eid(s),
                queued_at(eid(s), base + Duration::from_millis(s as u64)),
            );
        }
        assert_eq!(evict_oldest_connect(&pending, eid(1), 4, |_| true), None);
        assert_eq!(pending.len(), 4);
    }
}
