//! `ray connect` (direct-connection) state and its ALPN accept arm, owned as one
//! unit instead of living loose inside `ProtocolRouter`.
//!
//! Holds the three connect maps (pending/approved/outgoing) and the
//! `CONNECT_ALPN` accept arm. The `ProtocolRouter` accept loop holds an
//! `Arc<ConnectService>` and delegates to it; `Daemon` holds the same handle
//! for the IPC-side connect commands (`connect`/`connections approve`/…), which
//! mint and join networks over the core registry.

use super::*;

/// A pending incoming `ray connect` request, awaiting `ray connections approve`.
/// Keyed by the requester's transport endpoint id (not contact id) so it
/// survives the requester rotating their contact key.
#[derive(Clone)]
pub(crate) struct PendingConnect {
    pub(crate) from_contact_id: EndpointId,
    pub(crate) from_endpoint: EndpointId,
    pub(crate) hostname: Option<String>,
    pub(crate) requested_at: Instant,
}

pub(crate) struct ConnectService {
    /// `ray connect` requests received on `CONNECT_ALPN`, awaiting approval.
    /// Keyed by the requester's transport endpoint id.
    pub(crate) pending_connects: Arc<DashMap<EndpointId, PendingConnect>>,
    /// Approved connect requests: requester endpoint id → (room id, coordinator).
    /// The `CONNECT_ALPN` handler replies `Approved` from here when the requester
    /// re-dials after `ray connections approve`.
    pub(crate) approved_connects: Arc<DashMap<EndpointId, (EndpointId, EndpointId)>>,
    /// Peer endpoints we have sent an outgoing `ray connect` request to. Used by
    /// the concurrency tie-break: if both peers requested *and* approved each
    /// other, only the higher endpoint id mints, avoiding a duplicate network.
    pub(crate) outgoing_connects: Arc<DashSet<EndpointId>>,
    /// Foundation handles (endpoint + contact id) for the connect handshake and
    /// contact-record publishing.
    transport: Arc<Transport>,
    /// Whether the data plane is active, gating immediate contact republish on
    /// key rotation.
    active: Arc<AtomicBool>,
    /// The network-owning service, for minting/joining the 2-peer direct network
    /// once a connect request is approved.
    registry: Arc<NetworkRegistry>,
}

impl ConnectService {
    pub(crate) fn new(
        transport: Arc<Transport>,
        active: Arc<AtomicBool>,
        registry: Arc<NetworkRegistry>,
    ) -> Self {
        Self {
            pending_connects: Arc::new(DashMap::new()),
            approved_connects: Arc::new(DashMap::new()),
            outgoing_connects: Arc::new(DashSet::new()),
            transport,
            active,
            registry,
        }
    }

    /// Approve a pending `ray connect` request by contact-id prefix: mint a
    /// restricted 2-peer network with the requester pre-approved (idempotent if
    /// already linked; defers to the higher endpoint id on a simultaneous
    /// cross-connect). The initiator's connect-retry loop then joins it.
    pub(crate) async fn approve_connection(&self, id_prefix: &str) -> IpcMessage {
        let found = self
            .pending_connects
            .iter()
            .find(|p| {
                p.from_contact_id
                    .fmt_short()
                    .to_string()
                    .starts_with(id_prefix)
                    || p.from_contact_id.to_string().starts_with(id_prefix)
            })
            .map(|p| p.value().clone());
        let Some(req) = found else {
            return ipc_err(format!("no pending connection request matching '{id_prefix}'"));
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
        let my_host = config::load()
            .ok()
            .and_then(|c| c.default_hostname)
            .unwrap_or_else(crate::hostname::generate_hostname);
        let name = self
            .registry
            .direct_network_name(&my_host, req.hostname.as_deref());
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

    /// `ray connect <contact-id>`: resolve the contact to an endpoint, dial it
    /// over CONNECT_ALPN, and send a request. If approved immediately we join the
    /// minted direct network; if pending we retry on a backoff.
    pub(crate) async fn connect(
        self: &Arc<Self>,
        contact_id: &str,
        hostname: Option<String>,
    ) -> IpcMessage {
        let contact_pubkey = match contact_id.parse::<EndpointId>() {
            Ok(id) => id,
            Err(e) => {
                return ipc_err(format!("invalid contact id: {e}"));
            }
        };
        if contact_pubkey == self.transport.contact_public {
            return ipc_err("cannot connect to your own contact id".to_string());
        }
        let pkarr = match dht::create_pkarr_client(&self.transport.endpoint) {
            Ok(c) => c,
            Err(e) => {
                return ipc_err(format!("failed to create pkarr client: {e}"));
            }
        };
        let peer = match dht::resolve_contact(&pkarr, contact_pubkey).await {
            Ok(id) => id,
            Err(_) => {
                return ipc_err("contact offline or unknown (could not resolve contact id)"
                        .to_string());
            }
        };
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
            Ok(_) => ipc_err("unexpected response from contact".to_string()),
            Err(e) => {
                self.outgoing_connects.remove(&peer);
                ipc_err(format!("failed to reach contact: {e}"))
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
                from_contact_id: self.transport.contact_public,
                from_endpoint: self.transport.endpoint.id(),
                hostname,
            },
        )
        .await?;
        control::recv_framed::<control::ConnectMsg>(&mut recv).await
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
        if let IpcMessage::Joined { name, .. } = &resp
            && let Ok(Some(mut n)) = config::load_network(name)
        {
            n.direct = true;
            let _ = config::save_network(&n);
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
                    }) => {
                        match me.join_direct(room_id, coordinator, hostname.clone()).await {
                            IpcMessage::Joined { .. } | IpcMessage::Ok { .. } => {
                                tracing::info!(peer = %peer.fmt_short(), "direct connect join ok");
                            }
                            IpcMessage::Error { message } => {
                                tracing::warn!(peer = %peer.fmt_short(), error = %message, "direct connect join failed");
                            }
                            other => {
                                tracing::warn!(peer = %peer.fmt_short(), response = ?other, "direct connect join: unexpected response");
                            }
                        }
                        me.outgoing_connects.remove(&peer);
                        return;
                    }
                    Ok(control::ConnectMsg::Denied { reason }) => {
                        tracing::warn!(reason, peer = %peer.fmt_short(), "connect request denied");
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
                short_id: p.from_contact_id.fmt_short().to_string(),
                hostname: p.hostname.clone(),
                waiting_secs: now.saturating_duration_since(p.requested_at).as_secs(),
            })
            .collect();
        IpcMessage::PendingRequests { requests }
    }

    /// Decline a pending connection request by contact-id prefix.
    pub(crate) fn reject_connect(&self, id_prefix: &str) -> IpcMessage {
        let found = self
            .pending_connects
            .iter()
            .find(|p| {
                p.from_contact_id
                    .fmt_short()
                    .to_string()
                    .starts_with(id_prefix)
                    || p.from_contact_id.to_string().starts_with(id_prefix)
            })
            .map(|p| *p.key());
        match found {
            Some(peer) => {
                self.pending_connects.remove(&peer);
                IpcMessage::Ok {
                    message: format!("declined connection request '{id_prefix}'"),
                }
            }
            None => ipc_err(format!("no pending connection request matching '{id_prefix}'")),
        }
    }

    /// Rotate this node's contact key and, if the data plane is active, republish
    /// the contact record immediately so the new id resolves.
    pub(crate) async fn rotate_contact(&self) -> IpcMessage {
        let mut cfg = match config::load() {
            Ok(c) => c,
            Err(e) => {
                return ipc_err(format!("failed to load config: {e}"));
            }
        };
        let secret = config::rotate_contact_secret(&mut cfg);
        if let Err(e) = config::save_settings(&cfg) {
            return ipc_err(format!("failed to save config: {e}"));
        }
        if self.active.load(Ordering::SeqCst)
            && let Ok(client) = dht::create_pkarr_client(&self.transport.endpoint)
        {
            let _ = dht::publish_contact(&client, &secret, self.transport.endpoint.id()).await;
        }
        IpcMessage::ContactIdResponse {
            contact_id: secret.public().to_string(),
        }
    }

    /// `CONNECT_ALPN`: handle a `ray connect` friend request. Binds the request
    /// to the dialing identity, replies `Approved` if already accepted
    /// (idempotent), else queues it as `Pending` for `ray connections approve`.
    pub(crate) async fn accept_connect_request(&self, conn: Connection) {
        let pending = self.pending_connects.clone();
        let approved = self.approved_connects.clone();
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let request: control::ConnectMsg = match control::recv_framed(&mut recv).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read connect request");
                        return;
                    }
                };
                if let control::ConnectMsg::Request {
                    from_contact_id,
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
                        return;
                    }
                    // Already approved? Reply with the minted room id so
                    // a re-dialing requester joins it (idempotent).
                    let already = approved.get(&from_endpoint).map(|r| *r.value());
                    let reply = if let Some((room_id, coordinator)) = already {
                        control::ConnectMsg::Approved {
                            room_id,
                            coordinator,
                        }
                    } else {
                        pending.insert(
                            from_endpoint,
                            PendingConnect {
                                from_contact_id,
                                from_endpoint,
                                hostname,
                                requested_at: Instant::now(),
                            },
                        );
                        tracing::info!(from = %from_contact_id.fmt_short(), endpoint = %from_endpoint.fmt_short(), "connect request received");
                        control::ConnectMsg::Pending
                    };
                    if let Err(e) = control::send_framed(&mut send, &reply).await {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to send connect reply");
                        return;
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                } else {
                    tracing::warn!(peer = %remote_id.fmt_short(), "unexpected connect message type");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for connect");
            }
        }
    }
}
