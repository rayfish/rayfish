//! Direct-connection (`ray connect`) handlers for `DaemonState`, plus the shared
//! `store_and_publish_group` helper. Split out of `daemon/mod.rs`.

use super::super::*;

impl DaemonState {
    /// Name of a live direct (`ray connect`) network whose roster includes
    /// `peer`, if any — used to short-circuit duplicate connects.
    pub(crate) fn existing_direct_network_with(&self, peer: &EndpointId) -> Option<String> {
        let direct: HashSet<String> = config::load()
            .map(|c| {
                c.networks
                    .iter()
                    .filter(|n| n.direct)
                    .map(|n| n.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.networks.iter().find_map(|h| {
            if !direct.contains(h.key()) {
                return None;
            }
            let s = h.state.read().ok()?;
            let has = s.members.all().iter().any(|m| &m.identity == peer)
                || s.approved.all().iter().any(|a| &a.identity == peer);
            has.then(|| h.key().clone())
        })
    }

    /// Send a single connect request to `peer` over `CONNECT_ALPN` and return the
    /// reply.
    pub(crate) async fn send_connect_request(
        &self,
        peer: EndpointId,
        hostname: Option<String>,
    ) -> Result<control::ConnectMsg> {
        let conn =
            transport::connect_to_peer_with_alpn(&self.endpoint, peer, transport::CONNECT_ALPN)
                .await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        control::send_framed(
            &mut send,
            &control::ConnectMsg::Request {
                from_contact_id: self.contact_public,
                from_endpoint: self.endpoint.id(),
                hostname,
            },
        )
        .await?;
        control::recv_framed::<control::ConnectMsg>(&mut recv).await
    }

    /// Join an approved direct network and flag it `direct` in config so it shows
    /// as `[direct]` in `ray status`.
    pub(crate) async fn join_direct(
        self: &Arc<Self>,
        room_id: EndpointId,
        coordinator: EndpointId,
        hostname: Option<String>,
    ) -> IpcMessage {
        let resp = self
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

    /// Background retry loop for a connect request still `Pending`: re-dials the
    /// peer with backoff until it is `Approved` (then joins) or `Denied`.
    pub(crate) fn spawn_connect_retry(self: &Arc<Self>, peer: EndpointId, hostname: Option<String>) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut backoff = BACKOFF_INITIAL;
            loop {
                tokio::select! {
                    _ = me.shutdown_token.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                match me.send_connect_request(peer, hostname.clone()).await {
                    Ok(control::ConnectMsg::Approved {
                        room_id,
                        coordinator,
                    }) => {
                        let _ = me.join_direct(room_id, coordinator, hostname.clone()).await;
                        me.protocol_router.outgoing_connects.remove(&peer);
                        return;
                    }
                    Ok(control::ConnectMsg::Denied { reason }) => {
                        tracing::warn!(reason, peer = %peer.fmt_short(), "connect request denied");
                        me.protocol_router.outgoing_connects.remove(&peer);
                        return;
                    }
                    _ => {} // Pending or transient error — keep retrying.
                }
            }
        });
    }

    /// `ray connect <contact-id>`: request a direct connection by contact id.
    pub(crate) async fn connect(self: &Arc<Self>, contact_id: &str, hostname: Option<String>) -> IpcMessage {
        let contact_pubkey = match contact_id.parse::<EndpointId>() {
            Ok(id) => id,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("invalid contact id: {e}"),
                };
            }
        };
        if contact_pubkey == self.contact_public {
            return IpcMessage::Error {
                message: "cannot connect to your own contact id".to_string(),
            };
        }
        let pkarr = match dht::create_pkarr_client(&self.endpoint) {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to create pkarr client: {e}"),
                };
            }
        };
        let peer = match dht::resolve_contact(&pkarr, contact_pubkey).await {
            Ok(id) => id,
            Err(_) => {
                return IpcMessage::Error {
                    message: "contact offline or unknown (could not resolve contact id)"
                        .to_string(),
                };
            }
        };
        if let Some(name) = self.existing_direct_network_with(&peer) {
            return IpcMessage::Ok {
                message: format!("already connected to this peer on '{name}'"),
            };
        }
        self.protocol_router.outgoing_connects.insert(peer);
        match self.send_connect_request(peer, hostname.clone()).await {
            Ok(control::ConnectMsg::Approved {
                room_id,
                coordinator,
            }) => {
                self.protocol_router.outgoing_connects.remove(&peer);
                self.join_direct(room_id, coordinator, hostname).await
            }
            Ok(control::ConnectMsg::Pending) => {
                self.spawn_connect_retry(peer, hostname);
                IpcMessage::Ok {
                    message: "connect request sent — waiting for approval".to_string(),
                }
            }
            Ok(control::ConnectMsg::Denied { reason }) => {
                self.protocol_router.outgoing_connects.remove(&peer);
                IpcMessage::Error {
                    message: format!("connection denied: {reason}"),
                }
            }
            Ok(_) => IpcMessage::Error {
                message: "unexpected response from contact".to_string(),
            },
            Err(e) => {
                self.protocol_router.outgoing_connects.remove(&peer);
                IpcMessage::Error {
                    message: format!("failed to reach contact: {e}"),
                }
            }
        }
    }

    /// `ray connections`: list pending incoming connect requests.
    pub(crate) fn list_connections(&self) -> IpcMessage {
        let now = Instant::now();
        let requests = self
            .protocol_router
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

    /// Build a unique, valid network name for a direct connection from the two
    /// hostnames (e.g. `bob-alice`), resolving collisions against live networks.
    /// `my_host` is the minter's own hostname on the network, so the name and the
    /// minter's member hostname stay consistent.
    pub(crate) fn direct_network_name(&self, my_host: &str, peer_hostname: Option<&str>) -> String {
        let peer = peer_hostname.unwrap_or("peer");
        let mut base = format!("{my_host}-{peer}");
        if base.len() > 63 {
            base.truncate(63);
            base = base.trim_end_matches('-').to_string();
        }
        if !crate::hostname::is_valid_hostname(&base) {
            base = crate::network_name::generate_name();
        }
        let taken: Vec<String> = self.networks.iter().map(|h| h.key().clone()).collect();
        let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
        crate::hostname::resolve_collision(&base, &taken_refs)
    }

    /// `ray connections approve <id>`: approve a pending connect request, minting
    /// a 2-peer network with the requester pre-approved.
    pub(crate) async fn approve_connection(self: &Arc<Self>, id_prefix: &str) -> IpcMessage {
        let found = self
            .protocol_router
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
            return IpcMessage::Error {
                message: format!("no pending connection request matching '{id_prefix}'"),
            };
        };
        let peer = req.from_endpoint;

        // Idempotency: already linked on a direct network → reuse it.
        if let Some(name) = self.existing_direct_network_with(&peer) {
            self.protocol_router.pending_connects.remove(&peer);
            return IpcMessage::Ok {
                message: format!("already connected to this peer on '{name}'"),
            };
        }

        // Concurrency tie-break: if we also initiated a connect to this peer and
        // our endpoint id is the lower one, let the higher-id peer mint the
        // network; our own connect retry loop will join it.
        let we_initiated = self.protocol_router.outgoing_connects.contains(&peer);
        if we_initiated && self.endpoint.id().to_string() < peer.to_string() {
            self.protocol_router.pending_connects.remove(&peer);
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
        let name = self.direct_network_name(&my_host, req.hostname.as_deref());
        match self
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
                self.protocol_router.pending_connects.remove(&peer);
                self.protocol_router
                    .approved_connects
                    .insert(peer, (network_key, self.endpoint.id()));
                IpcMessage::Ok {
                    message: format!("approved — direct connection '{name}' created"),
                }
            }
            Ok(other) => other,
            Err(e) => IpcMessage::Error {
                message: format!("failed to create direct network: {e:#}"),
            },
        }
    }

    /// `ray contact rotate`: replace this node's contact key. The old contact id
    /// stops resolving once its pkarr record expires (~5 min).
    pub(crate) async fn rotate_contact(&self) -> IpcMessage {
        let mut cfg = match config::load() {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        };
        let secret = config::rotate_contact_secret(&mut cfg);
        if let Err(e) = config::save_settings(&cfg) {
            return IpcMessage::Error {
                message: format!("failed to save config: {e}"),
            };
        }
        // Publish the new record immediately if active.
        if self.active.load(Ordering::SeqCst)
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let _ = dht::publish_contact(&client, &secret, self.endpoint.id()).await;
        }
        IpcMessage::ContactIdResponse {
            contact_id: secret.public().to_string(),
        }
    }

    /// Store the current group snapshot as a blob and re-publish the pkarr record
    /// so members reconcile the new membership (used after `ray accept`).
    pub(crate) async fn store_and_publish_group(&self, network: &str) {
        let (hash, net_key, snap_bytes) = {
            let Some(handle) = self.networks.get(network) else {
                return;
            };
            let s = handle.state.read().unwrap();
            (
                s.snapshot.as_ref().map(|x| x.hash),
                s.network_secret_key.clone(),
                s.snapshot.as_ref().map(|x| x.msgpack_bytes.clone()),
            )
        };
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }
        if let (Some(hash), Some(key)) = (hash, net_key)
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let mut seed_peers: Vec<EndpointId> = self
                .peers
                .peers_for_network(network)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            seed_peers.push(self.endpoint.id());
            seed_peers.sort_by_key(|id| id.to_string());
            seed_peers.dedup();
            if let Err(e) = dht::publish_network(&client, &key, &hash, &seed_peers).await {
                tracing::warn!(error = %e, "failed to publish network record after accept");
            }
        }
    }


    // -----------------------------------------------------------------------
    // File sharing
    // -----------------------------------------------------------------------

}
