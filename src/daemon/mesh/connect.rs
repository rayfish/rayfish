//! Direct-connection (`ray connect`) handlers for `MeshManager`, plus the shared
//! `store_and_publish_group` helper. Split out of `daemon/mod.rs`.

use super::super::*;

impl MeshManager {
    /// Name of a live direct (`ray connect`) network whose roster includes
    /// `peer`, if any, used to short-circuit duplicate connects.
    pub(crate) fn existing_direct_network_with(&self, peer: &EndpointId) -> Option<String> {
        self.registry.existing_direct_network_with(peer)
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
                    _ = me.shutdown_token.cancelled() => return,
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
                        me.connect.outgoing_connects.remove(&peer);
                        return;
                    }
                    Ok(control::ConnectMsg::Denied { reason }) => {
                        tracing::warn!(reason, peer = %peer.fmt_short(), "connect request denied");
                        me.connect.outgoing_connects.remove(&peer);
                        return;
                    }
                    _ => {} // Pending or transient error, keep retrying.
                }
            }
        });
    }

    /// `ray connect <contact-id>`: request a direct connection by contact id.
    pub(crate) async fn connect(
        self: &Arc<Self>,
        contact_id: &str,
        hostname: Option<String>,
    ) -> IpcMessage {
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
        self.connect.outgoing_connects.insert(peer);
        match self.send_connect_request(peer, hostname.clone()).await {
            Ok(control::ConnectMsg::Approved {
                room_id,
                coordinator,
            }) => {
                self.connect.outgoing_connects.remove(&peer);
                self.join_direct(room_id, coordinator, hostname).await
            }
            Ok(control::ConnectMsg::Pending) => {
                self.spawn_connect_retry(peer, hostname);
                IpcMessage::Ok {
                    message: "connect request sent — waiting for approval".to_string(),
                }
            }
            Ok(control::ConnectMsg::Denied { reason }) => {
                self.connect.outgoing_connects.remove(&peer);
                IpcMessage::Error {
                    message: format!("connection denied: {reason}"),
                }
            }
            Ok(_) => IpcMessage::Error {
                message: "unexpected response from contact".to_string(),
            },
            Err(e) => {
                self.connect.outgoing_connects.remove(&peer);
                IpcMessage::Error {
                    message: format!("failed to reach contact: {e}"),
                }
            }
        }
    }

    /// `ray connections`: list pending incoming connect requests.
    pub fn list_connections(&self) -> IpcMessage {
        self.connect.list_connections()
    }

    /// Decline a pending connect request: drop it without minting a network. The
    /// requester's retry loop eventually times out.
    pub fn reject_connect(&self, id_prefix: &str) -> IpcMessage {
        self.connect.reject_connect(id_prefix)
    }

    /// `ray connections approve <id>`: approve a pending connect request, minting
    /// a 2-peer network with the requester pre-approved.
    pub async fn approve_connection(&self, id_prefix: &str) -> IpcMessage {
        self.connect.approve_connection(id_prefix).await
    }

    /// `ray contact rotate`: replace this node's contact key. The old contact id
    /// stops resolving once its pkarr record expires (~5 min).
    pub(crate) async fn rotate_contact(&self) -> IpcMessage {
        self.connect.rotate_contact().await
    }

    /// Store the current group snapshot as a blob and re-publish the pkarr record
    /// so members reconcile the new membership (used after `ray accept`).
    pub(crate) async fn store_and_publish_group(&self, network: &str) {
        self.registry.store_and_publish_group(network).await
    }

    // -----------------------------------------------------------------------
    // File sharing
    // -----------------------------------------------------------------------
}
