//! `MeshConnection`: one live mesh connection, driven for its whole lifetime.
//!
//! Built by [`ConnectionManager::drive_mesh_connection`] on both the accept and
//! dial paths. It owns **both planes** of the connection: the control-plane demux
//! loop (this file's `run`) and the single data-plane reader
//! (`forward::spawn_peer_reader`), which it spawns on entry and tears down on
//! exit. When the connection closes, `run` is the one place that reports the
//! [`forward::DisconnectEvent`] to the supervisor, so there is exactly one report
//! per dropped connection and no data/control race over who reports.

use iroh::endpoint::ConnectionError;

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
    pre_registered: bool,
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
            pre_registered,
        }
    }

    /// Drive the connection for its whole life: spawn the single data reader, then
    /// loop accepting control streams and routing each `ControlFrame` to the right
    /// per-network handler by `net`, or handling connection-level messages
    /// (`NetworkHandles`, `Ping`/`Pong`, `Unpaired`, `CertRefresh`) inline. On any
    /// exit that isn't daemon shutdown, stop the reader and, if this connection was
    /// ever a registered member, report the drop to the supervisor.
    pub(crate) async fn run(mut self) {
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

        loop {
            let accepted = tokio::select! {
                // Daemon shutdown: drop the reader and leave without reporting a
                // disconnect (the peer isn't gone, we are).
                _ = self.token.cancelled() => {
                    reader.abort();
                    return;
                }
                r = self.conn.accept_bi() => r,
            };
            let (send, mut recv) = match accepted {
                Ok(pair) => pair,
                // Connection closed. Tear down the reader and report the drop.
                Err(e) => {
                    reader.abort();
                    if registered {
                        self.report_disconnect(close_reason(&e)).await;
                    }
                    return;
                }
            };
            let frame = match control::recv_frame(&mut recv).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            // Control traffic counts as activity, so a connection mid control
            // exchange (e.g. a coordinator pushing roster updates) isn't idle-reaped.
            self.ctx.peers.note_activity_by_id(&self.peer_id);
            match self.gate.check() {
                crate::ratelimit::Verdict::Allow => {}
                crate::ratelimit::Verdict::Drop => continue,
                crate::ratelimit::Verdict::Close => {
                    tracing::warn!(peer = %self.peer_id.fmt_short(), "control-plane flood; closing connection");
                    self.conn
                        .close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                    reader.abort();
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
                ControlMsg::NetworkHandles { entries } => {
                    self.manager.apply_network_handles(self.peer_id, entries);
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
                ControlMsg::Unpaired => {
                    // Our primary is unpairing this device. Act only if the sender
                    // actually signed our cert (a stranger is a no-op). Leaving
                    // every network is heavy, so spawn it off the demux loop rather
                    // than awaiting inline.
                    if is_unpaired_by(self.peer_id) {
                        let registry = self.ctx.registry.clone();
                        tokio::spawn(async move {
                            let _ = registry.unpair_self().await;
                        });
                    }
                    continue;
                }
                ControlMsg::CertRefresh { cert } => {
                    // Our primary rotated and re-issued us; verified inside against
                    // our own cert (signer + device key + generation).
                    store_refreshed_cert(cert);
                    continue;
                }
                ControlMsg::RequestUnpair => {
                    // A paired secondary is unpairing itself and asks us (its
                    // primary) to write the authoritative nullifier. Act only if we
                    // are a primary (hold the network keys); `nullify_device`
                    // rejects a requester that is not one of our paired devices, so
                    // a stranger is a no-op. Off the demux loop: republish + prune
                    // is heavy.
                    if self.ctx.registry.current_device_cert().is_none() {
                        let registry = self.ctx.registry.clone();
                        let requester = self.peer_id;
                        tokio::spawn(async move {
                            if let Err(reason) = registry.nullify_device(requester).await {
                                tracing::debug!(peer = %requester.fmt_short(), %reason, "ignoring unpair request");
                            }
                        });
                    }
                    continue;
                }
                _ => {}
            }
            let Some(net_pubkey) = frame.net else {
                continue;
            };
            let Some(handler) = self.manager.handler_for(&net_pubkey) else {
                tracing::debug!(peer = %self.peer_id.fmt_short(), net = %net_pubkey.fmt_short(), "control frame for unknown network; ignoring");
                continue;
            };
            drop(recv); // one message per stream; the reply rides `send`
            // `handle_frame` registers the peer (route) as a side effect and
            // returns its mesh v4 once it is a member on this network.
            if let Some(ip) = handler
                .handle_frame(&self.conn, send, self.peer_id, frame.msg)
                .await
            {
                // The peer is now a member on this network, so this connection is
                // registered: a later drop must be reported.
                registered = true;
                // (Re)announce our outbound handle table so the peer can decode
                // datagrams we tag for this (possibly newly-shared) network.
                announce_network_handles(&self.ctx.peers, &self.conn, ip).await;
            }
        }
    }

    /// Report this connection's drop to the daemon-wide supervisor. The peer's
    /// collision-aware v4 comes from its roster entry (falling back to the index-0
    /// derivation if it was pruned already); `conn_stable_id` lets the supervisor's
    /// ABA guard ignore this event if the peer has since reconnected.
    async fn report_disconnect(&self, reason: forward::CloseReason) {
        let ip = self
            .ctx
            .peers
            .v4_for_id(&self.peer_id)
            .unwrap_or_else(|| crate::membership::derive_ip(&self.peer_id));
        let ipv6 = crate::membership::derive_ipv6(&self.peer_id);
        tracing::warn!(peer = %self.peer_id.fmt_short(), ip = %ip, reason = ?reason, "peer connection lost");
        let _ = self
            .ctx
            .disconnect_tx
            .send(forward::DisconnectEvent {
                endpoint_id: self.peer_id,
                ip,
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
