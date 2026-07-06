//! `ConnectionManager`: the per-peer mesh connection driver, in the daemon
//! dependency graph.
//!
//! With one QUIC connection per peer (not one per peer per network), a single
//! id-keyed reader drives each mesh connection for its whole lifetime: it accepts
//! control streams, demuxes each [`control::ControlFrame`] to the per-network
//! handler named by `frame.net`, and handles connection-level messages
//! (`NetworkHandles`, `Ping`/`Pong`, `Unpaired`, `CertRefresh`) inline. Data
//! frames reach the TUN via the per-peer reader spawned as a side effect of the
//! first network registration (`MeshCtx::register_peer_conn`, which owns
//! `tun_tx`).
//!
//! `ConnectionManager` owns the per-network handler registry (keyed by network
//! public key) and the in-flight `ray ping` probe map. [`ProtocolRouter`] (the
//! ALPN entry dispatcher) holds an `Arc<ConnectionManager>` and delegates the
//! mesh ALPN to it; the other ALPNs go to `FileService`/`ConnectService`/blobs.

use super::*;

/// Daemon-wide dispatch context the driver needs: the shared handles (`ctx`
/// carries `tun_tx` + the disconnect sender used to build per-peer readers) plus
/// the cancellation token. Set once after construction via a `OnceLock`, because
/// the router/connection-manager are built before the daemon that owns the ctx.
pub(crate) struct MeshDispatch {
    pub(crate) ctx: MeshCtx,
    pub(crate) token: CancellationToken,
}

pub(crate) struct ConnectionManager {
    /// Per-network mesh accept handlers, keyed by network **public key**. A single
    /// mesh connection may carry several of these (the peer shares several
    /// networks); the driver routes each control frame to the handler named by
    /// `ControlFrame.net`.
    handlers: DashMap<EndpointId, AcceptHandler>,
    /// In-flight `ray ping` probes, keyed by nonce. The driver fires the oneshot
    /// when the matching `Pong` arrives so the ping handler can measure RTT.
    pub(crate) pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
    /// Set once after construction; see [`MeshDispatch`].
    mesh: std::sync::OnceLock<MeshDispatch>,
}

impl ConnectionManager {
    pub(crate) fn new() -> Self {
        Self {
            handlers: DashMap::new(),
            pending_pongs: Arc::new(DashMap::new()),
            mesh: std::sync::OnceLock::new(),
        }
    }

    /// Install the daemon-wide mesh dispatch context. Called once by
    /// `MeshManager` right after it is built.
    pub(crate) fn set_mesh_dispatch(&self, dispatch: MeshDispatch) {
        let _ = self.mesh.set(dispatch);
    }

    /// Register a network's accept handler under its public key.
    pub(crate) fn register(&self, net_pubkey: EndpointId, handler: AcceptHandler) {
        self.handlers.insert(net_pubkey, handler);
    }

    /// Whether a handler is registered for this network public key.
    pub(crate) fn is_registered(&self, net_pubkey: &EndpointId) -> bool {
        self.handlers.contains_key(net_pubkey)
    }

    pub(crate) fn unregister(&self, net_pubkey: &EndpointId) {
        self.handlers.remove(net_pubkey);
    }

    /// Look up a network's handler by public key.
    pub(crate) fn handler_for(&self, net_pubkey: &EndpointId) -> Option<AcceptHandler> {
        self.handlers.get(net_pubkey).map(|h| h.value().clone())
    }

    /// Drive one mesh connection (single mesh ALPN) for its whole lifetime. Spawns
    /// the connection's single data reader on first network registration, then
    /// loops accepting control streams and routing each `ControlFrame` to the
    /// right per-network handler by `net`, or handling connection-level messages
    /// (`NetworkHandles`, `Ping`/`Pong`) inline. Shared by the accept side and the
    /// dial side (`MeshManager::drive_dialed_connection`).
    pub(crate) async fn drive_mesh_connection(self: Arc<Self>, conn: Connection) {
        let peer_id = conn.remote_id();
        let Some(mesh) = self.mesh.get() else {
            tracing::error!("mesh dispatch not set; dropping connection");
            return;
        };
        let token = mesh.token.clone();
        let mut gate = crate::ratelimit::ControlGate::new();
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => return,
                r = conn.accept_bi() => r,
            };
            let (send, mut recv) = match accepted {
                Ok(pair) => pair,
                Err(_) => return, // connection closed; the data reader emits the disconnect
            };
            let frame = match control::recv_frame(&mut recv).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            match gate.check() {
                crate::ratelimit::Verdict::Allow => {}
                crate::ratelimit::Verdict::Drop => continue,
                crate::ratelimit::Verdict::Close => {
                    tracing::warn!(peer = %peer_id.fmt_short(), "control-plane flood; closing connection");
                    conn.close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                    return;
                }
            }
            // Connection-level messages (not scoped to a network).
            match &frame.msg {
                ControlMsg::NetworkHandles { entries } => {
                    self.apply_network_handles(peer_id, entries);
                    continue;
                }
                ControlMsg::Ping { nonce } => {
                    respond_pong(&conn, *nonce).await;
                    continue;
                }
                ControlMsg::Pong { nonce } => {
                    if let Some((_, tx)) = self.pending_pongs.remove(nonce) {
                        let _ = tx.send(());
                    }
                    continue;
                }
                ControlMsg::Unpaired => {
                    // Our primary is unpairing this device. Act only if the sender
                    // actually signed our cert (a stranger is a no-op). Leaving
                    // every network is heavy, so spawn it off the demux loop rather
                    // than awaiting inline.
                    if is_unpaired_by(peer_id) {
                        let registry = mesh.ctx.registry.clone();
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
                _ => {}
            }
            let Some(net_pubkey) = frame.net else {
                continue;
            };
            let Some(handler) = self.handler_for(&net_pubkey) else {
                tracing::debug!(peer = %peer_id.fmt_short(), net = %net_pubkey.fmt_short(), "control frame for unknown network; ignoring");
                continue;
            };
            drop(recv); // one message per stream; the reply rides `send`
            // `handle_frame` registers the peer (route + data reader) as a side
            // effect and returns its mesh v4 once it is a member on this network.
            if let Some(ip) = handler.handle_frame(&conn, send, peer_id, frame.msg).await {
                // (Re)announce our outbound handle table so the peer can decode
                // datagrams we tag for this (possibly newly-shared) network.
                announce_network_handles(&mesh.ctx.peers, &conn, ip).await;
            }
        }
    }

    /// Apply a peer's announced `NetworkHandles` (its handle → network decode
    /// table) so our data reader can resolve inbound datagram tags. Stores the
    /// table on the peer's registered mesh IPs (falling back to the index-0
    /// derivation if it isn't registered yet).
    fn apply_network_handles(&self, peer_id: EndpointId, entries: &[control::NetworkHandle]) {
        let Some(mesh) = self.mesh.get() else { return };
        let ip = mesh
            .ctx
            .peers
            .v4_for_id(&peer_id)
            .unwrap_or_else(|| mesh.ctx.identity.derive_ip(&peer_id));
        let ipv6 = derive_ipv6(&peer_id);
        // Map network pubkey → local network name via the registry.
        let mut table: Vec<(u16, SmolStr)> = Vec::new();
        for e in entries {
            if let Some(h) = self.handlers.get(&e.network)
                && let Some(name) = h.network_name()
            {
                table.push((e.handle, SmolStr::new(name)));
            }
        }
        mesh.ctx.peers.set_inbound_handles(&ip, &ipv6, &table);
    }
}
