//! `ConnectionManager`: the per-peer mesh connection driver, in the daemon
//! dependency graph.
//!
//! With one QUIC connection per peer (not one per peer per network),
//! `drive_mesh_connection` builds one [`MeshConnection`] per connection and runs
//! it for the connection's whole lifetime: it demuxes each
//! [`control::ControlFrame`] to the per-network handler named by `frame.net`,
//! handles connection-level messages (`NetworkHandles`, `Ping`/`Pong`,
//! `Unpaired`, `CertRefresh`) inline, and owns the connection's single data
//! reader (which forwards datagrams to the TUN via `tun_tx`).
//!
//! `ConnectionManager` owns the per-network handler registry (keyed by network
//! public key) and the in-flight `ray ping` probe map. [`ProtocolRouter`] (the
//! ALPN entry dispatcher) holds an `Arc<ConnectionManager>` and delegates the
//! mesh ALPN to it; the other ALPNs go to `FileService`/`ConnectService`/blobs.

use super::*;

/// Daemon-wide dispatch context the driver needs: the shared handles (`ctx`
/// carries `tun_tx` + the disconnect sender a [`MeshConnection`] uses to report a
/// drop) plus the cancellation token. Set once after construction via a
/// `OnceLock`, because the router/connection-manager are built before the daemon
/// that owns the ctx.
pub(crate) struct MeshDispatch {
    pub(crate) ctx: MeshCtx,
    pub(crate) token: CancellationToken,
    /// Fired once per mesh connection as it starts (dialed or accepted), with
    /// the peer's id. Wired by the composition root to the file-service send
    /// outbox, which delivers queued offers the moment their peer reappears;
    /// the manager stays ignorant of who listens.
    pub(crate) on_peer_connected: Arc<dyn Fn(EndpointId) + Send + Sync>,
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
    /// `Daemon` right after it is built.
    /// Invoke the composition-root peer-connected hook (no-op before dispatch
    /// is installed). Called by each `MeshConnection` as its run loop starts.
    pub(crate) fn notify_peer_connected(&self, peer: EndpointId) {
        if let Some(mesh) = self.mesh.get() {
            (mesh.on_peer_connected)(peer);
        }
    }

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

    /// Drive one mesh connection (single mesh ALPN) for its whole lifetime. Builds
    /// the per-connection [`MeshConnection`] from the daemon-wide dispatch and runs
    /// its demux loop. Shared by the accept side (`pre_registered = false`, the peer
    /// registers as membership frames land) and the dial side (`pre_registered =
    /// true`, the caller already registered the peer before driving the demux).
    pub(crate) async fn drive_mesh_connection(
        self: Arc<Self>,
        conn: Connection,
        pre_registered: bool,
    ) {
        let Some(mesh) = self.mesh.get() else {
            tracing::error!("mesh dispatch not set; dropping connection");
            return;
        };
        MeshConnection::new(
            conn,
            self.clone(),
            mesh.ctx.clone(),
            mesh.token.clone(),
            pre_registered,
        )
        .run()
        .await;
    }

    /// Apply a peer's announced `NetworkHandles` (its handle → network decode
    /// table) so our data reader can resolve inbound datagram tags. Stores the
    /// table on the peer's registered mesh IPs (falling back to the index-0
    /// derivation if it isn't registered yet).
    pub(crate) fn apply_network_handles(
        &self,
        peer_id: EndpointId,
        entries: &[control::NetworkHandle],
    ) {
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
