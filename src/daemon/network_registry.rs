//! `NetworkRegistry`: the service that owns the set of active networks.
//!
//! This is the seam that the `MeshManager` network methods (create / join /
//! leave / coordinator / reconverge / …) migrate onto over the course of the
//! decomposition. It owns the per-network runtime handles keyed by name; during
//! the transition it shares the same `Arc<DashMap>` the daemon still holds, so
//! methods can move here one at a time while the tree stays green.
//!
//! It is a control-plane service: never on the packet path. Membership queries
//! (like the file auto-accept gate) and the coordinator/member operations live
//! here so leaf tasks and other services can call them directly instead of
//! signalling the daemon through a channel.

use super::*;

pub(crate) struct NetworkRegistry {
    /// Per-network runtime handles, keyed by network name. Shared with
    /// `MeshManager` during the transition (same `Arc`), so a method can move to
    /// the registry without splitting the map.
    networks: Arc<DashMap<String, NetworkHandle>>,
    /// Foundation handles (endpoint + blob store) for reseal/publish.
    transport: Arc<Transport>,
    /// Live peer routing table, for severing / notifying peers on roster change.
    peers: PeerTable,
    /// The per-peer connection driver, so the registry can (re-)register a
    /// network's accept handler (coordinator promotion) or unregister it on
    /// teardown directly.
    conn: Arc<ConnectionManager>,
    /// Magic-DNS service, to clear a torn-down network's `.ray` entries.
    dns: Arc<DnsService>,
    /// The TUN interface name, shared with the daemon (which sets it once the TUN
    /// is up), for refreshing DNS search domains after a network is torn down.
    tun_name: Arc<Mutex<String>>,
    /// This device's cert loaded at boot, the in-memory fallback for the paired
    /// check when the on-disk cert read errors (see [`Self::current_device_cert`]).
    device_cert: Option<control::DeviceCert>,
}

impl NetworkRegistry {
    pub(crate) fn new(
        networks: Arc<DashMap<String, NetworkHandle>>,
        transport: Arc<Transport>,
        peers: PeerTable,
        conn: Arc<ConnectionManager>,
        dns: Arc<DnsService>,
        tun_name: Arc<Mutex<String>>,
        device_cert: Option<control::DeviceCert>,
    ) -> Self {
        Self {
            networks,
            transport,
            peers,
            conn,
            dns,
            tun_name,
            device_cert,
        }
    }

    /// This device's pairing cert. The on-disk cert is authoritative: a cleanly
    /// absent file (`Ok(None)`, e.g. after `unpair_self` deletes it) means
    /// unpaired, so only a genuine read error falls back to the in-memory copy.
    fn current_device_cert(&self) -> Option<control::DeviceCert> {
        match identity::load_device_cert() {
            Ok(cert) => cert,
            Err(_) => self.device_cert.clone(),
        }
    }

    /// Unpair *this* device from its primary, locally: leave every network this
    /// device joined (graceful `LEAVE_CODE` close so peers prune us at once),
    /// purge any saved-but-inactive network configs, then delete the stored cert.
    /// Called by the phone's unpair control, the IPC path, and the device-side
    /// `ControlMsg::Unpaired` / self-nullify handlers (was the `self_unpair_tx`
    /// hand-off to the daemon loop). A device with no cert (a primary) is a no-op.
    pub(crate) async fn unpair_self(&self) -> IpcMessage {
        if self.current_device_cert().is_none() {
            return IpcMessage::Error {
                message: "this device is not paired to a primary".to_string(),
            };
        }
        // Leave every live network first (graceful close + config removal).
        let networks: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        for net in &networks {
            self.leave_network(net).await;
        }
        // Purge saved-but-inactive network configs too: a device unpaired while
        // offline discovers this at startup restore, before its networks are added
        // to `self.networks` (the join bails on the nullifier check first), so the
        // loop above sees none yet the config files remain and would make the node
        // churn trying to rejoin networks it was removed from.
        if let Ok(cfg) = config::load() {
            for net in &cfg.networks {
                let _ = config::delete_network(&net.name);
            }
        }
        match crate::identity::delete_device_cert() {
            Ok(()) => tracing::warn!("unpaired this device: deleted device certificate and left all networks"),
            Err(e) => {
                tracing::warn!(error = %e, "unpair: failed to delete device cert");
                return IpcMessage::Error {
                    message: format!("left all networks but failed to delete device cert: {e}"),
                };
            }
        }
        IpcMessage::Ok {
            message: format!("unpaired this device (left {} network(s))", networks.len()),
        }
    }

    /// Tear down a network's runtime: cancel its tasks, drop its peers + `.ray`
    /// entries, unregister its accept handler, and refresh DNS search domains.
    /// Returns whether the network was actually active. The mesh ALPN set is
    /// static, so (unlike the old `refresh_alpns`) only the search domains need
    /// updating here.
    pub(crate) async fn teardown_network_runtime(&self, name: &str) -> bool {
        let Some(handle) = self.networks.remove(name).map(|(_, v)| v) else {
            return false;
        };
        handle.cancel.cancel();
        for task in handle.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }

        self.peers.remove_by_network(name);
        self.dns.clear_network(name).await;
        self.conn.unregister(&handle.network_key);
        self.refresh_search_domains().await;
        true
    }

    /// Re-derive the OS DNS search domains from the currently-joined networks.
    /// Split out of the daemon's `refresh_alpns` (whose ALPN half is a no-op now
    /// the mesh ALPN is static) for the teardown path.
    async fn refresh_search_domains(&self) {
        let network_names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        let tun_name = self.tun_name.lock().unwrap().clone();
        dns_config::update_search_domains(&network_names, &tun_name).await;
    }

    /// Leave a network: gracefully close our connections with the leave code (so
    /// peers see an intentional departure and prune us), tear down the runtime,
    /// and remove it from config.
    pub(crate) async fn leave_network(&self, name: &str) -> IpcMessage {
        for (_eid, _ip, conn) in self.peers.peers_for_network_with_conn(name) {
            conn.close(VarInt::from_u32(forward::LEAVE_CODE), b"leave");
        }

        let was_active = self.teardown_network_runtime(name).await;
        let removed_from_config = config::delete_network(name).unwrap_or(false);

        if was_active || removed_from_config {
            tracing::info!(network = %name, "left network");
            IpcMessage::Ok {
                message: format!("left network '{}'", name),
            }
        } else {
            IpcMessage::Error {
                message: format!("network '{}' not found", name),
            }
        }
    }

    /// Whether a network by this name is currently active (in the live map).
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.networks.contains_key(name)
    }

    /// Resolve a peer name (hostname, `host.net.ray`, or mesh IPv4) to its
    /// endpoint id: Magic DNS + connected-peer route first, then the member
    /// roster (offline peers / self), then a short-id / endpoint-id prefix scan.
    pub(crate) async fn resolve_peer_name(&self, name: &str) -> Option<EndpointId> {
        let suffix = format!(".{}", crate::DNS_DOMAIN);
        let qualified = if name.ends_with(&suffix) {
            name.to_string()
        } else {
            format!("{name}{suffix}")
        };
        if let Some((ip, _)) = self.dns.resolve(&qualified, &suffix).await {
            if let Some(route) = self.peers.lookup_v4(&ip) {
                return Some(route.endpoint_id);
            }
            for entry in self.networks.iter() {
                let state = entry.value().state.read().unwrap();
                if let Some(m) = state.members.all().iter().find(|m| m.ip == ip) {
                    return Some(m.identity);
                }
            }
        }
        self.resolve_short_id_any_network(name)
    }

    /// Resolve a firewall `--peer` argument to a peer's **device** endpoint id,
    /// accepting more forms than [`Self::resolve_peer_name`]: hostname, mesh IPv4
    /// (incl. offline members from the roster), mesh IPv6 (connected peers only),
    /// short / full endpoint id, or a paired user identity.
    pub(crate) async fn resolve_peer_flexible(&self, name: &str) -> Option<EndpointId> {
        if let Some(id) = self.resolve_peer_name(name).await {
            return Some(id);
        }
        if let Ok(v4) = name.parse::<Ipv4Addr>()
            && let Some(route) = self.peers.lookup_v4(&v4)
        {
            return Some(route.endpoint_id);
        }
        if let Ok(v6) = name.parse::<std::net::Ipv6Addr>()
            && let Some(route) = self.peers.lookup_v6(&v6)
        {
            return Some(route.endpoint_id);
        }
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(id) = state.members.resolve_peer_literal(name) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve `"self"` or a short / prefix endpoint id against every network's
    /// roster to a full endpoint id.
    pub(crate) fn resolve_short_id_any_network(&self, short: &str) -> Option<EndpointId> {
        if short == "self" {
            return Some(self.transport.endpoint.id());
        }
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(m) = state
                .members
                .all()
                .iter()
                .find(|m| m.identity.to_string().starts_with(short))
            {
                return Some(m.identity);
            }
        }
        None
    }

    /// Whether `identity` is a current member of at least one network that has
    /// file auto-accept enabled. Backs the own-device file auto-accept gate.
    pub(crate) fn member_on_autoaccept_network(&self, identity: EndpointId) -> bool {
        for entry in self.networks.iter() {
            let enabled = config::load_network(entry.key())
                .ok()
                .flatten()
                .map(|nc| nc.auto_accept_files)
                .unwrap_or(false);
            if !enabled {
                continue;
            }
            let is_member = entry
                .value()
                .state
                .read()
                .map(|s| s.members.all().iter().any(|m| m.identity == identity))
                .unwrap_or(false);
            if is_member {
                return true;
            }
        }
        false
    }

    /// Register (or replace) `network`'s accept handler with a
    /// [`CoordinatorAcceptState`], so any node holding the network key admits
    /// fresh joiners instead of dropping their `JoinRequest`s. The daemon-wide
    /// `ctx` (identical for every network) is supplied by the caller: the daemon
    /// passes `self.mesh_ctx()`, a promoting control reader passes its own `ctx`.
    /// Also flips the stored role so `ray status` reports Coordinator at once.
    #[allow(clippy::too_many_arguments)] // the params are the handler's own fields
    pub(crate) fn register_coordinator_handler(
        &self,
        ctx: &MeshCtx,
        network: &str,
        state: SharedNetworkState,
        invite_lock: Arc<tokio::sync::Mutex<()>>,
        dht_notify: Option<Arc<Notify>>,
        network_key: EndpointId,
        cancel: CancellationToken,
    ) {
        self.conn.register(
            network_key,
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                ctx: ctx.clone(),
                network_name: network.to_string(),
                state,
                token: cancel,
                dht_notify,
                invite_lock,
            })),
        );
        if let Some(mut handle) = self.networks.get_mut(network) {
            handle.role = NetworkRole::Coordinator;
        }
    }

    /// Swap a live member to a coordinator accept handler after it is granted the
    /// per-network key (via `AdminGrant`), so it can admit fresh joiners. Called
    /// directly by the granted member's control reader (was the `promote_tx`
    /// hand-off to the daemon loop). Idempotent: a network already coordinating is
    /// left untouched ([`should_promote`]). No `refresh_alpns` is needed: the mesh
    /// ALPN is static and promotion adds no network, so the advertised set and the
    /// DNS search domains are unchanged.
    pub(crate) fn promote_to_coordinator(&self, ctx: &MeshCtx, network: &str) {
        let parts = {
            let Some(h) = self.networks.get(network) else {
                return;
            };
            if !should_promote(h.role.clone()) {
                return;
            }
            (
                h.state.clone(),
                h.invite_lock.clone(),
                h.dht_notify.clone(),
                h.network_key,
                h.cancel.clone(),
            )
        }; // DashMap ref dropped before the registration below.
        self.register_coordinator_handler(
            ctx, network, parts.0, parts.1, parts.2, parts.3, parts.4,
        );
        tracing::info!(network, "promoted to coordinator accept handler");
    }

    /// Clear a re-paired device's nullifier (the inverse of `unpair`). Invoked
    /// directly by the pairing accept arm when it re-authorizes a device: drops
    /// it from the durable `revoked_devices` seed and from every coordinated
    /// network's blob nullifier set, republishing so the device's fresh cert is
    /// honored mesh wide again. Non-coordinated networks clear on their own
    /// coordinator's next reseal. Best-effort; a persist/publish failure is
    /// logged, not surfaced.
    pub(crate) async fn reauth_device(&self, device: EndpointId) {
        // Drop from the durable nullifier seed so a later reseal won't re-add it.
        let mut cfg = config::load().unwrap_or_default();
        let hex = device.to_string();
        if let Some(pos) = cfg.revoked_devices.iter().position(|d| *d == hex) {
            cfg.revoked_devices.remove(pos);
            if let Err(e) = config::save_settings(&cfg) {
                tracing::warn!(error = %e, "reauth: failed to clear device from nullifier seed");
            }
        }
        // Collect coordinated networks (clone the handles) before awaiting.
        let mut nets: Vec<(String, SharedNetworkState, Option<Arc<Notify>>)> = Vec::new();
        for entry in self.networks.iter() {
            if entry.value().state.read().unwrap().network_secret_key.is_some() {
                nets.push((
                    entry.key().clone(),
                    entry.value().state.clone(),
                    entry.value().dht_notify.clone(),
                ));
            }
        }
        let mut changed = false;
        for (net, state, dht_notify) in nets {
            let removed = {
                let mut s = state.write().unwrap();
                s.nullifiers.remove(&device)
            };
            if removed {
                changed = true;
                update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
                let net_pubkey = state.read().unwrap().network_public_key;
                broadcast_member_sync(&self.peers, net_pubkey, &net, None).await;
            }
        }
        if changed {
            tracing::info!(device = %device.fmt_short(), "re-authorized device (cleared nullifier)");
        }
    }
}
