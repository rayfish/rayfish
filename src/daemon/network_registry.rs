//! `NetworkRegistry`: the service that owns the set of active networks.
//!
//! This is the seam that the `Daemon` network methods (create / join /
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
use arc_swap::ArcSwap;
use std::sync::OnceLock;

pub(crate) struct NetworkRegistry {
    /// Per-network runtime handles, keyed by network name. Shared with
    /// `Daemon` during the transition (same `Arc`), so a method can move to
    /// the registry without splitting the map.
    // Fields are `pub(crate)` because the network methods migrating onto the
    // registry live in their existing `daemon/mesh/*.rs` files (as `impl
    // NetworkRegistry` blocks), which are sibling modules and so cannot see
    // module-private fields. Mirrors how `Daemon`'s fields are reached.
    pub(crate) networks: Arc<DashMap<String, NetworkHandle>>,
    /// Foundation handles (endpoint + blob store) for reseal/publish.
    pub(crate) transport: Arc<Transport>,
    /// Live peer routing table, for severing / notifying peers on roster change.
    pub(crate) peers: PeerTable,
    /// The per-peer connection driver, so the registry can (re-)register a
    /// network's accept handler (coordinator promotion) or unregister it on
    /// teardown directly.
    pub(crate) conn: Arc<ConnectionManager>,
    /// Magic-DNS service, to clear a torn-down network's `.ray` entries.
    pub(crate) dns: Arc<DnsService>,
    /// The TUN interface name, shared with the daemon (which sets it once the TUN
    /// is up), for refreshing DNS search domains after a network is torn down.
    pub(crate) tun_name: Arc<ArcSwap<String>>,
    /// This device's cert loaded at boot, the in-memory fallback for the paired
    /// check when the on-disk cert read errors (see [`Self::current_device_cert`]).
    pub(crate) device_cert: Option<control::DeviceCert>,
    /// Daemon-wide shutdown token; each network's cancel is a child of it.
    pub(crate) shutdown_token: CancellationToken,
    /// Per-device firewall, threaded into the [`MeshCtx`] handler bundle.
    pub(crate) firewall: SharedFirewall,
    /// Transport-key -> user-identity map, threaded into the [`MeshCtx`] bundle.
    pub(crate) device_user_map: peers::DeviceUserMap,
    /// Sender to the single TUN writer, threaded into peer readers via [`MeshCtx`].
    pub(crate) tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
    /// Roster-pruned peers to skip on reconnect (see [`MeshCtx::pruned_peers`]).
    pub(crate) pruned_peers: Arc<DashSet<(String, EndpointId)>>,
    /// Daemon-wide disconnect channel drained by the connection supervisor.
    pub(crate) disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    /// The inbound QUIC router, needed to drive a freshly (re)dialed connection's
    /// control demux. Built after the registry (it depends on FileService /
    /// ConnectService, which depend on the registry), so it is set once at boot
    /// via [`Self::set_protocol_router`] rather than passed to `new`.
    protocol_router: OnceLock<Arc<ProtocolRouter>>,
}

impl NetworkRegistry {
    #[allow(clippy::too_many_arguments)] // one clone per shared daemon handle
    pub(crate) fn new(
        networks: Arc<DashMap<String, NetworkHandle>>,
        transport: Arc<Transport>,
        peers: PeerTable,
        conn: Arc<ConnectionManager>,
        dns: Arc<DnsService>,
        tun_name: Arc<ArcSwap<String>>,
        device_cert: Option<control::DeviceCert>,
        shutdown_token: CancellationToken,
        firewall: SharedFirewall,
        device_user_map: peers::DeviceUserMap,
        tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
        pruned_peers: Arc<DashSet<(String, EndpointId)>>,
        disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    ) -> Self {
        Self {
            networks,
            transport,
            peers,
            conn,
            dns,
            tun_name,
            device_cert,
            shutdown_token,
            firewall,
            device_user_map,
            tun_tx,
            pruned_peers,
            disconnect_tx,
            protocol_router: OnceLock::new(),
        }
    }

    /// Install the inbound QUIC router. Called once at boot after the router is
    /// built; the network (re)connect paths use it to drive a dialed connection's
    /// control demux.
    pub(crate) fn set_protocol_router(&self, router: Arc<ProtocolRouter>) {
        let _ = self.protocol_router.set(router);
    }

    /// The inbound QUIC router (panics if used before [`Self::set_protocol_router`]).
    pub(crate) fn protocol_router(&self) -> &Arc<ProtocolRouter> {
        self.protocol_router
            .get()
            .expect("protocol_router set at boot")
    }

    /// Build the [`MeshCtx`] handler bundle from the registry's own handles. This
    /// is the same bundle `Daemon::mesh_ctx` produces; relocating the builder
    /// here lets the network methods (create/join/coordinator spawn) assemble it
    /// themselves instead of taking it as a threaded-in argument.
    pub(crate) fn mesh_ctx(self: &Arc<Self>) -> MeshCtx {
        MeshCtx {
            identity: self.transport.identity.clone(),
            peers: self.peers.clone(),
            tun_tx: self.tun_tx.clone(),
            stats: self.transport.stats.clone(),
            blob_store: self.transport.blob_store.clone(),
            firewall: self.firewall.clone(),
            hostname_table: self.dns.hostname_table.clone(),
            reverse_table: self.dns.reverse_table.clone(),
            device_user_map: self.device_user_map.clone(),
            pruned_peers: self.pruned_peers.clone(),
            disconnect_tx: self.disconnect_tx.clone(),
            registry: self.clone(),
        }
    }

    /// This device's pairing cert. The on-disk cert is authoritative: a cleanly
    /// absent file (`Ok(None)`, e.g. after `unpair_self` deletes it) means
    /// unpaired, so only a genuine read error falls back to the in-memory copy.
    pub(crate) fn current_device_cert(&self) -> Option<control::DeviceCert> {
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
            Ok(()) => tracing::warn!(
                "unpaired this device: deleted device certificate and left all networks"
            ),
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

        // Drop this network from every peer's routing. A peer left sharing no
        // network at all is fully disconnected, so close its now-unused link with
        // the leave code (the peer treats it as intentional and stops reconnecting);
        // a peer we still share another network with keeps its connection.
        for (_ip, conn) in self.peers.remove_by_network(name) {
            conn.close(VarInt::from_u32(forward::LEAVE_CODE), b"leave");
        }
        self.dns.clear_network(name).await;
        self.conn.unregister(&handle.network_key);
        self.refresh_search_domains().await;
        true
    }

    /// Re-derive the OS DNS search domains from the currently-joined networks.
    /// Split out of the daemon's `refresh_alpns` (whose ALPN half is a no-op now
    /// the mesh ALPN is static) for the teardown path.
    pub(crate) async fn refresh_search_domains(&self) {
        let network_names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        let tun_name = self.tun_name.load().as_str().to_owned();
        dns_config::update_search_domains(&network_names, &tun_name).await;
    }

    /// Leave a network: announce our departure to its peers, tear down the runtime,
    /// and remove it from config.
    ///
    /// The departure is sent in-band and network-scoped (`ControlMsg::LeaveNetwork`)
    /// rather than by closing the QUIC connection, because one connection now
    /// carries every network two peers share: closing it would sever the peer on
    /// networks we are *not* leaving (and, on a peer that coordinates one of them,
    /// get us pruned from a network we never left). A coordinator that receives the
    /// message prunes us from that one network's roster and republishes.
    /// `teardown_network_runtime` then closes only the links left sharing no
    /// network at all.
    pub(crate) async fn leave_network(&self, name: &str) -> IpcMessage {
        // Send the in-band leave while the peer entries still list this network
        // (before teardown drops them). Best-effort: a peer that misses it converges
        // from the coordinator's republish, or ages us out as an offline member.
        if let Some(net_pubkey) = self.networks.get(name).map(|h| h.network_key) {
            broadcast_control_msg(&self.peers, net_pubkey, name, &ControlMsg::LeaveNetwork).await;
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

    /// Look up an active network we coordinate, returning its public key and
    /// invite lock, or an error response if it's absent or we're only a member.
    #[allow(clippy::result_large_err)]
    pub(crate) fn coordinator_handle(
        &self,
        network: &str,
    ) -> std::result::Result<(EndpointId, Arc<tokio::sync::Mutex<()>>), IpcMessage> {
        let Some(handle) = self.networks.get(network) else {
            return Err(IpcMessage::Error {
                message: format!("network '{network}' not active"),
            });
        };
        if !handle.role.is_coordinator() {
            return Err(IpcMessage::Error {
                message: format!("only the coordinator of '{network}' can manage invites/requests"),
            });
        }
        Ok((handle.network_key, handle.invite_lock.clone()))
    }

    /// The name of an existing direct (`ray connect`) network already linking us
    /// to `peer` (as a member or approved), if any. Used to keep `approve` /
    /// re-connect idempotent.
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

    /// Pick a collision-free `<me>-<peer>` name for a direct network.
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

    /// Mint a new network: generate its keypair, build the initial roster, seal +
    /// publish the blob, persist config, spawn coordinator tasks, and register the
    /// coordinator accept handler. `direct`/`pre_approve` back the `ray connect`
    /// 2-peer path. Takes a `&MeshCtx` for the task spawn + handler registration.
    pub(crate) async fn create_network_inner(
        self: &Arc<Self>,
        mode: GroupMode,
        custom_name: Option<String>,
        hostname: Option<String>,
        direct: bool,
        pre_approve: Option<(EndpointId, Option<String>)>,
    ) -> Result<IpcMessage> {
        let ctx = self.mesh_ctx();
        let name = match custom_name {
            Some(n) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&n),
                    "invalid network name '{n}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                n
            }
            None => network_name::generate_name(),
        };

        let net_secret_key = SecretKey::generate();
        let net_public_key = net_secret_key.public();

        if self.networks.contains_key(&name) {
            return Ok(IpcMessage::Error {
                message: format!("network '{name}' already active"),
            });
        }

        let my_ip = self.transport.identity.local_ip();

        let my_hostname = match hostname {
            Some(h) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&h),
                    "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                h
            }
            None => config::load()
                .ok()
                .and_then(|c| c.default_hostname)
                .unwrap_or_else(crate::hostname::generate_hostname),
        };

        let mut net_state = self.build_initial_roster(
            &name,
            my_ip,
            &my_hostname,
            mode,
            &net_secret_key,
            pre_approve,
        )?;

        dns::update_hostname(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            &name,
            &my_hostname,
            my_ip,
            derive_ipv6(&self.transport.identity.local_identity()),
        )
        .await;

        self.seal_and_publish(&mut net_state, &net_secret_key).await;

        let member_entries = to_member_entries(net_state.members.all());
        let approved_entries = to_approved_entries(net_state.approved.all());
        config::save_network(&config::NetworkConfig {
            name: name.clone(),
            group_mode: mode,
            my_ip: Some(my_ip),
            my_hostname: Some(my_hostname.clone()),
            pending_hostname: None,
            members: member_entries,
            approved: approved_entries,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: Some(net_public_key),
            transport: None,
            auto_accept_firewall: false,
            // Own-device file offers are auto-accepted by default (identity-checked).
            auto_accept_files: true,
            admins: vec![],
            direct,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
        })?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let invite_lock = Arc::new(tokio::sync::Mutex::new(()));
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        let (tasks, disconnect_tx) = self.spawn_coordinator_background_tasks(
            &ctx,
            &name,
            &net_secret_key,
            &state,
            &dht_notify,
            &cancel,
        );

        // Insert the handle first so register_coordinator_handler can update the role.
        let handle = NetworkHandle {
            name: name.clone(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            my_ip,
            state: state.clone(),
            dht_notify: Some(dht_notify.clone()),
            cancel: cancel.clone(),
            tasks,
            invite_lock: invite_lock.clone(),
            disconnect_tx: disconnect_tx.clone(),
        };
        self.networks.insert(name.clone(), handle);

        self.register_coordinator_handler(
            &ctx,
            &name,
            state,
            invite_lock,
            Some(dht_notify),
            net_public_key,
        );
        self.refresh_search_domains().await;

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network created");

        Ok(IpcMessage::Created {
            name,
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.transport.identity.local_identity())),
        })
    }

    /// Build the initial [`NetworkState`] for a network we're minting: a member
    /// list holding just us (as coordinator), plus an optional pre-approved peer
    /// (used by `ray connect` to admit the requester without a live prompt).
    pub(crate) fn build_initial_roster(
        &self,
        name: &str,
        my_ip: Ipv4Addr,
        my_hostname: &str,
        mode: GroupMode,
        net_secret_key: &SecretKey,
        pre_approve: Option<(EndpointId, Option<String>)>,
    ) -> Result<NetworkState> {
        let mut member_list = MemberList::new();
        member_list
            .add(Member {
                identity: self.transport.identity.local_identity(),
                ip: my_ip,
                is_coordinator: true,
                hostname: Some(my_hostname.to_string()),
                user_identity: None,
                device_cert: None,
                collision_index: 0,
                last_seen: None,
            })
            .expect("self-add cannot collide");

        let mut approved = ApprovedList::new();
        if let Some((peer_id, peer_hostname)) = pre_approve {
            let peer_ip = self.transport.identity.derive_ip(&peer_id);
            approved
                .approve(
                    ApprovedEntry {
                        identity: peer_id,
                        ip: peer_ip,
                        hostname: peer_hostname,
                        user_identity: None,
                        device_cert: None,
                        collision_index: 0,
                    },
                    &member_list,
                )
                .map_err(|e| anyhow::anyhow!("failed to pre-approve peer: {e:?}"))?;
        }

        Ok(NetworkState {
            members: member_list,
            approved,
            snapshot: None,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_secret_key.public(),
            network_name: Some(name.to_string()),
            mode,
            suggested_firewall: SuggestedFirewall::default(),
            reusable_keys: BTreeMap::new(),
            // Seeded from persisted `revoked_devices` by `seal_and_publish`.
            nullifiers: BTreeSet::new(),
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        })
    }

    /// Seed a coordinated network's nullifiers from our durable `revoked_devices`,
    /// refresh its blob snapshot, store the bytes, and publish the signed pkarr
    /// record. The coordinator-setup counterpart to [`Self::store_and_publish_group`].
    pub(crate) async fn seal_and_publish(
        &self,
        net_state: &mut NetworkState,
        net_secret_key: &SecretKey,
    ) {
        {
            let cfg = config::load().unwrap_or_default();
            net_state
                .nullifiers
                .extend(config::revoked_device_ids(&cfg));
        }
        net_state.refresh_snapshot();
        if let Some(snap) = &net_state.snapshot {
            let _ = self
                .transport
                .blob_store
                .blobs()
                .add_slice(&snap.msgpack_bytes)
                .await;
        }
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.transport.endpoint) {
            let blob_hash = net_state
                .snapshot
                .as_ref()
                .map(|s| s.hash)
                .expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                net_secret_key,
                &blob_hash,
                &[self.transport.endpoint.id()],
            )
            .await
            {
                tracing::warn!(error = %e, "failed to publish network record");
            }
        }
    }

    /// Spawn a coordinated network's background tasks: the pkarr network publisher
    /// and the ephemeral stale-member pruner. Dead-peer cleanup/reconnect is
    /// daemon-wide (the connection supervisor), so no per-network disconnect task.
    /// Returns the task handles plus the daemon-wide disconnect sender (taken from
    /// the supplied `ctx`) the caller uses to build peer readers.
    pub(crate) fn spawn_coordinator_background_tasks(
        &self,
        ctx: &MeshCtx,
        name: &str,
        net_secret_key: &SecretKey,
        state: &SharedNetworkState,
        dht_notify: &Arc<tokio::sync::Notify>,
        cancel: &CancellationToken,
    ) -> (
        Vec<tokio::task::JoinHandle<()>>,
        mpsc::Sender<forward::DisconnectEvent>,
    ) {
        let mut tasks = Vec::new();

        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.transport.endpoint) {
            tasks.push(spawn_network_publisher(
                pkarr_client,
                net_secret_key.clone(),
                state.clone(),
                self.transport.endpoint.id(),
                self.peers.clone(),
                name.to_string(),
                dht_notify.clone(),
                cancel.clone(),
            ));
        }

        tasks.push(spawn_stale_member_pruner(
            ctx.clone(),
            name.to_string(),
            state.clone(),
            Some(dht_notify.clone()),
            cancel.clone(),
        ));

        (tasks, ctx.disconnect_tx.clone())
    }

    /// Store a network's current blob snapshot in the blob store and publish the
    /// signed pkarr record (hash + seed peers). No-op if the network is gone or
    /// has no snapshot / secret key (only a coordinator holds the key).
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
            let _ = self.transport.blob_store.blobs().add_slice(&bytes).await;
        }
        if let (Some(hash), Some(key)) = (hash, net_key)
            && let Ok(client) = dht::create_pkarr_client(&self.transport.endpoint)
        {
            let mut seed_peers: Vec<EndpointId> = self
                .peers
                .peers_for_network(network)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            seed_peers.push(self.transport.endpoint.id());
            seed_peers.sort_by_key(|id| id.to_string());
            seed_peers.dedup();
            if let Err(e) = dht::publish_network(&client, &key, &hash, &seed_peers).await {
                tracing::warn!(error = %e, "failed to publish network record after accept");
            }
        }
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
    ) {
        self.conn.register(
            network_key,
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                ctx: ctx.clone(),
                network_name: network.to_string(),
                state,
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
        self.register_coordinator_handler(ctx, network, parts.0, parts.1, parts.2, parts.3);
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
            if entry
                .value()
                .state
                .read()
                .unwrap()
                .network_secret_key
                .is_some()
            {
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
