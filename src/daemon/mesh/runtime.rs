//! Network runtime handlers for `Daemon`: coordinator restore, nuke,
//! connect-all, activate/deactivate (data plane), teardown, leave. Split out of `daemon/mod.rs`.

use super::super::*;
// Only the desktop-gated `start_ssh` binds SSH listeners on concrete IPs.
#[cfg(feature = "desktop")]
use std::net::IpAddr;
use std::sync::RwLock;

/// The membership a coordinator restores at startup, sourced from the signed
/// `GroupBlob` (authoritative) or the stale config roster as a fallback.
struct RestoredRoster {
    members: MemberList,
    approved: ApprovedList,
    suggested_firewall: SuggestedFirewall,
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    nullifiers: BTreeSet<EndpointId>,
}

impl NetworkRegistry {
    /// Rebuild a network's roster for a coordinator restart. Prefers the
    /// published, network-key-signed `GroupBlob` (members + approved + suggested
    /// firewall + reusable keys); if the DHT is unreachable, falls back to the
    /// last-persisted config roster (which may be stale). Always ensures this
    /// node is present as a coordinator member.
    async fn restore_member_roster(
        &self,
        name: &str,
        net_public_key: EndpointId,
        net_config: Option<&config::NetworkConfig>,
        my_ip: Ipv4Addr,
        persisted_hostname: &Option<String>,
    ) -> RestoredRoster {
        let mut member_list = MemberList::new();
        let mut approved_list = ApprovedList::new();
        // `suggested_firewall` is authoritative in the signed blob; fall back to
        // an empty set only if the blob can't be fetched.
        let mut suggested_firewall = SuggestedFirewall::default();
        // Reusable join keys are authoritative in the signed blob too.
        let mut reusable_keys = BTreeMap::new();
        let mut nullifiers = BTreeSet::new();
        match self.restore_roster_from_blob(net_public_key).await {
            Ok(data) => {
                suggested_firewall = data.suggested_firewall.clone();
                reusable_keys = data.reusable_keys.clone();
                nullifiers = data.nullifiers.clone();
                for m in &data.members {
                    let _ = member_list.add(m.clone());
                }
                for a in &data.approved {
                    let _ = approved_list.approve(a.clone(), &member_list);
                }
                tracing::info!(
                    network = %name,
                    members = member_list.all().len(),
                    "restored roster from published group blob"
                );
            }
            Err(e) => {
                tracing::warn!(
                    network = %name,
                    error = %e,
                    "could not restore roster from DHT blob; falling back to config (may be stale)"
                );
                if let Some(nc) = net_config {
                    for entry in &nc.members {
                        let _ = member_list.add(Member {
                            identity: entry.identity,
                            ip: entry.ip,
                            is_coordinator: entry.is_coordinator,
                            hostname: entry.hostname.clone(),
                            user_identity: None,
                            device_cert: None,
                            collision_index: 0,
                            last_seen: None,
                            exit_node: false,
                        });
                    }
                    for entry in &nc.approved {
                        let ae = ApprovedEntry {
                            identity: entry.identity,
                            ip: entry.ip,
                            hostname: entry.hostname.clone(),
                            user_identity: None,
                            device_cert: None,
                            collision_index: 0,
                        };
                        let _ = approved_list.approve(ae, &member_list);
                    }
                }
            }
        }
        if !member_list.is_member(&self.transport.identity.local_identity()) {
            member_list
                .add(Member {
                    identity: self.transport.identity.local_identity(),
                    ip: my_ip,
                    is_coordinator: true,
                    hostname: persisted_hostname.clone(),
                    user_identity: None,
                    device_cert: None,
                    collision_index: 0,
                    last_seen: None,
                    exit_node: false,
                })
                .expect("self-add cannot collide");
        }
        RestoredRoster {
            members: member_list,
            approved: approved_list,
            suggested_firewall,
            reusable_keys,
            nullifiers,
        }
    }

    /// Restores a coordinator network from saved config (uses the existing name).
    pub(crate) async fn restore_coordinator_network(
        self: &Arc<Self>,
        name: &str,
        mode: GroupMode,
    ) -> Result<IpcMessage> {
        {
            if self.networks.contains_key(name) {
                return Ok(ipc_err(format!("network '{name}' already active")));
            }
        }

        let my_ip = self.transport.identity.local_ip();

        // Load persisted network secret key from config
        let app_config = config::load()?;
        let net_config = app_config.networks.iter().find(|n| n.name == name);
        let net_secret_key = net_config
            .and_then(|nc| nc.network_secret_key.clone())
            .context("no network secret key in config — cannot restore as coordinator")?;
        let net_public_key = net_secret_key.public();
        let persisted_hostname = net_config.and_then(|nc| nc.my_hostname.clone());

        // Restore membership from the authoritative published GroupBlob. The blob
        // (members + approved) is signed by the per-network key and published
        // to DHT, so it is the source of truth and survives a daemon restart. The
        // local blob store still holds the bytes we published before going down, so
        // we read them back by the hash in the pkarr record (falling back to a seed
        // peer, then to the stale config roster only if the DHT is unreachable).
        // Restoring from the blob is also what prevents a clobber: the rebuilt
        // snapshot hashes identical to the published record, so the periodic
        // re-publish becomes a no-op instead of overwriting the roster with a
        // coordinator-only stub.
        let RestoredRoster {
            members: member_list,
            approved: approved_list,
            suggested_firewall,
            reusable_keys,
            nullifiers,
        } = self
            .restore_member_roster(name, net_public_key, net_config, my_ip, &persisted_hostname)
            .await;

        let mut net_state = NetworkState {
            members: member_list,
            approved: approved_list,
            snapshot: None,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_public_key,
            network_name: Some(name.to_string()),
            mode,
            suggested_firewall,
            reusable_keys,
            nullifiers,
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        };

        self.seal_and_publish(&mut net_state, &net_secret_key).await;

        // Update config
        let member_entries = to_member_entries(net_state.members.all());
        let approved_entries = to_approved_entries(net_state.approved.all());
        config::save_network(&config::NetworkConfig {
            name: name.to_string(),
            group_mode: mode,
            my_ip: Some(my_ip),
            my_hostname: persisted_hostname.clone(),
            // Coordinators publish renames directly, so they never carry a
            // pending intent.
            pending_hostname: None,
            members: member_entries,
            approved: approved_entries,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: Some(net_public_key),
            transport: None,
            // Preserve the persisted consent flag + admin roster across a
            // restart; only the roster (members/approved) is authoritative
            // from the blob.
            auto_accept_firewall: net_config
                .map(|nc| nc.auto_accept_firewall)
                .unwrap_or(false),
            auto_accept_files: net_config.map(|nc| nc.auto_accept_files).unwrap_or(false),
            admins: net_config.map(|nc| nc.admins.clone()).unwrap_or_default(),
            direct: net_config.map(|nc| nc.direct).unwrap_or(false),
            ssh_allow: net_config
                .map(|nc| nc.ssh_allow.clone())
                .unwrap_or_default(),
            aliases: net_config.map(|nc| nc.aliases.clone()).unwrap_or_default(),
            ephemeral_ttl_secs: None,
            // Local exit-node policy survives restarts (server allow-list and the
            // client's selected exit peer); neither rides the signed blob.
            exit_allow: net_config
                .map(|nc| nc.exit_allow.clone())
                .unwrap_or_default(),
            exit_node_use: net_config.and_then(|nc| nc.exit_node_use.clone()),
        })?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(RwLock::new(net_state));
        let invite_lock = Arc::new(tokio::sync::Mutex::new(()));
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        let ctx = self.mesh_ctx();
        let (tasks, disconnect_tx) = self.spawn_coordinator_background_tasks(
            &ctx,
            name,
            &net_secret_key,
            &state,
            &dht_notify,
            &cancel,
        );

        self.register_coordinator_handler(
            &ctx,
            name,
            state.clone(),
            invite_lock.clone(),
            Some(dht_notify.clone()),
            net_public_key,
        );

        // Register hostnames in DNS table
        {
            let members_snapshot: Vec<_> = {
                let s = state.read().unwrap();
                s.members
                    .all()
                    .into_iter()
                    .filter_map(|m| {
                        m.hostname
                            .as_ref()
                            .map(|h| (h.clone(), m.ip, derive_ipv6(&m.identity)))
                    })
                    .collect()
            };
            for (hostname, ip, ipv6) in members_snapshot {
                dns::update_hostname(
                    &self.dns.hostname_table,
                    &self.dns.reverse_table,
                    name,
                    &hostname,
                    ip,
                    ipv6,
                )
                .await;
            }
        }

        let members_to_dial: Vec<Member> = state
            .read()
            .unwrap()
            .members
            .all()
            .into_iter()
            .cloned()
            .collect();
        // Seed the route map from the restored roster so the data path can re-dial
        // any member that has since been idle-closed, before the first reconverge
        // (self excluded).
        self.seed_route_map(name, &members_to_dial);
        // Eager-connect the roster at startup (all nodes): a failed dial marks a peer
        // offline immediately, so status distinguishes offline from idle from boot.
        // On-demand nodes then idle-close these links per connection and re-dial
        // lazily; the route map above is what lets them come back.
        self.dial_all_members(
            &members_to_dial,
            net_public_key,
            name,
            self.transport.identity.local_identity(),
            my_ip,
            persisted_hostname.clone(),
        )
        .await;

        // Register the network from its restored local state *before* dialing
        // peers, so `ray status` / IPC sees it the instant the local restore
        // finishes. `dial_all_members` awaits a handshake per peer; when it gated
        // this insert, a freshly (re)started daemon answered `status` with "no
        // active networks" until every dial resolved.
        let handle = NetworkHandle {
            name: name.to_string(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            dht_notify: Some(dht_notify),
            cancel: cancel.clone(),
            tasks,
            invite_lock,
            disconnect_tx: disconnect_tx.clone(),
        };
        self.networks.insert(name.to_string(), handle);
        self.refresh_search_domains().await;

        // Full mesh: proactively dial every known member in the background so a
        // restarting coordinator/co-coordinator reconnects to peers that haven't
        // (yet) dialed in, without blocking restore on peer connectivity. Without
        // the dial, a co-coordinator that comes back up only learns about peers
        // that connect *to it*, so two co-coordinators restarting together each
        // show the other offline until one is disturbed. The accept handler is
        // already registered so return traffic is handled, and the reconnect loop
        // retries anything still unreachable.
        {
            let me = Arc::clone(self);
            let network_name = name.to_string();
            tokio::spawn(async move {
                me.dial_all_members(
                    &members_to_dial,
                    net_public_key,
                    &network_name,
                    me.transport.identity.local_identity(),
                    my_ip,
                    persisted_hostname,
                )
                .await;
            });
        }

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network restored (coordinator)");

        Ok(IpcMessage::Created {
            name: name.to_string(),
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.transport.identity.local_identity())),
        })
    }

    #[tracing::instrument(skip(self), fields(net = name))]
    pub(crate) async fn nuke_network(&self, name: &str, force: bool) -> IpcMessage {
        // Check we're the coordinator and whether other members exist
        let (is_coordinator, has_other_members) = {
            let handle = match self.networks.get(name) {
                Some(h) => h,
                None => {
                    return ipc_err(format!("not in network '{name}'"));
                }
            };
            let state = handle.state.read().unwrap();
            let my_id = self.transport.endpoint.id();
            let is_coord = state
                .members
                .get(&my_id)
                .map(|m| m.is_coordinator)
                .unwrap_or(false);
            let others = state.members.all().len() > 1;
            (is_coord, others)
        };

        if !is_coordinator {
            return ipc_err("only the coordinator can nuke a network".to_string());
        }

        if has_other_members && !force {
            return ipc_err(
                "network has other members — use --force to destroy, or transfer ownership first"
                    .to_string(),
            );
        }

        // Publish empty pkarr record
        let net_secret_key = {
            let handle = self.networks.get(name).unwrap();
            let state = handle.state.read().unwrap();
            state.network_secret_key.clone()
        };
        if let Some(key) = net_secret_key
            && let Ok(client) = dht::create_pkarr_client(&self.transport.endpoint)
        {
            let empty_hash = group_blob_hash(
                &MemberList::new(),
                &ApprovedList::new(),
                &SuggestedFirewall::default(),
                None,
                &BTreeMap::new(),
                &BTreeSet::new(),
            );
            if let Err(e) = dht::publish_network(&client, &key, &empty_hash, &[]).await {
                tracing::warn!(error = %e, "failed to publish empty network record on nuke");
            }
        }

        // Leave the network (handles cleanup, config removal, etc.)
        self.leave_network(name).await
    }

    /// Remove a member from a closed network. Coordinator-only (any network-key
    /// holder). Prunes the target from the roster + approved list, republishes the
    /// signed blob, and broadcasts a `MemberSync` so every member reconverges and
    /// drops the target mesh-wide (`prune_departed_peers`); the coordinator also
    /// closes its own link to the target immediately. Refused on open networks
    /// (the target would auto-re-join) and against coordinators / self.
    pub(crate) async fn kick_member(&self, network: &str, peer: &str) -> IpcMessage {
        let (state, dht_notify, has_key, mode) = match self.networks.get(network) {
            Some(h) => {
                let (has_key, mode) = {
                    let s = h.state.read().unwrap();
                    (s.network_secret_key.is_some(), s.mode)
                };
                (h.state.clone(), h.dht_notify.clone(), has_key, mode)
            }
            None => {
                return ipc_err(format!("network '{network}' not found"));
            }
        };
        if !has_key {
            return ipc_err(
                "only a coordinator (network key holder) can kick a member".to_string(),
            );
        }
        if mode == GroupMode::Open {
            return ipc_err(format!(
                "'{network}' is an open network — a kicked peer can re-join immediately. \
                     Kicking only takes effect on a closed network."
            ));
        }

        // Resolve the argument to a roster member. `resolve_peer_name` may hand
        // back a transport id or a user identity; match either against the stored
        // member key (which is the user identity for a paired peer).
        let candidate = match self.resolve_peer_name(peer).await {
            Some(id) => id,
            None => {
                return ipc_err(format!("could not resolve peer '{peer}'"));
            }
        };
        let candidate_user = self.device_user_map.resolve(&candidate);
        let (member_id, member_ip, is_coord, display) = {
            let s = state.read().unwrap();
            match s
                .members
                .all()
                .into_iter()
                .find(|m| m.identity == candidate || m.identity == candidate_user)
            {
                Some(m) => (
                    m.identity,
                    m.ip,
                    m.is_coordinator,
                    m.hostname
                        .clone()
                        .unwrap_or_else(|| m.identity.fmt_short().to_string()),
                ),
                None => {
                    return ipc_err(format!("'{peer}' is not a member of '{network}'"));
                }
            }
        };
        if member_id == self.transport.endpoint.id() {
            return ipc_err("cannot kick yourself — use `ray leave` or `ray nuke`".to_string());
        }
        if is_coord {
            return ipc_err(format!(
                "'{display}' is a coordinator (holds the network key); kicking can't remove \
                     its access. Revoke the key instead."
            ));
        }

        // Prune the roster + approved list, then republish the signed blob so the
        // removal is authoritative, and drop the target's DNS entries.
        {
            let mut s = state.write().unwrap();
            s.members.remove(&member_id);
            s.approved.remove(&member_id);
        }
        dns::remove_hostname_by_ip(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            network,
            member_ip,
        )
        .await;
        update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
        let net_pubkey = state.read().unwrap().network_public_key;
        broadcast_member_sync(&self.peers, net_pubkey, network, None).await;

        // Sever our own link(s) to the target now, rather than waiting for it to
        // time out. Other members drop it when they reconverge from the freshly
        // published record (`prune_departed_peers`).
        for (pid, ip, _conn) in self.peers.peers_for_network_with_conn(network) {
            if pid == member_id || self.device_user_map.resolve(&pid) == member_id {
                // Only close the shared connection if this was the peer's last
                // network with us; otherwise just drop this network's route so a
                // peer we share other networks with stays reachable there.
                if let Some(conn) =
                    self.peers
                        .remove_peer_from_network(&ip, &derive_ipv6(&pid), network)
                {
                    conn.close(VarInt::from_u32(forward::KICK_CODE), b"kicked from network");
                }
            }
        }

        tracing::info!(peer = %member_id.fmt_short(), network = %network, "kicked member");
        IpcMessage::Ok {
            message: format!("kicked '{display}' from '{network}'"),
        }
    }

    /// Set or clear the per-network ephemeral policy (coordinator-local). A
    /// `None` TTL disables it. Persisted to the network's config; the pruner
    /// re-reads it each tick, so no restart is needed.
    pub(crate) async fn set_ephemeral(&self, network: &str, ttl_secs: Option<u64>) -> IpcMessage {
        let mut cfg = match config::load_network(network) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return ipc_err(format!("network '{network}' not found"));
            }
            Err(e) => {
                return ipc_err(format!("failed to load network '{network}': {e}"));
            }
        };
        cfg.ephemeral_ttl_secs = ttl_secs;
        if let Err(e) = config::save_network(&cfg) {
            return ipc_err(format!("failed to save network '{network}': {e}"));
        }
        match ttl_secs {
            Some(s) => IpcMessage::Ok {
                message: format!("ephemeral policy on '{network}' set to {s}s"),
            },
            None => IpcMessage::Ok {
                message: format!("ephemeral policy on '{network}' disabled"),
            },
        }
    }

    /// Read the per-network ephemeral TTL (open read).
    pub(crate) fn get_ephemeral(&self, network: &str) -> IpcMessage {
        match config::load_network(network) {
            Ok(Some(c)) => IpcMessage::EphemeralStatus {
                network: network.to_string(),
                ttl_secs: c.ephemeral_ttl_secs,
            },
            Ok(None) => ipc_err(format!("network '{network}' not found")),
            Err(e) => ipc_err(format!("failed to load network '{network}': {e}")),
        }
    }

    /// Connect to every saved network (control plane). Run once at daemon
    /// startup so mesh connections follow the daemon lifecycle, not the data
    /// plane: `ray down` keeps these connected so the node stays online to
    /// peers. Connections are dropped only on leave/nuke/shutdown.
    pub(crate) async fn connect_all_networks(self: &Arc<Self>) {
        let app_config = match config::load() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load config during connect");
                return;
            }
        };
        let mut count = 0;
        let mut coordinator_restores = Vec::new();
        for net in &app_config.networks {
            count += 1;
            if net.network_secret_key.is_some() {
                // We hold the secret key, restore as coordinator.
                let name = net.name.clone();
                let mode = net.group_mode;
                let daemon_c = Arc::clone(self);
                coordinator_restores.push(tokio::spawn(async move {
                    match daemon_c.restore_coordinator_network(&name, mode).await {
                        Ok(IpcMessage::Created { name, .. }) => {
                            tracing::info!(network = %name, "restored coordinator network");
                        }
                        Ok(IpcMessage::Error { message }) => {
                            tracing::warn!(network = %name, error = %message, "failed to restore network");
                        }
                        Err(e) => {
                            tracing::warn!(network = %name, error = %e, "failed to restore network");
                        }
                        _ => {}
                    }
                }));
            } else {
                // We're a member, rejoin via DHT lookup.
                let name = net.name.clone();
                let persisted_hostname = net.my_hostname.clone();
                let net_auto_accept = net.auto_accept_firewall;
                let net_auto_accept_files = net.auto_accept_files;
                let net_pubkey = match &net.network_public_key {
                    Some(k) => k.to_string(),
                    None => {
                        tracing::warn!(network = %name, "no network public key in config, skipping restore");
                        continue;
                    }
                };
                let daemon_c = Arc::clone(self);
                tokio::spawn(async move {
                    match daemon_c
                        .join_network_inner(
                            &net_pubkey,
                            Some(&name),
                            persisted_hostname,
                            None,
                            None,
                            net_auto_accept,
                            net_auto_accept_files,
                            false,
                        )
                        .await
                    {
                        Ok(TryJoin::Joined(IpcMessage::Joined { name, my_ip, .. })) => {
                            tracing::info!(network = %name, ip = %my_ip, "restored member network");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(network = %name, error = %e, "failed to restore network");
                        }
                    }
                });
            }
        }

        // Barrier: wait until every saved coordinator network has registered (its
        // local restore (roster + accept handler) is done) before returning, so
        // `run_daemon` opens the IPC server only once these networks are visible to
        // `ray status`. Peer dialing runs in the background (see
        // `restore_coordinator_network`), so this never blocks on connectivity;
        // member networks reconnect via their own loop and appear as they connect.
        for restore in coordinator_restores {
            let _ = restore.await;
        }

        // Resume closed-network joins that were still awaiting approval at shutdown.
        for pending in &app_config.pending_joins {
            if self.networks.contains_key(&pending.network_key) {
                continue;
            }
            let me = Arc::clone(self);
            let key = pending.network_key.clone();
            let name = pending.name.clone();
            tokio::spawn(async move {
                let _ = me
                    .join_network(&key, name.as_deref(), None, None, None, false, false)
                    .await;
            });
        }

        // Publish the contact record immediately so `ray connect` works right
        // away, rather than waiting up to one publisher interval (the active-gated
        // `spawn_contact_publisher` only re-checks every TTL/2).
        if let Some(secret) = app_config.contact_secret_key.clone()
            && let Ok(client) = dht::create_pkarr_client(&self.transport.endpoint)
        {
            let endpoint_id = self.transport.endpoint.id();
            tokio::spawn(async move {
                if let Err(e) = dht::publish_contact(&client, &secret, endpoint_id).await {
                    tracing::warn!(error = %e, "failed to publish contact record on connect");
                }
            });
        }

        tracing::info!(networks = count, "control plane connected");
    }
}

impl Daemon {
    /// Rebuild the live per-network SSH allow-list snapshot from persisted
    /// config, so a running listener authorizes against current rules. Cheap and
    /// only called on SSH config changes / activation (not the hot path).
    #[cfg(feature = "desktop")]
    pub(crate) fn rebuild_ssh_authz(&self) {
        let mut map = HashMap::new();
        if let Ok(cfg) = config::load() {
            for n in &cfg.networks {
                if !n.ssh_allow.is_empty() {
                    map.insert(n.name.clone(), n.ssh_allow.clone());
                }
            }
        }
        self.ssh_authz.store(Arc::new(map));
    }

    /// Start the embedded mesh SSH listeners on this node's mesh addresses, if
    /// not already running. Idempotent. Bound to the data plane: called from
    /// `activate` when `ssh_enabled`, and from the `ssh on` IPC while active.
    #[cfg(feature = "desktop")]
    pub(crate) fn start_ssh(self: &Arc<Self>) {
        let mut guard = self.ssh_token.lock().unwrap();
        if guard.is_some() {
            return;
        }
        let token = CancellationToken::new();
        *guard = Some(token.clone());
        drop(guard);
        self.rebuild_ssh_authz();
        let my_v4 = self.transport.identity.local_ip();
        let my_v6 = derive_ipv6(&self.transport.identity.local_identity());
        let server = crate::ssh::SshServer::new(
            self.registry.peers.clone(),
            self.registry.device_user_map.clone(),
            self.ssh_authz.clone(),
        );
        server.spawn(vec![IpAddr::V4(my_v4), IpAddr::V6(my_v6)], token);
        // Turn on the userspace port NAT so mesh `:22` reaches the listener.
        crate::forward::set_ssh_nat_active(true);
    }

    /// Stop the SSH listeners if running. Idempotent.
    #[cfg(feature = "desktop")]
    pub(crate) fn stop_ssh(&self) {
        crate::forward::set_ssh_nat_active(false);
        if let Some(t) = self.ssh_token.lock().unwrap().take() {
            t.cancel();
        }
    }

    /// Activate the VPN: bring the TUN interface up, configure system DNS.
    /// Idempotent: a no-op if already active. Runs entirely inside the
    /// (root) daemon, so the IPC client needs no privileges.
    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// bring the data plane up (mark active, configure Magic DNS). On Android the
    /// packet interface + routes are the `VpnService`'s job, so those desktop
    /// route calls are skipped.
    pub async fn activate(self: &Arc<Self>, hostname: Option<String>) -> IpcMessage {
        // Persist the personal default hostname first (before the already-active
        // short-circuit) so `ray up --hostname X` records the new default even
        // when the VPN is already up. Used as the fallback for future
        // creates/joins; doesn't rename networks already joined.
        if let Some(h) = hostname {
            if !crate::hostname::is_valid_hostname(&h) {
                return ipc_err(format!(
                    "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                ));
            }
            match config::load() {
                Ok(mut app_config) => {
                    app_config.default_hostname = Some(h);
                    if let Err(e) = config::save_settings(&app_config) {
                        tracing::warn!(error = %e, "failed to persist default hostname");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load config to set default hostname")
                }
            }
        }

        if self.active.swap(true, Ordering::SeqCst) {
            return IpcMessage::Ok {
                message: "already up".into(),
            };
        }

        // Non-fatal problems hit while activating. The daemon stays up, but we
        // return these to the client so `ray up` can tell the user something is
        // wrong instead of silently reporting success on a degraded VPN.
        let mut warnings: Vec<String> = Vec::new();

        // The TUN device/routes are managed by the OS on desktop. On Android the
        // packet interface is a `VpnService` fd whose routes are configured on the
        // Kotlin side, so these desktop route calls don't apply.
        #[cfg(not(target_os = "android"))]
        {
            let tun_name = self.tun_name.load().as_str().to_owned();
            let my_v4 = self.transport.identity.local_ip();
            let my_v6 = derive_ipv6(&self.transport.identity.local_identity());
            if let Err(e) = tun::set_link_up(&tun_name) {
                tracing::warn!(error = %e, "failed to bring TUN interface up");
                warnings.push(format!("failed to bring TUN interface up: {e}"));
            }

            // Linux drops the TUN's global IPv6 address whenever the link goes
            // down (`ray down`) and never restores it, so re-assign it here or
            // this node answers on IPv4 only for the rest of the daemon's life.
            #[cfg(target_os = "linux")]
            if let Err(e) = tun::ensure_ipv6_addr(&tun_name, my_v6).await {
                tracing::warn!(error = %e, "failed to assign TUN IPv6 address");
                warnings.push(format!("failed to assign TUN IPv6 address: {e}"));
            }

            // Route the 200::/7 peer range into the TUN. Must happen after
            // link-up: on Linux the kernel won't install an IPv6 connected route
            // while the link is down, so without this peer traffic leaks out the
            // default route.
            if let Err(e) = tun::route_peer_range(&tun_name).await {
                tracing::warn!(error = %e, "failed to route 200::/7 into TUN");
                warnings.push(format!("failed to route IPv6 peer range into TUN: {e}"));
            }

            if let Err(e) = tun::route_magic_dns(&tun_name).await {
                tracing::warn!(error = %e, "failed to route magic DNS IP into TUN");
            }

            // Loop our own addresses back through lo0 so self-traffic (e.g.
            // pinging our own hostname) is answered locally instead of leaving via
            // the TUN, where the forwarding loop would drop it as "no peer for
            // dst". No-op on Linux (kernel installs the `local` route
            // automatically).
            if let Err(e) = tun::route_self_loopback(my_v4, my_v6).await {
                tracing::warn!(error = %e, "failed to install loopback self-route");
                warnings.push(format!("failed to install loopback self-route: {e}"));
            }
        }

        // Clone the TUN name out of the lock before awaiting: the embedder
        // (mobile) stores it behind a mutex, and a std guard can't be held across
        // an await point.
        let dns_tun_name = self.tun_name.load().as_str().to_owned();
        self.dns.configure(&dns_tun_name, &mut warnings).await;

        // Start the embedded mesh SSH server if enabled. It binds the mesh IPs'
        // port 22, so it follows the data plane (mesh addresses must be up).
        #[cfg(feature = "desktop")]
        if config::load().map(|c| c.ssh_enabled).unwrap_or(false) {
            self.start_ssh();
        }

        // From here until `deactivate()`, the roster's exit-offer flag is kept in
        // sync with the loaded gateway policy (see `sync_exit_offers`).
        self.registry
            .exit_sync_enabled
            .store(true, Ordering::SeqCst);
        warnings.extend(self.apply_exit_node().await);

        tracing::info!("data plane activated");
        if warnings.is_empty() {
            IpcMessage::Ok {
                message: "VPN up".into(),
            }
        } else {
            let mut message = String::from("VPN up, but some things need attention:");
            for w in &warnings {
                message.push_str("\n  - ");
                message.push_str(w);
            }
            IpcMessage::Ok { message }
        }
    }

    /// Reconcile every piece of exit-node state with the on-disk config: the
    /// gateway allow policy and its kernel forwarding/NAT, and the client selection
    /// and its full-tunnel routing. Both halves are idempotent and both directions
    /// (install / remove) are handled, so this is the single entry point used by
    /// `activate` and by any `ray exit-node` change made while up. Returns a
    /// user-facing warning if either half could not be put in place.
    pub(crate) async fn apply_exit_node(&self) -> Option<String> {
        // One reconcile at a time (see `Daemon::exit_reconcile`): the kernel
        // enable's snapshot-then-write is not safe to interleave.
        let _guard = self.exit_reconcile.lock().await;
        let tun_name = self.tun_name.load().as_str().to_owned();
        let reload = self.registry.reload_exit_state();
        // Both halves run even if the first one failed: they are independent roles,
        // and each one's teardown path has to happen regardless.
        let server = apply_exit_server_os(&self.registry.exit_server, &tun_name).await;
        let client = self.apply_exit_client(&tun_name).await;
        // Advertise what actually survived the reconcile: a failed enable cleared
        // the offers, so this also withdraws a stale advertisement rather than
        // keeping clients routed into a gateway that forwards nothing.
        self.registry.sync_exit_offers().await;
        reload.or(server).or(client)
    }

    /// Spawn the daemon-lifetime listener that re-runs the exit reconcile when a
    /// reconverge nudges [`NetworkRegistry::exit_reapply`]: the roster just gained
    /// the exit peer a pending selection has been waiting for (boot before the
    /// first reconverge), so the full tunnel can finally go in without waiting for
    /// the next `ray up`. A channel rather than a direct call because the kernel
    /// plumbing lives here on `Daemon`, above the registry in the service graph.
    pub(crate) fn spawn_exit_reapply_listener(self: &Arc<Self>) {
        let daemon = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = daemon.shutdown_token.cancelled() => break,
                    _ = daemon.registry.exit_reapply.notified() => {}
                }
                if !daemon.active.load(Ordering::SeqCst) {
                    continue;
                }
                if let Some(warning) = daemon.apply_exit_node().await {
                    tracing::warn!(warning, "exit-node re-apply after roster update");
                }
            }
        });
    }

    /// After a `ray exit-node` mutation: if the data plane is up, reconcile the
    /// runtime state and kernel plumbing now (otherwise `activate()` picks it up
    /// on `ray up`), folding any reconcile warning into the reply so a failed
    /// install is never reported as plain success.
    pub(crate) async fn reconcile_exit_node(&self, resp: IpcMessage) -> IpcMessage {
        if !self.active.load(Ordering::SeqCst) {
            // Data plane on standby: persisted but not in effect until `ray up`.
            // (When the data plane is up we fall through and apply it now, so the
            // reply must not claim `ray up` is needed.)
            return match resp {
                IpcMessage::Ok { message } => IpcMessage::Ok {
                    message: format!("{message} (takes effect on `ray up`)"),
                },
                other => other,
            };
        }
        match (self.apply_exit_node().await, resp) {
            (Some(warning), IpcMessage::Ok { message }) => IpcMessage::Ok {
                message: format!("{message}\nwarning: {warning}"),
            },
            (_, resp) => resp,
        }
    }

    /// Install or remove the client full-tunnel routing to match the selection.
    /// The kernel plumbing spawns a series of `ip`/`nft` children and waits on
    /// them, so it runs on the blocking pool rather than stalling a runtime
    /// worker (this is called from the IPC dispatcher and `activate()`).
    #[cfg(target_os = "linux")]
    async fn apply_exit_client(&self, tun_name: &str) -> Option<String> {
        let install = self.registry.exit_client.is_active();
        let tun_name = tun_name.to_owned();
        let result = tokio::task::spawn_blocking(move || {
            if !install {
                crate::exit_node::teardown_client_routing();
                return Ok(());
            }
            crate::exit_node::install_client_routing(&tun_name).inspect_err(|_| {
                // A partial install must not stay live: rules that went in before
                // the failure (say v4's, with `ipv6.disable=1` failing the v6 half)
                // would keep routing traffic into a tunnel that was never fully set
                // up. Mirror the macOS branch and roll all of it back.
                crate::exit_node::teardown_client_routing();
            })
        })
        .await;
        match result {
            Ok(Ok(())) => None,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "failed to install exit-node client routing");
                Some(format!("failed to route traffic through exit node: {e}"))
            }
            Err(e) => Some(format!("exit-node routing task failed: {e}")),
        }
    }

    /// Install or remove the client full tunnel to match the selection.
    ///
    /// macOS has no fwmark: loop prevention instead pins iroh's sockets to the
    /// physical default-route interface (`exit_node::configure_socket`), and the
    /// pin only lands on a (re)bind, which `Endpoint::network_change` forces. So
    /// ordering matters both ways: pin and rebind *before* the default routes go
    /// in, and take the routes out *before* releasing the pin, so there is never
    /// a moment where iroh's own traffic can be routed into the tunnel it is
    /// carrying. The rebind is skipped when the pin state did not flip (re-apply
    /// while up, or teardown when no tunnel was installed).
    #[cfg(target_os = "macos")]
    async fn apply_exit_client(&self, tun_name: &str) -> Option<String> {
        let result = if !self.registry.exit_client.is_active() {
            tun::unroute_default_via_tun(tun_name).await;
            crate::exit_node::remove_relay_exclusions();
            if crate::exit_node::set_full_tunnel(false) {
                self.transport.endpoint.network_change().await;
            }
            None
        } else {
            // Establish the connection to the exit peer *before* pinning sockets
            // and installing the tunnel: a cold selection would otherwise dial the
            // exit peer over the routes it is about to become, so the dial gets
            // captured by the tunnel it is meant to carry and blackholes until a
            // manual `ray ping`. Warming it first (over the still-unpinned socket)
            // lets the pin keep the live connection off the tunnel.
            self.warm_exit_peer().await;
            // Keep iroh's relay servers off the tunnel: the socket pin only covers
            // direct QUIC, so a relay-routed exit link would otherwise be captured
            // by the tunnel and die. Resolve them now, while DNS is still split.
            let relay_ips = self.relay_underlay_ips().await;
            crate::exit_node::exclude_relays_from_tunnel(&relay_ips);
            if !crate::exit_node::set_full_tunnel(true) {
                self.transport.endpoint.network_change().await;
            }
            self.route_default_or_rollback(tun_name).await
        };
        // Re-apply system DNS to match the now-settled full-tunnel state: route
        // *all* DNS through Magic DNS while the tunnel is up (so resolution goes
        // out via the exit), split `.ray`-only otherwise.
        self.dns.reassert_os_config().await;
        result
    }

    /// Dial the selected exit peer so its mesh connection is live before the full
    /// tunnel pins sockets. Idempotent (a no-op when already connected).
    #[cfg(target_os = "macos")]
    async fn warm_exit_peer(&self) {
        if let Some(sel) = self.registry.exit_client.selection()
            && let Some(target) = self.registry.resolve_route(IpAddr::V4(sel.ipv4))
        {
            self.registry.dial_target(&target).await;
        }
    }

    /// Resolve iroh's relay servers to their IPv4 addresses so they can be routed
    /// around the full tunnel. Resolved via the system resolver, so call this
    /// while DNS is still split (before the tunnel's DNS catch-all goes in).
    #[cfg(target_os = "macos")]
    async fn relay_underlay_ips(&self) -> Vec<std::net::Ipv4Addr> {
        // The configured relay set (custom override + n0 default fallback), the
        // same the endpoint dials. Excluding the whole set (a handful of host
        // routes) covers whichever relay it is actually homed on.
        let relay_mode = config::load()
            .ok()
            .and_then(|c| crate::transport::build_relay_mode(&c.relay).ok().flatten())
            .unwrap_or(iroh::RelayMode::Default);
        let urls = relay_mode.relay_map().urls::<Vec<iroh::RelayUrl>>();
        let mut ips = Vec::new();
        for url in urls {
            let Some(host) = url.host_str() else { continue };
            let port = url.port_or_known_default().unwrap_or(443);
            if let Ok(addrs) = tokio::net::lookup_host((host, port)).await {
                for a in addrs {
                    if let IpAddr::V4(v4) = a.ip()
                        && !ips.contains(&v4)
                    {
                        ips.push(v4);
                    }
                }
            }
        }
        ips
    }

    /// Install the split default routes into the TUN, rolling the full-tunnel pin
    /// back on failure so a partial install (one family in, the other not) does
    /// not blackhole traffic.
    #[cfg(target_os = "macos")]
    async fn route_default_or_rollback(&self, tun_name: &str) -> Option<String> {
        match tun::route_default_via_tun(tun_name).await {
            Ok(()) => None,
            Err(e) => {
                tun::unroute_default_via_tun(tun_name).await;
                if crate::exit_node::set_full_tunnel(false) {
                    self.transport.endpoint.network_change().await;
                }
                tracing::warn!(error = %e, "failed to install exit-node client routing");
                Some(format!("failed to route traffic through exit node: {e}"))
            }
        }
    }

    /// Using an exit node needs full-tunnel routing plus loop prevention for the
    /// node's own transport, which only Linux (`SO_MARK` + policy routing) and
    /// macOS (`IP_BOUND_IF` socket pinning) have. Say so, rather than reporting
    /// success while every packet keeps leaving the local uplink. Offering an
    /// exit node works on every platform.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    async fn apply_exit_client(&self, _tun_name: &str) -> Option<String> {
        self.registry.exit_client.is_active().then(|| {
            "using an exit node is not supported on this platform yet; traffic still \
             leaves this host directly. Clear it with `ray exit-node none`."
                .to_string()
        })
    }

    /// Put the daemon on standby: take the data plane offline (revert system
    /// DNS, bring the TUN link down, stop forwarding) while keeping the control
    /// plane connected. Network connections, control readers, and pollers stay
    /// live so the node remains online to peers and keeps receiving roster/blob
    /// updates. Connections are dropped only on leave/nuke/shutdown. Idempotent.
    pub(crate) async fn deactivate(&self) -> IpcMessage {
        if !self.active.swap(false, Ordering::SeqCst) {
            return IpcMessage::Ok {
                message: "already on standby".into(),
            };
        }

        // The SSH listeners bind the mesh IPs, which go down with the data plane.
        #[cfg(feature = "desktop")]
        self.stop_ssh();

        // Clone the TUN name out of the lock before awaiting (see `activate`);
        // the DnsService reverts system DNS and clears the TUN search domains.
        let tun_name = self.tun_name.load().as_str().to_owned();
        self.dns.revert(&tun_name).await;

        #[cfg(not(target_os = "android"))]
        if let Err(e) = tun::set_link_down(&tun_name) {
            tracing::warn!(error = %e, "failed to bring TUN interface down");
        }

        // Exit-node server: drop the allow policy so no transit happens while on
        // standby, then reconcile (which removes the kernel forwarding/NAT). With no
        // offers left this is the teardown path, which never reports a problem.
        // Under the reconcile lock: this must not interleave with an in-flight
        // `apply_exit_node` (the reapply listener, a late IPC mutation), which
        // could otherwise re-enable what this is tearing down, or worse, snapshot
        // the half-torn-down sysctls as "original".
        let _guard = self.exit_reconcile.lock().await;
        self.registry.exit_server.clear();
        let _ = apply_exit_server_os(&self.registry.exit_server, &tun_name).await;

        // Withdraw the roster advertisement while the offers are still cleared and
        // syncing is still enabled: connections stay up on standby, so a peer that
        // kept routing through us would blackhole against the empty allow list
        // otherwise. `activate()` re-advertises. Then disable syncing, so a
        // reconverge during standby leaves the (withdrawn) flag alone.
        self.registry.sync_exit_offers().await;
        self.registry
            .exit_sync_enabled
            .store(false, Ordering::SeqCst);

        // Exit-node client: clear the selection, then reconcile, which removes the
        // full tunnel (Linux policy routing; macOS split-default routes + socket
        // pinning). Teardown never reports a problem.
        self.registry.exit_client.set(None);
        let _ = self.apply_exit_client(&tun_name).await;

        tracing::info!("VPN on standby");
        IpcMessage::Ok {
            message: "VPN on standby (still connected to peers)".into(),
        }
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// leave a network (close connections, tear down runtime, forget config).
    #[tracing::instrument(skip(self), fields(net = name))]
    pub async fn leave_network(&self, name: &str) -> IpcMessage {
        self.registry.leave_network(name).await
    }
}

/// Run [`ExitServer::apply_os`](crate::exit_node::ExitServer::apply_os) on the
/// blocking pool: enabling or disabling the gateway spawns a series of
/// `nft`/`pfctl`/`sysctl` children and waits on them, which must not stall a
/// runtime worker (this is reached from the IPC dispatcher, `activate()`, and
/// `deactivate()`).
async fn apply_exit_server_os(
    server: &crate::exit_node::ExitServer,
    tun_name: &str,
) -> Option<String> {
    let server = server.clone();
    let tun_name = tun_name.to_owned();
    match tokio::task::spawn_blocking(move || server.apply_os(&tun_name)).await {
        Ok(warning) => warning,
        Err(e) => Some(format!("exit-node reconcile task failed: {e}")),
    }
}
