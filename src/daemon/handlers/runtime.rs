//! Network runtime handlers for `DaemonState`: coordinator restore, nuke,
//! connect-all, activate/deactivate (data plane), teardown, leave. Split out of `daemon/mod.rs`.

use super::super::*;

/// The membership a coordinator restores at startup, sourced from the signed
/// `GroupBlob` (authoritative) or the stale config roster as a fallback.
struct RestoredRoster {
    members: MemberList,
    approved: ApprovedList,
    suggested_firewall: SuggestedFirewall,
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
}

impl DaemonState {
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
        match self.restore_roster_from_blob(net_public_key).await {
            Ok(data) => {
                suggested_firewall = data.suggested_firewall.clone();
                reusable_keys = data.reusable_keys.clone();
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
        if !member_list.is_member(&self.identity.local_identity()) {
            member_list
                .add(Member {
                    identity: self.identity.local_identity(),
                    ip: my_ip,
                    is_coordinator: true,
                    hostname: persisted_hostname.clone(),
                    user_identity: None,
                    device_cert: None,
                    collision_index: 0,
                })
                .expect("self-add cannot collide");
        }
        RestoredRoster {
            members: member_list,
            approved: approved_list,
            suggested_firewall,
            reusable_keys,
        }
    }

    /// Restores a coordinator network from saved config (uses the existing name).
    pub(crate) async fn restore_coordinator_network(&self, name: &str, mode: GroupMode) -> Result<IpcMessage> {
        {
            if self.networks.contains_key(name) {
                return Ok(IpcMessage::Error {
                    message: format!("network '{name}' already active"),
                });
            }
        }

        let my_ip = self.identity.local_ip();

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
            admins: net_config.map(|nc| nc.admins.clone()).unwrap_or_default(),
            direct: net_config.map(|nc| nc.direct).unwrap_or(false),
            ssh_allow: net_config
                .map(|nc| nc.ssh_allow.clone())
                .unwrap_or_default(),
        })?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let invite_lock = Arc::new(tokio::sync::Mutex::new(()));
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        let (tasks, disconnect_tx) =
            self.spawn_coordinator_background_tasks(name, &net_secret_key, &state, &dht_notify, &cancel);

        self.register_coordinator_handler(
            name,
            state.clone(),
            invite_lock.clone(),
            Some(dht_notify.clone()),
            net_public_key,
            disconnect_tx.clone(),
            cancel.clone(),
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
                    &self.hostname_table,
                    &self.reverse_table,
                    name,
                    &hostname,
                    ip,
                    ipv6,
                )
                .await;
            }
        }

        // Full mesh: proactively dial every known member so a restarting
        // coordinator/co-coordinator reconnects to peers that haven't (yet)
        // dialed in. Without this, a co-coordinator that comes back up only
        // learns about peers that connect *to it*; it never dials out, so two
        // co-coordinators restarting together can each show the other as
        // offline until one is manually disturbed. Done before the handle
        // takes ownership of `state`/`cancel`/`disconnect_tx`; the accept
        // handler is already registered so return traffic is handled.
        let members_to_dial: Vec<Member> = state
            .read()
            .unwrap()
            .members
            .all()
            .into_iter()
            .cloned()
            .collect();
        let alpn = transport::network_alpn(&net_public_key);
        self.dial_all_members(
            &members_to_dial,
            &alpn,
            name,
            self.identity.local_identity(),
            my_ip,
            persisted_hostname.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
        )
        .await;

        let handle = NetworkHandle {
            name: name.to_string(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            dht_notify: Some(dht_notify),
            cancel,
            tasks,
            invite_lock,
            disconnect_tx,
        };
        self.networks.insert(name.to_string(), handle);
        self.refresh_alpns().await;

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network restored (coordinator)");

        Ok(IpcMessage::Created {
            name: name.to_string(),
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        })
    }

    #[tracing::instrument(skip(self), fields(net = name))]
    pub(crate) async fn nuke_network(&self, name: &str, force: bool) -> IpcMessage {
        // Check we're the coordinator and whether other members exist
        let (is_coordinator, has_other_members) = {
            let handle = match self.networks.get(name) {
                Some(h) => h,
                None => {
                    return IpcMessage::Error {
                        message: format!("not in network '{name}'"),
                    };
                }
            };
            let state = handle.state.read().unwrap();
            let my_id = self.endpoint.id();
            let is_coord = state
                .members
                .get(&my_id)
                .map(|m| m.is_coordinator)
                .unwrap_or(false);
            let others = state.members.all().len() > 1;
            (is_coord, others)
        };

        if !is_coordinator {
            return IpcMessage::Error {
                message: "only the coordinator can nuke a network".to_string(),
            };
        }

        if has_other_members && !force {
            return IpcMessage::Error {
                message: "network has other members — use --force to destroy, or transfer ownership first".to_string(),
            };
        }

        // Publish empty pkarr record
        let net_secret_key = {
            let handle = self.networks.get(name).unwrap();
            let state = handle.state.read().unwrap();
            state.network_secret_key.clone()
        };
        if let Some(key) = net_secret_key
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let empty_hash = group_blob_hash(
                &MemberList::new(),
                &ApprovedList::new(),
                &SuggestedFirewall::default(),
                None,
                &BTreeMap::new(),
            );
            if let Err(e) = dht::publish_network(&client, &key, &empty_hash, &[]).await {
                tracing::warn!(error = %e, "failed to publish empty network record on nuke");
            }
        }

        // Leave the network (handles cleanup, config removal, etc.)
        self.leave_network(name).await
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
        for net in &app_config.networks {
            count += 1;
            if net.network_secret_key.is_some() {
                // We hold the secret key, restore as coordinator.
                let name = net.name.clone();
                let mode = net.group_mode;
                let daemon_c = Arc::clone(self);
                tokio::spawn(async move {
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
                });
            } else {
                // We're a member, rejoin via DHT lookup.
                let name = net.name.clone();
                let persisted_hostname = net.my_hostname.clone();
                let net_auto_accept = net.auto_accept_firewall;
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

        // Publish the contact record immediately so `ray connect` works right
        // away, rather than waiting up to one publisher interval (the active-gated
        // `spawn_contact_publisher` only re-checks every TTL/2).
        if let Some(secret) = app_config.contact_secret_key.clone()
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let endpoint_id = self.endpoint.id();
            tokio::spawn(async move {
                if let Err(e) = dht::publish_contact(&client, &secret, endpoint_id).await {
                    tracing::warn!(error = %e, "failed to publish contact record on connect");
                }
            });
        }

        tracing::info!(networks = count, "control plane connected");
    }

    /// Rebuild the live per-network SSH allow-list snapshot from persisted
    /// config, so a running listener authorizes against current rules. Cheap and
    /// only called on SSH config changes / activation (not the hot path).
    #[cfg(feature = "desktop")]
    pub(crate) fn rebuild_ssh_authz(&self) {
        let mut map = std::collections::HashMap::new();
        if let Ok(cfg) = config::load() {
            for n in &cfg.networks {
                if !n.ssh_allow.is_empty() {
                    map.insert(n.name.clone(), n.ssh_allow.clone());
                }
            }
        }
        self.ssh_authz.store(std::sync::Arc::new(map));
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
        let token = tokio_util::sync::CancellationToken::new();
        *guard = Some(token.clone());
        drop(guard);
        self.rebuild_ssh_authz();
        let my_v4 = self.identity.local_ip();
        let my_v6 = derive_ipv6(&self.identity.local_identity());
        let server = crate::ssh::SshServer::new(
            self.peers.clone(),
            self.device_user_map.clone(),
            self.ssh_authz.clone(),
        );
        server.spawn(
            vec![std::net::IpAddr::V4(my_v4), std::net::IpAddr::V6(my_v6)],
            token,
        );
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
    /// Idempotent — a no-op if already active. Runs entirely inside the
    /// (root) daemon, so the IPC client needs no privileges.
    pub(crate) async fn activate(self: &Arc<Self>, hostname: Option<String>) -> IpcMessage {
        // Persist the personal default hostname first (before the already-active
        // short-circuit) so `ray up --hostname X` records the new default even
        // when the VPN is already up. Used as the fallback for future
        // creates/joins; doesn't rename networks already joined.
        if let Some(h) = hostname {
            if !crate::hostname::is_valid_hostname(&h) {
                return IpcMessage::Error {
                    message: format!(
                        "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                    ),
                };
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
            let tun_name = self.tun_name.lock().unwrap().clone();
            if let Err(e) = tun::set_link_up(&tun_name) {
                tracing::warn!(error = %e, "failed to bring TUN interface up");
                warnings.push(format!("failed to bring TUN interface up: {e}"));
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
            let my_v4 = self.identity.local_ip();
            let my_v6 = derive_ipv6(&self.identity.local_identity());
            if let Err(e) = tun::route_self_loopback(my_v4, my_v6).await {
                tracing::warn!(error = %e, "failed to install loopback self-route");
                warnings.push(format!("failed to install loopback self-route: {e}"));
            }
        }

        self.configure_magic_dns(&mut warnings).await;

        // Start the embedded mesh SSH server if enabled. It binds the mesh IPs'
        // port 22, so it follows the data plane (mesh addresses must be up).
        #[cfg(feature = "desktop")]
        if config::load().map(|c| c.ssh_enabled).unwrap_or(false) {
            self.start_ssh();
        }

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

    /// Point system DNS at the in-daemon Magic DNS resolver: detect the OS DNS
    /// backend, merge any user-configured upstreams over the captured ones, and
    /// (Linux direct-resolv.conf mode) spawn the inotify re-assert watcher.
    /// Failures are non-fatal — pushed to `warnings` so `ray up` can surface them.
    async fn configure_magic_dns(&self, warnings: &mut Vec<String>) {
        // Configure system DNS to route .ray queries to our in-daemon resolver.
        dns_config::restore_stale_backups();
        let tun_name = self.tun_name.lock().unwrap().clone();
        match dns_config::detect_and_configure(&tun_name).await {
            Ok(c) => {
                let captured = c.captured_upstreams();
                // Merge any user-configured DNS upstreams over the system-captured
                // set (replace drops the captured ones; augment tries custom first).
                let dns_override = config::load().map(|c| c.dns_upstreams).unwrap_or_default();
                let upstreams = config::resolve_upstreams(&dns_override, captured);
                let is_direct = c.name() == "direct-resolv.conf";
                #[cfg(target_os = "linux")]
                let search = c.search_domains();
                tracing::info!(backend = c.name(), resolver_ip = %crate::dns::MAGIC_DNS_V4, upstreams = ?upstreams, "Magic DNS active");
                self.resolver.set_upstreams(upstreams);
                *self.dns_configurator.lock().unwrap() = Some(c);
                // In direct mode, re-assert /etc/resolv.conf the instant another
                // program (NetworkManager, dhclient) overwrites it (inotify watch).
                #[cfg(target_os = "linux")]
                if is_direct {
                    let rt = tokio_util::sync::CancellationToken::new();
                    *self.dns_reassert_token.lock().unwrap() = Some(rt.clone());
                    tokio::spawn(dns_config::run_resolv_reassert(search, rt));
                }
                #[cfg(not(target_os = "linux"))]
                let _ = is_direct;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to configure system DNS (Magic DNS requires manual setup)");
                warnings.push(format!(
                    "failed to configure system DNS, so .ray names won't resolve: {e}"
                ));
            }
        }
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

        if let Some(rt) = self.dns_reassert_token.lock().unwrap().take() {
            rt.cancel();
        }

        // The SSH listeners bind the mesh IPs, which go down with the data plane.
        #[cfg(feature = "desktop")]
        self.stop_ssh();

        // Revert system DNS (extract the configurator before reverting so the
        // mutex guard isn't held across the call).
        let configurator = self.dns_configurator.lock().unwrap().take();
        if let Some(configurator) = configurator
            && let Err(e) = dns_config::revert(configurator.as_ref()).await
        {
            tracing::warn!(error = %e, "failed to revert DNS configuration");
        }
        let tun_name = self.tun_name.lock().unwrap().clone();
        dns_config::clear_search_domains(&tun_name).await;

        #[cfg(not(target_os = "android"))]
        if let Err(e) = tun::set_link_down(&tun_name) {
            tracing::warn!(error = %e, "failed to bring TUN interface down");
        }

        tracing::info!("VPN on standby");
        IpcMessage::Ok {
            message: "VPN on standby (still connected to peers)".into(),
        }
    }

    /// Tear down a network's runtime state (connections, ALPN, DNS entries,
    /// background tasks) without touching its persisted config. Returns whether
    /// the network was active. Used by `leave_network` (which also forgets the
    /// config); standby (`deactivate`) no longer tears connections down.
    pub(crate) async fn teardown_network_runtime(&self, name: &str) -> bool {
        let Some(handle) = self.networks.remove(name).map(|(_, v)| v) else {
            return false;
        };
        handle.cancel.cancel();
        for task in handle.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }

        self.peers.remove_by_network(name);
        dns::remove_network(&self.hostname_table, &self.reverse_table, name).await;
        self.protocol_router
            .unregister(&transport::network_alpn(&handle.network_key));
        self.refresh_alpns().await;
        true
    }

    #[tracing::instrument(skip(self), fields(net = name))]
    pub(crate) async fn leave_network(&self, name: &str) -> IpcMessage {
        // Gracefully close our connections with the leave code BEFORE teardown
        // drops them, so each peer's reader sees an intentional close and the
        // coordinator prunes us from the roster (rather than waiting for an
        // idle timeout that only ever clears the green dot).
        for (_eid, _ip, conn) in self.peers.peers_for_network_with_conn(name) {
            conn.close(VarInt::from_u32(forward::LEAVE_CODE), b"leave");
        }

        let was_active = self.teardown_network_runtime(name).await;

        // Remove from config even if the network wasn't active
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

}
