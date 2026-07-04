//! Network create + join handlers for `MeshManager`: `create_network*`, the join
//! handshake (`join_network*`, dial/fetch/restore-roster helpers). Split out of `daemon/mod.rs`.

use super::super::*;

/// Borrowed bundle of the per-join inputs threaded through the dial + finalize
/// phases of `join_network_inner`, so each phase takes one argument instead of a
/// dozen. The references point at locals that live for the whole join.
struct JoinContext<'a> {
    display_name: &'a str,
    my_hostname: &'a str,
    alpn: &'a [u8],
    my_ip: Ipv4Addr,
    net_pubkey: EndpointId,
    /// Single-use invite secret to redeem at admission, if any. Cloned per dial
    /// attempt (a fresh join may try several coordinators).
    invite: Option<Vec<u8>>,
    auto_accept_firewall: bool,
    /// Seed for per-network auto-accept of file offers from own devices
    /// (`--auto-accept-files`); persisted, config wins on reconnect/restore.
    auto_accept_files: bool,
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    /// Pinned coordinator to dial first (the invite minter), if known.
    coordinator: Option<EndpointId>,
}

/// A live mesh connection produced by the dial phase: the per-network state cell
/// plus the cancellation token, disconnect channel, and background tasks that
/// `finalize_join` folds into the `NetworkHandle`.
struct EstablishedMesh {
    state: SharedNetworkState,
    cancel: CancellationToken,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Tear down a failed dial attempt: cancel the token and abort every spawned
/// task. Used on each unreachable/denied coordinator before trying the next.
fn abort_join_tasks(cancel: &CancellationToken, tasks: Vec<tokio::task::JoinHandle<()>>) {
    cancel.cancel();
    for t in tasks {
        t.abort();
    }
}

impl MeshManager {
    /// Refresh the network's blob snapshot, store its bytes in the local blob
    /// store, and publish the network-key-signed pkarr record (blob hash + this
    /// endpoint as the seed peer). Shared by network creation and coordinator
    /// restore — both seal a freshly built `NetworkState` and announce it.
    pub(crate) async fn seal_and_publish(
        &self,
        net_state: &mut NetworkState,
        net_secret_key: &SecretKey,
    ) {
        net_state.refresh_snapshot();
        if let Some(snap) = &net_state.snapshot {
            let _ = self.blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            let blob_hash = net_state
                .snapshot
                .as_ref()
                .map(|s| s.hash)
                .expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                net_secret_key,
                &blob_hash,
                &[self.endpoint.id()],
            )
            .await
            {
                tracing::warn!(error = %e, "failed to publish network record");
            }
        }
    }

    /// Spawn the two background tasks every coordinator network needs: the pkarr
    /// record publisher and the peer-disconnect cleanup (which republishes the
    /// blob when a member drops). Returns the task handles plus the
    /// `disconnect_tx` the accept handlers feed. Shared by create + restore.
    pub(crate) fn spawn_coordinator_background_tasks(
        &self,
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

        // Network publisher (single pkarr record: blob hash + seed peers)
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_network_publisher(
                pkarr_client,
                net_secret_key.clone(),
                state.clone(),
                self.endpoint.id(),
                self.peers.clone(),
                name.to_string(),
                dht_notify.clone(),
                cancel.clone(),
            ));
        }

        // Disconnect handler (coordinator removes dead peers, republishes blob)
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(
            disconnect_rx,
            self.peers.clone(),
            cancel.clone(),
            Some(CoordinatorCleanup {
                state: state.clone(),
                blob_store: self.blob_store.clone(),
                dht_notify: Some(dht_notify.clone()),
                hostname_table: self.dns.hostname_table.clone(),
                reverse_table: self.dns.reverse_table.clone(),
                device_user_map: self.device_user_map.clone(),
                network_name: name.to_string(),
            }),
        ));

        (tasks, disconnect_tx)
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// create a new network and register this node as its coordinator.
    #[tracing::instrument(skip(self, hostname), fields(mode = ?mode))]
    pub async fn create_network(
        &self,
        mode: GroupMode,
        name: Option<String>,
        hostname: Option<String>,
    ) -> IpcMessage {
        match self
            .create_network_inner(mode, name, hostname, false, None)
            .await
        {
            Ok(resp) => resp,
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    /// Create a network and register it as coordinator.
    ///
    /// `direct` marks an auto-minted 2-peer `ray connect` network (persisted so
    /// `ray status` can tag it). `pre_approve` adds a peer to the `ApprovedList`
    /// before the blob is signed/published, so the named peer can be welcomed
    /// without a separate `ray accept` round-trip — used by `approve_connection`.
    /// Build the initial [`NetworkState`] for a freshly created network: the
    /// creator as sole coordinator, plus any `pre_approve` peer (a `ray connect`
    /// requester) admitted up front so the published blob already carries the
    /// approval and the peer is welcomed on its join without a separate
    /// `ray accept`.
    fn build_initial_roster(
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
                identity: self.identity.local_identity(),
                ip: my_ip,
                is_coordinator: true,
                hostname: Some(my_hostname.to_string()),
                user_identity: None,
                device_cert: None,
                collision_index: 0,
            })
            .expect("self-add cannot collide");

        let mut approved = ApprovedList::new();
        if let Some((peer_id, peer_hostname)) = pre_approve {
            let peer_ip = self.identity.derive_ip(&peer_id);
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
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        })
    }

    pub(crate) async fn create_network_inner(
        &self,
        mode: GroupMode,
        custom_name: Option<String>,
        hostname: Option<String>,
        direct: bool,
        pre_approve: Option<(EndpointId, Option<String>)>,
    ) -> Result<IpcMessage> {
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

        // Generate per-network keypair
        let net_secret_key = SecretKey::generate();
        let net_public_key = net_secret_key.public();

        if self.networks.contains_key(&name) {
            return Ok(IpcMessage::Error {
                message: format!("network '{name}' already active"),
            });
        }

        let my_ip = self.identity.local_ip();

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

        // Register in DNS hostname table
        dns::update_hostname(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            &name,
            &my_hostname,
            my_ip,
            derive_ipv6(&self.identity.local_identity()),
        )
        .await;

        self.seal_and_publish(&mut net_state, &net_secret_key).await;

        // Save to config
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
            auto_accept_files: false,
            admins: vec![],
            direct,
            ssh_allow: vec![],
            aliases: BTreeMap::new(),
        })?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let invite_lock = Arc::new(tokio::sync::Mutex::new(()));
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        let (tasks, disconnect_tx) = self.spawn_coordinator_background_tasks(
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

        // Register protocol handler for this network
        self.register_coordinator_handler(
            &name,
            state,
            invite_lock,
            Some(dht_notify),
            net_public_key,
            disconnect_tx,
            cancel,
        );
        self.refresh_alpns().await;

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network created");

        Ok(IpcMessage::Created {
            name,
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        })
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// join an existing network by key (optionally with an invite/coordinator).
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self, hostname), fields(net = name.unwrap_or(network_key)))]
    pub async fn join_network(
        self: &Arc<Self>,
        network_key: &str,
        name: Option<&str>,
        hostname: Option<String>,
        invite: Option<Vec<u8>>,
        coordinator: Option<EndpointId>,
        auto_accept_firewall: bool,
        auto_accept_files: bool,
    ) -> IpcMessage {
        match self
            .join_network_inner(
                network_key,
                name,
                hostname.clone(),
                invite.clone(),
                coordinator,
                auto_accept_firewall,
                auto_accept_files,
                true,
            )
            .await
        {
            Ok(TryJoin::Joined(resp)) => {
                let _ = config::remove_pending_join(network_key);
                resp
            }
            Ok(TryJoin::Pending) => {
                // Persist so the retry resumes after a restart.
                let _ = config::add_pending_join(config::PendingJoinEntry {
                    network_key: network_key.to_string(),
                    name: name.map(|s| s.to_string()),
                });
                // Closed network: queued for live approval. Retry in the
                // background on a backoff until `ray accept` admits us.
                let me = Arc::clone(self);
                let nk = network_key.to_string();
                let nm = name.map(|s| s.to_string());
                tokio::spawn(async move {
                    let mut backoff = BACKOFF_INITIAL;
                    loop {
                        tokio::select! {
                            _ = me.shutdown_token.cancelled() => return,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        match me
                            .join_network_inner(
                                &nk,
                                nm.as_deref(),
                                hostname.clone(),
                                invite.clone(),
                                coordinator,
                                auto_accept_firewall,
                                auto_accept_files,
                                true,
                            )
                            .await
                        {
                            Ok(TryJoin::Joined(_)) => {
                                let _ = config::remove_pending_join(&nk);
                                tracing::info!(net = %nk, "approval granted - joined");
                                return;
                            }
                            Ok(TryJoin::Pending) => continue,
                            Err(e) => {
                                tracing::warn!(net = %nk, error = %e, "join retry failed");
                            }
                        }
                    }
                });
                IpcMessage::Ok {
                    message: "join request sent - waiting for coordinator approval (run `ray status` to check)"
                        .to_string(),
                }
            }
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn join_network_inner(
        self: &Arc<Self>,
        network_key: &str,
        alias: Option<&str>,
        hostname: Option<String>,
        invite: Option<Vec<u8>>,
        coordinator: Option<EndpointId>,
        // Auto-install coordinator-suggested firewall rules on this network
        // (`--auto-accept-firewall`); persisted so it survives restarts.
        auto_accept_firewall: bool,
        // Seed for per-network auto-accept of file offers from own devices
        // (`--auto-accept-files`); persisted, config wins on reconnect/restore.
        auto_accept_files: bool,
        // True for a fresh join (we send a JoinRequest first); false when
        // restoring a network we're already a member of (legacy handshake where
        // the coordinator speaks first).
        initial: bool,
    ) -> Result<TryJoin> {
        let net_pubkey: EndpointId = network_key.parse().context("invalid network key")?;

        if let Some(a) = alias
            && self.networks.contains_key(a)
        {
            anyhow::bail!("already in network '{a}'");
        }

        let data = self.resolve_and_fetch_blob(net_pubkey).await?;

        let alpn = transport::network_alpn(&net_pubkey);
        let my_ip = self.identity.local_ip();
        // Use coordinator's network name from GroupBlob, or user alias, or truncated key as fallback
        let blob_name = data
            .name
            .clone()
            .unwrap_or_else(|| network_key[..network_key.len().min(8)].to_string());
        let display_name_owned = alias.map(|a| a.to_string()).unwrap_or(blob_name);
        let display_name = display_name_owned.as_str();

        if self.networks.contains_key(display_name) {
            anyhow::bail!("already in network '{display_name}'");
        }

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

        // One invite-ledger lock for this network, shared between the join's
        // control listener (which may handle InviteShare/InviteUsed once this
        // node is promoted to co-coordinator) and the coordinator handler we may
        // register below — so all ledger access stays serialized.
        let invite_lock = Arc::new(tokio::sync::Mutex::new(()));

        let ctx = JoinContext {
            display_name,
            my_hostname: &my_hostname,
            alpn: &alpn,
            my_ip,
            net_pubkey,
            invite,
            auto_accept_firewall,
            auto_accept_files,
            invite_lock: invite_lock.clone(),
            coordinator,
        };

        // Establish the mesh link. A fresh join tries each coordinator in the
        // blob's dial order (minter first) until one welcomes us; a reconnect/
        // restore uses the legacy single-coordinator handshake where the
        // coordinator speaks first. Either may return `None` (closed network,
        // queued for `ray accept`) — propagate that to the caller as `Pending`.
        let established = if initial {
            self.dial_fresh_join(&ctx, &data).await?
        } else {
            self.dial_reconnect(&ctx, &data).await?
        };
        let Some(mesh) = established else {
            return Ok(TryJoin::Pending);
        };

        self.finalize_join(ctx, &data, mesh).await
    }

    /// Resolve a network's signed pkarr record, gate on mesh-protocol version,
    /// and fetch + verify its `GroupBlob` from a seed peer. The version check is
    /// a pre-dial courtesy: the versioned ALPN is the hard gate but fails
    /// opaquely, so comparing the network-key-signed record up front yields a
    /// precise, actionable error instead.
    async fn resolve_and_fetch_blob(
        &self,
        net_pubkey: EndpointId,
    ) -> Result<crate::membership::GroupBlob> {
        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let record = dht::resolve_network_packet(&pkarr_client, net_pubkey)
            .await
            .context("failed to resolve network record")?;

        // Absent version (older record) ⇒ skip and let the ALPN gate decide.
        if let Some(net_ver) = dht::mesh_version_from_record(&record) {
            let mine = transport::MESH_PROTOCOL_VERSION;
            anyhow::ensure!(
                net_ver == mine,
                "incompatible mesh protocol: this network runs v{net_ver}, this build speaks v{mine} \
                 - run `ray update` so both sides match"
            );
        }

        let (expected_hash, peer_ids) =
            dht::decode_network_record(&record).context("invalid network record")?;
        if peer_ids.is_empty() {
            anyhow::bail!("no peers found in network record");
        }
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        for peer_id in &peer_ids {
            match self.try_fetch_group_blob(*peer_id, blob_hash).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    tracing::warn!(peer = %peer_id.fmt_short(), error = %e, "failed to fetch blob");
                }
            }
        }
        anyhow::bail!("could not fetch group blob from any peer")
    }

    /// Fresh-join dial: try each coordinator in `coordinator_dial_order` (minter
    /// first) until one welcomes us. `Ok(None)` means a coordinator queued the
    /// request (`JoinPending`) and we stop there; the caller retries with backoff
    /// until `ray accept` admits us.
    async fn dial_fresh_join(
        self: &Arc<Self>,
        ctx: &JoinContext<'_>,
        data: &crate::membership::GroupBlob,
    ) -> Result<Option<EstablishedMesh>> {
        let my_id = self.identity.local_identity();
        // With no invite, use our own id as the nominal minter;
        // coordinator_dial_order filters it out (minter != me), so we just get
        // all blob coordinators in order.
        let minter = ctx.coordinator.unwrap_or(my_id);
        let order = coordinator_dial_order(minter, &data.members, my_id);
        if order.is_empty() {
            anyhow::bail!("no coordinator found in network record");
        }

        let mut last_err = anyhow::anyhow!("no coordinators tried");
        for coordinator_id in &order {
            let cancel = self.shutdown_token.child_token();
            let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
            let tasks =
                vec![self.spawn_join_reconnect(ctx, my_id, &disconnect_tx, disconnect_rx, &cancel)];

            tracing::info!(coordinator = %coordinator_id.fmt_short(), "connecting to coordinator");
            let conn = match transport::connect_to_peer_with_alpn(
                &self.endpoint,
                *coordinator_id,
                ctx.alpn,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(coordinator = %coordinator_id.fmt_short(), error = %e, "coordinator unreachable, trying next");
                    abort_join_tasks(&cancel, tasks);
                    last_err = anyhow::anyhow!("coordinator offline: {e}");
                    continue;
                }
            };

            match self
                .run_join_handshake(
                    ctx,
                    data,
                    conn,
                    true,
                    &disconnect_tx,
                    &cancel,
                    ctx.invite.clone(),
                )
                .await
            {
                Ok(JoinResult::Joined(state)) => {
                    return Ok(Some(EstablishedMesh {
                        state,
                        cancel,
                        disconnect_tx,
                        tasks,
                    }));
                }
                Ok(JoinResult::Pending) => {
                    // This coordinator queued the request — don't try the next;
                    // let the caller retry with backoff until accepted.
                    abort_join_tasks(&cancel, tasks);
                    return Ok(None);
                }
                Err(e) => {
                    tracing::warn!(coordinator = %coordinator_id.fmt_short(), error = %e, "coordinator denied or unreachable, trying next");
                    abort_join_tasks(&cancel, tasks);
                    last_err = e;
                }
            }
        }

        anyhow::bail!(
            "no coordinator admitted the join (tried {}): {last_err:#}",
            order.len()
        )
    }

    /// Reconnect/restore dial: the coordinator speaks first, so pick the single
    /// coordinator from the blob and run the legacy handshake. `Ok(None)` when
    /// queued for live approval (caller retries on backoff).
    async fn dial_reconnect(
        self: &Arc<Self>,
        ctx: &JoinContext<'_>,
        data: &crate::membership::GroupBlob,
    ) -> Result<Option<EstablishedMesh>> {
        let coordinator_id = ctx
            .coordinator
            .or_else(|| {
                data.members
                    .iter()
                    .find(|m| m.is_coordinator)
                    .map(|m| m.identity)
            })
            .context("no coordinator found in network record")?;

        // The reconnect loop is spawned unconditionally and up front. A member
        // already holds the verified blob, so being *in* the network does not
        // depend on the coordinator answering right now: if it is offline at
        // restore we still register the network from the blob and let this loop
        // dial it back when it returns. Without this a member that reboots while
        // its coordinator is down silently drops the network from its running
        // state until a lucky restart.
        let cancel = self.shutdown_token.child_token();
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        let my_id = self.identity.local_identity();
        let tasks =
            vec![self.spawn_join_reconnect(ctx, my_id, &disconnect_tx, disconnect_rx, &cancel)];

        // Fallback state built straight from the verified blob so registration
        // never blocks on (or dies with) the coordinator handshake.
        let state_from_blob = || {
            let mut ns = NetworkState {
                members: MemberList::from_members(data.members.clone()),
                approved: ApprovedList::from_entries(data.approved.clone()),
                snapshot: None,
                network_secret_key: None,
                network_public_key: ctx.net_pubkey,
                network_name: Some(ctx.display_name.to_string()),
                mode: GroupMode::Restricted,
                suggested_firewall: data.suggested_firewall.clone(),
                reusable_keys: data.reusable_keys.clone(),
                pending_suggestions: Vec::new(),
                pending: HashMap::new(),
            };
            ns.refresh_snapshot();
            Arc::new(std::sync::RwLock::new(ns))
        };

        tracing::info!(coordinator = %coordinator_id.fmt_short(), "connecting to coordinator");
        let mut seed_from_blob = false;
        let state = match transport::connect_to_peer_with_alpn(
            &self.endpoint,
            coordinator_id,
            ctx.alpn,
        )
        .await
        {
            Ok(conn) => match self
                .run_join_handshake(
                    ctx,
                    data,
                    conn,
                    false,
                    &disconnect_tx,
                    &cancel,
                    ctx.invite.clone(),
                )
                .await
            {
                Ok(JoinResult::Joined(state)) => state,
                Ok(JoinResult::Pending) => {
                    // Closed network: queued for live approval. Stop the just-
                    // spawned reconnect loop (nothing connected yet); caller
                    // retries on a backoff until `ray accept` lets us in.
                    abort_join_tasks(&cancel, tasks);
                    return Ok(None);
                }
                Err(e) => {
                    // Dialed the coordinator but the handshake failed. We still
                    // hold the verified blob, so register from it and let the
                    // reconnect loop recover rather than dropping the network.
                    tracing::warn!(coordinator = %coordinator_id.fmt_short(), error = %e, "coordinator handshake failed on restore; registering from blob, reconnect loop will retry");
                    seed_from_blob = true;
                    state_from_blob()
                }
            },
            Err(e) => {
                // Coordinator offline at restore: register from the blob so the
                // network stays live; the reconnect loop dials it back once it
                // returns.
                tracing::warn!(coordinator = %coordinator_id.fmt_short(), error = %e, "coordinator offline on restore; registering from blob, reconnect loop will retry");
                seed_from_blob = true;
                state_from_blob()
            }
        };

        // The reconnect loop is edge-triggered on disconnect events, so a cold
        // registration (no live connection yet) needs a synthetic kick per member
        // to start the backoff-retry dial. Only fires when we registered from the
        // blob without a live handshake.
        if seed_from_blob {
            let me = self.identity.local_identity();
            for m in &data.members {
                if m.identity == me {
                    continue;
                }
                let _ = disconnect_tx
                    .send(forward::DisconnectEvent {
                        endpoint_id: m.identity,
                        ip: m.ip,
                        ipv6: derive_ipv6(&m.identity),
                        network: ctx.display_name.to_string(),
                        intentional: false,
                        // Synthetic cold-restore kick: no live connection backs
                        // it, so it must always drive the reconnect dial.
                        conn_stable_id: None,
                    })
                    .await;
            }
        }

        Ok(Some(EstablishedMesh {
            state,
            cancel,
            disconnect_tx,
            tasks,
        }))
    }

    /// Spawn the per-network reconnect loop used by both dial paths.
    fn spawn_join_reconnect(
        &self,
        ctx: &JoinContext<'_>,
        my_id: EndpointId,
        disconnect_tx: &mpsc::Sender<forward::DisconnectEvent>,
        disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
        cancel: &CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        spawn_reconnect_loop(
            disconnect_rx,
            self.endpoint.clone(),
            ctx.alpn.to_vec(),
            ctx.display_name.to_string(),
            my_id,
            ctx.my_ip,
            self.mesh_ctx(),
            disconnect_tx.clone(),
            cancel.clone(),
            self.current_device_cert(),
        )
    }

    /// Run the mesh handshake over an established connection (shared by both dial
    /// paths). `initial` distinguishes a fresh join (we speak first) from a
    /// reconnect/restore (coordinator speaks first).
    #[allow(clippy::too_many_arguments)]
    async fn run_join_handshake(
        &self,
        ctx: &JoinContext<'_>,
        data: &crate::membership::GroupBlob,
        conn: iroh::endpoint::Connection,
        initial: bool,
        disconnect_tx: &mpsc::Sender<forward::DisconnectEvent>,
        cancel: &CancellationToken,
        invite_secret: Option<Vec<u8>>,
    ) -> Result<JoinResult> {
        join_mesh_shared(
            conn,
            &self.endpoint,
            ctx.display_name,
            ctx.alpn,
            self.mesh_ctx(),
            JoinParams {
                my_hostname: Some(ctx.my_hostname.to_string()),
                net_pubkey: ctx.net_pubkey,
                device_cert: self.current_device_cert(),
                invite_secret,
                suggested_firewall: data.suggested_firewall.clone(),
                reusable_keys: data.reusable_keys.clone(),
                auto_accept_firewall: ctx.auto_accept_firewall,
                auto_accept_files: ctx.auto_accept_files,
                initial,
            },
            disconnect_tx.clone(),
            cancel.clone(),
            self.promote_tx.clone(),
            ctx.invite_lock.clone(),
            self.protocol_router.pending_pongs.clone(),
        )
        .await
    }

    /// Register the accept handler, persist the network public key, seed the blob
    /// store, spawn the membership poller, install the `NetworkHandle`, and sync
    /// DNS. Runs once the dial phase produced a live mesh connection.
    async fn finalize_join(
        self: &Arc<Self>,
        ctx: JoinContext<'_>,
        data: &crate::membership::GroupBlob,
        mesh: EstablishedMesh,
    ) -> Result<TryJoin> {
        let EstablishedMesh {
            state,
            cancel,
            disconnect_tx,
            mut tasks,
        } = mesh;
        let JoinContext {
            display_name,
            my_hostname,
            alpn,
            my_ip,
            net_pubkey,
            invite_lock,
            ..
        } = ctx;

        // A node that already holds the network secret key (e.g. a
        // co-coordinator joining after a config-only restore) should run as
        // Coordinator so it can admit future peers immediately — even though
        // it arrived here via join rather than restore.
        let held_key = state.read().unwrap().network_secret_key.clone();
        match role_for_key_holder(held_key.is_some()) {
            NetworkRole::Coordinator => {
                let net_public_key = state.read().unwrap().network_public_key;
                self.register_coordinator_handler(
                    display_name,
                    state.clone(),
                    invite_lock.clone(),
                    None,
                    net_public_key,
                    disconnect_tx.clone(),
                    cancel.clone(),
                );
            }
            // `Direct` is a display-only role (set in `status`), never produced by
            // `role_for_key_holder`; a non-key-holder runs as a plain member.
            NetworkRole::Member | NetworkRole::Direct => {
                self.protocol_router.register(
                    alpn.to_vec(),
                    AcceptHandler::Member(Arc::new(MemberAcceptState {
                        ctx: self.mesh_ctx(),
                        network_name: display_name.to_string(),
                        state: state.clone(),
                        disconnect_tx: disconnect_tx.clone(),
                        token: cancel.clone(),
                    })),
                );
            }
        }

        // Set the network public key on the state
        {
            let mut s = state.write().unwrap();
            s.network_public_key = net_pubkey;
            s.refresh_snapshot();
        }
        let snap_bytes = state
            .read()
            .unwrap()
            .snapshot
            .as_ref()
            .map(|s| s.msgpack_bytes.clone());
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        // Save config with network public key (use display_name for config)
        if let Ok(Some(mut net)) = config::load_network(display_name) {
            net.network_public_key = Some(net_pubkey);
            let _ = config::save_network(&net);
        }

        // Membership poller
        if let Ok(poller_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_group_poller(
                poller_client,
                net_pubkey,
                state.clone(),
                self.endpoint.clone(),
                self.mesh_ctx(),
                display_name.to_string(),
                cancel.clone(),
            ));
        }

        let handle = NetworkHandle {
            name: display_name.to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Member,
            my_ip,
            state,
            dht_notify: None,
            cancel,
            tasks,
            invite_lock,
            disconnect_tx,
        };
        self.networks.insert(display_name.to_string(), handle);
        self.refresh_alpns().await;

        // Register hostnames in DNS table
        dns::update_hostname(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            display_name,
            my_hostname,
            my_ip,
            derive_ipv6(&self.identity.local_identity()),
        )
        .await;
        for member in &data.members {
            if let Some(ref h) = member.hostname {
                dns::update_hostname(
                    &self.dns.hostname_table,
                    &self.dns.reverse_table,
                    display_name,
                    h,
                    member.ip,
                    derive_ipv6(&member.identity),
                )
                .await;
            }
        }

        tracing::info!(network = %display_name, key = %net_pubkey, ip = %my_ip, "joined network");

        Ok(TryJoin::Joined(IpcMessage::Joined {
            name: display_name.to_string(),
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        }))
    }

    /// Fetch the authoritative GroupBlob for a network we coordinate, used to
    /// restore the roster across a daemon restart. Resolves the pkarr record to
    /// get the blob hash, reads the bytes back from the local blob store (where
    /// we stored them before publishing — no network round-trip), and verifies +
    /// decodes. Falls back to fetching from a seed peer if the local store
    /// doesn't have them (e.g. blobs dir was wiped). Returns an error if the DHT
    /// is unreachable, so the caller can fall back to the (possibly stale)
    /// config roster rather than booting empty.
    pub(crate) async fn restore_roster_from_blob(
        &self,
        net_pubkey: EndpointId,
    ) -> Result<crate::membership::GroupBlob> {
        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, seed_peers) = dht::resolve_network(&pkarr_client, net_pubkey)
            .await
            .context("resolve pkarr record for roster restore")?;
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        // Local blob store first: the coordinator stored these bytes before
        // publishing, so they're on disk.
        if let Ok(bytes) = self.blob_store.blobs().get_bytes(blob_hash).await
            && let Ok(data) = verify_group_blob(&bytes, &expected_hash)
        {
            return Ok(data);
        }

        // Fall back to fetching from a seed peer.
        for peer_id in &seed_peers {
            if *peer_id == self.endpoint.id() {
                continue;
            }
            let conn = match transport::connect_to_peer_with_alpn(
                &self.endpoint,
                *peer_id,
                iroh_blobs::protocol::ALPN,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => continue,
            };
            if self
                .blob_store
                .remote()
                .fetch(conn, HashAndFormat::raw(blob_hash))
                .await
                .is_err()
            {
                continue;
            }
            if let Ok(bytes) = self.blob_store.blobs().get_bytes(blob_hash).await
                && let Ok(data) = verify_group_blob(&bytes, &expected_hash)
            {
                return Ok(data);
            }
        }
        anyhow::bail!("group blob not found locally or at any seed peer");
    }

    pub(crate) async fn try_fetch_group_blob(
        &self,
        peer_id: EndpointId,
        blob_hash: iroh_blobs::Hash,
    ) -> Result<crate::membership::GroupBlob> {
        let conn = transport::connect_to_peer_with_alpn(
            &self.endpoint,
            peer_id,
            iroh_blobs::protocol::ALPN,
        )
        .await?;
        self.blob_store
            .remote()
            .fetch(conn, HashAndFormat::raw(blob_hash))
            .await
            .map_err(|e| anyhow::anyhow!("blob fetch failed: {e}"))?;
        let bytes = self
            .blob_store
            .blobs()
            .get_bytes(blob_hash)
            .await
            .map_err(|e| anyhow::anyhow!("blob read failed: {e}"))?;
        crate::membership::decode_group_blob(&bytes)
    }

    #[allow(dead_code)]
    pub(crate) async fn try_dht_fallback_join(
        &self,
        network_name: &str,
        net_pubkey: EndpointId,
        alpn: &[u8],
    ) -> Result<IpcMessage> {
        tracing::info!(network = %network_name, "trying DHT fallback");

        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, _peer_ids) = dht::resolve_network(&pkarr_client, net_pubkey).await?;

        let my_identity = self.identity.local_identity();
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        let app_config = config::load()?;
        let net_config = app_config
            .networks
            .iter()
            .find(|n| n.name == network_name)
            .context("network not in config")?;

        for member in &net_config.members {
            if member.identity == my_identity {
                continue;
            }

            let blobs_conn = match transport::connect_to_peer_with_alpn(
                &self.endpoint,
                member.identity,
                iroh_blobs::protocol::ALPN,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => continue,
            };

            if self
                .blob_store
                .remote()
                .fetch(blobs_conn, HashAndFormat::raw(blob_hash))
                .await
                .is_err()
            {
                continue;
            }

            let blob_bytes = match self.blob_store.blobs().get_bytes(blob_hash).await {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            let data = verify_group_blob(&blob_bytes, &expected_hash)?;
            tracing::info!(network = %network_name, members = data.members.len(), "group blob resolved via DHT fallback");

            let my_ip = self.identity.local_ip();
            let my_hostname = net_config.my_hostname.clone();
            let cancel = self.shutdown_token.child_token();
            let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

            let tasks = vec![spawn_reconnect_loop(
                disconnect_rx,
                self.endpoint.clone(),
                alpn.to_vec(),
                network_name.to_string(),
                my_identity,
                my_ip,
                self.mesh_ctx(),
                disconnect_tx.clone(),
                cancel.clone(),
                self.current_device_cert(),
            )];

            self.dial_all_members(
                &data.members,
                alpn,
                network_name,
                my_identity,
                my_ip,
                my_hostname.clone(),
                disconnect_tx.clone(),
                cancel.clone(),
            )
            .await;

            let mut ns = NetworkState {
                members: MemberList::from_members(data.members),
                approved: ApprovedList::from_entries(data.approved),
                snapshot: None,
                network_secret_key: None,
                network_public_key: net_pubkey,
                network_name: data.name.clone(),
                mode: GroupMode::Restricted,
                suggested_firewall: SuggestedFirewall::default(),
                reusable_keys: data.reusable_keys.clone(),
                pending_suggestions: Vec::new(),
                pending: HashMap::new(),
            };
            ns.refresh_snapshot();
            let live_state = Arc::new(std::sync::RwLock::new(ns));

            let handle = NetworkHandle {
                name: network_name.to_string(),
                network_key: net_pubkey,
                role: NetworkRole::Member,
                my_ip,
                state: live_state,
                dht_notify: None,
                cancel,
                tasks,
                invite_lock: Arc::new(tokio::sync::Mutex::new(())),
                disconnect_tx,
            };
            self.networks.insert(network_name.to_string(), handle);
            self.refresh_alpns().await;

            return Ok(IpcMessage::Joined {
                name: network_name.to_string(),
                my_ip,
                my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
            });
        }

        anyhow::bail!("no peers reachable for DHT fallback")
    }

    /// Dial every known member of a network: open a QUIC connection on the
    /// network ALPN, send `MeshHello`, register the peer in the PeerTable, and
    /// spawn a peer reader for each. Shared by the join path and coordinator
    /// restore so a restarting coordinator/co-coordinator proactively
    /// reconnects to **all** known members (full mesh), not just the peers
    /// that happen to dial in. Failures per-peer are logged at debug and
    /// skipped (the reconnect loop + group poller are the backstop).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn dial_all_members(
        &self,
        members: &[Member],
        alpn: &[u8],
        network_name: &str,
        my_identity: EndpointId,
        my_ip: Ipv4Addr,
        my_hostname: Option<String>,
        disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
        cancel: CancellationToken,
    ) {
        // Announce the current name (a pending rename or the confirmed one),
        // read fresh from config, rather than a value captured before a rename.
        let my_hostname = outgoing_hostname(network_name).or(my_hostname);
        for m in members {
            if m.identity == my_identity {
                continue;
            }
            match transport::connect_to_peer_with_alpn(&self.endpoint, m.identity, alpn).await {
                Ok(peer_conn) => {
                    if let Ok((mut s, _)) = peer_conn.open_bi().await {
                        let _ = control::send_msg(
                            &mut s,
                            &ControlMsg::MeshHello {
                                identity: my_identity,
                                ip: my_ip,
                                hostname: my_hostname.clone(),
                                device_cert: self.current_device_cert(),
                            },
                        )
                        .await;
                    }
                    crate::spawn_path_logger(peer_conn.clone(), m.identity.fmt_short().to_string());
                    self.peers.add(
                        m.ip,
                        derive_ipv6(&m.identity),
                        peer_conn.clone(),
                        m.identity,
                        network_name,
                    );
                    forward::spawn_peer_reader(
                        peer_conn,
                        m.identity,
                        m.ip,
                        derive_ipv6(&m.identity),
                        network_name.to_string(),
                        forward::ForwardCtx {
                            firewall: self.firewall.clone(),
                            tun_tx: self.tun_tx.clone(),
                            disconnect_tx: disconnect_tx.clone(),
                            token: cancel.clone(),
                            stats: self.stats.clone(),
                            device_user_map: self.device_user_map.clone(),
                        },
                    );
                    tracing::info!(
                        network = %network_name,
                        peer = %m.identity.fmt_short(),
                        "dialed known member on restore/join (full mesh)"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        network = %network_name,
                        peer = %m.identity.fmt_short(),
                        error = %e,
                        "could not dial member yet; reconnect loop will retry"
                    );
                }
            }
        }
    }
}
