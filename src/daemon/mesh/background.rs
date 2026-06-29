//! Background tasks and roster reconvergence for the mesh core. Moved out of
//! `daemon/mod.rs` to keep that module focused on type definitions and process
//! wiring.
//!
//! Holds the per-network background loops (DHT publisher, group poller, peer
//! cleanup, coordinator control reader), the verified-blob reconvergence path
//! (`fetch_verified_blob`/`reconverge_and_apply`), coordinator gossip/dial-order
//! helpers, the suggested-firewall and roster-to-DNS application, and the
//! pending-rename drain. All are free functions over the shared handles; the
//! daemon-initiated control-message send helpers stay in `daemon/mod.rs`.

use super::super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_network_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    notify: Arc<tokio::sync::Notify>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let hash = {
                let s = state.read().unwrap();
                s.snapshot
                    .as_ref()
                    .map(|snap| snap.hash)
                    .unwrap_or_else(|| {
                        group_blob_hash(
                            &s.members,
                            &s.approved,
                            &s.suggested_firewall,
                            s.network_name.as_deref(),
                            &s.reusable_keys,
                        )
                    })
            };
            let mut seed_peers: Vec<EndpointId> = peers
                .peers_for_network(&network_name)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            seed_peers.push(endpoint_id);
            seed_peers.sort_by_key(|id| id.to_string());
            seed_peers.dedup();

            match dht::publish_network(&client, &net_secret_key, &hash, &seed_peers).await {
                Ok(()) => tracing::info!(peers = seed_peers.len(), "published network record"),
                Err(e) => tracing::warn!(error = %e, "failed to publish network record"),
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(300)) => {},
            }
        }
    })
}

/// Publish this node's contact record (`ray connect`).
/// Publishes the `contact_key -> current endpoint` pkarr record on a TTL/2
/// interval (record TTL is 300s). Runs for the lifetime of the daemon (control
/// plane), not gated by the data-plane `active` flag, so standby nodes stay
/// reachable for `ray connect` requests. Reads `contact_secret` fresh from
/// config each cycle so a `RotateContact` takes effect without a restart.
pub(crate) fn spawn_contact_publisher(
    client: PkarrRelayClient,
    endpoint_id: EndpointId,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let secret = config::load().ok().and_then(|c| c.contact_secret_key);
            if let Some(secret) = secret {
                match dht::publish_contact(&client, &secret, endpoint_id).await {
                    Ok(()) => {
                        tracing::debug!(contact = %secret.public().fmt_short(), "published contact record")
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to publish contact record"),
                }
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(150)) => {},
            }
        }
    })
}

/// A polling publisher for a *granted* co-coordinator (a member that received
/// the network key via `AdminGrant`). Unlike [`spawn_network_publisher`] (which
/// is notify-driven and spawned at create/restore time), this is spawned at
/// runtime when a member is promoted: it has no `dht_notify` handle, so it
/// re-reads the snapshot hash every few seconds and republishes on change.
/// Latency is bounded by `LAZY_PUBLISH_INTERVAL`; members' 60s group poller is
/// the downstream backstop regardless.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_lazy_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    token: CancellationToken,
) -> JoinHandle<()> {
    const LAZY_PUBLISH_INTERVAL: Duration = Duration::from_secs(10);
    tokio::spawn(async move {
        let mut last_hash: Option<blake3::Hash> = None;
        loop {
            let hash = {
                let s = state.read().unwrap();
                s.snapshot
                    .as_ref()
                    .map(|snap| snap.hash)
                    .unwrap_or_else(|| {
                        group_blob_hash(
                            &s.members,
                            &s.approved,
                            &s.suggested_firewall,
                            s.network_name.as_deref(),
                            &s.reusable_keys,
                        )
                    })
            };
            if last_hash != Some(hash) {
                let mut seed_peers: Vec<EndpointId> = peers
                    .peers_for_network(&network_name)
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect();
                seed_peers.push(endpoint_id);
                seed_peers.sort_by_key(|id| id.to_string());
                seed_peers.dedup();
                match dht::publish_network(&client, &net_secret_key, &hash, &seed_peers).await {
                    Ok(()) => {
                        tracing::info!(
                            network = %network_name,
                            "lazy publisher: published network record"
                        );
                        last_hash = Some(hash);
                    }
                    Err(e) => tracing::warn!(error = %e, "lazy publisher: publish failed"),
                }
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(LAZY_PUBLISH_INTERVAL) => {},
            }
        }
    })
}

/// Materialize this node's suggested firewall rules for `network` from the
/// verified blob state, then either install them (replacing the prior
/// `Network(net)` set, leaving `Local` rules untouched) when the node opted into
/// `--auto-accept-firewall`, or queue them for manual `ray firewall accept`. A
/// node with no assigned hostname is a no-op. Peer hostnames are resolved against
/// the blob's member list, so a rule for a not-yet-joined peer appears once it
/// joins and the roster updates.
pub(crate) fn apply_suggested_firewall(
    firewall: &SharedFirewall,
    my_identity: EndpointId,
    network_name: &str,
    state: &std::sync::RwLock<NetworkState>,
) {
    let (suggestions, members): (SuggestedFirewall, Vec<Member>) = {
        let s = state.read().unwrap();
        (s.suggested_firewall.clone(), s.roster())
    };
    // Derive my hostname from the member roster (the authoritative source) rather
    // than the join-time claim.
    let my_hostname = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone());
    let Some(my_hostname) = my_hostname else {
        return;
    };
    let map: HashMap<&str, EndpointId> = members
        .iter()
        .filter_map(|m| m.hostname.as_deref().map(|h| (h, m.identity)))
        .collect();
    let resolve = |h: &str| map.get(h).copied();
    let rules =
        firewall::materialize_suggestions(network_name, &my_hostname, &suggestions, &resolve);

    // Auto-install only if this node opted into `--auto-accept-firewall` for the
    // network; otherwise queue the materialized rules for `ray firewall accept`.
    let auto_accept = config::load()
        .ok()
        .and_then(|c| {
            c.networks
                .into_iter()
                .find(|n| n.name == network_name)
                .map(|n| n.auto_accept_firewall)
        })
        .unwrap_or(false);
    if auto_accept {
        let config = firewall.replace_network_rules(network_name, rules);
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, network = network_name, "failed to persist firewall config");
        }
        state.write().unwrap().pending_suggestions.clear();
        tracing::info!(
            network = network_name,
            "auto-accepted suggested firewall rules"
        );
    } else {
        // Don't re-queue suggestions this node already installed: an accepted
        // rule is re-materialized on every blob reconverge, so without this it
        // reappears in the pending queue indefinitely and re-accepting it stacks
        // a duplicate. Compare the full rule (selector + action) so a coordinator
        // flipping a rule's action still surfaces for review.
        let installed: Vec<firewall::FirewallRule> = firewall
            .get_config()
            .rules
            .iter()
            .filter(|r| matches!(&r.origin, firewall::RuleOrigin::Network(n) if n == network_name))
            .cloned()
            .collect();
        let fresh: Vec<firewall::FirewallRule> = rules
            .into_iter()
            .filter(|r| !installed.iter().any(|i| i == r))
            .collect();
        let count = fresh.len();
        state.write().unwrap().pending_suggestions = fresh;
        tracing::info!(
            network = network_name,
            count,
            "queued suggested firewall rules for review"
        );
    }
}

/// Resolve the network's *signed* group-blob hash (and seed peers) from the
/// pkarr record. This is the sole authority for the roster/firewall.
pub(crate) async fn resolve_signed(
    endpoint: &Endpoint,
    net_pubkey: EndpointId,
) -> Option<(blake3::Hash, Vec<EndpointId>)> {
    let client = dht::create_pkarr_client(endpoint).ok()?;
    dht::resolve_network(&client, net_pubkey).await.ok()
}

/// Fetch the group blob for `signed` from any connected peer or seed, and verify
/// its bytes against `signed`. Returns the verified blob, or `None` if no source
/// could serve a blob matching the signed hash. The blob is content-addressed by
/// `signed`, so a peer can only ever serve the authentic blob — never a forgery.
pub(crate) async fn fetch_verified_blob(
    endpoint: &Endpoint,
    blob_store: &FsStore,
    peers: &PeerTable,
    signed: blake3::Hash,
    network_name: &str,
    seeds: &[EndpointId],
) -> Option<crate::membership::GroupBlob> {
    let blob_hash = iroh_blobs::Hash::from_bytes(*signed.as_bytes());
    let mut peer_ids: Vec<EndpointId> = peers
        .peers_for_network(network_name)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    peer_ids.extend_from_slice(seeds);
    peer_ids.sort_by_key(|id| id.to_string());
    peer_ids.dedup();
    for pid in &peer_ids {
        if let Ok(conn) =
            transport::connect_to_peer_with_alpn(endpoint, *pid, iroh_blobs::protocol::ALPN).await
            && blob_store
                .remote()
                .fetch(conn, HashAndFormat::raw(blob_hash))
                .await
                .is_ok()
            && let Ok(bytes) = blob_store.blobs().get_bytes(blob_hash).await
            && let Ok(data) = crate::membership::verify_group_blob(&bytes, &signed)
        {
            return Some(data);
        }
    }
    None
}

/// Reconverge the live network state from the signed pkarr record and apply it
/// (roster + DNS + suggested firewall). Invoked when a peer sends a `MemberSync`
/// or `BlobUpdated` *hint* — the hint is only a trigger; the roster/firewall come
/// exclusively from the network-key-signed record, never from the peer message.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn reconverge_and_apply(
    endpoint: &Endpoint,
    ctx: &MeshCtx,
    net_pubkey: EndpointId,
    network_name: &str,
    state: &SharedNetworkState,
    my_identity: EndpointId,
    alpn: &[u8],
    my_ip: Ipv4Addr,
    device_cert: &Option<control::DeviceCert>,
) {
    let MeshCtx {
        peers,
        blob_store,
        firewall,
        hostname_table,
        reverse_table,
        ..
    } = ctx;
    let current = state.read().unwrap().snapshot.as_ref().map(|s| s.hash);
    let Some((signed, seeds)) = resolve_signed(endpoint, net_pubkey).await else {
        tracing::debug!(network = %network_name, "reconverge: signed record unavailable");
        return;
    };
    if crate::membership::trusted_reconverge_hash(current, signed).is_none() {
        // Already converged on the signed hash — but a local rename can still be
        // unconfirmed precisely *because* the coordinator hasn't republished, so
        // the hash never changes. Keep driving the rename to the coordinator
        // (the drain no-ops unless `pending_hostname` is set).
        let roster = state.read().unwrap().roster();
        drain_pending_rename(
            endpoint,
            &roster,
            alpn,
            network_name,
            my_identity,
            my_ip,
            device_cert,
        )
        .await;
        return;
    }
    let Some(data) =
        fetch_verified_blob(endpoint, blob_store, peers, signed, network_name, &seeds).await
    else {
        tracing::warn!(network = %network_name, "reconverge: could not fetch verified blob");
        return;
    };
    // Two coordinators can independently admit a fresh joiner at the same
    // collision index, producing a roster with duplicate IPs. Resolve it
    // deterministically (lowest identity keeps the slot, others re-roll) before
    // it reaches the PeerTable/DNS so every node converges on the same map.
    let tiebroken = crate::membership::resolve_ip_tiebreak(data.members.clone());
    if let Err(e) = crate::membership::validate_no_duplicate_ips(&tiebroken) {
        tracing::warn!(network = %network_name, error = %e, "roster still has duplicate IPs after tiebreak; applying tiebroken version");
    }
    let roster = {
        let mut s = state.write().unwrap();
        s.members = MemberList::from_members(tiebroken);
        s.approved = ApprovedList::from_entries(data.approved.clone());
        s.suggested_firewall = data.suggested_firewall.clone();
        s.refresh_snapshot();
        s.roster()
    };
    apply_roster_to_dns(
        &roster,
        network_name,
        my_identity,
        hostname_table,
        reverse_table,
    )
    .await;
    apply_suggested_firewall(firewall, my_identity, network_name, state);
    // If a local rename is still unconfirmed by this just-applied blob, keep
    // delivering it to the coordinator set until it lands.
    drain_pending_rename(
        endpoint,
        &roster,
        alpn,
        network_name,
        my_identity,
        my_ip,
        device_cert,
    )
    .await;
    tracing::info!(network = %network_name, "reconverged from signed record");
}

/// Compute the order in which a joiner should dial coordinators.
/// Returns the minter first (if present and not `me`), then every other
/// `is_coordinator` member except `me`, de-duplicated, preserving order.
/// Consumed by the join dial-fallback loop.
pub(crate) fn coordinator_dial_order(
    minter: EndpointId,
    members: &[Member],
    me: EndpointId,
) -> Vec<EndpointId> {
    let mut order = Vec::new();
    let is_coord = |id: EndpointId| members.iter().any(|m| m.identity == id && m.is_coordinator);
    if minter != me && is_coord(minter) {
        order.push(minter);
    }
    for m in members {
        if m.is_coordinator && m.identity != me && !order.contains(&m.identity) {
            order.push(m.identity);
        }
    }
    order
}

/// Pick the peers to gossip single-use invite state to: every other
/// `is_coordinator` member, excluding ourselves. Only coordinators (network-key
/// holders) can admit, so only they need the shared invite ledger; a
/// non-coordinator is never a target.
pub(crate) fn gossip_targets(members: &[Member], me: EndpointId) -> Vec<EndpointId> {
    members
        .iter()
        .filter(|m| m.is_coordinator && m.identity != me)
        .map(|m| m.identity)
        .collect()
}

/// Whether `peer` is a coordinator in our verified roster. Invite-gossip arms
/// (`InviteShare`/`InviteUsed`) act only on messages from a coordinator peer, so
/// a non-coordinator member can't inject or burn invite state.
pub(crate) fn sender_is_coordinator(state: &SharedNetworkState, peer: EndpointId) -> bool {
    state
        .read()
        .unwrap()
        .members
        .all()
        .iter()
        .any(|m| m.identity == peer && m.is_coordinator)
}

/// Send `msg` to each coordinator peer (per [`gossip_targets`]) that has a live
/// connection on `network`. Best-effort: a target without a live connection is
/// skipped (it will reconverge invite state from a future share/redeem or, for
/// reusable keys, the signed blob). Never carries the raw secret — only its hash.
pub(crate) async fn gossip_to_coordinators(
    peers: &PeerTable,
    network: &str,
    members: &[Member],
    me: EndpointId,
    msg: &ControlMsg,
) {
    let targets = gossip_targets(members, me);
    if targets.is_empty() {
        return;
    }
    for (eid, _ip, conn) in peers.peers_for_network_with_conn(network) {
        if !targets.contains(&eid) {
            continue;
        }
        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(&mut send, msg).await;
        }
    }
}

/// Outcome of a single coordinator dial attempt during the join fallback loop.
/// Used as a unit-testable specification of the loop termination policy.
#[derive(Clone, Copy, PartialEq, Debug)]
#[allow(dead_code)]
pub(crate) enum DialOutcome {
    Welcomed,
    Denied,
    Unreachable,
}

/// Returns `(index_of_last_tried, welcomed)`.
/// Iterates `outcomes` left-to-right and stops at the first `Welcomed`.
/// If none is found, returns the index of the last element and `false`.
#[allow(dead_code)]
pub(crate) fn pick_first_welcome(outcomes: &[DialOutcome]) -> (usize, bool) {
    for (i, o) in outcomes.iter().enumerate() {
        if *o == DialOutcome::Welcomed {
            return (i, true);
        }
    }
    (outcomes.len().saturating_sub(1), false)
}

/// Last-known roster from persisted config. Used only as a fallback when the
/// signed pkarr record is briefly unreachable during a reconnect — never trusts
/// peer-supplied membership.
pub(crate) fn persisted_roster(network_name: &str) -> Vec<Member> {
    config::load()
        .ok()
        .and_then(|c| c.networks.into_iter().find(|n| n.name == network_name))
        .map(|n| {
            n.members
                .into_iter()
                .map(|m| Member {
                    identity: m.identity,
                    ip: m.ip,
                    is_coordinator: m.is_coordinator,
                    hostname: m.hostname,
                    user_identity: None,
                    device_cert: None,
                    collision_index: 0,
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn spawn_group_poller(
    client: PkarrRelayClient,
    net_pubkey: EndpointId,
    state: SharedNetworkState,
    endpoint: Endpoint,
    ctx: MeshCtx,
    network_name: String,
    token: CancellationToken,
) -> JoinHandle<()> {
    let MeshCtx {
        peers,
        blob_store,
        firewall: fw,
        ..
    } = ctx;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(60)) => {},
            }

            let current_hash = {
                let s = state.read().unwrap();
                s.snapshot.as_ref().map(|snap| snap.hash)
            };

            let (remote_hash, _seed_peers) = match dht::resolve_network(&client, net_pubkey).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "group poll failed");
                    continue;
                }
            };

            if current_hash == Some(remote_hash) {
                continue;
            }

            tracing::info!(old = ?current_hash, new = %remote_hash, "group blob changed");

            let blob_hash = iroh_blobs::Hash::from_bytes(*remote_hash.as_bytes());

            let peer_ids: Vec<EndpointId> = peers
                .peers_for_network(&network_name)
                .into_iter()
                .map(|(id, _)| id)
                .collect();

            let mut new_data = None;
            for peer_id in &peer_ids {
                let conn = match transport::connect_to_peer_with_alpn(
                    &endpoint,
                    *peer_id,
                    iroh_blobs::protocol::ALPN,
                )
                .await
                {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if blob_store
                    .remote()
                    .fetch(conn, HashAndFormat::raw(blob_hash))
                    .await
                    .is_err()
                {
                    continue;
                }
                match blob_store.blobs().get_bytes(blob_hash).await {
                    Ok(bytes) => match crate::membership::decode_group_blob(&bytes) {
                        Ok(data) => {
                            new_data = Some(data);
                            break;
                        }
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                }
            }

            let Some(data) = new_data else {
                tracing::warn!("could not fetch updated group blob from any peer");
                continue;
            };

            // Reconcile: find removed peers
            let old_members: Vec<EndpointId> = {
                let s = state.read().unwrap();
                s.members.all().iter().map(|m| m.identity).collect()
            };
            let new_member_ids: std::collections::HashSet<EndpointId> =
                data.members.iter().map(|m| m.identity).collect();

            for old_id in &old_members {
                if !new_member_ids.contains(old_id) {
                    let s = state.read().unwrap();
                    if let Some(member) = s.members.get(old_id) {
                        peers.remove(&member.ip, &derive_ipv6(old_id));
                        tracing::info!(peer = %old_id.fmt_short(), "removed kicked peer");
                    }
                }
            }

            let my_id = endpoint.id();
            if !new_member_ids.contains(&my_id)
                && !data.approved.iter().any(|a| a.identity == my_id)
            {
                tracing::warn!("we have been removed from the network");
                break;
            }

            // Update state and re-materialize suggested firewall rules from the
            // freshly verified blob. Suggestions ride in the blob, so they are
            // refreshed here.
            {
                let mut s = state.write().unwrap();
                s.members = MemberList::from_members(data.members.clone());
                s.approved = ApprovedList::from_entries(data.approved.clone());
                s.suggested_firewall = data.suggested_firewall.clone();
                s.refresh_snapshot();
            }
            apply_suggested_firewall(&fw, endpoint.id(), &network_name, &state);
        }
    })
}

/// Extra context a coordinator needs to prune the canonical member list when a
/// peer leaves deliberately (`ray leave`). Members pass `None` and only ever
/// drop the connection from the [`PeerTable`].
pub(crate) struct CoordinatorCleanup {
    pub(crate) state: SharedNetworkState,
    pub(crate) blob_store: FsStore,
    pub(crate) dht_notify: Option<Arc<tokio::sync::Notify>>,
    pub(crate) hostname_table: dns::HostnameTable,
    pub(crate) reverse_table: dns::ReverseLookupTable,
    pub(crate) device_user_map: peers::DeviceUserMap,
    pub(crate) network_name: String,
}

pub(crate) fn spawn_peer_cleanup(
    mut disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
    peers: PeerTable,
    token: CancellationToken,
    coordinator: Option<CoordinatorCleanup>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                event = disconnect_rx.recv() => {
                    match event {
                        Some(ev) => {
                            tracing::info!(peer = %ev.endpoint_id.fmt_short(), ip = %ev.ip, network = %ev.network, intentional = ev.intentional, "removing dead peer");
                            // Drop only this network's route; a multi-homed peer
                            // stays reachable via its other networks.
                            peers.remove_peer_from_network(&ev.ip, &ev.ipv6, &ev.network);

                            // A deliberate `ray leave` (graceful close with the
                            // leave code) prunes the member from the roster and
                            // propagates the change; a transient drop only clears
                            // the green dot above. Only the coordinator is
                            // authoritative, so members pass `coordinator = None`.
                            if ev.intentional && let Some(c) = &coordinator {
                                let member_id = c.device_user_map.resolve(&ev.endpoint_id);
                                c.state.write().unwrap().members.remove(&member_id);
                                dns::remove_hostname_by_ip(
                                    &c.hostname_table,
                                    &c.reverse_table,
                                    &c.network_name,
                                    ev.ip,
                                )
                                .await;
                                update_snapshot_and_publish(&c.state, &c.blob_store, &c.dht_notify).await;
                                broadcast_member_sync(&peers, None).await;
                                tracing::info!(peer = %member_id.fmt_short(), "pruned member after leave");
                            }
                        }
                        None => return,
                    }
                }
            }
        }
    })
}

/// Coordinator-side per-member control reader. Continuously accepts control
/// streams from one member and processes `MeshHello`s as live create-or-update
/// signals — the only path by which a member's hostname (or device cert) reaches
/// the coordinator after the initial handshake. On a hostname that differs from
/// the stored one, the coordinator resolves collisions authoritatively, updates
/// the roster + DNS, republishes the group blob, and broadcasts `MemberSync` so
/// every peer reflects the change immediately. Runs until the network token is
/// cancelled or the connection drops.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_coordinator_control_reader(
    conn: Connection,
    remote_id: EndpointId,
    peer_ip: Ipv4Addr,
    network_name: String,
    state: SharedNetworkState,
    ctx: MeshCtx,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    token: CancellationToken,
    // Serializes single-use invite ledger access for the invite-gossip arms.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    // Fires the waiting `ray ping` handler when a matching `Pong` arrives.
    pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
) {
    let MeshCtx {
        peers,
        blob_store,
        hostname_table,
        reverse_table,
        device_user_map,
        ..
    } = ctx;
    tokio::spawn(async move {
        let mut gate = crate::ratelimit::ControlGate::new();
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => return,
                r = conn.accept_bi() => r,
            };
            let mut recv = match accepted {
                Ok((_send, recv)) => recv,
                Err(_) => return, // connection closed
            };
            let msg = match control::recv_msg(&mut recv).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Throttle inbound control messages per connection: drop over-budget
            // ones, and drop the peer entirely if it sustains a flood.
            match gate.check() {
                crate::ratelimit::Verdict::Allow => {}
                crate::ratelimit::Verdict::Drop => continue,
                crate::ratelimit::Verdict::Close => {
                    tracing::warn!(peer = %remote_id.fmt_short(), "control-plane flood; closing connection");
                    conn.close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                    return;
                }
            }
            // Invite gossip from another coordinator: a co-coordinator that minted
            // or redeemed an invite tells us so our ledger stays in sync. Honor it
            // only from a coordinator peer in our verified roster.
            match msg {
                ControlMsg::InviteShare {
                    id,
                    secret_hash,
                    expires,
                } => {
                    if !sender_is_coordinator(&state, remote_id) {
                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteShare from non-coordinator");
                        continue;
                    }
                    let Ok(hash) = String::from_utf8(secret_hash) else {
                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteShare with non-utf8 hash");
                        continue;
                    };
                    let _guard = invite_lock.lock().await;
                    if let Ok(mut store) = crate::invite::InviteStore::load(&network_name) {
                        let _ = store.record_shared(id, hash, expires);
                    }
                    continue;
                }
                ControlMsg::InviteUsed { secret_hash } => {
                    if !sender_is_coordinator(&state, remote_id) {
                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteUsed from non-coordinator");
                        continue;
                    }
                    let Ok(hash) = String::from_utf8(secret_hash) else {
                        tracing::warn!(peer = %remote_id.fmt_short(), "ignoring InviteUsed with non-utf8 hash");
                        continue;
                    };
                    let _guard = invite_lock.lock().await;
                    if let Ok(mut store) = crate::invite::InviteStore::load(&network_name) {
                        let _ = store.burn_by_hash(&hash);
                    }
                    continue;
                }
                ControlMsg::Ping { nonce } => {
                    respond_pong(&conn, nonce).await;
                    continue;
                }
                ControlMsg::Pong { nonce } => {
                    if let Some((_, tx)) = pending_pongs.remove(&nonce) {
                        let _ = tx.send(());
                    }
                    continue;
                }
                _ => {}
            }
            let ControlMsg::MeshHello {
                hostname,
                device_cert,
                ..
            } = msg
            else {
                continue;
            };

            // Verify and store device cert if present.
            if let Some(ref cert) = device_cert
                && cert.verify()
                && cert.device_key == remote_id
            {
                {
                    let mut s = state.write().unwrap();
                    if let Some(m) = s.members.get_mut(&remote_id) {
                        m.user_identity = Some(cert.user_identity);
                        m.device_cert = Some(cert.clone());
                    }
                }
                device_user_map.insert(remote_id, cert.user_identity);
            }

            let Some(desired) = hostname else { continue };
            tracing::info!(
                network = %network_name,
                peer = %remote_id.fmt_short(),
                desired = %desired,
                "coordinator received MeshHello hostname"
            );

            // Resolve collisions authoritatively against the rest of the roster,
            // then detect whether this is a genuine change for this member.
            let (final_hostname, changed) = {
                let s = state.read().unwrap();
                let taken: Vec<String> = s
                    .members
                    .all()
                    .iter()
                    .filter(|m| m.identity != remote_id)
                    .filter_map(|m| m.hostname.clone())
                    .collect();
                let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
                let final_hostname = crate::hostname::resolve_collision(&desired, &taken_refs);
                let old = s
                    .members
                    .all()
                    .iter()
                    .find(|m| m.identity == remote_id)
                    .and_then(|m| m.hostname.clone());
                let changed = old.as_deref() != Some(final_hostname.as_str());
                (final_hostname, changed)
            };

            if changed {
                let mut s = state.write().unwrap();
                if let Some(m) = s.members.get_mut(&remote_id) {
                    m.hostname = Some(final_hostname.clone());
                }
            }

            // Re-assert this peer's DNS entry (idempotent; clears any stale name
            // sharing its IP before inserting the current one).
            dns::remove_hostname_by_ip(&hostname_table, &reverse_table, &network_name, peer_ip)
                .await;
            let ipv6 = derive_ipv6(&remote_id);
            dns::update_hostname(
                &hostname_table,
                &reverse_table,
                &network_name,
                &final_hostname,
                peer_ip,
                ipv6,
            )
            .await;

            if changed {
                tracing::info!(peer = %remote_id.fmt_short(), network = %network_name, hostname = %final_hostname, "peer hostname changed; republishing blob + broadcasting MemberSync");
                update_snapshot_and_publish(&state, &blob_store, &dht_notify).await;
                broadcast_member_sync(&peers, None).await;
            } else {
                tracing::debug!(peer = %remote_id.fmt_short(), network = %network_name, hostname = %final_hostname, "peer hostname unchanged; no republish (idempotent MeshHello)");
            }
        }
    });
}

/// Rebuild a network's DNS entries from its member roster (the single source of
/// truth) and persist our own — possibly coordinator-corrected — hostname. Called
/// whenever a roster update arrives so renames, joins, and departures all reflect
/// in `*.ray` resolution immediately.
/// Pick which connection path to report in `ray status`. Prefers the path iroh
/// has selected; otherwise falls back to the best concrete path so a live
/// connection never renders as `Unknown` (`?`). Priority Direct > Relay > Tor.
/// Returns the index into `classes`, or `None` only when there are no paths.
pub(crate) fn choose_path_index(classes: &[(ipc::ConnType, bool)]) -> Option<usize> {
    if let Some(i) = classes.iter().position(|(_, selected)| *selected) {
        return Some(i);
    }
    for want in [
        ipc::ConnType::Direct,
        ipc::ConnType::Relay,
        ipc::ConnType::Tor,
    ] {
        if let Some(i) = classes.iter().position(|(ct, _)| *ct == want) {
            return Some(i);
        }
    }
    // A path with no IP/relay/custom classification (none today) or, really,
    // only reached when `classes` is empty.
    (!classes.is_empty()).then_some(0)
}

/// Decide whether a locally-requested rename has been confirmed by the signed
/// blob. Satisfied when the blob's self-name equals the requested name or its
/// coordinator-assigned collision form `{pending}-{digits}` (e.g. a request for
/// `alice` that the coordinator seated as `alice-1`). Used to clear the pending
/// intent so we stop resending.
pub(crate) fn rename_satisfied(pending: &str, blob: Option<&str>) -> bool {
    match blob {
        Some(name) if name == pending => true,
        Some(name) => name
            .strip_prefix(pending)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
}

/// Drive a queued rename to completion. If `pending_hostname` is still set after
/// a reconverge (i.e. the freshly-applied blob doesn't yet reflect it), dial
/// every coordinator in the roster and re-send `MeshHello(pending)`. A dialed
/// connection is one the coordinator *accepts*, so its control reader always
/// reads the hello regardless of which side first established the mesh link.
/// Runs only while a rename is in flight, so steady state does no extra dialing.
pub(crate) async fn drain_pending_rename(
    endpoint: &Endpoint,
    roster: &[Member],
    alpn: &[u8],
    network_name: &str,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    device_cert: &Option<control::DeviceCert>,
) {
    // `apply_roster_to_dns` already cleared the intent if the blob confirmed it,
    // so a value here means it's genuinely still outstanding.
    let Some(pending) = (match config::load_network(network_name) {
        Ok(Some(net)) => net.pending_hostname,
        _ => None,
    }) else {
        return;
    };

    let coordinators: Vec<&Member> = roster
        .iter()
        .filter(|m| m.is_coordinator && m.identity != my_identity)
        .collect();
    tracing::info!(
        network = %network_name,
        hostname = %pending,
        coordinators = coordinators.len(),
        "pending rename outstanding; delivering MeshHello to coordinator set"
    );
    if coordinators.is_empty() {
        tracing::warn!(
            network = %network_name,
            hostname = %pending,
            "no other coordinator in roster to deliver pending rename to; will retry on next reconverge/backstop"
        );
    }

    for m in coordinators {
        match transport::connect_to_peer_with_alpn(endpoint, m.identity, alpn).await {
            Ok(conn) => {
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let _ = control::send_msg(
                        &mut send,
                        &ControlMsg::MeshHello {
                            identity: my_identity,
                            ip: my_ip,
                            hostname: Some(pending.clone()),
                            device_cert: device_cert.clone(),
                        },
                    )
                    .await;
                    tracing::info!(
                        network = %network_name,
                        coordinator = %m.identity.fmt_short(),
                        hostname = %pending,
                        "re-sent pending rename to coordinator"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    network = %network_name,
                    coordinator = %m.identity.fmt_short(),
                    error = %e,
                    "could not reach coordinator to deliver pending rename; will retry"
                );
            }
        }
    }
}

/// Whether this node has an unconfirmed rename queued for `network_name`.
/// Gates the reconverge worker's periodic backstop so it idles unless there's
/// a rename to keep delivering.
pub(crate) fn has_pending_hostname(network_name: &str) -> bool {
    matches!(
        config::load_network(network_name),
        Ok(Some(net)) if net.pending_hostname.is_some()
    )
}

/// The hostname this node should announce to peers: a not-yet-confirmed rename
/// intent (`pending_hostname`) if one is queued, otherwise the confirmed name.
/// Read fresh from config at every announce so a rename done mid-session is
/// advertised on the next (re)connect — not a value captured at daemon start.
pub(crate) fn outgoing_hostname(network_name: &str) -> Option<String> {
    match config::load_network(network_name) {
        Ok(Some(net)) => net.pending_hostname.or(net.my_hostname),
        _ => None,
    }
}

pub(crate) async fn apply_roster_to_dns(
    members: &[Member],
    network_name: &str,
    my_identity: EndpointId,
    hostname_table: &dns::HostnameTable,
    reverse_table: &dns::ReverseLookupTable,
) {
    let mut entries: Vec<(String, Ipv4Addr, std::net::Ipv6Addr)> = members
        .iter()
        .filter_map(|m| {
            m.hostname
                .as_ref()
                .map(|h| (h.clone(), m.ip, derive_ipv6(&m.identity)))
        })
        .collect();

    // Our own name in the freshly-fetched (authoritative) blob.
    let blob_self = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone());

    if let Ok(Some(mut net)) = config::load_network(network_name) {
        match net.pending_hostname.clone() {
            // A locally-requested rename is in flight. Until the blob confirms
            // it, keep showing/persisting the requested name and don't let a
            // stale blob clobber it back to the old one.
            Some(pending) if !rename_satisfied(&pending, blob_self.as_deref()) => {
                tracing::info!(
                    network = %network_name,
                    pending = %pending,
                    blob = blob_self.as_deref().unwrap_or("<none>"),
                    "rename still unconfirmed by signed blob; holding local name and keeping it queued for delivery"
                );
                if let Some(me) = members.iter().find(|m| m.identity == my_identity) {
                    // Override our own DNS entry so `.ray` resolution and
                    // `ray status` reflect the pending name immediately.
                    let v6 = derive_ipv6(&my_identity);
                    entries.retain(|(_, v4, _)| *v4 != me.ip);
                    entries.push((pending.clone(), me.ip, v6));
                }
                if net.my_hostname.as_deref() != Some(pending.as_str()) {
                    net.my_hostname = Some(pending);
                    let _ = config::save_network(&net);
                }
            }
            // Either the rename landed, or there was none: follow the blob and
            // clear any (now-confirmed) pending intent.
            pending => {
                let mut dirty = false;
                if let Some(p) = &pending {
                    tracing::info!(
                        network = %network_name,
                        requested = %p,
                        confirmed = blob_self.as_deref().unwrap_or("<none>"),
                        "rename confirmed by signed blob; clearing pending intent"
                    );
                    net.pending_hostname = None;
                    dirty = true;
                }
                if let Some(mine) = blob_self.clone()
                    && net.my_hostname.as_deref() != Some(mine.as_str())
                {
                    net.my_hostname = Some(mine);
                    dirty = true;
                }
                if dirty {
                    let _ = config::save_network(&net);
                }
            }
        }
    }

    dns::sync_network_hostnames(hostname_table, reverse_table, network_name, &entries).await;
}

/// Current Unix time in seconds. Reusable-key expiry uses wall-clock time (the
/// same convention as the single-use invite ledger).
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) async fn update_snapshot_and_publish(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
) {
    let snap_bytes = {
        let mut s = state.write().unwrap();
        s.refresh_snapshot();
        s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
    };
    if let Some(bytes) = snap_bytes {
        let _ = blob_store.blobs().add_slice(&bytes).await;
    }
    if let Some(notify) = dht_notify {
        notify.notify_one();
    }
}
