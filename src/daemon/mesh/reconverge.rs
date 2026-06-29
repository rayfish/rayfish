//! Verified-blob reconvergence: resolve the network-key-signed pkarr record,
//! fetch + verify the `GroupBlob`, re-seat IP collisions, then apply the roster
//! to DNS and re-materialize suggested firewall rules. The 60s group poller and
//! the peer-cleanup-adjacent helpers that drive reconvergence live here.

use super::super::*;


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


/// Current Unix time in seconds. Reusable-key expiry uses wall-clock time (the
/// same convention as the single-use invite ledger).
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
