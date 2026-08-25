//! Verified-blob reconvergence: resolve the network-key-signed pkarr record,
//! fetch + verify the `GroupBlob`, re-seat IP collisions, then apply the roster
//! to DNS and re-materialize suggested firewall rules. The group poller and the
//! peer-cleanup-adjacent helpers that drive reconvergence live here.

use std::net::Ipv6Addr;

use super::super::*;

/// How often a node re-resolves the signed record when nothing triggers it.
#[cfg(not(target_os = "android"))]
const GROUP_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// The same poll on a battery-powered node, where every tick is a radio wakeup
/// that usually learns nothing. Coordinators push `MemberSync` to members they
/// can dial, so here the poll is a backstop for a trigger that was missed
/// entirely (every coordinator offline while the blob changed), not the
/// mechanism. Reconvergence still happens promptly on wake: bringing the data
/// plane up fires `NetworkRegistry::poll_nudge`, which resolves immediately.
///
/// Keyed on the platform, not on `on_demand`: that is a desktop config key
/// (`GlobalKey::OnDemand`) a wired node can set for its own reasons, and a
/// 15-minute-stale roster is not what it asked for by setting it.
#[cfg(target_os = "android")]
const GROUP_POLL_INTERVAL_BATTERY: Duration = Duration::from_secs(15 * 60);

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

/// Resolve the network's *signed* group-blob hash, seed peers, and author
/// timestamp from the pkarr record. This is the sole authority for the
/// roster/firewall.
///
/// The timestamp comes back with the rest because the DHT can serve a stale
/// record (that is the whole reason the `SignedRecord` mesh fast path exists),
/// and a stale one must not undo a fresher record we already applied. Same floor,
/// same reason, as the mesh path.
pub(crate) async fn resolve_signed(
    endpoint: &Endpoint,
    net_pubkey: EndpointId,
) -> Option<(blake3::Hash, Vec<EndpointId>, u64)> {
    let client = dht::create_pkarr_client(endpoint).ok()?;
    let packet = dht::resolve_network_packet(&client, net_pubkey)
        .await
        .ok()?;
    let ts = packet.timestamp().as_micros();
    let (hash, seeds) = dht::decode_network_record(&packet).ok()?;
    Some((hash, seeds, ts))
}

/// Fetch the group blob for `signed` from any connected peer or seed, and verify
/// its bytes against `signed`. Returns the verified blob, or `None` if no source
/// could serve a blob matching the signed hash. The blob is content-addressed by
/// `signed`, so a peer can only ever serve the authentic blob, never a forgery.
///
/// The two ways this returns `None` are told apart in the log, and the second one
/// stops the loop early. Bytes that do not hash to `signed` are that peer's
/// problem, so the next source is worth trying. Bytes that hash correctly and
/// then fail to decode are *everyone's*: the blob is content-addressed, so every
/// source serves those same bytes, and what we are looking at is a publisher on a
/// build whose `GroupBlob` is not the shape ours is (the roster rides the shared
/// `iroh_blobs` ALPN, which gates nothing). That reads as an unreachable
/// coordinator when it is a version split, and it repeats every group poll, so
/// the decode error itself goes in the log rather than being swallowed with the
/// dial failures.
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
        let Ok(conn) =
            transport::connect_to_peer_with_alpn(endpoint, *pid, iroh_blobs::protocol::ALPN).await
        else {
            continue;
        };
        if blob_store
            .remote()
            .fetch(conn, HashAndFormat::raw(blob_hash))
            .await
            .is_err()
        {
            continue;
        }
        let Ok(bytes) = blob_store.blobs().get_bytes(blob_hash).await else {
            continue;
        };
        if blake3::hash(&bytes) != signed {
            tracing::warn!(
                network = %network_name,
                peer = %pid.fmt_short(),
                "reconverge: a peer served bytes that do not match the signed hash"
            );
            continue;
        }
        match crate::membership::decode_group_blob(&bytes) {
            Ok(data) => {
                if let Err(e) = retain_group_blob(blob_store, &bytes).await {
                    tracing::warn!(
                        network = %network_name,
                        peer = %pid.fmt_short(),
                        error = %e,
                        "reconverge: failed to retain verified group blob"
                    );
                    return None;
                }
                return Some(data);
            }
            Err(e) => {
                tracing::warn!(
                    network = %network_name,
                    peer = %pid.fmt_short(),
                    error = %e,
                    "reconverge: the signed group blob does not decode against this build; \
                     the network's coordinator is on an incompatible version"
                );
                return None;
            }
        }
    }
    None
}

/// Compute a generation directly from the blob-bearing fields. `snapshot` is a
/// publication cache and may lag mutations that have not reached
/// `refresh_snapshot` yet, so it cannot safely guard an in-flight reconverge.
fn current_group_hash(state: &NetworkState) -> blake3::Hash {
    group_blob_hash(
        &state.members,
        &state.approved,
        &state.suggested_firewall,
        state.group_name.as_deref(),
        &state.reusable_keys,
        &state.nullifiers,
    )
}

/// Reconverge the live network state from the signed pkarr record and apply it
/// (roster + DNS + suggested firewall). Invoked when a peer sends a `MemberSync`
/// or `BlobUpdated` *hint*: the hint is only a trigger; the roster/firewall come
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
    device_cert: &Option<control::DeviceCert>,
) {
    let MeshCtx {
        peers,
        blob_store,
        firewall,
        hostname_table,
        reverse_table,
        device_user_map,
        pruned_peers,
        route_map,
        registry,
        ..
    } = ctx;
    if !confirm_pending_snapshot_durability(state, blob_store, network_name).await {
        tracing::debug!(network = %network_name, "reconverge: waiting for the current snapshot durability retry");
        return;
    }
    let (floor, generation) = {
        let s = state.read().unwrap();
        (s.last_record_timestamp, current_group_hash(&s))
    };
    let Some((signed, seeds, record_ts)) = resolve_signed(endpoint, net_pubkey).await else {
        tracing::debug!(network = %network_name, "reconverge: signed record unavailable");
        return;
    };
    if pending_authored_group_hash(state, network_name).is_some_and(|pending| pending != signed) {
        tracing::debug!(network = %network_name, "reconverge: keeping a durably authored snapshot until its publication is confirmed");
        return;
    }
    if !state.read().unwrap().needs_reconverge(signed) {
        // A prior apply may have reached live state while its config write failed.
        // Retry the durable pointer even though no blob reconvergence is needed;
        // the stored verified bytes make this safe and stale pointers stay
        // unpublishable in the meantime.
        persist_group_hash_if_needed(state, blob_store, network_name, signed, true).await;
        // Already converged on the signed hash. Even so, check whether we have
        // been nullified in the blob we already hold (e.g. we applied it while
        // still offline-blocked from ever receiving `ControlMsg::Unpaired`): if so,
        // tear ourselves out. Otherwise keep driving any unconfirmed local rename
        // (the drain no-ops unless `pending_hostname` is set).
        let (roster, nullifiers) = {
            let s = state.read().unwrap();
            (s.roster(), s.nullifiers.clone())
        };
        if let Some(cert) = device_cert
            && self_is_nullified(cert, &roster, &nullifiers)
        {
            tracing::warn!(network = %network_name, "this device is nullified by its primary in the signed blob; unpairing self");
            let registry = registry.clone();
            tokio::spawn(async move {
                let _ = registry.unpair_self().await;
            });
            return;
        }
        drain_pending_rename(
            endpoint,
            &roster,
            alpn,
            network_name,
            my_identity,
            device_cert,
        )
        .await;
        // Re-sync the exit-offer flag on this path too. An offer broadcast can
        // miss entirely (activation at boot races the first peer connections;
        // every coordinator offline), and a missed offer never changes the blob,
        // so the apply path below would never run and the offer would stay
        // invisible forever. Quiet no-op when the flag already matches.
        registry.sync_exit_offers().await;
        return;
    }
    // The record names a different blob than we hold. Take it only if it was
    // authored after the last one we applied: the DHT can serve a copy older than
    // the record a coordinator already handed us over the mesh, and applying that
    // would undo the roster rather than update it.
    if !record_is_newer(record_ts, floor) {
        tracing::debug!(
            network = %network_name,
            record_ts,
            floor,
            "reconverge: DHT served a record older than the last applied; keeping ours"
        );
        return;
    }
    let Some(data) =
        fetch_verified_blob(endpoint, blob_store, peers, signed, network_name, &seeds).await
    else {
        tracing::warn!(network = %network_name, "reconverge: could not fetch verified blob");
        return;
    };
    // Self-unpair: if our own device cert is nullified in this (verified, signed)
    // blob and the blob is coordinated by our *own* primary, the primary has
    // revoked this device. Tear ourselves out (delete the cert + leave every
    // network) even if we never received the best-effort `ControlMsg::Unpaired`
    // (e.g. we were offline at unpair time). This rides the signed blob the group
    // poller already fetches, so it needs no live mesh link. The
    // own-primary-coordinator gate stops a foreign network's coordinator from
    // forcing a global deauth by listing our key.
    let self_nullified = device_cert
        .as_ref()
        .is_some_and(|cert| self_is_nullified(cert, &data.members, &data.nullifiers));
    let commit = state.read().unwrap().snapshot_commit.clone();
    let commit_guard = commit.lock().await;
    // A local author may have refreshed live state before its blob and recovery
    // pointer became durable while this fetch was in flight. Re-check provenance
    // under the same commit lock before an older signed record can replace it.
    if state.read().unwrap().unconfirmed_durable_hash.is_some() {
        tracing::debug!(network = %network_name, "reconverge: local snapshot durability became pending while fetching");
        return;
    }
    if pending_authored_group_hash(state, network_name).is_some_and(|pending| pending != signed) {
        tracing::debug!(network = %network_name, "reconverge: keeping a durably authored snapshot until its publication is confirmed");
        return;
    }
    // No tiebreak: an address is blake3 of the identity, so two coordinators
    // admitting concurrently cannot produce a roster with duplicate addresses.
    // Revalidate and replace under one write guard so a mutation cannot land in
    // the gap and then be overwritten by this fetched state.
    let roster = {
        let mut s = state.write().unwrap();
        if current_group_hash(&s) != generation {
            tracing::debug!(network = %network_name, "reconverge: local roster changed while fetching; discarding stale result");
            return;
        }
        if self_nullified {
            drop(s);
            tracing::warn!(network = %network_name, "this device is nullified by its primary in the signed blob; unpairing self");
            let registry = registry.clone();
            tokio::spawn(async move {
                let _ = registry.unpair_self().await;
            });
            return;
        }
        s.members = MemberList::from_members(data.members.clone());
        s.approved = ApprovedList::from_entries(data.approved.clone());
        s.suggested_firewall = data.suggested_firewall.clone();
        s.group_name = data.name.clone();
        s.reusable_keys = data.reusable_keys.clone();
        s.nullifiers = data.nullifiers.clone();
        s.refresh_snapshot();
        // What the network agreed on, which is not our re-encoding of it unless
        // the publisher writes the same bytes we would. See `converged_hash`.
        s.converged_hash = Some(signed);
        s.last_record_timestamp = Some(record_ts);
        s.roster()
    };
    persist_group_hash_locked(state, blob_store, network_name, signed, true).await;
    drop(commit_guard);
    apply_roster_to_dns(
        &roster,
        network_name,
        my_identity,
        hostname_table,
        reverse_table,
        route_map,
    )
    .await;
    // Drop any live connection to a peer the signed roster no longer lists (it was
    // kicked, or left while we were offline). Removing it from the roster alone
    // stops us *routing* to it, but the peer reader keeps injecting its inbound
    // datagrams until the connection closes, so close it. We record the peer in
    // `pruned_peers` first: closing wakes our own reconnect loop, which would
    // otherwise re-dial the peer (it still lists us) and re-form the link.
    prune_departed_peers(
        peers,
        device_user_map,
        pruned_peers,
        state,
        network_name,
        my_identity,
    );
    // The mirror of the prune: a peer we are already connected to that this roster
    // now lists, but whose connection never got registered for this network.
    attach_rejoined_peers(peers, device_user_map, &roster, network_name, my_identity).await;
    apply_suggested_firewall(firewall, my_identity, network_name, state);
    // If a local rename is still unconfirmed by this just-applied blob, keep
    // delivering it to the coordinator set until it lands.
    drain_pending_rename(
        endpoint,
        &roster,
        alpn,
        network_name,
        my_identity,
        device_cert,
    )
    .await;
    // Re-advertise the exit offer if the fresh roster disagrees with what we
    // actually offer. This is the retry that makes the offer survive a missed
    // broadcast: reconverges run exactly when a connection (re)forms (the
    // "reconnected" trigger), so a sync here reaches a live coordinator, unlike
    // the activation-time one, which can fire before any network is connected
    // and go to zero peers. Quiet no-op when the flag already matches.
    registry.sync_exit_offers().await;
    registry.nudge_exit_reapply();
    tracing::info!(network = %network_name, "reconverged from signed record");
}

/// Whether this device's own cert has been nullified by its **own primary** in a
/// verified blob, the signal to self-unpair. True iff (1) our `device_key` is in
/// the blob's `nullifiers`, and (2) the blob is coordinated by our user identity
/// (a coordinator member whose identity is our `cert.user_identity`). The second
/// condition ensures only our primary can trigger a global teardown; a foreign
/// network listing our key just gets us pruned there, not deauthorized everywhere.
pub(crate) fn self_is_nullified(
    cert: &control::DeviceCert,
    members: &[Member],
    nullifiers: &std::collections::BTreeSet<EndpointId>,
) -> bool {
    nullifiers.contains(&cert.device_key)
        && members
            .iter()
            .any(|m| m.is_coordinator && m.identity == cert.user_identity)
}

/// Close and drop every connection to a peer that `network`'s current roster no
/// longer contains. Runs on every node after it applies a verified roster, so a
/// kicked (or departed) peer is severed mesh-wide, not just by the coordinator
/// that removed it. Each pruned peer is recorded in `pruned_peers` so this node's
/// reconnect loop skips the re-dial that closing the connection would trigger.
pub(crate) fn prune_departed_peers(
    peers: &PeerTable,
    device_user_map: &peers::DeviceUserMap,
    pruned_peers: &Arc<DashSet<(String, EndpointId)>>,
    state: &SharedNetworkState,
    network_name: &str,
    my_identity: EndpointId,
) {
    // Device keys nullified on this network (`ray unpair`), read once.
    let nullifiers = state.read().unwrap().nullifiers.clone();
    for (peer_id, _ip, _conn) in peers.peers_for_network_with_conn(network_name) {
        // Membership is by roster identity, which for a paired peer is its user
        // identity, not the transport id the PeerTable is keyed on. Check both.
        let user_id = device_user_map.resolve(&peer_id);
        // A peer whose device key is nullified on this network is severed even if a
        // stale roster still lists it, the nullifier is authoritative over the
        // (possibly not-yet-republished) membership. `peer_id` is the transport
        // (device) key the nullifier set is keyed on.
        let nullified = nullifiers.contains(&peer_id);
        let still_member = {
            let s = state.read().unwrap();
            s.members.is_member(&peer_id) || s.members.is_member(&user_id)
        };
        if !nullified && (still_member || peer_id == my_identity || user_id == my_identity) {
            continue;
        }
        tracing::info!(peer = %peer_id.fmt_short(), network = %network_name, "pruning peer no longer in roster");
        pruned_peers.insert((network_name.to_string(), peer_id));
        // One connection carries every shared network, so only close it when this
        // was the peer's last network with us; otherwise just drop this network's
        // route and leave the peer reachable on the others (`remove_peer_from_network`
        // returns the connection iff its network set emptied).
        if let Some(conn) = peers.remove_peer_from_network(&derive_ipv6(&peer_id), network_name) {
            conn.close(
                VarInt::from_u32(forward::KICK_CODE),
                b"removed from network",
            );
        }
    }
}

/// Register the connections we already hold for peers this roster lists but whose
/// link was never registered for `network`.
///
/// One connection carries every network two peers share, and it is registered per
/// network as each side's `MeshHello` for that network is processed. A hello is
/// only registered if the network's roster already names the sender, so one that
/// arrives while the roster is still converging (a restart, a fresh join, a blob
/// that lands after the link) is dropped and never retried: the connection then
/// carries a network the peer table does not list. That is not cosmetic, the set
/// is the in-band reachability wall, so `resolve_inbound_by_id` drops the
/// network's inbound datagrams and `ray status` shows the peer `Idle` on it while
/// it is plainly `Active` on another. Reconverge is the right place to repair it:
/// it runs exactly when a verified roster arrives, which is the information that
/// was missing when the hello landed.
pub(crate) async fn attach_rejoined_peers(
    peers: &PeerTable,
    device_user_map: &peers::DeviceUserMap,
    members: &[Member],
    network_name: &str,
    my_identity: EndpointId,
) {
    for m in members {
        if m.identity == my_identity {
            continue;
        }
        // The roster keys a paired peer by its user identity, while the peer table
        // is keyed on the transport (device) id, so resolve through the same map
        // the prune pass uses before looking the connection up.
        let Some((ip, conn)) = peers.connected_device_for(&m.identity, device_user_map) else {
            continue;
        };
        if peers.attach_network(&ip, network_name).is_none() {
            continue;
        }
        tracing::info!(
            peer = %m.identity.fmt_short(),
            network = %network_name,
            "attached an existing connection to a network its handshake missed"
        );
        // The peer cannot decode datagrams tagged with a handle it has never been
        // told about, so the repair is only half done until we re-announce.
        crate::daemon::announce_network_handles(peers, &conn, ip).await;
    }
}

pub(crate) async fn apply_roster_to_dns(
    members: &[Member],
    network_name: &str,
    my_identity: EndpointId,
    hostname_table: &dns::HostnameTable,
    reverse_table: &dns::ReverseLookupTable,
    route_map: &peers::RosterRouteMap,
) {
    // Refresh the IP -> member map so the on-demand data path can lazily dial any
    // roster member (self excluded). The roster is the source of truth, so a
    // shrinking roster drops stale entries via the per-network replace.
    let routes: Vec<peers::RouteMember> = members
        .iter()
        .filter(|m| m.identity != my_identity)
        .map(|m| peers::RouteMember {
            endpoint_id: m.identity,
            ipv6: derive_ipv6(&m.identity),
        })
        .collect();
    route_map.sync_network(network_name, &routes);
    // The roster is the source of truth for DNS. Every member has exactly one
    // address and it is derived, not stored, so the entry is a bare `Ipv6Addr`:
    // there is no A record to hold back and nothing that can be missing.
    let mut entries: Vec<(String, Ipv6Addr)> = members
        .iter()
        .filter_map(|m| {
            m.hostname
                .as_ref()
                .map(|h| (h.clone(), derive_ipv6(&m.identity)))
        })
        .collect();

    // Our own name in the freshly-fetched (authoritative) blob.
    let blob_self = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone());

    let _ = config::update_network(network_name, |net| {
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
                    entries.retain(|(_, addr)| *addr != derive_ipv6(&me.identity));
                    entries.push((pending.clone(), v6));
                }
                if net.my_hostname.as_deref() != Some(pending.as_str()) {
                    net.my_hostname = Some(pending);
                }
            }
            // Either the rename landed, or there was none: follow the blob and
            // clear any (now-confirmed) pending intent.
            pending => {
                if let Some(p) = &pending {
                    tracing::info!(
                        network = %network_name,
                        requested = %p,
                        confirmed = blob_self.as_deref().unwrap_or("<none>"),
                        "rename confirmed by signed blob; clearing pending intent"
                    );
                    net.pending_hostname = None;
                }
                if let Some(mine) = blob_self.clone()
                    && net.my_hostname.as_deref() != Some(mine.as_str())
                {
                    net.my_hostname = Some(mine);
                }
            }
        }
        Ok(())
    });

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
        registry,
        ..
    } = ctx;
    tokio::spawn(async move {
        // `interval` fires its first tick immediately, so the poller does an
        // at-start resolve (catching a blob that changed while we were offline or
        // mid-restart) and then settles into its cadence. Without this the first
        // re-check was a full interval after boot.
        #[cfg(target_os = "android")]
        let period = GROUP_POLL_INTERVAL_BATTERY;
        #[cfg(not(target_os = "android"))]
        let period = GROUP_POLL_INTERVAL;
        let mut tick = tokio::time::interval(period);
        let nudge = registry.poll_nudge.clone();
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tick.tick() => {},
                // The data plane came up. Resolve now rather than at the next
                // tick, and re-arm so a nudge doesn't shorten the cadence.
                _ = nudge.notified() => tick.reset(),
            }

            // Re-advertise the exit offer if the signed roster still disagrees
            // with what this node actually offers. Delivery can miss entirely
            // (activation at boot runs before the network is registered; every
            // coordinator unreachable), and a missed offer never changes the
            // blob, so no reconverge trigger would ever heal it. Quiet local
            // no-op when the flag already matches.
            registry.sync_exit_offers().await;

            let (remote_hash, seed_peers) = match dht::resolve_network(&client, net_pubkey).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "group poll failed");
                    continue;
                }
            };

            if pending_authored_group_hash(&state, &network_name)
                .is_some_and(|pending| pending != remote_hash)
            {
                tracing::debug!(network = %network_name, "group poll: keeping a durably authored snapshot until its publication is confirmed");
                continue;
            }

            // Through the same method as the trigger-driven path, so the two
            // cannot answer "have we converged on this record" differently. They
            // did: this one open-coded the comparison against the snapshot hash,
            // our own re-encoding, and was missed when the other moved off it.
            // This is the hotter of the two and has no timestamp floor to damp it,
            // so a member whose bytes differ from the publisher's refetched the
            // whole roster, re-materialized the suggested firewall and nudged the
            // exit reconcile once a minute, forever.
            let (needs_reconverge, current_hash) = {
                let s = state.read().unwrap();
                (s.needs_reconverge(remote_hash), s.converged_hash)
            };
            if !needs_reconverge {
                persist_group_hash_if_needed(&state, &blob_store, &network_name, remote_hash, true)
                    .await;
                continue;
            }

            tracing::info!(old = ?current_hash, new = %remote_hash, "group blob changed");

            if matches!(
                fetch_and_apply_blob(
                    &endpoint,
                    &blob_store,
                    &peers,
                    &fw,
                    &registry,
                    &state,
                    &network_name,
                    remote_hash,
                    &seed_peers,
                )
                .await,
                ReconvergeOutcome::Departed
            ) {
                break;
            }
        }
    })
}

/// Outcome of applying a verified group blob at `remote_hash`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReconvergeOutcome {
    /// Roster (and suggested firewall) updated from the new blob.
    Applied,
    /// The blob could not be fetched from any peer or seed; nothing changed.
    Unfetched,
    /// State changed while the blob was in flight, so its result was discarded.
    Superseded,
    /// This node is no longer part of the network (kicked, or its own primary
    /// nullified this device). The caller should stop polling this network.
    Departed,
}

/// Fetch the verified group blob for `remote_hash` (from any connected peer or the
/// record's seed peers) and apply it: honor a self-nullification, prune removed
/// peers, detect our own removal, and refresh the roster + suggested firewall.
///
/// Shared by the group poller and the `SignedRecord` fast path (a coordinator
/// hands a reconnecting member the current signed record over the mesh), so both
/// converge through identical, verified logic. The hash always arrives from a
/// network-key-signed record; the blob itself is verified in `fetch_verified_blob`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_apply_blob(
    endpoint: &Endpoint,
    blob_store: &FsStore,
    peers: &PeerTable,
    fw: &SharedFirewall,
    registry: &Arc<NetworkRegistry>,
    state: &SharedNetworkState,
    network_name: &str,
    remote_hash: blake3::Hash,
    seed_peers: &[EndpointId],
) -> ReconvergeOutcome {
    if !confirm_pending_snapshot_durability(state, blob_store, network_name).await {
        tracing::debug!(network = %network_name, "reconverge: waiting for the current snapshot durability retry");
        return ReconvergeOutcome::Superseded;
    }
    if pending_authored_group_hash(state, network_name)
        .is_some_and(|pending| pending != remote_hash)
    {
        tracing::debug!(network = %network_name, "reconverge: refusing to replace a pending authored snapshot with an older published record");
        return ReconvergeOutcome::Superseded;
    }
    let generation = current_group_hash(&state.read().unwrap());
    // Fetch the verified blob from any connected peer *or* the record's seed
    // peers. Including the seeds is essential: a node that has been isolated
    // (e.g. an unpaired device the coordinator already severed) has no connected
    // peers, so a connected-only fetch could never discover its own
    // removal/nullification.
    let Some(data) = fetch_verified_blob(
        endpoint,
        blob_store,
        peers,
        remote_hash,
        network_name,
        seed_peers,
    )
    .await
    else {
        tracing::warn!("could not fetch updated group blob from any peer");
        return ReconvergeOutcome::Unfetched;
    };

    // Self-unpair: our own primary listed this device in the signed blob's
    // nullifiers (`ray unpair`). Tear ourselves out even though we never
    // received `ControlMsg::Unpaired` (we were offline/severed). Rides the
    // signed blob, so it needs no live mesh link. See `self_is_nullified`.
    let self_nullified = crate::identity::load_device_cert()
        .ok()
        .flatten()
        .is_some_and(|cert| self_is_nullified(&cert, &data.members, &data.nullifiers));

    let new_member_ids: std::collections::HashSet<EndpointId> =
        data.members.iter().map(|m| m.identity).collect();
    let my_id = endpoint.id();
    let self_removed =
        !new_member_ids.contains(&my_id) && !data.approved.iter().any(|a| a.identity == my_id);

    let commit = state.read().unwrap().snapshot_commit.clone();
    let commit_guard = commit.lock().await;
    // The live generation can become durable after the optimistic check above
    // but before this lock is acquired. Once its pending pointer exists, an older
    // signed record must not roll it back.
    if state.read().unwrap().unconfirmed_durable_hash.is_some() {
        tracing::debug!(network = %network_name, "reconverge: local snapshot durability became pending while fetching");
        return ReconvergeOutcome::Superseded;
    }
    if pending_authored_group_hash(state, network_name)
        .is_some_and(|pending| pending != remote_hash)
    {
        tracing::debug!(network = %network_name, "reconverge: refusing to replace a pending authored snapshot with an older published record");
        return ReconvergeOutcome::Superseded;
    }
    // Revalidate and replace under one write guard so a mutation cannot land in
    // the gap and then be overwritten by this fetched state.
    let old_members: Vec<EndpointId> = {
        let mut s = state.write().unwrap();
        if current_group_hash(&s) != generation {
            tracing::debug!(network = %network_name, "reconverge: local roster changed while fetching; discarding stale result");
            return ReconvergeOutcome::Superseded;
        }
        if self_nullified {
            drop(s);
            tracing::warn!(network = %network_name, "this device is nullified by its primary in the signed blob; unpairing self");
            let registry = registry.clone();
            tokio::spawn(async move {
                let _ = registry.unpair_self().await;
            });
            return ReconvergeOutcome::Departed;
        }
        if self_removed {
            drop(s);
            tracing::warn!("we have been removed from the network");
            return ReconvergeOutcome::Departed;
        }
        let old_members = s.members.all().iter().map(|m| m.identity).collect();
        s.members = MemberList::from_members(data.members.clone());
        s.approved = ApprovedList::from_entries(data.approved.clone());
        s.suggested_firewall = data.suggested_firewall.clone();
        s.group_name = data.name.clone();
        s.reusable_keys = data.reusable_keys.clone();
        s.nullifiers = data.nullifiers.clone();
        s.refresh_snapshot();
        // The hash the network agreed on, not our re-encoding of it. See
        // `converged_hash`.
        s.converged_hash = Some(remote_hash);
        old_members
    };

    // Reconcile: find removed peers after the state replacement. `old_members`
    // was captured under the same guard, so each absent id was present in the
    // generation we just replaced.
    for old_id in &old_members {
        if !new_member_ids.contains(old_id) {
            peers.remove(&derive_ipv6(old_id));
            tracing::info!(peer = %old_id.fmt_short(), "removed kicked peer");
        }
    }

    persist_group_hash_locked(state, blob_store, network_name, remote_hash, true).await;
    drop(commit_guard);
    apply_suggested_firewall(fw, endpoint.id(), network_name, state);

    // Exit-node reconciliation. The fresh roster may have wiped our advertised
    // offer (a coordinator rebuild) or missed one made while every coordinator was
    // offline: re-sync the flag with what we actually offer. And it may carry the
    // exit peer a pending client selection has been waiting on since boot, or a
    // changed capability claim from the gateway a live tunnel already points at:
    // nudge the daemon to re-run the exit reconcile rather than leaking traffic
    // until the next `ray up`. All cheap no-ops otherwise.
    registry.sync_exit_offers().await;
    registry.nudge_exit_reapply();
    ReconvergeOutcome::Applied
}

/// Current Unix time in seconds. Reusable-key expiry uses wall-clock time (the
/// same convention as the single-use invite ledger).
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod self_nullified_tests {
    use super::*;
    use iroh::SecretKey;

    fn member(identity: EndpointId, is_coordinator: bool) -> Member {
        Member {
            identity,
            is_coordinator,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        }
    }

    #[test]
    fn self_unpair_only_when_own_primary_nullifies() {
        let primary = SecretKey::generate(); // our user identity
        let device = SecretKey::generate().public();
        let cert = control::DeviceCert::create(&primary, &device, 0);
        let mut nulls = std::collections::BTreeSet::new();
        nulls.insert(device);

        // Our primary coordinates the network and listed us: self-unpair.
        let roster = vec![member(primary.public(), true)];
        assert!(self_is_nullified(&cert, &roster, &nulls));

        // Nullified, but the network is coordinated by someone else (foreign):
        // must NOT trigger a global teardown.
        let foreign = vec![member(SecretKey::generate().public(), true)];
        assert!(!self_is_nullified(&cert, &foreign, &nulls));

        // Our primary is present but only as a plain member (not coordinator):
        // not authoritative here.
        let noncoord = vec![member(primary.public(), false)];
        assert!(!self_is_nullified(&cert, &noncoord, &nulls));

        // Not nullified at all.
        assert!(!self_is_nullified(
            &cert,
            &roster,
            &std::collections::BTreeSet::new()
        ));
    }
}
