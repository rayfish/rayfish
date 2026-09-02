//! Network runtime handlers for `Daemon`: coordinator restore, nuke,
//! connect-all, activate/deactivate (data plane), teardown, leave. Split out of `daemon/mod.rs`.

use super::super::*;
// The desktop-gated `start_ssh` binds SSH listeners on concrete IPs, and the
// macOS exit-node helpers below match on underlay addresses. macOS without the
// desktop feature (the ray-mobile host build) still needs the import.
#[cfg(any(feature = "desktop", target_os = "macos"))]
use std::net::IpAddr;
use std::sync::RwLock;

use super::create_join::{RestoredGroupBlob, mesh_version_is_speakable};

/// How long `ray exit-node use` waits for the exit peer to answer through the
/// finished tunnel before returning anyway. Long enough to cover a re-punch after
/// the routing change (the netwatch-driven rebind lands a few seconds in), short
/// enough that a broken exit node does not hang the command.
#[cfg(target_os = "macos")]
const EXIT_READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-attempt wait for a control pong. Also paces the readiness loop.
#[cfg(target_os = "macos")]
const NUDGE_REPLY_WAIT: Duration = Duration::from_millis(500);

/// The roster rows one `ray kick` removes: the named identity and every device
/// held by the same user. Returns `(targets, any_is_coordinator, display)`, or
/// `None` when nothing in the roster matches.
///
/// Membership follows the user identity while a roster row is per device, and
/// this is where the two are reconciled. Kicking used to take the *first* row
/// matching either the device or its user, which meant naming a paired
/// secondary removed its primary (seated earlier) and left the secondary in the
/// network. Removing the whole user is the only reading that matches what the
/// rest of the daemon does with a pairing: `ssh` and the firewall resolve a
/// device to its user and grant on that, so access cannot be taken away one
/// device at a time. Revoking a single device is `ray unpair`, which nullifies
/// its cert mesh-wide rather than editing one network's roster.
fn kick_targets(
    members: &MemberList,
    candidate: EndpointId,
    candidate_user: EndpointId,
) -> Option<(Vec<EndpointId>, bool, String)> {
    let rows: Vec<&Member> = members
        .all()
        .into_iter()
        .filter(|m| {
            m.identity == candidate
                || m.identity == candidate_user
                || m.user_identity == Some(candidate_user)
        })
        .collect();
    // Name the row the caller pointed at, falling back to the primary's, so the
    // message says what they typed rather than a sibling device.
    let named = rows
        .iter()
        .find(|m| m.identity == candidate)
        .or(rows.first())?;
    let display = named
        .hostname
        .clone()
        .unwrap_or_else(|| named.identity.fmt_short().to_string());
    Some((
        rows.iter().map(|m| m.identity).collect(),
        rows.iter().any(|m| m.is_coordinator),
        display,
    ))
}

/// First and last backoff step for the member-network restore retry loop.
const RESTORE_RETRY_MIN: Duration = Duration::from_secs(2);
const RESTORE_RETRY_MAX: Duration = Duration::from_secs(60);
/// How often the restore supervisor re-checks that every saved network is live.
/// Matches [`RESTORE_RETRY_MAX`]: a network being restored is already retrying
/// at that rate, so sweeping faster only re-reads the config for nothing.
const RESTORE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Minimum spacing between two peer-triggered sweeps. See
/// [`NetworkRegistry::run_restore_supervisor`].
const NUDGE_DEBOUNCE: Duration = Duration::from_secs(5);

/// The saved-network fields a member restore works from, read off the config
/// once when the restore is spawned. The retry loop and the warm-resume path
/// both take the whole group, so neither call site has to keep seven values in
/// the right order.
pub(crate) struct SavedMemberNetwork {
    pub(crate) name: String,
    /// The network public key as it is stored: still a string, because a config
    /// that fails to parse must still reach the signed-record restore.
    pub(crate) net_pubkey: String,
    pub(crate) persisted_hostname: Option<String>,
    pub(crate) auto_accept_firewall: bool,
    pub(crate) auto_accept_files: bool,
    pub(crate) cached_hash: Option<blake3::Hash>,
    pub(crate) cached_is_published: bool,
}

/// Whether the member-restore loop runs another attempt or is done.
enum RestoreNext {
    Retry,
    Stop,
}

/// The membership a coordinator restores at startup from the authoritative,
/// network-key-signed `GroupBlob`.
struct RestoredRoster {
    members: MemberList,
    approved: ApprovedList,
    group_name: Option<String>,
    suggested_firewall: SuggestedFirewall,
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    nullifiers: BTreeSet<EndpointId>,
    source_hash: blake3::Hash,
    source_published: bool,
}

/// Turn a complete content-addressed blob into coordinator state, reconciling the
/// one authority the blob cannot revoke: possession of the network secret key.
/// Existing signed metadata is preserved; only the local key-holder role and its
/// online timestamp are local facts refreshed at boot.
fn materialize_coordinator_roster(
    restored: RestoredGroupBlob,
    local_identity: EndpointId,
    persisted_hostname: Option<String>,
) -> RestoredRoster {
    let RestoredGroupBlob {
        blob: data,
        hash: source_hash,
        published: source_published,
    } = restored;
    let mut members = MemberList::from_members(data.members);
    match members.get_mut(&local_identity) {
        Some(local) => {
            local.is_coordinator = true;
            local.last_seen = None;
        }
        None => members.add(Member {
            identity: local_identity,
            is_coordinator: true,
            hostname: persisted_hostname,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        }),
    }
    RestoredRoster {
        members,
        approved: ApprovedList::from_entries(data.approved),
        group_name: data.name,
        suggested_firewall: data.suggested_firewall,
        reusable_keys: data.reusable_keys,
        nullifiers: data.nullifiers,
        source_hash,
        source_published,
    }
}

fn apply_coordinator_restore_to_config(
    config: &mut config::NetworkConfig,
    mode: GroupMode,
    members: &MemberList,
    approved: &ApprovedList,
    net_secret_key: &SecretKey,
    last_group_hash: Option<blake3::Hash>,
    last_group_hash_published: bool,
) {
    config.group_mode = mode;
    config.pending_hostname = None;
    config.members = to_member_entries(members.all());
    config.approved = to_approved_entries(approved.all());
    config.network_secret_key = Some(net_secret_key.clone());
    config.network_public_key = Some(net_secret_key.public());
    if let Some(hash) = last_group_hash {
        config.last_group_hash = Some(hash);
        config.last_group_hash_published = last_group_hash_published;
    }
}

impl NetworkRegistry {
    /// Rebuild a network's roster for a coordinator restart from the published,
    /// network-key-signed `GroupBlob` (members + approved + suggested firewall +
    /// reusable keys). A transient resolve/fetch failure is an error so the
    /// restore supervisor retries without publishing stale local config.
    async fn restore_member_roster(
        &self,
        name: &str,
        net_public_key: EndpointId,
        net_config: &config::NetworkConfig,
    ) -> Result<RestoredRoster> {
        let persisted_peers: Vec<_> = net_config.members.iter().map(|m| m.identity).collect();
        let data = self
            .restore_roster_from_blob(
                net_public_key,
                net_config.last_group_hash,
                net_config.last_group_hash_published,
                &persisted_peers,
            )
            .await
            .with_context(|| format!("restore complete roster for '{name}'"))?;
        let restored = materialize_coordinator_roster(
            data,
            self.transport.identity.local_identity(),
            net_config.my_hostname.clone(),
        );
        tracing::info!(
            network = %name,
            members = restored.members.all().len(),
            "restored roster from complete group blob"
        );
        Ok(restored)
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

        let my_ip = self.transport.identity.local_ipv6();

        // Load persisted network secret key from config.
        let net_config = config::load_network(name)?.context("network is no longer saved")?;
        let net_secret_key = net_config
            .network_secret_key
            .clone()
            .context("no network secret key in config — cannot restore as coordinator")?;
        let net_public_key = net_secret_key.public();
        let persisted_hostname = net_config.my_hostname.clone();

        // Restore membership from the authoritative published GroupBlob. The blob
        // (members + approved) is signed by the per-network key and published
        // to DHT, so it is the source of truth and survives a daemon restart. The
        // local blob store still holds the bytes we published before going down, so
        // we read them back by the hash in the pkarr record (falling back to a seed
        // peer. If neither source has it, restoration fails and is retried without
        // publishing anything.
        // Restoring from the blob is also what prevents a clobber: the rebuilt
        // snapshot hashes identical to the published record, so the periodic
        // re-publish becomes a no-op instead of overwriting the roster with a
        // coordinator-only stub.
        let RestoredRoster {
            members: member_list,
            approved: approved_list,
            group_name,
            suggested_firewall,
            reusable_keys,
            nullifiers,
            source_hash,
            source_published,
        } = self
            .restore_member_roster(name, net_public_key, &net_config)
            .await?;

        let mut net_state = NetworkState {
            members: member_list,
            approved: approved_list,
            snapshot: None,
            snapshot_commit: Arc::new(AsyncMutex::new(())),
            converged_hash: None,
            unconfirmed_durable_hash: None,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_public_key,
            network_name: Some(name.to_string()),
            group_name,
            mode,
            suggested_firewall,
            reusable_keys,
            nullifiers,
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
            // A key holder authors records rather than applying them, so it keeps
            // no replay floor.
            last_record_timestamp: None,
        };

        let last_group_hash = self.seal_group_snapshot(&mut net_state).await?;
        let restored_hash_was_published = source_published && last_group_hash == source_hash;

        // Replace only the blob-derived projection on the latest saved config.
        // Everything else in this file is node-local policy and must survive
        // both a coordinator restart and writes made while restoration awaited.
        let updated = config::update_network(name, |latest| {
            apply_coordinator_restore_to_config(
                latest,
                mode,
                &net_state.members,
                &net_state.approved,
                &net_secret_key,
                Some(last_group_hash),
                restored_hash_was_published,
            );
            Ok(())
        })?;
        anyhow::ensure!(updated.is_some(), "network is no longer saved");
        let restored_record = self
            .publish_group_hash(name, &net_secret_key, last_group_hash)
            .await;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(RwLock::new(net_state));
        let invite_lock = Arc::new(AsyncMutex::new(()));
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        let ctx = self.mesh_ctx();
        let tasks = self.spawn_coordinator_background_tasks(
            &ctx,
            name,
            &net_secret_key,
            &state,
            &dht_notify,
            &cancel,
            restored_record.as_ref().map(|_| last_group_hash),
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
                            .map(|h| (h.clone(), derive_ipv6(&m.identity)))
                    })
                    .collect()
            };
            for (hostname, ipv6) in members_snapshot {
                dns::update_hostname(
                    &self.dns.hostname_table,
                    &self.dns.reverse_table,
                    name,
                    &hostname,
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
        // Register the network from its restored local state before dialing
        // peers, so `ray status` / IPC sees it the instant the local restore
        // finishes. `dial_all_members` awaits a handshake per peer; when it gated
        // this insert, a freshly (re)started daemon answered `status` with "no
        // active networks" until every dial resolved.
        let handle = NetworkHandle {
            name: name.to_string(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            state,
            dht_notify: Some(dht_notify),
            cancel: cancel.clone(),
            tasks,
            invite_lock,
            // A coordinator holds the network key and publishes the record, so
            // the version it advertises is this build's by construction.
            incompatible: None,
        };
        self.networks.insert(name.to_string(), handle);
        self.refresh_search_domains().await;

        // Full mesh: proactively dial every known member in the background so a
        // restarting coordinator/co-coordinator reconnects to peers that haven't
        // (yet) dialed in, without blocking restore on peer connectivity. Track
        // the task on the handle and stop it with the network token so leave/nuke
        // cannot let a stale restore dial recreate routes after teardown.
        let me = Arc::clone(self);
        let network_name = name.to_string();
        let dial_cancel = cancel.clone();
        let dial_task = tokio::spawn(async move {
            tokio::select! {
                _ = dial_cancel.cancelled() => {}
                _ = me.dial_all_members(
                    &members_to_dial,
                    net_public_key,
                    &network_name,
                    me.transport.identity.local_identity(),
                    persisted_hostname,
                ) => {}
            }
        });
        if let Some(mut handle) = self.networks.get_mut(name) {
            handle.tasks.push(dial_task);
        } else {
            dial_task.abort();
        }

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network restored (coordinator)");

        Ok(IpcMessage::Created {
            name: name.to_string(),
            network_key: net_public_key,
            my_ipv6: derive_ipv6(&self.transport.identity.local_identity()),
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
            && let Ok(client) =
                dht::create_pkarr_client(&self.transport.endpoint, &self.transport.pkarr_relay_url)
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
    pub(crate) async fn kick_member(
        self: &Arc<Self>,
        network: &str,
        peer: &str,
        confirm: bool,
    ) -> IpcMessage {
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
        // Membership follows the user identity, so a kick removes the person and
        // every device they hold rather than whichever roster row matched first.
        // It used to take the first: naming a paired secondary resolved to its
        // primary, and since the primary's row is normally seated earlier,
        // `ray kick <phone>` removed the *laptop* and left the phone in place.
        // The victim's own row is matched too, so a device with no live pairing
        // (a stale row from a reinstall) is still kickable by its own id.
        let (targets, is_coord, display) = {
            let s = state.read().unwrap();
            match kick_targets(&s.members, candidate, candidate_user) {
                Some(t) => t,
                None => {
                    return ipc_err(format!("'{peer}' is not a member of '{network}'"));
                }
            }
        };
        if targets.contains(&self.transport.endpoint.id()) {
            return ipc_err("cannot kick yourself — use `ray leave` or `ray nuke`".to_string());
        }
        if is_coord {
            return ipc_err(format!(
                "'{display}' is a coordinator (holds the network key); kicking can't remove \
                     its access. Revoke the key instead."
            ));
        }

        // Naming one device takes the whole user (see `kick_targets`), which is
        // not something the command line says out loud: the argument names one
        // row and three can go. Hand the set back and let the CLI ask, unless the
        // caller already answered (`--yes`, or a second request after the
        // prompt). A single-row kick is what it looks like, so it goes straight
        // through and scripts calling it keep working.
        if targets.len() > 1 && !confirm {
            let rows = {
                let s = state.read().unwrap();
                let members = s.members.all();
                targets
                    .iter()
                    .map(|id| {
                        let row = members.iter().find(|m| m.identity == *id);
                        ipc::KickTarget {
                            hostname: row.and_then(|m| m.hostname.clone()),
                            short_id: id.fmt_short().to_string(),
                            primary: *id == candidate_user,
                        }
                    })
                    .collect()
            };
            return IpcMessage::KickConfirm {
                network: network.to_string(),
                display,
                targets: rows,
            };
        }

        // The two calls the ephemeral pruner makes, which is what
        // `remove_member_roster_only`'s doc has always claimed the manual kick
        // shared with it. It did not: this path closed the victim's connection
        // with `KICK_CODE` instead, and a close code cannot name a network, so it
        // is not a kick the victim can act on. `confirm_kick_and_leave` runs off
        // the in-band, network-scoped `ControlMsg::KickedFromNetwork`, which only
        // `finalize_removal` sends; without it the victim learned of its own
        // removal from the group poll, whose `Departed` outcome does nothing but
        // stop polling, leaving the network in `ray status` with a roster frozen
        // at the kick. `finalize_removal` also deliberately leaves the connection
        // open, so the message cannot lose a race with its own teardown.
        let ctx = self.mesh_ctx();
        for member_id in &targets {
            remove_member_roster_only(&ctx, network, &state, *member_id, derive_ipv6(member_id))
                .await;
        }
        // One finalize for the whole set: it publishes the snapshot once and
        // sends every victim its own `KickedFromNetwork`, so a person and their
        // devices leave on the same record rather than on N republished ones.
        finalize_removal(&ctx, network, &state, &dht_notify, &targets).await;

        for member_id in &targets {
            tracing::info!(peer = %member_id.fmt_short(), network = %network, "kicked member");
        }
        let devices = match targets.len() {
            1 => String::new(),
            n => format!(" and {} paired device(s)", n - 1),
        };
        IpcMessage::Ok {
            message: format!("kicked '{display}'{devices} from '{network}'"),
        }
    }

    /// Restore one saved member network, retrying until it lands.
    ///
    /// Restoring a membership needs the network's signed pkarr record, so it
    /// needs working DNS and a route off the box. After an abrupt reboot the
    /// daemon can start before either is true: the service manager brings us up
    /// as soon as the network target is nominally ready, and on Linux a leftover
    /// rayfish `/etc/resolv.conf` points the process resolver at our own Magic
    /// DNS before it has upstreams. A one-shot restore turned that transient
    /// failure into a permanent one: the network never registered, `ray status`
    /// showed it inactive, and only a manual `ray restart` brought it back. So
    /// retry with backoff until the join lands, the network is gone from the
    /// config (leave/nuke), or the daemon shuts down.
    async fn restore_member_network(self: Arc<Self>, saved: SavedMemberNetwork) {
        let name = saved.name.as_str();
        let net_pubkey = saved.net_pubkey.as_str();
        let persisted_hostname = &saved.persisted_hostname;
        let auto_accept_firewall = saved.auto_accept_firewall;
        let auto_accept_files = saved.auto_accept_files;
        let parsed_key = net_pubkey.parse::<EndpointId>();
        if let Ok(net_public_key) = parsed_key {
            match self
                .warm_resume_member_network(&saved, net_public_key)
                .await
            {
                Ok(true) => {
                    self.restore_errors.remove(name);
                    return;
                }
                Ok(false) => {}
                Err(e) => {
                    // The normal signed-record restore immediately below remains
                    // the fallback: a bad or absent local cache must never make
                    // a saved network unrecoverable.
                    tracing::warn!(network = %name, error = %e, "warm resume failed; falling back to signed-record restore");
                }
            }
        }
        let mut delay = RESTORE_RETRY_MIN;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            // A network already registered as version-incompatible was built from
            // its signed blob alone: it is visible and marked in `ray status`, but
            // no peer on it is reachable until its coordinator republishes at a
            // version this build speaks. Re-running the join would only be refused
            // as "already in network", so watch the record instead and rebuild
            // only once it matches. Leaving the registration untouched meanwhile
            // is the point: tearing it down each retry would put the network back
            // to invisible between attempts.
            let stuck = match self.incompatible_registration(name) {
                Some(mismatch) => {
                    !self
                        .mesh_version_recovered(name, net_pubkey, &mismatch)
                        .await
                }
                None => false,
            };
            if stuck {
                match self.after_attempt(name, &mut delay, attempt).await {
                    RestoreNext::Retry => continue,
                    RestoreNext::Stop => return,
                }
            }
            match self
                .join_network_inner(
                    net_pubkey,
                    Some(name),
                    persisted_hostname.clone(),
                    None,
                    None,
                    auto_accept_firewall,
                    auto_accept_files,
                    false,
                )
                .await
            {
                // The reply is boxed (`TryJoin::Joined`), so the two Joined cases
                // are told apart inside the arm rather than by pattern.
                Ok(TryJoin::Joined(resp)) => match *resp {
                    IpcMessage::Joined {
                        ref name, my_ipv6, ..
                    } => {
                        // Registered, but possibly only from the blob because the
                        // record advertises a mesh version we don't speak. That is
                        // not the end of the restore: stay in the loop so a
                        // coordinator republish promotes it.
                        match self.incompatible_registration(name) {
                            Some(m) => {
                                self.restore_errors.insert(
                                    name.clone(),
                                    format!(
                                        "runs mesh protocol v{}, this build speaks v{}",
                                        m.network, m.ours
                                    ),
                                );
                                tracing::warn!(network = %name, ip = %my_ipv6, attempt, network_version = m.network, our_version = m.ours, "registered member network as version-incompatible; waiting for the coordinator to republish");
                            }
                            None => {
                                self.restore_errors.remove(name);
                                tracing::info!(network = %name, ip = %my_ipv6, attempt, "restored member network");
                                return;
                            }
                        }
                    }
                    // Not reachable today (a reconnect handshake only ever returns
                    // `Admitted`), and that is exactly why it must not be a silent
                    // `return`: a saved network that never registers is invisible
                    // except as a faint `inactive` marker in `ray status`.
                    ref other => {
                        tracing::warn!(network = %name, attempt, response = ?other, retry_in = ?delay, "unexpected response restoring network, retrying");
                    }
                },
                // Queued for live approval on a closed network. `TryJoin::Pending`
                // and `dial_reconnect` both document that the caller retries until
                // `ray accept` lets us in, so retry: settling here strands the
                // network until someone notices and restarts the daemon.
                Ok(TryJoin::Pending) => {
                    tracing::warn!(network = %name, attempt, retry_in = ?delay, "restore queued for approval on a closed network, retrying");
                }
                Err(e) => {
                    // Keep the reason where `ray status` can read it: a saved
                    // network that never registers otherwise renders as a bare
                    // "inactive" with the explanation only in the daemon log.
                    self.restore_errors
                        .insert(name.to_string(), format!("{e:#}"));
                    // The first failure is worth flagging; the rest are just the
                    // shape of waiting for connectivity, so keep them at debug.
                    if attempt == 1 {
                        tracing::warn!(network = %name, error = %e, retry_in = ?delay, "failed to restore network, retrying");
                    } else {
                        tracing::debug!(network = %name, error = %e, attempt, retry_in = ?delay, "failed to restore network, retrying");
                    }
                }
            }

            match self.after_attempt(name, &mut delay, attempt).await {
                RestoreNext::Retry => {}
                RestoreNext::Stop => return,
            }
        }
    }

    /// The version mismatch a registered network is flagged with. `None` covers
    /// both "not registered" and "registered and healthy".
    fn incompatible_registration(&self, name: &str) -> Option<MeshVersionMismatch> {
        self.networks.get(name).and_then(|h| h.incompatible.clone())
    }

    /// Sleep out one restore backoff step, then say whether the loop goes on.
    ///
    /// Every exit from the restore loop has to be greppable, otherwise a network
    /// that is saved but not live has no explanation anywhere. A registration
    /// flagged version-incompatible is not an exit: it holds the network open
    /// (and marked) in `ray status` while the loop waits for its coordinator to
    /// republish at a version this build speaks.
    async fn after_attempt(&self, name: &str, delay: &mut Duration, attempt: u32) -> RestoreNext {
        tokio::select! {
            _ = self.shutdown_token.cancelled() => return RestoreNext::Stop,
            _ = tokio::time::sleep(*delay) => {}
        }
        *delay = (*delay * 2).min(RESTORE_RETRY_MAX);

        if self.networks.contains_key(name) && self.incompatible_registration(name).is_none() {
            tracing::debug!(network = %name, attempt, "network registered by another path, ending restore");
            self.restore_errors.remove(name);
            return RestoreNext::Stop;
        }
        if let Ok(cfg) = config::load()
            && !cfg.networks.iter().any(|n| n.name == name)
        {
            tracing::debug!(network = %name, "network no longer saved, giving up restore");
            self.restore_errors.remove(name);
            return RestoreNext::Stop;
        }
        RestoreNext::Retry
    }

    /// The mesh protocol version a network's signed record advertises. `Ok(None)`
    /// means the record predates the field; `Err` means it could not be read at
    /// all, which says nothing about the version.
    async fn record_mesh_version(&self, net_pubkey: &str) -> Result<Option<u32>> {
        let net_pubkey: EndpointId = net_pubkey.parse().context("invalid network key")?;
        let client =
            dht::create_pkarr_client(&self.transport.endpoint, &self.transport.pkarr_relay_url)?;
        let record = dht::resolve_network_packet(&client, net_pubkey).await?;
        Ok(dht::mesh_version_from_record(&record))
    }

    /// Re-read a version-incompatible network's record and, if the coordinator
    /// has since republished at a version this build speaks, drop the blob-only
    /// registration so the caller can run a real restore over it. Returns whether
    /// it did.
    ///
    /// Tearing down is the only thing this touches, and only on a version that
    /// now matches: a mismatch that still holds must leave the registration
    /// exactly where it is, or each retry would take the network out of
    /// `ray status` and put it back.
    async fn mesh_version_recovered(
        &self,
        name: &str,
        net_pubkey: &str,
        mismatch: &MeshVersionMismatch,
    ) -> bool {
        let record_version = match self.record_mesh_version(net_pubkey).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(network = %name, error = %e, "could not re-read the network record; keeping the incompatible registration");
                return false;
            }
        };
        if !mesh_version_is_speakable(record_version, transport::MESH_PROTOCOL_VERSION) {
            return false;
        }
        tracing::info!(
            network = %name,
            was = mismatch.network,
            now = ?record_version,
            "network republished at a mesh version this build speaks; rebuilding the registration"
        );
        self.teardown_network_runtime(name).await;
        true
    }

    /// Start a member network's restore loop, unless one is already running for
    /// it. The [`restoring`](NetworkRegistry::restoring) guard is what lets the
    /// startup path and the supervisor's sweep both call this freely.
    fn spawn_member_restore(self: &Arc<Self>, net: &config::NetworkConfig) {
        let Some(net_pubkey) = net.network_public_key.map(|k| k.to_string()) else {
            tracing::warn!(network = %net.name, "no network public key in config, skipping restore");
            return;
        };
        if !self.restoring.insert(net.name.clone()) {
            return;
        }
        let me = Arc::clone(self);
        let guard = net.name.clone();
        let saved = SavedMemberNetwork {
            name: net.name.clone(),
            net_pubkey,
            persisted_hostname: net.my_hostname.clone(),
            auto_accept_firewall: net.auto_accept_firewall,
            auto_accept_files: net.auto_accept_files,
            cached_hash: net.last_group_hash,
            cached_is_published: net.last_group_hash_published,
        };
        tokio::spawn(async move {
            Arc::clone(&me).restore_member_network(saved).await;
            me.restoring.remove(&guard);
        });
    }

    /// Start a coordinator network's restore, unless one is already running for
    /// it. Returns the handle so startup can await it as a barrier; the sweep
    /// drops it. Unlike the member path this is a single attempt, so the sweep's
    /// tick is what retries it.
    fn spawn_coordinator_restore(
        self: &Arc<Self>,
        net: &config::NetworkConfig,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if !self.restoring.insert(net.name.clone()) {
            return None;
        }
        let me = Arc::clone(self);
        let name = net.name.clone();
        let mode = net.group_mode;
        Some(tokio::spawn(async move {
            match me.restore_coordinator_network(&name, mode).await {
                Ok(IpcMessage::Created { .. }) => {
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
            me.restoring.remove(&name);
        }))
    }

    /// Keep every saved network live. Sweeps on a tick and whenever a peer sends
    /// traffic for a network we have saved but not registered, restarting the
    /// restore for anything missing.
    ///
    /// The startup restore alone is not enough: it can end (a member loop that
    /// gives up because the network registered by another path, a coordinator
    /// restore that failed once) and nothing revisits the decision, leaving a
    /// network that is saved but dead until someone notices and restarts the
    /// daemon. A node in that state looks healthy: it stays connected to its
    /// peers and answers `ray ping`, while every packet for the missing network
    /// is dropped as belonging to an unknown one.
    pub(crate) async fn run_restore_supervisor(self: Arc<Self>) {
        loop {
            let nudged = tokio::select! {
                _ = self.shutdown_token.cancelled() => return,
                _ = tokio::time::sleep(RESTORE_SWEEP_INTERVAL) => false,
                _ = self.restore_nudge.notified() => true,
            };
            self.sweep_missing_networks();
            // A nudge comes from peer traffic, so its rate is the peer's to
            // choose. Hold the floor after serving one: `Notify` collapses
            // everything that arrives meanwhile into a single pending wake-up, so
            // a peer spraying frames for an unknown network costs one sweep per
            // debounce window rather than one per frame.
            if nudged {
                tokio::select! {
                    _ = self.shutdown_token.cancelled() => return,
                    _ = tokio::time::sleep(NUDGE_DEBOUNCE) => {}
                }
            }
        }
    }

    /// One pass: start a restore for every saved network that is neither live
    /// nor already being restored.
    fn sweep_missing_networks(self: &Arc<Self>) {
        let app_config = match config::load() {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "failed to load config during restore sweep");
                return;
            }
        };
        let missing = missing_networks(
            &app_config.networks,
            |name| self.networks.contains_key(name),
            |name| self.restoring.contains(name),
        );
        for m in missing {
            let Some(net) = app_config.networks.iter().find(|n| n.name == m.name) else {
                continue;
            };
            // Debug, not info: this repeats every sweep for as long as a network
            // stays unrestorable. The restore it starts logs its own outcome
            // (info on success, warn on failure), which is the part worth seeing.
            tracing::debug!(network = %m.name, "saved network is not live, restoring it");
            if m.coordinator_mode.is_some() {
                self.spawn_coordinator_restore(net);
            } else {
                self.spawn_member_restore(net);
            }
        }
    }

    /// Ask the restore supervisor to sweep now. Called from the control demux
    /// when a peer sends a frame for a network we have saved but not live: the
    /// peer is back, so there is no reason to sit out the rest of the tick.
    ///
    /// Deliberately does no work of its own (no config read, no map scan) beyond
    /// waking the supervisor: it runs per dropped frame, at a rate the peer
    /// chooses. The supervisor decides whether anything actually needs restoring
    /// and rate-limits itself.
    pub(crate) fn nudge_restore(&self) {
        self.restore_nudge.notify_one();
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
                coordinator_restores.extend(self.spawn_coordinator_restore(net));
            } else {
                // We're a member, rejoin via DHT lookup.
                self.spawn_member_restore(net);
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
            && let Ok(client) =
                dht::create_pkarr_client(&self.transport.endpoint, &self.transport.pkarr_relay_url)
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
        let my_v6 = derive_ipv6(&self.transport.identity.local_identity());
        let server = crate::ssh::SshServer::new(
            self.registry.peers.clone(),
            self.registry.device_user_map.clone(),
            self.ssh_authz.clone(),
        );
        // The overlay carries no IPv4, so there is one address to bind and it is
        // the derived mesh IPv6.
        let binds = vec![IpAddr::V6(my_v6)];
        server.spawn(binds, token);
        // Turn on the userspace port NAT so mesh `:22` reaches the listener.
        crate::forward::set_ssh_nat_active(true);
    }

    /// Start the IPv4 listener bridge, if not already running. Idempotent.
    /// Bound to the data plane for the same reason as the SSH listeners: it
    /// binds this node's mesh address, which goes down with the TUN.
    #[cfg(feature = "desktop")]
    pub(crate) fn start_v4_bridge(self: &Arc<Self>) {
        let mut guard = self.v4_bridge_token.lock().unwrap();
        if guard.is_some() {
            return;
        }
        let token = CancellationToken::new();
        *guard = Some(token.clone());
        drop(guard);
        let my_v6 = derive_ipv6(&self.transport.identity.local_identity());
        crate::v4bridge::V4Bridge::new(my_v6).spawn(token);
    }

    /// Stop the IPv4 listener bridge if running. Idempotent.
    #[cfg(feature = "desktop")]
    pub(crate) fn stop_v4_bridge(&self) {
        if let Some(t) = self.v4_bridge_token.lock().unwrap().take() {
            t.cancel();
        }
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
    ///
    /// Returns `Error` only when the link itself could not be brought up, which
    /// nothing after it can work around; that path puts the node back on standby
    /// rather than leaving it half configured. Every other problem comes back as
    /// an `Ok` carrying warnings.
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
            if let Err(e) = config::update_settings(|cfg| {
                cfg.default_hostname = Some(h);
                Ok(())
            }) {
                tracing::warn!(error = %e, "failed to persist default hostname");
            }
        }

        if self.active.swap(true, Ordering::SeqCst) {
            return IpcMessage::Ok {
                message: "already up".to_string(),
            };
        }

        // Re-resolve every network's signed record now. A battery-powered node
        // polls on a long interval, so a device coming up after a spell on
        // standby would otherwise route from whatever the roster looked like
        // when it went down.
        self.registry.poll_nudge.notify_waiters();

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
            let my_v6 = derive_ipv6(&self.transport.identity.local_identity());
            if let Err(e) = tun::set_link_up(&tun_name).await {
                // Not one warning among many. With the link down the kernel
                // flushes the address assigned below and refuses the connected
                // route, so every step after this one would report success onto
                // an interface that cannot carry a packet, and the node would
                // sit there advertising a data plane it does not have. Undo the
                // half-built state and stay on standby, which is both true and
                // what `ray status` will then say.
                let err = format!("{e:#}");
                tracing::error!(error = %err, "failed to bring TUN interface up");
                self.deactivate().await;
                return ipc_err(format!("failed to bring the TUN interface up: {err}"));
            }

            // Linux drops the TUN's global IPv6 address whenever the link goes
            // down (`ray down`) and never restores it, so re-assign it here or
            // this node answers on IPv4 only for the rest of the daemon's life.
            #[cfg(target_os = "linux")]
            if let Err(e) = tun::ensure_ipv6_addr(&tun_name, my_v6).await {
                let err = format!("{e:#}");
                tracing::warn!(error = %err, "failed to assign TUN IPv6 address");
                warnings.push(format!("failed to assign TUN IPv6 address: {err}"));
            }

            // Route the 200::/7 peer range into the TUN. Must happen after
            // link-up: on Linux the kernel won't install an IPv6 connected route
            // while the link is down, so without this peer traffic leaks out the
            // default route.
            // `200::/7` also delivers `dns::MAGIC_DNS_V6`, so the resolver needs
            // no host route of its own.
            if let Err(e) = tun::route_peer_range(&tun_name).await {
                let err = format!("{e:#}");
                tracing::warn!(error = %err, "failed to route 200::/7 into TUN");
                warnings.push(format!("failed to route IPv6 peer range into TUN: {err}"));
            }

            // Another VPN's kill switch ends in a catch-all block, and its
            // allow-list names the private ranges, which `200::/7` is not one
            // of: without a pass rule of ours ahead of it the mesh dies the
            // moment that VPN connects, with the packets dropped before they
            // ever reach the TUN. See `crate::hostfw`.
            #[cfg(target_os = "macos")]
            if config::load().map(|c| c.pf_passthrough).unwrap_or(true) {
                if let Err(e) = crate::hostfw::install_tun_passthrough(&tun_name) {
                    let err = format!("{e:#}");
                    tracing::warn!(error = %err, "failed to load the pf passthrough anchor");
                    warnings.push(format!("failed to load the pf passthrough anchor: {err}"));
                }
            } else if let Some(w) = crate::hostfw::pf_block_warning() {
                // Turned off by hand on a host where something is in fact
                // default-denying. Say which ruleset, or the operator is left
                // reading a mesh that is up and carries nothing.
                tracing::warn!("{w}");
                warnings.push(w);
            }

            // Loop our own addresses back through lo0 so self-traffic (e.g.
            // pinging our own hostname) is answered locally instead of leaving via
            // the TUN, where the forwarding loop would drop it as "no peer for
            // dst". No-op on Linux (kernel installs the `local` route
            // automatically).
            if let Err(e) = tun::route_self_loopback(my_v6).await {
                let err = format!("{e:#}");
                tracing::warn!(error = %err, "failed to install loopback self-route");
                warnings.push(format!("failed to install loopback self-route: {err}"));
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
            // Mesh SSH listens on a NAT'd port, so a host firewall allowing
            // "22/tcp" still drops it and the failure looks like a dead network
            // rather than a firewall rule. Surface it with the other `ray up`
            // warnings; we only read the ruleset, never edit it.
            if let Some(w) =
                crate::hostfw::check_inbound_tcp(&dns_tun_name, crate::ssh::SSH_LISTEN_PORT)
                    .warning(crate::ssh::SSH_LISTEN_PORT)
            {
                tracing::warn!("{w}");
                warnings.push(w);
            }
        }

        // Bridge the host's IPv4-only listeners onto the mesh address. Same
        // lifetime as the SSH server and for the same reason: it binds that
        // address. What it exposes is what `0.0.0.0` already exposes, and the
        // firewall still decides who reaches it (see `crate::v4bridge`).
        #[cfg(feature = "desktop")]
        if config::load().map(|c| c.v4_bridge).unwrap_or(true) {
            self.start_v4_bridge();
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
                message: "VPN up".to_string(),
            }
        } else {
            // Logged as well as returned: at service start nobody is holding the
            // IPC socket to read the reply, and a node that came up half
            // configured would otherwise leave no trace of it in `ray logs`.
            tracing::warn!(
                problems = %warnings.join("; "),
                "data plane activated with problems"
            );
            let mut message = "VPN up. Some things need attention:".to_string();
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
        let started = tokio::time::Instant::now();
        let _guard = self.exit_reconcile.lock().await;
        let locked = started.elapsed();
        let tun_name = self.tun_name.load().as_str().to_owned();
        let reload = self.registry.reload_exit_state();
        let reloaded = started.elapsed();
        // Both halves run even if the first one failed: they are independent roles,
        // and each one's teardown path has to happen regardless.
        let server = apply_exit_server_os(&self.registry.exit_server, &tun_name).await;
        let served = started.elapsed();
        let client = self.apply_exit_client(&tun_name).await;
        // What the kernel accepted, for `ray exit-node status`: a failed install
        // rolls back its own rules and leaves the selection standing, so the
        // selection alone cannot say whether anything is being tunnelled.
        self.registry
            .exit_install_error
            .store(client.clone().map(Arc::new));
        // `None` from `apply_exit_client` means the install succeeded (or that
        // there was nothing to install, in which case the selection is inactive).
        self.apply_exit_dns(self.registry.exit_client.is_active() && client.is_none());
        let clients = started.elapsed();
        // Advertise what actually survived the reconcile: a failed enable cleared
        // the offers, so this also withdraws a stale advertisement rather than
        // keeping clients routed into a gateway that forwards nothing.
        self.registry.sync_exit_offers().await;
        // This runs inside the IPC request, so anything slow here is time the user
        // spends staring at `ray exit-node use`. Timed per phase because a stall in
        // any of them is indistinguishable from the outside.
        tracing::debug!(
            lock = ?locked,
            reload = ?(reloaded - locked),
            server = ?(served - reloaded),
            client = ?(clients - served),
            sync_offers = ?(started.elapsed() - clients),
            total = ?started.elapsed(),
            "exit reconcile timing"
        );
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

    /// Which families the tunnel currently selected would carry, or
    /// [`ExitFamilies::Neither`] when nothing is selected.
    ///
    /// One reader for the routing install, the socket pin and the DNS override,
    /// so the three cannot end up describing different tunnels.
    fn tunnel_carries(&self) -> ExitFamilies {
        self.registry
            .exit_client
            .selection()
            .map(|s| s.carries)
            .unwrap_or(ExitFamilies::Neither)
    }

    /// Point the Magic DNS forwarder at upstreams the tunnel can actually reach,
    /// or put the captured ones back when no tunnel is up.
    ///
    /// Only a tunnel that carries IPv6 and not IPv4 needs this: every upstream the
    /// desktop capture produces is IPv4, so without an override the exit node
    /// would carry the traffic while each lookup that steered it went out the
    /// physical link. See [`exit_node::tunnel_upstreams`].
    /// `installed` is whether the tunnel actually went in, not merely whether one
    /// is selected. A failed install rolls the routing back but leaves the
    /// selection active, and pointing the forwarder at a public IPv6 resolver with
    /// no tunnel to reach it through is worse than leaving DNS alone: a host in
    /// this mode usually has no native IPv6 at all (the mode is about an IPv4
    /// conflict, not about having v6 transit), so every lookup would SERVFAIL on a
    /// host whose DNS worked a moment earlier.
    fn apply_exit_dns(&self, installed: bool) {
        let over = installed.then(|| {
            let configured = config::load().map(|c| c.dns_upstreams).unwrap_or_default();
            crate::exit_node::tunnel_upstreams(self.tunnel_carries(), &configured)
        });
        // `None` from either level means "no override": no tunnel, or a tunnel
        // whose own family already carries the captured upstreams.
        let over = over.flatten();
        // The override only moves the daemon's *own* forwarder. Whether an app's
        // query ever reaches that forwarder is the OS backend's decision, and on
        // Linux only the direct-resolv.conf backend sends us everything: the
        // split-DNS backends register `~ray` as the sole routing domain, so
        // non-`.ray` lookups go to the host's other links, over IPv4, which this
        // mode deliberately does not tunnel. macOS has no such gap, because
        // `apply_exit_client` re-asserts a catch-all match domain while the tunnel
        // is up. Giving Linux the same flip is the real fix and is not done here.
        //
        // Sharing `/etc/resolv.conf` with another mesh is the same gap by a
        // different route: we are the first nameserver and get every name, but a
        // name outside `.ray` is answered REFUSED so the stub asks the next line,
        // which is that mesh's resolver. The forwarder is out of the path either
        // way, and this is the host the mode is for, so it is worth saying.
        #[cfg(target_os = "linux")]
        if over.is_some()
            && let Some(backend) = self.dns.backend_name()
            && (backend != "direct-resolv.conf" || self.dns.resolver.defers_off_mesh())
        {
            tracing::warn!(
                backend,
                shared_resolv_conf = self.dns.resolver.defers_off_mesh(),
                "IPv6-only full tunnel is up, but non-`.ray` lookups do not reach \
                 rayfish's forwarder on this host, so they still leave over IPv4, \
                 outside the exit node"
            );
        }
        self.dns.resolver.set_tunnel_upstreams(over);
    }

    /// Install or remove the client full-tunnel routing to match the selection.
    /// The kernel plumbing spawns a series of `ip`/`nft` children and waits on
    /// them, so it runs on the blocking pool rather than stalling a runtime
    /// worker (this is called from the IPC dispatcher and `activate()`).
    #[cfg(target_os = "linux")]
    async fn apply_exit_client(&self, tun_name: &str) -> Option<String> {
        let install = self.registry.exit_client.is_active();
        let carries = self.tunnel_carries();
        let tun_name = tun_name.to_owned();
        let result = tokio::task::spawn_blocking(move || {
            if !install {
                crate::exit_node::teardown_client_routing();
                return Ok(());
            }
            crate::exit_node::install_client_routing(&tun_name, carries).inspect_err(|_| {
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
            crate::exit_node::remove_tunnel_exclusions();
            crate::exit_node::clear_physical_defaults();
            if crate::exit_node::set_full_tunnel(false, false) {
                self.transport.endpoint.network_change().await;
                // The rebind that releases the pin drops every direct path too.
                self.nudge_all_peers();
            }
            None
        } else {
            // Keep iroh's own underlay traffic off the tunnel with host routes: the
            // relay servers (resolved now, while DNS is still split) and, below,
            // the exit peer's direct addresses.
            let relay_ips = self.relay_underlay_ips().await;
            crate::exit_node::exclude_from_tunnel(&self.tunnel_relevant(relay_ips));
            // Snapshot the physical default interfaces while the routing table is
            // still clean. Once the split defaults are in, a live lookup answers
            // "the tunnel" for any family without a default route of its own, and
            // pinning iroh there routes its transport into its own tunnel.
            crate::exit_node::capture_physical_defaults();
            // Pin and rebind before the routes go in: `network_change` rebinds
            // iroh's UDP socket to apply the pin, and until it has, the transport
            // has nothing keeping it out of the tunnel.
            // Rebind whenever the pin state changed, which now includes the tunnel
            // narrowing or widening under a live selection, not just coming up.
            if crate::exit_node::set_full_tunnel(true, self.tunnel_carries().carries_v4()) {
                self.transport.endpoint.network_change().await;
            }
            let conn = self.exit_peer_conn().await;
            // The exit peer's own direct addresses need the same treatment as the
            // relays, and are only knowable from the live connection. Without this
            // the direct path is the one thing still routed into the tunnel: it
            // blackholes, iroh spends ~20s failing over, and only the relay (which
            // does have a host route) carries traffic.
            if let Some(conn) = &conn {
                crate::exit_node::exclude_from_tunnel(
                    &self.tunnel_relevant(peer_underlay_ips(conn)),
                );
            }
            let failure = self.route_default_or_rollback(tun_name).await;
            if failure.is_none() {
                // Only now is the routing table in its final shape. Everything
                // before this point gets invalidated by it: a rebind drops every
                // hole-punched path, and installing the routes makes netwatch fire
                // its own network change a few seconds later, which drops them
                // again. So wait here, at the end, or the command returns while
                // the tunnel is still settling and the first `curl` hangs.
                self.nudge_all_peers();
                if let Some(conn) = conn {
                    self.await_exit_ready(&conn).await;
                }
            }
            failure
        };
        // Re-apply system DNS to match the now-settled full-tunnel state: route
        // *all* DNS through Magic DNS while the tunnel is up (so resolution goes
        // out via the exit), split `.ray`-only otherwise.
        self.dns.reassert_os_config(tun_name).await;
        result
    }

    /// Nudge every live peer connection so it re-punches a direct path after the
    /// full-tunnel rebind dropped it to the relay. Fire-and-forget (the mesh is
    /// still reachable over the relay meanwhile); only the exit peer is worth
    /// blocking on, which [`warm_exit_peer`](Self::warm_exit_peer) does.
    #[cfg(target_os = "macos")]
    fn nudge_all_peers(&self) {
        let exit_ip = self.registry.exit_client.selection().map(|s| s.ipv6);
        for (ip, conn) in self.registry.peers.all_connections() {
            if Some(ip) == exit_ip {
                continue; // warmed synchronously below
            }
            let router = self.protocol_router.clone();
            tokio::spawn(async move { nudge_holepunch(&router, &conn).await });
        }
    }

    /// The live connection to the selected exit peer, dialing it if there is none.
    #[cfg(target_os = "macos")]
    async fn exit_peer_conn(&self) -> Option<Connection> {
        let sel = self.registry.exit_client.selection()?;
        // Dial only when there is no live connection. Dialing on top of one opens a
        // *second* QUIC connection to the same peer, and with one reader per peer
        // the two ends settle on different connections: we send every exit packet
        // down ours while the gateway reads its own, and nothing crosses in either
        // direction. Same gate the on-demand data path and `ray ping` use.
        if let Some(conn) = self.registry.peers.conn_for_ip(&sel.ipv6) {
            return Some(conn);
        }
        let target = self.registry.resolve_route(IpAddr::V6(sel.ipv6))?;
        self.registry.dial_target(&target).await;
        self.registry.peers.conn_for_ip(&sel.ipv6)
    }

    /// Narrow underlay addresses to the families the tunnel actually captures.
    ///
    /// The exclusions exist to keep iroh's own traffic off the split default. For a
    /// family the tunnel does not carry there is no default of ours to route
    /// around, so a host route is not just wasted work: it pins that address to the
    /// physical gateway, carving it out of whichever co-resident VPN owns that
    /// family on this Mac.
    ///
    /// Reads [`Self::tunnel_carries`], the same fact the routing install and the
    /// socket pin read. It used to read this node's mode, which was the same answer
    /// only until the gateway's claim could narrow a tunnel too: a dual-stack Mac
    /// through a gateway that can only return IPv6 has no IPv4 default of ours and
    /// was still excluding IPv4 addresses from it.
    #[cfg(target_os = "macos")]
    fn tunnel_relevant(&self, ips: Vec<IpAddr>) -> Vec<IpAddr> {
        let carries = self.tunnel_carries();
        ips.into_iter()
            .filter(|ip| match ip {
                IpAddr::V4(_) => carries.carries_v4() || carries.is_unknown(),
                IpAddr::V6(_) => carries.carries_v6() || carries.is_unknown(),
            })
            .collect()
    }

    /// Block until the exit peer answers over the finished tunnel, so
    /// `ray exit-node use` returns only once traffic through it actually works.
    ///
    /// The readiness signal is a control ping that comes *back*. Path state is not
    /// enough: every failure this feature has had (the transport pinned into its own
    /// tunnel, the split connection, relay traffic captured by the tunnel) presented
    /// as a healthy-looking path carrying nothing, and each one showed up here as a
    /// ping that never returned. On expiry we proceed anyway rather than fail the
    /// command, since the tunnel is installed and may still come good.
    #[cfg(target_os = "macos")]
    async fn await_exit_ready(&self, conn: &Connection) {
        let started = tokio::time::Instant::now();
        let ready = tokio::time::timeout(EXIT_READY_TIMEOUT, async {
            loop {
                // Re-check every round: hole-punching discovers new candidate
                // addresses as it goes, and one that appears without a host route
                // around the tunnel is a path that will blackhole.
                crate::exit_node::exclude_from_tunnel(
                    &self.tunnel_relevant(peer_underlay_ips(conn)),
                );
                if nudge_holepunch(&self.protocol_router, conn).await {
                    break;
                }
            }
        })
        .await
        .is_ok();
        if ready {
            tracing::debug!(took = ?started.elapsed(), "exit peer reachable through the tunnel");
        } else {
            tracing::warn!(
                timeout = ?EXIT_READY_TIMEOUT,
                "exit peer did not answer through the tunnel; traffic may not flow yet"
            );
        }
    }

    /// Resolve iroh's relay servers to their IPv4 addresses so they can be routed
    /// around the full tunnel. Resolved via the system resolver, so call this
    /// while DNS is still split (before the tunnel's DNS catch-all goes in).
    #[cfg(target_os = "macos")]
    async fn relay_underlay_ips(&self) -> Vec<IpAddr> {
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
                    if !ips.contains(&a.ip()) {
                        ips.push(a.ip());
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
        match tun::route_default_via_tun(tun_name, self.tunnel_carries()).await {
            Ok(()) => None,
            Err(e) => {
                tun::unroute_default_via_tun(tun_name).await;
                if crate::exit_node::set_full_tunnel(false, false) {
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

        // The SSH listeners and the IPv4 bridge bind the mesh IPs, which go down
        // with the data plane.
        #[cfg(feature = "desktop")]
        self.stop_ssh();
        #[cfg(feature = "desktop")]
        self.stop_v4_bridge();

        // Clone the TUN name out of the lock before awaiting (see `activate`);
        // the DnsService reverts system DNS and clears the TUN search domains.
        let tun_name = self.tun_name.load().as_str().to_owned();
        self.dns.revert(&tun_name).await;

        #[cfg(target_os = "windows")]
        if let Err(e) = tun::unroute_peer_range(&tun_name).await {
            tracing::warn!(error = %format!("{e:#}"), "failed to remove Windows TUN routes");
        }

        // A link that will not go down keeps the address and the `200::/7` route,
        // so the host still routes the overlay into a TUN whose writer is now
        // dropping everything: peer traffic black-holes instead of failing fast.
        // Ours to clean up, and pf rules outlive the process: an anchor still
        // passing an interface that no longer exists is harmless but is state we
        // left behind.
        #[cfg(target_os = "macos")]
        crate::hostfw::remove_tun_passthrough();

        #[cfg(not(target_os = "android"))]
        if let Err(e) = tun::set_link_down(&tun_name).await {
            tracing::warn!(error = %format!("{e:#}"), "failed to bring TUN interface down");
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
        // Standby is not a failed install: leaving the last one recorded would
        // have `ray exit-node status` blame it for a tunnel that is down because
        // the user put it down.
        self.registry.exit_install_error.store(None);
        // With the tunnel gone this drops any DNS override, so standby does not
        // leave the forwarder pointed at a resolver chosen for a tunnel that no
        // longer exists.
        self.apply_exit_dns(false);

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

/// Send one control ping on `conn` and report whether the pong came back within
/// [`NUDGE_REPLY_WAIT`].
///
/// Doubles as the hole-punch nudge: iroh only upgrades off the relay once there is
/// traffic on the connection, so the ping drives the upgrade whether or not the
/// caller cares about the answer.
#[cfg(target_os = "macos")]
async fn nudge_holepunch(router: &ProtocolRouter, conn: &Connection) -> bool {
    let nonce: u64 = rand::random();
    let (tx, rx) = tokio::sync::oneshot::channel();
    router.pending_pongs().insert(nonce, tx);
    if let Ok((mut send, _)) = conn.open_bi().await {
        let _ = control::send_msg(&mut send, None, &control::ControlMsg::Ping { nonce }).await;
    }
    let answered = tokio::time::timeout(NUDGE_REPLY_WAIT, rx).await.is_ok();
    router.pending_pongs().remove(&nonce);
    answered
}

/// The exit peer's own underlay addresses, as iroh currently knows them.
///
/// These are the addresses our QUIC packets to the exit peer are actually sent to,
/// so they are exactly what must be routed around the full tunnel. Relay paths are
/// skipped: the relay servers are excluded separately, by name, before DNS moves
/// into the tunnel.
///
/// Both families. Which one a peer's *underlay* is reachable over is not ours to
/// pick, and the tunnel carries IPv6, so an IPv6 underlay path is precisely the one
/// that would otherwise be swallowed by the tunnel it is carrying.
#[cfg(target_os = "macos")]
fn peer_underlay_ips(conn: &Connection) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for path in conn.paths().iter() {
        if let iroh::TransportAddr::Ip(addr) = path.remote_addr()
            && !ips.contains(&addr.ip())
        {
            ips.push(addr.ip());
        }
    }
    ips
}

#[cfg(test)]
mod coordinator_restore_tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SecretKey::from(bytes).public()
    }

    fn member(identity: EndpointId, coordinator: bool) -> Member {
        Member {
            identity,
            is_coordinator: coordinator,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: Some(42),
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        }
    }

    fn blob(members: Vec<Member>) -> crate::membership::GroupBlob {
        crate::membership::GroupBlob {
            members,
            approved: Vec::new(),
            suggested_firewall: SuggestedFirewall::default(),
            name: Some("signed-name".to_string()),
            reusable_keys: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        }
    }

    fn restored(blob: crate::membership::GroupBlob) -> RestoredGroupBlob {
        RestoredGroupBlob {
            blob,
            hash: blake3::hash(b"source"),
            published: true,
        }
    }

    #[test]
    fn restore_repairs_an_existing_key_holder() {
        let me = id(1);
        let mut existing = member(me, false);
        existing.hostname = Some("signed-host".to_string());
        existing.exit_node = true;
        existing.exit_families = ExitFamilies::V6;

        let restored = materialize_coordinator_roster(restored(blob(vec![existing])), me, None);
        let mine = restored.members.get(&me).unwrap();

        assert!(mine.is_coordinator);
        assert_eq!(mine.hostname.as_deref(), Some("signed-host"));
        assert!(mine.exit_node);
        assert_eq!(mine.exit_families, ExitFamilies::V6);
        assert_eq!(mine.last_seen, None);
    }

    #[test]
    fn restore_inserts_an_absent_key_holder_without_dropping_the_roster() {
        let me = id(1);
        let peer = id(2);

        let restored = materialize_coordinator_roster(
            restored(blob(vec![member(peer, true)])),
            me,
            Some("local-host".to_string()),
        );

        assert_eq!(restored.members.all().len(), 2);
        assert!(restored.members.get(&peer).is_some());
        let mine = restored.members.get(&me).unwrap();
        assert!(mine.is_coordinator);
        assert_eq!(mine.hostname.as_deref(), Some("local-host"));
    }

    #[test]
    fn restore_preserves_complete_blob_policy_state() {
        let me = id(1);
        let approved_id = id(2);
        let nullified = id(3);
        let (key_hash, key) = crate::membership::ReusableKey::from_secret(b"key", 10, 20);
        let approved = ApprovedEntry {
            identity: approved_id,
            hostname: Some("waiting".to_string()),
            user_identity: None,
            device_cert: None,
        };
        let mut source = blob(vec![member(me, true)]);
        source.approved.push(approved.clone());
        source.reusable_keys.insert(key_hash.clone(), key.clone());
        source.nullifiers.insert(nullified);

        let restored = materialize_coordinator_roster(restored(source), me, None);

        assert_eq!(restored.approved.all(), vec![&approved]);
        assert_eq!(restored.reusable_keys.get(&key_hash), Some(&key));
        assert_eq!(restored.nullifiers, BTreeSet::from([nullified]));
    }

    #[test]
    fn restore_changes_only_blob_derived_config_fields() {
        let me = id(1);
        let key = SecretKey::generate();
        let hash = blake3::hash(b"complete snapshot");
        let mut members = MemberList::new();
        members.add(member(me, true));
        let mut config = config::NetworkConfig {
            name: "local-name".to_string(),
            pending_hostname: Some("queued-rename".to_string()),
            transport: Some(config::TransportMode::Tor),
            auto_accept_firewall: true,
            ephemeral_ttl_secs: Some(7_200),
            exit_allow: vec!["*".to_string()],
            ..Default::default()
        };

        apply_coordinator_restore_to_config(
            &mut config,
            GroupMode::Restricted,
            &members,
            &ApprovedList::new(),
            &key,
            Some(hash),
            true,
        );

        assert_eq!(config.name, "local-name");
        assert_eq!(config.transport, Some(config::TransportMode::Tor));
        assert!(config.auto_accept_firewall);
        assert_eq!(config.ephemeral_ttl_secs, Some(7_200));
        assert_eq!(config.exit_allow, vec!["*"]);
        assert_eq!(config.pending_hostname, None);
        assert_eq!(config.last_group_hash, Some(hash));
        assert!(config.last_group_hash_published);
        assert_eq!(config.network_public_key, Some(key.public()));

        apply_coordinator_restore_to_config(
            &mut config,
            GroupMode::Restricted,
            &members,
            &ApprovedList::new(),
            &key,
            None,
            false,
        );
        assert_eq!(
            config.last_group_hash,
            Some(hash),
            "a failed replacement snapshot write must retain the recovery pointer"
        );
    }
}

#[cfg(test)]
mod kick_target_tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SecretKey::from(bytes).public()
    }

    fn member(identity: EndpointId, user: Option<EndpointId>, hostname: &str) -> Member {
        Member {
            identity,
            is_coordinator: false,
            hostname: Some(hostname.to_string()),
            user_identity: user,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        }
    }

    /// Laptop (primary, seated in its own right) plus a phone paired to it.
    fn roster() -> (MemberList, EndpointId, EndpointId) {
        let laptop = id(1);
        let phone = id(2);
        let mut members = MemberList::new();
        members.add(member(laptop, None, "laptop"));
        members.add(member(phone, Some(laptop), "phone"));
        (members, laptop, phone)
    }

    #[test]
    fn kicking_a_paired_device_takes_the_whole_user() {
        let (members, laptop, phone) = roster();
        // What `ray kick <phone>` resolves to: the phone's id, and the user
        // identity its cert names, which is the laptop.
        let (targets, _, display) = kick_targets(&members, phone, laptop).unwrap();
        assert_eq!(targets.len(), 2, "both devices of the user must be removed");
        assert!(targets.contains(&laptop) && targets.contains(&phone));
        assert_eq!(display, "phone", "the message names what the caller typed");
    }

    #[test]
    fn kicking_the_primary_takes_its_devices_too() {
        let (members, laptop, phone) = roster();
        let (targets, _, display) = kick_targets(&members, laptop, laptop).unwrap();
        assert!(targets.contains(&laptop) && targets.contains(&phone));
        assert_eq!(display, "laptop");
    }

    #[test]
    fn an_unpaired_row_is_kicked_alone() {
        // A stale row left by a reinstall: no live pairing, so `resolve` hands
        // back the device id itself and only that row goes.
        let (mut members, _laptop, _phone) = roster();
        let ghost = id(3);
        members.add(member(ghost, None, "old-phone"));
        let (targets, _, display) = kick_targets(&members, ghost, ghost).unwrap();
        assert_eq!(targets, vec![ghost]);
        assert_eq!(display, "old-phone");
    }

    #[test]
    fn a_stranger_matches_nothing() {
        let (members, _laptop, _phone) = roster();
        let stranger = id(9);
        assert!(kick_targets(&members, stranger, stranger).is_none());
    }
}
