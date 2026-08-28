//! Network create + join handlers for `Daemon`: `create_network*`, the join
//! handshake (`join_network*`, dial/fetch/restore-roster helpers). Split out of `daemon/mod.rs`.

use super::super::*;

/// Upper bound on a single proactive full-mesh dial in `dial_all_members`. An
/// offline peer's `connect` fails on its own (fast when it has no fresh
/// discovery record, but up to iroh's internal handshake timeout (tens of
/// seconds) when a stale record still points at it). We cap it so a
/// restart/reconnect never blocks that long on a dead peer: the dial is
/// best-effort and the peer's own reconnect loop re-establishes the link once it
/// comes back online.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Borrowed bundle of the per-join inputs threaded through the dial + finalize
/// phases of `join_network_inner`, so each phase takes one argument instead of a
/// dozen. The references point at locals that live for the whole join.
/// The knobs one join carries: who we say we are, what credential we present,
/// and what we consent to once inside. Grouped so the call sites name each
/// value rather than lining up seven positionals, several of them bare `bool`s
/// that would swap silently.
#[derive(Debug, Clone, Default)]
pub struct JoinOptions {
    /// Name to claim. Authoritative only if the credential binds one.
    pub hostname: Option<String>,
    /// Single-use invite secret or reusable key to present at admission.
    pub invite: Option<Vec<u8>>,
    /// Coordinator to dial first (the invite minter), when known.
    pub coordinator: Option<EndpointId>,
    /// Auto-install coordinator-suggested firewall rules on this network
    /// (`--auto-accept-firewall`); persisted so it survives restarts.
    pub auto_accept_firewall: bool,
    /// Seed for per-network auto-accept of file offers from own devices
    /// (`--auto-accept-files`); persisted, config wins on reconnect/restore.
    pub auto_accept_files: bool,
    /// Roles to ask for (`ray join --role sentry`). Narrows what the credential
    /// grants and can never widen it, so an empty list (the usual case) takes
    /// whatever the credential carries.
    pub roles: Vec<String>,
}

struct JoinContext<'a> {
    display_name: &'a str,
    my_hostname: &'a str,
    alpn: &'a [u8],
    net_pubkey: EndpointId,
    /// Exact GroupBlob hash committed by the signed record used for this join.
    group_hash: blake3::Hash,
    /// Single-use invite secret to redeem at admission, if any. Cloned per dial
    /// attempt (a fresh join may try several coordinators).
    invite: Option<Vec<u8>>,
    auto_accept_firewall: bool,
    /// Seed for per-network auto-accept of file offers from own devices
    /// (`--auto-accept-files`); persisted, config wins on reconnect/restore.
    auto_accept_files: bool,
    invite_lock: Arc<AsyncMutex<()>>,
    /// Pinned coordinator to dial first (the invite minter), if known.
    coordinator: Option<EndpointId>,
    /// Roles this join asks for, forwarded in the `JoinRequest`.
    roles: Vec<String>,
    /// Set on a restore whose network record advertises a mesh protocol version
    /// this build does not speak. Only [`VersionGate::Record`] can produce it,
    /// so it is always `None` on a fresh join.
    mismatch: Option<MeshVersionMismatch>,
}

/// What a mesh-protocol version mismatch means for the path that hit it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum VersionGate {
    /// A fresh `ray join`. Admission needs a mesh connection the versioned ALPN
    /// refuses, so nothing can be registered and the precise error is the whole
    /// answer.
    Refuse,
    /// A restore of a network this node is already a member of. Its roster blob
    /// rides the (unversioned) blob ALPN and still decodes, so the network
    /// registers from it and the mismatch is recorded for `ray status` instead
    /// of taking the network out of existence.
    Record,
}

/// A network's verified roster blob plus what its signed record said about the
/// mesh protocol version.
struct ResolvedNetwork {
    blob: crate::membership::GroupBlob,
    /// Exact content hash committed by the verified network record.
    hash: blake3::Hash,
    /// `Some` when the record advertises a version this build does not speak and
    /// the caller asked to record that rather than refuse.
    mismatch: Option<MeshVersionMismatch>,
}

/// Where coordinator restore learned the complete blob hash it is allowed to
/// apply. A live signed record wins unless the local pointer is a durably stored
/// authored generation whose publication had not yet been confirmed. The plain
/// cached fallback exists to republish after an already-published record expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoreHashSource {
    Published,
    Cached,
    LocalPending,
}

#[derive(Debug, PartialEq, Eq)]
struct RestoreTarget {
    hash: blake3::Hash,
    peers: Vec<EndpointId>,
    source: RestoreHashSource,
}

pub(crate) struct RestoredGroupBlob {
    pub(crate) blob: crate::membership::GroupBlob,
    pub(crate) hash: blake3::Hash,
    pub(crate) published: bool,
}

/// Select the exact content-addressed blob a coordinator may restore. Persisted
/// members are transport hints only: they can supply bytes for `hash`, but can
/// neither choose the hash nor become roster data themselves.
fn select_restore_target(
    published: Option<(blake3::Hash, Vec<EndpointId>)>,
    cached: Option<blake3::Hash>,
    cached_is_published: bool,
    persisted_peers: &[EndpointId],
) -> Option<RestoreTarget> {
    let pending = cached.filter(|_| !cached_is_published);
    let (hash, mut peers, source) = if let Some(hash) = pending {
        let peers = published.map(|(_, peers)| peers).unwrap_or_default();
        (hash, peers, RestoreHashSource::LocalPending)
    } else {
        match published {
            Some((hash, peers)) => (hash, peers, RestoreHashSource::Published),
            None => (cached?, Vec::new(), RestoreHashSource::Cached),
        }
    };
    peers.extend_from_slice(persisted_peers);
    peers.sort_by_key(|id| *id.as_bytes());
    peers.dedup();
    Some(RestoreTarget {
        hash,
        peers,
        source,
    })
}

fn apply_join_record_pointer(
    net: &mut config::NetworkConfig,
    net_pubkey: EndpointId,
    group_hash: blake3::Hash,
) {
    net.network_public_key = Some(net_pubkey);
    net.last_group_hash = Some(group_hash);
    net.last_group_hash_published = true;
}

/// Finish a join's durable authority transition. Plain members cache the signed
/// record they initially fetched. A freshly promoted direct-network key-holder
/// instead persists the key together with the exact admitted generation and
/// marks that authored authority as pending until its own publisher confirms it.
fn apply_finalized_join_config(
    net: &mut config::NetworkConfig,
    net_pubkey: EndpointId,
    initial_group_hash: blake3::Hash,
    held_key: Option<&SecretKey>,
    converged_hash: Option<blake3::Hash>,
    direct_exact_hash: Option<blake3::Hash>,
    direct_hash_published: Option<bool>,
) -> Result<()> {
    if let Some(key) = held_key {
        let current_hash = converged_hash
            .context("co-coordinator join has no exact admitted group snapshot hash")?;
        // Reconvergence may have advanced the complete signed state between the
        // Welcome and finalization. Preserve provenance already persisted for
        // that generation; otherwise the live generation must still be the exact
        // record bound to the key grant.
        let published = if net.last_group_hash == Some(current_hash) {
            net.last_group_hash_published
        } else {
            anyhow::ensure!(
                direct_exact_hash == Some(current_hash),
                "co-coordinator join advanced beyond its exact admission record without durable provenance"
            );
            direct_hash_published
                .context("co-coordinator join has no admission publication provenance")?
        };
        net.network_secret_key = Some(key.clone());
        net.network_public_key = Some(net_pubkey);
        net.last_group_hash = Some(current_hash);
        net.last_group_hash_published = published;
    } else {
        apply_join_record_pointer(net, net_pubkey, initial_group_hash);
    }
    Ok(())
}

/// Whether the mesh version a network's record advertises is one this build can
/// speak.
///
/// An absent version means a record published before the field existed: not a
/// refusal, just unknown, so the ALPN gate decides for those.
pub(super) fn mesh_version_is_speakable(record_version: Option<u32>, ours: u32) -> bool {
    record_version.is_none_or(|v| v == ours)
}

/// Compare the mesh version a network's signed record advertises against ours,
/// and turn a mismatch into whatever `gate` says it means here.
fn gate_mesh_version(
    record_version: Option<u32>,
    ours: u32,
    gate: VersionGate,
) -> Result<Option<MeshVersionMismatch>> {
    let Some(network) = record_version else {
        return Ok(None);
    };
    if mesh_version_is_speakable(Some(network), ours) {
        return Ok(None);
    }
    anyhow::ensure!(
        gate == VersionGate::Record,
        "incompatible mesh protocol: this network runs v{network}, this build speaks v{ours} \
         - run `ray update` so both sides match"
    );
    Ok(Some(MeshVersionMismatch { network, ours }))
}

fn reconnect_coordinator(
    explicit: Option<EndpointId>,
    members: &[crate::membership::Member],
    my_identity: EndpointId,
) -> Option<EndpointId> {
    explicit.filter(|id| *id != my_identity).or_else(|| {
        members
            .iter()
            .find(|member| member.is_coordinator && member.identity != my_identity)
            .map(|member| member.identity)
    })
}

/// A live mesh connection produced by the dial phase: the per-network state cell
/// plus the cancellation token and background tasks that `finalize_join` folds
/// into the `NetworkHandle`.
struct EstablishedMesh {
    state: SharedNetworkState,
    direct_exact_hash: Option<blake3::Hash>,
    direct_hash_published: Option<bool>,
    cancel: CancellationToken,
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

impl Daemon {
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
            Err(e) => ipc_err(format!("{e:#}")),
        }
    }

    /// Create a network and register it as coordinator.
    ///
    /// `direct` marks an auto-minted 2-peer `ray connect` network (persisted so
    /// `ray status` can tag it). `pre_approve` adds a peer to the `ApprovedList`
    /// before the blob is signed/published, so the named peer can be welcomed
    /// without a separate `ray accept` round-trip, used by `approve_connection`.
    pub(crate) async fn create_network_inner(
        &self,
        mode: GroupMode,
        custom_name: Option<String>,
        hostname: Option<String>,
        direct: bool,
        pre_approve: Option<(EndpointId, Option<String>)>,
    ) -> Result<IpcMessage> {
        self.registry
            .create_network_inner(mode, custom_name, hostname, direct, pre_approve)
            .await
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// join an existing network by key (optionally with an invite/coordinator).
    /// Thin delegate to the network registry, which owns the join path.
    pub async fn join_network(
        self: &Arc<Self>,
        network_key: &str,
        name: Option<&str>,
        opts: JoinOptions,
    ) -> IpcMessage {
        self.registry.join_network(network_key, name, opts).await
    }
}

impl NetworkRegistry {
    /// Join an existing network by key (optionally with an invite/coordinator).
    #[tracing::instrument(skip(self, opts), fields(net = name.unwrap_or(network_key)))]
    pub async fn join_network(
        self: &Arc<Self>,
        network_key: &str,
        name: Option<&str>,
        opts: JoinOptions,
    ) -> IpcMessage {
        match self
            .join_network_inner(network_key, name, opts.clone(), true)
            .await
        {
            Ok(TryJoin::Joined(resp)) => {
                let _ = config::remove_pending_join(network_key);
                *resp
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
                let retry_opts = opts;
                tokio::spawn(async move {
                    let mut backoff = BACKOFF_INITIAL;
                    loop {
                        tokio::select! {
                            _ = me.shutdown_token.cancelled() => return,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        match me
                            .join_network_inner(&nk, nm.as_deref(), retry_opts.clone(), true)
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
            Err(e) => ipc_err(format!("{e:#}")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn join_network_inner(
        self: &Arc<Self>,
        network_key: &str,
        alias: Option<&str>,
        opts: JoinOptions,
        // True for a fresh join (we send a JoinRequest first); false when
        // restoring a network we're already a member of (legacy handshake where
        // the coordinator speaks first).
        initial: bool,
    ) -> Result<TryJoin> {
        let JoinOptions {
            hostname,
            invite,
            coordinator,
            auto_accept_firewall,
            auto_accept_files,
            roles,
        } = opts;
        let net_pubkey: EndpointId = network_key.parse().context("invalid network key")?;

        if let Some(a) = alias
            && self.networks.contains_key(a)
        {
            anyhow::bail!("already in network '{a}'");
        }

        // A fresh join has to be admitted by a coordinator over a mesh connection
        // the versioned ALPN would refuse, so a version mismatch there is fatal
        // and the precise message is the right answer. A restore is already a
        // member: it registers from the verified blob and records the mismatch.
        let gate = if initial {
            VersionGate::Refuse
        } else {
            VersionGate::Record
        };
        let ResolvedNetwork {
            blob: data,
            hash: group_hash,
            mismatch,
        } = self.resolve_and_fetch_blob(net_pubkey, gate).await?;

        // If our own primary has nullified this device in the signed blob
        // (`ray unpair`), tear ourselves out instead of trying (and failing) to
        // join. This is the reliable teardown path when the device was offline at
        // unpair time (so it never got `ControlMsg::Unpaired`) and the coordinator
        // now rejects its cert at the mesh handshake: the blob is fetched from the
        // record's seed peers, needs no mesh admission, and this runs on every
        // startup restore + reconnect. Spawn `unpair_self` (delete the cert +
        // leave every network) so it runs off this join path.
        if let Some(cert) = self.current_device_cert()
            && self_is_nullified(&cert, &data.members, &data.nullifiers)
        {
            tracing::warn!(network = %network_key, "this device is nullified by its primary in the signed blob; unpairing self");
            let registry = self.clone();
            tokio::spawn(async move {
                let _ = registry.unpair_self().await;
            });
            anyhow::bail!("this device has been unpaired by its primary");
        }

        let alpn = transport::mesh_alpn();
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
            // No name given: this machine's own, unless the roster we just
            // fetched already has it. The blob is in hand before we dial, so
            // that clash is visible here and needs nothing from the wire.
            None => {
                let me = self.transport.identity.local_identity();
                let taken: Vec<&str> = data
                    .members
                    .iter()
                    .filter(|m| m.identity != me)
                    .filter_map(|m| m.hostname.as_deref())
                    .collect();
                crate::hostname::default_hostname(
                    config::load().ok().and_then(|c| c.default_hostname),
                    &taken,
                )
            }
        };

        // One invite-ledger lock for this network, shared between the join's
        // control listener (which may handle InviteShare/InviteUsed once this
        // node is promoted to co-coordinator) and the coordinator handler we may
        // register below, so all ledger access stays serialized.
        let invite_lock = Arc::new(AsyncMutex::new(()));

        let ctx = JoinContext {
            display_name,
            my_hostname: &my_hostname,
            alpn: &alpn,
            net_pubkey,
            group_hash,
            invite,
            auto_accept_firewall,
            auto_accept_files,
            invite_lock: invite_lock.clone(),
            coordinator,
            roles,
            mismatch,
        };

        // Establish the mesh link. A fresh join tries each coordinator in the
        // blob's dial order (minter first) until one welcomes us; a reconnect/
        // restore uses the legacy single-coordinator handshake where the
        // coordinator speaks first. Either may return `None` (closed network,
        // queued for `ray accept`), propagate that to the caller as `Pending`.
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
    ///
    /// `gate` says what a mismatch means here. On a fresh join it is fatal (see
    /// [`VersionGate`]); on a restore the blob is still fetched and returned, so
    /// the caller can register the network from it and mark it incompatible.
    async fn resolve_and_fetch_blob(
        &self,
        net_pubkey: EndpointId,
        gate: VersionGate,
    ) -> Result<ResolvedNetwork> {
        let pkarr_client = dht::create_pkarr_client(&self.transport.endpoint)?;
        let record = dht::resolve_network_packet(&pkarr_client, net_pubkey)
            .await
            .with_context(|| {
                format!(
                    "could not look up this network at {}",
                    dht::effective_pkarr_url()
                )
            })?;

        let mismatch = gate_mesh_version(
            dht::mesh_version_from_record(&record),
            transport::MESH_PROTOCOL_VERSION,
            gate,
        )?;

        let (expected_hash, peer_ids) =
            dht::decode_network_record(&record).context("invalid network record")?;
        if peer_ids.is_empty() {
            anyhow::bail!("no peers found in network record");
        }
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        for peer_id in &peer_ids {
            match self.try_fetch_group_blob(*peer_id, blob_hash).await {
                Ok(blob) => {
                    return Ok(ResolvedNetwork {
                        blob,
                        hash: expected_hash,
                        mismatch,
                    });
                }
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
        let my_id = self.transport.identity.local_identity();
        // With no invite, use our own id as the nominal minter;
        // coordinator_dial_order filters it out (minter != me), so we just get
        // all blob coordinators in order.
        let minter = ctx.coordinator.unwrap_or(my_id);
        let mut order = coordinator_dial_order(minter, &data.members, my_id);
        // An explicitly-provided coordinator (from an invite, or the primary we
        // just paired with) is a trusted dial target even if the fetched blob's
        // roster does not flag it `is_coordinator`: a stale roster must not
        // strand the join. Try it first.
        if let Some(coord) = ctx.coordinator
            && coord != my_id
            && !order.contains(&coord)
        {
            order.insert(0, coord);
        }
        if order.is_empty() {
            anyhow::bail!("no coordinator found in network record");
        }

        let mut last_err = anyhow::anyhow!("no coordinators tried");
        for coordinator_id in &order {
            let cancel = self.shutdown_token.child_token();
            // Reconnect + cleanup are daemon-wide now (the connection supervisor),
            // so no per-network reconnect task; readers report to the shared sender.
            let tasks: Vec<tokio::task::JoinHandle<()>> = vec![];

            tracing::info!(coordinator = %coordinator_id.fmt_short(), "connecting to coordinator");
            let conn = match transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
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
                .run_join_handshake(ctx, data, conn, true, &cancel, ctx.invite.clone())
                .await
            {
                Ok(JoinResult::Joined {
                    state,
                    direct_exact_hash,
                    direct_hash_published,
                }) => {
                    return Ok(Some(EstablishedMesh {
                        state,
                        direct_exact_hash,
                        direct_hash_published,
                        cancel,
                        tasks,
                    }));
                }
                Ok(JoinResult::Pending) => {
                    // This coordinator queued the request, don't try the next;
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
        let my_identity = self.transport.identity.local_identity();
        let coordinator_id = reconnect_coordinator(ctx.coordinator, &data.members, my_identity)
            .context("no coordinator found in network record")?;

        // The reconnect loop is spawned unconditionally and up front. A member
        // already holds the verified blob, so being *in* the network does not
        // depend on the coordinator answering right now: if it is offline at
        // restore we still register the network from the blob and let this loop
        // dial it back when it returns. Without this a member that reboots while
        // its coordinator is down silently drops the network from its running
        // state until a lucky restart.
        let cancel = self.shutdown_token.child_token();
        // Reconnect + cleanup are daemon-wide now (the connection supervisor).
        let tasks: Vec<tokio::task::JoinHandle<()>> = vec![];

        // Fallback state built straight from the verified blob so registration
        // never blocks on (or dies with) the coordinator handshake.
        let state_from_blob = || {
            let mut ns = NetworkState {
                members: MemberList::from_members(data.members.clone()),
                approved: ApprovedList::from_entries(data.approved.clone()),
                snapshot: None,
                snapshot_commit: Arc::new(AsyncMutex::new(())),
                converged_hash: None,
                unconfirmed_durable_hash: None,
                network_secret_key: None,
                network_public_key: ctx.net_pubkey,
                network_name: Some(ctx.display_name.to_string()),
                group_name: data.name.clone(),
                mode: GroupMode::Restricted,
                suggested_firewall: data.suggested_firewall.clone(),
                reusable_keys: data.reusable_keys.clone(),
                nullifiers: data.nullifiers.clone(),
                pending_suggestions: Vec::new(),
                pending: HashMap::new(),
                // Cold restore: nothing has been applied yet, so there is no
                // rollback to refuse. The floor is set by whichever record lands
                // first, the reconverge poll or a coordinator's `SignedRecord`.
                last_record_timestamp: None,
            };
            ns.refresh_snapshot();
            Arc::new(std::sync::RwLock::new(ns))
        };

        // Seed the route map from the verified blob so the data path can re-dial the
        // coordinator or any member that has since been idle-closed, before the first
        // reconverge poll populates it.
        self.seed_route_map(ctx.display_name, &data.members);

        let mut seed_from_blob = false;
        // A version-incompatible network gets no handshake: the versioned mesh
        // ALPN refuses the dial, so attempting one only spends the restore's
        // budget on a connection that cannot exist. Register from the verified
        // blob so the network is visible (and marked) instead of vanishing, and
        // let the restore loop watch for a coordinator republish. The member
        // dials below still run, and each one failing the ALPN gate is what
        // flags the peer rows incompatible too.
        if let Some(ref m) = ctx.mismatch {
            tracing::warn!(
                network = %ctx.display_name,
                network_version = m.network,
                our_version = m.ours,
                "network runs an incompatible mesh protocol version; registering from the signed blob, no peer on it is reachable"
            );
            self.seed_absent_members(ctx.display_name, &data.members);
            return Ok(Some(EstablishedMesh {
                state: state_from_blob(),
                direct_exact_hash: None,
                direct_hash_published: None,
                cancel,
                tasks,
            }));
        }

        tracing::info!(coordinator = %coordinator_id.fmt_short(), "connecting to coordinator");
        let state = match transport::connect_to_peer_with_alpn(
            &self.transport.endpoint,
            coordinator_id,
            ctx.alpn,
        )
        .await
        {
            Ok(conn) => match self
                .run_join_handshake(ctx, data, conn, false, &cancel, ctx.invite.clone())
                .await
            {
                Ok(JoinResult::Joined {
                    state,
                    direct_exact_hash: _,
                    direct_hash_published: _,
                }) => state,
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

        if seed_from_blob {
            self.seed_absent_members(ctx.display_name, &data.members);
        }

        Ok(Some(EstablishedMesh {
            state,
            direct_exact_hash: None,
            direct_hash_published: None,
            cancel,
            tasks,
        }))
    }

    /// Kick a reconnect for every roster member but ourselves on a cold
    /// registration (one with no live handshake).
    ///
    /// The daemon-wide supervisor is edge-triggered on disconnects and these
    /// peers aren't in the table, so nothing else would dial them. NB: the
    /// `NetworkHandle` is inserted by `finalize_join` after this returns, so the
    /// dial's per-network target lookup must tolerate a brief absence — the
    /// supervisor re-checks `self.networks` at dial time, by when it's present.
    fn seed_absent_members(self: &Arc<Self>, network: &str, members: &[crate::membership::Member]) {
        let me = self.transport.identity.local_identity();
        let net = SmolStr::new(network);
        for m in members {
            if m.identity == me {
                continue;
            }
            self.clone().spawn_reconnect(m.identity, vec![net.clone()]);
        }
    }

    /// Run the mesh handshake over an established connection (shared by both dial
    /// paths). `initial` distinguishes a fresh join (we speak first) from a
    /// reconnect/restore (we re-announce, then reconverge from the signed record).
    #[allow(clippy::too_many_arguments)]
    async fn run_join_handshake(
        self: &Arc<Self>,
        ctx: &JoinContext<'_>,
        data: &crate::membership::GroupBlob,
        conn: iroh::endpoint::Connection,
        initial: bool,
        cancel: &CancellationToken,
        invite_secret: Option<Vec<u8>>,
    ) -> Result<JoinResult> {
        join_mesh_shared(
            conn,
            &self.transport.endpoint,
            ctx.display_name,
            ctx.alpn,
            self.mesh_ctx(),
            JoinParams {
                my_hostname: Some(ctx.my_hostname.to_string()),
                net_pubkey: ctx.net_pubkey,
                device_cert: self.current_device_cert(),
                invite_secret,
                group_blob: data.clone(),
                auto_accept_firewall: ctx.auto_accept_firewall,
                auto_accept_files: ctx.auto_accept_files,
                requested_roles: ctx.roles.clone(),
                initial,
            },
            cancel.clone(),
            self.clone(),
            ctx.invite_lock.clone(),
            self.protocol_router().clone(),
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
            direct_exact_hash,
            direct_hash_published,
            cancel,
            mut tasks,
        } = mesh;
        let JoinContext {
            display_name,
            my_hostname,
            net_pubkey,
            group_hash,
            invite_lock,
            mismatch,
            ..
        } = ctx;

        // Serialize the authority transition with every snapshot mutation. This
        // binds the durable key and provenance to one exact live generation.
        let snapshot_commit = state.read().unwrap().snapshot_commit.clone();
        let commit_guard = snapshot_commit.lock().await;
        let (held_key, converged_hash) = {
            let state = state.read().unwrap();
            (state.network_secret_key.clone(), state.converged_hash)
        };

        // Set the network public key on the state. It is not part of GroupBlob,
        // so refreshing here would only overwrite the exact signed convergence
        // hash adopted by a direct-network co-coordinator.
        state.write().unwrap().network_public_key = net_pubkey;
        let snapshot = state
            .read()
            .unwrap()
            .snapshot
            .as_ref()
            .map(|s| (s.hash, s.msgpack_bytes.clone()));
        if let Some((_hash, bytes)) = snapshot
            && let Err(e) = self.transport.blob_store.blobs().add_slice(&bytes).await
        {
            tracing::warn!(error = %e, "failed to store local group snapshot");
        }

        // Persist either the plain member's signed record pointer or the direct
        // co-coordinator's key plus exact admitted hash in one transaction. The
        // key is not exposed through a coordinator handler until this succeeds.
        let persist_result = config::update_network(display_name, |net| {
            apply_finalized_join_config(
                net,
                net_pubkey,
                group_hash,
                held_key.as_ref(),
                converged_hash,
                direct_exact_hash,
                direct_hash_published,
            )
        })
        .and_then(|updated| updated.context("network config was deleted while joining"));
        let finalized_config = match persist_result {
            Ok(config) => config,
            Err(e) => {
                drop(commit_guard);
                cancel.cancel();
                self.conn.unregister(&net_pubkey);
                for (_ip, conn) in self.peers.remove_by_network(display_name) {
                    conn.close(VarInt::from_u32(0), b"failed join");
                }
                self.route_map.remove_network(display_name);
                return Err(e);
            }
        };
        drop(commit_guard);

        let role = role_for_key_holder(held_key.is_some());
        let dht_notify = if let Some(key) = held_key.as_ref() {
            let notify = Arc::new(tokio::sync::Notify::new());
            let initially_published = (finalized_config.last_group_hash == converged_hash
                && finalized_config.last_group_hash_published)
                .then_some(converged_hash)
                .flatten();
            tasks.extend(self.spawn_coordinator_background_tasks(
                &self.mesh_ctx(),
                display_name,
                key,
                &state,
                &notify,
                &cancel,
                initially_published,
            ));
            Some(notify)
        } else {
            None
        };

        // Membership poller
        if let Ok(poller_client) = dht::create_pkarr_client(&self.transport.endpoint) {
            tasks.push(spawn_group_poller(
                poller_client,
                net_pubkey,
                state.clone(),
                self.transport.endpoint.clone(),
                self.mesh_ctx(),
                display_name.to_string(),
                cancel.clone(),
            ));
        }

        let handle = NetworkHandle {
            name: display_name.to_string(),
            network_key: net_pubkey,
            role: role.clone(),
            state: state.clone(),
            dht_notify: dht_notify.clone(),
            cancel: cancel.clone(),
            tasks,
            invite_lock: invite_lock.clone(),
            incompatible: mismatch,
        };
        self.networks.insert(display_name.to_string(), handle);

        // Expose coordinator authority only after its key, exact complete hash,
        // publisher, and Coordinator handle are all installed.
        match role {
            NetworkRole::Coordinator => self.register_coordinator_handler(
                &self.mesh_ctx(),
                display_name,
                state.clone(),
                invite_lock.clone(),
                dht_notify,
                net_pubkey,
            ),
            NetworkRole::Member | NetworkRole::Direct => {
                if !self.protocol_router().is_registered(&net_pubkey) {
                    self.protocol_router().register(
                        net_pubkey,
                        AcceptHandler::Member(Arc::new(MemberAcceptState {
                            ctx: self.mesh_ctx(),
                            network_name: display_name.to_string(),
                            state: state.clone(),
                            net_pubkey,
                            my_identity: self.transport.identity.local_identity(),
                            endpoint: self.transport.endpoint.clone(),
                            registry: self.clone(),
                            invite_lock: invite_lock.clone(),
                            reconverge_notify: Arc::new(tokio::sync::Notify::new()),
                        })),
                    );
                }
            }
        }
        apply_suggested_firewall(
            &self.firewall,
            self.transport.identity.local_identity(),
            display_name,
            &state,
        );
        self.refresh_search_domains().await;

        // Register hostnames in DNS table
        dns::update_hostname(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            display_name,
            my_hostname,
            derive_ipv6(&self.transport.identity.local_identity()),
        )
        .await;
        for member in &data.members {
            if let Some(ref h) = member.hostname {
                dns::update_hostname(
                    &self.dns.hostname_table,
                    &self.dns.reverse_table,
                    display_name,
                    h,
                    derive_ipv6(&member.identity),
                )
                .await;
            }
        }

        tracing::info!(network = %display_name, key = %net_pubkey, "joined network");

        Ok(TryJoin::Joined(Box::new(IpcMessage::Joined {
            name: display_name.to_string(),
            my_ipv6: derive_ipv6(&self.transport.identity.local_identity()),
        })))
    }

    /// Fetch the complete GroupBlob used to restore a coordinated network. A
    /// pending locally-authored hash wins over an older reachable record; once
    /// its publication is confirmed, the live signed record wins again. If no
    /// record is reachable, the last complete hash persisted alongside the
    /// network config lets a sole coordinator read the same content-addressed
    /// bytes back and republish it. Persisted member identities are only fetch
    /// hints for that exact hash; their lossy config roster is never applied.
    pub(crate) async fn restore_roster_from_blob(
        &self,
        net_pubkey: EndpointId,
        cached_hash: Option<blake3::Hash>,
        cached_is_published: bool,
        persisted_peers: &[EndpointId],
    ) -> Result<RestoredGroupBlob> {
        let resolved = match dht::create_pkarr_client(&self.transport.endpoint) {
            Ok(client) => match dht::resolve_network_packet(&client, net_pubkey).await {
                Ok(packet) => Some(
                    dht::decode_network_record(&packet)
                        .context("decode signed pkarr record for roster restore")?,
                ),
                Err(e) => {
                    tracing::debug!(error = %e, "network record unavailable during roster restore");
                    None
                }
            },
            Err(e) => {
                tracing::debug!(error = %e, "pkarr client unavailable during roster restore");
                None
            }
        };
        let resolution_error = resolved
            .is_none()
            .then(|| "signed network record was unavailable".to_string());
        let target =
            select_restore_target(resolved, cached_hash, cached_is_published, persisted_peers)
                .with_context(|| {
                    resolution_error
                        .clone()
                        .unwrap_or_else(|| "no roster hash available".into())
                })?;
        let target_was_published = target.source != RestoreHashSource::LocalPending;
        match target.source {
            RestoreHashSource::Cached => {
                tracing::warn!(
                    network = %net_pubkey.fmt_short(),
                    error = resolution_error.as_deref().unwrap_or("record unavailable"),
                    hash = %target.hash,
                    "network record unavailable; restoring its last complete local snapshot"
                );
            }
            RestoreHashSource::LocalPending => {
                tracing::warn!(
                    network = %net_pubkey.fmt_short(),
                    hash = %target.hash,
                    "restoring a durably authored local snapshot whose publication was not confirmed"
                );
            }
            RestoreHashSource::Published => {}
        }

        let expected_hash = target.hash;
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        // Local blob store first: snapshots are permanently retained when they
        // are authored or fetched, so the normal restart has no network trip.
        if let Ok(bytes) = self.transport.blob_store.blobs().get_bytes(blob_hash).await
            && let Ok(data) = verify_group_blob(&bytes, &expected_hash)
        {
            retain_group_blob(&self.transport.blob_store, &bytes).await?;
            return Ok(RestoredGroupBlob {
                blob: data,
                hash: expected_hash,
                published: target_was_published,
            });
        }

        // A current record's seeds and the saved roster are only transport hints:
        // every peer must provide bytes matching the selected hash.
        for peer_id in &target.peers {
            if *peer_id == self.transport.endpoint.id() {
                continue;
            }
            let conn = match transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
                *peer_id,
                iroh_blobs::protocol::ALPN,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => continue,
            };
            if self
                .transport
                .blob_store
                .remote()
                .fetch(conn, HashAndFormat::raw(blob_hash))
                .await
                .is_err()
            {
                continue;
            }
            if let Ok(bytes) = self.transport.blob_store.blobs().get_bytes(blob_hash).await
                && let Ok(data) = verify_group_blob(&bytes, &expected_hash)
            {
                retain_group_blob(&self.transport.blob_store, &bytes).await?;
                return Ok(RestoredGroupBlob {
                    blob: data,
                    hash: expected_hash,
                    published: target_was_published,
                });
            }
        }
        anyhow::bail!("group blob {expected_hash} not found locally or at any known peer");
    }

    pub(crate) async fn try_fetch_group_blob(
        &self,
        peer_id: EndpointId,
        blob_hash: iroh_blobs::Hash,
    ) -> Result<crate::membership::GroupBlob> {
        let conn = transport::connect_to_peer_with_alpn(
            &self.transport.endpoint,
            peer_id,
            iroh_blobs::protocol::ALPN,
        )
        .await?;
        self.transport
            .blob_store
            .remote()
            .fetch(conn, HashAndFormat::raw(blob_hash))
            .await
            .map_err(|e| anyhow::anyhow!("blob fetch failed: {e}"))?;
        let bytes = self
            .transport
            .blob_store
            .blobs()
            .get_bytes(blob_hash)
            .await
            .map_err(|e| anyhow::anyhow!("blob read failed: {e}"))?;
        let blob = crate::membership::decode_group_blob(&bytes)?;
        retain_group_blob(&self.transport.blob_store, &bytes).await?;
        Ok(blob)
    }

    /// Dial every known member of a network: open a QUIC connection on the
    /// network ALPN, send `MeshHello`, register the peer in the PeerTable, and
    /// spawn a peer reader for each. Shared by the join path and coordinator
    /// restore so a restarting coordinator/co-coordinator proactively
    /// reconnects to **all** known members (full mesh), not just the peers
    /// that happen to dial in. Failures per-peer are logged at debug and
    /// skipped (the reconnect loop + group poller are the backstop).
    pub(crate) async fn dial_all_members(
        self: &Arc<Self>,
        members: &[Member],
        net_pubkey: EndpointId,
        network_name: &str,
        my_identity: EndpointId,
        my_hostname: Option<String>,
    ) {
        // Announce the current name (a pending rename or the confirmed one),
        // read fresh from config, rather than a value captured before a rename.
        let my_hostname = outgoing_hostname(network_name).or(my_hostname);
        let ctx = self.mesh_ctx();
        for m in members {
            if m.identity == my_identity {
                continue;
            }
            // Bound each dial so a dead peer with a stale discovery record can't
            // stall restore for iroh's full internal handshake timeout; the
            // connection supervisor retries anything still unreachable.
            let dialed = tokio::time::timeout(
                DIAL_TIMEOUT,
                transport::connect_to_peer_with_alpn(
                    &self.transport.endpoint,
                    m.identity,
                    &transport::mesh_alpn(),
                ),
            )
            .await;
            match dialed {
                Ok(Ok(peer_conn)) => {
                    if let Ok((mut s, _)) = peer_conn.open_bi().await {
                        let _ = control::send_msg(
                            &mut s,
                            Some(net_pubkey),
                            &ControlMsg::MeshHello {
                                identity: my_identity,
                                hostname: my_hostname.clone(),
                                device_cert: self.current_device_cert(),
                            },
                        )
                        .await;
                    }
                    crate::spawn_path_logger(peer_conn.clone(), m.identity.fmt_short().to_string());
                    // Register the route, then drive the new connection's control
                    // demux (which owns the data reader) and announce our handles.
                    let conn_changed = ctx.register_peer_conn(&peer_conn, m.identity, network_name);
                    if conn_changed {
                        let router = self.protocol_router().clone();
                        let dconn = peer_conn.clone();
                        tokio::spawn(
                            async move { router.drive_mesh_connection(dconn, true).await },
                        );
                    }
                    announce_network_handles(&self.peers, &peer_conn, derive_ipv6(&m.identity))
                        .await;
                    // Eager-connect reachability: a successful dial marks the peer
                    // reachable so `ray status` shows it active/idle, not offline.
                    self.reachability.note_ok(m.identity);
                    tracing::info!(
                        network = %network_name,
                        peer = %m.identity.fmt_short(),
                        "dialed known member on restore/join (full mesh)"
                    );
                }
                Ok(Err(e)) => {
                    // Distinguish an incompatible-version peer (ALPN gate) from a
                    // merely-unreachable one, so `ray status` can flag it instead
                    // of showing plain offline. A success later clears this in
                    // `PeerTable::add`.
                    if transport::is_alpn_mismatch(&format!("{e:#}")) {
                        self.peers.mark_incompatible(m.identity);
                    } else {
                        self.peers.clear_incompatible(&m.identity);
                    }
                    // Record the failed reach so status shows the peer offline from
                    // startup, not optimistically idle.
                    self.reachability.note_fail(m.identity);
                    tracing::debug!(
                        network = %network_name,
                        peer = %m.identity.fmt_short(),
                        error = %e,
                        "could not dial member yet; connection supervisor will retry"
                    );
                }
                Err(_elapsed) => {
                    self.reachability.note_fail(m.identity);
                    tracing::debug!(
                        network = %network_name,
                        peer = %m.identity.fmt_short(),
                        timeout_secs = DIAL_TIMEOUT.as_secs(),
                        "dial timed out; connection supervisor will retry"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A restore of a network we already belong to must not be undone by the
    /// version gate. The roster blob is not ALPN-gated, so the network still
    /// registers from it; the mismatch is recorded and shown. Without this the
    /// network vanished from `ray status` entirely, which reads as "gone", not
    /// as "you and it are on different protocol versions".
    #[test]
    fn a_restore_records_a_version_mismatch_instead_of_failing() {
        let mismatch = gate_mesh_version(Some(2), 4, VersionGate::Record)
            .expect("a restore never fails on the version")
            .expect("a differing version is a mismatch");
        assert_eq!(
            mismatch,
            MeshVersionMismatch {
                network: 2,
                ours: 4
            }
        );
    }

    /// A fresh join has to be admitted by a coordinator over a mesh connection
    /// the versioned ALPN refuses, so there is nothing to register and the
    /// precise message is the whole answer.
    #[test]
    fn a_fresh_join_still_fails_on_a_version_mismatch() {
        let err = gate_mesh_version(Some(2), 4, VersionGate::Refuse)
            .expect_err("a fresh join cannot proceed on a mismatch");
        let msg = format!("{err:#}");
        assert!(msg.contains("this network runs v2"), "{msg}");
        assert!(msg.contains("this build speaks v4"), "{msg}");
        assert!(msg.contains("ray update"), "{msg}");
    }

    #[test]
    fn a_matching_version_is_not_a_mismatch_on_either_path() {
        assert!(
            gate_mesh_version(Some(4), 4, VersionGate::Record)
                .unwrap()
                .is_none()
        );
        assert!(
            gate_mesh_version(Some(4), 4, VersionGate::Refuse)
                .unwrap()
                .is_none()
        );
    }

    /// Records published before the version field carry no version at all.
    /// Treating that as a mismatch would flag every older network incompatible
    /// on a guess; the ALPN gate is what decides for those.
    #[test]
    fn an_absent_version_is_not_a_mismatch() {
        assert!(mesh_version_is_speakable(None, 4));
        assert!(
            gate_mesh_version(None, 4, VersionGate::Refuse)
                .unwrap()
                .is_none()
        );
        assert!(
            gate_mesh_version(None, 4, VersionGate::Record)
                .unwrap()
                .is_none()
        );
    }

    /// The check the restore loop runs on every retry over a network it
    /// registered as incompatible: a coordinator republish at our version is
    /// what lets the blob-only registration be rebuilt as a normal one.
    #[test]
    fn a_republished_matching_version_is_speakable_again() {
        assert!(!mesh_version_is_speakable(Some(2), 4));
        assert!(mesh_version_is_speakable(Some(4), 4));
    }

    fn id(seed: u8) -> EndpointId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SecretKey::from(bytes).public()
    }

    #[test]
    fn reconnect_never_selects_the_locally_listed_coordinator() {
        let me = id(1);
        let other = id(2);
        let member = |identity| crate::membership::Member {
            identity,
            is_coordinator: true,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
        };
        let roster = vec![member(me), member(other)];

        assert_eq!(reconnect_coordinator(None, &roster, me), Some(other));
        assert_eq!(reconnect_coordinator(Some(me), &roster, me), Some(other));
    }

    #[test]
    fn join_caches_the_signed_record_hash_not_a_local_projection() {
        let net_pubkey = id(1);
        let signed_hash = blake3::hash(b"signed complete roster");
        let local_partial_hash = blake3::hash(b"local partial roster");
        let mut net = config::empty_network_config("joined");
        net.last_group_hash = Some(local_partial_hash);

        apply_join_record_pointer(&mut net, net_pubkey, signed_hash);

        assert_eq!(net.network_public_key, Some(net_pubkey));
        assert_eq!(net.last_group_hash, Some(signed_hash));
        assert!(net.last_group_hash_published);
        assert_ne!(net.last_group_hash, Some(local_partial_hash));
    }

    #[test]
    fn direct_join_commits_the_key_with_the_exact_admitted_generation() {
        let key = SecretKey::generate();
        let net_pubkey = key.public();
        let pre_admission = blake3::hash(b"record used to find the coordinator");
        let admitted = blake3::hash(b"record containing the admitted co-coordinator");
        let mut net = config::empty_network_config("direct");

        apply_finalized_join_config(
            &mut net,
            net_pubkey,
            pre_admission,
            Some(&key),
            Some(admitted),
            Some(admitted),
            Some(true),
        )
        .unwrap();

        assert_eq!(
            net.network_secret_key.as_ref().map(SecretKey::to_bytes),
            Some(key.to_bytes())
        );
        assert_eq!(net.network_public_key, Some(net_pubkey));
        assert_eq!(net.last_group_hash, Some(admitted));
        assert_ne!(net.last_group_hash, Some(pre_admission));
        assert!(
            net.last_group_hash_published,
            "the original coordinator confirmed publication before Welcome"
        );
    }

    #[test]
    fn unconfirmed_direct_admission_remains_pending_until_a_key_holder_publishes_it() {
        let key = SecretKey::generate();
        let admitted = blake3::hash(b"durable but not confirmed published");
        let mut net = config::empty_network_config("direct");

        apply_finalized_join_config(
            &mut net,
            key.public(),
            blake3::hash(b"pre-admission"),
            Some(&key),
            Some(admitted),
            Some(admitted),
            Some(false),
        )
        .unwrap();

        assert_eq!(net.last_group_hash, Some(admitted));
        assert!(!net.last_group_hash_published);
    }

    #[test]
    fn direct_join_preserves_provenance_for_a_newer_durable_generation() {
        let key = SecretKey::generate();
        let admitted = blake3::hash(b"admission record");
        let newer = blake3::hash(b"newer signed record applied during finalization");
        let mut net = config::empty_network_config("direct");
        net.last_group_hash = Some(newer);
        net.last_group_hash_published = true;

        apply_finalized_join_config(
            &mut net,
            key.public(),
            blake3::hash(b"pre-admission"),
            Some(&key),
            Some(newer),
            Some(admitted),
            Some(false),
        )
        .unwrap();

        assert_eq!(net.last_group_hash, Some(newer));
        assert!(net.last_group_hash_published);
        assert_eq!(
            net.network_secret_key.as_ref().map(SecretKey::to_bytes),
            Some(key.to_bytes())
        );
    }

    #[test]
    fn direct_join_rejects_an_unpersisted_generation_advance() {
        let key = SecretKey::generate();
        let admitted = blake3::hash(b"admission record");
        let newer = blake3::hash(b"unpersisted newer record");
        let mut net = config::empty_network_config("direct");

        let err = apply_finalized_join_config(
            &mut net,
            key.public(),
            blake3::hash(b"pre-admission"),
            Some(&key),
            Some(newer),
            Some(admitted),
            Some(false),
        )
        .expect_err("a different live generation needs its own durable provenance");

        assert!(format!("{err:#}").contains("advanced beyond its exact admission record"));
        assert!(net.network_secret_key.is_none());
        assert!(net.last_group_hash.is_none());
    }

    #[test]
    fn direct_join_refuses_to_persist_authority_without_an_exact_generation() {
        let key = SecretKey::generate();
        let mut net = config::empty_network_config("direct");

        let err = apply_finalized_join_config(
            &mut net,
            key.public(),
            blake3::hash(b"pre-admission"),
            Some(&key),
            None,
            None,
            Some(false),
        )
        .expect_err("authority without a complete recovery generation must fail");

        assert!(format!("{err:#}").contains("no exact admitted group snapshot hash"));
        assert!(net.network_secret_key.is_none());
        assert!(net.last_group_hash.is_none());
    }

    #[test]
    fn a_published_restore_hash_wins_over_the_cached_hash() {
        let published = blake3::hash(b"published");
        let cached = blake3::hash(b"cached");
        let record_seed = id(1);
        let saved_member = id(2);

        let target = select_restore_target(
            Some((published, vec![record_seed])),
            Some(cached),
            true,
            &[saved_member],
        )
        .expect("published record is a restore target");

        assert_eq!(target.hash, published);
        assert_eq!(target.source, RestoreHashSource::Published);
        let mut expected = vec![record_seed, saved_member];
        expected.sort_by_key(|id| *id.as_bytes());
        assert_eq!(target.peers, expected);
    }

    #[test]
    fn an_unconfirmed_local_generation_wins_over_the_older_record() {
        let published = blake3::hash(b"published");
        let pending = blake3::hash(b"pending local generation");
        let record_seed = id(1);

        let target = select_restore_target(
            Some((published, vec![record_seed])),
            Some(pending),
            false,
            &[],
        )
        .expect("pending durable snapshot is a restore target");

        assert_eq!(target.hash, pending);
        assert_eq!(target.source, RestoreHashSource::LocalPending);
        assert_eq!(target.peers, vec![record_seed]);
    }

    #[test]
    fn an_unreachable_record_uses_the_last_complete_snapshot_hash() {
        let cached = blake3::hash(b"cached");
        let saved_member = id(2);

        let target = select_restore_target(None, Some(cached), true, &[saved_member])
            .expect("cached complete snapshot is a restore target");

        assert_eq!(target.hash, cached);
        assert_eq!(target.source, RestoreHashSource::Cached);
        assert_eq!(target.peers, vec![saved_member]);
    }

    #[test]
    fn restore_has_no_target_without_a_record_or_cached_snapshot() {
        assert!(select_restore_target(None, None, true, &[id(2)]).is_none());
    }

    #[test]
    fn restore_fetch_hints_are_deduplicated() {
        let hash = blake3::hash(b"published");
        let peer = id(1);
        let target = select_restore_target(Some((hash, vec![peer])), None, true, &[peer]).unwrap();
        assert_eq!(target.peers, vec![peer]);
    }
}
