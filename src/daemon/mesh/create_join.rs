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

/// Everything one `ray join` needs, as a named bundle.
///
/// A struct rather than a parameter list because the join path already carried
/// eight positional arguments through four layers, and the read key would have
/// made nine of them, three of which are `Option`s of similar-looking types.
/// Part of the embedding API: `ray-mobile` builds one of these too.
#[derive(Debug, Clone, Default)]
pub struct JoinSpec {
    /// The network public key (room id), always bare. An invite code is split at
    /// the CLI / mobile boundary, so nothing inward ever sees it whole: the key
    /// is parsed as an `EndpointId`, sliced for a fallback display name, and
    /// compared by string equality for pending-join dedupe.
    pub network_key: String,
    /// Local alias for the network, if the user named one.
    pub name: Option<String>,
    pub hostname: Option<String>,
    /// Single-use or reusable invite secret to redeem at admission.
    pub invite: Option<Vec<u8>>,
    /// Coordinator to dial first (the invite minter), when the code named one.
    pub coordinator: Option<EndpointId>,
    /// Roster read key we already hold. Only a restore sets this, out of
    /// `NetworkConfig`: no share code carries a key, so a fresh join arrives
    /// with `None` and asks a coordinator for one (`acquire_read_key`) before it
    /// can read the roster.
    pub read_key: Option<ReadKey>,
    pub auto_accept_firewall: bool,
    pub auto_accept_files: bool,
}

/// Borrowed bundle of the per-join inputs threaded through the dial + finalize
/// phases of `join_network_inner`, so each phase takes one argument instead of a
/// dozen. The references point at locals that live for the whole join.
struct JoinContext<'a> {
    display_name: &'a str,
    my_hostname: &'a str,
    alpn: &'a [u8],
    net_pubkey: EndpointId,
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
    /// The read key this network's blob is sealed under: granted by a
    /// coordinator during this join, or (on a restore) read from config.
    read_key: Option<ReadKey>,
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
enum ResolvedNetwork {
    Resolved {
        blob: crate::membership::GroupBlob,
        /// `Some` when the record advertises a version this build does not speak
        /// and the caller asked to record that rather than refuse.
        mismatch: Option<MeshVersionMismatch>,
        /// The key the blob was opened with, which the caller persists. Either
        /// the one we arrived holding (a restore) or the one a coordinator just
        /// granted (a fresh join into a sealed network).
        read_key: Option<ReadKey>,
    },
    /// The roster is sealed, we hold no key, and no coordinator would grant one,
    /// which on a closed network is what "your join needs approval" looks like
    /// one step earlier than usual. A join request has been queued.
    NeedsApproval,
}

/// How long to wait for a coordinator to answer a pre-admission read-key
/// request. Short on purpose: an unentitled asker is answered with silence, so
/// this is also how long a refusal takes, and it is paid once per candidate
/// coordinator before the join can proceed.
const READ_KEY_TIMEOUT: Duration = Duration::from_secs(10);

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

/// A live mesh connection produced by the dial phase: the per-network state cell
/// plus the cancellation token and background tasks that `finalize_join` folds
/// into the `NetworkHandle`.
struct EstablishedMesh {
    state: SharedNetworkState,
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
    pub async fn join_network(self: &Arc<Self>, spec: JoinSpec) -> IpcMessage {
        self.registry.join_network(spec).await
    }
}

impl NetworkRegistry {
    /// Join an existing network by key (optionally with an invite/coordinator).
    #[tracing::instrument(skip(self, spec), fields(net = spec.name.as_deref().unwrap_or(&spec.network_key)))]
    pub async fn join_network(self: &Arc<Self>, spec: JoinSpec) -> IpcMessage {
        match self.join_network_inner(&spec, true).await {
            Ok(TryJoin::Joined(resp)) => {
                let _ = config::remove_pending_join(&spec.network_key);
                *resp
            }
            Ok(TryJoin::Pending) => {
                // Persist so the retry resumes after a restart.
                let _ = config::add_pending_join(config::PendingJoinEntry {
                    network_key: spec.network_key.clone(),
                    name: spec.name.clone(),
                });
                // Closed network: queued for live approval. Retry in the
                // background on a backoff until `ray accept` admits us.
                let me = Arc::clone(self);
                let nk = spec.network_key.clone();
                tokio::spawn(async move {
                    let mut backoff = BACKOFF_INITIAL;
                    loop {
                        tokio::select! {
                            _ = me.shutdown_token.cancelled() => return,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        match me.join_network_inner(&spec, true).await {
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

    pub(crate) async fn join_network_inner(
        self: &Arc<Self>,
        spec: &JoinSpec,
        // True for a fresh join (we send a JoinRequest first); false when
        // restoring a network we're already a member of (legacy handshake where
        // the coordinator speaks first).
        initial: bool,
    ) -> Result<TryJoin> {
        let JoinSpec {
            network_key,
            name: alias,
            hostname,
            invite,
            coordinator,
            // Read from `spec` in `resolve_and_fetch_blob`, which is also where
            // a fresh join acquires one, so the binding below is the acquired
            // key rather than this field.
            read_key: _,
            auto_accept_firewall,
            auto_accept_files,
        } = spec;
        let (auto_accept_firewall, auto_accept_files) = (*auto_accept_firewall, *auto_accept_files);
        let coordinator = *coordinator;
        let hostname = hostname.clone();
        let invite = invite.clone();
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
        let resolved = self.resolve_and_fetch_blob(net_pubkey, gate, spec).await?;
        let ResolvedNetwork::Resolved {
            blob: data,
            mismatch,
            read_key,
        } = resolved
        else {
            return Ok(TryJoin::Pending);
        };

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
        let display_name_owned = alias.clone().unwrap_or(blob_name);
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
            invite,
            auto_accept_firewall,
            auto_accept_files,
            invite_lock: invite_lock.clone(),
            coordinator,
            read_key: read_key.clone(),
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
        spec: &JoinSpec,
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

        let decoded = dht::decode_network_record(&record).context("invalid network record")?;
        if decoded.seed_peers.is_empty() {
            anyhow::bail!("no peers found in network record");
        }
        // The blob is sealed and we hold no key. Fetching would be pointless
        // (every seed peer serves the same bytes we cannot open), so ask for the
        // key first. `commitment` is in the network-key-signed record, which is
        // what makes a granted key checkable without a roster we cannot read.
        let mut read_key = spec.read_key.clone();
        if let Some(commitment) = decoded.read_key_commitment
            && read_key.is_none()
        {
            // An invite names its minter, which is a coordinator by construction
            // and need not be in the record's (necessarily stale) seed list, so
            // it is asked first.
            let mut candidates = decoded.seed_peers.clone();
            if let Some(coord) = spec.coordinator
                && !candidates.contains(&coord)
            {
                candidates.insert(0, coord);
            }
            read_key = self
                .acquire_read_key(net_pubkey, &candidates, spec.invite.as_deref(), &commitment)
                .await;
            if read_key.is_none() {
                // Refused. On a closed network with no invite that is the
                // expected answer and not a failure: the request still has to
                // reach the operator, so queue it and report Pending. The retry
                // that follows approval is granted the key, because approval is
                // one of the things `may_read_roster` accepts.
                if self.queue_join_request(net_pubkey, &candidates).await {
                    return Ok(ResolvedNetwork::NeedsApproval);
                }
                anyhow::bail!(
                    "this network's roster is encrypted and no coordinator would hand over \
                     the key or queue a join request; join with an invite code, or check \
                     that a coordinator is online"
                );
            }
        }
        let blob_hash = iroh_blobs::Hash::from_bytes(*decoded.blob_hash.as_bytes());

        for peer_id in &decoded.seed_peers {
            match self
                .try_fetch_group_blob(*peer_id, blob_hash, net_pubkey, read_key.as_ref())
                .await
            {
                Ok(blob) => {
                    return Ok(ResolvedNetwork::Resolved {
                        blob,
                        mismatch,
                        read_key,
                    });
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id.fmt_short(), error = %e, "failed to fetch blob");
                }
            }
        }
        anyhow::bail!("could not fetch group blob from any peer")
    }

    /// Put a join request in front of the operator on a network whose roster we
    /// cannot read.
    ///
    /// The normal join sends its `JoinRequest` after the blob is open, because
    /// the roster is what picks the coordinator to dial and settles the
    /// hostname. Neither is available here, so this dials the record's seed
    /// peers instead and sends the machine's own name undeduplicated: the
    /// coordinator resolves collisions authoritatively at admission anyway, and
    /// this name exists mostly so `ray requests` shows the operator who is
    /// asking. Returns whether some coordinator queued us.
    ///
    /// Only ever reached with no invite and no prior approval, so `JoinPending`
    /// is the only success this can see. An invite or an approval would have
    /// been granted the read key, and an open network grants it to anybody.
    async fn queue_join_request(&self, net_pubkey: EndpointId, seed_peers: &[EndpointId]) -> bool {
        let alpn = transport::mesh_alpn();
        let hostname = crate::hostname::default_hostname(
            config::load().ok().and_then(|c| c.default_hostname),
            &[],
        );
        let request = ControlMsg::JoinRequest {
            invite_secret: None,
            hostname: Some(hostname),
            device_cert: self.current_device_cert(),
        };
        for peer_id in seed_peers {
            if *peer_id == self.transport.identity.local_identity() {
                continue;
            }
            let queued = async {
                let conn =
                    transport::connect_to_peer_with_alpn(&self.transport.endpoint, *peer_id, &alpn)
                        .await
                        .ok()?;
                let (mut send, mut recv) = conn.open_bi().await.ok()?;
                control::send_msg(&mut send, Some(net_pubkey), &request)
                    .await
                    .ok()?;
                match tokio::time::timeout(READ_KEY_TIMEOUT, control::recv_msg(&mut recv)).await {
                    Ok(Ok(ControlMsg::JoinPending)) => Some(()),
                    _ => None,
                }
            }
            .await;
            if queued.is_some() {
                tracing::info!(
                    coordinator = %peer_id.fmt_short(),
                    "join queued for approval; the roster stays sealed until then",
                );
                return true;
            }
        }
        false
    }

    /// Ask this network's peers for the roster read key, before being admitted.
    ///
    /// A joiner has to open the roster before it can dial: the roster is what
    /// names the coordinators, and it is what settles whether the hostname this
    /// machine wants is already taken. No code carries the key, so this is where
    /// a fresh join gets one.
    ///
    /// Every candidate comes out of the signed record's seed peer list, which
    /// always contains at least one coordinator (only a network-key holder
    /// publishes, and each publisher puts itself in the list), so a coordinator
    /// is reachable here whenever the record is fresh. Non-coordinators simply
    /// do not answer.
    ///
    /// A grant is adopted only if it matches the record's `k,` commitment, so a
    /// peer that answers with the wrong key (or a hostile one that answers at
    /// all) cannot make us decrypt garbage or accept a roster it authored. That
    /// check is what stands in for the public half a symmetric key does not
    /// have.
    async fn acquire_read_key(
        &self,
        net_pubkey: EndpointId,
        seed_peers: &[EndpointId],
        invite: Option<&[u8]>,
        commitment: &blake3::Hash,
    ) -> Option<ReadKey> {
        let alpn = transport::mesh_alpn();
        let request = ControlMsg::ReadKeyRequest {
            invite_secret: invite.map(|s| s.to_vec()),
            device_cert: self.current_device_cert(),
        };
        for peer_id in seed_peers {
            if *peer_id == self.transport.identity.local_identity() {
                continue;
            }
            match self
                .ask_peer_for_read_key(*peer_id, net_pubkey, &alpn, &request, commitment)
                .await
            {
                Ok(Some(key)) => {
                    tracing::info!(peer = %peer_id.fmt_short(), "received this network's roster read key");
                    return Some(key);
                }
                // Answered with silence, or is not a coordinator: try the next.
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(peer = %peer_id.fmt_short(), error = %e, "read key request failed");
                }
            }
        }
        None
    }

    /// One peer's turn in [`Self::acquire_read_key`]. `Ok(None)` means the peer
    /// declined (or is not a coordinator, or timed out), which is not an error:
    /// a refusal is deliberately indistinguishable from silence.
    async fn ask_peer_for_read_key(
        &self,
        peer_id: EndpointId,
        net_pubkey: EndpointId,
        alpn: &[u8],
        request: &ControlMsg,
        commitment: &blake3::Hash,
    ) -> Result<Option<ReadKey>> {
        let conn = transport::connect_to_peer_with_alpn(&self.transport.endpoint, peer_id, alpn)
            .await
            .context("connect")?;
        let (mut send, mut recv) = conn.open_bi().await.context("open stream")?;
        control::send_msg(&mut send, Some(net_pubkey), request)
            .await
            .context("send read key request")?;

        let reply = match tokio::time::timeout(READ_KEY_TIMEOUT, control::recv_msg(&mut recv)).await
        {
            Ok(Ok(msg)) => msg,
            // Declined (the coordinator closes without answering) or too slow.
            Ok(Err(_)) | Err(_) => return Ok(None),
        };
        match reply {
            ControlMsg::ReadKeyGrant {
                network_pubkey,
                read_key,
            } if network_pubkey == net_pubkey => {
                let key = ReadKey::from_bytes(read_key);
                if &key.commitment() != commitment {
                    tracing::warn!(
                        peer = %peer_id.fmt_short(),
                        "read key does not match the signed record's commitment; ignoring",
                    );
                    return Ok(None);
                }
                Ok(Some(key))
            }
            _ => Ok(None),
        }
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
                Ok(JoinResult::Joined(state)) => {
                    return Ok(Some(EstablishedMesh {
                        state,
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
        // Reconnect + cleanup are daemon-wide now (the connection supervisor).
        let tasks: Vec<tokio::task::JoinHandle<()>> = vec![];

        // Fallback state built straight from the verified blob so registration
        // never blocks on (or dies with) the coordinator handshake.
        let state_from_blob = || {
            let mut ns = NetworkState {
                members: MemberList::from_members(data.members.clone()),
                approved: ApprovedList::from_entries(data.approved.clone()),
                snapshot: None,
                converged_hash: None,
                network_secret_key: None,
                read_key: ctx.read_key.clone(),
                network_public_key: ctx.net_pubkey,
                network_name: Some(ctx.display_name.to_string()),
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

        if seed_from_blob {
            self.seed_absent_members(ctx.display_name, &data.members);
        }

        Ok(Some(EstablishedMesh {
            state,
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
                suggested_firewall: data.suggested_firewall.clone(),
                reusable_keys: data.reusable_keys.clone(),
                read_key: ctx.read_key.clone(),
                auto_accept_firewall: ctx.auto_accept_firewall,
                auto_accept_files: ctx.auto_accept_files,
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
            cancel,
            mut tasks,
        } = mesh;
        let JoinContext {
            display_name,
            my_hostname,
            net_pubkey,
            invite_lock,
            mismatch,
            ..
        } = ctx;

        // A node that already holds the network secret key (e.g. a
        // co-coordinator joining after a config-only restore) should run as
        // Coordinator so it can admit future peers immediately — even though
        // it arrived here via join rather than restore. This overwrites the
        // member handler `join_mesh_shared` registered on the live-join path.
        let held_key = state.read().unwrap().network_secret_key.clone();
        match role_for_key_holder(held_key.is_some()) {
            NetworkRole::Coordinator => {
                let net_public_key = state.read().unwrap().network_public_key;
                self.register_coordinator_handler(
                    &self.mesh_ctx(),
                    display_name,
                    state.clone(),
                    invite_lock.clone(),
                    None,
                    net_public_key,
                );
            }
            // `Direct` is a display-only role (set in `status`), never produced by
            // `role_for_key_holder`; a non-key-holder runs as a plain member. The
            // live-join path already registered the member handler in
            // `join_mesh_shared`; register here only for the cold-restore path
            // (state built from the blob, no live handshake). Reconverge for that
            // path is covered by the group poller below.
            NetworkRole::Member | NetworkRole::Direct => {
                if !self.protocol_router().is_registered(&net_pubkey) {
                    self.protocol_router().register(
                        net_pubkey,
                        AcceptHandler::Member(Arc::new(MemberAcceptState {
                            ctx: self.mesh_ctx(),
                            network_name: display_name.to_string(),
                            state: state.clone(),
                            token: cancel.clone(),
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
            let _ = self.transport.blob_store.blobs().add_slice(&bytes).await;
        }

        // Save config with network public key (use display_name for config)
        if let Ok(Some(mut net)) = config::load_network(display_name) {
            net.network_public_key = Some(net_pubkey);
            let _ = config::save_network(&net);
        }

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
            role: NetworkRole::Member,
            state,
            dht_notify: None,
            cancel,
            tasks,
            invite_lock,
            incompatible: mismatch,
        };
        self.networks.insert(display_name.to_string(), handle);
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

    /// Fetch the authoritative GroupBlob for a network we coordinate, used to
    /// restore the roster across a daemon restart. Resolves the pkarr record to
    /// get the blob hash, reads the bytes back from the local blob store (where
    /// we stored them before publishing, no network round-trip), and verifies +
    /// decodes. Falls back to fetching from a seed peer if the local store
    /// doesn't have them (e.g. blobs dir was wiped). Returns an error if the DHT
    /// is unreachable, so the caller can fall back to the (possibly stale)
    /// config roster rather than booting empty.
    pub(crate) async fn restore_roster_from_blob(
        &self,
        net_pubkey: EndpointId,
        read_key: Option<&ReadKey>,
    ) -> Result<crate::membership::GroupBlob> {
        let pkarr_client = dht::create_pkarr_client(&self.transport.endpoint)?;
        let record = dht::resolve_network(&pkarr_client, net_pubkey)
            .await
            .context("resolve pkarr record for roster restore")?;
        let expected_hash = record.blob_hash;
        let seed_peers = record.seed_peers;
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        // Local blob store first: the coordinator stored these bytes before
        // publishing, so they're on disk.
        if let Ok(bytes) = self.transport.blob_store.blobs().get_bytes(blob_hash).await
            && let Ok(data) = verify_group_blob(&bytes, &expected_hash, read_key, &net_pubkey)
        {
            return Ok(data);
        }

        // Fall back to fetching from a seed peer.
        for peer_id in &seed_peers {
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
                && let Ok(data) = verify_group_blob(&bytes, &expected_hash, read_key, &net_pubkey)
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
        net_pubkey: EndpointId,
        read_key: Option<&ReadKey>,
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
        crate::membership::open_group_blob(&bytes, read_key, &net_pubkey)
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
}
