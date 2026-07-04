//! Connection-accept machinery for the mesh core. Moved out of `daemon/mod.rs`.
//!
//! Holds the per-network accept handlers (`CoordinatorAcceptState` admits or
//! queues joiners; `MemberAcceptState` welcomes approved members), the
//! `AcceptHandler` enum the router dispatches through, and the `ProtocolRouter`
//! that fans incoming connections out by ALPN (mesh handlers plus the
//! `blobs`/`files`/`pair`/`connect` arms). `MeshCtx` and the roster-projection
//! helpers stay in `daemon/mod.rs` since they are shared infrastructure.

use super::super::*;

/// Upper bound on a closed network's in-memory pending-join queue. Keyed by peer
/// identity, so repeat requests from one peer don't grow it; this caps a flood
/// across *distinct* identities (an attacker would need a fresh key per slot).
/// At the cap, the oldest unanswered request is evicted to admit a newer one.
pub(crate) const MAX_PENDING_JOINS: usize = 256;

/// Make room for a join request from `incoming`: if the queue is full and this is
/// a new identity, drop the oldest entry and return its id. A no-op (returns
/// `None`) when `incoming` is already queued or there is spare capacity.
pub(crate) fn evict_oldest_pending(
    pending: &mut HashMap<EndpointId, PendingJoin>,
    incoming: EndpointId,
    cap: usize,
) -> Option<EndpointId> {
    if pending.contains_key(&incoming) || pending.len() < cap {
        return None;
    }
    let oldest = pending
        .iter()
        .min_by_key(|(_, p)| p.requested_at)
        .map(|(id, _)| *id)?;
    pending.remove(&oldest);
    Some(oldest)
}

/// A paired device is auto-admitted into a closed network only when its device
/// cert is signed by this coordinator's own owner identity. The cert's
/// signature is verified by the caller before this check.
fn owner_admits(device_cert: Option<&control::DeviceCert>, own_identity: EndpointId) -> bool {
    device_cert.map(|c| c.user_identity) == Some(own_identity)
}

pub(crate) struct CoordinatorAcceptState {
    pub(crate) ctx: MeshCtx,
    pub(crate) network_name: String,
    pub(crate) state: SharedNetworkState,
    pub(crate) disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    pub(crate) token: CancellationToken,
    pub(crate) dht_notify: Option<Arc<tokio::sync::Notify>>,
    /// Shared with this network's [`NetworkHandle`]; see its `invite_lock`.
    pub(crate) invite_lock: Arc<tokio::sync::Mutex<()>>,
    /// Shared with the router; lets the control reader resolve `ray ping` Pongs.
    pub(crate) pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
}

impl CoordinatorAcceptState {
    /// Fast path for a known member reconnecting: re-add its route, send a
    /// `MemberSync`, and spawn the control reader + peer reader. `peer_ip` carries
    /// the member's stored collision index (not a fresh index-0 derivation).
    fn handle_known_member_reconnect(
        &self,
        conn: Connection,
        remote_id: EndpointId,
        peer_ip: Ipv4Addr,
    ) {
        tracing::info!(ip = %peer_ip, "known member reconnecting");
        crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
        let peer_ipv6 = derive_ipv6(&remote_id);
        self.ctx.peers.add(
            peer_ip,
            peer_ipv6,
            conn.clone(),
            remote_id,
            &self.network_name,
        );
        let token = self.token.clone();
        let disconnect_tx = self.disconnect_tx.clone();
        let network = self.network_name.clone();
        let state = self.state.clone();
        let dht_notify = self.dht_notify.clone();
        let invite_lock = self.invite_lock.clone();
        let pending_pongs = self.pending_pongs.clone();
        let ctx = self.ctx.clone();
        tokio::spawn(async move {
            send_member_sync(&conn).await;
            spawn_coordinator_control_reader(
                conn.clone(),
                remote_id,
                peer_ip,
                network.clone(),
                state,
                ctx.clone(),
                dht_notify,
                token.clone(),
                invite_lock,
                pending_pongs,
            );
            forward::spawn_peer_reader(
                conn,
                remote_id,
                peer_ip,
                peer_ipv6,
                network,
                ctx.forward_ctx(disconnect_tx, token),
            );
        });
    }

    async fn handle_connection(&self, conn: Connection) {
        let remote_id = conn.remote_id();

        // Known member reconnecting: reuse its roster IP (which carries any
        // collision_index), not a fresh index-0 derivation.
        let member_ip = {
            let s = self.state.read().unwrap();
            s.members.get(&remote_id).map(|m| m.ip)
        };
        let peer_ip = member_ip.unwrap_or_else(|| self.ctx.identity.derive_ip(&remote_id));
        if member_ip.is_some() {
            self.handle_known_member_reconnect(conn, remote_id, peer_ip);
            return;
        }

        // Non-member: read the joiner's JoinRequest first, then gate by prior
        // approval, invite secret, and access mode. Known members are handled
        // above (send-first) and never reach here; fresh joiners always send a
        // JoinRequest first (see `join_mesh_shared`).
        let (send, mut recv) =
            match tokio::time::timeout(Duration::from_secs(5), conn.accept_bi()).await {
                Ok(Ok(pair)) => pair,
                _ => return,
            };
        let msg = match tokio::time::timeout(Duration::from_secs(5), control::recv_msg(&mut recv))
            .await
        {
            Ok(Ok(m)) => m,
            _ => return,
        };
        let (invite_secret, hostname, device_cert) = match msg {
            ControlMsg::JoinRequest {
                invite_secret,
                hostname,
                device_cert,
            } => (invite_secret, hostname, device_cert),
            // Tolerate a bare MeshHello from older clients as a no-invite join.
            ControlMsg::MeshHello {
                hostname,
                device_cert,
                ..
            } => (None, hostname, device_cert),
            _ => return,
        };

        // Verify a device certificate if one is presented, and record the
        // transport-key → user-identity binding so paired devices resolve.
        if let Some(ref cert) = device_cert {
            if !cert.verify() || cert.device_key != remote_id {
                tracing::warn!(peer = %remote_id.fmt_short(), "invalid device certificate");
                return;
            }
            self.ctx
                .device_user_map
                .insert(remote_id, cert.user_identity);
        }

        // A peer pre-approved via `ray accept` is admitted directly.
        let is_approved = self.state.read().unwrap().approved.is_approved(&remote_id);
        if is_approved {
            // Live-approved name is joiner-chosen, not authoritative.
            self.admit_peer(
                conn,
                send,
                remote_id,
                peer_ip,
                hostname,
                device_cert,
                true,
                false,
            )
            .await;
            return;
        }

        // Unknown peer presenting an invite secret: verify and burn it.
        if let Some(secret) = invite_secret {
            self.redeem_invite_and_admit(
                conn,
                send,
                remote_id,
                peer_ip,
                hostname,
                device_cert,
                secret,
            )
            .await;
            return;
        }

        // Unknown peer, no invite: open networks auto-admit; closed networks
        // queue the request for live operator approval (`ray accept`).
        let mode = self.state.read().unwrap().mode;
        match mode {
            GroupMode::Open => {
                // Open-mode name is joiner-chosen, not authoritative.
                self.admit_peer(
                    conn,
                    send,
                    remote_id,
                    peer_ip,
                    hostname,
                    device_cert,
                    false,
                    false,
                )
                .await;
            }
            GroupMode::Restricted => {
                // A device cert signed by this coordinator's own owner identity
                // is one of our own paired devices: admit directly, same as an
                // open network, with no manual approval step. Must run before
                // `device_cert`/`hostname` are moved into the pending-join queue.
                if owner_admits(device_cert.as_ref(), self.ctx.identity.local_identity()) {
                    self.admit_peer(
                        conn,
                        send,
                        remote_id,
                        peer_ip,
                        hostname,
                        device_cert,
                        false,
                        false,
                    )
                    .await;
                    return;
                }
                // Queue for live operator approval, bounded by MAX_PENDING_JOINS
                // (oldest-evicted) so a peer churning fresh identities can't grow
                // it without limit. Still no per-peer concurrent-stream cap — the
                // control-flood rate limiter covers sustained message floods.
                {
                    let mut s = self.state.write().unwrap();
                    if let Some(dropped) =
                        evict_oldest_pending(&mut s.pending, remote_id, MAX_PENDING_JOINS)
                    {
                        tracing::warn!(
                            evicted = %dropped.fmt_short(),
                            "pending-join queue full; evicted oldest request"
                        );
                    }
                    s.pending.insert(
                        remote_id,
                        PendingJoin {
                            hostname,
                            device_cert,
                            requested_at: Instant::now(),
                        },
                    );
                }
                tracing::info!(peer = %remote_id.fmt_short(), ip = %peer_ip, "join queued for approval");
                let mut send = send;
                let _ = control::send_msg(&mut send, &ControlMsg::JoinPending).await;
                // We return (dropping `conn`) right after; wait for the joiner
                // to read JoinPending so the connection isn't torn down first.
                let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
            }
        }
    }

    /// Admit (or reject) an unknown peer that presented an invite `secret`.
    /// Tries the local single-use ledger first (burns on success; un-burns if
    /// admission is then denied by a collision, and gossips `InviteUsed` to the
    /// other coordinators on success), then the verified blob's reusable keys
    /// (no burn). Denies if neither matches.
    #[allow(clippy::too_many_arguments)]
    async fn redeem_invite_and_admit(
        &self,
        conn: Connection,
        send: iroh::endpoint::SendStream,
        remote_id: EndpointId,
        peer_ip: Ipv4Addr,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
        secret: Vec<u8>,
    ) {
        let redeemed = {
            let _guard = self.invite_lock.lock().await;
            match crate::invite::InviteStore::load(&self.network_name) {
                Ok(mut store) => store.redeem(&secret, remote_id),
                Err(e) => Err(e),
            }
        };
        match redeemed {
            Ok(invite_hostname) => {
                tracing::info!(peer = %remote_id.fmt_short(), "invite redeemed");
                // A hostname bound to the invite is authoritative: it overrides
                // the joiner's `--hostname` claim and is rejected on collision.
                // A free-chosen name (no binding) keeps collision-rename.
                let authoritative = invite_hostname.is_some();
                let assigned = invite_hostname.or(hostname);
                let admitted = self
                    .admit_peer(
                        conn,
                        send,
                        remote_id,
                        peer_ip,
                        assigned,
                        device_cert,
                        false,
                        authoritative,
                    )
                    .await;
                // Admission can still be denied (hostname/IP collision) after
                // the secret was burned; un-burn so the holder can retry.
                if !admitted {
                    let _guard = self.invite_lock.lock().await;
                    if let Ok(mut store) = crate::invite::InviteStore::load(&self.network_name) {
                        let _ = store.restore(&secret);
                    }
                } else {
                    // Tell the other coordinators this single-use invite is
                    // spent so their ledgers burn it too. Hash only, no secret.
                    let secret_hash = crate::invite::hash_secret(&secret);
                    let members = self.state.read().unwrap().roster();
                    gossip_to_coordinators(
                        &self.ctx.peers,
                        &self.network_name,
                        &members,
                        self.ctx.identity.local_identity(),
                        &ControlMsg::InviteUsed {
                            secret_hash: secret_hash.into_bytes(),
                        },
                    )
                    .await;
                }
            }
            Err(single_use_err) => {
                // Not a single-use invite — it may be a reusable key, which
                // lives in the signed blob and is redeemable by any network-key
                // holder (no burn). The blob is the verified source of truth.
                let reusable_id = {
                    let s = self.state.read().unwrap();
                    crate::membership::validate_reusable_key(&s.reusable_keys, &secret, now_secs())
                        .map(|k| k.id.clone())
                };
                if let Some(key_id) = reusable_id {
                    tracing::info!(
                        peer = %remote_id.fmt_short(),
                        key_id = %key_id,
                        "reusable key redeemed"
                    );
                    // Reusable joins are non-authoritative: joiner-chosen name,
                    // collision → suffix.
                    self.admit_peer(
                        conn,
                        send,
                        remote_id,
                        peer_ip,
                        hostname,
                        device_cert,
                        false,
                        false,
                    )
                    .await;
                } else {
                    tracing::warn!(peer = %remote_id.fmt_short(), error = %single_use_err, "invite rejected");
                    self.deny(&conn, send, format!("invite rejected: {single_use_err}"))
                        .await;
                }
            }
        }
    }

    /// Reply on the joiner's stream that the join was refused, then wait for the
    /// joiner to close so the JoinDenied flushes before `conn` is dropped.
    async fn deny(&self, conn: &Connection, mut send: iroh::endpoint::SendStream, reason: String) {
        let _ = control::send_msg(&mut send, &ControlMsg::JoinDenied { reason }).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    }

    /// Admit a non-member peer into the network: assign hostname/IP, add to the
    /// member list, broadcast `MemberApproved`, reply `Welcome` on the joiner's
    /// stream, and start forwarding. Shared by the invite, open-mode, and
    /// live-approval admission paths.
    /// Returns `true` if the peer was admitted, `false` if the join was denied
    /// (hostname or IP collision). Callers that burned a credential to get here
    /// (an invite) restore it on `false` so the holder isn't locked out.
    #[allow(clippy::too_many_arguments)]
    async fn admit_peer(
        &self,
        conn: Connection,
        mut send: iroh::endpoint::SendStream,
        remote_id: EndpointId,
        _suggested_ip: Ipv4Addr,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
        was_approved: bool,
        // The hostname is coordinator-authoritative (came from an invite binding).
        // Authoritative names are rejected on collision (no silent rename), so no
        // peer can claim another's name to take its suggested firewall rules.
        authoritative: bool,
    ) -> bool {
        let (peer_ip, collision_index, final_hostname) =
            match self.validate_admission(remote_id, hostname, authoritative) {
                Ok(plan) => plan,
                Err(reason) => {
                    self.deny(&conn, send, reason).await;
                    return false;
                }
            };

        // A direct (`ray connect`) network is a symmetric 2-peer link, so the
        // pre-approved requester is made a co-coordinator: marked coordinator in
        // the roster here and granted the network key over its connection below.
        let grant_direct = was_approved
            && config::load_network(&self.network_name)
                .ok()
                .flatten()
                .is_some_and(|n| n.direct);

        let user_id_opt = device_cert.as_ref().map(|c| c.user_identity);
        let snap_bytes = {
            let mut s = self.state.write().unwrap();
            if was_approved {
                s.approved.remove(&remote_id);
            }
            s.pending.remove(&remote_id);
            let _ = s.members.add(Member {
                identity: remote_id,
                ip: peer_ip,
                is_coordinator: grant_direct,
                hostname: final_hostname.clone(),
                user_identity: user_id_opt,
                device_cert: device_cert.clone(),
                collision_index,
            });
            s.refresh_snapshot();
            s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
        };
        if let Some(bytes) = snap_bytes {
            let _ = self.ctx.blob_store.blobs().add_slice(&bytes).await;
        }

        if let Some(ref h) = final_hostname {
            dns::update_hostname(
                &self.ctx.hostname_table,
                &self.ctx.reverse_table,
                &self.network_name,
                h,
                peer_ip,
                derive_ipv6(&remote_id),
            )
            .await;
        }

        broadcast_control_msg(
            &self.ctx.peers,
            &ControlMsg::MemberApproved {
                identity: remote_id,
                ip: peer_ip,
                hostname: final_hostname.clone(),
                device_cert: device_cert.clone(),
            },
        )
        .await;

        let (members, approved) = {
            let s = self.state.read().unwrap();
            (s.roster(), s.approved_snapshot())
        };

        tracing::info!(ip = %peer_ip, "new member admitted and joined");
        let _ = control::send_msg(
            &mut send,
            &ControlMsg::Welcome {
                members: members.clone(),
                approved,
            },
        )
        .await;

        if let Some(notify) = &self.dht_notify {
            notify.notify_one();
        }
        broadcast_member_sync(&self.ctx.peers, Some(peer_ip)).await;

        self.spawn_admitted_member_tasks(conn.clone(), remote_id, peer_ip);

        // Direct link: hand the network key to the just-admitted peer so both
        // sides are coordinators. Sent over its live mesh connection, where its
        // member control reader is already `accept_bi`-ing (it handles
        // `AdminGrant` -> persist key + promote to coordinator).
        if grant_direct {
            self.grant_direct_coordinator(&conn, remote_id).await;
        }
        true
    }

    /// Send an `AdminGrant` (the per-network secret key) to a peer over its live
    /// mesh connection, making it a co-coordinator. Used for `ray connect` direct
    /// networks, which are symmetric 2-peer links. Best-effort: a failure only
    /// leaves the peer as a plain member (it was already marked coordinator in the
    /// signed roster), so it can be re-granted with `ray admin add`.
    async fn grant_direct_coordinator(&self, conn: &Connection, peer: EndpointId) {
        let (net_pubkey, net_secret) = {
            let s = self.state.read().unwrap();
            (s.network_public_key, s.network_secret_key.clone())
        };
        let Some(net_secret) = net_secret else {
            return;
        };
        let grant = ControlMsg::AdminGrant {
            network_pubkey: net_pubkey,
            secret_key: net_secret.to_bytes(),
        };
        match conn.open_bi().await {
            Ok((mut send, _)) => {
                if let Err(e) = control::send_msg(&mut send, &grant).await {
                    tracing::warn!(peer = %peer.fmt_short(), error = %e,
                        "failed to grant co-coordinator to direct peer");
                    return;
                }
                tracing::info!(peer = %peer.fmt_short(),
                    "granted co-coordinator to direct-connect peer");
                // Record the grant locally (mirrors `admin_add`) so our own
                // `ray admin list` shows the peer as a key-holder too.
                if let Ok(Some(mut net)) = config::load_network(&self.network_name)
                    && !net.admins.contains(&peer)
                {
                    net.admins.push(peer);
                    let _ = config::save_network(&net);
                }
            }
            Err(e) => tracing::warn!(peer = %peer.fmt_short(), error = %e,
                "failed to open stream to grant direct co-coordinator"),
        }
    }

    /// Decide a joiner's authoritative IP + hostname from the current roster, or
    /// return a denial reason. The IP is the lowest free collision index (not the
    /// peer-suggested address) so two coordinators admitting at index 0 produce a
    /// roster the reconverge tiebreak resolves deterministically. An invite-bound
    /// (`authoritative`) hostname already held by a different identity is rejected
    /// (no silent rename); a joiner-chosen name keeps collision resolution
    /// (`name` → `name-1` → …). An IP collision with a different identity is also
    /// rejected.
    fn validate_admission(
        &self,
        remote_id: EndpointId,
        hostname: Option<String>,
        authoritative: bool,
    ) -> std::result::Result<(Ipv4Addr, u32, Option<String>), String> {
        let (peer_ip, collision_index) = {
            let s = self.state.read().unwrap();
            crate::membership::assign_ip(&s.members, &remote_id)
        };
        let final_hostname = if let Some(desired) = hostname {
            let taken = {
                let s = self.state.read().unwrap();
                s.members
                    .all()
                    .iter()
                    .filter(|m| m.identity != remote_id)
                    .filter_map(|m| m.hostname.clone())
                    .collect::<Vec<String>>()
            };
            let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
            match crate::hostname::admission_hostname(&desired, &taken_refs, authoritative) {
                Ok(name) => Some(name),
                Err(conflict) => {
                    return Err(format!(
                        "hostname '{conflict}' is already in use on this network"
                    ));
                }
            }
        } else {
            None
        };
        let collision = {
            let s = self.state.read().unwrap();
            if let Some(existing) = s.members.get_by_ip(peer_ip) {
                existing.identity != remote_id
            } else if let Some(existing) = s.approved.get_by_ip(peer_ip) {
                existing.identity != remote_id
            } else {
                false
            }
        };
        if collision {
            return Err(format!("IP collision: {peer_ip} already assigned"));
        }
        Ok((peer_ip, collision_index, final_hostname))
    }

    /// Register an admitted member in the peer table and start its control reader
    /// (so a later rename via `MeshHello` propagates immediately, not only after a
    /// reconnect) plus its inbound data-plane reader.
    fn spawn_admitted_member_tasks(
        &self,
        conn: Connection,
        remote_id: EndpointId,
        peer_ip: Ipv4Addr,
    ) {
        let peer_ipv6 = derive_ipv6(&remote_id);
        crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
        self.ctx.peers.add(
            peer_ip,
            peer_ipv6,
            conn.clone(),
            remote_id,
            &self.network_name,
        );
        spawn_coordinator_control_reader(
            conn.clone(),
            remote_id,
            peer_ip,
            self.network_name.clone(),
            self.state.clone(),
            self.ctx.clone(),
            self.dht_notify.clone(),
            self.token.clone(),
            self.invite_lock.clone(),
            self.pending_pongs.clone(),
        );
        forward::spawn_peer_reader(
            conn,
            remote_id,
            peer_ip,
            peer_ipv6,
            self.network_name.clone(),
            self.ctx
                .forward_ctx(self.disconnect_tx.clone(), self.token.clone()),
        );
    }
}

pub(crate) struct MemberAcceptState {
    pub(crate) ctx: MeshCtx,
    pub(crate) network_name: String,
    pub(crate) state: SharedNetworkState,
    pub(crate) disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    pub(crate) token: CancellationToken,
}

impl MemberAcceptState {
    /// Register a freshly handshaked peer in the peer table and start its
    /// inbound data-plane reader. Shared by the approved-join and known-member
    /// branches of `handle_connection`.
    fn register_peer(&self, conn: Connection, peer_identity: EndpointId, ip: Ipv4Addr) {
        let peer_ipv6 = derive_ipv6(&peer_identity);
        self.ctx.peers.add(
            ip,
            peer_ipv6,
            conn.clone(),
            peer_identity,
            &self.network_name,
        );
        forward::spawn_peer_reader(
            conn,
            peer_identity,
            ip,
            peer_ipv6,
            self.network_name.clone(),
            self.ctx
                .forward_ctx(self.disconnect_tx.clone(), self.token.clone()),
        );
    }

    async fn handle_connection(&self, conn: Connection) {
        let Ok((_send, mut recv)) = conn.accept_bi().await else {
            return;
        };
        let transport_id = conn.remote_id();
        let Ok(ControlMsg::MeshHello {
            identity: peer_identity,
            ip,
            hostname,
            device_cert,
            ..
        }) = control::recv_msg(&mut recv).await
        else {
            return;
        };
        // Verify identity: either transport key matches, or a valid device cert is present
        let effective_user_id = if peer_identity == transport_id {
            peer_identity
        } else if let Some(ref cert) = device_cert {
            if !cert.verify()
                || cert.device_key != transport_id
                || cert.user_identity != peer_identity
            {
                tracing::warn!(peer = %transport_id.fmt_short(), "invalid device certificate");
                return;
            }
            cert.user_identity
        } else {
            return;
        };
        if let Some(ref cert) = device_cert {
            self.ctx
                .device_user_map
                .insert(transport_id, cert.user_identity);
        }
        let _ = effective_user_id;
        let (is_member, is_approved) = {
            let s = self.state.read().unwrap();
            (
                s.members.is_member(&peer_identity),
                s.approved.is_approved(&peer_identity),
            )
        };
        // Resolve hostname collisions
        let final_hostname = if let Some(desired) = hostname {
            let taken = self.state.read().unwrap().taken_hostnames(peer_identity);
            let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
            Some(crate::hostname::resolve_collision(&desired, &taken_refs))
        } else {
            None
        };
        // Update DNS table
        if let Some(ref h) = final_hostname {
            let ipv6 = derive_ipv6(&peer_identity);
            dns::update_hostname(
                &self.ctx.hostname_table,
                &self.ctx.reverse_table,
                &self.network_name,
                h,
                ip,
                ipv6,
            )
            .await;
        }
        if is_approved {
            self.admit_approved_member(conn, peer_identity, ip, final_hostname, device_cert)
                .await;
        } else if is_member {
            if final_hostname.is_some() {
                let mut s = self.state.write().unwrap();
                if let Some(m) = s.members.get_mut(&peer_identity) {
                    m.hostname = final_hostname;
                }
            }
            self.register_peer(conn, peer_identity, ip);
        }
    }

    /// Promote a previously-approved peer to a full member on its `MeshHello`:
    /// seat it with the authoritative IP recorded at approval (not the
    /// peer-supplied one), republish the blob, send `Welcome`, start its reader,
    /// and trigger a `MemberSync` so the rest of the mesh learns the new roster.
    async fn admit_approved_member(
        &self,
        conn: Connection,
        peer_identity: EndpointId,
        ip: Ipv4Addr,
        final_hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
    ) {
        let (snap_bytes, ip) = {
            let mut s = self.state.write().unwrap();
            let approved_entry = s.approved.remove(&peer_identity);
            let user_id_opt = device_cert.as_ref().map(|c| c.user_identity);
            // Trust the authoritative IP + collision index recorded when the
            // peer was approved, not the peer-supplied MeshHello.ip.
            let (member_ip, member_idx) = approved_entry
                .as_ref()
                .map(|e| (e.ip, e.collision_index))
                .unwrap_or((ip, 0));
            let _ = s.members.add(Member {
                identity: peer_identity,
                ip: member_ip,
                is_coordinator: false,
                hostname: final_hostname.clone(),
                user_identity: user_id_opt,
                device_cert: device_cert.clone(),
                collision_index: member_idx,
            });
            s.refresh_snapshot();
            (
                s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone()),
                member_ip,
            )
        };
        if let Some(bytes) = snap_bytes {
            let _ = self.ctx.blob_store.blobs().add_slice(&bytes).await;
        }
        let (members, approved_list) = {
            let s = self.state.read().unwrap();
            (s.roster(), s.approved_snapshot())
        };
        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(
                &mut send,
                &ControlMsg::Welcome {
                    members,
                    approved: approved_list,
                },
            )
            .await;
        }
        self.register_peer(conn, peer_identity, ip);
        broadcast_member_sync(&self.ctx.peers, Some(ip)).await;
    }
}

pub(crate) enum AcceptHandler {
    Coordinator(Arc<CoordinatorAcceptState>),
    Member(Arc<MemberAcceptState>),
}

#[cfg(test)]
impl AcceptHandler {
    pub(crate) fn is_coordinator(&self) -> bool {
        matches!(self, AcceptHandler::Coordinator(_))
    }
}

pub(crate) struct MeshProtocol {
    handler: AcceptHandler,
}

impl std::fmt::Debug for MeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshProtocol").finish()
    }
}

impl ProtocolHandler for MeshProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        match &self.handler {
            AcceptHandler::Coordinator(state) => state.handle_connection(conn).await,
            AcceptHandler::Member(state) => state.handle_connection(conn).await,
        }
        Ok(())
    }
}

/// One control stream's already-read message plus its send half (for a
/// same-stream reply, e.g. `Welcome`). Routed by the per-connection demux to the
/// right per-network handler.
pub(crate) type InControl = (iroh::endpoint::SendStream, ControlMsg);

/// Daemon-wide dispatch context the accept loop needs to drive a mesh
/// connection: build the per-peer forward context and route disconnects. Set on
/// the `ProtocolRouter` by `MeshManager` after construction (the router is built
/// first), via a `OnceLock`.
pub(crate) struct MeshDispatch {
    pub(crate) ctx: MeshCtx,
    pub(crate) disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    pub(crate) token: CancellationToken,
}

pub(crate) struct ProtocolRouter {
    blobs: BlobsProtocol,
    /// Per-network mesh accept handlers, keyed by network **public key**. A single
    /// mesh connection may carry several of these (the peer shares several
    /// networks); the connection driver routes each control frame to the handler
    /// named by `ControlFrame.net`.
    handlers: DashMap<EndpointId, AcceptHandler>,
    /// File-transfer + pairing state and their ALPN accept arms. The accept loop
    /// delegates the `FILES_ALPN`/`PAIR_ALPN` arms to this; `MeshManager` holds
    /// the same handle for the IPC-side file/pairing commands.
    files: Arc<FileService>,
    /// `ray connect` state (pending/approved/outgoing maps) and the `CONNECT_ALPN`
    /// accept arm. The accept loop delegates to this; `MeshManager` holds the same
    /// handle for the IPC-side connect commands.
    connect: Arc<ConnectService>,
    /// In-flight `ray ping` probes, keyed by nonce. The connection driver fires
    /// the oneshot when the matching `Pong` arrives so the ping handler can
    /// measure round-trip time.
    pub(crate) pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
    /// Set once after construction; see [`MeshDispatch`].
    mesh: std::sync::OnceLock<MeshDispatch>,
}

impl ProtocolRouter {
    pub(crate) fn new(
        blobs: BlobsProtocol,
        files: Arc<FileService>,
        connect: Arc<ConnectService>,
    ) -> Self {
        Self {
            blobs,
            handlers: DashMap::new(),
            files,
            connect,
            pending_pongs: Arc::new(DashMap::new()),
            mesh: std::sync::OnceLock::new(),
        }
    }

    /// Install the daemon-wide mesh dispatch context. Called once by
    /// `MeshManager` right after it is built.
    pub(crate) fn set_mesh_dispatch(&self, dispatch: MeshDispatch) {
        let _ = self.mesh.set(dispatch);
    }

    /// Register a network's accept handler under its public key.
    pub(crate) fn register(&self, net_pubkey: EndpointId, handler: AcceptHandler) {
        self.handlers.insert(net_pubkey, handler);
    }

    /// Replace a network's accept handler (used when a member is promoted to
    /// coordinator). Returns whether a handler was present.
    pub(crate) fn is_registered(&self, net_pubkey: &EndpointId) -> bool {
        self.handlers.contains_key(net_pubkey)
    }

    pub(crate) fn unregister(&self, net_pubkey: &EndpointId) {
        self.handlers.remove(net_pubkey);
    }

    /// Look up a network's handler by public key.
    pub(crate) fn handler_for(&self, net_pubkey: &EndpointId) -> Option<AcceptHandler> {
        self.handlers.get(net_pubkey).map(|h| h.value().clone())
    }

    /// The static ALPN set the endpoint advertises: the single mesh ALPN plus the
    /// network-independent blobs / files / pairing / connect ALPNs.
    pub(crate) fn alpns(&self) -> Vec<Vec<u8>> {
        vec![
            transport::mesh_alpn(),
            iroh_blobs::protocol::ALPN.to_vec(),
            transport::FILES_ALPN.to_vec(),
            PAIR_ALPN.to_vec(),
            transport::CONNECT_ALPN.to_vec(),
        ]
    }

    pub(crate) fn spawn_accept_loop(
        self: &Arc<Self>,
        endpoint: Endpoint,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let router = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { return };
                        let router = router.clone();
                        tokio::spawn(async move {
                            let conn = match incoming.await {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::debug!(error = ?e, "incoming handshake failed");
                                    return;
                                }
                            };
                            let alpn = conn.alpn().to_vec();
                            match alpn.as_slice() {
                                a if a == iroh_blobs::protocol::ALPN => {
                                    let _ = router.blobs.clone().accept(conn).await;
                                }
                                a if a == transport::FILES_ALPN => router.files.accept_file_offer(conn).await,
                                a if a == PAIR_ALPN => router.files.accept_pair_request(conn).await,
                                a if a == transport::CONNECT_ALPN => router.connect.accept_connect_request(conn).await,
                                a if a == transport::mesh_alpn() => router.drive_mesh_connection(conn).await,
                                _ => {
                                    tracing::warn!(
                                        alpn = %String::from_utf8_lossy(&alpn),
                                        "no handler for ALPN"
                                    );
                                }
                            }
                        });
                    }
                }
            }
        })
    }

    /// Drive one mesh connection (single mesh ALPN) for its whole lifetime. Spawns
    /// the connection's single data reader on first network registration, then
    /// loops accepting control streams and routing each `ControlFrame` to the
    /// right per-network handler by `net`, or handling connection-level messages
    /// (`NetworkHandles`, `Ping`/`Pong`) inline. Shared by the accept side (here)
    /// and the dial side (`MeshManager::drive_dialed_connection`).
    pub(crate) async fn drive_mesh_connection(self: Arc<Self>, conn: Connection) {
        let peer_id = conn.remote_id();
        let Some(mesh) = self.mesh.get() else {
            tracing::error!("mesh dispatch not set; dropping connection");
            return;
        };
        let token = mesh.token.clone();
        let mut reader_spawned = false;
        let mut gate = crate::ratelimit::ControlGate::new();
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => return,
                r = conn.accept_bi() => r,
            };
            let (send, mut recv) = match accepted {
                Ok(pair) => pair,
                Err(_) => return, // connection closed; the data reader emits the disconnect
            };
            let frame = match control::recv_msg(&mut recv).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            match gate.check() {
                crate::ratelimit::Verdict::Allow => {}
                crate::ratelimit::Verdict::Drop => continue,
                crate::ratelimit::Verdict::Close => {
                    tracing::warn!(peer = %peer_id.fmt_short(), "control-plane flood; closing connection");
                    conn.close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                    return;
                }
            }
            // Connection-level messages (not scoped to a network).
            match &frame.msg {
                ControlMsg::NetworkHandles { entries } => {
                    self.apply_network_handles(peer_id, entries);
                    continue;
                }
                ControlMsg::Ping { nonce } => {
                    respond_pong(&conn, *nonce).await;
                    continue;
                }
                ControlMsg::Pong { nonce } => {
                    if let Some((_, tx)) = self.pending_pongs.remove(nonce) {
                        let _ = tx.send(());
                    }
                    continue;
                }
                _ => {}
            }
            let Some(net_pubkey) = frame.net else {
                continue;
            };
            let Some(handler) = self.handler_for(&net_pubkey) else {
                tracing::debug!(peer = %peer_id.fmt_short(), net = %net_pubkey.fmt_short(), "control frame for unknown network; ignoring");
                continue;
            };
            drop(recv); // one message per stream; the reply rides `send`
            let registered = handler.handle_frame(&conn, send, peer_id, frame.msg).await;
            if let Some(ip) = registered {
                if !reader_spawned {
                    reader_spawned = true;
                    let peer_ipv6 = derive_ipv6(&peer_id);
                    forward::spawn_peer_reader(
                        conn.clone(),
                        peer_id,
                        ip,
                        peer_ipv6,
                        mesh.ctx.peers.clone(),
                        mesh.ctx
                            .forward_ctx(mesh.disconnect_tx.clone(), token.clone()),
                    );
                }
                // (Re)announce our outbound handle table so the peer can decode
                // datagrams we tag for this (possibly newly-shared) network.
                announce_network_handles(&mesh.ctx.peers, &conn, ip).await;
            }
        }
    }

    /// Apply a peer's announced `NetworkHandles` (its handle → network decode
    /// table) so our data reader can resolve inbound datagram tags. Resolves the
    /// peer's mesh IPs from its endpoint id.
    fn apply_network_handles(&self, peer_id: EndpointId, entries: &[control::NetworkHandle]) {
        let Some(mesh) = self.mesh.get() else { return };
        let ip = mesh.ctx.identity.derive_ip(&peer_id);
        let ipv6 = derive_ipv6(&peer_id);
        // Map network pubkey → local network name via the registry.
        let mut table: Vec<(u16, SmolStr)> = Vec::new();
        for e in entries {
            if let Some(h) = self.handlers.get(&e.network)
                && let Some(name) = h.network_name()
            {
                table.push((e.handle, SmolStr::new(name)));
            }
        }
        mesh.ctx.peers.set_inbound_handles(&ip, &ipv6, &table);
    }
}

#[cfg(test)]
mod pending_cap_tests {
    use super::*;

    fn eid(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        iroh::SecretKey::from(b).public()
    }

    fn pending_at(t: Instant) -> PendingJoin {
        PendingJoin {
            hostname: None,
            device_cert: None,
            requested_at: t,
        }
    }

    #[test]
    fn no_eviction_below_cap() {
        let mut pending = HashMap::new();
        pending.insert(eid(1), pending_at(Instant::now()));
        assert_eq!(evict_oldest_pending(&mut pending, eid(2), 4), None);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn owner_admits_only_matching_user_identity() {
        let owner = iroh::SecretKey::from([7u8; 32]);
        let owner_id = owner.public();
        let device = iroh::SecretKey::from([9u8; 32]).public();
        let cert = control::DeviceCert::create(&owner, &device);

        // Cert signed by this owner -> admit.
        assert!(owner_admits(Some(&cert), owner_id));
        // No cert -> do not auto-admit.
        assert!(!owner_admits(None, owner_id));
        // Cert signed by a different user -> do not auto-admit.
        let other = iroh::SecretKey::from([11u8; 32]).public();
        assert!(!owner_admits(Some(&cert), other));
    }

    #[test]
    fn repeat_request_from_same_peer_never_evicts() {
        let mut pending = HashMap::new();
        for s in 0..4u8 {
            pending.insert(eid(s), pending_at(Instant::now()));
        }
        // eid(1) is already queued: a re-request must not evict anyone.
        assert_eq!(evict_oldest_pending(&mut pending, eid(1), 4), None);
        assert_eq!(pending.len(), 4);
    }

    #[test]
    fn full_queue_evicts_the_oldest() {
        let base = Instant::now();
        let mut pending = HashMap::new();
        // eid(0) is the oldest; later ids are progressively newer.
        for s in 0..4u8 {
            pending.insert(eid(s), pending_at(base + Duration::from_millis(s as u64)));
        }
        let evicted = evict_oldest_pending(&mut pending, eid(99), 4);
        assert_eq!(evicted, Some(eid(0)));
        assert_eq!(pending.len(), 3);
        assert!(!pending.contains_key(&eid(0)));
    }
}
