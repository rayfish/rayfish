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
    pub(crate) token: CancellationToken,
    pub(crate) dht_notify: Option<Arc<tokio::sync::Notify>>,
    /// Shared with this network's [`NetworkHandle`]; see its `invite_lock`.
    pub(crate) invite_lock: Arc<tokio::sync::Mutex<()>>,
}

impl CoordinatorAcceptState {
    /// Dispatch one control frame arriving on a mesh connection this coordinator
    /// accepts. Returns the peer's mesh IPv4 once it is a registered member on this
    /// network (so the per-connection demux can announce our handle table to it),
    /// else `None`. Ping/Pong/`NetworkHandles` are connection-level and handled by
    /// the demux before it ever reaches here.
    pub(crate) async fn handle_frame(
        &self,
        conn: &Connection,
        send: iroh::endpoint::SendStream,
        peer_id: EndpointId,
        msg: ControlMsg,
    ) -> Option<Ipv4Addr> {
        match msg {
            ControlMsg::JoinRequest {
                invite_secret,
                hostname,
                device_cert,
            } => {
                self.handle_join_request(conn, send, peer_id, invite_secret, hostname, device_cert)
                    .await
            }
            // A known member re-announcing (reconnect or rename); an unknown peer
            // sending a bare MeshHello is an older client doing a no-invite join.
            ControlMsg::MeshHello {
                hostname,
                device_cert,
                ..
            } => {
                let is_member = self.state.read().unwrap().members.is_member(&peer_id);
                if is_member {
                    self.handle_member_hello(conn, peer_id, hostname, device_cert)
                        .await
                } else {
                    self.handle_join_request(conn, send, peer_id, None, hostname, device_cert)
                        .await
                }
            }
            ControlMsg::InviteShare {
                id,
                secret_hash,
                expires,
            } => {
                self.handle_invite_share(peer_id, id, secret_hash, expires)
                    .await;
                None
            }
            ControlMsg::InviteUsed { secret_hash } => {
                self.handle_invite_used(peer_id, secret_hash).await;
                None
            }
            _ => None,
        }
    }

    /// A fresh joiner's `JoinRequest` (or an older client's bare `MeshHello`): gate
    /// by prior approval, invite secret, and access mode, then admit or queue. The
    /// admission decisions are unchanged from the per-network-connection era; only
    /// the transport (one shared connection, demux-dispatched) differs.
    async fn handle_join_request(
        &self,
        conn: &Connection,
        send: iroh::endpoint::SendStream,
        remote_id: EndpointId,
        invite_secret: Option<Vec<u8>>,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
    ) -> Option<Ipv4Addr> {
        // Verify a device certificate if presented, and record the transport-key →
        // user-identity binding so paired devices resolve.
        if let Some(ref cert) = device_cert {
            if !cert.verify() || cert.device_key != remote_id {
                tracing::warn!(peer = %remote_id.fmt_short(), "invalid device certificate");
                return None;
            }
            // Reject a cert nullified on this network (`ray unpair`). This one check
            // covers every admission branch below: owner auto-admit, invite,
            // live-approved, and open. A nullified device key is refused; every
            // other device is admitted unchanged (no fleet rotation).
            if self
                .state
                .read()
                .unwrap()
                .nullifiers
                .contains(&cert.device_key)
            {
                tracing::warn!(peer = %remote_id.fmt_short(), "rejecting nullified device certificate");
                return None;
            }
            self.ctx
                .device_user_map
                .insert(remote_id, cert.user_identity);
        }

        // A peer pre-approved via `ray accept` is admitted directly.
        let is_approved = self.state.read().unwrap().approved.is_approved(&remote_id);
        if is_approved {
            // Live-approved name is joiner-chosen, not authoritative.
            return self
                .admit_peer(conn, send, remote_id, hostname, device_cert, true, false)
                .await;
        }

        // Unknown peer presenting an invite secret: verify and burn it.
        if let Some(secret) = invite_secret {
            return self
                .redeem_invite_and_admit(conn, send, remote_id, hostname, device_cert, secret)
                .await;
        }

        // Unknown peer, no invite: open networks auto-admit; closed networks queue
        // the request for live operator approval (`ray accept`).
        let mode = self.state.read().unwrap().mode;
        match mode {
            GroupMode::Open => {
                self.admit_peer(conn, send, remote_id, hostname, device_cert, false, false)
                    .await
            }
            GroupMode::Restricted => {
                // A device cert signed by this coordinator's own owner identity is
                // one of our own paired devices: admit directly (no approval step).
                if owner_admits(device_cert.as_ref(), self.ctx.identity.local_identity()) {
                    return self
                        .admit_peer(conn, send, remote_id, hostname, device_cert, false, false)
                        .await;
                }
                // Queue for live operator approval, bounded by MAX_PENDING_JOINS
                // (oldest-evicted) so a peer churning fresh identities can't grow
                // it without limit. Still no per-peer concurrent-stream cap, the
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
                tracing::info!(peer = %remote_id.fmt_short(), "join queued for approval");
                let mut send = send;
                let _ = control::send_msg(&mut send, Some(self.net_pubkey()), &ControlMsg::JoinPending).await;
                None
            }
        }
    }

    /// The public key of the network this coordinator serves.
    fn net_pubkey(&self) -> EndpointId {
        self.state.read().unwrap().network_public_key
    }

    /// A known member re-announced over a (re)established connection: register its
    /// route + data reader, refresh its device cert, and apply any rename
    /// authoritatively (resolve collisions, update roster + DNS, republish the blob
    /// and broadcast `MemberSync` on a real change). Returns the member's mesh v4.
    async fn handle_member_hello(
        &self,
        conn: &Connection,
        remote_id: EndpointId,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
    ) -> Option<Ipv4Addr> {
        let peer_ip = self.state.read().unwrap().members.get(&remote_id).map(|m| m.ip)?;
        crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
        self.ctx
            .register_peer_conn(conn, remote_id, peer_ip, &self.network_name, &self.token);

        // Verify and store device cert if present, unless the device key is
        // nullified on this network (`ray unpair`): a nullified cert is not
        // recorded as a paired device, so it stops resolving to the user's
        // identity.
        if let Some(ref cert) = device_cert
            && cert.verify()
            && cert.device_key == remote_id
            && !self.state.read().unwrap().nullifiers.contains(&cert.device_key)
        {
            {
                let mut s = self.state.write().unwrap();
                if let Some(m) = s.members.get_mut(&remote_id) {
                    m.user_identity = Some(cert.user_identity);
                    m.device_cert = Some(cert.clone());
                }
            }
            self.ctx.device_user_map.insert(remote_id, cert.user_identity);
        }

        let Some(desired) = hostname else {
            return Some(peer_ip);
        };

        // Resolve collisions authoritatively against the rest of the roster, then
        // detect whether this is a genuine change for this member.
        let (final_hostname, changed) = {
            let s = self.state.read().unwrap();
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
            let mut s = self.state.write().unwrap();
            if let Some(m) = s.members.get_mut(&remote_id) {
                m.hostname = Some(final_hostname.clone());
            }
        }

        // Re-assert this peer's DNS entry (idempotent).
        dns::remove_hostname_by_ip(
            &self.ctx.hostname_table,
            &self.ctx.reverse_table,
            &self.network_name,
            peer_ip,
        )
        .await;
        dns::update_hostname(
            &self.ctx.hostname_table,
            &self.ctx.reverse_table,
            &self.network_name,
            &final_hostname,
            peer_ip,
            derive_ipv6(&remote_id),
        )
        .await;

        if changed {
            tracing::info!(peer = %remote_id.fmt_short(), network = %self.network_name, hostname = %final_hostname, "peer hostname changed; republishing blob + broadcasting MemberSync");
            update_snapshot_and_publish(&self.state, &self.ctx.blob_store, &self.dht_notify).await;
            broadcast_member_sync(&self.ctx.peers, self.net_pubkey(), &self.network_name, None).await;
        }
        Some(peer_ip)
    }

    /// Handle an `InviteShare` gossiped by another coordinator: record its hash so
    /// this coordinator can redeem the cross-minted single-use invite too. Honored
    /// only from a coordinator peer in our verified roster.
    async fn handle_invite_share(
        &self,
        peer_id: EndpointId,
        id: String,
        secret_hash: Vec<u8>,
        expires: u64,
    ) {
        if !sender_is_coordinator(&self.state, peer_id) {
            tracing::warn!(peer = %peer_id.fmt_short(), "ignoring InviteShare from non-coordinator");
            return;
        }
        let Ok(hash) = String::from_utf8(secret_hash) else {
            return;
        };
        let _guard = self.invite_lock.lock().await;
        if let Ok(mut store) = crate::invite::InviteStore::load(&self.network_name) {
            let _ = store.record_shared(id, hash, expires);
        }
    }

    /// Handle an `InviteUsed` gossiped by another coordinator: burn the single-use
    /// invite locally so it can't be reused here. Coordinator-only.
    async fn handle_invite_used(&self, peer_id: EndpointId, secret_hash: Vec<u8>) {
        if !sender_is_coordinator(&self.state, peer_id) {
            tracing::warn!(peer = %peer_id.fmt_short(), "ignoring InviteUsed from non-coordinator");
            return;
        }
        let Ok(hash) = String::from_utf8(secret_hash) else {
            return;
        };
        let _guard = self.invite_lock.lock().await;
        if let Ok(mut store) = crate::invite::InviteStore::load(&self.network_name) {
            let _ = store.burn_by_hash(&hash);
        }
    }

    /// Admit (or reject) an unknown peer that presented an invite `secret`.
    /// Tries the local single-use ledger first (burns on success; un-burns if
    /// admission is then denied by a collision, and gossips `InviteUsed` to the
    /// other coordinators on success), then the verified blob's reusable keys
    /// (no burn). Denies if neither matches.
    async fn redeem_invite_and_admit(
        &self,
        conn: &Connection,
        send: iroh::endpoint::SendStream,
        remote_id: EndpointId,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
        secret: Vec<u8>,
    ) -> Option<Ipv4Addr> {
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
                    .admit_peer(conn, send, remote_id, assigned, device_cert, false, authoritative)
                    .await;
                // Admission can still be denied (hostname/IP collision) after
                // the secret was burned; un-burn so the holder can retry.
                if admitted.is_none() {
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
                        self.net_pubkey(),
                        &members,
                        self.ctx.identity.local_identity(),
                        &ControlMsg::InviteUsed {
                            secret_hash: secret_hash.into_bytes(),
                        },
                    )
                    .await;
                }
                admitted
            }
            Err(single_use_err) => {
                // Not a single-use invite, it may be a reusable key, which
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
                    self.admit_peer(conn, send, remote_id, hostname, device_cert, false, false)
                        .await
                } else {
                    tracing::warn!(peer = %remote_id.fmt_short(), error = %single_use_err, "invite rejected");
                    self.deny(conn, send, format!("invite rejected: {single_use_err}"))
                        .await;
                    None
                }
            }
        }
    }

    /// Reply on the joiner's stream that the join was refused, then wait for the
    /// joiner to close so the JoinDenied flushes before `conn` is dropped.
    async fn deny(&self, conn: &Connection, mut send: iroh::endpoint::SendStream, reason: String) {
        let _ = control::send_msg(&mut send, Some(self.net_pubkey()), &ControlMsg::JoinDenied { reason }).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    }

    /// Admit a non-member peer into the network: assign hostname/IP, add to the
    /// member list, broadcast `MemberApproved`, reply `Welcome` on the joiner's
    /// stream, and start forwarding. Shared by the invite, open-mode, and
    /// live-approval admission paths.
    /// Returns `Some(ip)` with the admitted peer's mesh v4, or `None` if the join
    /// was denied (hostname or IP collision). Callers that burned a credential to
    /// get here (an invite) restore it on `None` so the holder isn't locked out.
    #[allow(clippy::too_many_arguments)]
    async fn admit_peer(
        &self,
        conn: &Connection,
        mut send: iroh::endpoint::SendStream,
        remote_id: EndpointId,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
        was_approved: bool,
        // The hostname is coordinator-authoritative (came from an invite binding).
        // Authoritative names are rejected on collision (no silent rename), so no
        // peer can claim another's name to take its suggested firewall rules.
        authoritative: bool,
    ) -> Option<Ipv4Addr> {
        let (peer_ip, collision_index, final_hostname) =
            match self.validate_admission(remote_id, hostname, authoritative) {
                Ok(plan) => plan,
                Err(reason) => {
                    self.deny(conn, send, reason).await;
                    return None;
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
                last_seen: Some(crate::membership::now_secs()),
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

        let net_pubkey = self.net_pubkey();
        broadcast_control_msg(
            &self.ctx.peers,
            net_pubkey,
            &self.network_name,
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
            Some(net_pubkey),
            &ControlMsg::Welcome {
                members: members.clone(),
                approved,
            },
        )
        .await;

        if let Some(notify) = &self.dht_notify {
            notify.notify_one();
        }

        // Register the peer's route + start its single data reader (the accept-side
        // demux already owns this connection's control loop).
        crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
        self.ctx
            .register_peer_conn(conn, remote_id, peer_ip, &self.network_name, &self.token);

        broadcast_member_sync(&self.ctx.peers, net_pubkey, &self.network_name, Some(peer_ip)).await;

        // Direct link: hand the network key to the just-admitted peer so both
        // sides are coordinators. Sent over its live mesh connection, where its
        // demux handles `AdminGrant` -> persist key + promote to coordinator.
        if grant_direct {
            self.grant_direct_coordinator(conn, remote_id).await;
        }
        Some(peer_ip)
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
                if let Err(e) = control::send_msg(&mut send, Some(net_pubkey), &grant).await {
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
}

pub(crate) struct MemberAcceptState {
    pub(crate) ctx: MeshCtx,
    pub(crate) network_name: String,
    pub(crate) state: SharedNetworkState,
    pub(crate) token: CancellationToken,
    /// This network's public key, so an `AdminGrant` can be checked against it and
    /// control frames tagged for the peer.
    pub(crate) net_pubkey: EndpointId,
    /// Our own identity, recorded on the roster when we are promoted.
    pub(crate) my_identity: EndpointId,
    /// The shared endpoint, needed to spin up a lazy publisher on promotion.
    pub(crate) endpoint: Endpoint,
    /// The network-owning service. On an `AdminGrant` this reader promotes itself
    /// by calling `registry.promote_to_coordinator` directly (was the `promote_tx`
    /// hand-off to the daemon loop).
    pub(crate) registry: Arc<NetworkRegistry>,
    /// Serializes single-use invite ledger access for the gossip arms.
    pub(crate) invite_lock: Arc<tokio::sync::Mutex<()>>,
    /// Kicks the debounced reconverge worker on a `MemberSync`/`BlobUpdated`
    /// trigger (the roster comes only from the signed pkarr record).
    pub(crate) reconverge_notify: Arc<tokio::sync::Notify>,
}

impl MemberAcceptState {
    /// Dispatch one control frame arriving on a mesh connection this member
    /// participates in. Coordinator broadcasts (`MemberApproved`/`MemberSync`/
    /// `BlobUpdated`/`AdminGrant`) and other members' `MeshHello`s all arrive here.
    /// Returns the peer's mesh v4 when the frame registered it (so the demux can
    /// announce our handle table), else `None`.
    pub(crate) async fn handle_frame(
        &self,
        conn: &Connection,
        send: iroh::endpoint::SendStream,
        peer_id: EndpointId,
        msg: ControlMsg,
    ) -> Option<Ipv4Addr> {
        match msg {
            ControlMsg::MeshHello {
                identity,
                ip,
                hostname,
                device_cert,
            } => {
                self.handle_mesh_hello(conn, send, peer_id, identity, ip, hostname, device_cert)
                    .await
            }
            ControlMsg::MemberApproved {
                identity,
                ip,
                hostname,
                ..
            } => {
                let entry = ApprovedEntry {
                    identity,
                    ip,
                    hostname,
                    user_identity: None,
                    device_cert: None,
                    collision_index: 0,
                };
                let mut s = self.state.write().unwrap();
                let members = s.members.clone();
                let _ = s.approved.approve(entry, &members);
                None
            }
            // Triggers only: the roster/firewall come exclusively from the
            // network-key-signed pkarr record, never from peer-supplied membership.
            // Coalesced into the debounced reconverge worker.
            ControlMsg::MemberSync | ControlMsg::BlobUpdated => {
                self.reconverge_notify.notify_one();
                None
            }
            ControlMsg::AdminGrant {
                network_pubkey,
                secret_key,
            } => {
                self.handle_admin_grant(peer_id, network_pubkey, secret_key)
                    .await;
                None
            }
            ControlMsg::InviteShare {
                id,
                secret_hash,
                expires,
            } => {
                if sender_is_coordinator(&self.state, peer_id)
                    && let Ok(hash) = String::from_utf8(secret_hash)
                {
                    let _guard = self.invite_lock.lock().await;
                    if let Ok(mut store) = crate::invite::InviteStore::load(&self.network_name) {
                        let _ = store.record_shared(id, hash, expires);
                    }
                }
                None
            }
            ControlMsg::InviteUsed { secret_hash } => {
                if sender_is_coordinator(&self.state, peer_id)
                    && let Ok(hash) = String::from_utf8(secret_hash)
                {
                    let _guard = self.invite_lock.lock().await;
                    if let Ok(mut store) = crate::invite::InviteStore::load(&self.network_name) {
                        let _ = store.burn_by_hash(&hash);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Another member (or an approved-but-not-yet-member peer) announced itself
    /// over a connection to us. Verify identity, refresh DNS, and either promote an
    /// approved peer to a member (replying `Welcome`) or register a known member.
    #[allow(clippy::too_many_arguments)]
    async fn handle_mesh_hello(
        &self,
        conn: &Connection,
        send: iroh::endpoint::SendStream,
        transport_id: EndpointId,
        peer_identity: EndpointId,
        ip: Ipv4Addr,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
    ) -> Option<Ipv4Addr> {
        // Verify identity: either the transport key matches, or a valid device
        // cert binds the transport key to the claimed user identity.
        if peer_identity != transport_id {
            match device_cert {
                Some(ref cert)
                    if cert.verify()
                        && cert.device_key == transport_id
                        && cert.user_identity == peer_identity => {}
                _ => {
                    tracing::warn!(peer = %transport_id.fmt_short(), "invalid device certificate");
                    return None;
                }
            }
        }
        if let Some(ref cert) = device_cert {
            self.ctx
                .device_user_map
                .insert(transport_id, cert.user_identity);
        }
        let (is_member, is_approved) = {
            let s = self.state.read().unwrap();
            (
                s.members.is_member(&peer_identity),
                s.approved.is_approved(&peer_identity),
            )
        };
        let final_hostname = if let Some(desired) = hostname {
            let taken = self.state.read().unwrap().taken_hostnames(peer_identity);
            let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
            Some(crate::hostname::resolve_collision(&desired, &taken_refs))
        } else {
            None
        };

        if is_approved {
            return self
                .admit_approved_member(conn, send, peer_identity, ip, final_hostname, device_cert)
                .await;
        }
        if is_member {
            // Register the member at its authoritative roster IP (not the
            // peer-supplied `ip`), so the data reader routes it correctly.
            let member_ip = self
                .state
                .read()
                .unwrap()
                .members
                .get(&peer_identity)
                .map(|m| m.ip)
                .unwrap_or(ip);
            if let Some(h) = &final_hostname {
                {
                    let mut s = self.state.write().unwrap();
                    if let Some(m) = s.members.get_mut(&peer_identity) {
                        m.hostname = Some(h.clone());
                    }
                }
                dns::update_hostname(
                    &self.ctx.hostname_table,
                    &self.ctx.reverse_table,
                    &self.network_name,
                    h,
                    member_ip,
                    derive_ipv6(&peer_identity),
                )
                .await;
            }
            self.ctx
                .register_peer_conn(conn, peer_identity, member_ip, &self.network_name, &self.token);
            return Some(member_ip);
        }
        None
    }

    /// Promote a previously-approved peer to a full member on its `MeshHello`:
    /// seat it with the authoritative IP recorded at approval (not the
    /// peer-supplied one), republish the blob, reply `Welcome`, start its reader,
    /// and trigger a `MemberSync` so the rest of the mesh learns the new roster.
    async fn admit_approved_member(
        &self,
        conn: &Connection,
        mut send: iroh::endpoint::SendStream,
        peer_identity: EndpointId,
        ip: Ipv4Addr,
        final_hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
    ) -> Option<Ipv4Addr> {
        let (snap_bytes, member_ip) = {
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
                last_seen: Some(crate::membership::now_secs()),
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
        if let Some(ref h) = final_hostname {
            dns::update_hostname(
                &self.ctx.hostname_table,
                &self.ctx.reverse_table,
                &self.network_name,
                h,
                member_ip,
                derive_ipv6(&peer_identity),
            )
            .await;
        }
        let (members, approved_list) = {
            let s = self.state.read().unwrap();
            (s.roster(), s.approved_snapshot())
        };
        let _ = control::send_msg(
            &mut send,
            Some(self.net_pubkey),
            &ControlMsg::Welcome {
                members,
                approved: approved_list,
            },
        )
        .await;
        self.ctx
            .register_peer_conn(conn, peer_identity, member_ip, &self.network_name, &self.token);
        broadcast_member_sync(&self.ctx.peers, self.net_pubkey, &self.network_name, Some(member_ip))
            .await;
        Some(member_ip)
    }

    /// A coordinator granted us the per-network key: verify it targets this
    /// network and is self-authenticating, persist it, take publish capability,
    /// and signal the daemon loop to swap in the coordinator accept handler.
    async fn handle_admin_grant(
        &self,
        peer_id: EndpointId,
        network_pubkey: EndpointId,
        secret_key: [u8; 32],
    ) {
        if network_pubkey != self.net_pubkey {
            tracing::warn!(peer = %peer_id.fmt_short(), "admin grant for a different network; ignoring");
            return;
        }
        // Self-authenticating: only adopt a key whose public half equals the
        // network pubkey (defeats a forged AdminGrant from a non-coordinator).
        if !admin_grant_key_valid(secret_key, self.net_pubkey) {
            tracing::warn!(peer = %peer_id.fmt_short(), "admin grant key does not match network pubkey; ignoring");
            return;
        }
        let key = SecretKey::from(secret_key);
        if let Ok(Some(mut net)) = config::load_network(&self.network_name) {
            net.network_secret_key = Some(key.clone());
            let _ = config::save_network(&net);
        }
        {
            let mut s = self.state.write().unwrap();
            s.network_secret_key = Some(key.clone());
            if let Some(m) = s.members.get_mut(&self.my_identity) {
                m.is_coordinator = true;
            }
            s.refresh_snapshot();
        }
        if let Ok(client) = dht::create_pkarr_client(&self.endpoint) {
            spawn_lazy_publisher(
                client,
                key,
                self.state.clone(),
                self.endpoint.id(),
                self.ctx.peers.clone(),
                self.network_name.clone(),
                self.token.clone(),
            );
            tracing::info!(network = %self.network_name, "promoted to co-coordinator; lazy publisher started");
        }
        // Swap ourselves to a coordinator accept handler directly (was a
        // `promote_tx` hand-off to the daemon loop). The registry owns the
        // ConnectionManager + networks map; we supply our own daemon-wide ctx.
        self.registry
            .promote_to_coordinator(&self.ctx, &self.network_name);
    }
}

#[derive(Clone)]
pub(crate) enum AcceptHandler {
    Coordinator(Arc<CoordinatorAcceptState>),
    Member(Arc<MemberAcceptState>),
}

impl AcceptHandler {
    #[cfg(test)]
    pub(crate) fn is_coordinator(&self) -> bool {
        matches!(self, AcceptHandler::Coordinator(_))
    }

    /// The local name of the network this handler serves. Used by the demux to map
    /// a peer's announced network pubkey back to our local decode-table name.
    pub(crate) fn network_name(&self) -> Option<String> {
        match self {
            AcceptHandler::Coordinator(s) => Some(s.network_name.clone()),
            AcceptHandler::Member(s) => Some(s.network_name.clone()),
        }
    }

    /// Process one network-scoped control frame, returning the peer's mesh v4 if it
    /// is now a registered member on this network (else `None`).
    pub(crate) async fn handle_frame(
        &self,
        conn: &Connection,
        send: iroh::endpoint::SendStream,
        peer_id: EndpointId,
        msg: ControlMsg,
    ) -> Option<Ipv4Addr> {
        match self {
            AcceptHandler::Coordinator(s) => s.handle_frame(conn, send, peer_id, msg).await,
            AcceptHandler::Member(s) => s.handle_frame(conn, send, peer_id, msg).await,
        }
    }
}

pub(crate) struct ProtocolRouter {
    blobs: BlobsProtocol,
    /// File-transfer + pairing state and their ALPN accept arms. The accept loop
    /// delegates the `FILES_ALPN`/`PAIR_ALPN` arms to this; `MeshManager` holds
    /// the same handle for the IPC-side file/pairing commands.
    files: Arc<FileService>,
    /// `ray connect` state (pending/approved/outgoing maps) and the `CONNECT_ALPN`
    /// accept arm. The accept loop delegates to this; `MeshManager` holds the same
    /// handle for the IPC-side connect commands.
    connect: Arc<ConnectService>,
    /// The per-peer mesh connection driver: owns the per-network handler registry,
    /// the frame demux, and the ping-probe map. The mesh ALPN is delegated here;
    /// register/handler_for/`pending_pongs` calls pass through to it.
    conn: Arc<ConnectionManager>,
}

impl ProtocolRouter {
    pub(crate) fn new(
        blobs: BlobsProtocol,
        files: Arc<FileService>,
        connect: Arc<ConnectService>,
        conn: Arc<ConnectionManager>,
    ) -> Self {
        Self {
            blobs,
            files,
            connect,
            conn,
        }
    }

    /// Install the daemon-wide mesh dispatch context on the connection driver.
    pub(crate) fn set_mesh_dispatch(&self, dispatch: MeshDispatch) {
        self.conn.set_mesh_dispatch(dispatch);
    }

    /// Register a network's accept handler under its public key. Passthrough to
    /// the connection driver, which owns the handler registry.
    pub(crate) fn register(&self, net_pubkey: EndpointId, handler: AcceptHandler) {
        self.conn.register(net_pubkey, handler);
    }

    /// Whether a handler is registered for this network public key.
    pub(crate) fn is_registered(&self, net_pubkey: &EndpointId) -> bool {
        self.conn.is_registered(net_pubkey)
    }

    /// In-flight `ray ping` probe map (nonce → oneshot), owned by the driver.
    pub(crate) fn pending_pongs(&self) -> &Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>> {
        &self.conn.pending_pongs
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

    /// Drive one mesh connection for its whole lifetime. Passthrough to the
    /// connection manager, which owns the driver, demux, and handler registry.
    /// Used by the accept loop (above) and the dial side
    /// (`MeshManager::drive_dialed_connection`).
    pub(crate) async fn drive_mesh_connection(self: Arc<Self>, conn: Connection) {
        self.conn.clone().drive_mesh_connection(conn).await;
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
        let cert = control::DeviceCert::create(&owner, &device, 0);

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
