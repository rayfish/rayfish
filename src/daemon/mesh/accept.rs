//! Connection-accept machinery for the mesh core. Moved out of `daemon/mod.rs`.
//!
//! Holds the per-network accept handlers (`CoordinatorAcceptState` admits or
//! queues joiners; `MemberAcceptState` welcomes approved members), the
//! `AcceptHandler` enum the router dispatches through, and the `ProtocolRouter`
//! that fans incoming connections out by ALPN (mesh handlers plus the
//! `blobs`/`files`/`pair`/`connect` arms). `MeshCtx` and the roster-projection
//! helpers stay in `daemon/mod.rs` since they are shared infrastructure.

use crate::daemon;

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

/// Whether a signed record authored at `record_ts` may replace what we hold,
/// given the timestamp of the last record applied (`floor`).
///
/// Strictly greater, because equal timestamps with different contents are two
/// records we have no ordering for, and keeping ours costs at most one republish
/// interval while taking theirs costs whatever the older one said. `None` accepts
/// anything: we have applied nothing yet, so there is no rollback to prevent.
pub(crate) fn record_is_newer(record_ts: u64, floor: Option<u64>) -> bool {
    match floor {
        Some(seen) => record_ts > seen,
        None => true,
    }
}

/// Whether a peer this network's roster does not account for may send `msg`.
///
/// A control frame reaches a per-network handler on the strength of the network
/// public key in its envelope, and that key is a discovery key: it is in every
/// invite code and it *is* the pkarr address, so anyone can name it. Without this
/// list, "knows the room id" and "is in the room" were the same thing as far as
/// the handlers were concerned, and the messages meant for members were reachable
/// by anyone who had ever seen an invite.
///
/// Three messages have to survive the filter, because each one is how a peer that
/// is legitimately not on our roster yet talks to us:
///
/// - `JoinRequest` is the whole point of a stranger dialing us.
/// - `MeshHello` is a joiner announcing itself to the rest of the roster right
///   after admission (`connect_to_roster_peers`), which reaches members that have
///   not reconverged yet, and is also an older client's no-invite join.
/// - `SignedRecord` carries a network-key-signed packet that is verified against
///   the network key before anything is applied, so it needs no sender authority
///   at all. It is also precisely the message that repairs a roster too stale to
///   recognize its own coordinator, so gating it on that roster would be circular.
///
/// Everything else is either a coordinator's word (checked again in the arm), a
/// member's statement about itself, or a trigger whose cost is a DHT resolve and
/// a blob fetch. None of those are things to do on a stranger's say-so.
/// Written as a full match with no `_` arm on purpose: a new `ControlMsg` variant
/// then fails to compile until someone decides which side of the wall it belongs
/// on, which is the same reason the settings enums are matched exhaustively.
pub(crate) fn stranger_may_send(msg: &ControlMsg) -> bool {
    match msg {
        ControlMsg::JoinRequest { .. }
        | ControlMsg::MeshHello { .. }
        | ControlMsg::SignedRecord { .. } => true,

        // Coordinator authority. Each is checked again in its own arm.
        ControlMsg::MemberApproved { .. }
        | ControlMsg::AdminGrant { .. }
        | ControlMsg::InviteShare { .. }
        | ControlMsg::InviteUsed { .. }
        | ControlMsg::KickedFromNetwork
        | ControlMsg::Welcome { .. }
        | ControlMsg::JoinApproved { .. }
        | ControlMsg::JoinPending
        | ControlMsg::JoinDenied { .. } => false,

        // Cheap to send, a DHT resolve plus a blob fetch to honor.
        ControlMsg::MemberSync | ControlMsg::BlobUpdated => false,

        // A member's statements about itself, and its departure.
        ControlMsg::ExitNodeOffer { .. }
        | ControlMsg::Ipv6Only { .. }
        | ControlMsg::LeaveNetwork => false,

        // Connection-level: the demux handles these before it ever resolves a
        // per-network handler, so they never reach this decision. Listed rather
        // than caught by a wildcard so the exhaustiveness holds.
        ControlMsg::NetworkHandles { .. }
        | ControlMsg::Ping { .. }
        | ControlMsg::Pong { .. }
        | ControlMsg::Unpaired
        | ControlMsg::CertRefresh { .. }
        | ControlMsg::RequestUnpair
        | ControlMsg::NotSupported { .. }
        | ControlMsg::FileOffer { .. } => false,
    }
}

/// Whether admitting `joiner` onto this network should also hand it the network
/// secret key (co-coordinator), the `ray connect` direct-link grant.
///
/// A direct link is symmetric, so its one intended peer coordinates it too. The
/// grant therefore follows the *peer* recorded when the link was minted, not the
/// network's `direct` flag, which any later `ray requests accept` would ride
/// into a key it was never offered.
///
/// `direct_peer` is `None` on links minted before it was recorded, so those fall
/// back to the old rule but only while we are still the sole member: that is the
/// state a direct network sits in until its one peer arrives, and it keeps an
/// in-flight `ray connect` from an older build working, while still refusing a
/// third peer on an already-formed link.
pub(crate) fn grants_direct_key(
    net: &config::NetworkConfig,
    joiner: EndpointId,
    state: &SharedNetworkState,
) -> bool {
    if !net.direct {
        return false;
    }
    match net.direct_peer {
        Some(peer) => peer == joiner,
        None => state.read().unwrap().members.all().len() <= 1,
    }
}

/// What a `MeshHello`'s identity claim earns its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelloIdentity {
    /// Accept the hello. `Some(user)` is a device→user binding good enough to
    /// record in the `device_user_map`; `None` means the peer speaks only for
    /// its own transport key.
    Accept(Option<EndpointId>),
    /// Refuse the frame: the cert does not hold up, or it does not back the
    /// identity the sender claimed.
    Reject,
}

/// Decide what a `MeshHello` proved about who is sending it.
///
/// The `device_user_map` this feeds is daemon-wide and is what the inbound
/// firewall (`forward::evaluate_inbound`), mesh SSH (`ssh::resolve_user_policy`),
/// own-device file auto-accept, and member-leave pruning all authorize on. So a
/// cert only ever earns a binding here after its signature is checked and after
/// it is confirmed to name *this* transport key: a peer that presents a cert it
/// did not receive must not inherit the rights of the identity that signed it.
///
/// The two rules are independent, which is what the earlier version of this code
/// missed. Verifying the cert is not conditional on the sender claiming a
/// *different* identity: a sender claiming its own transport key still hands us a
/// `user_identity` we would otherwise store on its word alone.
///
/// A nullified device (`ray unpair`) keeps its valid signature forever, so the
/// revocation has to be applied here too: its binding is dropped, and a claim
/// that rests on it is refused outright. `revoked` is asked across every network
/// this node runs, because the binding it guards is daemon-wide.
pub(crate) fn check_hello_identity(
    transport_id: EndpointId,
    peer_identity: EndpointId,
    cert: Option<&control::DeviceCert>,
    revoked: bool,
) -> HelloIdentity {
    let binding = match cert {
        // A presented cert must verify and must bind the key that actually
        // dialed us. Anything else is a forgery attempt, not a peer without a
        // cert, so refuse the frame rather than quietly continuing without it.
        Some(c) if !c.verify() || c.device_key != transport_id => return HelloIdentity::Reject,
        // Verified, but revoked: worth nothing.
        Some(_) if revoked => None,
        Some(c) => Some(c.user_identity),
        None => None,
    };
    if peer_identity != transport_id && binding != Some(peer_identity) {
        // Claiming to be someone else takes a live binding that names them.
        return HelloIdentity::Reject;
    }
    HelloIdentity::Accept(binding)
}

pub(crate) struct CoordinatorAcceptState {
    pub(crate) ctx: MeshCtx,
    pub(crate) network_name: String,
    pub(crate) state: SharedNetworkState,
    pub(crate) dht_notify: Option<Arc<tokio::sync::Notify>>,
    /// Shared with this network's [`NetworkHandle`]; see its `invite_lock`.
    pub(crate) invite_lock: Arc<AsyncMutex<()>>,
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
            // A member left this one network in-band (`ray leave`). Prune it here
            // (roster + republish) without disturbing the networks it still shares
            // with us over the same connection.
            ControlMsg::LeaveNetwork => {
                self.ctx
                    .registry
                    .handle_member_leave(&self.network_name, peer_id)
                    .await;
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
                let _ =
                    control::send_msg(&mut send, Some(self.net_pubkey()), &ControlMsg::JoinPending)
                        .await;
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
        let peer_ip = self
            .state
            .read()
            .unwrap()
            .members
            .get(&remote_id)
            .map(|m| m.ip)?;
        crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
        self.ctx
            .register_peer_conn(conn, remote_id, peer_ip, &self.network_name);

        // Hand this (re)connecting member our current signed record over the mesh
        // so it converges to the live roster in ~1s instead of waiting out a stale
        // DHT lookup plus the group poll. Only a coordinator holds the network
        // key, so only we can originate it; the member verifies the record against
        // the network key before applying (see `MemberAcceptState::handle_frame`).
        if let Some(record) = self.ctx.registry.current_signed_record(&self.network_name) {
            let msg = ControlMsg::SignedRecord { packet: record };
            if let Err(e) = open_and_send(conn, Some(self.net_pubkey()), &msg).await {
                tracing::debug!(peer = %remote_id.fmt_short(), error = %e, "failed to hand signed record to reconnecting member");
            }
        }

        // Verify and store device cert if present, unless the device key is
        // nullified on this network (`ray unpair`): a nullified cert is not
        // recorded as a paired device, so it stops resolving to the user's
        // identity.
        if let Some(ref cert) = device_cert
            && cert.verify()
            && cert.device_key == remote_id
            && !self
                .state
                .read()
                .unwrap()
                .nullifiers
                .contains(&cert.device_key)
        {
            {
                let mut s = self.state.write().unwrap();
                if let Some(m) = s.members.get_mut(&remote_id) {
                    m.user_identity = Some(cert.user_identity);
                    m.device_cert = Some(cert.clone());
                }
            }
            self.ctx
                .device_user_map
                .insert(remote_id, cert.user_identity);
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
            Some(peer_ip),
            derive_ipv6(&remote_id),
        )
        .await;

        if changed {
            tracing::info!(peer = %remote_id.fmt_short(), network = %self.network_name, hostname = %final_hostname, "peer hostname changed; republishing blob + broadcasting MemberSync");
            update_snapshot_and_publish(&self.state, &self.ctx.blob_store, &self.dht_notify).await;
            broadcast_member_sync(
                &self.ctx.registry,
                self.net_pubkey(),
                &self.network_name,
                None,
            )
            .await;
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
                    .admit_peer(
                        conn,
                        send,
                        remote_id,
                        assigned,
                        device_cert,
                        false,
                        authoritative,
                    )
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
        let _ = control::send_msg(
            &mut send,
            Some(self.net_pubkey()),
            &ControlMsg::JoinDenied { reason },
        )
        .await;
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
        //
        // Pinned to the peer the link was minted for (`direct_peer`), not to the
        // network's `direct` flag: the flag says the *network* is a direct link,
        // so on its own it handed the network key to anyone ever approved here,
        // and a later `ray requests accept` on that network would give the key
        // away without saying so.
        let grant_direct = was_approved
            && config::load_network(&self.network_name)
                .ok()
                .flatten()
                .is_some_and(|n| grants_direct_key(&n, remote_id, &self.state));

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
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
                ipv6_only: false,
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
                Some(peer_ip),
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

        // A direct (`ray connect`) link is symmetric, so the pre-approved requester
        // is made a co-coordinator. Hand it the network key inside the Welcome it is
        // already reading on the join stream (deterministic, no separate best-effort
        // stream that could be dropped or race its handler setup).
        let (members, approved, direct_key) = {
            let s = self.state.read().unwrap();
            let direct_key = grant_direct
                .then(|| s.network_secret_key.as_ref().map(|k| k.to_bytes()))
                .flatten();
            (s.roster(), s.approved_snapshot(), direct_key)
        };

        tracing::info!(ip = %peer_ip, "new member admitted and joined");
        let _ = control::send_msg(
            &mut send,
            Some(net_pubkey),
            &ControlMsg::Welcome {
                members: members.clone(),
                approved,
                direct_key,
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
            .register_peer_conn(conn, remote_id, peer_ip, &self.network_name);

        broadcast_member_sync(
            &self.ctx.registry,
            net_pubkey,
            &self.network_name,
            Some(peer_ip),
        )
        .await;

        // The key rode the Welcome above (see `direct_key`). Record the grant
        // locally (mirrors `admin_add`) so our own `ray admin list` shows the peer
        // as a co-coordinator too.
        if grant_direct
            && let Ok(Some(mut net)) = config::load_network(&self.network_name)
            && !net.admins.contains(&remote_id)
        {
            net.admins.push(remote_id);
            let _ = config::save_network(&net);
        }
        Some(peer_ip)
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
    pub(crate) invite_lock: Arc<AsyncMutex<()>>,
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
            // Only a coordinator admits, so only a coordinator may say who was
            // admitted. Without this check the message was an unauthenticated
            // write into our approved list, and an entry there is not inert: the
            // sender's next `MeshHello` takes the `is_approved` branch below
            // straight into `admit_approved_member`, which seats it as a member
            // at the IP *this message* chose, writes its `.ray` name, and
            // registers its route. Same gate as `InviteShare`/`KickedFromNetwork`.
            ControlMsg::MemberApproved {
                identity,
                ip,
                hostname,
                ..
            } => {
                if !sender_is_coordinator(&self.state, peer_id) {
                    tracing::warn!(peer = %peer_id.fmt_short(), "ignoring MemberApproved from non-coordinator");
                    return None;
                }
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
            // A coordinator handed us its current signed record over the mesh (fast
            // path on (re)connect). Verify it against the network key and apply it
            // directly, bypassing a possibly-stale DHT lookup. Still the same trust
            // model: the record is network-key-signed and verified here, the peer is
            // only its transport.
            ControlMsg::SignedRecord { packet } => {
                self.apply_signed_record(&packet).await;
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
            // Our coordinator says we have been removed from this network (`ray
            // kick`). Act only on a kick from a coordinator (a stranger is ignored),
            // and treat it as a trigger, not authority: confirm against the signed
            // record and leave only if it no longer lists us. Off the demux loop:
            // the confirm (a DHT resolve + blob fetch) and the leave are slow, and
            // leaving tears down this very handler's network.
            ControlMsg::KickedFromNetwork => {
                if sender_is_coordinator(&self.state, peer_id) {
                    let registry = self.registry.clone();
                    let network = self.network_name.clone();
                    tokio::spawn(async move {
                        registry.confirm_kick_and_leave(&network).await;
                    });
                }
                None
            }
            _ => None,
        }
    }

    /// Apply a signed network record a coordinator handed us over the mesh (the
    /// `SignedRecord` fast path). Verify it against this network's key, check it is
    /// newer than the last record we applied, and if it names a different blob,
    /// fetch + apply it directly. This bypasses a fresh DHT resolve (which can
    /// serve a stale record for ~60-90s right after a restart), so a reconnecting
    /// member converges to the live roster in ~1s. The trust model is unchanged:
    /// the record is network-key-signed and verified here, exactly like the DHT
    /// copy; the peer is only its transport.
    ///
    /// This message is deliberately exempt from the demux's roster wall (see
    /// `stranger_may_send`), which is exactly why the freshness check belongs
    /// here: a signature says who wrote a record, not when, so without it anyone
    /// holding the room id could hand us a record the DHT served publicly last
    /// week and roll the roster back to it.
    async fn apply_signed_record(&self, packet_bytes: &[u8]) {
        let packet = match dht::verify_network_record(packet_bytes, self.net_pubkey) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "rejecting signed record handed over the mesh");
                return;
            }
        };
        let (remote_hash, seed_peers) = match dht::decode_network_record(&packet) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "undecodable signed record handed over the mesh");
                return;
            }
        };
        let record_ts = packet.timestamp().as_micros();
        let (current_hash, floor, needs) = {
            let s = self.state.read().unwrap();
            (
                s.converged_hash,
                s.last_record_timestamp,
                s.needs_reconverge(remote_hash),
            )
        };
        if !needs {
            return;
        }
        if !record_is_newer(record_ts, floor) {
            tracing::warn!(
                record_ts,
                floor,
                "rejecting a signed record older than the last one applied (replay)"
            );
            return;
        }
        tracing::info!(old = ?current_hash, new = %remote_hash, "applying signed record handed by coordinator");
        self.state.write().unwrap().last_record_timestamp = Some(record_ts);
        fetch_and_apply_blob(
            &self.endpoint,
            &self.ctx.blob_store,
            &self.ctx.peers,
            &self.ctx.firewall,
            &self.registry,
            &self.state,
            &self.network_name,
            remote_hash,
            &seed_peers,
        )
        .await;
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
        // Verify the cert and the identity claim together, before anything is
        // recorded. See `check_hello_identity`: the binding this stores is what
        // the firewall and mesh SSH later authorize on, so it is never taken on
        // the sender's word.
        // Nullifiers from every network, not just this one: the binding this
        // writes is daemon-wide, so a device revoked anywhere must not re-earn it
        // by saying hello on a network that has not heard about the revocation.
        let revoked = device_cert
            .as_ref()
            .is_some_and(|c| self.registry.is_nullified_anywhere(&c.device_key));
        let binding = match check_hello_identity(
            transport_id,
            peer_identity,
            device_cert.as_ref(),
            revoked,
        ) {
            HelloIdentity::Accept(binding) => binding,
            HelloIdentity::Reject => {
                tracing::warn!(peer = %transport_id.fmt_short(), "invalid device certificate");
                return None;
            }
        };
        if let Some(user_identity) = binding {
            self.ctx.device_user_map.insert(transport_id, user_identity);
        }
        // A cert that earned no binding (revoked on this network) is not written
        // to the roster either, matching the coordinator's `handle_member_hello`.
        let device_cert = binding.and(device_cert);
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
                    Some(member_ip),
                    derive_ipv6(&peer_identity),
                )
                .await;
            }
            self.ctx
                .register_peer_conn(conn, peer_identity, member_ip, &self.network_name);
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
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
                ipv6_only: false,
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
                Some(member_ip),
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
                // Reconnect path: a returning co-coordinator already holds the key
                // (persisted in its config); only fresh direct admissions grant it.
                direct_key: None,
            },
        )
        .await;
        self.ctx
            .register_peer_conn(conn, peer_identity, member_ip, &self.network_name);
        broadcast_member_sync(
            &self.ctx.registry,
            self.net_pubkey,
            &self.network_name,
            Some(member_ip),
        )
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

    /// Whether this network's roster accounts for `peer_id` at all: a seated
    /// member, or a peer approved and not yet seated.
    ///
    /// Checked against both the transport key and the user identity it resolves
    /// to. Admission seats a member under the key that dialed (`admit_peer`), so
    /// the resolved lookup is normally redundant; it is defense in depth for the
    /// roster shapes that do key a member by user identity, and it costs one map
    /// read.
    pub(crate) fn knows_sender(&self, peer_id: EndpointId) -> bool {
        let (state, ctx) = match self {
            AcceptHandler::Coordinator(s) => (&s.state, &s.ctx),
            AcceptHandler::Member(s) => (&s.state, &s.ctx),
        };
        let user_id = ctx.device_user_map.resolve(&peer_id);
        let s = state.read().unwrap();
        [peer_id, user_id]
            .iter()
            .any(|id| s.members.is_member(id) || s.approved.is_approved(id))
    }

    /// The local name of the network this handler serves. Used by the demux to map
    /// a peer's announced network pubkey back to our local decode-table name.
    pub(crate) fn network_name(&self) -> Option<String> {
        match self {
            AcceptHandler::Coordinator(s) => Some(s.network_name.clone()),
            AcceptHandler::Member(s) => Some(s.network_name.clone()),
        }
    }

    fn registry(&self) -> &Arc<NetworkRegistry> {
        match self {
            AcceptHandler::Coordinator(s) => &s.ctx.registry,
            AcceptHandler::Member(s) => &s.ctx.registry,
        }
    }

    /// Network-scoped messages both roles handle identically, dispatched here so
    /// an arm cannot sit in one role's match and be silently discarded by the
    /// other's catch-all (`ExitNodeOffer` once lived only in the Member dispatch,
    /// so a plain coordinator, the one node that records the offer on the signed
    /// roster, dropped it). Returns true if the message was consumed.
    pub(crate) fn handle_common(&self, peer_id: EndpointId, msg: &ControlMsg) -> bool {
        match *msg {
            // A member tells us it does (or no longer does) offer itself as an
            // exit node. Only a network-key holder records it on the sender's
            // roster entry and republishes (`record_exit_offer` no-ops
            // otherwise). Off the demux loop: signing + DHT publish are slow.
            ControlMsg::ExitNodeOffer {
                enabled,
                exit_families,
            } => {
                let registry = self.registry().clone();
                let Some(network) = self.network_name() else {
                    return true;
                };
                tokio::spawn(async move {
                    registry
                        .record_exit_offer(&network, peer_id, enabled, exit_families)
                        .await;
                });
                true
            }
            // Same shape for a member telling us its data plane is IPv6-only, so
            // its mesh IPv4 must not be handed out in DNS answers.
            ControlMsg::Ipv6Only { enabled } => {
                let registry = self.registry().clone();
                let Some(network) = self.network_name() else {
                    return true;
                };
                tokio::spawn(async move {
                    registry.record_ipv6_only(&network, peer_id, enabled).await;
                });
                true
            }
            _ => false,
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
        if self.handle_common(peer_id, &msg) {
            return None;
        }
        match self {
            AcceptHandler::Coordinator(s) => s.handle_frame(conn, send, peer_id, msg).await,
            AcceptHandler::Member(s) => s.handle_frame(conn, send, peer_id, msg).await,
        }
    }
}

/// iroh [`ProtocolHandler`](iroh::protocol::ProtocolHandler) adapters: one per
/// ALPN, each handing an accepted connection to the owning service. The iroh
/// `Router` dispatches by ALPN and runs each `accept` on its own task, which
/// replaces the hand-rolled accept loop + `match alpn`. Blobs ships its own
/// handler (`BlobsProtocol`), so it needs no adapter. `FileService` backs *two*
/// ALPNs (files + pair), hence two adapters over the same service. Each service
/// method handles its own errors (logs, closes the connection), so `accept`
/// always reports `Ok`.
#[derive(Clone)]
struct MeshProtocol(Arc<ConnectionManager>);

#[derive(Clone)]
struct FilesProtocol(Arc<FileService>);

#[derive(Clone)]
struct PairProtocol(Arc<FileService>);

#[derive(Clone)]
struct ConnectProtocol(Arc<ConnectService>);

impl std::fmt::Debug for MeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MeshProtocol")
    }
}

impl std::fmt::Debug for FilesProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FilesProtocol")
    }
}

impl std::fmt::Debug for PairProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairProtocol")
    }
}

impl std::fmt::Debug for ConnectProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectProtocol")
    }
}

impl iroh::protocol::ProtocolHandler for MeshProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        self.0.clone().drive_mesh_connection(conn, false).await;
        Ok(())
    }
}
impl iroh::protocol::ProtocolHandler for FilesProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        self.0.accept_file_offer(conn).await;
        Ok(())
    }
}

impl iroh::protocol::ProtocolHandler for PairProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        self.0.accept_pair_request(conn).await;
        Ok(())
    }
}

impl iroh::protocol::ProtocolHandler for ConnectProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        self.0.accept_connect_request(conn).await;
        Ok(())
    }
}

pub(crate) struct ProtocolRouter {
    blobs: BlobsProtocol,
    /// File-transfer + pairing state and their ALPN accept arms. The accept loop
    /// delegates the `FILES_ALPN`/`PAIR_ALPN` arms to this; `Daemon` holds
    /// the same handle for the IPC-side file/pairing commands.
    files: Arc<FileService>,
    /// `ray connect` state (pending/approved/outgoing maps) and the `CONNECT_ALPN`
    /// accept arm. The accept loop delegates to this; `Daemon` holds the same
    /// handle for the IPC-side connect commands.
    connect: Arc<ConnectService>,
    /// The per-peer mesh connection driver: owns the per-network handler registry,
    /// the frame demux, and the ping-probe map. The mesh ALPN is delegated here;
    /// register/handler_for/`pending_pongs` calls pass through to it.
    conn_mngr: Arc<ConnectionManager>,
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
            conn_mngr: conn,
        }
    }

    /// Install the daemon-wide mesh dispatch context on the connection driver.
    pub(crate) fn set_mesh_dispatch(&self, dispatch: MeshDispatch) {
        self.conn_mngr.set_mesh_dispatch(dispatch);
    }

    /// Register a network's accept handler under its public key. Passthrough to
    /// the connection driver, which owns the handler registry.
    pub(crate) fn register(&self, net_pubkey: EndpointId, handler: AcceptHandler) {
        self.conn_mngr.register(net_pubkey, handler);
    }

    /// Whether a handler is registered for this network public key.
    pub(crate) fn is_registered(&self, net_pubkey: &EndpointId) -> bool {
        self.conn_mngr.is_registered(net_pubkey)
    }

    /// In-flight `ray ping` probe map (nonce → oneshot), owned by the driver.
    pub(crate) fn pending_pongs(&self) -> &Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>> {
        &self.conn_mngr.pending_pongs
    }

    /// Build and spawn the iroh protocol [`Router`](iroh::protocol::Router) for
    /// this endpoint. It owns the accept loop and dispatches each inbound
    /// connection by its negotiated ALPN to the matching handler (blobs, files,
    /// pair, connect, mesh), running each on its own task. Replaces the
    /// hand-rolled accept loop. The returned `Router` aborts when dropped, so the
    /// caller must keep it alive (stashed on `Daemon`) and `shutdown()` it on exit.
    pub(crate) fn build_router(&self, endpoint: Endpoint) -> iroh::protocol::Router {
        iroh::protocol::Router::builder(endpoint)
            .accept(iroh_blobs::protocol::ALPN, self.blobs.clone())
            .accept(transport::FILES_ALPN, FilesProtocol(self.files.clone()))
            .accept(daemon::PAIR_ALPN, PairProtocol(self.files.clone()))
            .accept(
                transport::CONNECT_ALPN,
                ConnectProtocol(self.connect.clone()),
            )
            .accept(transport::mesh_alpn(), MeshProtocol(self.conn_mngr.clone()))
            .spawn()
    }

    /// Drive one mesh connection for its whole lifetime. Passthrough to the
    /// connection manager, which owns the driver, demux, and handler registry.
    /// Used by the accept loop (above, `pre_registered = false`) and the dial side
    /// (`pre_registered = true`).
    pub(crate) async fn drive_mesh_connection(
        self: Arc<Self>,
        conn: Connection,
        pre_registered: bool,
    ) {
        self.conn_mngr
            .clone()
            .drive_mesh_connection(conn, pre_registered)
            .await;
    }
}

#[cfg(test)]
mod record_freshness_tests {
    use super::*;

    /// Nothing applied yet, so there is no rollback to refuse.
    #[test]
    fn any_record_passes_an_empty_floor() {
        assert!(record_is_newer(1, None));
        assert!(record_is_newer(0, None));
    }

    /// The replay this guards. A signature says who authored a record, never
    /// when, so an old record for this network stays valid forever and its hash
    /// differs from the current one, which is all the previous check compared. It
    /// would re-seat kicked members, restore devices the blob nullified, and
    /// revert the suggested firewall.
    #[test]
    fn an_older_record_is_refused() {
        assert!(!record_is_newer(500, Some(1_000)));
    }

    /// Equal timestamps with different contents give no ordering, so we keep
    /// what we have and wait for the next republish rather than guess.
    #[test]
    fn an_equal_timestamp_is_refused() {
        assert!(!record_is_newer(1_000, Some(1_000)));
    }

    #[test]
    fn a_newer_record_is_taken() {
        assert!(record_is_newer(1_001, Some(1_000)));
    }
}

#[cfg(test)]
mod stranger_policy_tests {
    use super::*;
    use iroh::SecretKey;

    fn eid(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        SecretKey::from(b).public()
    }

    /// The three ways a peer our roster does not list may legitimately speak.
    #[test]
    fn only_the_pre_membership_messages_pass() {
        for msg in [
            ControlMsg::JoinRequest {
                invite_secret: None,
                hostname: None,
                device_cert: None,
            },
            ControlMsg::MeshHello {
                identity: eid(1),
                ip: Ipv4Addr::new(100, 64, 0, 2),
                hostname: None,
                device_cert: None,
            },
            ControlMsg::SignedRecord { packet: vec![] },
        ] {
            assert!(stranger_may_send(&msg), "{msg:?} must reach a coordinator");
        }
    }

    /// Everything a member says, a stranger may not. Listed one by one rather
    /// than by negation so that adding a `ControlMsg` variant is a decision made
    /// here, not a default inherited silently.
    #[test]
    fn member_messages_are_refused_from_a_stranger() {
        for msg in [
            // Coordinator authority.
            ControlMsg::MemberApproved {
                identity: eid(1),
                ip: Ipv4Addr::new(100, 64, 0, 2),
                hostname: None,
                device_cert: None,
            },
            ControlMsg::AdminGrant {
                network_pubkey: eid(1),
                secret_key: [0u8; 32],
            },
            ControlMsg::InviteShare {
                id: "ab".into(),
                secret_hash: vec![],
                expires: 0,
            },
            ControlMsg::InviteUsed {
                secret_hash: vec![],
            },
            ControlMsg::KickedFromNetwork,
            // Triggers: cheap to send, a DHT resolve plus a blob fetch to honor.
            ControlMsg::MemberSync,
            ControlMsg::BlobUpdated,
            // A member's statements about itself, and its departure.
            ControlMsg::ExitNodeOffer {
                enabled: true,
                exit_families: ExitFamilies::Dual,
            },
            ControlMsg::Ipv6Only { enabled: true },
            ControlMsg::LeaveNetwork,
        ] {
            assert!(!stranger_may_send(&msg), "{msg:?} must need membership");
        }
    }
}

#[cfg(test)]
mod direct_grant_tests {
    use super::*;
    use iroh::SecretKey;

    fn eid(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        SecretKey::from(b).public()
    }

    fn state_with_members(ids: &[EndpointId]) -> SharedNetworkState {
        let mut list = MemberList::new();
        for (i, id) in ids.iter().enumerate() {
            list.add(Member {
                identity: *id,
                ip: Ipv4Addr::new(100, 64, 0, (i + 2) as u8),
                is_coordinator: i == 0,
                hostname: None,
                user_identity: None,
                device_cert: None,
                collision_index: 0,
                last_seen: None,
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
                ipv6_only: false,
            })
            .unwrap();
        }
        Arc::new(RwLock::new(NetworkState {
            members: list,
            approved: ApprovedList::new(),
            snapshot: None,
            converged_hash: None,
            network_secret_key: None,
            network_public_key: eid(200),
            network_name: Some("dario-alex".to_string()),
            mode: GroupMode::Restricted,
            suggested_firewall: SuggestedFirewall::default(),
            reusable_keys: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
            last_record_timestamp: None,
        }))
    }

    fn direct_net(peer: Option<EndpointId>) -> config::NetworkConfig {
        let mut net = config::empty_network_config("dario-alex");
        net.direct = true;
        net.direct_peer = peer;
        net
    }

    /// The peer the link was minted for gets the network key: that is the whole
    /// point of a direct link being symmetric.
    #[test]
    fn the_minted_for_peer_is_granted() {
        let (me, peer) = (eid(1), eid(2));
        let state = state_with_members(&[me]);
        assert!(grants_direct_key(&direct_net(Some(peer)), peer, &state));
    }

    /// The regression. A direct network approving a *second* peer later (via
    /// `ray requests accept`) used to hand it the network key too, because the
    /// grant keyed on the network being `direct` rather than on who the link was
    /// for. Nothing tells the user they just made a stranger a co-coordinator.
    #[test]
    fn a_later_approved_peer_is_not_granted() {
        let (me, peer, third) = (eid(1), eid(2), eid(3));
        let state = state_with_members(&[me, peer]);
        assert!(!grants_direct_key(&direct_net(Some(peer)), third, &state));
    }

    /// An ordinary mesh never grants, approved or not.
    #[test]
    fn a_normal_network_never_grants() {
        let (me, peer) = (eid(1), eid(2));
        let state = state_with_members(&[me]);
        let mut net = direct_net(Some(peer));
        net.direct = false;
        assert!(!grants_direct_key(&net, peer, &state));
    }

    /// Links minted before `direct_peer` was recorded keep working while we are
    /// still alone on them, which is the state they sit in until their one peer
    /// arrives.
    #[test]
    fn legacy_link_grants_only_while_unformed() {
        let (me, peer, third) = (eid(1), eid(2), eid(3));
        let alone = state_with_members(&[me]);
        assert!(grants_direct_key(&direct_net(None), peer, &alone));
        // Once the link has both ends, a third peer gets nothing.
        let formed = state_with_members(&[me, peer]);
        assert!(!grants_direct_key(&direct_net(None), third, &formed));
    }
}

#[cfg(test)]
mod hello_identity_tests {
    use super::*;
    use iroh::SecretKey;

    fn key(seed: u8) -> SecretKey {
        let mut b = [0u8; 32];
        b[0] = seed;
        SecretKey::from(b)
    }

    /// The regression this whole helper exists for. A peer claiming its own
    /// transport key used to skip cert verification entirely, and the very next
    /// line recorded the cert's `user_identity` in the daemon-wide
    /// `device_user_map`. That map is what the inbound firewall and mesh SSH
    /// authorize on, so an unsigned cert naming a victim handed the sender the
    /// victim's rules on this node. An unverifiable cert must buy nothing.
    #[test]
    fn unsigned_cert_claiming_own_key_is_refused() {
        let attacker = key(1).public();
        let victim = key(2).public();
        // Signed by the attacker's *own* key but asserting the victim as the
        // user identity: `verify()` fails because the signature does not check
        // out against the claimed `user_identity`.
        let forged = control::DeviceCert {
            user_identity: victim,
            device_key: attacker,
            generation: 0,
            signature: key(1).sign(attacker.as_bytes()),
        };
        assert!(!forged.verify(), "test fixture must be an invalid cert");
        assert_eq!(
            check_hello_identity(attacker, attacker, Some(&forged), false),
            HelloIdentity::Reject,
        );
    }

    /// A cert that verifies but names a *different* device is someone else's,
    /// replayed. Binding it to whoever presented it is the same escalation by
    /// another route.
    #[test]
    fn valid_cert_for_another_device_is_refused() {
        let user = key(1);
        let real_device = key(2).public();
        let attacker = key(3).public();
        let cert = control::DeviceCert::create(&user, &real_device, 0);
        assert!(cert.verify());
        assert_eq!(
            check_hello_identity(attacker, attacker, Some(&cert), false),
            HelloIdentity::Reject,
        );
    }

    /// The legitimate case: a cert signed by the user over this very device key
    /// binds it, whether or not the sender also claims the user identity.
    #[test]
    fn valid_cert_binds_its_own_device() {
        let user = key(1);
        let device = key(2).public();
        let cert = control::DeviceCert::create(&user, &device, 0);
        // Speaking as itself.
        assert_eq!(
            check_hello_identity(device, device, Some(&cert), false),
            HelloIdentity::Accept(Some(user.public())),
        );
        // Speaking as its user identity, which the cert backs.
        assert_eq!(
            check_hello_identity(device, user.public(), Some(&cert), false),
            HelloIdentity::Accept(Some(user.public())),
        );
    }

    /// No cert at all is fine, it just proves nothing beyond the transport key.
    /// Claiming another identity without one is not.
    #[test]
    fn certless_hello_speaks_only_for_itself() {
        let peer = key(1).public();
        let other = key(2).public();
        assert_eq!(
            check_hello_identity(peer, peer, None, false),
            HelloIdentity::Accept(None),
        );
        assert_eq!(
            check_hello_identity(peer, other, None, false),
            HelloIdentity::Reject,
        );
    }

    /// `ray unpair` cannot invalidate a signature, so the nullifier set is the
    /// only thing standing between a revoked device and the user's rights. A
    /// still-valid revoked cert earns no binding, and a claim resting on it is
    /// refused rather than downgraded.
    #[test]
    fn nullified_device_earns_no_binding() {
        let user = key(1);
        let device = key(2).public();
        let cert = control::DeviceCert::create(&user, &device, 0);
        // Asked across every network this node runs, not just the one the hello
        // arrived on, since the binding it guards is daemon-wide.
        assert_eq!(
            check_hello_identity(device, device, Some(&cert), true),
            HelloIdentity::Accept(None),
        );
        assert_eq!(
            check_hello_identity(device, user.public(), Some(&cert), true),
            HelloIdentity::Reject,
        );
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
