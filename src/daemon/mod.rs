//! The rayfish daemon: a long-lived, root-owned process that holds the iroh
//! [`Endpoint`], the TUN device, the [`PeerTable`], and the [`ProtocolRouter`],
//! and serves the unprivileged CLI over a Unix-socket IPC channel.
//!
//! # Two lifecycles
//!
//! The daemon deliberately separates two concepts that are easy to conflate:
//!
//! - **Process / infrastructure lifecycle** — the iroh endpoint, IPC socket,
//!   accept loop, blob store, DNS resolver, metrics server, and the TUN *file
//!   descriptor*. These are built once in [`run_daemon`] and live for the whole
//!   process. They are torn down only by the daemon-wide `shutdown_token`
//!   (real shutdown / `IpcMessage::Shutdown`).
//! - **Active VPN state** — the TUN link being *up*, system DNS being
//!   configured, and the saved networks being connected. This is toggled at
//!   runtime by [`MeshManager::activate`] / [`MeshManager::deactivate`], driven
//!   by the `Up` / `Down` IPC commands, and tracked by [`MeshManager::active`].
//!
//! This mirrors Tailscale's split between the always-running `tailscaled`
//! daemon and the `tailscale up` / `tailscale down` client toggles: `down`
//! puts the daemon on *standby* (VPN state torn down) without killing the
//! process, so the next `up` is a cheap, unprivileged IPC call rather than a
//! root service restart.
//!
//! # Cancellation tokens
//!
//! There are two tiers, and the distinction is what makes standby work:
//!
//! - `shutdown_token` (the token passed into [`run_daemon`]) gates all the
//!   always-on infrastructure. Cancelling it stops the **process**. `Down`
//!   never touches it — otherwise the IPC accept loop would die and there would
//!   be nothing left to receive the next `Up`.
//! - Each active network owns a `shutdown_token.child_token()` stored on its
//!   [`NetworkHandle`]. `deactivate` cancels these per-network children to stop
//!   that network's background tasks. Because cancellation is one-shot, every
//!   `activate` mints *fresh* child tokens, so `up → down → up` cycles work.

use bytes::Bytes;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};

use anyhow::{Context, Result};
use iroh::address_lookup::PkarrRelayClient;
use iroh::endpoint::{Connection, Endpoint, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointId, SecretKey};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, HashAndFormat};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::audit;
use crate::config;
use crate::control::{self, ControlMsg};
use crate::dht;
use crate::dns;
use crate::dns_config;
use crate::firewall::{self, SharedFirewall};
use crate::forward;
use crate::identity;
use crate::ipc::{self, FirewallRuleView, IpcMessage, NetworkRole, NetworkStatus, PeerStatus};
use crate::membership::{
    ApprovedEntry, ApprovedList, GroupMode, IdentityProvider, IrohIdentityProvider, Member,
    MemberList, canonical_group_bytes, derive_ipv6, group_blob_hash, verify_group_blob,
};
use crate::network_name;
use crate::peers::{self, PeerTable};
use crate::stats::ForwardMetrics;
use crate::transport;
use crate::tun::{self, check_cgnat_conflict};
use ray_proto::SuggestedFirewall;

// `MeshManager`'s IPC operations are split by domain into the `mesh/` submodule;
// see `mesh/mod.rs`. Each holds an additional `impl MeshManager` block. Nested a
// level down so the module names can be the clean domain names without colliding
// with the `use crate::{firewall, dns, …}` aliases above.
mod mesh;
// The mesh core's join handshake and background-task/reconvergence helpers were
// moved into `mesh/{join,background}.rs`; re-export them at the daemon level so
// `mod.rs` and the other `mesh/` submodules (via `use super::super::*`) call them
// by bare name, as before the split.
pub(crate) use mesh::*;

// Domain satellites with their own owned state (and ALPN accept arms), held by
// `MeshManager` as fields rather than loose on the core. See each module.
mod dns_manager;
pub(crate) use dns_manager::DnsManager;

mod file_service;
pub(crate) use file_service::FileService;

mod connect_service;
pub(crate) use connect_service::ConnectService;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// ALPN for the device-pairing protocol. The trailing `/1` is its protocol
/// version — **bump it on any breaking change to the `PairMsg` handshake**;
/// peers on different versions can't negotiate a connection (transport-enforced).
const PAIR_ALPN: &[u8] = b"rayfish/pair/1";

/// Node-wide shared handles, cloned into every per-network accept handler and
/// background task. Every field is a cheap `Clone` — an `Arc`-backed handle, a
/// channel sender, or a small wrapper — so the whole bundle is cloned by value
/// instead of threaded as a dozen separate arguments/struct fields. Built once
/// per daemon via [`MeshManager::mesh_ctx`]; a new daemon-wide dependency is one
/// field here rather than one parameter at every call site.
#[derive(Clone)]
pub(crate) struct MeshCtx {
    identity: IrohIdentityProvider,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Bytes>,
    stats: Arc<ForwardMetrics>,
    blob_store: FsStore,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
}

impl MeshCtx {
    /// Build the per-peer data-plane bundle for `forward::spawn_peer_reader`,
    /// combining this context's shared handles with the caller's per-connection
    /// `disconnect_tx`/`token`.
    fn forward_ctx(
        &self,
        disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
        token: CancellationToken,
    ) -> forward::ForwardCtx {
        forward::ForwardCtx {
            firewall: self.firewall.clone(),
            tun_tx: self.tun_tx.clone(),
            disconnect_tx,
            token,
            stats: self.stats.clone(),
            device_user_map: self.device_user_map.clone(),
        }
    }
}

/// Project a roster's `Member`s into the persistable `config::MemberEntry` form
/// (drops the runtime-only `user_identity`/`device_cert`/`collision_index`).
pub(crate) fn to_member_entries<'a>(
    members: impl IntoIterator<Item = &'a Member>,
) -> Vec<config::MemberEntry> {
    members
        .into_iter()
        .map(|m| config::MemberEntry {
            identity: m.identity,
            ip: m.ip,
            is_coordinator: m.is_coordinator,
            hostname: m.hostname.clone(),
        })
        .collect()
}

/// Project approved entries into the persistable `config::ApprovedConfigEntry`.
pub(crate) fn to_approved_entries<'a>(
    approved: impl IntoIterator<Item = &'a ApprovedEntry>,
) -> Vec<config::ApprovedConfigEntry> {
    approved
        .into_iter()
        .map(|a| config::ApprovedConfigEntry {
            identity: a.identity,
            ip: a.ip,
            hostname: a.hostname.clone(),
        })
        .collect()
}

struct CoordinatorAcceptState {
    ctx: MeshCtx,
    network_name: String,
    state: SharedNetworkState,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    /// Shared with this network's [`NetworkHandle`]; see its `invite_lock`.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    /// Shared with the router; lets the control reader resolve `ray ping` Pongs.
    pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
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
        self.ctx
            .peers
            .add(peer_ip, peer_ipv6, conn.clone(), remote_id, &self.network_name);
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
            self.ctx.device_user_map.insert(remote_id, cert.user_identity);
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
                conn, send, remote_id, peer_ip, hostname, device_cert, secret,
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
                // TODO(abuse-hardening): the pending-join queue is unbounded and
                // has no TTL — a peer could open many join streams to grow it. Out
                // of scope for the control-flood rate limiter (see
                // ~/.claude/plans/hidden-jumping-fountain.md); cap/evict here and
                // add a per-peer concurrent-stream limit if this becomes a vector.
                {
                    let mut s = self.state.write().unwrap();
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
                        conn, send, remote_id, peer_ip, hostname, device_cert, false, false,
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
        // Assign the IP authoritatively from the current roster: lowest free
        // collision index whose derived IPv4 isn't already held by a *different*
        // identity. This (not the peer-suggested address) is what we store and
        // report back, so two coordinators that both admit at index 0 produce a
        // roster the reconverge tiebreak can resolve deterministically.
        let (peer_ip, collision_index) = {
            let s = self.state.read().unwrap();
            crate::membership::assign_ip(&s.members, &remote_id)
        };
        // Resolve the hostname. An authoritative (invite-bound) name already bound
        // to a different identity is rejected. A joiner-chosen name keeps
        // collision resolution (`name` → `name-1` → …).
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
                    self.deny(
                        &conn,
                        send,
                        format!("hostname '{conflict}' is already in use on this network"),
                    )
                    .await;
                    return false;
                }
            }
        } else {
            None
        };

        // Reject an IP collision with a different identity.
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
            self.deny(
                &conn,
                send,
                format!("IP collision: {peer_ip} already assigned"),
            )
            .await;
            return false;
        }

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
                is_coordinator: false,
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

        let peer_ipv6 = derive_ipv6(&remote_id);
        crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
        self.ctx.peers.add(
            peer_ip,
            peer_ipv6,
            conn.clone(),
            remote_id,
            &self.network_name,
        );
        // Keep reading control streams from this member so a later rename (sent
        // as a MeshHello) propagates immediately, not just after a reconnect.
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
        true
    }
}

struct MemberAcceptState {
    ctx: MeshCtx,
    network_name: String,
    state: SharedNetworkState,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
}

impl MemberAcceptState {
    /// Register a freshly handshaked peer in the peer table and start its
    /// inbound data-plane reader. Shared by the approved-join and known-member
    /// branches of `handle_connection`.
    fn register_peer(&self, conn: Connection, peer_identity: EndpointId, ip: Ipv4Addr) {
        let peer_ipv6 = derive_ipv6(&peer_identity);
        self.ctx
            .peers
            .add(ip, peer_ipv6, conn.clone(), peer_identity, &self.network_name);
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
            self.ctx.device_user_map
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

enum AcceptHandler {
    Coordinator(Arc<CoordinatorAcceptState>),
    Member(Arc<MemberAcceptState>),
}

#[cfg(test)]
impl AcceptHandler {
    fn is_coordinator(&self) -> bool {
        matches!(self, AcceptHandler::Coordinator(_))
    }
}

struct MeshProtocol {
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

struct ProtocolRouter {
    blobs: BlobsProtocol,
    handlers: DashMap<Vec<u8>, Arc<MeshProtocol>>,
    /// File-transfer + pairing state and their ALPN accept arms. The accept loop
    /// delegates the `FILES_ALPN`/`PAIR_ALPN` arms to this; `MeshManager` holds
    /// the same handle for the IPC-side file/pairing commands.
    files: Arc<FileService>,
    /// `ray connect` state (pending/approved/outgoing maps) and the `CONNECT_ALPN`
    /// accept arm. The accept loop delegates to this; `MeshManager` holds the same
    /// handle for the IPC-side connect commands.
    connect: Arc<ConnectService>,
    /// In-flight `ray ping` probes, keyed by nonce. The control reader fires the
    /// oneshot when the matching `Pong` arrives so the ping handler can measure
    /// round-trip time. Cloned into both control readers.
    pending_pongs: Arc<DashMap<u64, tokio::sync::oneshot::Sender<()>>>,
}

impl ProtocolRouter {
    fn new(blobs: BlobsProtocol, files: Arc<FileService>, connect: Arc<ConnectService>) -> Self {
        Self {
            blobs,
            handlers: DashMap::new(),
            files,
            connect,
            pending_pongs: Arc::new(DashMap::new()),
        }
    }

    fn register(&self, alpn: Vec<u8>, handler: AcceptHandler) {
        self.handlers
            .insert(alpn, Arc::new(MeshProtocol { handler }));
    }

    fn unregister(&self, alpn: &[u8]) {
        self.handlers.remove(alpn);
    }

    fn alpns(&self) -> Vec<Vec<u8>> {
        let mut alpns: Vec<Vec<u8>> = self.handlers.iter().map(|r| r.key().clone()).collect();
        alpns.push(iroh_blobs::protocol::ALPN.to_vec());
        alpns.push(transport::FILES_ALPN.to_vec());
        alpns.push(PAIR_ALPN.to_vec());
        alpns.push(transport::CONNECT_ALPN.to_vec());
        alpns
    }

    fn spawn_accept_loop(
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
                                _ => {
                                    if let Some(handler) = router.handlers.get(&alpn).map(|r| r.clone()) {
                                        let _ = handler.accept(conn).await;
                                    } else {
                                        tracing::warn!(
                                            alpn = %String::from_utf8_lossy(&alpn),
                                            "no handler for ALPN"
                                        );
                                    }
                                }
                            }
                        });
                    }
                }
            }
        })
    }
}

#[derive(Clone)]
struct GroupSnapshot {
    hash: blake3::Hash,
    msgpack_bytes: Vec<u8>,
}

/// A per-network state cell shared (read-mostly) across the accept handlers,
/// publisher, poller, and cleanup tasks for that network.
pub(crate) type SharedNetworkState = Arc<std::sync::RwLock<NetworkState>>;

pub(crate) struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
    snapshot: Option<GroupSnapshot>,
    network_secret_key: Option<SecretKey>,
    network_public_key: EndpointId,
    network_name: Option<String>,
    /// Access mode (open auto-admits; restricted gates unknown joiners). Only the
    /// coordinator's accept path consults this; members default to `Restricted`.
    mode: GroupMode,
    /// Coordinator-suggested firewall rules carried in the blob (keyed by subject
    /// hostname; the `*` subject targets every node). On a coordinator this is
    /// what it publishes; on a member it is what it last received and
    /// materializes rules from.
    suggested_firewall: SuggestedFirewall,
    /// Reusable join keys carried in the signed blob (keyed by hex
    /// `blake3(secret)`). On a network-key holder this is what it publishes and
    /// validates redemptions against; on a plain member it is what it last
    /// received. Reloaded from the verified blob on every reconverge so any admin
    /// can admit and revocation propagates.
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    /// Materialized suggested rules awaiting manual `ray firewall accept` on a
    /// node that did not opt into `--auto-accept-firewall`. Empty when
    /// auto-accepting.
    pending_suggestions: Vec<firewall::FirewallRule>,
    /// Peers awaiting live operator approval on a closed network (coordinator
    /// only, in-memory, never persisted or published).
    pending: HashMap<EndpointId, PendingJoin>,
}

/// A join request held pending live approval on a closed network.
struct PendingJoin {
    hostname: Option<String>,
    device_cert: Option<control::DeviceCert>,
    requested_at: Instant,
}

impl NetworkState {
    /// Snapshot the current member roster as an owned `Vec` (the members map is
    /// the single source of truth; callers take a copy to release the lock).
    fn roster(&self) -> Vec<Member> {
        self.members.all().into_iter().cloned().collect()
    }

    /// Snapshot the current approved-but-not-yet-joined entries as an owned `Vec`.
    fn approved_snapshot(&self) -> Vec<ApprovedEntry> {
        self.approved.all().into_iter().cloned().collect()
    }

    /// Hostnames currently claimed by other members (excluding `except`), used to
    /// resolve a rename/join collision against the roster.
    fn taken_hostnames(&self, except: EndpointId) -> Vec<String> {
        self.members
            .all()
            .iter()
            .filter(|m| m.identity != except)
            .filter_map(|m| m.hostname.clone())
            .collect()
    }

    fn refresh_snapshot(&mut self) {
        let bytes = canonical_group_bytes(
            &self.members,
            &self.approved,
            &self.suggested_firewall,
            self.network_name.as_deref(),
            &self.reusable_keys,
        );
        let hash = blake3::hash(&bytes);
        self.snapshot = Some(GroupSnapshot {
            hash,
            msgpack_bytes: bytes,
        });
    }
}

/// Runtime state for one active network. Created when a network is joined,
/// created, or reconnected; dropped (after `cancel`ling and awaiting `tasks`)
/// when the network is left or the VPN is put on standby. The persisted config
/// (in `networks.toml`) outlives this handle — standby tears down the handle
/// but keeps the config so `activate` can rebuild it.
#[allow(dead_code)]
pub struct NetworkHandle {
    name: String,
    network_key: EndpointId,
    role: NetworkRole,
    my_ip: Ipv4Addr,
    state: SharedNetworkState,
    /// DHT republish trigger; `Some` only on the coordinator (the sole publisher).
    /// Lets `set_hostname` re-publish the group blob on a coordinator self-rename.
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    /// Child of the daemon `shutdown_token`. Cancelling it stops this network's
    /// background tasks (reconnect loop, group poller, publisher, peer readers)
    /// without affecting the rest of the daemon.
    cancel: CancellationToken,
    /// Background tasks owned by this network, awaited on teardown.
    tasks: Vec<JoinHandle<()>>,
    /// Serializes invite-ledger reads/writes (mint, redeem, revoke) so concurrent
    /// joins can't double-burn a single-use invite (TOCTOU on the toml file).
    /// Shared with this network's [`CoordinatorAcceptState`].
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    /// Disconnect channel for this network's accept handlers, kept so a member
    /// promoted to coordinator (via `AdminGrant`) can re-register a
    /// [`CoordinatorAcceptState`] on the live channel without rebuilding it.
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
}

/// Shared, always-on daemon state. Cloned (via `Arc`) into every IPC handler
/// and background task. Holds both the infrastructure that lives for the whole
/// process and the handles for the currently-active networks. See the
/// module-level docs for the two-lifecycle model.
pub struct MeshManager {
    endpoint: Endpoint,
    identity: IrohIdentityProvider,
    peers: PeerTable,
    stats: Arc<ForwardMetrics>,
    /// When the daemon process started, used for uptime in diagnostics.
    start: Instant,
    tun_tx: mpsc::Sender<Bytes>,
    networks: Arc<DashMap<String, NetworkHandle>>,
    shutdown_token: CancellationToken,
    blob_store: FsStore,
    firewall: SharedFirewall,
    protocol_router: Arc<ProtocolRouter>,
    /// Magic DNS naming tables, resolver, and OS-DNS configurator (see [`DnsManager`]).
    dns: DnsManager,
    mdns_enabled: bool,
    tun_name: String,
    /// File-transfer + pairing state and ALPN accept arms (see [`FileService`]).
    /// Shared with [`ProtocolRouter`], which runs the accept arms.
    files: Arc<FileService>,
    /// `ray connect` state + ALPN accept arm (see [`ConnectService`]). Shared with
    /// [`ProtocolRouter`], which runs the accept arm.
    connect: Arc<ConnectService>,
    device_cert: Option<control::DeviceCert>,
    device_user_map: peers::DeviceUserMap,
    /// This node's contact id (`ray connect`): the public half of the rotatable
    /// contact key. The secret lives in config (read fresh by the publisher and
    /// `rotate_contact` so rotation needs no restart); only the public id is
    /// surfaced here for `ray status` / `ray contact id`.
    contact_public: EndpointId,
    /// Whether the VPN is currently active (TUN up, networks connected) or on
    /// standby. Toggled by the `Up`/`Down` IPC commands.
    active: Arc<AtomicBool>,
    /// Promotion signal: a co-coordinator's per-peer control reader sends the
    /// network name here after persisting an `AdminGrant` key, and the main
    /// daemon loop ([`serve_ipc`]) drains it into
    /// [`MeshManager::promote_to_coordinator`]. The reader holds only field
    /// clones (not the full `MeshManager`), so it can't promote itself — hence
    /// the channel hand-off to the loop that does hold the `Arc<MeshManager>`.
    promote_tx: mpsc::Sender<String>,
}

/// Map key-holding status to a [`NetworkRole`].
///
/// A node that holds the per-network secret key (original coordinator or one
/// promoted via `ray admin add`) runs as `Coordinator`; all other nodes run
/// as `Member`.
fn role_for_key_holder(holds_network_key: bool) -> NetworkRole {
    if holds_network_key {
        NetworkRole::Coordinator
    } else {
        NetworkRole::Member
    }
}

/// Whether an `AdminGrant`'s key is genuinely this network's key.
///
/// Self-authenticating admission of the granted key: we adopt it only if its
/// public half equals the network pubkey. An attacker who does not already hold
/// the real secret cannot forge a key that passes, so a forged `AdminGrant`
/// from a non-coordinator member is rejected without any roster lookup (and so
/// without depending on reconverge timing for the granter's `is_coordinator`
/// flag, which a sender-identity check would).
fn admin_grant_key_valid(secret_key: [u8; 32], net_pubkey: EndpointId) -> bool {
    SecretKey::from(secret_key).public() == net_pubkey
}

/// Whether a network in `current` role should be (re-)registered as coordinator.
///
/// A member promoted via `AdminGrant` must swap to the coordinator accept
/// handler; a network already running as coordinator is a no-op.
fn should_promote(current: NetworkRole) -> bool {
    !current.is_coordinator()
}

impl MeshManager {
    /// Bundle the daemon-wide shared handles into a [`MeshCtx`] for the accept
    /// handlers and background tasks. Every field is a cheap `Clone`.
    pub(crate) fn mesh_ctx(&self) -> MeshCtx {
        MeshCtx {
            identity: self.identity.clone(),
            peers: self.peers.clone(),
            tun_tx: self.tun_tx.clone(),
            stats: self.stats.clone(),
            blob_store: self.blob_store.clone(),
            firewall: self.firewall.clone(),
            hostname_table: self.dns.hostname_table.clone(),
            reverse_table: self.dns.reverse_table.clone(),
            device_user_map: self.device_user_map.clone(),
        }
    }

    pub(crate) async fn refresh_alpns(&self) {
        let alpns = self.protocol_router.alpns();
        let alpn_strs: Vec<String> = alpns
            .iter()
            .map(|a| String::from_utf8_lossy(a).to_string())
            .collect();
        tracing::info!(alpns = ?alpn_strs, "refreshing ALPNs");
        self.endpoint.set_alpns(alpns);

        let network_names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        dns_config::update_search_domains(&network_names, &self.tun_name).await;
    }

    /// Register a [`CoordinatorAcceptState`] handler for `network` and update
    /// the network's role in `self.networks` to [`NetworkRole::Coordinator`].
    ///
    /// Calling this at create, restore, and admin-promotion sites keeps the
    /// coordinator-registration logic in one place. The method is synchronous
    /// (no `.await`) because `protocol_router.register` is a plain HashMap
    /// swap; the caller is responsible for spawning the `disconnect_rx` cleanup
    /// task **before** calling this so the channel is live when the first
    /// incoming connection arrives.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_coordinator_handler(
        &self,
        network: &str,
        state: SharedNetworkState,
        invite_lock: Arc<tokio::sync::Mutex<()>>,
        dht_notify: Option<Arc<tokio::sync::Notify>>,
        network_key: EndpointId,
        disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
        cancel: CancellationToken,
    ) {
        self.protocol_router.register(
            transport::network_alpn(&network_key),
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                ctx: self.mesh_ctx(),
                network_name: network.to_string(),
                state,
                disconnect_tx,
                token: cancel,
                dht_notify,
                invite_lock,
                pending_pongs: self.protocol_router.pending_pongs.clone(),
            })),
        );
        // Flip the stored role so `ray status` reports Coordinator immediately.
        if let Some(mut handle) = self.networks.get_mut(network) {
            handle.role = NetworkRole::Coordinator;
        }
    }

    /// Re-register the [`CoordinatorAcceptState`] for `network` so a node just
    /// granted the per-network key (via `AdminGrant`) can admit fresh joiners
    /// instead of silently dropping their `JoinRequest`s under
    /// `AcceptHandler::Member`.
    ///
    /// Idempotent: a network already running as coordinator is left untouched
    /// ([`should_promote`]). The needed [`NetworkHandle`] fields are cloned
    /// inside a scoped block so the `DashMap` ref is dropped before the
    /// (synchronous) registration — never held across it.
    pub(crate) async fn promote_to_coordinator(&self, network: &str) {
        let parts = {
            let Some(h) = self.networks.get(network) else {
                return;
            };
            if !should_promote(h.role.clone()) {
                return;
            }
            (
                h.state.clone(),
                h.invite_lock.clone(),
                h.dht_notify.clone(),
                h.network_key,
                h.disconnect_tx.clone(),
                h.cancel.clone(),
            )
        }; // DashMap ref dropped before the registration below.
        self.register_coordinator_handler(
            network, parts.0, parts.1, parts.2, parts.3, parts.4, parts.5,
        );
        self.refresh_alpns().await;
        tracing::info!(network, "promoted to coordinator accept handler");
    }

    /// Tailscale-style access control. Read-only queries are open to any local
    /// user; mutating commands require the caller to be root or the configured
    /// operator UID; setting the operator itself is root-only. Returns `None`
    /// when the request is permitted, or `Some(error)` to short-circuit it.
    ///
    /// Identity is taken from the connecting socket's `SO_PEERCRED` (the kernel
    /// vouches for it — it can't be forged by the client), so the socket file
    /// mode only has to permit the connection, not gate authority.
    pub(crate) fn check_authorized(req: &IpcMessage, peer_cred: Option<(u32, u32)>) -> Option<IpcMessage> {
        // Reads are available to everyone.
        if matches!(
            req,
            IpcMessage::Status
                | IpcMessage::Report
                | IpcMessage::FirewallShow
                | IpcMessage::FirewallSuggestions { .. }
                | IpcMessage::FirewallPending { .. }
                | IpcMessage::ListFiles
                | IpcMessage::Connections
                | IpcMessage::ContactId
                | IpcMessage::Ping { .. }
                | IpcMessage::Netcheck
        ) {
            return None;
        }

        let uid = peer_cred.map(|(uid, _)| uid);

        // Root may do anything.
        if uid == Some(0) {
            return None;
        }

        // Granting operator access is reserved for root.
        if matches!(req, IpcMessage::SetOperator { .. }) {
            return Some(IpcMessage::Error {
                message: "permission denied: granting operator access requires root \
                          (re-run with sudo)"
                    .to_string(),
            });
        }

        // Otherwise the caller must be the configured operator.
        let operator = config::load().ok().and_then(|c| c.operator_uid);
        if uid.is_some() && uid == operator {
            return None;
        }

        Some(IpcMessage::Error {
            message: "permission denied: this user is not authorized to control rayfish.\n\
                      Grant access with: sudo ray set-operator <user>"
                .to_string(),
        })
    }

    /// Persist the operator UID so that user can run mutating `ray` commands
    /// without root. Authorization (root-only) is enforced in `check_authorized`.
    pub(crate) fn set_operator(&self, uid: u32) -> IpcMessage {
        let mut app_config = match config::load() {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        };
        app_config.operator_uid = Some(uid);
        if let Err(e) = config::save_settings(&app_config) {
            return IpcMessage::Error {
                message: format!("failed to save config: {e}"),
            };
        }
        IpcMessage::Ok {
            message: format!("operator set to uid {uid}; that user can now run ray without sudo"),
        }
    }

    pub(crate) async fn handle_request(
        self: &Arc<Self>,
        req: IpcMessage,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        if let Some(denied) = Self::check_authorized(&req, peer_cred) {
            return denied;
        }
        match req {
            IpcMessage::Create {
                mode,
                name,
                hostname,
                transport: _,
            } => self.create_network(mode, name, hostname).await,
            IpcMessage::Join {
                network_key,
                name,
                hostname,
                transport: _,
                invite,
                coordinator,
                auto_accept_firewall,
            } => {
                self.join_network(
                    &network_key,
                    name.as_deref(),
                    hostname,
                    invite,
                    coordinator,
                    auto_accept_firewall,
                )
                .await
            }
            IpcMessage::Leave { name } => self.leave_network(&name).await,
            IpcMessage::Nuke { name, force } => self.nuke_network(&name, force).await,
            IpcMessage::Status => self.status(),
            IpcMessage::Report => self.build_report(peer_cred),
            IpcMessage::Up { hostname } => self.activate(hostname).await,
            IpcMessage::Down => self.deactivate().await,
            IpcMessage::Shutdown => {
                self.shutdown_token.cancel();
                IpcMessage::Ok {
                    message: "shutting down".to_string(),
                }
            }
            IpcMessage::FirewallAdd {
                direction,
                action,
                protocol,
                port,
                peer,
                network,
            } => self.firewall_add(
                direction,
                action,
                protocol,
                port.as_deref(),
                peer.as_deref(),
                network.as_deref(),
            ),
            IpcMessage::FirewallRemove { index } => self.firewall_remove(index),
            IpcMessage::FirewallShow => self.firewall_show(),
            IpcMessage::FirewallDefault { action } => self.firewall_default(action),
            IpcMessage::FirewallReject { enabled } => self.firewall_reject(enabled),
            IpcMessage::FirewallSuggest {
                network,
                suggestions,
            } => self.firewall_suggest(&network, suggestions).await,
            IpcMessage::FirewallSuggestions { network } => self.firewall_suggestions(&network),
            IpcMessage::FirewallPending { network } => self.firewall_pending(&network),
            IpcMessage::FirewallAccept { network } => self.firewall_accept(&network),
            IpcMessage::FirewallDeny { network } => self.firewall_deny(&network),
            IpcMessage::FirewallResolveSuggestions {
                network,
                accept,
                deny,
            } => self.firewall_resolve_suggestions(&network, &accept, &deny),
            IpcMessage::FirewallAutoAccept { network, enabled } => {
                self.firewall_auto_accept(&network, enabled)
            }
            IpcMessage::SetHostname { network, hostname } => {
                self.set_hostname(&network, &hostname).await
            }
            IpcMessage::SendFile { path, peer } => self.send_file(&path, &peer).await,
            IpcMessage::ListFiles => self.list_files(),
            IpcMessage::AcceptFile { id, output } => self.accept_file(id, output, peer_cred).await,
            IpcMessage::StartPairing => self.start_pairing(),
            IpcMessage::PairWithDevice {
                endpoint_id,
                secret,
            } => self.pair_with_device(endpoint_id, secret).await,
            IpcMessage::SetOperator { uid } => self.set_operator(uid),
            IpcMessage::InviteCreate {
                network,
                expires_secs,
                hostname,
                reusable,
            } => {
                self.invite_create(&network, expires_secs, hostname, reusable)
                    .await
            }
            IpcMessage::InviteList { network } => self.invite_list(&network).await,
            IpcMessage::InviteRevoke { network, id } => self.invite_revoke(&network, &id).await,
            IpcMessage::Requests { network } => self.list_requests(&network),
            IpcMessage::AcceptRequest { network, id } => self.accept_request(&network, &id).await,
            IpcMessage::DenyRequest { network, id } => self.deny_request(&network, &id),
            IpcMessage::AdminAdd { network, identity } => self.admin_add(&network, &identity).await,
            IpcMessage::AdminList { network } => self.admin_list(&network),
            IpcMessage::Connect {
                contact_id,
                hostname,
            } => self.connect(&contact_id, hostname).await,
            IpcMessage::Connections => self.list_connections(),
            IpcMessage::ApproveConnection { id } => self.approve_connection(&id).await,
            IpcMessage::ContactId => IpcMessage::ContactIdResponse {
                contact_id: self.contact_public.to_string(),
            },
            IpcMessage::RotateContact => self.rotate_contact().await,
            IpcMessage::Ping {
                peer,
                count,
                interval_ms,
            } => self.ping(&peer, count, interval_ms).await,
            IpcMessage::Netcheck => self.netcheck().await,
            other => IpcMessage::Error {
                message: format!("unexpected message: {:?}", other),
            },
        }
    }

    // -----------------------------------------------------------------------
    // Hostname
    // -----------------------------------------------------------------------

    pub(crate) async fn set_hostname(&self, network: &str, hostname: &str) -> IpcMessage {
        use crate::hostname;

        if !hostname::is_valid_hostname(hostname) {
            return IpcMessage::Error {
                message: "invalid hostname (lowercase ASCII, 1-63 chars)".to_string(),
            };
        }

        let (my_ip, is_coord, state, dht_notify) = match self.networks.get(network) {
            Some(h) => (
                h.my_ip,
                h.role.is_coordinator(),
                h.state.clone(),
                h.dht_notify.clone(),
            ),
            None => {
                return IpcMessage::Error {
                    message: format!("network '{}' not found", network),
                };
            }
        };

        let my_identity = self.endpoint.id();

        // The coordinator is authoritative, so it resolves collisions against the
        // roster up front. A member applies its requested name optimistically and
        // lets the coordinator correct it via the authoritative MemberSync.
        let new_hostname = if is_coord {
            let taken = state.read().unwrap().taken_hostnames(my_identity);
            let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
            hostname::resolve_collision(hostname, &taken_refs)
        } else {
            hostname.to_string()
        };

        // Update our own member entry.
        if let Ok(mut s) = state.write()
            && let Some(me) = s.members.get_mut(&my_identity)
        {
            me.hostname = Some(new_hostname.clone());
        }

        // Update DNS table: remove old entry for our IP, insert new one.
        dns::remove_hostname_by_ip(&self.dns.hostname_table, &self.dns.reverse_table, network, my_ip)
            .await;
        dns::update_hostname(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            network,
            &new_hostname,
            my_ip,
            derive_ipv6(&self.identity.local_identity()),
        )
        .await;

        // Persist to config. A member also records the rename as a durable
        // pending intent so it keeps being delivered to a coordinator across
        // reconnects/restarts until the signed blob confirms it; a coordinator
        // publishes authoritatively, so it clears any pending intent.
        if let Ok(Some(mut net)) = config::load_network(network) {
            net.my_hostname = Some(new_hostname.clone());
            net.pending_hostname = if is_coord {
                None
            } else {
                Some(new_hostname.clone())
            };
            let _ = config::save_network(&net);
        }

        if is_coord {
            // Authoritative: republish the group blob and push the new roster to
            // every peer immediately.
            tracing::info!(
                network = %network,
                hostname = %new_hostname,
                "coordinator renamed self; republishing blob + broadcasting MemberSync"
            );
            update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
            broadcast_member_sync(&self.peers, None).await;
        } else {
            self.announce_rename_to_peers(network, my_identity, my_ip, &new_hostname)
                .await;
        }

        let dns_name = format!("{}.{}.{}", new_hostname, network, crate::DNS_DOMAIN);
        IpcMessage::Ok {
            message: format!("hostname set to {} ({})", new_hostname, dns_name),
        }
    }

    /// Fast-path a member's rename to its connected peers via `MeshHello` (only
    /// the coordinator's continuous control reader acts on it — resolving
    /// collisions and broadcasting the authoritative `MemberSync`). The durable
    /// `pending_hostname` intent + reconverge drain backstop the rest.
    async fn announce_rename_to_peers(
        &self,
        network: &str,
        my_identity: EndpointId,
        my_ip: Ipv4Addr,
        new_hostname: &str,
    ) {
        let peers = self.peers.peers_for_network_with_conn(network);
        tracing::info!(
            network = %network,
            hostname = %new_hostname,
            connected_peers = peers.len(),
            "member rename queued as pending intent; sending MeshHello to connected peers"
        );
        let mut sent = 0usize;
        for (_peer_id, _peer_ip, conn) in &peers {
            if let Ok((mut send, _recv)) = conn.open_bi().await {
                let msg = ControlMsg::MeshHello {
                    identity: my_identity,
                    ip: my_ip,
                    hostname: Some(new_hostname.to_string()),
                    device_cert: self.device_cert.clone(),
                };
                if control::send_msg(&mut send, &msg).await.is_ok() {
                    sent += 1;
                }
            }
        }
        tracing::debug!(
            network = %network,
            hostname = %new_hostname,
            sent,
            connected_peers = peers.len(),
            "fast-path rename MeshHello delivered; drain backstop covers the rest"
        );
    }

    pub(crate) fn resolve_short_id_any_network(&self, short: &str) -> Option<EndpointId> {
        if short == "self" {
            return Some(self.endpoint.id());
        }
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(m) = state
                .members
                .all()
                .iter()
                .find(|m| m.identity.to_string().starts_with(short))
            {
                return Some(m.identity);
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Invite + join-request handlers (coordinator only)
    // -----------------------------------------------------------------------

    /// Look up an active network we coordinate, returning its public key and
    /// invite lock, or an error response if it's absent or we're only a member.
    #[allow(clippy::result_large_err)]
    pub(crate) fn coordinator_handle(
        &self,
        network: &str,
    ) -> std::result::Result<(EndpointId, Arc<tokio::sync::Mutex<()>>), IpcMessage> {
        let Some(handle) = self.networks.get(network) else {
            return Err(IpcMessage::Error {
                message: format!("network '{network}' not active"),
            });
        };
        if !handle.role.is_coordinator() {
            return Err(IpcMessage::Error {
                message: format!("only the coordinator of '{network}' can manage invites/requests"),
            });
        }
        Ok((handle.network_key, handle.invite_lock.clone()))
    }

}

fn guess_mime_type(filename: &str) -> String {
    mime_guess::from_path(filename)
        .first_or_octet_stream()
        .to_string()
}

fn format_size(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}

/// Entry point for `ray daemon`. Builds the always-on infrastructure, enters
/// the active VPN state, then serves IPC until shutdown. The heavy lifting is
/// delegated to [`build_daemon`] (construction) and [`serve_ipc`] (the request
/// loop); see the module docs for the infrastructure-vs-active-state split.
/// Read the most recent rolling log files from [`crate::logdir::log_dir`],
/// newest first, capped at ~3 MB total so report bundles stay small. Returns
/// `(archive_name, bytes)` entries placed under `logs/` in the tarball.
fn collect_recent_logs() -> Vec<(String, Vec<u8>)> {
    const MAX_TOTAL: u64 = 3 * 1024 * 1024;

    let dir = crate::logdir::log_dir();
    let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("rayfish.log") || n == "panic.log")
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    // Daily rotation appends a date suffix, so lexical order is chronological;
    // take the newest files first.
    entries.sort();
    entries.reverse();

    let mut out = Vec::new();
    let mut total = 0u64;
    for path in entries {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        total += bytes.len() as u64;
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            out.push((format!("logs/{name}"), bytes));
        }
        if total >= MAX_TOTAL {
            break;
        }
    }
    out
}

/// Write `files` as a gzipped tar archive at `path`. Each entry is `(name, bytes)`.
fn write_bundle(path: &std::path::Path, files: &[(String, Vec<u8>)]) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(enc);
    for (name, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        // `append_data` sets the path and recomputes the checksum.
        builder.append_data(&mut header, name, data.as_slice())?;
    }
    builder.into_inner()?.finish()?;
    Ok(())
}

pub async fn run_daemon(token: CancellationToken, stats: Arc<ForwardMetrics>) -> Result<()> {
    // Bail early on a CGNAT clash (e.g. Tailscale) before touching anything.
    check_cgnat_conflict()?;

    let (daemon, _metrics_server, promote_rx) = build_daemon(token.clone(), stats).await?;

    // Connect the control plane (mesh connections) once, for the daemon's
    // whole lifetime, then bring the data plane up. `ray up`/`ray down` toggle
    // only the data plane after this; connections persist across `down` so the
    // node stays online to peers.
    daemon.connect_all_networks().await;
    daemon.activate(None).await;

    let result = serve_ipc(&daemon, promote_rx, token).await;

    // Close the iroh endpoint before returning. Dropping it on return logs
    // "Endpoint dropped without calling `Endpoint::close`. Aborting
    // ungracefully." and can leave the process lingering until the service
    // manager escalates to SIGKILL — which delays the relaunch on
    // `ray restart`/`ray update` past the client's reachability probe. Closing
    // it here lets QUIC connections terminate cleanly and the process exit
    // promptly so the new daemon comes up fast.
    daemon.endpoint.close().await;

    result
}

/// Construct all always-on daemon infrastructure: identity, iroh endpoint, blob
/// store, TUN device, forwarding loop, DNS resolver, mDNS discovery, protocol
/// router, and metrics server. Returns the shared [`MeshManager`] — still on
/// standby, so the caller is expected to run [`MeshManager::activate`] — and the
/// metrics-server guard, which must outlive the process.
/// The ALPNs the endpoint advertises at boot: one per saved network plus the
/// network-independent blobs / file-transfer / pairing / connect ALPNs. A
/// freshly-started daemon with no active network must still accept `ray pair` /
/// `ray send` / `ray connect`, otherwise the initial handshake fails with "peer
/// doesn't support any known protocol" until the first create/join triggers
/// `refresh_alpns()`. Mirrors `ProtocolRouter::alpns()`.
fn initial_alpns(app_config: &config::AppConfig) -> Vec<Vec<u8>> {
    let mut alpns: Vec<Vec<u8>> = app_config
        .networks
        .iter()
        .filter_map(|net| net.network_public_key.as_ref().map(transport::network_alpn))
        .collect();
    alpns.push(iroh_blobs::protocol::ALPN.to_vec());
    alpns.push(transport::FILES_ALPN.to_vec());
    alpns.push(PAIR_ALPN.to_vec());
    alpns.push(transport::CONNECT_ALPN.to_vec());
    alpns
}

async fn build_daemon(
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
) -> Result<(
    Arc<MeshManager>,
    Option<iroh_metrics::service::MetricsServer>,
    mpsc::Receiver<String>,
)> {
    // Relocate a pre-/etc config tree into /etc/rayfish (Linux upgrade path)
    // before anything reads identity or config. No-op on macOS / once migrated.
    config::migrate_location();

    // --- Identity (persistent transport key + optional device certificate) ---
    let key = identity::load_or_create()?;
    let public_key = key.public();
    let device_cert = identity::load_device_cert()?;
    if let Some(ref cert) = device_cert {
        tracing::info!(user = %cert.user_identity.fmt_short(), "loaded device certificate");
    }
    let collision_index = identity::load_collision_index()?;
    let identity = IrohIdentityProvider::new(public_key, collision_index);
    let my_ip = identity.local_ip();

    // --- iroh endpoint (one ALPN per saved network + the blobs ALPN) ---
    let mut app_config = config::load()?;
    // Point the pkarr client at the configured discovery-DNS server (if any)
    // before any record publish/resolve happens.
    dht::set_discovery_override(&app_config.discovery_dns);
    // Lazily generate + persist this node's contact key (`ray connect`). The
    // secret stays in config; only its public id is held in `MeshManager`.
    let contact_public = config::contact_secret(&mut app_config).public();
    if let Err(e) = config::save_settings(&app_config) {
        tracing::warn!(error = %e, "failed to persist contact key");
    }
    let alpns = initial_alpns(&app_config);
    let use_tor = app_config
        .networks
        .iter()
        .any(|net| net.transport.as_ref().is_some_and(|t| t.is_tor()));
    let ep = transport::create_endpoint_with_alpns(
        key.clone(),
        alpns,
        use_tor,
        &app_config.relay,
        &app_config.discovery_dns,
    )
    .await?;

    // --- Content-addressed blob store (membership/file transfer) ---
    let blobs_dir = config::config_dir()?.join("blobs");
    std::fs::create_dir_all(&blobs_dir)?;
    let blob_store = FsStore::load(&blobs_dir)
        .await
        .context("failed to open blob store")?;
    let blobs_proto = BlobsProtocol::new(&blob_store, None);

    // --- Single TUN device + the forwarding loop, shared across networks ---
    let my_ipv6 = derive_ipv6(&identity.local_identity());
    let (tun_reader, tun_writer, tun_name) = tun::create(my_ip, my_ipv6)
        .await
        .context("failed to create TUN device")?;
    // Append-only audit log of peer connect/disconnect events. If it can't be
    // opened (e.g. unwritable config dir) the daemon still runs without auditing.
    let peers = match audit::AuditLog::open() {
        Ok(log) => PeerTable::with_audit(Arc::new(log)),
        Err(e) => {
            tracing::warn!(error = %e, "failed to open audit log; peer events will not be audited");
            PeerTable::new()
        }
    };
    let fw_config = firewall::load_firewall().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load firewall config, using defaults");
        firewall::FirewallConfig::default()
    });
    let shared_firewall = SharedFirewall::new(fw_config);
    shared_firewall.clone().spawn_evictor(token.clone());
    let active = Arc::new(AtomicBool::new(false));
    let (tun_tx, tun_rx) = mpsc::channel::<Bytes>(256);
    forward::spawn_tun_writer(tun_writer, tun_rx, active.clone());
    let device_user_map = peers::DeviceUserMap::new();

    // --- Magic DNS resolver + optional mDNS local discovery ---
    let hostname_table = dns::new_hostname_table();
    let reverse_table = dns::new_reverse_table();
    let dns_resolver = std::sync::Arc::new(crate::dns_resolver::Resolver::new(
        hostname_table.clone(),
        reverse_table.clone(),
    ));
    tokio::spawn(forward::run_mesh(
        tun_reader,
        peers.clone(),
        shared_firewall.clone(),
        token.clone(),
        stats.clone(),
        dns_resolver.clone(),
        tun_tx.clone(),
    ));
    let mdns_enabled = app_config.mdns_enabled;
    if mdns_enabled {
        spawn_mdns_discovery(&ep, token.clone());
    } else {
        tracing::info!("mDNS discovery disabled");
    }

    // --- Protocol router + the shared MeshManager ---
    let files = Arc::new(FileService::new(key.clone()));
    let connect = Arc::new(ConnectService::new());
    let protocol_router = Arc::new(ProtocolRouter::new(
        blobs_proto,
        files.clone(),
        connect.clone(),
    ));
    // Promotion channel: a co-coordinator's control reader signals the main
    // daemon loop to swap in the coordinator accept handler on `AdminGrant`.
    let (promote_tx, promote_rx) = mpsc::channel::<String>(16);
    let daemon = Arc::new(MeshManager {
        endpoint: ep,
        identity,
        peers,
        stats: stats.clone(),
        start: Instant::now(),
        tun_tx,
        networks: Arc::new(DashMap::new()),
        shutdown_token: token.clone(),
        blob_store,
        firewall: shared_firewall,
        protocol_router: protocol_router.clone(),
        dns: DnsManager::new(hostname_table, reverse_table, dns_resolver.clone()),
        mdns_enabled,
        tun_name,
        files,
        connect,
        device_cert,
        device_user_map,
        contact_public,
        active: active.clone(),
        promote_tx,
    });

    // --- Accept loop (ALPN dispatch) + Prometheus metrics ---
    protocol_router.spawn_accept_loop(daemon.endpoint.clone(), token.clone());

    // --- Contact record publisher (ray connect) ---
    if let Ok(pkarr_client) = dht::create_pkarr_client(&daemon.endpoint) {
        spawn_contact_publisher(
            pkarr_client,
            daemon.endpoint.id(),
            token.clone(),
        );
    }
    let metrics_server =
        spawn_metrics_server(stats, daemon.peers.clone(), &daemon.endpoint, token).await;

    tracing::info!(ip = %my_ip, id = %daemon.endpoint.id().fmt_short(), "daemon started");
    Ok((daemon, metrics_server, promote_rx))
}

/// Advertise this endpoint over mDNS (`_rayfish._udp.local`) and log LAN peer
/// discovery events until cancellation. Non-fatal: a failure just means no
/// local discovery.
fn spawn_mdns_discovery(ep: &Endpoint, token: CancellationToken) {
    let mdns = match iroh_mdns_address_lookup::MdnsAddressLookup::builder()
        .service_name("rayfish")
        .advertise(true)
        .build(ep.id())
    {
        Ok(mdns) => mdns,
        Err(e) => {
            tracing::warn!(error = %e, "failed to start mDNS discovery");
            return;
        }
    };
    let Ok(lookups) = ep.address_lookup() else {
        return;
    };
    lookups.add(mdns.clone());
    tracing::info!("mDNS discovery enabled (advertising _rayfish._udp.local)");

    tokio::spawn(async move {
        use futures::StreamExt;
        let mut events = mdns.subscribe().await;
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                event = events.next() => match event {
                    Some(iroh_mdns_address_lookup::DiscoveryEvent::Discovered { endpoint_info, .. }) => {
                        tracing::info!(
                            peer = %endpoint_info.endpoint_id.fmt_short(),
                            "mDNS: peer discovered on LAN"
                        );
                    }
                    Some(iroh_mdns_address_lookup::DiscoveryEvent::Expired { endpoint_id }) => {
                        tracing::info!(
                            peer = %endpoint_id.fmt_short(),
                            "mDNS: peer left LAN"
                        );
                    }
                    None => break,
                    _ => {}
                }
            }
        }
    });
}

/// Register rayfish counters, per-peer gauges, and iroh endpoint metrics, then
/// start the Prometheus HTTP endpoint on `:9090`. The returned guard must be
/// kept alive for the process lifetime; `None` means metrics export is disabled.
async fn spawn_metrics_server(
    stats: Arc<ForwardMetrics>,
    peers: PeerTable,
    endpoint: &Endpoint,
    token: CancellationToken,
) -> Option<iroh_metrics::service::MetricsServer> {
    let mut registry = iroh_metrics::Registry::default();
    registry.register(stats);
    let peer_metrics = Arc::new(crate::stats::PeerMetrics::default());
    registry.register(peer_metrics.clone());
    peer_metrics.spawn_collector(peers, token);
    registry.register_all(endpoint.metrics());

    let metrics_addr: SocketAddr = ([0, 0, 0, 0], 9090).into();
    match iroh_metrics::service::MetricsServer::spawn(metrics_addr, Arc::new(registry)).await {
        Ok(server) => {
            tracing::info!(addr = %server.local_addr(), "metrics server started");
            Some(server)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start metrics server (Prometheus export disabled)");
            None
        }
    }
}

/// Bind the IPC Unix socket and serve client requests until the daemon-wide
/// `token` is cancelled. On shutdown, put the VPN on standby (revert DNS, drop
/// connections, bring the TUN down) and remove the socket file. Each request is
/// handled on its own task so a slow client can't block the accept loop.
async fn serve_ipc(
    daemon: &Arc<MeshManager>,
    mut promote_rx: mpsc::Receiver<String>,
    token: CancellationToken,
) -> Result<()> {
    let socket_path = ipc::socket_path();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path).context("failed to bind IPC socket")?;
    set_socket_permissions(&socket_path);
    tracing::info!(path = %socket_path.display(), "IPC socket listening");

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!("daemon shutting down");
                daemon.deactivate().await;
                let _ = std::fs::remove_file(&socket_path);
                return Ok(());
            }
            // A co-coordinator just persisted an `AdminGrant` key: swap its
            // accept handler to coordinator so it can admit fresh joiners.
            // Idempotent and quick (a synchronous handler swap), so running it
            // inline in the loop is fine.
            Some(net) = promote_rx.recv() => {
                daemon.promote_to_coordinator(&net).await;
            }
            result = listener.accept() => match result {
                Ok((stream, _)) => {
                    let daemon = daemon.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_ipc_client(stream, &daemon).await {
                            tracing::debug!(error = %e, "IPC client error");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "IPC accept error"),
            }
        }
    }
}

/// Make the IPC socket connectable by any local user. Authority is not granted
/// by reaching the socket — every mutating request is authorized per-connection
/// in `check_authorized` via `SO_PEERCRED` (root or the configured operator
/// UID), Tailscale's model — so the file mode only has to permit the connect().
fn set_socket_permissions(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
        unsafe { libc::chmod(c_path.as_ptr(), 0o666) };
        tracing::info!("IPC socket mode 0666 (per-request authorization via peer creds)");
    }
}

async fn handle_ipc_client(stream: UnixStream, daemon: &Arc<MeshManager>) -> Result<()> {
    let peer_cred = stream.peer_cred().ok().map(|c| (c.uid(), c.gid()));
    let mut framed = ipc::framed(stream);
    let req = ipc::recv(&mut framed).await?;
    let resp = daemon.handle_request(req, peer_cred).await;
    ipc::send(&mut framed, resp).await?;
    Ok(())
}

// Background tasks + roster reconvergence live in `mesh/background.rs`.

// ---------------------------------------------------------------------------
// Control-message helpers (daemon-initiated, fire-and-forget)
// ---------------------------------------------------------------------------

/// Open a fresh bi stream and send one control message on it. Every
/// daemon-initiated control message rides its own `open_bi` (the control readers
/// drop the request stream's send half, so a reply can't ride it back). Returns
/// the result so callers can log per-peer failures.
async fn open_and_send(conn: &Connection, msg: &ControlMsg) -> Result<()> {
    let (mut send, _recv) = conn.open_bi().await.context("open control stream")?;
    control::send_msg(&mut send, msg).await
}

async fn send_member_sync(conn: &Connection) {
    let _ = open_and_send(conn, &ControlMsg::MemberSync).await;
}

/// Reply to a `ray ping` probe by echoing `Pong{nonce}` over a fresh stream
/// (see [`open_and_send`] for why the reply can't ride the request stream back).
async fn respond_pong(conn: &Connection, nonce: u64) {
    let _ = open_and_send(conn, &ControlMsg::Pong { nonce }).await;
}

async fn broadcast_member_sync(peers: &PeerTable, exclude_ip: Option<Ipv4Addr>) {
    for (ip, conn) in peers.all_connections() {
        if Some(ip) == exclude_ip {
            continue;
        }
        if let Err(e) = open_and_send(&conn, &ControlMsg::MemberSync).await {
            tracing::warn!(peer_ip = %ip, error = %e, "failed to sync members");
        }
    }
}

async fn broadcast_control_msg(peers: &PeerTable, msg: &ControlMsg) {
    for (_ip, conn) in peers.all_connections() {
        let _ = open_and_send(&conn, msg).await;
    }
}

#[cfg(test)]
mod report_tests {
    use super::{collect_recent_logs, write_bundle};

    #[test]
    fn test_write_bundle_is_valid_targz() {
        let dir = std::env::temp_dir().join(format!("rayfish-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundle.tgz");
        let files = vec![
            ("sysinfo.txt".to_string(), b"rayfish 0.1.0\n".to_vec()),
            (
                "logs/rayfish.log.2026-06-23".to_string(),
                b"hello log\n".to_vec(),
            ),
        ];
        write_bundle(&path, &files).unwrap();

        // Re-read it back through the gzip+tar decoders to prove it's well-formed.
        let f = std::fs::File::open(&path).unwrap();
        let dec = flate2::read::GzDecoder::new(f);
        let mut archive = tar::Archive::new(dec);
        let mut names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["logs/rayfish.log.2026-06-23", "sysinfo.txt"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_collect_recent_logs_missing_dir_is_empty() {
        // The log dir may not exist in CI / non-root test runs; must not panic.
        let _ = collect_recent_logs();
    }
}

#[cfg(test)]
mod accept_handler_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    // Build a minimal NetworkState for use in test AcceptHandler construction.
    fn make_network_state() -> SharedNetworkState {
        let net_secret = iroh::SecretKey::from_bytes(&[1u8; 32]);
        let net_pub = net_secret.public();
        Arc::new(std::sync::RwLock::new(NetworkState {
            members: MemberList::new(),
            approved: ApprovedList::new(),
            snapshot: None,
            network_secret_key: None,
            network_public_key: net_pub,
            network_name: Some("test-net".to_string()),
            mode: GroupMode::Restricted,
            suggested_firewall: SuggestedFirewall::default(),
            reusable_keys: BTreeMap::new(),
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        }))
    }

    /// Throwaway [`MeshCtx`] for accept-handler tests: a fresh blob store and
    /// dummy handles, none of which the constructed handlers exercise here.
    fn sample_mesh_ctx(identity: IrohIdentityProvider, blob_store: FsStore) -> MeshCtx {
        let (tun_tx, _) = tokio::sync::mpsc::channel(1);
        MeshCtx {
            identity,
            peers: PeerTable::new(),
            tun_tx,
            stats: Arc::new(ForwardMetrics::default()),
            blob_store,
            firewall: SharedFirewall::new(crate::firewall::FirewallConfig::default()),
            hostname_table: dns::new_hostname_table(),
            reverse_table: dns::new_reverse_table(),
            device_user_map: peers::DeviceUserMap::new(),
        }
    }

    async fn sample_coordinator_handler() -> AcceptHandler {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = FsStore::load(tmp.path()).await.unwrap();
        let (disconnect_tx, _) = tokio::sync::mpsc::channel(1);
        let my_key = iroh::SecretKey::from_bytes(&[2u8; 32]);
        let my_id = my_key.public();
        AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
            ctx: sample_mesh_ctx(IrohIdentityProvider::new(my_id, 0), blob_store),
            network_name: "test-net".to_string(),
            state: make_network_state(),
            disconnect_tx,
            token: tokio_util::sync::CancellationToken::new(),
            dht_notify: None,
            invite_lock: Arc::new(tokio::sync::Mutex::new(())),
            pending_pongs: Arc::new(DashMap::new()),
        }))
    }

    async fn sample_member_handler() -> AcceptHandler {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = FsStore::load(tmp.path()).await.unwrap();
        let (disconnect_tx, _) = tokio::sync::mpsc::channel(1);
        let my_key = iroh::SecretKey::from_bytes(&[3u8; 32]);
        AcceptHandler::Member(Arc::new(MemberAcceptState {
            ctx: sample_mesh_ctx(IrohIdentityProvider::new(my_key.public(), 0), blob_store),
            network_name: "test-net".to_string(),
            state: make_network_state(),
            disconnect_tx,
            token: tokio_util::sync::CancellationToken::new(),
        }))
    }

    #[tokio::test]
    async fn register_replaces_member_handler_with_coordinator() {
        // AcceptHandler exposes whether it is the coordinator variant.
        assert!(!sample_member_handler().await.is_coordinator());
        assert!(sample_coordinator_handler().await.is_coordinator());
    }

    #[test]
    fn holds_key_implies_coordinator_role() {
        assert_eq!(role_for_key_holder(true), NetworkRole::Coordinator);
        assert_eq!(role_for_key_holder(false), NetworkRole::Member);
    }

    #[test]
    fn choose_path_prefers_selected() {
        use ipc::ConnType::*;
        // The selected path wins even when it isn't the "best" type.
        let classes = [(Relay, false), (Direct, true)];
        assert_eq!(super::choose_path_index(&classes), Some(1));
    }

    #[test]
    fn choose_path_falls_back_to_best_unselected() {
        use ipc::ConnType::*;
        // No path selected: report a concrete path (Direct > Relay > Tor)
        // instead of Unknown, so a live connection never shows `?`.
        let classes = [(Relay, false), (Direct, false), (Tor, false)];
        assert_eq!(super::choose_path_index(&classes), Some(1));

        let only_relay = [(Relay, false)];
        assert_eq!(super::choose_path_index(&only_relay), Some(0));
    }

    #[test]
    fn choose_path_empty_is_none() {
        assert_eq!(super::choose_path_index(&[]), None);
    }

    #[test]
    fn rename_satisfied_exact_and_collision_forms() {
        // Exact match confirms the rename.
        assert!(super::rename_satisfied("scw-iroh", Some("scw-iroh")));
        // Coordinator-assigned collision suffix still confirms it.
        assert!(super::rename_satisfied("alice", Some("alice-1")));
        assert!(super::rename_satisfied("alice", Some("alice-42")));
        // A different name (still the old one, or someone else's) does not.
        assert!(!super::rename_satisfied("scw-iroh", Some("bell")));
        // A look-alike that isn't `name-<digits>` does not.
        assert!(!super::rename_satisfied("alice", Some("alice-bob")));
        assert!(!super::rename_satisfied("alice", Some("alicex")));
        assert!(!super::rename_satisfied("alice", Some("alice-")));
        // No blob entry yet: not satisfied.
        assert!(!super::rename_satisfied("alice", None));
    }

    #[test]
    fn promote_is_idempotent_decision() {
        // Re-registering an already-coordinator network is a no-op decision.
        assert!(should_promote(NetworkRole::Member));
        assert!(!should_promote(NetworkRole::Coordinator));
    }
}

#[cfg(test)]
mod coordinator_dial_order_tests {
    use super::*;
    use crate::membership::{Member, derive_ip};

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        let key = iroh::SecretKey::from(key_bytes);
        key.public()
    }

    #[test]
    fn dial_order_puts_minter_first_then_other_coordinators() {
        let (a, b, c, me) = (test_id(1), test_id(2), test_id(3), test_id(9));
        let mk = |id, coord| Member {
            identity: id,
            ip: derive_ip(&id),
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
        };
        let members = vec![mk(a, true), mk(b, true), mk(c, false), mk(me, true)];
        // minter = b: b first, then the other coordinator a, never c (not coord), never me.
        assert_eq!(super::coordinator_dial_order(b, &members, me), vec![b, a]);
    }

    #[test]
    fn admin_grant_key_accepted_only_when_public_matches_network() {
        // The real network key: its public half is the network pubkey.
        let net_secret = iroh::SecretKey::from({
            let mut b = [0u8; 32];
            b[0] = 42;
            b
        });
        let net_pubkey = net_secret.public();

        // A genuine grant carries the real secret → accepted.
        assert!(super::admin_grant_key_valid(
            net_secret.to_bytes(),
            net_pubkey
        ));

        // A forged grant carries an attacker-chosen key whose public half does
        // not match the network pubkey → rejected (no roster lookup needed).
        let forged = iroh::SecretKey::from({
            let mut b = [0u8; 32];
            b[0] = 7;
            b
        });
        assert!(!super::admin_grant_key_valid(forged.to_bytes(), net_pubkey));
    }

    #[test]
    fn gossip_targets_are_coordinator_peers_only() {
        let (a, b, c) = (test_id(1), test_id(2), test_id(3));
        let mk = |id, coord| Member {
            identity: id,
            ip: derive_ip(&id),
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
        };
        let members = vec![mk(a, true), mk(b, false), mk(c, true)];
        let me = a;
        // gossip to other coordinators only: c (not b, not me).
        assert_eq!(super::gossip_targets(&members, me), vec![c]);
    }
}

#[cfg(test)]
mod dial_fallback_tests {
    use super::*;

    #[test]
    fn dial_fallback_stops_on_first_welcome() {
        // outcomes simulate dialing in order: first errors, second welcomes, third never tried.
        let outcomes = vec![
            DialOutcome::Unreachable,
            DialOutcome::Welcomed,
            DialOutcome::Denied,
        ];
        let (idx, welcomed) = pick_first_welcome(&outcomes);
        assert_eq!((idx, welcomed), (1, true));
    }

    #[test]
    fn dial_fallback_reports_failure_when_all_exhausted() {
        let outcomes = vec![DialOutcome::Unreachable, DialOutcome::Denied];
        let (_idx, welcomed) = pick_first_welcome(&outcomes);
        assert!(!welcomed);
    }
}
