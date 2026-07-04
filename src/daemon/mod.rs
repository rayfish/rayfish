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
//!   runtime by [`DaemonState::activate`] / [`DaemonState::deactivate`], driven
//!   by the `Up` / `Down` IPC commands, and tracked by [`DaemonState::active`].
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
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};

use anyhow::{Context, Result};
use iroh::address_lookup::PkarrRelayClient;
use iroh::endpoint::{Connection, Endpoint, SendStream, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointId, SecretKey};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, HashAndFormat};
use iroh_mdns_address_lookup::DiscoveryEvent;
use iroh_metrics::service::MetricsServer;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
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
// The desktop TUN device and its CGNAT pre-flight check don't exist on Android,
// where the packet interface is a `VpnService` fd supplied from Kotlin.
#[cfg(not(target_os = "android"))]
use crate::tun::{self, check_cgnat_conflict};
#[cfg(feature = "desktop")]
use crate::update;
use ray_proto::SuggestedFirewall;

// `DaemonState`'s IPC handlers are split by domain into the `handlers/`
// submodule; see `handlers/mod.rs`. Each holds an additional `impl DaemonState`
// block. Nested a level down so the module names can be the clean domain names
// without colliding with the `use crate::{firewall, dns, …}` aliases above.
mod handlers;

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
/// per daemon via [`DaemonState::mesh_ctx`]; a new daemon-wide dependency is one
/// field here rather than one parameter at every call site.
#[derive(Clone)]
pub(crate) struct MeshCtx {
    identity: IrohIdentityProvider,
    peers: PeerTable,
    tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
    stats: Arc<ForwardMetrics>,
    blob_store: FsStore,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
    /// Peers removed from a network's roster (via `ray kick` or a stale-entry
    /// prune during reconverge), keyed by `(network, transport id)`. A member
    /// closes such a peer's connection but can't see its own close code, so its
    /// reconnect loop would re-dial the removed peer (which still lists it) and
    /// re-form the link. The reconnect loop consumes an entry here to skip that
    /// one reconnect. Populated in [`reconverge_and_apply`] and the kick handler.
    pruned_peers: Arc<DashSet<(String, EndpointId)>>,
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

/// A paired device is auto-admitted into a closed network only when its device
/// cert is signed by this coordinator's own owner identity. The cert's
/// signature is verified by the caller before this check.
fn owner_admits(device_cert: Option<&control::DeviceCert>, own_identity: EndpointId) -> bool {
    device_cert.map(|c| c.user_identity) == Some(own_identity)
}

struct CoordinatorAcceptState {
    ctx: MeshCtx,
    network_name: String,
    state: SharedNetworkState,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    dht_notify: Option<Arc<Notify>>,
    /// Shared with this network's [`NetworkHandle`]; see its `invite_lock`.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    /// Shared with the router; lets the control reader resolve `ray ping` Pongs.
    pending_pongs: Arc<DashMap<u64, oneshot::Sender<()>>>,
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
                // `device_cert` is moved into the pending-join queue below.
                if owner_admits(device_cert.as_ref(), self.ctx.identity.local_identity()) {
                    self.admit_peer(
                        conn, send, remote_id, peer_ip, hostname, device_cert, false, false,
                    )
                    .await;
                    return;
                }
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
        send: SendStream,
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
    async fn deny(&self, conn: &Connection, mut send: SendStream, reason: String) {
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
        mut send: SendStream,
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

struct PendingFile {
    id: u64,
    from: EndpointId,
    filename: String,
    size: u64,
    mime_type: String,
    blob_hash: blake3::Hash,
}

/// A pending incoming `ray connect` request, awaiting `ray connections approve`.
/// Keyed by the requester's transport endpoint id (not contact id) so it
/// survives the requester rotating their contact key.
#[derive(Clone)]
struct PendingConnect {
    from_contact_id: EndpointId,
    from_endpoint: EndpointId,
    hostname: Option<String>,
    requested_at: Instant,
}

struct ProtocolRouter {
    blobs: BlobsProtocol,
    handlers: DashMap<Vec<u8>, Arc<MeshProtocol>>,
    pending_files: Arc<std::sync::Mutex<Vec<PendingFile>>>,
    file_id_counter: Arc<AtomicU64>,
    /// Nudge sent after each newly-queued `PendingFile` (carrying its id) so the
    /// auto-accept worker can evaluate it against the own-devices policy. The
    /// router stays policy-free; all trust logic lives on `DaemonState`.
    new_file_tx: mpsc::UnboundedSender<u64>,
    pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    secret_key: SecretKey,
    /// `ray connect` requests received on `CONNECT_ALPN`, awaiting approval.
    /// Keyed by the requester's transport endpoint id.
    pending_connects: Arc<DashMap<EndpointId, PendingConnect>>,
    /// Approved connect requests: requester endpoint id → (room id, coordinator).
    /// The `CONNECT_ALPN` handler replies `Approved` from here when the requester
    /// re-dials after `ray connections approve`.
    approved_connects: Arc<DashMap<EndpointId, (EndpointId, EndpointId)>>,
    /// Peer endpoints we have sent an outgoing `ray connect` request to. Used by
    /// the concurrency tie-break: if both peers requested *and* approved each
    /// other, only the higher endpoint id mints, avoiding a duplicate network.
    outgoing_connects: Arc<DashSet<EndpointId>>,
    /// In-flight `ray ping` probes, keyed by nonce. The control reader fires the
    /// oneshot when the matching `Pong` arrives so the ping handler can measure
    /// round-trip time. Cloned into both control readers.
    pending_pongs: Arc<DashMap<u64, oneshot::Sender<()>>>,
}

impl ProtocolRouter {
    fn new(
        blobs: BlobsProtocol,
        secret_key: SecretKey,
        pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
        new_file_tx: mpsc::UnboundedSender<u64>,
    ) -> Self {
        Self {
            blobs,
            handlers: DashMap::new(),
            pending_files: Arc::new(std::sync::Mutex::new(Vec::new())),
            file_id_counter: Arc::new(AtomicU64::new(1)),
            new_file_tx,
            pairing_secret,
            secret_key,
            pending_connects: Arc::new(DashMap::new()),
            approved_connects: Arc::new(DashMap::new()),
            outgoing_connects: Arc::new(DashSet::new()),
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

    /// `FILES_ALPN`: read a single `FileOffer` and queue it for `ray files`.
    /// Rejects offers whose claimed sender doesn't match the dialing identity.
    async fn accept_file_offer(&self, conn: Connection) {
        let pending = self.pending_files.clone();
        let counter = self.file_id_counter.clone();
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((_send, mut recv)) => {
                match control::recv_msg(&mut recv).await {
                    Ok(control::ControlMsg::FileOffer {
                        from,
                        filename,
                        size,
                        mime_type,
                        blob_hash,
                    }) => {
                        if from == remote_id {
                            let id = counter.fetch_add(1, Ordering::Relaxed);
                            tracing::info!(from = %from.fmt_short(), filename = %filename, size, "file offer received");
                            pending.lock().unwrap().push(PendingFile {
                                id,
                                from,
                                filename,
                                size,
                                mime_type,
                                blob_hash,
                            });
                            // Nudge the auto-accept worker; it decides whether the
                            // sender is one of our own devices on an enabled network.
                            let _ = self.new_file_tx.send(id);
                        } else {
                            tracing::warn!(claimed = %from.fmt_short(), actual = %remote_id.fmt_short(), "file offer identity mismatch");
                        }
                    }
                    Ok(other) => {
                        tracing::warn!(msg = ?other, "unexpected control message on FILES_ALPN");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read file offer");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for file offer");
            }
        }
    }

    /// `PAIR_ALPN`: complete a device-pairing handshake. Verifies the dialer's
    /// secret against the active pairing session and, on match, signs and returns
    /// a `DeviceCert` binding the new device key to our identity.
    async fn accept_pair_request(&self, conn: Connection) {
        let pairing_secret = self.pairing_secret.clone();
        let secret_key = self.secret_key.clone();
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                // Read length-prefixed PairMsg::Request
                let mut len_buf = [0u8; 4];
                if let Err(e) = recv.read_exact(&mut len_buf).await {
                    tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read pair request length");
                    return;
                }
                let body_len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; body_len];
                if let Err(e) = recv.read_exact(&mut body).await {
                    tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read pair request body");
                    return;
                }
                let request: control::PairMsg = match rmp_serde::from_slice(&body) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to decode pair request");
                        return;
                    }
                };
                match request {
                    control::PairMsg::Request {
                        secret,
                        device_pubkey,
                    } => {
                        // Verify the secret matches the stored pairing secret
                        let stored = pairing_secret.lock().unwrap().take();
                        match stored {
                            Some(expected) if expected == secret => {
                                // Sign the device's public key
                                // Share our saved networks so the new device can auto-join them. Only
                                // networks with a known public key (skips freshly created, unsynced ones).
                                let networks: Vec<control::PairNetwork> = match config::load() {
                                    Ok(cfg) => cfg
                                        .networks
                                        .into_iter()
                                        .filter_map(|n| {
                                            n.network_public_key.map(|k| control::PairNetwork {
                                                name: n.name,
                                                network_key: k.to_string(),
                                            })
                                        })
                                        .collect(),
                                    Err(_) => Vec::new(),
                                };
                                let cert = control::DeviceCert::create(&secret_key, &device_pubkey);
                                let response = control::PairMsg::Response { cert, networks };
                                let response_bytes = match rmp_serde::to_vec_named(&response) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        tracing::warn!(error = %e, "failed to encode pair response");
                                        return;
                                    }
                                };
                                let len = (response_bytes.len() as u32).to_be_bytes();
                                if let Err(e) = send.write_all(&len).await {
                                    tracing::warn!(error = %e, "failed to send pair response length");
                                    return;
                                }
                                if let Err(e) = send.write_all(&response_bytes).await {
                                    tracing::warn!(error = %e, "failed to send pair response body");
                                    return;
                                }
                                // Flush before the connection drops: finish the stream and wait
                                // (briefly) for the joiner to close. Returning here drops `conn`,
                                // which RSTs the stream — without this the joiner often sees
                                // "connection lost" and never receives the cert even though we
                                // logged success below.
                                let _ = send.finish();
                                let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed())
                                    .await;
                                tracing::info!(device = %device_pubkey.fmt_short(), "device paired successfully");
                            }
                            Some(_) => {
                                tracing::warn!(peer = %remote_id.fmt_short(), "pairing secret mismatch");
                            }
                            None => {
                                tracing::warn!(peer = %remote_id.fmt_short(), "no pairing session active");
                            }
                        }
                    }
                    _ => {
                        tracing::warn!(peer = %remote_id.fmt_short(), "unexpected pair message type");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for pairing");
            }
        }
    }

    /// `CONNECT_ALPN`: handle a `ray connect` friend request. Binds the request
    /// to the dialing identity, replies `Approved` if already accepted
    /// (idempotent), else queues it as `Pending` for `ray connections approve`.
    async fn accept_connect_request(&self, conn: Connection) {
        let pending = self.pending_connects.clone();
        let approved = self.approved_connects.clone();
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let request: control::ConnectMsg = match control::recv_framed(&mut recv).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read connect request");
                        return;
                    }
                };
                if let control::ConnectMsg::Request {
                    from_contact_id,
                    from_endpoint,
                    hostname,
                } = request
                {
                    // Bind the request to the dialing identity: the
                    // endpoint we pre-approve must be the one that dialed.
                    if from_endpoint != remote_id {
                        tracing::warn!(claimed = %from_endpoint.fmt_short(), actual = %remote_id.fmt_short(), "connect request endpoint mismatch");
                        let _ = control::send_framed(
                            &mut send,
                            &control::ConnectMsg::Denied {
                                reason: "endpoint mismatch".to_string(),
                            },
                        )
                        .await;
                        return;
                    }
                    // Already approved? Reply with the minted room id so
                    // a re-dialing requester joins it (idempotent).
                    let already = approved.get(&from_endpoint).map(|r| *r.value());
                    let reply = if let Some((room_id, coordinator)) = already {
                        control::ConnectMsg::Approved {
                            room_id,
                            coordinator,
                        }
                    } else {
                        pending.insert(
                            from_endpoint,
                            PendingConnect {
                                from_contact_id,
                                from_endpoint,
                                hostname,
                                requested_at: Instant::now(),
                            },
                        );
                        tracing::info!(from = %from_contact_id.fmt_short(), endpoint = %from_endpoint.fmt_short(), "connect request received");
                        control::ConnectMsg::Pending
                    };
                    if let Err(e) = control::send_framed(&mut send, &reply).await {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to send connect reply");
                        return;
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                } else {
                    tracing::warn!(peer = %remote_id.fmt_short(), "unexpected connect message type");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for connect");
            }
        }
    }

    fn spawn_accept_loop(
        self: &Arc<Self>,
        endpoint: Endpoint,
        cancel: CancellationToken,
    ) -> JoinHandle<()> {
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
                                a if a == transport::FILES_ALPN => router.accept_file_offer(conn).await,
                                a if a == PAIR_ALPN => router.accept_pair_request(conn).await,
                                a if a == transport::CONNECT_ALPN => router.accept_connect_request(conn).await,
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
pub(crate) type SharedNetworkState = Arc<RwLock<NetworkState>>;

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
    dht_notify: Option<Arc<Notify>>,
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
/// Handles for the packet-forwarding tasks a [`DaemonState::attach_tun`] call
/// spawns (the TUN writer and the `run_mesh` reader loop), plus a dedicated
/// cancellation token so the data plane can be stopped independently of a full
/// daemon shutdown (used by [`DaemonState::detach_tun`] / `ray-mobile`'s `down`).
struct TunTasks {
    /// Cancels the `run_mesh` reader loop without touching `shutdown_token`.
    cancel: CancellationToken,
    /// The TUN writer task (`spawn_tun_writer`).
    writer: JoinHandle<()>,
    /// The `run_mesh` reader loop task.
    mesh: JoinHandle<()>,
}

pub struct DaemonState {
    endpoint: Endpoint,
    identity: IrohIdentityProvider,
    peers: PeerTable,
    stats: Arc<ForwardMetrics>,
    /// When the daemon process started, used for uptime in diagnostics.
    start: Instant,
    /// Sender half of the current TUN write channel, in a swappable cell.
    /// [`DaemonState::attach_tun`] creates a fresh channel on every attach and
    /// stores the new sender here, so incoming send-sites (peer readers, DNS
    /// injection) always resolve the live writer via `tun_tx.load()`. This is
    /// what makes the VPN off/on toggle work: `detach_tun` stops the writer, and
    /// the next `attach_tun` swaps in a new sender feeding a fresh writer. On
    /// desktop the daemon attaches exactly once, so the cell holds one sender for
    /// its whole life and is never swapped.
    tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
    networks: Arc<DashMap<String, NetworkHandle>>,
    shutdown_token: CancellationToken,
    blob_store: FsStore,
    firewall: SharedFirewall,
    protocol_router: Arc<ProtocolRouter>,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    mdns_enabled: bool,
    /// Whether this node opted into automatic stable updates (`ray auto-update
    /// on` / `ray install --auto-update`). Read at startup; when set, `run_daemon`
    /// spawns the periodic update task. Echoed back in `ray status`.
    auto_update: bool,
    /// Name of the OS TUN device (desktop) or a placeholder until a packet
    /// interface is attached. Interior-mutable because on embedders (mobile) the
    /// interface is attached after construction via [`DaemonState::attach_tun`],
    /// while on desktop it is set once at boot.
    tun_name: std::sync::Mutex<String>,
    /// Handles for the packet-forwarding tasks spawned by
    /// [`DaemonState::attach_tun`], kept so a future `down()`/detach can stop them.
    tun_tasks: std::sync::Mutex<Option<TunTasks>>,
    /// Promotion-channel receiver drained by [`serve_ipc`]. Stored here so the
    /// headless builder can construct the daemon and hand the receiver back to
    /// [`run_daemon`] afterwards.
    promote_rx: std::sync::Mutex<Option<mpsc::Receiver<String>>>,
    /// Prometheus metrics-server guard. Kept alive for the daemon's whole lifetime
    /// (dropping it stops the export); `None` if the server failed to bind.
    _metrics_server: std::sync::Mutex<Option<iroh_metrics::service::MetricsServer>>,
    pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    device_cert: Option<control::DeviceCert>,
    device_user_map: peers::DeviceUserMap,
    /// Peers removed from a roster whose reconnect should be suppressed once.
    /// Shared into [`MeshCtx::pruned_peers`]; see that field for the mechanism.
    pruned_peers: Arc<DashSet<(String, EndpointId)>>,
    /// This node's contact id (`ray connect`): the public half of the rotatable
    /// contact key. The secret lives in config (read fresh by the publisher and
    /// `rotate_contact` so rotation needs no restart); only the public id is
    /// surfaced here for `ray status` / `ray contact id`.
    contact_public: EndpointId,
    /// Whether the VPN is currently active (TUN up, networks connected) or on
    /// standby. Toggled by the `Up`/`Down` IPC commands.
    active: Arc<AtomicBool>,
    /// The system-DNS configurator owned while active, so `Down` can revert it.
    dns_configurator: Arc<std::sync::Mutex<Option<Box<dyn dns_config::DnsConfigurator>>>>,
    /// In-daemon Magic DNS resolver (answers `.ray` queries intercepted via TUN).
    resolver: Arc<crate::dns_resolver::Resolver>,
    /// Cancellation token for the `run_resolv_reassert` task (Linux direct mode).
    dns_reassert_token: std::sync::Mutex<Option<CancellationToken>>,
    /// Live per-network SSH allow lists for the embedded mesh SSH server. Swapped
    /// atomically on `ray firewall ssh allow/deny`, so a running listener picks up
    /// changes without restart. See [`crate::ssh`]. Desktop-only: the embedded
    /// mesh SSH server isn't part of the Android build.
    #[cfg(feature = "desktop")]
    ssh_authz: crate::ssh::SshAuthz,
    /// Cancellation token for the running SSH listeners (`None` when off / on
    /// standby). Set by [`DaemonState::start_ssh`], cleared by `stop_ssh`.
    // The only readers/writers (`start_ssh`/`stop_ssh`) are desktop-only, so on a
    // `--no-default-features` (Android) build the field is inert; silence the
    // resulting dead-code warning there rather than dropping the field.
    #[cfg_attr(not(feature = "desktop"), allow(dead_code))]
    ssh_token: std::sync::Mutex<Option<CancellationToken>>,
    /// Promotion signal: a co-coordinator's per-peer control reader sends the
    /// network name here after persisting an `AdminGrant` key, and the main
    /// daemon loop ([`serve_ipc`]) drains it into
    /// [`DaemonState::promote_to_coordinator`]. The reader holds only field
    /// clones (not the full `DaemonState`), so it can't promote itself — hence
    /// the channel hand-off to the loop that does hold the `Arc<DaemonState>`.
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

impl DaemonState {
    /// The device cert to present when joining, preferring the on-disk copy so a
    /// join issued right after pairing (same process, no restart) carries the
    /// freshly stored cert rather than the value loaded at startup.
    pub fn current_device_cert(&self) -> Option<control::DeviceCert> {
        identity::load_device_cert()
            .ok()
            .flatten()
            .or_else(|| self.device_cert.clone())
    }

    /// Cancel the daemon-wide shutdown token, tearing down every network's run
    /// loop, the accept loop, and the data-plane forward tasks. The iroh
    /// endpoint closes once the last `Arc<DaemonState>` clone drops as those
    /// tasks wind down. Same effect as the desktop `IpcMessage::Shutdown`; used
    /// by mobile to go fully offline when the tunnel is disabled.
    pub fn trigger_shutdown(&self) {
        self.shutdown_token.cancel();
    }

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
            hostname_table: self.hostname_table.clone(),
            reverse_table: self.reverse_table.clone(),
            device_user_map: self.device_user_map.clone(),
            pruned_peers: self.pruned_peers.clone(),
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
        let tun_name = self.tun_name.lock().unwrap().clone();
        dns_config::update_search_domains(&network_names, &tun_name).await;
    }

    /// Attach a packet interface to a headless [`DaemonState`] and start the data
    /// plane's forwarding tasks: the TUN writer (`spawn_tun_writer`) and the mesh
    /// forwarding loop (`run_mesh`, reading `reader` and using the state's
    /// peers/firewall/stats/resolver).
    ///
    /// A fresh `tun_tx`/`tun_rx` channel is created on every call: the new
    /// receiver feeds the writer, and the new sender is stored in the `tun_tx`
    /// cell so incoming send-sites (peer readers, DNS injection) resolve the live
    /// writer via `tun_tx.load()`. This makes re-attach work: after a
    /// [`detach_tun`] the next `attach_tun` swaps in a new sender and a new writer,
    /// so forwarding resumes. This is the exact VPN off/on toggle path on Android.
    ///
    /// This is the embedding API (used by `ray-mobile` and future embedders) and
    /// is also how `run_daemon` wires the desktop OS TUN device. The forwarding
    /// loop runs under a child of `shutdown_token`, and its handles are stored so a
    /// later `down()`/detach can stop the data plane without tearing down the whole
    /// daemon. Desktop attaches exactly once, so the cell is never swapped there.
    pub async fn attach_tun<R: crate::tun::TunRead, W: crate::tun::TunWrite>(
        self: &Arc<Self>,
        reader: R,
        writer: W,
    ) {
        // Fresh channel per attach. The previous writer (if any) was torn down by
        // `detach_tun`, which dropped the old receiver; swapping in the new sender
        // reconnects every incoming send-site to this writer.
        let (new_tx, new_rx) = mpsc::channel::<Bytes>(256);
        self.tun_tx.store(Arc::new(new_tx.clone()));

        // A dedicated child token so the data plane can be stopped independently
        // of a full daemon shutdown; it still cancels when `shutdown_token` does.
        let cancel = self.shutdown_token.child_token();
        let writer_handle = forward::spawn_tun_writer(writer, new_rx, self.active.clone());
        let mesh_handle = {
            let peers = self.peers.clone();
            let firewall = self.firewall.clone();
            let cancel = cancel.clone();
            let stats = self.stats.clone();
            let resolver = self.resolver.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    forward::run_mesh(reader, peers, firewall, cancel, stats, resolver, new_tx).await
                {
                    tracing::warn!(error = %e, "mesh forwarding loop exited with error");
                }
            })
        };

        // Self-healing: if `attach_tun` is called twice without an intervening
        // `detach_tun`, stop the previous data plane before installing the new
        // one. `JoinHandle::drop` detaches rather than aborts, so without this
        // the old writer + `run_mesh` loop would keep running forever on the old
        // fds (a leak of two live mesh loops). On the normal detach->attach path
        // `detach_tun` already took the old tasks, so `replace` returns `None`.
        let new_tasks = TunTasks {
            cancel,
            writer: writer_handle,
            mesh: mesh_handle,
        };
        let old = self.tun_tasks.lock().unwrap().replace(new_tasks);
        if let Some(old) = old {
            old.cancel.cancel();
            old.writer.abort();
            old.mesh.abort();
        }
    }

    /// Part of the embedding API (used by `ray-mobile`'s `down`): stop the
    /// packet-forwarding data plane started by [`attach_tun`] (the TUN writer and
    /// the `run_mesh` reader loop) WITHOUT tearing down the control plane. The
    /// iroh endpoint and every network connection stay live, so the node remains
    /// reachable to peers and keeps receiving roster/blob updates; only local
    /// packet forwarding over the attached interface stops. Cancelling the loop's
    /// child token and aborting the tasks drops the reader/writer, closing the
    /// underlying fds. Idempotent: a no-op if no interface is attached.
    pub fn detach_tun(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(tasks) = self.tun_tasks.lock().unwrap().take() {
            tasks.cancel.cancel();
            tasks.writer.abort();
            tasks.mesh.abort();
        }
    }

    /// Point the Magic DNS resolver at the given upstream servers so non-`.ray`
    /// queries are forwarded there instead of refused. The desktop path captures
    /// upstreams from the system resolver config; Android has none to capture, so
    /// the platform reads the underlying network's DNS servers and passes them in.
    pub fn set_dns_upstreams(&self, servers: Vec<Ipv4Addr>) {
        self.resolver.set_upstreams(servers);
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
        dht_notify: Option<Arc<Notify>>,
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
    pub(crate) fn check_authorized(
        req: &IpcMessage,
        peer_cred: Option<(u32, u32)>,
    ) -> Option<IpcMessage> {
        // Reads are available to everyone.
        if matches!(
            req,
            IpcMessage::Status
                | IpcMessage::Report
                | IpcMessage::FirewallShow
                | IpcMessage::FirewallSuggestions { .. }
                | IpcMessage::FirewallPending { .. }
                | IpcMessage::FirewallSshShow
                | IpcMessage::ListFiles
                | IpcMessage::Connections
                | IpcMessage::ContactId
                | IpcMessage::Ping { .. }
                | IpcMessage::Netcheck
                | IpcMessage::AliasList { .. }
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
                auto_accept_files,
            } => {
                self.join_network(
                    &network_key,
                    name.as_deref(),
                    hostname,
                    invite,
                    coordinator,
                    auto_accept_firewall,
                    auto_accept_files,
                )
                .await
            }
            IpcMessage::Leave { name } => self.leave_network(&name).await,
            IpcMessage::Nuke { name, force } => self.nuke_network(&name, force).await,
            IpcMessage::Kick { network, peer } => self.kick_member(&network, &peer).await,
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
            } => {
                self.firewall_add(
                    direction,
                    action,
                    protocol,
                    port.as_deref(),
                    peer.as_deref(),
                    network.as_deref(),
                )
                .await
            }
            IpcMessage::FirewallRemove { index } => self.firewall_remove(index),
            IpcMessage::FirewallShow => self.firewall_show(),
            IpcMessage::FirewallDefault { action } => self.firewall_default(action),
            IpcMessage::FirewallReject { enabled } => self.firewall_reject(enabled),
            IpcMessage::FirewallSetEnabled { enabled } => self.firewall_set_enabled(enabled),
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
            IpcMessage::FilesAutoAccept { network, enabled } => {
                self.files_auto_accept(&network, enabled).await
            }
            IpcMessage::FirewallSshSet { enabled } => self.firewall_ssh_set(enabled),
            IpcMessage::FirewallSshAllow {
                network,
                peer,
                users,
                allow,
            } => self.firewall_ssh_allow(&network, &peer, users, allow).await,
            IpcMessage::FirewallSshShow => self.firewall_ssh_show(),
            IpcMessage::SetHostname { network, hostname } => {
                self.set_hostname(&network, &hostname).await
            }
            IpcMessage::AliasSet {
                network,
                identity,
                alias,
            } => self.set_alias(&network, &identity, &alias),
            IpcMessage::AliasRemove { network, alias } => self.remove_alias(&network, &alias),
            IpcMessage::AliasList { network } => self.list_aliases(&network),
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

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    pub async fn set_hostname(&self, network: &str, hostname: &str) -> IpcMessage {
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
        dns::remove_hostname_by_ip(&self.hostname_table, &self.reverse_table, network, my_ip).await;
        dns::update_hostname(
            &self.hostname_table,
            &self.reverse_table,
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
                    device_cert: self.current_device_cert(),
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
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(&dir) {
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
fn write_bundle(path: &Path, files: &[(String, Vec<u8>)]) -> std::io::Result<()> {
    let file = File::create(path)?;
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
    #[cfg(not(target_os = "android"))]
    check_cgnat_conflict()?;

    // Build the always-on infrastructure without a packet interface, then attach
    // the desktop OS TUN device below. The headless builder is the same one
    // `build_headless()` exposes to embedders (mobile), so both paths share
    // identical construction.
    let daemon = build_daemon(token.clone(), stats).await?;

    // Attach the real OS TUN device: create it, record its name, and spawn the
    // writer + `run_mesh` forwarding loop. On Android the packet interface is a
    // `VpnService` fd attached later by `ray-mobile` via `attach_tun`, so this is
    // skipped here.
    #[cfg(not(target_os = "android"))]
    {
        let my_ipv6 = derive_ipv6(&daemon.identity.local_identity());
        let (tun_reader, tun_writer, tun_name) = tun::create(daemon.identity.local_ip(), my_ipv6)
            .await
            .context("failed to create TUN device")?;
        *daemon.tun_name.lock().unwrap() = tun_name;
        daemon.attach_tun(tun_reader, tun_writer).await;
    }

    // Connect the control plane (mesh connections) once, for the daemon's
    // whole lifetime, then bring the data plane up. `ray up`/`ray down` toggle
    // only the data plane after this; connections persist across `down` so the
    // node stays online to peers.
    daemon.connect_all_networks().await;
    daemon.activate(None).await;

    // The promotion receiver was stashed on the daemon by the builder; take it
    // back to drive the IPC loop.
    let promote_rx = daemon
        .promote_rx
        .lock()
        .unwrap()
        .take()
        .expect("promote_rx present after build");

    // Opt-in automatic updates: a single daemon-wide task that periodically
    // checks for a newer stable release and swaps + restarts onto it. Desktop-only
    // (the self-replacing updater is not built into the Android lib).
    #[cfg(feature = "desktop")]
    if daemon.auto_update {
        spawn_auto_update(daemon.shutdown_token.clone());
    }

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
/// router, and metrics server. Returns the shared [`DaemonState`] — still on
/// standby, so the caller is expected to run [`DaemonState::activate`] — and the
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

/// Construct a headless [`DaemonState`] for an embedder (used by `ray-mobile`
/// and future embedders). Builds the identity, iroh endpoint, blob store, Magic
/// DNS resolver + membership pollers, protocol router/accept loop, contact
/// publisher, and metrics server, then connects saved networks. It does NOT open
/// the Unix-socket IPC server and does NOT create a real OS TUN device or spawn a
/// forwarding loop; the caller supplies a packet interface via
/// [`DaemonState::attach_tun`]. The returned daemon is on standby (no data
/// plane), so bring it up with [`DaemonState::activate`].
///
/// This is the same construction path `run_daemon` uses on desktop, so desktop
/// and embedder builds stay in lock-step.
pub async fn build_headless() -> Result<Arc<DaemonState>> {
    let token = CancellationToken::new();
    let stats = Arc::new(ForwardMetrics::default());
    let daemon = build_daemon(token, stats).await?;
    // Bring the saved networks' control plane up, matching `run_daemon`.
    daemon.connect_all_networks().await;
    Ok(daemon)
}

/// Build all always-on daemon infrastructure WITHOUT a packet interface or the
/// Unix-socket IPC server: identity, iroh endpoint, blob store, firewall, Magic
/// DNS resolver, mDNS discovery, protocol router/accept loop, contact publisher,
/// and metrics server. The returned [`DaemonState`] is on standby (no data
/// plane). Attach a TUN with [`DaemonState::attach_tun`], connect saved networks
/// with [`DaemonState::connect_all_networks`], then bring the data plane up with
/// [`DaemonState::activate`]. The TUN write channel's receiver and the promotion
/// receiver are stashed on the state for the caller to consume.
///
/// Shared by [`run_daemon`] (desktop) and [`build_headless`] (embedders).
async fn build_daemon(token: CancellationToken, stats: Arc<ForwardMetrics>) -> Result<Arc<DaemonState>> {
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
    // Register our mesh addresses for the userspace SSH port NAT (mesh `:22`
    // <-> the embedded server's listen port). Stays inactive until `ssh on`.
    forward::init_ssh_nat(
        my_ip,
        derive_ipv6(&identity.local_identity()),
        crate::forward::SSH_LISTEN_PORT,
    );

    // --- iroh endpoint (one ALPN per saved network + the blobs ALPN) ---
    let mut app_config = config::load()?;
    // Point the pkarr client at the configured discovery-DNS server (if any)
    // before any record publish/resolve happens.
    dht::set_discovery_override(&app_config.discovery_dns);
    // Lazily generate + persist this node's contact key (`ray connect`). The
    // secret stays in config; only its public id is held in `DaemonState`.
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

    // --- Packet interface: deferred to `attach_tun` ---
    // No OS TUN device is created here. On desktop `run_daemon` creates the real
    // device and calls `attach_tun`; on embedders (mobile) the `VpnService` fd is
    // attached the same way. `tun_name` starts as a placeholder and is overwritten
    // when a real interface is attached.
    let tun_name = String::from("rayfish");
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
    // The `tun_tx` cell starts with a placeholder sender whose receiver is
    // dropped immediately: no real channel exists until `attach_tun` creates one
    // and swaps it in. Any send before the first attach (there are none in
    // practice) is a harmless dropped packet. `attach_tun` (desktop: once at
    // boot; mobile: on each `up()`) recreates the channel and stores the live
    // sender here.
    let tun_tx = {
        let (placeholder_tx, _placeholder_rx) = mpsc::channel::<Bytes>(1);
        Arc::new(arc_swap::ArcSwap::from_pointee(placeholder_tx))
    };
    let device_user_map = peers::DeviceUserMap::new();

    // --- Magic DNS resolver + optional mDNS local discovery ---
    let hostname_table = dns::new_hostname_table();
    let reverse_table = dns::new_reverse_table();
    let dns_resolver = Arc::new(crate::dns_resolver::Resolver::new(
        hostname_table.clone(),
        reverse_table.clone(),
    ));
    let mdns_enabled = app_config.mdns_enabled;
    if mdns_enabled {
        spawn_mdns_discovery(&ep, token.clone());
    } else {
        tracing::info!("mDNS discovery disabled");
    }
    let auto_update = app_config.auto_update;

    // --- Protocol router + the shared DaemonState ---
    let pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>> =
        Arc::new(std::sync::Mutex::new(None));
    // Auto-accept worker channel: the router nudges this with each newly-queued
    // file offer id; the worker (spawned once the daemon exists) evaluates it.
    let (new_file_tx, new_file_rx) = mpsc::unbounded_channel::<u64>();
    let protocol_router = Arc::new(ProtocolRouter::new(
        blobs_proto,
        key.clone(),
        pairing_secret.clone(),
        new_file_tx,
    ));
    // Promotion channel: a co-coordinator's control reader signals the main
    // daemon loop to swap in the coordinator accept handler on `AdminGrant`.
    let (promote_tx, promote_rx) = mpsc::channel::<String>(16);
    let daemon = Arc::new(DaemonState {
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
        hostname_table,
        reverse_table,
        mdns_enabled,
        auto_update,
        tun_name: std::sync::Mutex::new(tun_name),
        tun_tasks: std::sync::Mutex::new(None),
        promote_rx: std::sync::Mutex::new(Some(promote_rx)),
        _metrics_server: std::sync::Mutex::new(None),
        pairing_secret,
        device_cert,
        device_user_map,
        pruned_peers: Arc::new(DashSet::new()),
        contact_public,
        active: active.clone(),
        dns_configurator: Arc::new(std::sync::Mutex::new(None)),
        resolver: dns_resolver.clone(),
        dns_reassert_token: std::sync::Mutex::new(None),
        #[cfg(feature = "desktop")]
        ssh_authz: crate::ssh::new_authz(),
        ssh_token: std::sync::Mutex::new(None),
        promote_tx,
    });

    // --- Accept loop (ALPN dispatch) + Prometheus metrics ---
    protocol_router.spawn_accept_loop(daemon.endpoint.clone(), token.clone());

    // --- File auto-accept worker (own-devices offers) ---
    spawn_file_auto_accept(daemon.clone(), new_file_rx, token.clone());

    // --- Contact record publisher (ray connect) ---
    if let Ok(pkarr_client) = dht::create_pkarr_client(&daemon.endpoint) {
        spawn_contact_publisher(pkarr_client, daemon.endpoint.id(), token.clone());
    }
    let metrics_server =
        spawn_metrics_server(stats, daemon.peers.clone(), &daemon.endpoint, token).await;
    // Keep the metrics-server guard alive for the daemon's whole lifetime.
    *daemon._metrics_server.lock().unwrap() = metrics_server;

    tracing::info!(ip = %my_ip, id = %daemon.endpoint.id().fmt_short(), "daemon started");
    Ok(daemon)
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
                    Some(DiscoveryEvent::Discovered { endpoint_info, .. }) => {
                        tracing::info!(
                            peer = %endpoint_info.endpoint_id.fmt_short(),
                            "mDNS: peer discovered on LAN"
                        );
                    }
                    Some(DiscoveryEvent::Expired { endpoint_id }) => {
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
) -> Option<MetricsServer> {
    let mut registry = iroh_metrics::Registry::default();
    registry.register(stats);
    let peer_metrics = Arc::new(crate::stats::PeerMetrics::default());
    registry.register(peer_metrics.clone());
    peer_metrics.spawn_collector(peers, token);
    registry.register_all(endpoint.metrics());

    let metrics_addr: SocketAddr = ([0, 0, 0, 0], 9090).into();
    match MetricsServer::spawn(metrics_addr, Arc::new(registry)).await {
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
    daemon: &Arc<DaemonState>,
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
fn set_socket_permissions(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
        unsafe { libc::chmod(c_path.as_ptr(), 0o666) };
        tracing::info!("IPC socket mode 0666 (per-request authorization via peer creds)");
    }
}

async fn handle_ipc_client(stream: UnixStream, daemon: &Arc<DaemonState>) -> Result<()> {
    let peer_cred = stream.peer_cred().ok().map(|c| (c.uid(), c.gid()));
    let mut framed = ipc::framed(stream);
    let req = ipc::recv(&mut framed).await?;
    let resp = daemon.handle_request(req, peer_cred).await;
    ipc::send(&mut framed, resp).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Network task helpers (extracted from main.rs patterns)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_network_publisher(
    client: PkarrRelayClient,
    net_secret_key: SecretKey,
    state: SharedNetworkState,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    notify: Arc<Notify>,
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
fn spawn_contact_publisher(
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
fn spawn_lazy_publisher(
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
fn apply_suggested_firewall(
    firewall: &SharedFirewall,
    my_identity: EndpointId,
    network_name: &str,
    state: &RwLock<NetworkState>,
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
async fn resolve_signed(
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
async fn fetch_verified_blob(
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
async fn reconverge_and_apply(
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
        device_user_map,
        pruned_peers,
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
    // Drop any live connection to a peer the signed roster no longer lists (it was
    // kicked, or left while we were offline). Removing it from the roster alone
    // stops us *routing* to it, but the peer reader keeps injecting its inbound
    // datagrams until the connection closes — so close it. We record the peer in
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

/// Close and drop every connection to a peer that `network`'s current roster no
/// longer contains. Runs on every node after it applies a verified roster, so a
/// kicked (or departed) peer is severed mesh-wide, not just by the coordinator
/// that removed it. Each pruned peer is recorded in `pruned_peers` so this node's
/// reconnect loop skips the re-dial that closing the connection would trigger.
fn prune_departed_peers(
    peers: &PeerTable,
    device_user_map: &peers::DeviceUserMap,
    pruned_peers: &Arc<DashSet<(String, EndpointId)>>,
    state: &SharedNetworkState,
    network_name: &str,
    my_identity: EndpointId,
) {
    for (peer_id, ip, conn) in peers.peers_for_network_with_conn(network_name) {
        // Membership is by roster identity, which for a paired peer is its user
        // identity, not the transport id the PeerTable is keyed on. Check both.
        let user_id = device_user_map.resolve(&peer_id);
        let still_member = {
            let s = state.read().unwrap();
            s.members.is_member(&peer_id) || s.members.is_member(&user_id)
        };
        if still_member || peer_id == my_identity || user_id == my_identity {
            continue;
        }
        tracing::info!(peer = %peer_id.fmt_short(), network = %network_name, "pruning peer no longer in roster");
        pruned_peers.insert((network_name.to_string(), peer_id));
        conn.close(
            VarInt::from_u32(forward::KICK_CODE),
            b"removed from network",
        );
        peers.remove_peer_from_network(&ip, &derive_ipv6(&peer_id), network_name);
    }
}

/// Compute the order in which a joiner should dial coordinators.
/// Returns the minter first (if present and not `me`), then every other
/// `is_coordinator` member except `me`, de-duplicated, preserving order.
/// Consumed by the join dial-fallback loop.
fn coordinator_dial_order(
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
fn gossip_targets(members: &[Member], me: EndpointId) -> Vec<EndpointId> {
    members
        .iter()
        .filter(|m| m.is_coordinator && m.identity != me)
        .map(|m| m.identity)
        .collect()
}

/// Whether `peer` is a coordinator in our verified roster. Invite-gossip arms
/// (`InviteShare`/`InviteUsed`) act only on messages from a coordinator peer, so
/// a non-coordinator member can't inject or burn invite state.
fn sender_is_coordinator(state: &SharedNetworkState, peer: EndpointId) -> bool {
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
async fn gossip_to_coordinators(
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
enum DialOutcome {
    Welcomed,
    Denied,
    Unreachable,
}

/// Returns `(index_of_last_tried, welcomed)`.
/// Iterates `outcomes` left-to-right and stops at the first `Welcomed`.
/// If none is found, returns the index of the last element and `false`.
#[allow(dead_code)]
fn pick_first_welcome(outcomes: &[DialOutcome]) -> (usize, bool) {
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
fn persisted_roster(network_name: &str) -> Vec<Member> {
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

/// How long after boot the first auto-update check runs (avoids racing startup
/// and lets a just-restarted daemon settle before it may restart again).
#[cfg(feature = "desktop")]
const AUTO_UPDATE_INITIAL_DELAY: Duration = Duration::from_secs(300);
/// Base interval between auto-update checks.
#[cfg(feature = "desktop")]
const AUTO_UPDATE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// Don't retry the *same* target release within this window (restart-loop guard).
#[cfg(feature = "desktop")]
const AUTO_UPDATE_BACKOFF_SECS: i64 = 24 * 60 * 60;

/// Opt-in auto-updater (`ray auto-update on` / `ray install --auto-update`): a
/// single daemon-wide task that periodically resolves the latest **stable**
/// release and, when it is newer than this build, downloads + verifies + swaps
/// the binary and restarts the service onto it. Errors are logged and never
/// propagated — this task must never crash the daemon. Nightlies are never
/// auto-installed. Desktop-only: the Android lib ships no self-replacing binary.
#[cfg(feature = "desktop")]
fn spawn_auto_update(token: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Jitter each tick so a fleet upgraded together doesn't hit the GitHub
        // API in lockstep (anonymous limit is 60/hr per IP).
        let first = AUTO_UPDATE_INITIAL_DELAY + Duration::from_secs(rand::random::<u64>() % 300);
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tokio::time::sleep(first) => {}
        }
        loop {
            if let Err(e) = auto_update_once().await {
                tracing::warn!(error = %e, "auto-update check failed");
            }
            let next = AUTO_UPDATE_INTERVAL + Duration::from_secs(rand::random::<u64>() % 300);
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(next) => {}
            }
        }
    })
}

/// One auto-update cycle: check for a newer stable release and, if found and not
/// backed off, swap the binary and trigger a self-restart. `Ok(())` means nothing
/// needed doing (or the swap+restart was scheduled — the daemon is torn down and
/// relaunched onto the new binary shortly after).
#[cfg(feature = "desktop")]
async fn auto_update_once() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let asset = update::release_asset_name(std::env::consts::OS, std::env::consts::ARCH)?;
    let client = update::build_http_client()?;
    let token = update::github_token();

    let release = update::resolve_stable_release(&client, &token).await?;
    let tag = release.tag_name.clone();
    let latest = update::normalize_version(&tag).to_string();
    if !update::version_is_newer(&latest, current) {
        tracing::debug!(current, latest = %latest, "auto-update: already on latest stable");
        return Ok(());
    }

    // Restart-loop guard: refuse a repeat of the same target inside the backoff
    // window so a bad build that keeps mis-reporting its version can't tight-loop
    // download + restart.
    let mut cfg = config::load()?;
    let now = unix_now();
    if !update::should_attempt_target(
        &tag,
        cfg.auto_update_last_target.as_deref(),
        cfg.auto_update_last_attempt,
        now,
        AUTO_UPDATE_BACKOFF_SECS,
    ) {
        tracing::warn!(target = %tag, "auto-update: recently attempted this target, backing off");
        return Ok(());
    }

    // Record the attempt *before* swapping so a crash mid-swap still counts
    // against the backoff; it survives the restart via settings.toml.
    cfg.auto_update_last_target = Some(tag.clone());
    cfg.auto_update_last_attempt = Some(now);
    if let Err(e) = config::save_settings(&cfg) {
        tracing::warn!(error = %e, "auto-update: failed to persist attempt marker");
    }

    tracing::info!(current, target = %tag, "auto-update: found newer stable release, swapping");
    let expected = update::fetch_checksum(&client, &tag, &asset).await?;
    let bin_url = update::asset_download_url(&tag, &asset);
    update::download_and_swap(&client, &bin_url, &expected, &asset).await?;

    tracing::info!(target = %tag, "auto-update: binary swapped, restarting service onto it");
    update::trigger_detached_restart();
    Ok(())
}

/// Current unix time in whole seconds (best-effort; 0 before the epoch, which
/// never happens in practice).
#[cfg(feature = "desktop")]
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn spawn_group_poller(
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
            let new_member_ids: HashSet<EndpointId> =
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
struct CoordinatorCleanup {
    state: SharedNetworkState,
    blob_store: FsStore,
    dht_notify: Option<Arc<Notify>>,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
    network_name: String,
}

/// Drain newly-queued file-offer ids and hand each to the own-devices
/// auto-accept policy. Runs for the daemon's lifetime; a nudge that arrives
/// before the flag is on is a no-op (the offer stays queued for manual accept).
fn spawn_file_auto_accept(
    daemon: Arc<DaemonState>,
    mut rx: mpsc::UnboundedReceiver<u64>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                id = rx.recv() => match id {
                    Some(id) => daemon.try_auto_accept_file(id).await,
                    None => return,
                },
            }
        }
    })
}

fn spawn_peer_cleanup(
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
fn spawn_coordinator_control_reader(
    conn: Connection,
    remote_id: EndpointId,
    peer_ip: Ipv4Addr,
    network_name: String,
    state: SharedNetworkState,
    ctx: MeshCtx,
    dht_notify: Option<Arc<Notify>>,
    token: CancellationToken,
    // Serializes single-use invite ledger access for the invite-gossip arms.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    // Fires the waiting `ray ping` handler when a matching `Pong` arrives.
    pending_pongs: Arc<DashMap<u64, oneshot::Sender<()>>>,
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
fn choose_path_index(classes: &[(ipc::ConnType, bool)]) -> Option<usize> {
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
fn rename_satisfied(pending: &str, blob: Option<&str>) -> bool {
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
async fn drain_pending_rename(
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
fn has_pending_hostname(network_name: &str) -> bool {
    matches!(
        config::load_network(network_name),
        Ok(Some(net)) if net.pending_hostname.is_some()
    )
}

/// The hostname this node should announce to peers: a not-yet-confirmed rename
/// intent (`pending_hostname`) if one is queued, otherwise the confirmed name.
/// Read fresh from config at every announce so a rename done mid-session is
/// advertised on the next (re)connect — not a value captured at daemon start.
fn outgoing_hostname(network_name: &str) -> Option<String> {
    match config::load_network(network_name) {
        Ok(Some(net)) => net.pending_hostname.or(net.my_hostname),
        _ => None,
    }
}

async fn apply_roster_to_dns(
    members: &[Member],
    network_name: &str,
    my_identity: EndpointId,
    hostname_table: &dns::HostnameTable,
    reverse_table: &dns::ReverseLookupTable,
) {
    let mut entries: Vec<(String, Ipv4Addr, Ipv6Addr)> = members
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
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn update_snapshot_and_publish(
    state: &SharedNetworkState,
    blob_store: &FsStore,
    dht_notify: &Option<Arc<Notify>>,
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

#[allow(clippy::too_many_arguments)]
/// Result of the initial join handshake against the coordinator.
enum JoinResult {
    /// Admitted (open network, valid invite, or pre-approved): live network state.
    Joined(SharedNetworkState),
    /// Queued for live approval on a closed network; the caller should retry.
    Pending,
}

/// Outcome of one `join_network_inner` attempt.
pub(crate) enum TryJoin {
    Joined(IpcMessage),
    Pending,
}

/// By-value parameters for one [`join_mesh_shared`] handshake, grouped so the
/// function's argument list stays manageable. These are all decided once, at the
/// call site, per join: the joiner's chosen hostname and cert, the invite secret
/// it presents, the blob-derived `suggested_firewall`/`reusable_keys` it
/// inherits, its firewall consent, and whether this is a fresh join or a
/// reconnect.
struct JoinParams {
    my_hostname: Option<String>,
    net_pubkey: EndpointId,
    device_cert: Option<control::DeviceCert>,
    invite_secret: Option<Vec<u8>>,
    /// From the fetched blob: the current coordinator-suggested firewall rules,
    /// persisted so a member inherits them.
    suggested_firewall: SuggestedFirewall,
    /// From the fetched blob: reusable join keys, so this node can validate
    /// redemptions if it later holds the network key (HA admission).
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    /// Consent: auto-install suggested rules without a manual review queue.
    auto_accept_firewall: bool,
    /// Seed for per-network auto-accept of file offers from our own devices
    /// (`--auto-accept-files`). Only applied on a first join; the persisted
    /// config value wins on reconnect/restore (see `join_mesh_shared`).
    auto_accept_files: bool,
    /// Fresh join (send `JoinRequest` first) vs reconnect/restore (coordinator
    /// speaks first).
    initial: bool,
}

#[allow(clippy::too_many_arguments)]
async fn join_mesh_shared(
    initial_conn: Connection,
    ep: &Endpoint,
    network_name: &str,
    alpn: &[u8],
    ctx: MeshCtx,
    params: JoinParams,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    // Promotion signal: the per-peer control reader sends this network's name
    // here after persisting an `AdminGrant` key, so the daemon loop can swap in
    // the coordinator accept handler (see `DaemonState::promote_to_coordinator`).
    promote_tx: mpsc::Sender<String>,
    // Guards the single-use invite ledger. Shared with the NetworkHandle so the
    // control listener's `InviteShare`/`InviteUsed` handling (a co-coordinator
    // learning of invites it didn't mint) is serialized with mint/redeem.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
    // Shared with the router; lets the member control reader resolve `ray ping`
    // Pongs back to the waiting handler.
    pending_pongs: Arc<DashMap<u64, oneshot::Sender<()>>>,
) -> Result<JoinResult> {
    // A whole-bundle clone for the debounced reconverge worker, which forwards
    // the ctx straight to `reconverge_and_apply`.
    let worker_ctx = ctx.clone();
    let MeshCtx {
        identity,
        peers,
        blob_store,
        firewall,
        ..
    } = ctx;
    let JoinParams {
        my_hostname,
        net_pubkey,
        device_cert,
        invite_secret,
        suggested_firewall,
        reusable_keys,
        auto_accept_firewall,
        auto_accept_files,
        initial,
    } = params;
    let my_identity = identity.local_identity();
    let my_ip = identity.local_ip();

    // Handshake. A fresh join (`initial`) opens a stream and sends a JoinRequest
    // first (carrying the invite secret + hostname), then reads the coordinator's
    // verdict on the same stream. A reconnect/restore keeps the legacy handshake
    // where the coordinator speaks first (Welcome/MemberSync).
    let (members, approved) = if initial {
        let (mut send, mut recv) = initial_conn
            .open_bi()
            .await
            .context("open join control stream")?;
        control::send_msg(
            &mut send,
            &ControlMsg::JoinRequest {
                invite_secret,
                hostname: my_hostname.clone(),
                device_cert: device_cert.clone(),
            },
        )
        .await
        .context("send join request")?;
        let msg = tokio::time::timeout(Duration::from_secs(30), control::recv_msg(&mut recv))
            .await
            .context("timeout awaiting join response")??;
        match msg {
            ControlMsg::Welcome { members, approved } => {
                tracing::info!(network = %network_name, "welcomed to network");
                if let Some(existing) = members
                    .iter()
                    .find(|m| m.ip == my_ip && m.identity != my_identity)
                {
                    anyhow::bail!(
                        "IP collision: {} is already assigned to {}",
                        my_ip,
                        existing.identity
                    );
                }
                (members, approved)
            }
            ControlMsg::JoinPending => {
                tracing::info!(network = %network_name, "join pending operator approval");
                return Ok(JoinResult::Pending);
            }
            ControlMsg::JoinDenied { reason } => {
                anyhow::bail!("join denied: {reason}");
            }
            other => {
                anyhow::bail!("expected Welcome or JoinPending, got {other:?}");
            }
        }
    } else {
        let (_send, mut recv) = initial_conn
            .accept_bi()
            .await
            .context("accept control stream")?;
        let msg = control::recv_msg(&mut recv).await?;
        match msg {
            ControlMsg::Welcome { members, approved } => {
                tracing::info!(network = %network_name, "welcomed to network");
                (members, approved)
            }
            ControlMsg::JoinApproved { your_ip, members } => {
                tracing::info!(ip = %your_ip, network = %network_name, "joined network (legacy)");
                (members, vec![])
            }
            ControlMsg::MemberSync => {
                // Reconnected via a peer. The message is only a trigger — fetch
                // the authoritative roster from the network-key-signed pkarr
                // record. If it's briefly unreachable, fall back to our last
                // persisted roster rather than trusting peer-supplied membership.
                tracing::info!(network = %network_name, "reconnected via peer; reconverging from signed record");
                match resolve_signed(ep, net_pubkey).await {
                    Some((signed, seeds)) => {
                        match fetch_verified_blob(
                            ep,
                            &blob_store,
                            &peers,
                            signed,
                            network_name,
                            &seeds,
                        )
                        .await
                        {
                            Some(data) => (data.members, data.approved),
                            None => (persisted_roster(network_name), vec![]),
                        }
                    }
                    None => (persisted_roster(network_name), vec![]),
                }
            }
            ControlMsg::JoinDenied { reason } => {
                anyhow::bail!("join denied: {reason}");
            }
            other => {
                anyhow::bail!("expected Welcome or MemberSync, got {other:?}");
            }
        }
    };

    // Save membership to config
    let member_entries = to_member_entries(members.iter());
    let approved_config = to_approved_entries(approved.iter());
    let persisted_hostname = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone())
        .or(my_hostname.clone());
    // Preserve the direct-connection flag across reconnects (a member joining a
    // 2-peer `ray connect` network). On the first join the flag is set by the
    // `connect` handler after this returns.
    // Preserve a queued rename intent across reconnects/restores: the blob we
    // just fetched won't carry it yet, so persisting it here keeps the drain
    // alive until a coordinator confirms the new name.
    let (direct, pending_hostname, ssh_allow, aliases, prev_auto_accept_files) =
        config::load_network(network_name)?
            .map(|n| {
                (
                    n.direct,
                    n.pending_hostname,
                    n.ssh_allow,
                    n.aliases,
                    n.auto_accept_files,
                )
            })
            .unwrap_or((false, None, vec![], BTreeMap::new(), false));
    // The toggle command (`ray files auto-accept`) is authoritative, so preserve
    // a previously-persisted value; the join-time `--auto-accept-files` seed only
    // needs to take effect on the first join (no prior config).
    let auto_accept_files = prev_auto_accept_files || auto_accept_files;
    config::save_network(&config::NetworkConfig {
        name: network_name.to_string(),
        group_mode: GroupMode::Restricted,
        my_ip: Some(my_ip),
        my_hostname: persisted_hostname,
        pending_hostname,
        members: member_entries,
        approved: approved_config,
        network_secret_key: None,
        network_public_key: Some(net_pubkey),
        transport: None,
        auto_accept_firewall,
        auto_accept_files,
        admins: vec![],
        direct,
        ssh_allow,
        aliases,
    })?;

    // On reconnect/restore the coordinator hasn't seen our hostname this session,
    // so send a MeshHello. A fresh join already conveyed it in the JoinRequest.
    if !initial {
        let (mut send, _recv) = initial_conn.open_bi().await?;
        control::send_msg(
            &mut send,
            &ControlMsg::MeshHello {
                identity: my_identity,
                ip: my_ip,
                // Read fresh so a rename done since startup (a pending intent or
                // the confirmed name) is announced on this reconnect, not a name
                // captured when the daemon launched.
                hostname: outgoing_hostname(network_name),
                device_cert: device_cert.clone(),
            },
        )
        .await?;
    }

    // Add initial connection peer
    let remote_id = initial_conn.remote_id();
    let remote_ip = identity.derive_ip(&remote_id);
    crate::spawn_path_logger(initial_conn.clone(), remote_id.fmt_short().to_string());
    let remote_ipv6 = derive_ipv6(&remote_id);
    peers.add(
        remote_ip,
        remote_ipv6,
        initial_conn.clone(),
        remote_id,
        network_name,
    );
    forward::spawn_peer_reader(
        initial_conn.clone(),
        remote_id,
        remote_ip,
        remote_ipv6,
        network_name.to_string(),
        worker_ctx.forward_ctx(disconnect_tx.clone(), token.clone()),
    );

    // Connect to other known members
    for member in &members {
        if member.identity == my_identity || member.identity == initial_conn.remote_id() {
            continue;
        }
        match transport::connect_to_peer_with_alpn(ep, member.identity, alpn).await {
            Ok(conn) => {
                let (mut send, _recv) = conn.open_bi().await?;
                control::send_msg(
                    &mut send,
                    &ControlMsg::MeshHello {
                        identity: my_identity,
                        ip: my_ip,
                        hostname: outgoing_hostname(network_name),
                        device_cert: device_cert.clone(),
                    },
                )
                .await?;
                let member_ipv6 = derive_ipv6(&member.identity);
                peers.add(
                    member.ip,
                    member_ipv6,
                    conn.clone(),
                    member.identity,
                    network_name,
                );
                forward::spawn_peer_reader(
                    conn,
                    member.identity,
                    member.ip,
                    member_ipv6,
                    network_name.to_string(),
                    worker_ctx.forward_ctx(disconnect_tx.clone(), token.clone()),
                );
                tracing::info!(peer_ip = %member.ip, "connected to mesh peer");
            }
            Err(e) => {
                tracing::warn!(peer_ip = %member.ip, error = %e, "mesh peer unavailable");
            }
        }
    }

    let live_state = {
        let mut ns = NetworkState {
            members: MemberList::from_members(members.clone()),
            approved: ApprovedList::from_entries(approved),
            snapshot: None,
            network_secret_key: None,
            network_public_key: net_pubkey,
            network_name: Some(network_name.to_string()),
            mode: GroupMode::Restricted,
            suggested_firewall,
            reusable_keys,
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        };
        ns.refresh_snapshot();
        if let Some(snap) = &ns.snapshot {
            let _ = blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }
        Arc::new(RwLock::new(ns))
    };

    // Materialize this node's suggested rules from the blob we just joined with.
    // Re-runs on every roster/blob update from the control listener below.
    apply_suggested_firewall(&firewall, my_identity, network_name, &live_state);

    // Reconverge worker: `MemberSync`/`BlobUpdated` triggers fan into this
    // single, debounced task instead of each driving a reconverge inline. A
    // burst of triggers (e.g. several coordinators broadcasting after one roster
    // change) collapses into one pkarr resolve + reconverge, and a slow
    // reconverge never blocks the control listener's accept loop. The signed
    // record stays the source of truth, so converging once per burst suffices.
    let reconverge_notify = Arc::new(Notify::new());
    tokio::spawn({
        let notify = reconverge_notify.clone();
        let token = token.clone();
        let live_state = live_state.clone();
        let network_name = network_name.to_string();
        let ctx_w = worker_ctx;
        let endpoint_w = ep.clone();
        let my_identity_w = my_identity;
        let net_pubkey_w = net_pubkey;
        let alpn_w = alpn.to_vec();
        let my_ip_w = my_ip;
        let device_cert_w = device_cert.clone();
        async move {
            // Backstop tick so a queued rename is retried even on a quiet
            // network that sends no `MemberSync`/`BlobUpdated` triggers. It does
            // a reconverge only while a rename is outstanding, so steady state
            // stays trigger-driven (no extra pkarr traffic).
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = notify.notified() => {}
                    _ = tick.tick() => {
                        // Only the pending-rename backstop wants the periodic
                        // wake; otherwise idle until the next real trigger.
                        if !has_pending_hostname(&network_name) {
                            continue;
                        }
                        tracing::debug!(
                            network = %network_name,
                            "backstop tick: pending rename outstanding, reconverging to retry delivery"
                        );
                    }
                }
                // Debounce: absorb a burst of triggers into a single reconverge.
                // A trigger that arrives during the sleep or the reconverge is
                // retained by `Notify` and handled on the next iteration.
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                }
                reconverge_and_apply(
                    &endpoint_w,
                    &ctx_w,
                    net_pubkey_w,
                    &network_name,
                    &live_state,
                    my_identity_w,
                    &alpn_w,
                    my_ip_w,
                    &device_cert_w,
                )
                .await;
            }
        }
    });

    // Control listener
    tokio::spawn({
        let initial_conn = initial_conn.clone();
        let token = token.clone();
        let live_state = live_state.clone();
        let network_name = network_name.to_string();
        let peers_c = peers.clone();
        let endpoint_c = ep.clone();
        let my_identity_c = my_identity;
        let net_pubkey_c = net_pubkey;
        let promote_tx = promote_tx.clone();
        let invite_lock = invite_lock.clone();
        let reconverge_notify = reconverge_notify.clone();
        let pending_pongs = pending_pongs.clone();
        async move {
            let mut gate = crate::ratelimit::ControlGate::new();
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = initial_conn.accept_bi() => {
                        match result {
                            Ok((_send, mut recv)) => {
                                let msg = match control::recv_msg(&mut recv).await {
                                    Ok(m) => m,
                                    Err(_) => continue,
                                };
                                // Throttle inbound control messages per connection:
                                // drop over-budget ones, drop the peer on a flood.
                                match gate.check() {
                                    crate::ratelimit::Verdict::Allow => {}
                                    crate::ratelimit::Verdict::Drop => continue,
                                    crate::ratelimit::Verdict::Close => {
                                        tracing::warn!(peer = %remote_id.fmt_short(), "control-plane flood; closing connection");
                                        initial_conn.close(VarInt::from_u32(forward::ABUSE_CODE), b"control flood");
                                        return;
                                    }
                                }
                                match msg {
                                    ControlMsg::MemberApproved { identity, ip, hostname, .. } => {
                                        let entry = ApprovedEntry { identity, ip, hostname, user_identity: None, device_cert: None, collision_index: 0 };
                                        let mut s = live_state.write().unwrap();
                                        let members = s.members.clone();
                                        let _ = s.approved.approve(entry, &members);
                                    }
                                    ControlMsg::MemberSync => {
                                        // Trigger only. The roster/firewall come exclusively
                                        // from the network-key-signed pkarr record, never from
                                        // peer-supplied membership. Coalesced into the debounced
                                        // reconverge worker.
                                        reconverge_notify.notify_one();
                                    }
                                    ControlMsg::BlobUpdated => {
                                        // Trigger only. Reconverge from the network-key-signed
                                        // pkarr record — a malicious member can't inject a
                                        // forged roster/firewall blob via this message. Coalesced
                                        // into the debounced reconverge worker.
                                        reconverge_notify.notify_one();
                                    }
                                    ControlMsg::AdminGrant { network_pubkey, secret_key } => {
                                        // Coordinator granted us the per-network key.
                                        // Verify it targets this network (the stream is
                                        // already ALPN-scoped, but defense in depth).
                                        if network_pubkey != net_pubkey_c {
                                            tracing::warn!(
                                                peer = %remote_id.fmt_short(),
                                                "admin grant for a different network; ignoring"
                                            );
                                            continue;
                                        }
                                        // Self-authenticating: only adopt a key
                                        // that genuinely is this network's key
                                        // (its public half must equal the network
                                        // pubkey). Defeats a forged AdminGrant
                                        // from a non-coordinator member without
                                        // relying on reconverge timing for the
                                        // granter's is_coordinator flag.
                                        if !admin_grant_key_valid(secret_key, net_pubkey_c) {
                                            tracing::warn!(
                                                peer = %remote_id.fmt_short(),
                                                "admin grant key does not match network pubkey; ignoring"
                                            );
                                            continue;
                                        }
                                        let key = SecretKey::from(secret_key);
                                        // Persist + take local publish capability.
                                        if let Ok(Some(mut net)) = config::load_network(&network_name) {
                                            net.network_secret_key = Some(key.clone());
                                            let _ = config::save_network(&net);
                                        }
                                        let endpoint_id = endpoint_c.id();
                                        {
                                            let mut s = live_state.write().unwrap();
                                            s.network_secret_key = Some(key.clone());
                                            if let Some(m) = s.members.get_mut(&my_identity_c) {
                                                m.is_coordinator = true;
                                            }
                                            s.refresh_snapshot();
                                        }
                                        // Spawn a lazy publisher (this node can now
                                        // publish the signed blob / suggest rules).
                                        if let Ok(client) = dht::create_pkarr_client(&endpoint_c) {
                                            spawn_lazy_publisher(
                                                client,
                                                key,
                                                live_state.clone(),
                                                endpoint_id,
                                                peers_c.clone(),
                                                network_name.clone(),
                                                token.clone(),
                                            );
                                            tracing::info!(
                                                network = %network_name,
                                                "promoted to co-coordinator; lazy publisher started"
                                            );
                                        }
                                        // Signal the daemon loop to swap this
                                        // network's accept handler to coordinator
                                        // so it can admit fresh joiners (not just
                                        // welcome pre-approved peers). The loop
                                        // holds the `Arc<DaemonState>` this task
                                        // does not. Best-effort: a closed channel
                                        // only means the daemon is shutting down.
                                        let _ = promote_tx.send(network_name.clone()).await;
                                    }
                                    ControlMsg::InviteShare { id, secret_hash, expires } => {
                                        // Another coordinator minted a single-use
                                        // invite; record its hash so we can redeem
                                        // it too. Only honor it from a peer that is
                                        // a coordinator in our verified roster.
                                        if !sender_is_coordinator(&live_state, remote_id) {
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
                                    }
                                    ControlMsg::InviteUsed { secret_hash } => {
                                        // Another coordinator redeemed a single-use
                                        // invite; burn it locally so it can't be
                                        // reused here. Coordinator-only.
                                        if !sender_is_coordinator(&live_state, remote_id) {
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
                                    }
                                    ControlMsg::Ping { nonce } => {
                                        respond_pong(&initial_conn, nonce).await;
                                    }
                                    ControlMsg::Pong { nonce } => {
                                        if let Some((_, tx)) = pending_pongs.remove(&nonce) {
                                            let _ = tx.send(());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Err(_) => return,
                        }
                    }
                }
            }
        }
    });

    Ok(JoinResult::Joined(live_state))
}

#[allow(clippy::too_many_arguments)]
fn spawn_reconnect_loop(
    mut disconnect_rx: mpsc::Receiver<forward::DisconnectEvent>,
    ep: Endpoint,
    alpn: Vec<u8>,
    network_name: String,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    ctx: MeshCtx,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    device_cert: Option<control::DeviceCert>,
) -> JoinHandle<()> {
    // The reconnect MeshHello reads the current hostname fresh from config
    // (`outgoing_hostname`), so no captured hostname is threaded through.
    let MeshCtx {
        peers,
        tun_tx,
        stats,
        firewall,
        device_user_map,
        pruned_peers,
        ..
    } = ctx;
    use tracing::Instrument as _;
    // Tag all reconnect-loop logs for this network so they correlate in reports.
    let span = tracing::info_span!("reconnect", net = %network_name);
    let reconnect_loop = async move {
        loop {
            let event = tokio::select! {
                _ = token.cancelled() => return,
                event = disconnect_rx.recv() => match event {
                    Some(ev) => ev,
                    None => return,
                },
            };
            let peer_id = event.endpoint_id;
            let peer_ip = event.ip;
            let peer_ipv6 = event.ipv6;
            // Drop only this network's route; other networks the peer shares with
            // us stay live.
            peers.remove_peer_from_network(&peer_ip, &peer_ipv6, &event.network);

            // A deliberate `ray leave` (graceful close with the leave code) means
            // the peer is gone for good — don't spin a reconnect task against it.
            // The coordinator's MemberSync will prune it from our roster.
            if event.intentional {
                tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer left, not reconnecting");
                continue;
            }
            // We just pruned this peer from the roster (it was kicked or departed)
            // and closed the connection ourselves — that close is what woke this
            // loop. The peer still lists us, so re-dialing would re-form the link.
            // Consume the one-shot suppression entry and skip.
            if pruned_peers
                .remove(&(network_name.clone(), peer_id))
                .is_some()
            {
                tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer removed from roster, not reconnecting");
                continue;
            }
            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "peer disconnected, will reconnect");

            let ep = ep.clone();
            let alpn = alpn.clone();
            let network_name = network_name.clone();
            let peers = peers.clone();
            let tun_tx = tun_tx.clone();
            let disconnect_tx = disconnect_tx.clone();
            let token = token.clone();
            let stats = stats.clone();
            let firewall = firewall.clone();
            let device_cert = device_cert.clone();
            let device_user_map = device_user_map.clone();

            tokio::spawn(async move {
                let mut backoff = BACKOFF_INITIAL;
                loop {
                    if token.is_cancelled() {
                        return;
                    }
                    tracing::info!(peer = %peer_id.fmt_short(), secs = backoff.as_secs(), "reconnecting in");
                    tokio::select! {
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);

                    match transport::connect_to_peer_with_alpn(&ep, peer_id, &alpn).await {
                        Ok(conn) => {
                            let (mut send, _) = match conn.open_bi().await {
                                Ok(bi) => bi,
                                Err(e) => {
                                    tracing::warn!(error = %e, "reconnect handshake failed");
                                    continue;
                                }
                            };
                            if let Err(e) = control::send_msg(
                                &mut send,
                                &ControlMsg::MeshHello {
                                    identity: my_identity,
                                    ip: my_ip,
                                    hostname: outgoing_hostname(&network_name),
                                    device_cert: device_cert.clone(),
                                },
                            )
                            .await
                            {
                                tracing::warn!(error = %e, "reconnect MeshHello failed");
                                continue;
                            }
                            tracing::info!(peer = %peer_id.fmt_short(), ip = %peer_ip, "reconnected to peer");
                            peers.add(peer_ip, peer_ipv6, conn.clone(), peer_id, &network_name);
                            forward::spawn_peer_reader(
                                conn,
                                peer_id,
                                peer_ip,
                                peer_ipv6,
                                network_name,
                                forward::ForwardCtx {
                                    firewall,
                                    tun_tx,
                                    disconnect_tx,
                                    token,
                                    stats,
                                    device_user_map,
                                },
                            );
                            return;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "reconnect attempt failed");
                        }
                    }
                }
            });
        }
    };
    tokio::spawn(reconnect_loop.instrument(span))
}

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
        let net_secret = SecretKey::from_bytes(&[1u8; 32]);
        let net_pub = net_secret.public();
        Arc::new(RwLock::new(NetworkState {
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
            tun_tx: Arc::new(arc_swap::ArcSwap::from_pointee(tun_tx)),
            stats: Arc::new(ForwardMetrics::default()),
            blob_store,
            firewall: SharedFirewall::new(crate::firewall::FirewallConfig::default()),
            hostname_table: dns::new_hostname_table(),
            reverse_table: dns::new_reverse_table(),
            device_user_map: peers::DeviceUserMap::new(),
            pruned_peers: Arc::new(DashSet::new()),
        }
    }

    async fn sample_coordinator_handler() -> AcceptHandler {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = FsStore::load(tmp.path()).await.unwrap();
        let (disconnect_tx, _) = tokio::sync::mpsc::channel(1);
        let my_key = SecretKey::from_bytes(&[2u8; 32]);
        let my_id = my_key.public();
        AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
            ctx: sample_mesh_ctx(IrohIdentityProvider::new(my_id, 0), blob_store),
            network_name: "test-net".to_string(),
            state: make_network_state(),
            disconnect_tx,
            token: CancellationToken::new(),
            dht_notify: None,
            invite_lock: Arc::new(tokio::sync::Mutex::new(())),
            pending_pongs: Arc::new(DashMap::new()),
        }))
    }

    async fn sample_member_handler() -> AcceptHandler {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = FsStore::load(tmp.path()).await.unwrap();
        let (disconnect_tx, _) = tokio::sync::mpsc::channel(1);
        let my_key = SecretKey::from_bytes(&[3u8; 32]);
        AcceptHandler::Member(Arc::new(MemberAcceptState {
            ctx: sample_mesh_ctx(IrohIdentityProvider::new(my_key.public(), 0), blob_store),
            network_name: "test-net".to_string(),
            state: make_network_state(),
            disconnect_tx,
            token: CancellationToken::new(),
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

    #[test]
    fn owner_admits_only_matching_user_identity() {
        let owner = SecretKey::generate();
        let owner_id = owner.public();
        let device = SecretKey::generate().public();
        let cert = control::DeviceCert::create(&owner, &device);

        // Cert signed by this owner -> admit.
        assert!(owner_admits(Some(&cert), owner_id));
        // No cert -> do not auto-admit.
        assert!(!owner_admits(None, owner_id));
        // Cert signed by a different user -> do not auto-admit.
        let other = SecretKey::generate().public();
        assert!(!owner_admits(Some(&cert), other));
    }
}

#[cfg(test)]
mod coordinator_dial_order_tests {
    use super::*;
    use crate::membership::{Member, derive_ip};

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        let key = SecretKey::from(key_bytes);
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
        let net_secret = SecretKey::from({
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
        let forged = SecretKey::from({
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

#[cfg(test)]
mod headless_tests {
    use super::*;

    /// `build_headless()` constructs a usable `Arc<DaemonState>` (identity,
    /// endpoint, blob store, DNS, pollers) in an isolated config dir and answers a
    /// `status()` call, all without binding the Unix-socket IPC server that
    /// `run_daemon`/`serve_ipc` would.
    ///
    /// Multi-threaded flavor: `build_headless` builds an iroh endpoint and an
    /// iroh-blobs `FsStore` whose background actor tasks must make progress while
    /// the builder awaits, matching the daemon binary's `#[tokio::main]` runtime.
    /// The `timeout` guard turns a future startup regression into a fast failure
    /// instead of a hung test.
    /// Process-wide lock serializing tests that mutate `RAYFISH_CONFIG_DIR` (or
    /// any other env var read by `config::config_dir()`), since lib tests share
    /// one process and run on parallel threads. Shared with `identity::tests`
    /// via `crate::config::CONFIG_ENV_LOCK` so neither module's tests observe a
    /// `RAYFISH_CONFIG_DIR` bled through from the other.
    use crate::config::CONFIG_ENV_LOCK as ENV_LOCK;

    /// RAII guard that restores a previous env var value (or removes it if it
    /// was unset) on drop, so the var is restored even if the test body panics.
    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    // `ENV_LOCK` is a `Mutex<()>` used only to serialize whole tests against each
    // other; it guards no data mutated across the awaits, so holding it across
    // them is intentional (that is the point) and safe.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_headless_returns_usable_state_without_ipc_socket() {
        // Serialize against any other test that touches env vars read by
        // `config::config_dir()`, so no concurrent test observes a bled-through
        // `RAYFISH_CONFIG_DIR`.
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        // Isolate identity/config/blobs from the system config dir. The guard
        // restores the previous value (or removes the var) on drop, including
        // on panic, so this can't poison later tests.
        let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

        let daemon = tokio::time::timeout(std::time::Duration::from_secs(30), build_headless())
            .await
            .expect("build_headless should not hang")
            .expect("build_headless should succeed");

        // It returns a shared `Arc<DaemonState>`.
        assert!(Arc::strong_count(&daemon) >= 1);

        // The embedding `status()` API answers without a socket ever being bound.
        assert!(matches!(daemon.status(), IpcMessage::StatusResponse { .. }));
    }

    /// In-memory TUN writer that records every written packet into a shared
    /// buffer, so a test can observe which writer the data plane routed to.
    #[derive(Clone, Default)]
    struct FakeTunWriter {
        written: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl crate::tun::TunWrite for FakeTunWriter {
        async fn write_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
            self.written.lock().unwrap().push(packet.to_vec());
            Ok(())
        }
    }

    /// In-memory TUN reader that never yields a packet, so `run_mesh` parks in
    /// its read and only exits when its task is cancelled/aborted. It carries an
    /// `Arc<()>` liveness token: the reader is owned solely by the spawned
    /// `run_mesh` future, so the token's strong count drops back to the caller's
    /// single reference the moment that task's future is dropped on abort. That
    /// makes "the old data plane was torn down" directly observable.
    struct FakeTunReader {
        _alive: Arc<()>,
    }

    impl crate::tun::TunRead for FakeTunReader {
        async fn read_into(&mut self, _buf: &mut bytes::BytesMut) -> anyhow::Result<usize> {
            std::future::pending::<()>().await;
            unreachable!("FakeTunReader never returns");
        }
    }

    /// Poll `sink` until it holds `want` packets. Bounded (~2s total) so a real
    /// failure fails fast instead of hanging; the short poll interval leaves room
    /// for the cross-thread wakeup of the writer task without a fixed sleep that
    /// would either flake (too short) or slow the suite (too long).
    async fn wait_for_len(sink: &Arc<std::sync::Mutex<Vec<Vec<u8>>>>, want: usize) -> bool {
        for _ in 0..400 {
            if sink.lock().unwrap().len() >= want {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        false
    }

    /// Re-attaching the TUN after a `detach_tun` must resume forwarding to the
    /// new writer (the VPN off/on toggle path), and a second `attach_tun`
    /// WITHOUT an intervening detach must stop the previous writer instead of
    /// leaking it (two live writers on two fds).
    // See `build_headless_returns_usable_state_without_ipc_socket`: `ENV_LOCK`
    // only serializes tests and guards no data across the awaits.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attach_tun_is_self_healing_on_reattach_and_double_attach() {
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

        let daemon = tokio::time::timeout(std::time::Duration::from_secs(30), build_headless())
            .await
            .expect("build_headless should not hang")
            .expect("build_headless should succeed");

        use std::sync::atomic::Ordering;

        // Helper: send one packet through the same `tun_tx` cell the peer-reader
        // and DNS-injection paths use, then wait for the given writer to see it.
        async fn send_pkt(daemon: &Arc<DaemonState>, pkt: &'static [u8]) {
            daemon
                .tun_tx
                .load_full()
                .send(Bytes::from_static(pkt))
                .await
                .expect("tun_tx send should reach the live writer");
        }

        // Poll until `token`'s strong count falls back to 1 (only this test
        // holds it), i.e. the `run_mesh` task that owned the matching reader was
        // dropped. Bounded so a leak fails fast instead of hanging.
        async fn wait_for_reader_dropped(token: &Arc<()>) -> bool {
            for _ in 0..400 {
                if Arc::strong_count(token) == 1 {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            false
        }

        // 1. First attach: reader1 + writer1, forwarding active.
        let writer1 = FakeTunWriter::default();
        let sink1 = writer1.written.clone();
        daemon
            .attach_tun(FakeTunReader { _alive: Arc::new(()) }, writer1)
            .await;
        daemon.active.store(true, Ordering::SeqCst);

        send_pkt(&daemon, b"packet-1").await;
        assert!(
            wait_for_len(&sink1, 1).await,
            "writer1 should receive the first packet"
        );

        // 2. Toggle: detach, then re-attach reader2 + writer2. This is the path
        //    that used to silently break before the fresh-channel-per-attach fix.
        daemon.detach_tun();
        let writer2 = FakeTunWriter::default();
        let sink2 = writer2.written.clone();
        let alive2 = Arc::new(());
        daemon
            .attach_tun(FakeTunReader { _alive: alive2.clone() }, writer2)
            .await;
        daemon.active.store(true, Ordering::SeqCst);

        send_pkt(&daemon, b"packet-2").await;
        assert!(
            wait_for_len(&sink2, 1).await,
            "writer2 should receive the packet after a detach->attach toggle"
        );

        // 3. Double-attach guard: attach writer3 WITHOUT detaching first. The
        //    previous data plane (writer2's mesh loop + writer) must be aborted,
        //    not leaked. Observe both halves of "no two live data planes":
        //    - writer3 receives the packet (the cell now routes to writer3), and
        //    - reader2's `run_mesh` task was dropped (`alive2` count back to 1),
        //      which without the self-healing guard would leak and stay at 2.
        let writer3 = FakeTunWriter::default();
        let sink3 = writer3.written.clone();
        daemon
            .attach_tun(FakeTunReader { _alive: Arc::new(()) }, writer3)
            .await;
        daemon.active.store(true, Ordering::SeqCst);

        send_pkt(&daemon, b"packet-3").await;
        assert!(
            wait_for_len(&sink3, 1).await,
            "writer3 should receive the packet after a double-attach"
        );
        assert!(
            wait_for_reader_dropped(&alive2).await,
            "the prior mesh loop must be aborted on a second attach without detach (no leak)"
        );

        daemon.detach_tun();
    }
}
