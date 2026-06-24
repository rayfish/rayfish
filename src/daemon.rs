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
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

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

use crate::config;
use crate::control::{self, ControlMsg};
use crate::dht;
use crate::audit;
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
use ray_proto::SuggestedFirewall;
use crate::network_name;
use crate::peers::{self, PeerTable};
use crate::stats::ForwardMetrics;
use crate::transport;
use crate::tun::{self, check_cgnat_conflict};

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const PAIR_ALPN: &[u8] = b"rayfish/pair/1";

struct CoordinatorAcceptState {
    network_name: String,
    identity: IrohIdentityProvider,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Bytes>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    blob_store: FsStore,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
    /// Shared with this network's [`NetworkHandle`]; see its `invite_lock`.
    invite_lock: Arc<tokio::sync::Mutex<()>>,
}

impl CoordinatorAcceptState {
    async fn handle_connection(&self, conn: Connection) {
        let remote_id = conn.remote_id();
        let peer_ip = self.identity.derive_ip(&remote_id);

        // Known member reconnecting
        let is_member = self.state.read().unwrap().members.is_member(&remote_id);
        if is_member {
            tracing::info!(ip = %peer_ip, "known member reconnecting");
            crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
            let peer_ipv6 = derive_ipv6(&remote_id);
            self.peers.add(
                peer_ip,
                peer_ipv6,
                conn.clone(),
                remote_id,
                &self.network_name,
            );
            let token = self.token.clone();
            let stats = self.stats.clone();
            let tun_tx = self.tun_tx.clone();
            let disconnect_tx = self.disconnect_tx.clone();
            let network = self.network_name.clone();
            let firewall = self.firewall.clone();
            let state = self.state.clone();
            let hostname_table = self.hostname_table.clone();
            let reverse_table = self.reverse_table.clone();
            let device_user_map = self.device_user_map.clone();
            let peers_ctrl = self.peers.clone();
            let blob_store_ctrl = self.blob_store.clone();
            let dht_notify_ctrl = self.dht_notify.clone();
            let token_ctrl = token.clone();
            let network_ctrl = network.clone();
            tokio::spawn(async move {
                send_member_sync(&conn).await;
                spawn_coordinator_control_reader(
                    conn.clone(),
                    remote_id,
                    peer_ip,
                    network_ctrl,
                    state,
                    hostname_table,
                    reverse_table,
                    device_user_map.clone(),
                    peers_ctrl,
                    blob_store_ctrl,
                    dht_notify_ctrl,
                    token_ctrl,
                );
                forward::spawn_peer_reader(
                    conn,
                    remote_id,
                    peer_ip,
                    peer_ipv6,
                    network,
                    firewall,
                    tun_tx,
                    disconnect_tx,
                    token,
                    stats,
                    device_user_map,
                );
            });
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
            self.device_user_map.insert(remote_id, cert.user_identity);
        }

        // A peer pre-approved via `ray accept` is admitted directly.
        let is_approved = self.state.read().unwrap().approved.is_approved(&remote_id);
        if is_approved {
            // Live-approved name is joiner-chosen, not authoritative.
            self.admit_peer(conn, send, remote_id, peer_ip, hostname, device_cert, true, false)
                .await;
            return;
        }

        // Unknown peer presenting an invite secret: verify and burn it.
        if let Some(secret) = invite_secret {
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
                    }
                }
                Err(single_use_err) => {
                    // Not a single-use invite — it may be a reusable key, which
                    // lives in the signed blob and is redeemable by any network-key
                    // holder (no burn). The blob is the verified source of truth.
                    let reusable_id = {
                        let s = self.state.read().unwrap();
                        crate::membership::validate_reusable_key(
                            &s.reusable_keys,
                            &secret,
                            now_secs(),
                        )
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
            return;
        }

        // Unknown peer, no invite: open networks auto-admit; closed networks
        // queue the request for live operator approval (`ray accept`).
        let mode = self.state.read().unwrap().mode;
        match mode {
            GroupMode::Open => {
                // Open-mode name is joiner-chosen, not authoritative.
                self.admit_peer(conn, send, remote_id, peer_ip, hostname, device_cert, false, false)
                    .await;
            }
            GroupMode::Restricted => {
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
        peer_ip: Ipv4Addr,
        hostname: Option<String>,
        device_cert: Option<control::DeviceCert>,
        was_approved: bool,
        // The hostname is coordinator-authoritative (came from an invite binding).
        // Authoritative names are rejected on collision (no silent rename), so no
        // peer can claim another's name to take its suggested firewall rules.
        authoritative: bool,
    ) -> bool {
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
            self.deny(&conn, send, format!("IP collision: {peer_ip} already assigned"))
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
            });
            s.refresh_snapshot();
            s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
        };
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        if let Some(ref h) = final_hostname {
            dns::update_hostname(
                &self.hostname_table,
                &self.reverse_table,
                &self.network_name,
                h,
                peer_ip,
                derive_ipv6(&remote_id),
            )
            .await;
        }

        broadcast_control_msg(
            &self.peers,
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
            (
                s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                s.approved.all().into_iter().cloned().collect::<Vec<_>>(),
            )
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
        broadcast_member_sync(&self.peers, Some(peer_ip)).await;

        let peer_ipv6 = derive_ipv6(&remote_id);
        crate::spawn_path_logger(conn.clone(), remote_id.fmt_short().to_string());
        self.peers.add(
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
            self.hostname_table.clone(),
            self.reverse_table.clone(),
            self.device_user_map.clone(),
            self.peers.clone(),
            self.blob_store.clone(),
            self.dht_notify.clone(),
            self.token.clone(),
        );
        forward::spawn_peer_reader(
            conn,
            remote_id,
            peer_ip,
            peer_ipv6,
            self.network_name.clone(),
            self.firewall.clone(),
            self.tun_tx.clone(),
            self.disconnect_tx.clone(),
            self.token.clone(),
            self.stats.clone(),
            self.device_user_map.clone(),
        );
        true
    }
}

struct MemberAcceptState {
    network_name: String,
    state: Arc<std::sync::RwLock<NetworkState>>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Bytes>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    blob_store: FsStore,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
}

impl MemberAcceptState {
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
            self.device_user_map
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
            let taken: Vec<String> = {
                let s = self.state.read().unwrap();
                s.members
                    .all()
                    .iter()
                    .filter(|m| m.identity != peer_identity)
                    .filter_map(|m| m.hostname.clone())
                    .collect()
            };
            let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
            Some(crate::hostname::resolve_collision(&desired, &taken_refs))
        } else {
            None
        };
        // Update DNS table
        if let Some(ref h) = final_hostname {
            let ipv6 = derive_ipv6(&peer_identity);
            dns::update_hostname(
                &self.hostname_table,
                &self.reverse_table,
                &self.network_name,
                h,
                ip,
                ipv6,
            )
            .await;
        }
        if is_approved {
            let snap_bytes = {
                let mut s = self.state.write().unwrap();
                s.approved.remove(&peer_identity);
                let user_id_opt = device_cert.as_ref().map(|c| c.user_identity);
                let _ = s.members.add(Member {
                    identity: peer_identity,
                    ip,
                    is_coordinator: false,
                    hostname: final_hostname.clone(),
                    user_identity: user_id_opt,
                    device_cert: device_cert.clone(),
                });
                s.refresh_snapshot();
                s.snapshot.as_ref().map(|snap| snap.msgpack_bytes.clone())
            };
            if let Some(bytes) = snap_bytes {
                let _ = self.blob_store.blobs().add_slice(&bytes).await;
            }
            let (members, approved_list) = {
                let s = self.state.read().unwrap();
                (
                    s.members.all().into_iter().cloned().collect::<Vec<_>>(),
                    s.approved.all().into_iter().cloned().collect::<Vec<_>>(),
                )
            };
            if let Ok((mut send, _)) = conn.open_bi().await {
                let _ = control::send_msg(
                    &mut send,
                    &ControlMsg::Welcome {
                        members: members.clone(),
                        approved: approved_list,
                    },
                )
                .await;
            }
            let peer_ipv6 = derive_ipv6(&peer_identity);
            self.peers.add(
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
                self.firewall.clone(),
                self.tun_tx.clone(),
                self.disconnect_tx.clone(),
                self.token.clone(),
                self.stats.clone(),
                self.device_user_map.clone(),
            );
            broadcast_member_sync(&self.peers, Some(ip)).await;
        } else if is_member {
            if final_hostname.is_some() {
                let mut s = self.state.write().unwrap();
                if let Some(m) = s.members.get_mut(&peer_identity) {
                    m.hostname = final_hostname;
                }
            }
            let peer_ipv6 = derive_ipv6(&peer_identity);
            self.peers.add(
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
                self.firewall.clone(),
                self.tun_tx.clone(),
                self.disconnect_tx.clone(),
                self.token.clone(),
                self.stats.clone(),
                self.device_user_map.clone(),
            );
        }
    }
}

enum AcceptHandler {
    Coordinator(Arc<CoordinatorAcceptState>),
    Member(Arc<MemberAcceptState>),
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

struct ProtocolRouter {
    blobs: BlobsProtocol,
    handlers: DashMap<Vec<u8>, Arc<MeshProtocol>>,
    pending_files: Arc<std::sync::Mutex<Vec<PendingFile>>>,
    file_id_counter: Arc<AtomicU64>,
    pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    secret_key: SecretKey,
}

impl ProtocolRouter {
    fn new(
        blobs: BlobsProtocol,
        secret_key: SecretKey,
        pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    ) -> Self {
        Self {
            blobs,
            handlers: DashMap::new(),
            pending_files: Arc::new(std::sync::Mutex::new(Vec::new())),
            file_id_counter: Arc::new(AtomicU64::new(1)),
            pairing_secret,
            secret_key,
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
                                a if a == transport::FILES_ALPN => {
                                    let pending = router.pending_files.clone();
                                    let counter = router.file_id_counter.clone();
                                    let remote_id = conn.remote_id();
                                    match conn.accept_bi().await {
                                        Ok((_send, mut recv)) => {
                                            match control::recv_msg(&mut recv).await {
                                                Ok(control::ControlMsg::FileOffer { from, filename, size, mime_type, blob_hash }) => {
                                                    if from == remote_id {
                                                        let id = counter.fetch_add(1, Ordering::Relaxed);
                                                        tracing::info!(from = %from.fmt_short(), filename = %filename, size, "file offer received");
                                                        pending.lock().unwrap().push(PendingFile { id, from, filename, size, mime_type, blob_hash });
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
                                a if a == PAIR_ALPN => {
                                    let pairing_secret = router.pairing_secret.clone();
                                    let secret_key = router.secret_key.clone();
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
                                                control::PairMsg::Request { secret, device_pubkey } => {
                                                    // Verify the secret matches the stored pairing secret
                                                    let stored = pairing_secret.lock().unwrap().take();
                                                    match stored {
                                                        Some(expected) if expected == secret => {
                                                            // Sign the device's public key
                                                            let cert = control::DeviceCert::create(&secret_key, &device_pubkey);
                                                            let response = control::PairMsg::Response { cert };
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
                                                            let _ = tokio::time::timeout(
                                                                Duration::from_secs(5),
                                                                conn.closed(),
                                                            )
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

struct NetworkState {
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
    state: Arc<std::sync::RwLock<NetworkState>>,
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
}

/// Shared, always-on daemon state. Cloned (via `Arc`) into every IPC handler
/// and background task. Holds both the infrastructure that lives for the whole
/// process and the handles for the currently-active networks. See the
/// module-level docs for the two-lifecycle model.
pub struct DaemonState {
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
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    mdns_enabled: bool,
    tun_name: String,
    pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    device_cert: Option<control::DeviceCert>,
    device_user_map: peers::DeviceUserMap,
    /// Whether the VPN is currently active (TUN up, networks connected) or on
    /// standby. Toggled by the `Up`/`Down` IPC commands.
    active: Arc<AtomicBool>,
    /// The system-DNS configurator owned while active, so `Down` can revert it.
    dns_configurator: Arc<std::sync::Mutex<Option<Box<dyn dns_config::DnsConfigurator>>>>,
}

impl DaemonState {
    async fn refresh_alpns(&self) {
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

    /// Tailscale-style access control. Read-only queries are open to any local
    /// user; mutating commands require the caller to be root or the configured
    /// operator UID; setting the operator itself is root-only. Returns `None`
    /// when the request is permitted, or `Some(error)` to short-circuit it.
    ///
    /// Identity is taken from the connecting socket's `SO_PEERCRED` (the kernel
    /// vouches for it — it can't be forged by the client), so the socket file
    /// mode only has to permit the connection, not gate authority.
    fn check_authorized(req: &IpcMessage, peer_cred: Option<(u32, u32)>) -> Option<IpcMessage> {
        // Reads are available to everyone.
        if matches!(
            req,
            IpcMessage::Status
                | IpcMessage::Report
                | IpcMessage::FirewallShow
                | IpcMessage::FirewallSuggestions { .. }
                | IpcMessage::FirewallPending { .. }
                | IpcMessage::ListFiles
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
    fn set_operator(&self, uid: u32) -> IpcMessage {
        let mut app_config = match config::load() {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        };
        app_config.operator_uid = Some(uid);
        if let Err(e) = config::save(&app_config) {
            return IpcMessage::Error {
                message: format!("failed to save config: {e}"),
            };
        }
        IpcMessage::Ok {
            message: format!("operator set to uid {uid}; that user can now run ray without sudo"),
        }
    }

    async fn handle_request(
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
                &direction,
                &action,
                &protocol,
                port.as_deref(),
                peer.as_deref(),
                network.as_deref(),
            ),
            IpcMessage::FirewallRemove { index } => self.firewall_remove(index),
            IpcMessage::FirewallShow => self.firewall_show(),
            IpcMessage::FirewallDefault { action } => self.firewall_default(&action),
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
            IpcMessage::AdminAdd { network, identity } => {
                self.admin_add(&network, &identity).await
            }
            IpcMessage::AdminList { network } => self.admin_list(&network),
            other => IpcMessage::Error {
                message: format!("unexpected message: {:?}", other),
            },
        }
    }

    #[tracing::instrument(skip(self, hostname), fields(mode = ?mode))]
    async fn create_network(
        &self,
        mode: GroupMode,
        name: Option<String>,
        hostname: Option<String>,
    ) -> IpcMessage {
        match self.create_network_inner(mode, name, hostname).await {
            Ok(resp) => resp,
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    async fn create_network_inner(
        &self,
        mode: GroupMode,
        custom_name: Option<String>,
        hostname: Option<String>,
    ) -> Result<IpcMessage> {
        let name = match custom_name {
            Some(n) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&n),
                    "invalid network name '{n}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                n
            }
            None => network_name::generate_name(),
        };

        // Generate per-network keypair
        let net_secret_key = SecretKey::generate();
        let net_public_key = net_secret_key.public();

        if self.networks.contains_key(&name) {
            return Ok(IpcMessage::Error {
                message: format!("network '{name}' already active"),
            });
        }

        let my_ip = self.identity.local_ip();

        let my_hostname = match hostname {
            Some(h) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&h),
                    "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                h
            }
            None => config::load()
                .ok()
                .and_then(|c| c.default_hostname)
                .unwrap_or_else(crate::hostname::generate_hostname),
        };

        let mut member_list = MemberList::new();
        member_list
            .add(Member {
                identity: self.identity.local_identity(),
                ip: my_ip,
                is_coordinator: true,
                hostname: Some(my_hostname.clone()),
                user_identity: None,
                device_cert: None,
            })
            .expect("self-add cannot collide");

        // Register in DNS hostname table
        dns::update_hostname(
            &self.hostname_table,
            &self.reverse_table,
            &name,
            &my_hostname,
            my_ip,
            derive_ipv6(&self.identity.local_identity()),
        )
        .await;

        let mut net_state = NetworkState {
            members: member_list,
            approved: ApprovedList::new(),
            snapshot: None,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_public_key,
            network_name: Some(name.clone()),
            mode,
            suggested_firewall: SuggestedFirewall::default(),
            reusable_keys: BTreeMap::new(),
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        };

        net_state.refresh_snapshot();
        if let Some(snap) = &net_state.snapshot {
            let _ = self.blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }

        // Publish single pkarr record
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            let blob_hash = net_state
                .snapshot
                .as_ref()
                .map(|s| s.hash)
                .expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                &net_secret_key,
                &blob_hash,
                &[self.endpoint.id()],
            )
            .await
            {
                tracing::warn!(error = %e, "failed to publish network record");
            }
        }

        // Save to config
        let member_entries = net_state
            .members
            .all()
            .into_iter()
            .map(|m| config::MemberEntry {
                identity: m.identity,
                ip: m.ip,
                is_coordinator: m.is_coordinator,
                hostname: m.hostname.clone(),
            })
            .collect();
        let approved_entries = net_state
            .approved
            .all()
            .into_iter()
            .map(|a| config::ApprovedConfigEntry {
                identity: a.identity,
                ip: a.ip,
                hostname: a.hostname.clone(),
            })
            .collect();
        let mut app_config = config::load()?;
        config::upsert_network(
            &mut app_config,
            config::NetworkConfig {
                name: name.clone(),
                group_mode: mode,
                my_ip: Some(my_ip),
                my_hostname: Some(my_hostname.clone()),
                members: member_entries,
                approved: approved_entries,
                network_secret_key: Some(net_secret_key.clone()),
                network_public_key: Some(net_public_key),
                transport: None,
                auto_accept_firewall: false,
                admins: vec![],
            },
        );
        config::save(&app_config)?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let invite_lock = Arc::new(tokio::sync::Mutex::new(()));
        let mut tasks = Vec::new();

        // Network publisher (single pkarr record: blob hash + seed peers)
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_network_publisher(
                pkarr_client,
                net_secret_key.clone(),
                state.clone(),
                self.endpoint.id(),
                self.peers.clone(),
                name.clone(),
                dht_notify.clone(),
                cancel.clone(),
            ));
        }

        // Disconnect handler (coordinator removes dead peers)
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(
            disconnect_rx,
            self.peers.clone(),
            cancel.clone(),
            Some(CoordinatorCleanup {
                state: state.clone(),
                blob_store: self.blob_store.clone(),
                dht_notify: Some(dht_notify.clone()),
                hostname_table: self.hostname_table.clone(),
                reverse_table: self.reverse_table.clone(),
                device_user_map: self.device_user_map.clone(),
                network_name: name.clone(),
            }),
        ));

        // Register protocol handler for this network
        self.protocol_router.register(
            transport::network_alpn(&net_public_key),
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                network_name: name.clone(),
                identity: self.identity.clone(),
                state: state.clone(),
                peers: self.peers.clone(),
                tun_tx: self.tun_tx.clone(),
                disconnect_tx,
                token: cancel.clone(),
                stats: self.stats.clone(),
                dht_notify: Some(dht_notify.clone()),
                blob_store: self.blob_store.clone(),
                firewall: self.firewall.clone(),
                hostname_table: self.hostname_table.clone(),
                reverse_table: self.reverse_table.clone(),
                device_user_map: self.device_user_map.clone(),
                invite_lock: invite_lock.clone(),
            })),
        );

        // Update ALPNs
        let handle = NetworkHandle {
            name: name.clone(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            dht_notify: Some(dht_notify),
            cancel,
            tasks,
            invite_lock,
        };
        self.networks.insert(name.clone(), handle);
        self.refresh_alpns().await;

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network created");

        Ok(IpcMessage::Created {
            name,
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        })
    }

    #[tracing::instrument(skip(self, hostname), fields(net = name.unwrap_or(network_key)))]
    async fn join_network(
        self: &Arc<Self>,
        network_key: &str,
        name: Option<&str>,
        hostname: Option<String>,
        invite: Option<Vec<u8>>,
        coordinator: Option<EndpointId>,
        auto_accept_firewall: bool,
    ) -> IpcMessage {
        match self
            .join_network_inner(
                network_key,
                name,
                hostname.clone(),
                invite.clone(),
                coordinator,
                auto_accept_firewall,
                true,
            )
            .await
        {
            Ok(TryJoin::Joined(resp)) => resp,
            Ok(TryJoin::Pending) => {
                // Closed network: queued for live approval. Retry in the
                // background on a backoff until `ray accept` admits us.
                let me = Arc::clone(self);
                let nk = network_key.to_string();
                let nm = name.map(|s| s.to_string());
                tokio::spawn(async move {
                    let mut backoff = BACKOFF_INITIAL;
                    loop {
                        tokio::select! {
                            _ = me.shutdown_token.cancelled() => return,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        match me
                            .join_network_inner(
                                &nk,
                                nm.as_deref(),
                                hostname.clone(),
                                invite.clone(),
                                coordinator,
                                auto_accept_firewall,
                                true,
                            )
                            .await
                        {
                            Ok(TryJoin::Joined(_)) => {
                                tracing::info!(net = %nk, "approval granted — joined");
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
                    message: "join request sent — waiting for coordinator approval (run `ray status` to check)"
                        .to_string(),
                }
            }
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn join_network_inner(
        self: &Arc<Self>,
        network_key: &str,
        alias: Option<&str>,
        hostname: Option<String>,
        invite: Option<Vec<u8>>,
        coordinator: Option<EndpointId>,
        // Auto-install coordinator-suggested firewall rules on this network
        // (`--auto-accept-firewall`); persisted so it survives restarts.
        auto_accept_firewall: bool,
        // True for a fresh join (we send a JoinRequest first); false when
        // restoring a network we're already a member of (legacy handshake where
        // the coordinator speaks first).
        initial: bool,
    ) -> Result<TryJoin> {
        let net_pubkey: EndpointId = network_key.parse().context("invalid network key")?;

        if let Some(a) = alias
            && self.networks.contains_key(a)
        {
            anyhow::bail!("already in network '{a}'");
        }

        // Resolve single pkarr record → (blob_hash, seed_peers)
        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, peer_ids) = dht::resolve_network(&pkarr_client, net_pubkey)
            .await
            .context("failed to resolve network record")?;

        if peer_ids.is_empty() {
            anyhow::bail!("no peers found in network record");
        }

        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        let mut group_blob = None;
        for peer_id in &peer_ids {
            match self.try_fetch_group_blob(*peer_id, blob_hash).await {
                Ok(data) => {
                    group_blob = Some(data);
                    break;
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id.fmt_short(), error = %e, "failed to fetch blob");
                    continue;
                }
            }
        }

        let data = group_blob.context("could not fetch group blob from any peer")?;

        let alpn = transport::network_alpn(&net_pubkey);
        let my_ip = self.identity.local_ip();
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

        // Admission always runs through the coordinator (only it can approve an
        // unknown peer or redeem an invite). An invite pins the coordinator's id;
        // otherwise it's the member flagged `is_coordinator` in the GroupBlob.
        let coordinator_id = coordinator
            .or_else(|| {
                data.members
                    .iter()
                    .find(|m| m.is_coordinator)
                    .map(|m| m.identity)
            })
            .context("no coordinator found in network record")?;
        tracing::info!(coordinator = %coordinator_id.fmt_short(), "connecting to coordinator");
        let conn = transport::connect_to_peer_with_alpn(&self.endpoint, coordinator_id, &alpn)
            .await
            .map_err(|e| {
                anyhow::anyhow!("coordinator offline; cannot join this network right now: {e}")
            })?;

        let my_hostname = match hostname {
            Some(h) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&h),
                    "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                h
            }
            None => config::load()
                .ok()
                .and_then(|c| c.default_hostname)
                .unwrap_or_else(crate::hostname::generate_hostname),
        };

        let cancel = self.shutdown_token.child_token();
        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

        let tasks = vec![spawn_reconnect_loop(
            disconnect_rx,
            self.endpoint.clone(),
            alpn.clone(),
            display_name.to_string(),
            self.identity.local_identity(),
            my_ip,
            Some(my_hostname.clone()),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
            self.stats.clone(),
            self.firewall.clone(),
            self.device_cert.clone(),
            self.device_user_map.clone(),
        )];

        let state = match join_mesh_shared(
            conn,
            &self.endpoint,
            display_name,
            &self.identity,
            &alpn,
            Some(my_hostname.clone()),
            self.peers.clone(),
            self.tun_tx.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
            self.stats.clone(),
            self.blob_store.clone(),
            self.firewall.clone(),
            net_pubkey,
            self.device_cert.clone(),
            self.device_user_map.clone(),
            self.hostname_table.clone(),
            self.reverse_table.clone(),
            invite,
            data.suggested_firewall.clone(),
            data.reusable_keys.clone(),
            auto_accept_firewall,
            initial,
        )
        .await?
        {
            JoinResult::Joined(state) => state,
            JoinResult::Pending => {
                // Closed network: we've been queued for live approval. Stop the
                // just-spawned reconnect loop (nothing is connected yet) and let
                // the caller retry on a backoff until `ray accept` lets us in.
                cancel.cancel();
                return Ok(TryJoin::Pending);
            }
        };

        self.protocol_router.register(
            alpn.clone(),
            AcceptHandler::Member(Arc::new(MemberAcceptState {
                network_name: display_name.to_string(),
                state: state.clone(),
                peers: self.peers.clone(),
                tun_tx: self.tun_tx.clone(),
                disconnect_tx,
                token: cancel.clone(),
                stats: self.stats.clone(),
                blob_store: self.blob_store.clone(),
                firewall: self.firewall.clone(),
                hostname_table: self.hostname_table.clone(),
                reverse_table: self.reverse_table.clone(),
                device_user_map: self.device_user_map.clone(),
            })),
        );

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
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }

        // Save config with network public key (use display_name for config)
        if let Ok(mut app_config) = config::load() {
            if let Some(net) = app_config
                .networks
                .iter_mut()
                .find(|n| n.name == display_name)
            {
                net.network_public_key = Some(net_pubkey);
            }
            let _ = config::save(&app_config);
        }

        // Membership poller
        let mut tasks = tasks;
        if let Ok(poller_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_group_poller(
                poller_client,
                net_pubkey,
                state.clone(),
                self.endpoint.clone(),
                self.blob_store.clone(),
                self.peers.clone(),
                display_name.to_string(),
                self.firewall.clone(),
                cancel.clone(),
            ));
        }

        let handle = NetworkHandle {
            name: display_name.to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Member,
            my_ip,
            state,
            dht_notify: None,
            cancel,
            tasks,
            invite_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        self.networks.insert(display_name.to_string(), handle);
        self.refresh_alpns().await;

        // Register hostnames in DNS table
        dns::update_hostname(
            &self.hostname_table,
            &self.reverse_table,
            display_name,
            &my_hostname,
            my_ip,
            derive_ipv6(&self.identity.local_identity()),
        )
        .await;
        for member in &data.members {
            if let Some(ref h) = member.hostname {
                dns::update_hostname(
                    &self.hostname_table,
                    &self.reverse_table,
                    display_name,
                    h,
                    member.ip,
                    derive_ipv6(&member.identity),
                )
                .await;
            }
        }

        tracing::info!(network = %display_name, key = %network_key, ip = %my_ip, "joined network");

        Ok(TryJoin::Joined(IpcMessage::Joined {
            name: display_name.to_string(),
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        }))
    }

    /// Fetch the authoritative GroupBlob for a network we coordinate, used to
    /// restore the roster across a daemon restart. Resolves the pkarr record to
    /// get the blob hash, reads the bytes back from the local blob store (where
    /// we stored them before publishing — no network round-trip), and verifies +
    /// decodes. Falls back to fetching from a seed peer if the local store
    /// doesn't have them (e.g. blobs dir was wiped). Returns an error if the DHT
    /// is unreachable, so the caller can fall back to the (possibly stale)
    /// config roster rather than booting empty.
    async fn restore_roster_from_blob(
        &self,
        net_pubkey: EndpointId,
    ) -> Result<crate::membership::GroupBlob> {
        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, seed_peers) = dht::resolve_network(&pkarr_client, net_pubkey)
            .await
            .context("resolve pkarr record for roster restore")?;
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        // Local blob store first: the coordinator stored these bytes before
        // publishing, so they're on disk.
        if let Ok(bytes) = self.blob_store.blobs().get_bytes(blob_hash).await
            && let Ok(data) = verify_group_blob(&bytes, &expected_hash)
        {
            return Ok(data);
        }

        // Fall back to fetching from a seed peer.
        for peer_id in &seed_peers {
            if *peer_id == self.endpoint.id() {
                continue;
            }
            let conn = match transport::connect_to_peer_with_alpn(
                &self.endpoint,
                *peer_id,
                iroh_blobs::protocol::ALPN,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => continue,
            };
            if self
                .blob_store
                .remote()
                .fetch(conn, HashAndFormat::raw(blob_hash))
                .await
                .is_err()
            {
                continue;
            }
            if let Ok(bytes) = self.blob_store.blobs().get_bytes(blob_hash).await
                && let Ok(data) = verify_group_blob(&bytes, &expected_hash)
            {
                return Ok(data);
            }
        }
        anyhow::bail!("group blob not found locally or at any seed peer");
    }

    async fn try_fetch_group_blob(
        &self,
        peer_id: EndpointId,
        blob_hash: iroh_blobs::Hash,
    ) -> Result<crate::membership::GroupBlob> {
        let conn = transport::connect_to_peer_with_alpn(
            &self.endpoint,
            peer_id,
            iroh_blobs::protocol::ALPN,
        )
        .await?;
        self.blob_store
            .remote()
            .fetch(conn, HashAndFormat::raw(blob_hash))
            .await
            .map_err(|e| anyhow::anyhow!("blob fetch failed: {e}"))?;
        let bytes = self
            .blob_store
            .blobs()
            .get_bytes(blob_hash)
            .await
            .map_err(|e| anyhow::anyhow!("blob read failed: {e}"))?;
        crate::membership::decode_group_blob(&bytes)
    }

    #[allow(dead_code)]
    async fn try_dht_fallback_join(
        &self,
        network_name: &str,
        net_pubkey: EndpointId,
        alpn: &[u8],
    ) -> Result<IpcMessage> {
        tracing::info!(network = %network_name, "trying DHT fallback");

        let pkarr_client = dht::create_pkarr_client(&self.endpoint)?;
        let (expected_hash, _peer_ids) = dht::resolve_network(&pkarr_client, net_pubkey).await?;

        let my_identity = self.identity.local_identity();
        let blob_hash = iroh_blobs::Hash::from_bytes(*expected_hash.as_bytes());

        let app_config = config::load()?;
        let net_config = app_config
            .networks
            .iter()
            .find(|n| n.name == network_name)
            .context("network not in config")?;

        for member in &net_config.members {
            if member.identity == my_identity {
                continue;
            }

            let blobs_conn = match transport::connect_to_peer_with_alpn(
                &self.endpoint,
                member.identity,
                iroh_blobs::protocol::ALPN,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => continue,
            };

            if self
                .blob_store
                .remote()
                .fetch(blobs_conn, HashAndFormat::raw(blob_hash))
                .await
                .is_err()
            {
                continue;
            }

            let blob_bytes = match self.blob_store.blobs().get_bytes(blob_hash).await {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            let data = verify_group_blob(&blob_bytes, &expected_hash)?;
            tracing::info!(network = %network_name, members = data.members.len(), "group blob resolved via DHT fallback");

            let my_ip = self.identity.local_ip();
            let my_hostname = net_config.my_hostname.clone();
            let cancel = self.shutdown_token.child_token();
            let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);

            let tasks = vec![spawn_reconnect_loop(
                disconnect_rx,
                self.endpoint.clone(),
                alpn.to_vec(),
                network_name.to_string(),
                my_identity,
                my_ip,
                my_hostname.clone(),
                self.peers.clone(),
                self.tun_tx.clone(),
                disconnect_tx.clone(),
                cancel.clone(),
                self.stats.clone(),
                self.firewall.clone(),
                self.device_cert.clone(),
                self.device_user_map.clone(),
            )];

            self.dial_all_members(
                &data.members,
                alpn,
                network_name,
                my_identity,
                my_ip,
                my_hostname.clone(),
                disconnect_tx.clone(),
                cancel.clone(),
            )
            .await;



            let mut ns = NetworkState {
                members: MemberList::from_members(data.members),
                approved: ApprovedList::from_entries(data.approved),
                snapshot: None,
                network_secret_key: None,
                network_public_key: net_pubkey,
                network_name: data.name.clone(),
                mode: GroupMode::Restricted,
                suggested_firewall: SuggestedFirewall::default(),
                reusable_keys: data.reusable_keys.clone(),
                pending_suggestions: Vec::new(),
                pending: HashMap::new(),
            };
            ns.refresh_snapshot();
            let live_state = Arc::new(std::sync::RwLock::new(ns));

            let handle = NetworkHandle {
                name: network_name.to_string(),
                network_key: net_pubkey,
                role: NetworkRole::Member,
                my_ip,
                state: live_state,
                dht_notify: None,
                cancel,
                tasks,
                invite_lock: Arc::new(tokio::sync::Mutex::new(())),
            };
            self.networks.insert(network_name.to_string(), handle);
            self.refresh_alpns().await;

            return Ok(IpcMessage::Joined {
                name: network_name.to_string(),
                my_ip,
                my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
            });
        }

        anyhow::bail!("no peers reachable for DHT fallback")
    }

    /// Dial every known member of a network: open a QUIC connection on the
    /// network ALPN, send `MeshHello`, register the peer in the PeerTable, and
    /// spawn a peer reader for each. Shared by the join path and coordinator
    /// restore so a restarting coordinator/co-coordinator proactively
    /// reconnects to **all** known members (full mesh), not just the peers
    /// that happen to dial in. Failures per-peer are logged at debug and
    /// skipped (the reconnect loop + group poller are the backstop).
    #[allow(clippy::too_many_arguments)]
    async fn dial_all_members(
        &self,
        members: &[Member],
        alpn: &[u8],
        network_name: &str,
        my_identity: EndpointId,
        my_ip: Ipv4Addr,
        my_hostname: Option<String>,
        disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
        cancel: CancellationToken,
    ) {
        for m in members {
            if m.identity == my_identity {
                continue;
            }
            match transport::connect_to_peer_with_alpn(&self.endpoint, m.identity, alpn).await {
                Ok(peer_conn) => {
                    if let Ok((mut s, _)) = peer_conn.open_bi().await {
                        let _ = control::send_msg(
                            &mut s,
                            &ControlMsg::MeshHello {
                                identity: my_identity,
                                ip: my_ip,
                                hostname: my_hostname.clone(),
                                device_cert: self.device_cert.clone(),
                            },
                        )
                        .await;
                    }
                    crate::spawn_path_logger(
                        peer_conn.clone(),
                        m.identity.fmt_short().to_string(),
                    );
                    self.peers.add(
                        m.ip,
                        derive_ipv6(&m.identity),
                        peer_conn.clone(),
                        m.identity,
                        network_name,
                    );
                    forward::spawn_peer_reader(
                        peer_conn,
                        m.identity,
                        m.ip,
                        derive_ipv6(&m.identity),
                        network_name.to_string(),
                        self.firewall.clone(),
                        self.tun_tx.clone(),
                        disconnect_tx.clone(),
                        cancel.clone(),
                        self.stats.clone(),
                        self.device_user_map.clone(),
                    );
                    tracing::info!(
                        network = %network_name,
                        peer = %m.identity.fmt_short(),
                        "dialed known member on restore/join (full mesh)"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        network = %network_name,
                        peer = %m.identity.fmt_short(),
                        error = %e,
                        "could not dial member yet; reconnect loop will retry"
                    );
                }
            }
        }
    }

    /// Restores a coordinator network from saved config (uses the existing name).
    async fn restore_coordinator_network(&self, name: &str, mode: GroupMode) -> Result<IpcMessage> {
        {
            if self.networks.contains_key(name) {
                return Ok(IpcMessage::Error {
                    message: format!("network '{name}' already active"),
                });
            }
        }

        let my_ip = self.identity.local_ip();

        // Load persisted network secret key from config
        let app_config = config::load()?;
        let net_config = app_config.networks.iter().find(|n| n.name == name);
        let net_secret_key = net_config
            .and_then(|nc| nc.network_secret_key.clone())
            .context("no network secret key in config — cannot restore as coordinator")?;
        let net_public_key = net_secret_key.public();
        let persisted_hostname = net_config.and_then(|nc| nc.my_hostname.clone());

        // Restore membership from the authoritative published GroupBlob. The blob
        // (members + approved) is signed by the per-network key and published
        // to DHT, so it is the source of truth and survives a daemon restart. The
        // local blob store still holds the bytes we published before going down, so
        // we read them back by the hash in the pkarr record (falling back to a seed
        // peer, then to the stale config roster only if the DHT is unreachable).
        // Restoring from the blob is also what prevents a clobber: the rebuilt
        // snapshot hashes identical to the published record, so the periodic
        // re-publish becomes a no-op instead of overwriting the roster with a
        // coordinator-only stub.
        let mut member_list = MemberList::new();
        let mut approved_list = ApprovedList::new();
        // `suggested_firewall` is authoritative in the signed blob; fall back to
        // an empty set only if the blob can't be fetched.
        let mut suggested_firewall = SuggestedFirewall::default();
        // Reusable join keys are authoritative in the signed blob too.
        let mut reusable_keys = BTreeMap::new();
        match self.restore_roster_from_blob(net_public_key).await {
            Ok(data) => {
                suggested_firewall = data.suggested_firewall.clone();
                reusable_keys = data.reusable_keys.clone();
                for m in &data.members {
                    let _ = member_list.add(m.clone());
                }
                for a in &data.approved {
                    let _ = approved_list.approve(a.clone(), &member_list);
                }
                tracing::info!(
                    network = %name,
                    members = member_list.all().len(),
                    "restored roster from published group blob"
                );
            }
            Err(e) => {
                tracing::warn!(
                    network = %name,
                    error = %e,
                    "could not restore roster from DHT blob; falling back to config (may be stale)"
                );
                if let Some(nc) = net_config {
                    for entry in &nc.members {
                        let _ = member_list.add(Member {
                            identity: entry.identity,
                            ip: entry.ip,
                            is_coordinator: entry.is_coordinator,
                            hostname: entry.hostname.clone(),
                            user_identity: None,
                            device_cert: None,
                        });
                    }
                    for entry in &nc.approved {
                        let ae = ApprovedEntry {
                            identity: entry.identity,
                            ip: entry.ip,
                            hostname: entry.hostname.clone(),
                            user_identity: None,
                            device_cert: None,
                        };
                        let _ = approved_list.approve(ae, &member_list);
                    }
                }
            }
        }
        if !member_list.is_member(&self.identity.local_identity()) {
            member_list
                .add(Member {
                    identity: self.identity.local_identity(),
                    ip: my_ip,
                    is_coordinator: true,
                    hostname: persisted_hostname.clone(),
                    user_identity: None,
                    device_cert: None,
                })
                .expect("self-add cannot collide");
        }

        let mut net_state = NetworkState {
            members: member_list,
            approved: approved_list,
            snapshot: None,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_public_key,
            network_name: Some(name.to_string()),
            mode,
            suggested_firewall,
            reusable_keys,
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
        };

        net_state.refresh_snapshot();
        if let Some(snap) = &net_state.snapshot {
            let _ = self.blob_store.blobs().add_slice(&snap.msgpack_bytes).await;
        }

        // Publish single pkarr record
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            let blob_hash = net_state
                .snapshot
                .as_ref()
                .map(|s| s.hash)
                .expect("snapshot set");
            if let Err(e) = dht::publish_network(
                &pkarr_client,
                &net_secret_key,
                &blob_hash,
                &[self.endpoint.id()],
            )
            .await
            {
                tracing::warn!(error = %e, "failed to publish network record on restore");
            }
        }

        // Update config
        let member_entries = net_state
            .members
            .all()
            .into_iter()
            .map(|m| config::MemberEntry {
                identity: m.identity,
                ip: m.ip,
                is_coordinator: m.is_coordinator,
                hostname: m.hostname.clone(),
            })
            .collect();
        let approved_entries = net_state
            .approved
            .all()
            .into_iter()
            .map(|a| config::ApprovedConfigEntry {
                identity: a.identity,
                ip: a.ip,
                hostname: a.hostname.clone(),
            })
            .collect();
        let mut app_config = config::load()?;
        config::upsert_network(
            &mut app_config,
            config::NetworkConfig {
                name: name.to_string(),
                group_mode: mode,
                my_ip: Some(my_ip),
                my_hostname: persisted_hostname.clone(),
                members: member_entries,
                approved: approved_entries,
                network_secret_key: Some(net_secret_key.clone()),
                network_public_key: Some(net_public_key),
                transport: None,
                // Preserve the persisted consent flag + admin roster across a
                // restart; only the roster (members/approved) is authoritative
                // from the blob.
                auto_accept_firewall: net_config
                    .map(|nc| nc.auto_accept_firewall)
                    .unwrap_or(false),
                admins: net_config.map(|nc| nc.admins.clone()).unwrap_or_default(),
            },
        );
        config::save(&app_config)?;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let invite_lock = Arc::new(tokio::sync::Mutex::new(()));
        let mut tasks = Vec::new();

        let dht_notify = Arc::new(tokio::sync::Notify::new());
        if let Ok(pkarr_client) = dht::create_pkarr_client(&self.endpoint) {
            tasks.push(spawn_network_publisher(
                pkarr_client,
                net_secret_key.clone(),
                state.clone(),
                self.endpoint.id(),
                self.peers.clone(),
                name.to_string(),
                dht_notify.clone(),
                cancel.clone(),
            ));
        }

        let (disconnect_tx, disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(64);
        tasks.push(spawn_peer_cleanup(
            disconnect_rx,
            self.peers.clone(),
            cancel.clone(),
            Some(CoordinatorCleanup {
                state: state.clone(),
                blob_store: self.blob_store.clone(),
                dht_notify: Some(dht_notify.clone()),
                hostname_table: self.hostname_table.clone(),
                reverse_table: self.reverse_table.clone(),
                device_user_map: self.device_user_map.clone(),
                network_name: name.to_string(),
            }),
        ));

        self.protocol_router.register(
            transport::network_alpn(&net_public_key),
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                network_name: name.to_string(),
                identity: self.identity.clone(),
                state: state.clone(),
                peers: self.peers.clone(),
                tun_tx: self.tun_tx.clone(),
                disconnect_tx: disconnect_tx.clone(),
                token: cancel.clone(),
                stats: self.stats.clone(),
                dht_notify: Some(dht_notify.clone()),
                blob_store: self.blob_store.clone(),
                firewall: self.firewall.clone(),
                hostname_table: self.hostname_table.clone(),
                reverse_table: self.reverse_table.clone(),
                device_user_map: self.device_user_map.clone(),
                invite_lock: invite_lock.clone(),
            })),
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
                            .map(|h| (h.clone(), m.ip, derive_ipv6(&m.identity)))
                    })
                    .collect()
            };
            for (hostname, ip, ipv6) in members_snapshot {
                dns::update_hostname(
                    &self.hostname_table,
                    &self.reverse_table,
                    name,
                    &hostname,
                    ip,
                    ipv6,
                )
                .await;
            }
        }

        // Full mesh: proactively dial every known member so a restarting
        // coordinator/co-coordinator reconnects to peers that haven't (yet)
        // dialed in. Without this, a co-coordinator that comes back up only
        // learns about peers that connect *to it*; it never dials out, so two
        // co-coordinators restarting together can each show the other as
        // offline until one is manually disturbed. Done before the handle
        // takes ownership of `state`/`cancel`/`disconnect_tx`; the accept
        // handler is already registered so return traffic is handled.
        let members_to_dial: Vec<Member> =
            state.read().unwrap().members.all().into_iter().cloned().collect();
        let alpn = transport::network_alpn(&net_public_key);
        self.dial_all_members(
            &members_to_dial,
            &alpn,
            name,
            self.identity.local_identity(),
            my_ip,
            persisted_hostname.clone(),
            disconnect_tx.clone(),
            cancel.clone(),
        )
        .await;

        let handle = NetworkHandle {
            name: name.to_string(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            my_ip,
            state,
            dht_notify: Some(dht_notify),
            cancel,
            tasks,
            invite_lock,
        };
        self.networks.insert(name.to_string(), handle);
        self.refresh_alpns().await;

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network restored (coordinator)");

        Ok(IpcMessage::Created {
            name: name.to_string(),
            network_key: net_public_key,
            my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
        })
    }

    #[tracing::instrument(skip(self), fields(net = name))]
    async fn nuke_network(&self, name: &str, force: bool) -> IpcMessage {
        // Check we're the coordinator and whether other members exist
        let (is_coordinator, has_other_members) = {
            let handle = match self.networks.get(name) {
                Some(h) => h,
                None => {
                    return IpcMessage::Error {
                        message: format!("not in network '{name}'"),
                    };
                }
            };
            let state = handle.state.read().unwrap();
            let my_id = self.endpoint.id();
            let is_coord = state
                .members
                .get(&my_id)
                .map(|m| m.is_coordinator)
                .unwrap_or(false);
            let others = state.members.all().len() > 1;
            (is_coord, others)
        };

        if !is_coordinator {
            return IpcMessage::Error {
                message: "only the coordinator can nuke a network".to_string(),
            };
        }

        if has_other_members && !force {
            return IpcMessage::Error {
                message: "network has other members — use --force to destroy, or transfer ownership first".to_string(),
            };
        }

        // Publish empty pkarr record
        let net_secret_key = {
            let handle = self.networks.get(name).unwrap();
            let state = handle.state.read().unwrap();
            state.network_secret_key.clone()
        };
        if let Some(key) = net_secret_key
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let empty_hash = group_blob_hash(
                &MemberList::new(),
                &ApprovedList::new(),
                &SuggestedFirewall::default(),
                None,
                &BTreeMap::new(),
            );
            if let Err(e) = dht::publish_network(&client, &key, &empty_hash, &[]).await {
                tracing::warn!(error = %e, "failed to publish empty network record on nuke");
            }
        }

        // Leave the network (handles cleanup, config removal, etc.)
        self.leave_network(name).await
    }

    /// Activate the VPN: bring the TUN interface up, configure system DNS, and
    /// reconnect every saved network. Idempotent — a no-op if already active.
    /// Runs entirely inside the (root) daemon, so the IPC client needs no
    /// privileges.
    async fn activate(self: &Arc<Self>, hostname: Option<String>) -> IpcMessage {
        // Persist the personal default hostname first (before the already-active
        // short-circuit) so `ray up --hostname X` records the new default even
        // when the VPN is already up. Used as the fallback for future
        // creates/joins; doesn't rename networks already joined.
        if let Some(h) = hostname {
            if !crate::hostname::is_valid_hostname(&h) {
                return IpcMessage::Error {
                    message: format!(
                        "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                    ),
                };
            }
            match config::load() {
                Ok(mut app_config) => {
                    app_config.default_hostname = Some(h);
                    if let Err(e) = config::save(&app_config) {
                        tracing::warn!(error = %e, "failed to persist default hostname");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load config to set default hostname")
                }
            }
        }

        if self.active.swap(true, Ordering::SeqCst) {
            return IpcMessage::Ok {
                message: "already up".into(),
            };
        }

        // Non-fatal problems hit while activating. The daemon stays up, but we
        // return these to the client so `ray up` can tell the user something is
        // wrong instead of silently reporting success on a degraded VPN.
        let mut warnings: Vec<String> = Vec::new();

        if let Err(e) = tun::set_link_up(&self.tun_name) {
            tracing::warn!(error = %e, "failed to bring TUN interface up");
            warnings.push(format!("failed to bring TUN interface up: {e}"));
        }

        // Route the 200::/7 peer range into the TUN. Must happen after link-up:
        // on Linux the kernel won't install an IPv6 connected route while the
        // link is down, so without this peer traffic leaks out the default route.
        if let Err(e) = tun::route_peer_range(&self.tun_name).await {
            tracing::warn!(error = %e, "failed to route 200::/7 into TUN");
            warnings.push(format!("failed to route IPv6 peer range into TUN: {e}"));
        }

        // Configure system DNS to route .ray queries to our local resolver.
        dns_config::restore_stale_backups();
        match dns_config::detect_and_configure(&self.tun_name).await {
            Ok(c) => {
                tracing::info!(backend = c.name(), "system DNS configured for .ray");
                *self.dns_configurator.lock().unwrap() = Some(c);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to configure system DNS (Magic DNS requires manual setup)");
                warnings.push(format!(
                    "failed to configure system DNS, so .ray names won't resolve: {e}"
                ));
            }
        }

        // Reconnect every saved network.
        let app_config = match config::load() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load config during activate");
                return IpcMessage::Ok {
                    message: "VPN up (no saved networks reconnected)".into(),
                };
            }
        };
        let mut count = 0;
        for net in &app_config.networks {
            count += 1;
            if net.network_secret_key.is_some() {
                // We hold the secret key — restore as coordinator.
                let name = net.name.clone();
                let mode = net.group_mode;
                let daemon_c = Arc::clone(self);
                tokio::spawn(async move {
                    match daemon_c.restore_coordinator_network(&name, mode).await {
                        Ok(IpcMessage::Created { name, .. }) => {
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
                });
            } else {
                // We're a member — rejoin via DHT lookup.
                let name = net.name.clone();
                let persisted_hostname = net.my_hostname.clone();
                let net_auto_accept = net.auto_accept_firewall;
                let net_pubkey = match &net.network_public_key {
                    Some(k) => k.to_string(),
                    None => {
                        tracing::warn!(network = %name, "no network public key in config, skipping restore");
                        continue;
                    }
                };
                let daemon_c = Arc::clone(self);
                tokio::spawn(async move {
                    match daemon_c
                        .join_network_inner(
                            &net_pubkey,
                            Some(&name),
                            persisted_hostname,
                            None,
                            None,
                            net_auto_accept,
                            false,
                        )
                        .await
                    {
                        Ok(TryJoin::Joined(IpcMessage::Joined { name, my_ip, .. })) => {
                            tracing::info!(network = %name, ip = %my_ip, "restored member network");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(network = %name, error = %e, "failed to restore network");
                        }
                    }
                });
            }
        }

        tracing::info!(networks = count, "VPN activated");
        if warnings.is_empty() {
            IpcMessage::Ok {
                message: "VPN up".into(),
            }
        } else {
            let mut message = String::from("VPN up, but some things need attention:");
            for w in &warnings {
                message.push_str("\n  - ");
                message.push_str(w);
            }
            IpcMessage::Ok { message }
        }
    }

    /// Put the daemon on standby: tear down active network connections, revert
    /// system DNS, and bring the TUN interface down. The daemon process keeps
    /// running so it can be reactivated with `activate`. Idempotent.
    async fn deactivate(&self) -> IpcMessage {
        if !self.active.swap(false, Ordering::SeqCst) {
            return IpcMessage::Ok {
                message: "already on standby".into(),
            };
        }

        let names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        for name in &names {
            self.teardown_network_runtime(name).await;
        }

        // Revert system DNS (extract the configurator before reverting so the
        // mutex guard isn't held across the call).
        let configurator = self.dns_configurator.lock().unwrap().take();
        if let Some(configurator) = configurator
            && let Err(e) = dns_config::revert(configurator.as_ref()).await
        {
            tracing::warn!(error = %e, "failed to revert DNS configuration");
        }
        dns_config::clear_search_domains(&self.tun_name).await;

        if let Err(e) = tun::set_link_down(&self.tun_name) {
            tracing::warn!(error = %e, "failed to bring TUN interface down");
        }

        tracing::info!("VPN on standby");
        IpcMessage::Ok {
            message: "VPN down (daemon still running)".into(),
        }
    }

    /// Tear down a network's runtime state (connections, ALPN, DNS entries,
    /// background tasks) without touching its persisted config. Returns whether
    /// the network was active. Shared by `leave_network` (which also forgets the
    /// config) and `deactivate` (which keeps it for later reactivation).
    async fn teardown_network_runtime(&self, name: &str) -> bool {
        let Some(handle) = self.networks.remove(name).map(|(_, v)| v) else {
            return false;
        };
        handle.cancel.cancel();
        for task in handle.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }

        self.peers.remove_by_network(name);
        dns::remove_network(&self.hostname_table, &self.reverse_table, name).await;
        self.protocol_router
            .unregister(&transport::network_alpn(&handle.network_key));
        self.refresh_alpns().await;
        true
    }

    #[tracing::instrument(skip(self), fields(net = name))]
    async fn leave_network(&self, name: &str) -> IpcMessage {
        // Gracefully close our connections with the leave code BEFORE teardown
        // drops them, so each peer's reader sees an intentional close and the
        // coordinator prunes us from the roster (rather than waiting for an
        // idle timeout that only ever clears the green dot).
        for (_eid, _ip, conn) in self.peers.peers_for_network_with_conn(name) {
            conn.close(VarInt::from_u32(forward::LEAVE_CODE), b"leave");
        }

        let was_active = self.teardown_network_runtime(name).await;

        // Remove from config even if the network wasn't active
        let removed_from_config = if let Ok(mut app_config) = config::load()
            && config::remove_network(&mut app_config, name)
        {
            let _ = config::save(&app_config);
            true
        } else {
            false
        };

        if was_active || removed_from_config {
            tracing::info!(network = %name, "left network");
            IpcMessage::Ok {
                message: format!("left network '{}'", name),
            }
        } else {
            IpcMessage::Error {
                message: format!("network '{}' not found", name),
            }
        }
    }

    fn status(&self) -> IpcMessage {
        let hostname_snapshot = self.hostname_table.try_read().ok();
        let my_id = self.endpoint.id();
        let statuses: Vec<NetworkStatus> = self
            .networks
            .iter()
            .map(|h| {
                // Build the peer list from the *roster* (every known member),
                // not just the live connections — so `ray status` shows offline
                // peers too (Tailscale-style). A peer with no active connection
                // gets `connection: None`; the CLI renders it with an offline dot.
                let (members, member_count) = {
                    let s = match h.state.read() {
                        Ok(s) => s,
                        Err(_) => {
                            return NetworkStatus {
                                name: h.name.clone(),
                                role: h.role.clone(),
                                my_ip: h.my_ip,
                                my_ipv6: Some(derive_ipv6(&my_id)),
                                my_hostname: None,
                                network_key: Some(h.network_key.to_string()),
                                member_count: 0,
                                peers: vec![],
                            };
                        }
                    };
                    let count = s.members.all().len();
                    let all = s.members.all().into_iter().cloned().collect::<Vec<_>>();
                    (all, count)
                };
                // Index live connections by endpoint id for a fast lookup.
                let connected: HashMap<EndpointId, Connection> = self
                    .peers
                    .peers_for_network_with_conn(&h.name)
                    .into_iter()
                    .map(|(eid, _, conn)| (eid, conn))
                    .collect();
                let network_key = Some(h.network_key.to_string());
                let peers = members
                    .iter()
                    .filter(|m| m.identity != my_id)
                    .map(|m| {
                        let hostname = m.hostname.clone().or_else(|| {
                            hostname_snapshot.as_ref().and_then(|table| {
                                table.get(&h.name).and_then(|hosts| {
                                    hosts
                                        .iter()
                                        .find(|(_, v)| v.0 == m.ip)
                                        .map(|(k, _)| k.clone())
                                })
                            })
                        });
                        let connection = connected.get(&m.identity).map(Self::gather_conn_info);
                        let user_id = self.device_user_map.resolve(&m.identity);
                        let user_identity = if user_id != m.identity { Some(user_id) } else { None };
                        PeerStatus {
                            endpoint_id: m.identity,
                            ip: m.ip,
                            ipv6: Some(derive_ipv6(&m.identity)),
                            hostname,
                            user_identity,
                            connection,
                        }
                    })
                    .collect();
                let my_hostname = hostname_snapshot.as_ref().and_then(|table| {
                    table.get(&h.name).and_then(|hosts| {
                        hosts
                            .iter()
                            .find(|(_, v)| v.0 == h.my_ip)
                            .map(|(k, _)| k.clone())
                    })
                });
                NetworkStatus {
                    name: h.name.clone(),
                    role: h.role.clone(),
                    my_ip: h.my_ip,
                    my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
                    my_hostname,
                    network_key,
                    member_count,
                    peers,
                }
            })
            .collect();

        IpcMessage::StatusResponse {
            endpoint_id: self.endpoint.id(),
            mdns_enabled: self.mdns_enabled,
            active: self.active.load(Ordering::SeqCst),
            networks: statuses,
            packets_rx: self.stats.packets_rx.get(),
            packets_tx: self.stats.packets_tx.get(),
            bytes_rx: self.stats.bytes_rx.get(),
            bytes_tx: self.stats.bytes_tx.get(),
        }
    }

    /// Assemble a diagnostic `.tgz` (logs + metrics + sanitized status + system
    /// info) on disk and return its path plus a pre-filled GitHub issue. Runs
    /// daemon-side because the log files are root-owned; the resulting bundle is
    /// chowned to the calling user so an unprivileged `ray report` can attach it.
    ///
    /// Sanitization: the bundle is built only from already-public material — the
    /// `StatusResponse` (which never carries secret keys), counters, and the log
    /// files. It never touches `secret_key` or `network_secret_key`.
    fn build_report(&self, peer_cred: Option<(u32, u32)>) -> IpcMessage {
        use std::fmt::Write as _;

        // --- sysinfo.txt ---
        let version = env!("CARGO_PKG_VERSION");
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let uname = std::process::Command::new("uname")
            .arg("-a")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let uptime = self.start.elapsed().as_secs();
        let active = self.active.load(Ordering::SeqCst);
        let mut sysinfo = String::new();
        let _ = writeln!(sysinfo, "rayfish {version}");
        let _ = writeln!(sysinfo, "os: {os}  arch: {arch}");
        if !uname.is_empty() {
            let _ = writeln!(sysinfo, "uname: {uname}");
        }
        let _ = writeln!(sysinfo, "endpoint_id: {}", self.endpoint.id());
        let _ = writeln!(sysinfo, "uptime_secs: {uptime}");
        let _ = writeln!(sysinfo, "active: {active}");
        let _ = writeln!(sysinfo, "networks: {}", self.networks.len());

        // --- metrics.txt ---
        let snap = self.stats.snapshot(self.start);
        let total_drops: u64 = snap.drops.iter().map(|(_, c)| c).sum();
        let mut metrics = String::new();
        let _ = writeln!(metrics, "packets_rx: {}", snap.packets_rx);
        let _ = writeln!(metrics, "packets_tx: {}", snap.packets_tx);
        let _ = writeln!(metrics, "bytes_rx:   {}", snap.bytes_rx);
        let _ = writeln!(metrics, "bytes_tx:   {}", snap.bytes_tx);
        let _ = writeln!(metrics, "drops_total: {total_drops}");
        for (reason, count) in &snap.drops {
            let _ = writeln!(metrics, "  drop[{reason}]: {count}");
        }

        // --- status.txt (sanitized: StatusResponse carries no secrets) ---
        let status = format!("{:#?}", self.status());

        // --- collect files for the tarball ---
        let mut files: Vec<(String, Vec<u8>)> = vec![
            ("sysinfo.txt".to_string(), sysinfo.into_bytes()),
            ("metrics.txt".to_string(), metrics.into_bytes()),
            ("status.txt".to_string(), status.into_bytes()),
        ];
        files.extend(collect_recent_logs());
        let has_panics = files.iter().any(|(name, _)| name == "logs/panic.log");

        // --- write the gzipped tarball ---
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = std::path::PathBuf::from("/tmp").join(format!("rayfish-report-{ts}.tgz"));
        if let Err(e) = write_bundle(&path, &files) {
            return IpcMessage::Error {
                message: format!("failed to write report bundle: {e}"),
            };
        }

        // Make it readable by, and owned by, the user who invoked `ray report`.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        if let Some((uid, gid)) = peer_cred {
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
        }

        let issue_title = if has_panics {
            format!("[report] crash diagnostics from {os} (rayfish {version})")
        } else {
            format!("[report] diagnostics from {os} (rayfish {version})")
        };
        let mut issue_body = String::new();
        let _ = writeln!(issue_body, "**rayfish {version}** on {os}/{arch}");
        let _ = writeln!(issue_body);
        if has_panics {
            let _ = writeln!(
                issue_body,
                "⚠️ One or more panics were recorded — see `logs/panic.log` in the bundle.\n"
            );
        }
        let _ = writeln!(
            issue_body,
            "Metrics: rx {} pkts / tx {} pkts, {} drops, uptime {}s",
            snap.packets_rx, snap.packets_tx, total_drops, uptime
        );
        let _ = writeln!(issue_body);
        let _ = writeln!(
            issue_body,
            "Diagnostic bundle: `{}` — **please attach this file to the issue.**",
            path.display()
        );
        let _ = writeln!(issue_body);
        let _ = writeln!(issue_body, "<!-- Describe what went wrong below. -->");

        IpcMessage::ReportBundle {
            path: path.display().to_string(),
            issue_title,
            issue_body,
        }
    }

    fn gather_conn_info(conn: &iroh::endpoint::Connection) -> ipc::ConnectionInfo {
        let paths = conn.paths();
        let selected = paths.iter().find(|p| p.is_selected());

        let (conn_type, remote_addr, rtt_ms) = match selected {
            Some(path) => {
                let addr = path.remote_addr();
                let ct = if addr.is_relay() {
                    ipc::ConnType::Relay
                } else if addr.is_custom() {
                    ipc::ConnType::Tor
                } else {
                    ipc::ConnType::Direct
                };
                let rtt = path.rtt().as_secs_f64() * 1000.0;
                (ct, Some(addr.to_string()), Some(rtt))
            }
            None => (ipc::ConnType::Unknown, None, None),
        };

        let stats = conn.stats();
        ipc::ConnectionInfo {
            conn_type,
            remote_addr,
            rtt_ms,
            bytes_tx: stats.udp_tx.bytes,
            bytes_rx: stats.udp_rx.bytes,
            datagrams_tx: stats.udp_tx.datagrams,
            datagrams_rx: stats.udp_rx.datagrams,
            lost_packets: stats.lost_packets,
        }
    }

    // -----------------------------------------------------------------------
    // Hostname
    // -----------------------------------------------------------------------

    async fn set_hostname(&self, network: &str, hostname: &str) -> IpcMessage {
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
            let taken: Vec<String> = {
                let s = state.read().unwrap();
                s.members
                    .all()
                    .iter()
                    .filter(|m| m.identity != my_identity)
                    .filter_map(|m| m.hostname.clone())
                    .collect()
            };
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

        // Persist to config.
        if let Ok(mut app_config) = config::load() {
            if let Some(net) = app_config.networks.iter_mut().find(|n| n.name == network) {
                net.my_hostname = Some(new_hostname.clone());
            }
            let _ = config::save(&app_config);
        }

        if is_coord {
            // Authoritative: republish the group blob and push the new roster to
            // every peer immediately.
            update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
            broadcast_member_sync(&self.peers, None).await;
        } else {
            // Notify the coordinator via MeshHello (sent to all connected peers;
            // only the coordinator's continuous control reader acts on it). It
            // resolves collisions and broadcasts the authoritative MemberSync.
            let peers = self.peers.peers_for_network_with_conn(network);
            for (_peer_id, _peer_ip, conn) in &peers {
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let msg = ControlMsg::MeshHello {
                        identity: my_identity,
                        ip: my_ip,
                        hostname: Some(new_hostname.clone()),
                        device_cert: self.device_cert.clone(),
                    };
                    let _ = control::send_msg(&mut send, &msg).await;
                }
            }
        }

        let dns_name = format!("{}.{}.{}", new_hostname, network, crate::DNS_DOMAIN);
        IpcMessage::Ok {
            message: format!("hostname set to {} ({})", new_hostname, dns_name),
        }
    }


    fn resolve_short_id_any_network(&self, short: &str) -> Option<EndpointId> {
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
    fn coordinator_handle(
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

    async fn invite_create(
        &self,
        network: &str,
        expires_secs: u64,
        hostname: Option<String>,
        reusable: bool,
    ) -> IpcMessage {
        if reusable {
            return self
                .reusable_key_create(network, expires_secs, hostname)
                .await;
        }
        let (net_pubkey, lock) = match self.coordinator_handle(network) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let minted = {
            let _guard = lock.lock().await;
            match crate::invite::InviteStore::load(network) {
                Ok(mut store) => store.mint(Duration::from_secs(expires_secs), hostname),
                Err(e) => Err(e),
            }
        };
        match minted {
            Ok((secret, id)) => {
                let code =
                    crate::invite::encode_invite_code(&net_pubkey, &self.endpoint.id(), &secret);
                IpcMessage::InviteCreated {
                    code,
                    id,
                    expires_secs,
                }
            }
            Err(e) => IpcMessage::Error {
                message: format!("failed to mint invite: {e:#}"),
            },
        }
    }

    /// Mint a reusable join key: insert its hash into the signed blob and
    /// republish, so any network-key holder can admit. Authority is holding the
    /// network secret key (like firewall suggestions), not the `is_coordinator`
    /// flag. A reusable key cannot bind an authoritative hostname.
    async fn reusable_key_create(
        &self,
        network: &str,
        expires_secs: u64,
        hostname: Option<String>,
    ) -> IpcMessage {
        if hostname.is_some() {
            return IpcMessage::Error {
                message: "a reusable key cannot bind a hostname (a multi-use key admits many \
                          machines); drop --hostname or omit --reusable"
                    .to_string(),
            };
        }
        let (state, dht_notify, net_pubkey, has_key) = match self.networks.get(network) {
            Some(h) => {
                let has_key = h.state.read().unwrap().network_secret_key.is_some();
                (h.state.clone(), h.dht_notify.clone(), h.network_key, has_key)
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            }
        };
        if !has_key {
            return IpcMessage::Error {
                message: "only a coordinator (network key holder) can mint a reusable key"
                    .to_string(),
            };
        }
        let secret = crate::invite::generate_secret();
        let (hash, key) = crate::membership::ReusableKey::from_secret(&secret, now_secs(), expires_secs);
        let id = key.id.clone();
        {
            let mut s = state.write().unwrap();
            s.reusable_keys.insert(hash, key);
        }
        update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
        let code = crate::invite::encode_invite_code(&net_pubkey, &self.endpoint.id(), &secret);
        IpcMessage::InviteCreated {
            code,
            id,
            expires_secs,
        }
    }

    async fn invite_list(&self, network: &str) -> IpcMessage {
        // Extract owned handles before any await (DashMap refs must not be held
        // across `.await`).
        let (lock, has_key, reusable) = {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let s = handle.state.read().unwrap();
            (
                handle.invite_lock.clone(),
                s.network_secret_key.is_some(),
                s.reusable_keys.clone(),
            )
        };
        if !has_key {
            return IpcMessage::Error {
                message: format!(
                    "only a coordinator (network key holder) can list invites for '{network}'"
                ),
            };
        }
        let mut invites: Vec<ipc::InviteInfo> = Vec::new();
        // Single-use invites from the local ledger (present on the minting node;
        // a co-coordinator's ledger is simply empty).
        {
            let _guard = lock.lock().await;
            if let Ok(store) = crate::invite::InviteStore::load(network) {
                for v in store.list() {
                    invites.push(ipc::InviteInfo {
                        id: v.id,
                        status: v.status,
                        created: v.created,
                        expires: v.expires,
                        redeemer: v.redeemer,
                        hostname: v.hostname,
                        reusable: false,
                    });
                }
            }
        }
        // Reusable keys from the signed blob — known to every network-key holder.
        let now = now_secs();
        for k in reusable.values() {
            let status = if k.revoked {
                "revoked"
            } else if now >= k.expires {
                "expired"
            } else {
                "active"
            };
            invites.push(ipc::InviteInfo {
                id: k.id.clone(),
                status: status.to_string(),
                created: k.created,
                expires: k.expires,
                redeemer: None,
                hostname: None,
                reusable: true,
            });
        }
        IpcMessage::InviteListResponse { invites }
    }

    async fn invite_revoke(&self, network: &str, id: &str) -> IpcMessage {
        let (state, dht_notify, lock, has_key) = {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let has_key = handle.state.read().unwrap().network_secret_key.is_some();
            (
                handle.state.clone(),
                handle.dht_notify.clone(),
                handle.invite_lock.clone(),
                has_key,
            )
        };
        if !has_key {
            return IpcMessage::Error {
                message: format!(
                    "only a coordinator (network key holder) can revoke invites for '{network}'"
                ),
            };
        }
        // A reusable key lives in the signed blob: revoke it there and republish
        // so the revocation propagates to every admin.
        let revoked_reusable = {
            let mut s = state.write().unwrap();
            crate::membership::revoke_reusable(&mut s.reusable_keys, id).is_ok()
        };
        if revoked_reusable {
            update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
            return IpcMessage::Ok {
                message: format!("revoked reusable key '{id}' (propagating to all admins)"),
            };
        }
        // Fall back to the local single-use invite ledger.
        let result = {
            let _guard = lock.lock().await;
            match crate::invite::InviteStore::load(network) {
                Ok(mut store) => store.revoke(id),
                Err(e) => Err(e),
            }
        };
        match result {
            Ok(()) => IpcMessage::Ok {
                message: format!("revoked invite '{id}'"),
            },
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    fn list_requests(&self, network: &str) -> IpcMessage {
        let Some(handle) = self.networks.get(network) else {
            return IpcMessage::Error {
                message: format!("network '{network}' not active"),
            };
        };
        if !handle.role.is_coordinator() {
            return IpcMessage::Error {
                message: format!("only the coordinator of '{network}' has join requests"),
            };
        }
        let s = handle.state.read().unwrap();
        let requests = s
            .pending
            .iter()
            .map(|(id, pj)| ipc::PendingRequestInfo {
                short_id: id.fmt_short().to_string(),
                hostname: pj.hostname.clone(),
                waiting_secs: pj.requested_at.elapsed().as_secs(),
            })
            .collect();
        IpcMessage::PendingRequests { requests }
    }

    async fn accept_request(&self, network: &str, id_prefix: &str) -> IpcMessage {
        if let Err(e) = self.coordinator_handle(network) {
            return e;
        }
        // Find and remove the pending request matching the short id prefix.
        let pending = {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut s = handle.state.write().unwrap();
            let found = s
                .pending
                .keys()
                .find(|k| {
                    k.fmt_short().to_string().starts_with(id_prefix)
                        || k.to_string().starts_with(id_prefix)
                })
                .copied();
            found.and_then(|id| s.pending.remove(&id).map(|pj| (id, pj)))
        };
        let Some((identity, pj)) = pending else {
            return IpcMessage::Error {
                message: format!("no pending request matching '{id_prefix}'"),
            };
        };

        let ip = self.identity.derive_ip(&identity);
        let user_id = pj.device_cert.as_ref().map(|c| c.user_identity);
        {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut s = handle.state.write().unwrap();
            let members = s.members.clone();
            let _ = s.approved.approve(
                ApprovedEntry {
                    identity,
                    ip,
                    hostname: pj.hostname.clone(),
                    user_identity: user_id,
                    device_cert: pj.device_cert.clone(),
                },
                &members,
            );
            s.refresh_snapshot();
        }
        self.store_and_publish_group(network).await;
        broadcast_control_msg(
            &self.peers,
            &ControlMsg::MemberApproved {
                identity,
                ip,
                hostname: pj.hostname.clone(),
                device_cert: pj.device_cert.clone(),
            },
        )
        .await;
        IpcMessage::Ok {
            message: format!("accepted {} — they'll join shortly", identity.fmt_short()),
        }
    }

    fn deny_request(&self, network: &str, id_prefix: &str) -> IpcMessage {
        if let Err(e) = self.coordinator_handle(network) {
            return e;
        }
        let Some(handle) = self.networks.get(network) else {
            return IpcMessage::Error {
                message: format!("network '{network}' not active"),
            };
        };
        let mut s = handle.state.write().unwrap();
        let found = s
            .pending
            .keys()
            .find(|k| {
                k.fmt_short().to_string().starts_with(id_prefix)
                    || k.to_string().starts_with(id_prefix)
            })
            .copied();
        match found {
            Some(id) => {
                s.pending.remove(&id);
                IpcMessage::Ok {
                    message: format!("denied {}", id.fmt_short()),
                }
            }
            None => IpcMessage::Error {
                message: format!("no pending request matching '{id_prefix}'"),
            },
        }
    }

    /// Coordinator-only: grant the per-network secret key to a member over an
    /// authenticated mesh stream, making it a co-coordinator (can publish /
    /// suggest firewall rules). The key is shared (shared-key model), so this is
    /// a transfer of publish capability, not an attributable delegation. The
    /// grant is recorded locally for `ray admin list`.
    async fn admin_add(&self, network: &str, identity_str: &str) -> IpcMessage {
        let Some(identity) = self.resolve_short_id_any_network(identity_str) else {
            return IpcMessage::Error {
                message: format!(
                    "could not resolve identity '{identity_str}' (use a short id of a joined member)"
                ),
            };
        };
        let (net_pubkey, net_secret_key) = match self.networks.get(network) {
            Some(h) => {
                let key = {
                    let s = h.state.read().unwrap();
                    s.network_secret_key.clone()
                };
                if key.is_none() {
                    return IpcMessage::Error {
                        message: "only a coordinator (network key holder) can grant admin".to_string(),
                    };
                }
                (h.network_key, key)
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            }
        };
        let Some(net_secret_key) = net_secret_key else {
            return IpcMessage::Error {
                message: "network key not available".to_string(),
            };
        };

        // The target must be a member of this network. Send the grant over the
        // *existing* mesh connection to that member (the one its control reader
        // is accept_bi-ing on from join time). Opening a fresh connection would
        // land the AdminGrant on the member's new-connection handler, which
        // expects a MeshHello first and silently drops anything else.
        let conn = self
            .peers
            .peers_for_network_with_conn(network)
            .into_iter()
            .find(|(id, _, _)| *id == identity)
            .map(|(_, _, c)| c)
            .ok_or_else(|| {
                IpcMessage::Error {
                    message: format!(
                        "could not find an active connection to {identity} on '{network}'"
                    ),
                }
            });
        let conn = match conn {
            Ok(c) => c,
            Err(e) => return e,
        };
        let grant = ControlMsg::AdminGrant {
            network_pubkey: net_pubkey,
            secret_key: net_secret_key.to_bytes(),
        };
        match conn.open_bi().await {
            Ok((mut send, _)) => match control::send_msg(&mut send, &grant).await {
                Ok(()) => {
                    // The grant connection is dropped when this handler returns;
                    // wait for the grantee to read it so it flushes first.
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                }
                Err(e) => {
                    return IpcMessage::Error {
                        message: format!("failed to send admin grant: {e}"),
                    };
                }
            },
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to open stream to {identity}: {e}"),
                };
            }
        }

        // Record the grant locally (coordinator's record; not verifiable).
        if let Ok(mut cfg) = config::load()
            && let Some(net) = cfg.networks.iter_mut().find(|n| n.name == network)
            && !net.admins.contains(&identity)
        {
            net.admins.push(identity);
            let _ = config::save(&cfg);
        }
        IpcMessage::Ok {
            message: format!("granted network key to {}", identity.fmt_short()),
        }
    }

    /// List this network's key-holders: the local node (if it holds the key) plus
    /// every identity it has granted the key to (`ray admin add`).
    fn admin_list(&self, network: &str) -> IpcMessage {
        let self_id = self.endpoint.id();
        let mut admins = Vec::new();
        let self_holds_key = match self.networks.get(network) {
            Some(h) => h.state.read().unwrap().network_secret_key.is_some(),
            None => false,
        };
        if self_holds_key {
            admins.push(ipc::AdminInfo {
                short_id: self_id.fmt_short().to_string(),
                self_node: true,
            });
        }
        if let Ok(cfg) = config::load()
            && let Some(net) = cfg.networks.iter().find(|n| n.name == network)
        {
            for id in &net.admins {
                admins.push(ipc::AdminInfo {
                    short_id: id.fmt_short().to_string(),
                    self_node: false,
                });
            }
        }
        if !self_holds_key && admins.is_empty() {
            return IpcMessage::Error {
                message: format!("network '{network}' not found or not a coordinator"),
            };
        }
        IpcMessage::AdminListResponse { admins }
    }

    /// Store the current group snapshot as a blob and re-publish the pkarr record
    /// so members reconcile the new membership (used after `ray accept`).
    async fn store_and_publish_group(&self, network: &str) {
        let (hash, net_key, snap_bytes) = {
            let Some(handle) = self.networks.get(network) else {
                return;
            };
            let s = handle.state.read().unwrap();
            (
                s.snapshot.as_ref().map(|x| x.hash),
                s.network_secret_key.clone(),
                s.snapshot.as_ref().map(|x| x.msgpack_bytes.clone()),
            )
        };
        if let Some(bytes) = snap_bytes {
            let _ = self.blob_store.blobs().add_slice(&bytes).await;
        }
        if let (Some(hash), Some(key)) = (hash, net_key)
            && let Ok(client) = dht::create_pkarr_client(&self.endpoint)
        {
            let mut seed_peers: Vec<EndpointId> = self
                .peers
                .peers_for_network(network)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            seed_peers.push(self.endpoint.id());
            seed_peers.sort_by_key(|id| id.to_string());
            seed_peers.dedup();
            if let Err(e) = dht::publish_network(&client, &key, &hash, &seed_peers).await {
                tracing::warn!(error = %e, "failed to publish network record after accept");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Firewall handlers
    // -----------------------------------------------------------------------

    fn firewall_add(
        &self,
        direction: &str,
        action: &str,
        protocol: &str,
        port: Option<&str>,
        peer: Option<&str>,
        network: Option<&str>,
    ) -> IpcMessage {
        let direction = match firewall::parse_direction(direction) {
            Ok(d) => d,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let action = match firewall::parse_action(action) {
            Ok(a) => a,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let protocol = match firewall::parse_protocol(protocol) {
            Ok(p) => p,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let port = match port {
            Some(s) => match firewall::parse_port_range(s) {
                Ok(r) => Some(r),
                Err(e) => {
                    return IpcMessage::Error {
                        message: e.to_string(),
                    };
                }
            },
            None => None,
        };
        let peer = match peer {
            Some(s) => match self.resolve_short_id_any_network(s) {
                Some(id) => firewall::PeerFilter::Identity(id),
                None => {
                    return IpcMessage::Error {
                        message: format!("unknown peer '{s}'"),
                    };
                }
            },
            None => firewall::PeerFilter::Any,
        };

        if let Some(net) = network
            && !self.networks.contains_key(net)
        {
            return IpcMessage::Error {
                message: format!("unknown network '{net}'"),
            };
        }
        let rule = firewall::FirewallRule {
            direction,
            action,
            protocol,
            port,
            peer,
            network: network.map(str::to_string),
            origin: firewall::RuleOrigin::Local,
        };
        let mut config = (*self.firewall.get_config()).clone();
        config.rules.push(rule);
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: "rule added".to_string(),
        }
    }

    fn firewall_remove(&self, index: usize) -> IpcMessage {
        let current = self.firewall.get_config();
        if index >= current.rules.len() {
            return IpcMessage::Error {
                message: format!(
                    "index {index} out of range (have {} rules)",
                    current.rules.len()
                ),
            };
        }
        let mut config = (*current).clone();
        config.rules.remove(index);
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: "rule removed".to_string(),
        }
    }

    fn firewall_show(&self) -> IpcMessage {
        let config = self.firewall.get_config();
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        IpcMessage::FirewallState {
            default: config.default_action.to_string(),
            rules: firewall::rule_views(&config.rules, &short_id),
        }
    }

    /// Coordinator-only: replace a network's suggested firewall rules and
    /// republish the signed blob. Authority comes from holding the per-network
    /// secret key (so any admin granted the key can suggest). Suggestions are
    /// advisory on every network; each node queues or auto-accepts them.
    async fn firewall_suggest(
        &self,
        network: &str,
        suggestions: SuggestedFirewall,
    ) -> IpcMessage {
        let (state, dht_notify, has_key) = match self.networks.get(network) {
            Some(h) => {
                let has_key = h.state.read().unwrap().network_secret_key.is_some();
                (h.state.clone(), h.dht_notify.clone(), has_key)
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
        };
        if !has_key {
            return IpcMessage::Error {
                message: "only a coordinator (network key holder) can suggest firewall rules"
                    .to_string(),
            };
        }
        let count: usize = suggestions.len();
        {
            let mut s = state.write().unwrap();
            s.suggested_firewall = suggestions;
        }
        update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
        // The coordinator is the blob's source, so the group poller's hash
        // check (local == published) short-circuits and it never re-applies its
        // own authored suggestions. Materialize them here so the coordinator is
        // subject to its own rules like any other member (auto-take or queue).
        apply_suggested_firewall(&self.firewall, self.endpoint.id(), network, &state);
        IpcMessage::Ok {
            message: format!("published firewall suggestions for '{network}' ({count} subjects)"),
        }
    }

    fn firewall_suggestions(&self, network: &str) -> IpcMessage {
        match self.networks.get(network) {
            Some(h) => {
                let suggestions = h.state.read().unwrap().suggested_firewall.clone();
                IpcMessage::FirewallSuggestionsResponse { suggestions }
            }
            None => IpcMessage::Error {
                message: format!("network '{network}' not found"),
            },
        }
    }

    /// Materialized suggested rules awaiting manual review (`ray firewall
    /// pending`). Returns the rules as structured views; the CLI renders them as
    /// an interactive picker on a TTY or a static table otherwise.
    fn firewall_pending(&self, network: &str) -> IpcMessage {
        match self.networks.get(network) {
            Some(h) => {
                let pending = h.state.read().unwrap().pending_suggestions.clone();
                let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
                IpcMessage::FirewallPendingResponse {
                    network: network.to_string(),
                    rules: firewall::rule_views(&pending, &short_id),
                }
            }
            None => IpcMessage::Error {
                message: format!("network '{network}' not found"),
            },
        }
    }

    /// Resolve individual queued suggestions from the interactive picker: install
    /// the rules whose view is in `accept`, drop both `accept`+`deny` from the
    /// queue, and persist. Matching is by view value so it's robust to queue
    /// reordering between fetch and resolve.
    fn firewall_resolve_suggestions(
        &self,
        network: &str,
        accept: &[FirewallRuleView],
        deny: &[FirewallRuleView],
    ) -> IpcMessage {
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let h = match self.networks.get(network) {
            Some(h) => h,
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
        };
        let accept_set: std::collections::HashSet<&FirewallRuleView> = accept.iter().collect();
        let deny_set: std::collections::HashSet<&FirewallRuleView> = deny.iter().collect();

        // Partition the queue: keep the still-undecided rules; collect accepted.
        let mut accepted_rules = Vec::new();
        {
            let mut s = h.state.write().unwrap();
            let mut remaining = Vec::new();
            for rule in std::mem::take(&mut s.pending_suggestions) {
                let view = firewall::rule_view(&rule, &short_id);
                if accept_set.contains(&view) {
                    accepted_rules.push(rule);
                } else if deny_set.contains(&view) {
                    // dropped
                } else {
                    remaining.push(rule);
                }
            }
            s.pending_suggestions = remaining;
        }

        let n_accept = accepted_rules.len();
        let n_deny = deny.len();
        if !accepted_rules.is_empty() {
            // Merge accepted rules into the network's existing installed set,
            // rather than replacing it, so earlier per-rule accepts survive.
            let mut existing: Vec<firewall::FirewallRule> = self
                .firewall
                .get_config()
                .rules
                .iter()
                .filter(|r| matches!(&r.origin, firewall::RuleOrigin::Network(n) if n == network))
                .cloned()
                .collect();
            existing.extend(accepted_rules);
            let config = self.firewall.replace_network_rules(network, existing);
            if let Err(e) = firewall::save_firewall(&config) {
                tracing::warn!(error = %e, "failed to persist firewall config");
            }
        }
        IpcMessage::Ok {
            message: format!("accepted {n_accept}, denied {n_deny} suggested rules for '{network}'"),
        }
    }

    /// Accept the queued suggested rules for a network: install them (replacing
    /// the prior `Network(net)` set), persist, and clear the queue.
    fn firewall_accept(&self, network: &str) -> IpcMessage {
        let rules = match self.networks.get(network) {
            Some(h) => {
                let mut s = h.state.write().unwrap();
                std::mem::take(&mut s.pending_suggestions)
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
        };
        if rules.is_empty() {
            return IpcMessage::Error {
                message: format!("no pending suggested rules for '{network}'"),
            };
        }
        let count = rules.len();
        let config = self.firewall.replace_network_rules(network, rules);
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: format!("accepted {count} suggested rules from '{network}'"),
        }
    }

    /// Discard the queued suggested rules for a network without installing them.
    fn firewall_deny(&self, network: &str) -> IpcMessage {
        match self.networks.get(network) {
            Some(h) => {
                let mut s = h.state.write().unwrap();
                let count = s.pending_suggestions.len();
                s.pending_suggestions.clear();
                IpcMessage::Ok {
                    message: format!("discarded {count} pending suggested rules for '{network}'"),
                }
            }
            None => IpcMessage::Error {
                message: format!("network '{network}' not found"),
            },
        }
    }

    /// Toggle this node's per-network auto-accept of coordinator-suggested
    /// firewall rules (persisted in config). Turning it on immediately
    /// re-materializes and installs the current suggestions; turning it off
    /// leaves already-installed rules in place but stops future auto-install.
    fn firewall_auto_accept(&self, network: &str, enabled: bool) -> IpcMessage {
        if !self.networks.contains_key(network) {
            return IpcMessage::Error {
                message: format!("network '{network}' not found"),
            };
        }
        // Persist the per-network flag.
        match config::load() {
            Ok(mut app_config) => {
                let Some(nc) = app_config.networks.iter_mut().find(|n| n.name == network) else {
                    return IpcMessage::Error {
                        message: format!("network '{network}' not found in config"),
                    };
                };
                nc.auto_accept_firewall = enabled;
                if let Err(e) = config::save(&app_config) {
                    return IpcMessage::Error {
                        message: format!("failed to persist auto-accept setting: {e}"),
                    };
                }
            }
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        }
        // Re-apply suggestions with the new consent setting. With auto-accept on
        // this installs the queued set; with it off it just (re)queues.
        if let Some(h) = self.networks.get(network) {
            apply_suggested_firewall(&self.firewall, self.endpoint.id(), network, &h.state);
        }
        IpcMessage::Ok {
            message: format!(
                "auto-accept firewall suggestions {} for '{network}'",
                if enabled { "enabled" } else { "disabled" }
            ),
        }
    }

    fn firewall_default(&self, action: &str) -> IpcMessage {
        let action = match firewall::parse_action(action) {
            Ok(a) => a,
            Err(e) => {
                return IpcMessage::Error {
                    message: e.to_string(),
                };
            }
        };
        let mut config = (*self.firewall.get_config()).clone();
        config.default_action = action;
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: format!(
                "default set to {}",
                if action == firewall::Action::Allow {
                    "allow"
                } else {
                    "deny"
                }
            ),
        }
    }

    // -----------------------------------------------------------------------
    // File sharing
    // -----------------------------------------------------------------------

    async fn resolve_peer_name(&self, name: &str) -> Option<EndpointId> {
        let suffix = format!(".{}", crate::DNS_DOMAIN);
        let qualified = if name.ends_with(&suffix) {
            name.to_string()
        } else {
            format!("{name}{suffix}")
        };
        if let Some((ip, _)) = dns::resolve_name(&qualified, &suffix, &self.hostname_table).await {
            // Try connected peers first
            if let Some(route) = self.peers.lookup_v4(&ip) {
                return Some(route.endpoint_id);
            }
            // Fall back to member list (peer may be offline or it's us)
            for entry in self.networks.iter() {
                let state = entry.value().state.read().unwrap();
                if let Some(m) = state.members.all().iter().find(|m| m.ip == ip) {
                    return Some(m.identity);
                }
            }
        }
        self.resolve_short_id_any_network(name)
    }

    async fn send_file(&self, path: &str, peer: &str) -> IpcMessage {
        let peer_id = match self.resolve_peer_name(peer).await {
            Some(id) => id,
            None => {
                return IpcMessage::Error {
                    message: format!("unknown peer '{peer}'"),
                };
            }
        };

        let file_path = std::path::Path::new(path);
        let file_bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot read '{}': {e}", file_path.display()),
                };
            }
        };

        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let size = file_bytes.len() as u64;
        let mime_type = guess_mime_type(&filename);
        let hash = blake3::hash(&file_bytes);

        if let Err(e) = self.blob_store.blobs().add_slice(&file_bytes).await {
            return IpcMessage::Error {
                message: format!("blob store error: {e}"),
            };
        }

        let msg = control::ControlMsg::FileOffer {
            from: self.endpoint.id(),
            filename: filename.clone(),
            size,
            mime_type: mime_type.clone(),
            blob_hash: hash,
        };

        match transport::connect_to_peer_with_alpn(&self.endpoint, peer_id, transport::FILES_ALPN)
            .await
        {
            Ok(conn) => match conn.open_bi().await {
                Ok((mut send, _)) => {
                    if let Err(e) = control::send_msg(&mut send, &msg).await {
                        return IpcMessage::Error {
                            message: format!("failed to send offer: {e}"),
                        };
                    }
                    // send_msg already finished the stream; wait for the peer to
                    // read the offer so it flushes before this `conn` is dropped.
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                }
                Err(e) => {
                    return IpcMessage::Error {
                        message: format!("failed to open stream: {e}"),
                    };
                }
            },
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot reach peer '{peer}': {e}"),
                };
            }
        }

        IpcMessage::Ok {
            message: format!("offered {} ({}) to {}", filename, format_size(size), peer),
        }
    }

    fn list_files(&self) -> IpcMessage {
        let pending = self.protocol_router.pending_files.lock().unwrap();
        let files = pending
            .iter()
            .map(|f| ipc::PendingFileInfo {
                id: f.id,
                from: f.from.fmt_short().to_string(),
                filename: f.filename.clone(),
                size: f.size,
                mime_type: f.mime_type.clone(),
            })
            .collect();
        IpcMessage::FileList { files }
    }

    async fn accept_file(
        &self,
        id: u64,
        output: Option<String>,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        let pending_file = {
            let mut pending = self.protocol_router.pending_files.lock().unwrap();
            let idx = pending.iter().position(|f| f.id == id);
            match idx {
                Some(i) => pending.remove(i),
                None => {
                    return IpcMessage::Error {
                        message: format!("no pending file with id {id}"),
                    };
                }
            }
        };

        let blob_hash = iroh_blobs::Hash::from_bytes(*pending_file.blob_hash.as_bytes());

        let conn = match transport::connect_to_peer_with_alpn(
            &self.endpoint,
            pending_file.from,
            iroh_blobs::protocol::ALPN,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot reach sender: {e}"),
                };
            }
        };

        if let Err(e) = self
            .blob_store
            .remote()
            .fetch(conn, iroh_blobs::HashAndFormat::raw(blob_hash))
            .await
        {
            return IpcMessage::Error {
                message: format!("blob fetch failed: {e}"),
            };
        }

        let bytes = match self.blob_store.blobs().get_bytes(blob_hash).await {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("blob read failed: {e}"),
                };
            }
        };

        let dir = match output {
            Some(ref p) => PathBuf::from(p),
            None => dirs::download_dir().unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("Downloads")
            }),
        };

        if let Err(e) = std::fs::create_dir_all(&dir) {
            return IpcMessage::Error {
                message: format!("cannot create directory '{}': {e}", dir.display()),
            };
        }

        let dest = dir.join(&pending_file.filename);
        if let Err(e) = std::fs::write(&dest, &bytes) {
            return IpcMessage::Error {
                message: format!("write failed: {e}"),
            };
        }

        if let Some((uid, gid)) = peer_cred {
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = std::ffi::CString::new(dest.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
            if let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
        }

        IpcMessage::Ok {
            message: format!("saved to {}", dest.display()),
        }
    }

    fn start_pairing(&self) -> IpcMessage {
        let secret: [u8; 32] = rand::random();

        let endpoint_id = self.endpoint.id();
        let mut ticket_bytes = Vec::with_capacity(64);
        ticket_bytes.extend_from_slice(endpoint_id.as_bytes());
        ticket_bytes.extend_from_slice(&secret);
        let ticket = bs58::encode(&ticket_bytes).into_string();

        *self.pairing_secret.lock().unwrap() = Some(secret);

        IpcMessage::PairingTicket { ticket }
    }

    async fn pair_with_device(&self, endpoint_id: EndpointId, secret: Vec<u8>) -> IpcMessage {
        let addr: iroh::EndpointAddr = endpoint_id.into();
        let conn = match self.endpoint.connect(addr, PAIR_ALPN).await {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to connect to primary device: {e}"),
                };
            }
        };
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to open stream: {e}"),
                };
            }
        };

        let secret_arr: [u8; 32] = match secret.try_into() {
            Ok(a) => a,
            Err(_) => {
                return IpcMessage::Error {
                    message: "invalid secret length".to_string(),
                };
            }
        };

        let request = control::PairMsg::Request {
            secret: secret_arr,
            device_pubkey: self.endpoint.id(),
        };
        let request_bytes = match rmp_serde::to_vec_named(&request) {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to encode pair request: {e}"),
                };
            }
        };
        let len = (request_bytes.len() as u32).to_be_bytes();
        if let Err(e) = send.write_all(&len).await {
            return IpcMessage::Error {
                message: format!("failed to send pair request: {e}"),
            };
        }
        if let Err(e) = send.write_all(&request_bytes).await {
            return IpcMessage::Error {
                message: format!("failed to send pair request: {e}"),
            };
        }

        // Read PairResponse
        let mut len_buf = [0u8; 4];
        if let Err(e) = recv.read_exact(&mut len_buf).await {
            return IpcMessage::Error {
                message: format!("failed to read pair response: {e}"),
            };
        }
        let body_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; body_len];
        if let Err(e) = recv.read_exact(&mut body).await {
            return IpcMessage::Error {
                message: format!("failed to read pair response body: {e}"),
            };
        }
        let response: control::PairMsg = match rmp_serde::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to decode pair response: {e}"),
                };
            }
        };

        match response {
            control::PairMsg::Response { cert } => {
                if !cert.verify() {
                    return IpcMessage::Error {
                        message: "received invalid device certificate".to_string(),
                    };
                }
                if let Err(e) = identity::store_device_cert(&cert) {
                    return IpcMessage::Error {
                        message: format!("failed to store device certificate: {e}"),
                    };
                }
                IpcMessage::PairingComplete {
                    user_identity: cert.user_identity,
                }
            }
            _ => IpcMessage::Error {
                message: "unexpected pairing response".to_string(),
            },
        }
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

    let (daemon, _metrics_server) = build_daemon(token.clone(), stats).await?;

    // Start active by default so a fresh boot behaves like before; `ray up` /
    // `ray down` toggle this at runtime without restarting the process.
    daemon.activate(None).await;

    serve_ipc(&daemon, token).await
}

/// Construct all always-on daemon infrastructure: identity, iroh endpoint, blob
/// store, TUN device, forwarding loop, DNS resolver, mDNS discovery, protocol
/// router, and metrics server. Returns the shared [`DaemonState`] — still on
/// standby, so the caller is expected to run [`DaemonState::activate`] — and the
/// metrics-server guard, which must outlive the process.
async fn build_daemon(
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
) -> Result<(
    Arc<DaemonState>,
    Option<iroh_metrics::service::MetricsServer>,
)> {
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
    let app_config = config::load()?;
    let mut alpns: Vec<Vec<u8>> = app_config
        .networks
        .iter()
        .filter_map(|net| net.network_public_key.as_ref().map(transport::network_alpn))
        .collect();
    alpns.push(iroh_blobs::protocol::ALPN.to_vec());
    // Always advertise the file-transfer and pairing ALPNs from boot. They are
    // network-independent, so a freshly-started daemon with no active network
    // must still accept `ray pair` / `ray send` connections — otherwise the
    // initial handshake fails with "peer doesn't support any known protocol"
    // until the first create/join triggers `refresh_alpns()`. Mirrors
    // `ProtocolRouter::alpns()`.
    alpns.push(transport::FILES_ALPN.to_vec());
    alpns.push(PAIR_ALPN.to_vec());
    let use_tor = app_config
        .networks
        .iter()
        .any(|net| net.transport.as_ref().is_some_and(|t| t.is_tor()));
    let ep = transport::create_endpoint_with_alpns(key.clone(), alpns, use_tor).await?;

    // --- Content-addressed blob store (membership/file transfer) ---
    let blobs_dir = dirs::config_dir()
        .context("no config directory")?
        .join("rayfish")
        .join("blobs");
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
    let (tun_tx, tun_rx) = mpsc::channel::<Bytes>(256);
    forward::spawn_tun_writer(tun_writer, tun_rx);
    let device_user_map = peers::DeviceUserMap::new();
    tokio::spawn(forward::run_mesh(
        tun_reader,
        peers.clone(),
        shared_firewall.clone(),
        token.clone(),
        stats.clone(),
    ));

    // --- Magic DNS resolver + optional mDNS local discovery ---
    let hostname_table = dns::new_hostname_table();
    let reverse_table = dns::new_reverse_table();
    spawn_dns_resolver(hostname_table.clone(), reverse_table.clone(), token.clone());

    let mdns_enabled = app_config.mdns_enabled;
    if mdns_enabled {
        spawn_mdns_discovery(&ep, token.clone());
    } else {
        tracing::info!("mDNS discovery disabled");
    }

    // --- Protocol router + the shared DaemonState ---
    let pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>> =
        Arc::new(std::sync::Mutex::new(None));
    let protocol_router = Arc::new(ProtocolRouter::new(
        blobs_proto,
        key.clone(),
        pairing_secret.clone(),
    ));
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
        tun_name,
        pairing_secret,
        device_cert,
        device_user_map,
        active: Arc::new(AtomicBool::new(false)),
        dns_configurator: Arc::new(std::sync::Mutex::new(None)),
    });

    // --- Accept loop (ALPN dispatch) + Prometheus metrics ---
    protocol_router.spawn_accept_loop(daemon.endpoint.clone(), token.clone());
    let metrics_server =
        spawn_metrics_server(stats, daemon.peers.clone(), &daemon.endpoint, token).await;

    tracing::info!(ip = %my_ip, id = %daemon.endpoint.id().fmt_short(), "daemon started");
    Ok((daemon, metrics_server))
}

/// Spawn the Magic DNS resolver on `127.0.0.1:53`. Non-fatal: if the socket
/// can't be bound, Magic DNS is simply disabled and the daemon runs on.
fn spawn_dns_resolver(
    table: dns::HostnameTable,
    reverse: dns::ReverseLookupTable,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        if let Err(e) = dns::spawn_dns_server(table, reverse, token).await {
            tracing::warn!(error = %e, "DNS server failed to start (Magic DNS disabled)");
        }
    });
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
async fn serve_ipc(daemon: &Arc<DaemonState>, token: CancellationToken) -> Result<()> {
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
    state: Arc<std::sync::RwLock<NetworkState>>,
    endpoint_id: EndpointId,
    peers: PeerTable,
    network_name: String,
    notify: Arc<tokio::sync::Notify>,
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
    state: Arc<std::sync::RwLock<NetworkState>>,
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
    state: &std::sync::RwLock<NetworkState>,
) {
    let (suggestions, members): (SuggestedFirewall, Vec<Member>) = {
        let s = state.read().unwrap();
        let members = s.members.all().into_iter().cloned().collect();
        (s.suggested_firewall.clone(), members)
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
    let rules = firewall::materialize_suggestions(network_name, &my_hostname, &suggestions, &resolve);

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
        tracing::info!(network = network_name, "auto-accepted suggested firewall rules");
    } else {
        let count = rules.len();
        state.write().unwrap().pending_suggestions = rules;
        tracing::info!(network = network_name, count, "queued suggested firewall rules for review");
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
    blob_store: &FsStore,
    peers: &PeerTable,
    net_pubkey: EndpointId,
    network_name: &str,
    state: &Arc<std::sync::RwLock<NetworkState>>,
    my_identity: EndpointId,
    hostname_table: &dns::HostnameTable,
    reverse_table: &dns::ReverseLookupTable,
    firewall: &SharedFirewall,
) {
    let current = state.read().unwrap().snapshot.as_ref().map(|s| s.hash);
    let Some((signed, seeds)) = resolve_signed(endpoint, net_pubkey).await else {
        tracing::debug!(network = %network_name, "reconverge: signed record unavailable");
        return;
    };
    if crate::membership::trusted_reconverge_hash(current, signed).is_none() {
        return; // already converged on the signed hash
    }
    let Some(data) =
        fetch_verified_blob(endpoint, blob_store, peers, signed, network_name, &seeds).await
    else {
        tracing::warn!(network = %network_name, "reconverge: could not fetch verified blob");
        return;
    };
    let roster = {
        let mut s = state.write().unwrap();
        s.members = MemberList::from_members(data.members.clone());
        s.approved = ApprovedList::from_entries(data.approved.clone());
        s.suggested_firewall = data.suggested_firewall.clone();
        s.refresh_snapshot();
        s.members.all().into_iter().cloned().collect::<Vec<Member>>()
    };
    apply_roster_to_dns(&roster, network_name, my_identity, hostname_table, reverse_table).await;
    apply_suggested_firewall(firewall, my_identity, network_name, state);
    tracing::info!(network = %network_name, "reconverged from signed record");
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
                })
                .collect()
        })
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn spawn_group_poller(
    client: PkarrRelayClient,
    net_pubkey: EndpointId,
    state: Arc<std::sync::RwLock<NetworkState>>,
    endpoint: Endpoint,
    blob_store: FsStore,
    peers: PeerTable,
    network_name: String,
    fw: SharedFirewall,
    token: CancellationToken,
) -> JoinHandle<()> {
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

/// Extra context a coordinator needs to prune the canonical member list when a
/// peer leaves deliberately (`ray leave`). Members pass `None` and only ever
/// drop the connection from the [`PeerTable`].
struct CoordinatorCleanup {
    state: Arc<std::sync::RwLock<NetworkState>>,
    blob_store: FsStore,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
    network_name: String,
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
    state: Arc<std::sync::RwLock<NetworkState>>,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
    peers: PeerTable,
    blob_store: FsStore,
    dht_notify: Option<Arc<tokio::sync::Notify>>,
    token: CancellationToken,
) {
    tokio::spawn(async move {
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
                tracing::info!(peer = %remote_id.fmt_short(), hostname = %final_hostname, "peer hostname changed; propagating");
                update_snapshot_and_publish(&state, &blob_store, &dht_notify).await;
                broadcast_member_sync(&peers, None).await;
            }
        }
    });
}

/// Rebuild a network's DNS entries from its member roster (the single source of
/// truth) and persist our own — possibly coordinator-corrected — hostname. Called
/// whenever a roster update arrives so renames, joins, and departures all reflect
/// in `*.ray` resolution immediately.
async fn apply_roster_to_dns(
    members: &[Member],
    network_name: &str,
    my_identity: EndpointId,
    hostname_table: &dns::HostnameTable,
    reverse_table: &dns::ReverseLookupTable,
) {
    let entries: Vec<(String, Ipv4Addr, std::net::Ipv6Addr)> = members
        .iter()
        .filter_map(|m| {
            m.hostname
                .as_ref()
                .map(|h| (h.clone(), m.ip, derive_ipv6(&m.identity)))
        })
        .collect();
    dns::sync_network_hostnames(hostname_table, reverse_table, network_name, &entries).await;

    // Persist our own name if the coordinator adjusted it (e.g. collision → -1).
    if let Some(mine) = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone())
        && let Ok(mut cfg) = config::load()
        && let Some(net) = cfg.networks.iter_mut().find(|n| n.name == network_name)
        && net.my_hostname.as_deref() != Some(mine.as_str())
    {
        net.my_hostname = Some(mine);
        let _ = config::save(&cfg);
    }
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
    state: &Arc<std::sync::RwLock<NetworkState>>,
    blob_store: &FsStore,
    dht_notify: &Option<Arc<tokio::sync::Notify>>,
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
    Joined(Arc<std::sync::RwLock<NetworkState>>),
    /// Queued for live approval on a closed network; the caller should retry.
    Pending,
}

/// Outcome of one `join_network_inner` attempt.
enum TryJoin {
    Joined(IpcMessage),
    Pending,
}

#[allow(clippy::too_many_arguments)]
async fn join_mesh_shared(
    initial_conn: Connection,
    ep: &Endpoint,
    network_name: &str,
    identity: &IrohIdentityProvider,
    alpn: &[u8],
    my_hostname: Option<String>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Bytes>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    blob_store: FsStore,
    firewall: SharedFirewall,
    net_pubkey: EndpointId,
    device_cert: Option<control::DeviceCert>,
    device_user_map: peers::DeviceUserMap,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    invite_secret: Option<Vec<u8>>,
    // From the fetched blob: the current coordinator-suggested firewall rules.
    // Persisted so a member inherits them.
    suggested_firewall: SuggestedFirewall,
    // From the fetched blob: reusable join keys, so this node can validate
    // redemptions if it later holds the network key (HA admission).
    reusable_keys: BTreeMap<String, crate::membership::ReusableKey>,
    // Consent: auto-install suggested rules without a manual review queue.
    auto_accept_firewall: bool,
    initial: bool,
) -> Result<JoinResult> {
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
                        match fetch_verified_blob(ep, &blob_store, &peers, signed, network_name, &seeds).await {
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
    let member_entries: Vec<config::MemberEntry> = members
        .iter()
        .map(|m| config::MemberEntry {
            identity: m.identity,
            ip: m.ip,
            is_coordinator: m.is_coordinator,
            hostname: m.hostname.clone(),
        })
        .collect();
    let approved_config: Vec<config::ApprovedConfigEntry> = approved
        .iter()
        .map(|a| config::ApprovedConfigEntry {
            identity: a.identity,
            ip: a.ip,
            hostname: a.hostname.clone(),
        })
        .collect();
    let persisted_hostname = members
        .iter()
        .find(|m| m.identity == my_identity)
        .and_then(|m| m.hostname.clone())
        .or(my_hostname.clone());
    let mut app_config = config::load()?;
    config::upsert_network(
        &mut app_config,
        config::NetworkConfig {
            name: network_name.to_string(),
            group_mode: GroupMode::Restricted,
            my_ip: Some(my_ip),
            my_hostname: persisted_hostname,
            members: member_entries,
            approved: approved_config,
            network_secret_key: None,
            network_public_key: Some(net_pubkey),
            transport: None,
            auto_accept_firewall,
            admins: vec![],
        },
    );
    config::save(&app_config)?;

    // On reconnect/restore the coordinator hasn't seen our hostname this session,
    // so send a MeshHello. A fresh join already conveyed it in the JoinRequest.
    if !initial {
        let (mut send, _recv) = initial_conn.open_bi().await?;
        control::send_msg(
            &mut send,
            &ControlMsg::MeshHello {
                identity: my_identity,
                ip: my_ip,
                hostname: my_hostname.clone(),
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
        firewall.clone(),
        tun_tx.clone(),
        disconnect_tx.clone(),
        token.clone(),
        stats.clone(),
        device_user_map.clone(),
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
                        hostname: my_hostname.clone(),
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
                    firewall.clone(),
                    tun_tx.clone(),
                    disconnect_tx.clone(),
                    token.clone(),
                    stats.clone(),
                    device_user_map.clone(),
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
        Arc::new(std::sync::RwLock::new(ns))
    };

    // Materialize this node's suggested rules from the blob we just joined with.
    // Re-runs on every roster/blob update from the control listener below.
    apply_suggested_firewall(&firewall, my_identity, network_name, &live_state);

    // Control listener
    tokio::spawn({
        let initial_conn = initial_conn.clone();
        let token = token.clone();
        let live_state = live_state.clone();
        let network_name = network_name.to_string();
        let blob_store = blob_store.clone();
        let peers_c = peers.clone();
        let endpoint_c = ep.clone();
        let hostname_table_c = hostname_table.clone();
        let reverse_table_c = reverse_table.clone();
        let firewall_c = firewall.clone();
        let my_identity_c = my_identity;
        let net_pubkey_c = net_pubkey;
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = initial_conn.accept_bi() => {
                        match result {
                            Ok((_send, mut recv)) => {
                                match control::recv_msg(&mut recv).await {
                                    Ok(ControlMsg::MemberApproved { identity, ip, hostname, .. }) => {
                                        let entry = ApprovedEntry { identity, ip, hostname, user_identity: None, device_cert: None };
                                        let mut s = live_state.write().unwrap();
                                        let members = s.members.clone();
                                        let _ = s.approved.approve(entry, &members);
                                    }
                                    Ok(ControlMsg::MemberSync) => {
                                        // Trigger only. The roster/firewall come exclusively
                                        // from the network-key-signed pkarr record, never from
                                        // peer-supplied membership.
                                        reconverge_and_apply(
                                            &endpoint_c, &blob_store, &peers_c, net_pubkey_c,
                                            &network_name, &live_state, my_identity_c,
                                            &hostname_table_c, &reverse_table_c, &firewall_c,
                                        ).await;
                                    }
                                    Ok(ControlMsg::BlobUpdated) => {
                                        // Trigger only. Reconverge from the network-key-signed
                                        // pkarr record — a malicious member can't inject a
                                        // forged roster/firewall blob via this message.
                                        reconverge_and_apply(
                                            &endpoint_c, &blob_store, &peers_c, net_pubkey_c,
                                            &network_name, &live_state, my_identity_c,
                                            &hostname_table_c, &reverse_table_c, &firewall_c,
                                        ).await;
                                    }
                                    Ok(ControlMsg::AdminGrant { network_pubkey, secret_key }) => {
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
                                        let key = SecretKey::from(secret_key);
                                        // Persist + take local publish capability.
                                        if let Ok(mut cfg) = config::load()
                                            && let Some(net) = cfg.networks.iter_mut().find(|n| n.name == network_name)
                                        {
                                            net.network_secret_key = Some(key.clone());
                                            let _ = config::save(&cfg);
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
                                    }
                                    Ok(_) => {}
                                    Err(_) => {}
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
    my_hostname: Option<String>,
    peers: PeerTable,
    tun_tx: mpsc::Sender<Bytes>,
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    firewall: SharedFirewall,
    device_cert: Option<control::DeviceCert>,
    device_user_map: peers::DeviceUserMap,
) -> JoinHandle<()> {
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
            let my_hostname = my_hostname.clone();
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
                                    hostname: my_hostname.clone(),
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
                                firewall,
                                tun_tx,
                                disconnect_tx,
                                token,
                                stats,
                                device_user_map,
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
// Broadcast helpers (same as main.rs but local to daemon)
// ---------------------------------------------------------------------------

async fn send_member_sync(conn: &Connection) {
    if let Ok((mut send, _)) = conn.open_bi().await {
        let _ = control::send_msg(&mut send, &ControlMsg::MemberSync).await;
    }
}

async fn broadcast_member_sync(peers: &PeerTable, exclude_ip: Option<Ipv4Addr>) {
    let msg = ControlMsg::MemberSync;
    for (ip, conn) in peers.all_connections() {
        if Some(ip) == exclude_ip {
            continue;
        }
        if let Ok((mut send, _)) = conn.open_bi().await
            && let Err(e) = control::send_msg(&mut send, &msg).await
        {
            tracing::warn!(peer_ip = %ip, error = %e, "failed to sync members");
        }
    }
}

async fn broadcast_control_msg(peers: &PeerTable, msg: &ControlMsg) {
    for (_ip, conn) in peers.all_connections() {
        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = control::send_msg(&mut send, msg).await;
        }
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
