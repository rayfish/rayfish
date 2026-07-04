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
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
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
use tokio::sync::Notify;
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
// The desktop TUN device and its CGNAT pre-flight check don't exist on Android,
// where the packet interface is a `VpnService` fd supplied from Kotlin.
#[cfg(not(target_os = "android"))]
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
// `run_daemon` (the `ray daemon` entry point) stays public for the binary.
pub use mesh::run_daemon;
// `build_headless` is the embedder (mobile) construction entry point.
pub use mesh::build_headless;

/// Legacy name for [`MeshManager`], kept so embedders (`ray-mobile`) that were
/// written against `DaemonState` compile unchanged after the daemon refactor.
pub type DaemonState = MeshManager;

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
pub(crate) struct PendingJoin {
    pub(crate) hostname: Option<String>,
    pub(crate) device_cert: Option<control::DeviceCert>,
    pub(crate) requested_at: Instant,
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
/// Handles for the packet-forwarding tasks a [`MeshManager::attach_tun`] call
/// spawns (the TUN writer and the `run_mesh` reader loop), plus a dedicated
/// cancellation token so the data plane can be stopped independently of a full
/// daemon shutdown (used by [`MeshManager::detach_tun`] / `ray-mobile`'s `down`).
struct TunTasks {
    /// Cancels the `run_mesh` reader loop without touching `shutdown_token`.
    cancel: CancellationToken,
    /// The TUN writer task (`spawn_tun_writer`).
    writer: JoinHandle<()>,
    /// The `run_mesh` reader loop task.
    mesh: JoinHandle<()>,
}

pub struct MeshManager {
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
    /// Magic DNS naming tables, resolver, and OS-DNS configurator (see [`DnsManager`]).
    dns: DnsManager,
    mdns_enabled: bool,
    /// Whether this node opted into automatic stable updates (`ray auto-update
    /// on` / `ray install --auto-update`). Read at startup; when set, `run_daemon`
    /// spawns the periodic update task. Echoed back in `ray status`.
    auto_update: bool,
    /// Name of the OS TUN device (desktop) or a placeholder until a packet
    /// interface is attached. Interior-mutable because on embedders (mobile) the
    /// interface is attached after construction via [`MeshManager::attach_tun`],
    /// while on desktop it is set once at boot.
    tun_name: std::sync::Mutex<String>,
    /// Handles for the packet-forwarding tasks spawned by
    /// [`MeshManager::attach_tun`], kept so a future `down()`/detach can stop them.
    tun_tasks: std::sync::Mutex<Option<TunTasks>>,
    /// Promotion-channel receiver drained by [`serve_ipc`]. Stored here so the
    /// headless builder can construct the daemon and hand the receiver back to
    /// [`run_daemon`] afterwards.
    promote_rx: std::sync::Mutex<Option<mpsc::Receiver<String>>>,
    /// Prometheus metrics-server guard. Kept alive for the daemon's whole lifetime
    /// (dropping it stops the export); `None` if the server failed to bind.
    _metrics_server: std::sync::Mutex<Option<iroh_metrics::service::MetricsServer>>,
    /// File-transfer + pairing state and ALPN accept arms (see [`FileService`]).
    /// Shared with [`ProtocolRouter`], which runs the accept arms.
    files: Arc<FileService>,
    /// `ray connect` state + ALPN accept arm (see [`ConnectService`]). Shared with
    /// [`ProtocolRouter`], which runs the accept arm.
    connect: Arc<ConnectService>,
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
    /// Live per-network SSH allow lists for the embedded mesh SSH server. Swapped
    /// atomically on `ray firewall ssh allow/deny`, so a running listener picks up
    /// changes without restart. See [`crate::ssh`]. Desktop-only: the embedded
    /// mesh SSH server isn't part of the Android build.
    #[cfg(feature = "desktop")]
    ssh_authz: crate::ssh::SshAuthz,
    /// Cancellation token for the running SSH listeners (`None` when off / on
    /// standby). Set by [`MeshManager::start_ssh`], cleared by `stop_ssh`.
    // The only readers/writers (`start_ssh`/`stop_ssh`) are desktop-only, so on a
    // `--no-default-features` (Android) build the field is inert; silence the
    // resulting dead-code warning there rather than dropping the field.
    #[cfg_attr(not(feature = "desktop"), allow(dead_code))]
    ssh_token: std::sync::Mutex<Option<CancellationToken>>,
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
    /// The device cert to present when joining, preferring the on-disk copy so a
    /// join issued right after pairing (same process, no restart) carries the
    /// freshly stored cert rather than the value loaded at startup.
    pub fn current_device_cert(&self) -> Option<control::DeviceCert> {
        identity::load_device_cert()
            .ok()
            .flatten()
            .or_else(|| self.device_cert.clone())
    }

    /// Gracefully take the whole node offline: cancel the daemon-wide shutdown
    /// token (stopping every network run loop, the accept loop, and the
    /// data-plane forward tasks) and then close the iroh endpoint so all QUIC
    /// connections terminate cleanly and peers see us drop immediately, rather
    /// than lingering until an idle timeout. Awaiting the close matters for
    /// embedders (mobile) that rebuild a fresh daemon on re-enable: without it
    /// the old endpoint's connections outlive `stop`, so a coordinator keeps the
    /// stale session while the rebuilt endpoint (same node key) comes up and the
    /// device shows offline until the race clears. Mirrors the shutdown tail of
    /// `run_daemon`. After this the `MeshManager` is spent; build a new one to
    /// come back online.
    pub async fn shutdown_and_close(&self) {
        self.shutdown_token.cancel();
        self.endpoint.close().await;
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
            hostname_table: self.dns.hostname_table.clone(),
            reverse_table: self.dns.reverse_table.clone(),
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
            let resolver = self.dns.resolver.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    forward::run_mesh(reader, peers, firewall, cancel, stats, resolver, new_tx)
                        .await
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
        self.dns.resolver.set_upstreams(servers);
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
        dns::remove_hostname_by_ip(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            network,
            my_ip,
        )
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

// Process bootstrap + IPC server live in `mesh/bootstrap.rs`; background tasks +
// roster reconvergence in `mesh/background.rs`.

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
    fn dial_order_edge_cases() {
        let (a, b, me) = (test_id(1), test_id(2), test_id(9));
        let mk = |id, coord| Member {
            identity: id,
            ip: derive_ip(&id),
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
        };

        // No coordinators in the roster ⇒ empty order (caller bails).
        let none_coord = vec![mk(a, false), mk(b, false)];
        assert!(super::coordinator_dial_order(a, &none_coord, me).is_empty());

        // Minter == me (the no-invite case where we pass our own id): we are
        // filtered out, leaving just the other coordinators.
        let members = vec![mk(a, true), mk(me, true)];
        assert_eq!(super::coordinator_dial_order(me, &members, me), vec![a]);

        // Minter isn't a coordinator in the blob: it is not promoted to the
        // front, but real coordinators still get dialed.
        let members = vec![mk(a, true), mk(b, false)];
        assert_eq!(super::coordinator_dial_order(b, &members, me), vec![a]);

        // Minter is a coordinator AND also appears in the member scan: listed
        // once (front), no duplicate.
        let members = vec![mk(a, true), mk(b, true)];
        assert_eq!(super::coordinator_dial_order(a, &members, me), vec![a, b]);
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

    #[test]
    fn gossip_targets_empty_when_sole_coordinator() {
        let me = test_id(1);
        let mk = |id, coord| Member {
            identity: id,
            ip: derive_ip(&id),
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            collision_index: 0,
        };
        // Only members are us (coordinator) and a plain member: nobody to gossip to.
        let members = vec![mk(me, true), mk(test_id(2), false)];
        assert!(super::gossip_targets(&members, me).is_empty());
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

    #[test]
    fn dial_fallback_empty_is_not_welcomed() {
        // Defensive: no coordinators tried at all. Must not panic and must
        // report "not welcomed" so the caller bails rather than indexing.
        let (idx, welcomed) = pick_first_welcome(&[]);
        assert_eq!((idx, welcomed), (0, false));
    }

    #[test]
    fn dial_fallback_first_welcome_wins_over_later() {
        let outcomes = vec![DialOutcome::Welcomed, DialOutcome::Welcomed];
        let (idx, welcomed) = pick_first_welcome(&outcomes);
        assert_eq!((idx, welcomed), (0, true));
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
            .attach_tun(
                FakeTunReader {
                    _alive: Arc::new(()),
                },
                writer1,
            )
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
            .attach_tun(
                FakeTunReader {
                    _alive: alive2.clone(),
                },
                writer2,
            )
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
            .attach_tun(
                FakeTunReader {
                    _alive: Arc::new(()),
                },
                writer3,
            )
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
