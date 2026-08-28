//! The rayfish daemon: a long-lived, root-owned process that holds the iroh
//! [`Endpoint`], the TUN device, the [`PeerTable`], and the [`ProtocolRouter`],
//! and serves the unprivileged CLI over a Unix-socket IPC channel.
//!
//! # Two lifecycles
//!
//! The daemon deliberately separates two concepts that are easy to conflate:
//!
//! - **Process / infrastructure lifecycle**: the iroh endpoint, IPC socket,
//!   accept loop, blob store, DNS resolver, metrics server, and the TUN *file
//!   descriptor*. These are built once in [`run_daemon`] and live for the whole
//!   process. They are torn down only by the daemon-wide `shutdown_token`
//!   (real shutdown / `IpcMessage::Shutdown`).
//! - **Active VPN state**: the TUN link being *up*, system DNS being
//!   configured, and the saved networks being connected. This is toggled at
//!   runtime by [`Daemon::activate`] / [`Daemon::deactivate`], driven
//!   by the `Up` / `Down` IPC commands, and tracked by [`Daemon::active`].
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
//!   never touches it, otherwise the IPC accept loop would die and there would
//!   be nothing left to receive the next `Up`.
//! - Each active network owns a `shutdown_token.child_token()` stored on its
//!   [`NetworkHandle`]. `deactivate` cancels these per-network children to stop
//!   that network's background tasks. Because cancellation is one-shot, every
//!   `activate` mints *fresh* child tokens, so `up → down → up` cycles work.

use arc_swap::ArcSwap;
use bytes::Bytes;
use iroh_metrics::service::MetricsServer;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};

use anyhow::{Context, Result};
use iroh::address_lookup::PkarrRelayClient;
use iroh::endpoint::{Connection, Endpoint, VarInt};
use iroh::{EndpointId, SecretKey};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, HashAndFormat};
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::AsyncMutex;
use crate::audit;
use crate::config;
use crate::config::settings::{self, FirewallKey, GlobalKey, NetworkKey, NodeKey};
use crate::config::{AppConfig, NetworkConfig};
use crate::control::{self, ControlMsg};
use crate::dht;
use crate::dns;
use crate::dns::config as dns_config;
use crate::firewall::{self, SharedFirewall};
use crate::forward;
use crate::identity;
use crate::ipc::{
    self, FirewallRuleView, InactiveNetwork, IpcMessage, LanPeerInfo, MeshVersionMismatch,
    NetworkRole, NetworkStatus, PeerState, PeerStatus, ipc_err,
};
use crate::membership::{
    ApprovedEntry, ApprovedList, ExitFamilies, GroupMode, IdentityProvider, IrohIdentityProvider,
    Member, MemberList, canonical_group_bytes, derive_ipv6, group_blob_hash, verify_group_blob,
};
use crate::network_name;
use crate::peers::{self, PeerTable};
use crate::stats::ForwardMetrics;
use crate::transport;
// The desktop TUN device and its CGNAT pre-flight check don't exist on Android,
// where the packet interface is a `VpnService` fd supplied from Kotlin.
#[cfg(not(target_os = "android"))]
use crate::tun;
use ray_proto::SuggestedFirewall;
use smol_str::SmolStr;

#[cfg(unix)]
type IpcOwnedFd = OwnedFd;
#[cfg(not(unix))]
type IpcOwnedFd = ();

#[derive(Clone, Debug)]
pub(crate) enum PeerIdentity {
    #[cfg(unix)]
    Unix { uid: u32, gid: u32 },
    #[cfg(windows)]
    Windows {
        sid: String,
        is_local_system: bool,
        is_elevated_admin: bool,
    },
}

#[cfg(windows)]
fn windows_peer_authorized(peer: Option<&PeerIdentity>, operator: Option<&str>) -> bool {
    peer.is_some_and(|peer| match peer {
        PeerIdentity::Windows {
            sid,
            is_local_system,
            is_elevated_admin,
        } => {
            *is_local_system
                || *is_elevated_admin
                || operator.is_some_and(|operator| operator == sid)
        }
    })
}

#[cfg(all(test, windows))]
mod windows_authorization_tests {
    use super::{PeerIdentity, windows_peer_authorized};

    fn peer(sid: &str, system: bool, admin: bool) -> PeerIdentity {
        PeerIdentity::Windows {
            sid: sid.to_owned(),
            is_local_system: system,
            is_elevated_admin: admin,
        }
    }

    #[test]
    fn zombie_authorization_matrix_fails_closed() {
        let operator = "S-1-5-21-1-2-3-1001";
        assert!(!windows_peer_authorized(None, Some(operator)));
        assert!(!windows_peer_authorized(
            Some(&peer("S-1-5-21-1-2-3-1002", false, false)),
            Some(operator)
        ));
        assert!(windows_peer_authorized(
            Some(&peer(operator, false, false)),
            Some(operator)
        ));
        assert!(windows_peer_authorized(
            Some(&peer("S-1-5-18", true, false)),
            None
        ));
        assert!(windows_peer_authorized(
            Some(&peer("S-1-5-21-1-2-3-500", false, true)),
            None
        ));
    }
}

impl PeerIdentity {
    #[cfg(unix)]
    fn unix_cred(&self) -> Option<(u32, u32)> {
        let Self::Unix { uid, gid } = self;
        Some((*uid, *gid))
    }

    #[cfg(not(unix))]
    fn unix_cred(&self) -> Option<(u32, u32)> {
        None
    }

    /// This caller in the form [`create_report_bundle`] opens the bundle to.
    fn report_requester(&self) -> ReportRequester {
        match self {
            #[cfg(unix)]
            Self::Unix { uid, gid } => ReportRequester::Unix {
                uid: *uid,
                gid: *gid,
            },
            #[cfg(windows)]
            Self::Windows { sid, .. } => ReportRequester::Windows { sid: sid.clone() },
        }
    }
}

/// Who asked for a diagnostics bundle, in whatever form the platform can hand a
/// file to.
///
/// The bundle packs the root daemon's `rayfish=debug` logs, peer ids and mesh
/// addresses, and `IpcMessage::Report` sits in the open-reads tier, so it is
/// created readable by nobody and then opened to exactly this caller: chowned on
/// Unix, granted read by SID on Windows. Not a `(u32, u32)`, because the two
/// platforms do not agree on what identifies a caller.
pub(crate) enum ReportRequester {
    #[cfg(unix)]
    Unix { uid: u32, gid: u32 },
    #[cfg(windows)]
    Windows { sid: String },
}

// `Daemon`'s IPC operations are split by domain into the `mesh/` submodule;
// see `mesh/mod.rs`. Each holds an additional `impl Daemon` block. Nested a
// level down so the module names can be the clean domain names without colliding
// with the `use crate::{firewall, dns, …}` aliases above.
mod mesh;
// The mesh core's join handshake and background-task/reconvergence helpers were
// moved into `mesh/{join,background}.rs`; re-export them at the daemon level so
// `mod.rs` and the other `mesh/` submodules (via `use super::super::*`) call them
// by bare name, as before the split.
pub(crate) use mesh::*;
// `run_daemon` (the `ray daemon` entry point) stays public for the binary.
pub use mesh::JoinOptions;
pub use mesh::run_daemon;
// `build_headless` is the embedder (mobile) construction entry point.
pub use mesh::build_headless;

/// Legacy name for [`Daemon`], kept so embedders (`ray-mobile`) that were
/// written against `DaemonState` compile unchanged after the daemon refactor.
pub type DaemonState = Daemon;

// The process-lifetime network + storage foundation every service depends on.
mod foundation;
pub(crate) use foundation::Transport;

// The per-peer mesh connection driver (one connection per peer, frame demux).
mod connection_manager;
pub(crate) use connection_manager::{ConnectionManager, MeshDispatch};

// One live mesh connection + its control-plane demux loop, built by the manager.
mod mesh_connection;
pub(crate) use mesh_connection::MeshConnection;

// The service that owns the set of active networks (M5 migration seam).
mod network_registry;
pub(crate) use network_registry::{DialTarget, NetworkRegistry, missing_networks};

// Domain satellites with their own owned state (and ALPN accept arms), held by
// `Daemon` as fields rather than loose on the core. See each module.
mod dns_service;
pub(crate) use dns_service::DnsService;

mod file_service;
pub(crate) use file_service::FileService;

/// In-flight transfer state, for progress reporting on both sides of a send.
pub mod transfers;

mod connect_service;
pub(crate) use connect_service::ConnectService;

// Nodes seen on the local network over mDNS (`ray mdns scan`).
mod lan_discovery;
pub(crate) use lan_discovery::LanPeers;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// ALPN for the device-pairing protocol. The trailing `/1` is its protocol
/// version - **bump it on any breaking change to the `PairMsg` handshake**;
/// peers on different versions can't negotiate a connection (transport-enforced).
const PAIR_ALPN: &[u8] = b"rayfish/pair/2";

/// Node-wide shared handles, cloned into every per-network accept handler and
/// background task. Every field is a cheap `Clone` (an `Arc`-backed handle, a
/// channel sender, or a small wrapper), so the whole bundle is cloned by value
/// instead of threaded as a dozen separate arguments/struct fields. Built once
/// per daemon via [`Daemon::mesh_ctx`]; a new daemon-wide dependency is one
/// field here rather than one parameter at every call site.
#[derive(Clone)]
pub(crate) struct MeshCtx {
    identity: IrohIdentityProvider,
    peers: PeerTable,
    tun_tx: Arc<ArcSwap<mpsc::Sender<Bytes>>>,
    stats: Arc<ForwardMetrics>,
    blob_store: FsStore,
    firewall: SharedFirewall,
    hostname_table: dns::HostnameTable,
    reverse_table: dns::ReverseLookupTable,
    device_user_map: peers::DeviceUserMap,
    /// Peers removed from a network's roster (via `ray kick` or a stale-entry
    /// prune during reconverge), keyed by `(network, transport id)`. A member
    /// closes such a peer's connection but can't see its own close code, so the
    /// connection supervisor would re-dial the removed peer (which still lists it)
    /// and re-form the link. The supervisor consumes an entry here to skip that
    /// one reconnect. Populated in [`reconverge_and_apply`] and the kick handler.
    pruned_peers: Arc<DashSet<(String, EndpointId)>>,
    /// IP -> roster member map (no connection required), populated wherever the
    /// roster is applied so the on-demand data path can resolve an unconnected
    /// destination to the peer to lazily dial. See [`peers::RosterRouteMap`].
    pub(crate) route_map: peers::RosterRouteMap,
    /// Daemon-wide disconnect channel. Every [`MeshConnection`] reports its peer's
    /// drop here when its demux loop ends, and a single
    /// [`NetworkRegistry::run_connection_supervisor`] consumes it. Under one mesh
    /// connection per identity a drop tears the peer down across every shared
    /// network at once, so this is node-wide rather than per-network. The channel
    /// keeps disconnect handling serial (one check-then-act at a time).
    disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    /// The network-owning service. Control readers reach it through the ctx to
    /// run network ops directly (e.g. `unpair_self` on a `ControlMsg::Unpaired` or
    /// a self-nullify during reconverge) instead of signalling the daemon loop.
    registry: Arc<NetworkRegistry>,
}

impl MeshCtx {
    /// Build the per-peer data-plane bundle for `forward::spawn_peer_reader`,
    /// combining this context's shared handles with the caller's `token`. Called
    /// by [`MeshConnection`], which owns the reader for the connection's lifetime.
    pub(crate) fn forward_ctx(&self, token: CancellationToken) -> forward::ForwardCtx {
        forward::ForwardCtx {
            firewall: self.firewall.clone(),
            tun_tx: self.tun_tx.clone(),
            token,
            stats: self.stats.clone(),
            device_user_map: self.device_user_map.clone(),
            exit: crate::exit_node::ExitContext {
                server: self.registry.exit_server.clone(),
                client: self.registry.exit_client.clone(),
                my_v6: derive_ipv6(&self.identity.local_identity()),
            },
        }
    }

    /// Register a peer's connection for `network` in the peer table: add its route
    /// (and, on the first shared network, its audit connect event). The
    /// connection's single data reader is not started here; [`MeshConnection`] owns
    /// it for the connection's lifetime. Returns whether the stored connection is
    /// new (the first shared network, or a reconnect that replaced a different
    /// connection), which the dial side uses to decide whether to drive a fresh
    /// control demux.
    pub(crate) fn register_peer_conn(
        &self,
        conn: &Connection,
        peer_id: EndpointId,
        network: &str,
    ) -> bool {
        let ipv6 = derive_ipv6(&peer_id);
        // Keep the roster route map current with every peer we connect to, so a
        // later idle teardown can re-dial it on demand (reconverge covers the
        // roster-wide sync + removals; this is the incremental add).
        self.route_map.sync_add(network, ipv6, peer_id);
        self.peers.add(ipv6, conn.clone(), peer_id, network)
    }
}

/// Announce our outbound handle table to a peer over `conn` so it can decode the
/// datagrams we tag for each shared network. Full snapshot (idempotent replace on
/// the receiver); connection-level (`net = None`). Resolves each local network
/// name to its public key from config, which is cheap and only runs when a
/// connection's shared-network set changes.
pub(crate) async fn announce_network_handles(
    peers: &PeerTable,
    conn: &Connection,
    peer_ip: Ipv6Addr,
) {
    let entries: Vec<control::NetworkHandle> = peers
        .outbound_handles(&peer_ip)
        .into_iter()
        .filter_map(|(name, handle)| {
            let pubkey = config::load_network(&name)
                .ok()
                .flatten()
                .and_then(|n| n.network_public_key)?;
            Some(control::NetworkHandle {
                network: pubkey,
                handle,
            })
        })
        .collect();
    if entries.is_empty() {
        return;
    }
    let _ = open_and_send(
        conn,
        None,
        &ControlMsg::NetworkHandles {
            entries,
            features: transport::FEATURE_IDLE_CLOSE,
        },
    )
    .await;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingSnapshotDurability {
    hash: blake3::Hash,
    /// Whether the exact generation came from a verified published record.
    published: bool,
}

pub(crate) struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
    snapshot: Option<GroupSnapshot>,
    /// Serializes durable snapshot-pointer updates with DHT publication for this
    /// network. Clone the Arc under the state read lock, then await it separately.
    snapshot_commit: Arc<AsyncMutex<()>>,
    /// The hash of the signed record this state is converged on, which is not
    /// always the hash of [`Self::snapshot`].
    ///
    /// The snapshot is *our* encoding of the group, and on a coordinator that is
    /// exactly what it publishes, so the two agree. On a member they need not:
    /// applying a fetched blob re-encodes it from local state, and a publisher on
    /// a build whose `Member` has a different field set (or the map encoding that
    /// preceded the compact one, which rmp-serde still reads) produces bytes ours
    /// cannot reproduce. Comparing the record against the snapshot hash then says
    /// "a different blob" forever: every poll refetches and reapplies, and the
    /// steady-state work on the converged branch (the self-nullify check, a
    /// pending rename, the exit-offer sync) never runs at all.
    ///
    /// So convergence is tracked as what we last accepted, and the snapshot stays
    /// what we would publish.
    converged_hash: Option<blake3::Hash>,
    /// The current generation's config rename may have landed but its durability
    /// barrier failed. No generation can be published or welcomed until an exact
    /// retry succeeds; durably persisting a newer current generation supersedes
    /// and clears an older ambiguity.
    unconfirmed_durable_hash: Option<PendingSnapshotDurability>,
    network_secret_key: Option<SecretKey>,
    network_public_key: EndpointId,
    /// Local config/runtime alias used to index this network on this device.
    network_name: Option<String>,
    /// Name carried by the signed GroupBlob. It must not be replaced by a local
    /// join alias, because a later promotion may make this node a publisher.
    group_name: Option<String>,
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
    /// Device keys nullified on this network (`ray unpair`). Carried in the signed
    /// blob: a coordinator seeds it from its persisted `revoked_devices` and drops
    /// nullified devices from `members`; a member adopts it from the verified blob
    /// on every reconverge. Enforcement (admission, MeshHello, prune) rejects a
    /// cert whose device key is listed.
    nullifiers: BTreeSet<EndpointId>,
    /// Author timestamp (microseconds since the epoch) of the most recent signed
    /// pkarr record applied to this state, and the floor every later one has to
    /// clear.
    ///
    /// A signature proves who wrote a record, never when: an old record for this
    /// network stays valid forever and its hash differs from the current one, so
    /// hash inequality alone reads a rollback as a change and applies it. That
    /// re-seats kicked members, restores devices the blob nullified, and reverts
    /// the suggested firewall, and the record it takes is one the DHT served
    /// publicly to anyone holding the room id. The timestamp lives inside the
    /// signed bytes (`SignedPacket::timestamp`), so it cannot be edited to clear
    /// the floor, and ordering on it is what pkarr relays themselves do.
    ///
    /// In memory only, so a restart starts from `None` and takes the first record
    /// it sees. That is the DHT's copy, which relays keep at the highest
    /// timestamp, and any later legitimate republish outranks a replay anyway, so
    /// the gap is a race at startup rather than a standing hole.
    last_record_timestamp: Option<u64>,
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
    pub(crate) fn roster(&self) -> Vec<Member> {
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
            self.group_name.as_deref(),
            &self.reusable_keys,
            &self.nullifiers,
        );
        let hash = blake3::hash(&bytes);
        self.snapshot = Some(GroupSnapshot {
            hash,
            msgpack_bytes: bytes,
        });
        // Our own encoding is by definition what we are converged on. An apply
        // from a fetched blob overwrites this with the record's hash right after,
        // since that is the one the network agreed on.
        self.converged_hash = Some(hash);
    }

    /// Whether a signed record naming `signed` is one this state has not applied.
    ///
    /// The single answer to "do we need to reconverge", for the group poller and
    /// the trigger-driven path alike. It exists as a method because those two open
    /// -coded the same comparison against different fields and drifted: one moved
    /// to [`Self::converged_hash`] and the other kept reading the snapshot's,
    /// which is our own re-encoding and need not equal what the publisher wrote.
    /// A member whose bytes differ then treats every poll as a change, forever.
    pub(crate) fn needs_reconverge(&self, signed: blake3::Hash) -> bool {
        crate::membership::trusted_reconverge_hash(self.converged_hash, signed).is_some()
    }
}

/// Runtime state for one active network. Created when a network is joined,
/// created, or reconnected; dropped (after `cancel`ling and awaiting `tasks`)
/// when the network is left or the VPN is put on standby. The persisted config
/// (in `networks.toml`) outlives this handle: standby tears down the handle
/// but keeps the config so `activate` can rebuild it.
pub struct NetworkHandle {
    name: String,
    network_key: EndpointId,
    role: NetworkRole,
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
    invite_lock: Arc<AsyncMutex<()>>,
    /// Set when this network's signed record advertises a mesh protocol version
    /// this build does not speak. The handle exists because the roster blob is
    /// not version-gated and registers fine; every dial on it is refused by the
    /// versioned ALPN, so the flag is what stops `ray status` from showing the
    /// network as healthy. Cleared by construction: the restore loop replaces
    /// the whole handle once the coordinator republishes at a version we speak.
    incompatible: Option<MeshVersionMismatch>,
}

/// Shared, always-on daemon state. Cloned (via `Arc`) into every IPC handler
/// and background task. Holds both the infrastructure that lives for the whole
/// process and the handles for the currently-active networks. See the
/// module-level docs for the two-lifecycle model.
/// Handles for the packet-forwarding tasks a [`Daemon::attach_tun`] call
/// spawns (the TUN writer and the `run_mesh` reader loop), plus a dedicated
/// cancellation token so the data plane can be stopped independently of a full
/// daemon shutdown (used by [`Daemon::detach_tun`] / `ray-mobile`'s `down`).
struct TunTasks {
    /// Cancels the `run_mesh` reader loop without touching `shutdown_token`.
    cancel: CancellationToken,
    /// The TUN writer task (`spawn_tun_writer`).
    writer: JoinHandle<()>,
    /// The `run_mesh` reader loop task.
    mesh: JoinHandle<()>,
}

pub struct Daemon {
    /// The process-lifetime foundation (endpoint, identity, blob store, metrics,
    /// contact id), grouped so extracted services can depend on `Arc<Transport>`
    /// instead of the whole daemon. During the service-decomposition transition
    /// this holds clones of the same handles the loose fields below still use;
    /// the loose fields go away when `Daemon` is dissolved.
    transport: Arc<Transport>,
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
    tun_tx: Arc<ArcSwap<mpsc::Sender<Bytes>>>,
    /// The network-owning service. Owns the `networks` map, `peers`, `firewall`,
    /// `device_user_map`, and `pruned_peers`; Daemon reaches all of them
    /// through `self.registry` rather than keeping its own copies. The
    /// daemon delegates coordinator registration / promotion to it, and hands
    /// clones to services (FileService) and control readers (MemberAcceptState)
    /// so they call it directly instead of signalling the daemon over a channel.
    registry: Arc<NetworkRegistry>,
    shutdown_token: CancellationToken,
    protocol_router: Arc<ProtocolRouter>,
    /// Magic DNS leaf service: naming tables, resolver, and OS-DNS configurator
    /// (see [`DnsService`]). Shared as `Arc` so extracted consumers can hold it.
    dns: Arc<DnsService>,
    mdns_enabled: bool,
    /// Whether this node opted into automatic stable updates
    /// (`ray config set auto-update on` / `ray install --auto-update`). Read at
    /// startup; when set, `run_daemon` spawns the periodic update task. Echoed
    /// back in `ray status`.
    auto_update: bool,
    /// Name of the OS TUN device (desktop) or a placeholder until a packet
    /// interface is attached. Interior-mutable because on embedders (mobile) the
    /// interface is attached after construction via [`Daemon::attach_tun`],
    /// while on desktop it is set once at boot. `Arc` so [`NetworkRegistry`] shares
    /// it for the leave/teardown DNS search-domain refresh.
    tun_name: Arc<ArcSwap<String>>,
    /// Handles for the packet-forwarding tasks spawned by
    /// [`Daemon::attach_tun`], kept so a future `down()`/detach can stop them.
    tun_tasks: Mutex<Option<TunTasks>>,
    /// Serializes exit-node reconciles. `apply_exit_node` runs from the IPC
    /// dispatcher, `activate()`, and the reconverge reapply listener, each on its
    /// own task, and the kernel enable underneath is check-then-write (the sysctl
    /// snapshot, the pf enable token): two interleaved runs can snapshot each
    /// other's intermediate state, after which teardown "restores" forwarding to
    /// on. One reconcile at a time. Tokio's mutex because the critical section
    /// awaits (blocking-pool `ip`/`nft`/`pfctl` children, offer broadcasts).
    pub(crate) exit_reconcile: AsyncMutex<()>,
    /// Prometheus metrics-server guard. Owned so it lives for the daemon's whole
    /// lifetime (dropping it stops the export); `None` if the server failed to bind.
    _metrics_server: Option<MetricsServer>,
    /// The iroh protocol [`Router`](iroh::protocol::Router): owns the endpoint
    /// accept loop and dispatches each inbound connection by ALPN to its handler.
    /// Owned for the daemon's whole lifetime (it aborts on drop); `run_daemon`
    /// (desktop) and [`Daemon::shutdown_and_close`] (embedders) `shutdown()` it
    /// on exit, which drains the protocol handlers (releasing the blob store's
    /// redb lock) and closes the endpoint.
    router: iroh::protocol::Router,
    /// File-transfer + pairing state and ALPN accept arms (see [`FileService`]).
    /// Shared with [`ProtocolRouter`], which runs the accept arms.
    files: Arc<FileService>,
    /// In-flight file transfers, both directions, for progress reporting. Shared
    /// with [`FileService`] (receive side) and the send-side provider event pump.
    transfers: Arc<transfers::TransferRegistry>,
    /// `ray connect` state + ALPN accept arm (see [`ConnectService`]). Shared with
    /// [`ProtocolRouter`], which runs the accept arm.
    connect: Arc<ConnectService>,
    device_cert: Option<control::DeviceCert>,
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
    /// standby). Set by [`Daemon::start_ssh`], cleared by `stop_ssh`, which are
    /// the only readers and are desktop-only, so the field does not exist on an
    /// Android build at all.
    #[cfg(feature = "desktop")]
    ssh_token: Mutex<Option<CancellationToken>>,
    /// Cancellation token for the IPv4 listener bridge (`None` when off / on
    /// standby). Same shape and same reason as `ssh_token`: it binds the mesh
    /// address, so it lives and dies with the data plane. See
    /// [`crate::v4bridge`].
    #[cfg(feature = "desktop")]
    v4_bridge_token: Mutex<Option<CancellationToken>>,
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

impl Daemon {
    /// The device cert to present when joining, preferring the on-disk copy so a
    /// join issued right after pairing (same process, no restart) carries the
    /// freshly stored cert rather than the value loaded at startup.
    pub fn current_device_cert(&self) -> Option<control::DeviceCert> {
        // The on-disk cert is authoritative: a cleanly-absent file (`Ok(None)`,
        // e.g. after `unpair_self` deletes it) means unpaired, so we must NOT fall
        // back to the in-memory copy loaded at build, otherwise `is_paired()`
        // would keep reporting paired after a self-unpair. Only a genuine read
        // error falls back to the in-memory cert.
        match identity::load_device_cert() {
            Ok(cert) => cert,
            Err(_) => self.device_cert.clone(),
        }
    }

    /// In-flight file transfers, both directions, for progress reporting. Cheap:
    /// clones a small vec. Safe to poll.
    pub fn list_transfers(&self) -> Vec<transfers::TransferInfo> {
        self.transfers.list()
    }

    /// Gracefully take the whole node offline: cancel the daemon-wide shutdown
    /// token (stopping every network run loop, the accept loop, and the
    /// data-plane forward tasks) and then close the iroh endpoint so all QUIC
    /// connections terminate cleanly and peers see us drop immediately, rather
    /// than lingering until an idle timeout. Awaiting the close matters for
    /// embedders (mobile) that rebuild a fresh daemon on re-enable: without it
    /// the old endpoint's connections outlive `stop`, so a coordinator keeps the
    /// stale session while the rebuilt endpoint (same node key) comes up and the
    /// device shows offline until the race clears.
    ///
    /// Shutting the protocol router down first is what releases the blob store,
    /// and it is not optional for an embedder either: `Router::shutdown` is the
    /// only thing that drives `BlobsProtocol::shutdown` -> `Store::shutdown`,
    /// which is what drops the store's redb `Database` and with it the exclusive
    /// file lock on `blobs/blobs.db`. Without it the lock outlives this call, and
    /// a second open does not fail, it waits: the next `build_headless` in the
    /// same process then blocks until whatever eventually drops the old store
    /// does, if anything does, which on mobile is how a disabled node never comes
    /// back. The explicit `endpoint.close()` after it is the same idempotent
    /// backstop the desktop tail keeps.
    ///
    /// After this the `Daemon` is spent; build a new one to come back online.
    pub async fn shutdown_and_close(&self) {
        let tun_attached = self.tun_tasks.lock().unwrap().is_some();
        tracing::info!(tun_attached, "shutdown: cancelling token, closing endpoint");
        self.shutdown_token.cancel();
        let _ = self.router.shutdown().await;
        self.transport.endpoint.close().await;
        tracing::info!("shutdown: router stopped, blob store released, endpoint closed");
    }

    /// Bundle the daemon-wide shared handles into a [`MeshCtx`] for the accept
    /// handlers and background tasks. Every field is a cheap `Clone`.
    /// Part of the embedding API (used by `ray-mobile`): the host OS observed a
    /// network change (Wi-Fi/cellular switch, roam, airplane mode). On desktop,
    /// netwatch sees route changes itself; on Android its route monitor is a
    /// stub (apps cannot subscribe to netlink route updates), so without this
    /// forward the endpoint sits on dead sockets until something else rebuilds
    /// them. iroh rebinds and re-probes its paths in response.
    pub async fn network_changed(&self) {
        tracing::info!("host reported a network change; rebinding endpoint");
        self.transport.endpoint.network_change().await;
        // Re-resolve every network's signed record too. Anything a coordinator
        // tried to push while we were between networks was delivered to an
        // address that had stopped working, and a battery-powered node would
        // otherwise carry that gap until its next long-interval tick. This is
        // also the cheapest moment to ask: the radio is already up for the
        // rebind.
        self.registry.poll_nudge.notify_waiters();
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
            let peers = self.registry.peers.clone();
            let firewall = self.registry.firewall.clone();
            let cancel = cancel.clone();
            let stats = self.stats.clone();
            let resolver = self.dns.resolver.clone();
            // The registry is the forwarding loop's on-demand dial mechanism: when a
            // packet has no live route, the loop asks it to dial the roster member.
            // Present on every node so any peer stays reachable-on-demand after a link
            // idle-closes.
            let dialer = Some(self.registry.clone());
            tokio::spawn(async move {
                if let Err(e) = forward::run_mesh(
                    reader, peers, firewall, cancel, stats, resolver, new_tx, dialer,
                )
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
            tracing::info!("detach_tun: aborting TUN writer + mesh forwarding tasks");
            tasks.cancel.cancel();
            tasks.writer.abort();
            tasks.mesh.abort();
        } else {
            tracing::debug!("detach_tun: no TUN attached");
        }
    }

    /// Point the Magic DNS resolver at the given upstream servers so non-`.ray`
    /// queries are forwarded there instead of refused. The desktop path captures
    /// upstreams from the system resolver config; Android has none to capture, so
    /// the platform reads the underlying network's DNS servers and passes them in.
    pub fn set_dns_upstreams(&self, servers: Vec<Ipv4Addr>) {
        self.dns.resolver.set_upstreams(servers);
    }

    /// Point the Magic DNS resolver at explicit `ip:port` upstreams. Android uses
    /// this to target a loopback `DnsResolver.rawQuery` proxy so non-`.ray`
    /// lookups honor the system Private DNS (DoT/DoH) rather than being forwarded
    /// as cleartext UDP on port 53.
    pub fn set_dns_upstream_addrs(&self, servers: Vec<SocketAddr>) {
        self.dns.resolver.set_upstream_addrs(servers);
    }

    /// Register a [`CoordinatorAcceptState`] handler for `network` and update
    /// the network's role in `self.registry.networks` to [`NetworkRole::Coordinator`].
    ///
    /// Calling this at create, restore, and admin-promotion sites keeps the
    /// coordinator-registration logic in one place. The method is synchronous
    /// (no `.await`) because `protocol_router.register` is a plain HashMap
    /// swap; the caller is responsible for spawning the `disconnect_rx` cleanup
    /// task **before** calling this so the channel is live when the first
    /// incoming connection arrives.
    /// Tailscale-style access control. Read-only queries are open to any local
    /// user; mutating commands require the caller to be root or the configured
    /// operator UID; setting the operator itself is root-only. Returns `None`
    /// when the request is permitted, or `Some(error)` to short-circuit it.
    ///
    /// Identity is taken from the connecting socket's `SO_PEERCRED` (the kernel
    /// vouches for it, it can't be forged by the client), so the socket file
    /// mode only has to permit the connection, not gate authority.
    pub(crate) fn check_authorized(
        req: &IpcMessage,
        peer: Option<&PeerIdentity>,
    ) -> Option<IpcMessage> {
        // Reads are available to everyone.
        if matches!(
            req,
            IpcMessage::Status
                | IpcMessage::Report
                | IpcMessage::Logs { .. }
                | IpcMessage::FirewallShow
                | IpcMessage::FirewallSuggestions { .. }
                | IpcMessage::FirewallPending { .. }
                | IpcMessage::FirewallSshShow
                | IpcMessage::ExitNodeStatus { .. }
                | IpcMessage::ListFiles
                | IpcMessage::Connections
                // The queue `ray requests <net> accept` reads its id out of,
                // and the same shape as `Connections` right above it.
                | IpcMessage::Requests { .. }
                | IpcMessage::ContactId
                | IpcMessage::Ping { .. }
                | IpcMessage::Netcheck
                | IpcMessage::AliasList { .. }
                | IpcMessage::ListPairedDevices
                | IpcMessage::ListLanPeers
                | IpcMessage::ConfigGet { .. }
                | IpcMessage::NetConfigGet { .. }
        ) {
            return None;
        }

        #[cfg(unix)]
        let uid = peer.map(|p| match p {
            PeerIdentity::Unix { uid, .. } => *uid,
        });
        // Root may do anything.
        #[cfg(unix)]
        if uid == Some(0) {
            return None;
        }

        // Granting operator access is reserved for root.
        if matches!(req, IpcMessage::SetOperator { .. }) {
            #[cfg(unix)]
            return Some(ipc_err(
                "permission denied: granting operator access requires root \
                          (re-run with sudo)"
                    .to_string(),
            ));
            // There is no root here to be, and `ray set-operator` does not use
            // this path on Windows: it writes the SID itself from an elevated
            // process (see `cmd_set_operator`). A frame arriving here is either
            // an older CLI or something hand-rolled, so say which command works
            // rather than naming a privilege that does not exist.
            #[cfg(windows)]
            return Some(ipc_err(
                "permission denied: set the operator from an Administrator \
                 terminal with: ray set-operator <user>"
                    .to_string(),
            ));
        }

        #[cfg(windows)]
        if windows_peer_authorized(peer, config::operator_sid().ok().flatten().as_deref()) {
            return None;
        }

        // Otherwise the caller must be the configured operator.
        #[cfg(unix)]
        {
            let operator = config::load().ok().and_then(|c| c.operator_uid);
            if uid.is_some() && uid == operator {
                return None;
            }
        }

        // The one error a non-operator is most likely to see, so it has to name a
        // command that exists on the platform reading it. Windows has no sudo,
        // and its `set-operator` needs an elevated terminal rather than a prefix.
        #[cfg(unix)]
        return Some(ipc_err(
            "permission denied: this user is not authorized to control rayfish.\n\
                      Grant access with: sudo ray set-operator <user>"
                .to_string(),
        ));
        #[cfg(windows)]
        Some(ipc_err(
            "permission denied: this user is not authorized to control rayfish.\n\
             Grant access from an Administrator terminal with: ray set-operator <user>"
                .to_string(),
        ))
    }

    /// Persist the operator UID so that user can run mutating `ray` commands
    /// without root. Authorization (root-only) is enforced in `check_authorized`.
    pub(crate) fn set_operator(&self, uid: u32) -> IpcMessage {
        if let Err(e) = config::update_settings(|cfg| {
            cfg.operator_uid = Some(uid);
            Ok(())
        }) {
            return ipc_err(format!("failed to save config: {e}"));
        }
        IpcMessage::Ok {
            message: format!("operator set to uid {uid}; that user can now run ray without sudo"),
        }
    }

    /// The nodes mDNS has seen on this LAN, newest sighting first, each marked
    /// with a network already shared with it (if any). Shared by `ray mdns scan`
    /// and the nearby block in `ray status`, so the two never disagree.
    pub(crate) fn lan_peer_infos(&self) -> Vec<LanPeerInfo> {
        let me = self.transport.endpoint.id();
        let mut peers: Vec<LanPeerInfo> = self
            .transport
            .lan_peers
            .snapshot()
            .into_iter()
            .filter(|(id, _)| *id != me)
            .map(|(id, peer)| LanPeerInfo {
                endpoint_id: id,
                short_id: id.fmt_short().to_string(),
                addrs: peer.addrs.iter().map(|a| a.to_string()).collect(),
                last_seen_secs: peer.last_seen.elapsed().as_secs(),
                shared_network: self.registry.network_shared_with(&id),
            })
            .collect();
        peers.sort_by_key(|p| p.last_seen_secs);
        peers
    }

    /// `ray mdns scan`: every LAN sighting, connected or not.
    pub(crate) fn list_lan_peers(&self) -> IpcMessage {
        IpcMessage::LanPeersList {
            peers: self.lan_peer_infos(),
            mdns_enabled: self.mdns_enabled,
        }
    }

    /// Apply one settings key and persist it. Serves `ray config set|unset` and
    /// every single-value command that used to carry its own IPC variant
    /// (`ray mdns`, `ray firewall on|off|reject|default`, `ray firewall ssh
    /// on|off`, `ray files download-dir|download-user`, and the hidden
    /// `ray auto-update`, whose only spelling is now the key itself).
    ///
    /// Dispatch is on the key's store, because the two a [`NodeKey`] can name
    /// are not interchangeable: a firewall key writes the live `ArcSwap` the
    /// packet path reads (a load/mutate/save there would silently turn `ray
    /// firewall off` into "restart required"), and `ssh` carries listener +
    /// passthrough side effects. Only a plain global key takes the
    /// load/mutate/save below. A per-network key cannot reach here: `ConfigSet`
    /// carries a `NodeKey`, which has no variant for one.
    fn config_apply(
        self: &Arc<Self>,
        key: NodeKey,
        value: &str,
        replace: bool,
        reset: bool,
    ) -> IpcMessage {
        let key = match key {
            NodeKey::Firewall(k) => return self.registry.firewall_config_set(k, value),
            // Not a plain config write: see `Daemon::ssh_config_set`.
            NodeKey::Global(GlobalKey::Ssh) => return self.ssh_config_set(value),
            // Likewise: the bridge's listeners follow the setting live.
            NodeKey::Global(GlobalKey::V4Bridge) => return self.v4_bridge_config_set(value),
            // Spelled out rather than caught by `_`, so a new global key cannot
            // land here by default. Falling through silently is precisely the
            // `ssh` bug: a key whose write needs a live side effect, getting
            // none, with nothing to notice it. Adding a variant breaks this
            // match and forces the choice.
            NodeKey::Global(
                k @ (GlobalKey::Mdns
                | GlobalKey::Relay
                | GlobalKey::DiscoveryDns
                | GlobalKey::DnsUpstreams
                | GlobalKey::AutoUpdate
                | GlobalKey::OnDemand
                | GlobalKey::DownloadDir
                | GlobalKey::DownloadUser),
            ) => k,
        };
        let mut set_err = None;
        let saved = config::update_settings(|cfg| {
            if let Err(e) = config::config_set(cfg, key, value, replace) {
                set_err = Some(e.to_string());
                anyhow::bail!("rejected");
            }
            Ok(())
        });
        if let Some(e) = set_err {
            return ipc_err(e);
        }
        let app_config = match saved {
            Ok(cfg) => cfg,
            Err(e) => return ipc_err(format!("failed to save config: {e}")),
        };
        IpcMessage::Ok {
            message: global_set_message(&app_config, key, reset),
        }
    }

    /// Read node config rows for `ray config get` from the daemon's own config.
    /// Firewall-scoped keys are read from the live config, not from disk, so a
    /// get always agrees with what the packet path is enforcing.
    ///
    /// Without a key this lists both stores, globals first: the two live in
    /// different files behind different handlers, but the user typed one
    /// command and expects every node setting back.
    fn config_get(&self, key: Option<NodeKey>) -> IpcMessage {
        let key = match key {
            Some(NodeKey::Firewall(k)) => return self.registry.firewall_config_get(k),
            Some(NodeKey::Global(k)) => Some(k),
            None => None,
        };
        let app_config = match config::load() {
            Ok(c) => c,
            Err(e) => return ipc_err(format!("failed to load config: {e}")),
        };
        let mut rows = config::config_get(&app_config, key);
        if key.is_none() {
            rows.extend(self.registry.firewall_config_rows(None));
        }
        IpcMessage::ConfigValues { rows }
    }

    /// Apply one per-network setting and persist just that network's file, then
    /// run whatever live re-materialization the key implies (the registry's
    /// `apply_network` is pure and deliberately does none of it).
    async fn net_config_apply(
        self: &Arc<Self>,
        network: &str,
        key: NetworkKey,
        value: &str,
    ) -> IpcMessage {
        let mut validation_error = None;
        let updated = config::update_network(network, |net| {
            settings::apply_network(net, key, value).inspect_err(|e| {
                validation_error = Some(e.to_string());
            })
        });
        let net = match updated {
            Ok(Some(net)) => net,
            Ok(None) => return ipc_err(format!("network '{network}' not found")),
            Err(_) if validation_error.is_some() => {
                return ipc_err(validation_error.unwrap());
            }
            Err(e) => return ipc_err(format!("failed to save config: {e}")),
        };
        // Run the live re-materialization the key implies, then confirm.
        match key {
            NetworkKey::AutoAcceptFirewall => self.registry.reapply_suggested_firewall(network),
            NetworkKey::AutoAcceptFiles if net.auto_accept_files => {
                self.files.drain_auto_acceptable().await
            }
            // The pruner re-reads the TTL each tick, so there is nothing to do
            // beyond the write.
            NetworkKey::AutoAcceptFiles | NetworkKey::EphemeralTtl => {}
        }
        IpcMessage::Ok {
            message: net_set_message(&net, network, key),
        }
    }

    /// Read one or every per-network setting.
    fn net_config_get(&self, network: &str, key: Option<NetworkKey>) -> IpcMessage {
        let net = match config::load_network(network) {
            Ok(Some(n)) => n,
            Ok(None) => return ipc_err(format!("network '{network}' not found")),
            Err(e) => return ipc_err(format!("failed to load network: {e}")),
        };
        let keys: Vec<NetworkKey> = match key {
            Some(k) => vec![k],
            None => NetworkKey::ALL.to_vec(),
        };
        let rows = keys
            .into_iter()
            .map(|k| (k.name().to_string(), settings::render_network(&net, k)))
            .collect();
        IpcMessage::ConfigValues { rows }
    }

    pub(crate) async fn handle_request(
        self: &Arc<Self>,
        req: IpcMessage,
        peer: Option<PeerIdentity>,
        fds: Vec<IpcOwnedFd>,
    ) -> IpcMessage {
        if let Some(denied) = Self::check_authorized(&req, peer.as_ref()) {
            return denied;
        }
        let peer_cred = peer.as_ref().and_then(PeerIdentity::unix_cred);
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
                roles,
            } => {
                self.join_network(
                    &network_key,
                    name.as_deref(),
                    JoinOptions {
                        hostname,
                        invite,
                        coordinator,
                        auto_accept_firewall,
                        auto_accept_files,
                        roles,
                    },
                )
                .await
            }
            IpcMessage::Leave { name } => self.leave_network(&name).await,
            IpcMessage::Nuke { name, force } => self.registry.nuke_network(&name, force).await,
            IpcMessage::Kick { network, peer } => self.registry.kick_member(&network, &peer).await,
            IpcMessage::Status => self.status(),
            IpcMessage::Report => self.build_report(peer.as_ref()),
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
                self.registry
                    .firewall_add(
                        direction,
                        action,
                        protocol,
                        port.as_deref(),
                        peer.as_deref(),
                        network.as_deref(),
                    )
                    .await
            }
            IpcMessage::FirewallRemove { index } => self.registry.firewall_remove(index),
            IpcMessage::FirewallShow => self.registry.firewall_show(),
            IpcMessage::FirewallSuggest {
                network,
                suggestions,
            } => self.registry.firewall_suggest(&network, suggestions).await,
            IpcMessage::FirewallSuggestions { network } => {
                self.registry.firewall_suggestions(&network)
            }
            IpcMessage::FirewallPending { network } => self.registry.firewall_pending(&network),
            IpcMessage::FirewallAccept { network } => self.registry.firewall_accept(&network),
            IpcMessage::FirewallDeny { network } => self.registry.firewall_deny(&network),
            IpcMessage::FirewallResolveSuggestions {
                network,
                accept,
                deny,
            } => self
                .registry
                .firewall_resolve_suggestions(&network, &accept, &deny),
            IpcMessage::FirewallSshAllow {
                network,
                peer,
                users,
                allow,
            } => self.firewall_ssh_allow(&network, &peer, users, allow).await,
            IpcMessage::FirewallSshShow => self.firewall_ssh_show(),
            IpcMessage::ExitNodeAllow {
                network,
                peer,
                allow,
            } => {
                let resp = self.registry.exit_node_allow(&network, &peer, allow).await;
                // If the data plane is up, reconcile the runtime state and kernel
                // plumbing now; otherwise `activate()` picks it up on `ray up`.
                self.reconcile_exit_node(resp).await
            }
            IpcMessage::ExitNodeUse { network, peer } => {
                let resp = self.registry.exit_node_use(&network, peer).await;
                self.reconcile_exit_node(resp).await
            }
            IpcMessage::ExitNodeStatus { network } => self.registry.exit_node_status(network),
            IpcMessage::SetHostname { network, hostname } => {
                self.set_hostname(&network, &hostname).await
            }
            IpcMessage::AliasSet {
                network,
                identity,
                alias,
            } => self.registry.set_alias(&network, &identity, &alias),
            IpcMessage::AliasRemove { network, alias } => {
                self.registry.remove_alias(&network, &alias)
            }
            IpcMessage::AliasList { network } => self.registry.list_aliases(&network),
            IpcMessage::SendFile { path, peer } => self.send_file(&path, &peer).await,
            IpcMessage::SendFileStaged {
                path,
                filename,
                peer,
            } => {
                self.files
                    .send_file_named(&path, Some(&filename), &peer)
                    .await
            }
            IpcMessage::SendFileFd { filename, peer } => {
                #[cfg(unix)]
                {
                    let mut fds = fds;
                    match fds.pop() {
                        Some(fd) => self.files.send_file_fd(fd, &filename, &peer).await,
                        None => ipc_err("SendFileFd request carried no file descriptor"),
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = (filename, peer, fds);
                    ipc_err("SendFileFd is unavailable on this platform")
                }
            }
            IpcMessage::CancelSend { id } => self.files.cancel_send(id),
            IpcMessage::ListFiles => self.list_files(),
            IpcMessage::AcceptFile { id, output } => {
                self.files.accept_file(id, output, peer_cred).await
            }
            IpcMessage::StartPairing => self.start_pairing(),
            IpcMessage::PairWithDevice {
                endpoint_id,
                secret,
            } => self.pair_with_device(endpoint_id, secret).await,
            IpcMessage::ListPairedDevices => self.list_paired_devices(),
            IpcMessage::Unpair { device } => self.unpair(&device).await,
            IpcMessage::SetOperator { uid } => self.set_operator(uid),
            IpcMessage::ListLanPeers => self.list_lan_peers(),
            IpcMessage::ConfigSet {
                key,
                value,
                replace,
            } => self.config_apply(key, &value, replace, false),
            IpcMessage::ConfigUnset { key } => self.config_apply(key, "", false, true),
            IpcMessage::ConfigGet { key } => self.config_get(key),
            IpcMessage::NetConfigSet {
                network,
                key,
                value,
            } => self.net_config_apply(&network, key, &value).await,
            IpcMessage::NetConfigGet { network, key } => self.net_config_get(&network, key),
            IpcMessage::InviteCreate {
                network,
                expires_secs,
                hostname,
                reusable,
                roles,
            } => {
                self.registry
                    .invite_create(&network, expires_secs, hostname, roles, reusable)
                    .await
            }
            IpcMessage::InviteList { network } => self.registry.invite_list(&network).await,
            IpcMessage::InviteRevoke { network, id } => {
                self.registry.invite_revoke(&network, &id).await
            }
            IpcMessage::Requests { network } => self.registry.list_requests(&network),
            IpcMessage::AcceptRequest { network, id, roles } => {
                self.registry.accept_request(&network, &id, roles).await
            }
            IpcMessage::DenyRequest { network, id } => self.registry.deny_request(&network, &id),
            IpcMessage::AdminAdd { network, identity } => {
                self.registry.admin_add(&network, &identity).await
            }
            IpcMessage::AdminList { network } => self.registry.admin_list(&network),
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
            other => ipc_err(format!("unexpected message: {:?}", other)),
        }
    }

    // -----------------------------------------------------------------------
    // Hostname
    // -----------------------------------------------------------------------

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    pub async fn set_hostname(&self, network: &str, hostname: &str) -> IpcMessage {
        use crate::hostname;

        if !hostname::is_valid_hostname(hostname) {
            return ipc_err("invalid hostname (lowercase ASCII, 1-63 chars)".to_string());
        }

        let (is_coord, state, dht_notify) = match self.registry.networks.get(network) {
            Some(h) => (
                h.role.is_coordinator(),
                h.state.clone(),
                h.dht_notify.clone(),
            ),
            None => {
                return ipc_err(format!("network '{}' not found", network));
            }
        };

        let my_identity = self.transport.endpoint.id();

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
            derive_ipv6(&self.transport.identity.local_identity()),
        )
        .await;
        dns::update_hostname(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            network,
            &new_hostname,
            derive_ipv6(&self.transport.identity.local_identity()),
        )
        .await;

        // Persist to config. A member also records the rename as a durable
        // pending intent so it keeps being delivered to a coordinator across
        // reconnects/restarts until the signed blob confirms it; a coordinator
        // publishes authoritatively, so it clears any pending intent.
        let _ = config::update_network(network, |net| {
            net.my_hostname = Some(new_hostname.clone());
            net.pending_hostname = if is_coord {
                None
            } else {
                Some(new_hostname.clone())
            };
            Ok(())
        });

        // Fast-path the rename to connected peers via `MeshHello`, regardless of
        // role. A peer *coordinator* only learns a self-rename this way: it acts
        // on another node's `MeshHello` (routed to `handle_member_hello`, which
        // applies the rename and republishes) but not on a `MemberSync`/
        // `BlobUpdated` trigger, and coordinators don't run the group poller. So
        // without this, a co-coordinator's rename never reached its peer
        // coordinators (roster + `.ray` DNS both stayed stale on them).
        self.announce_rename_to_peers(network, my_identity, &new_hostname)
            .await;
        if is_coord {
            // Authoritative: republish the signed blob so members reconverge from
            // the record, and broadcast a `MemberSync` trigger to nudge them.
            tracing::info!(
                network = %network,
                hostname = %new_hostname,
                "coordinator renamed self; republishing blob + broadcasting MemberSync"
            );
            update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
            let net_pubkey = state.read().unwrap().network_public_key;
            broadcast_member_sync(&self.registry, net_pubkey, network, None).await;
        }

        let dns_name = format!("{}.{}.{}", new_hostname, network, crate::DNS_DOMAIN);
        IpcMessage::Ok {
            message: format!("hostname set to {} ({})", new_hostname, dns_name),
        }
    }

    /// Fast-path a member's rename to its connected peers via `MeshHello` (only
    /// the coordinator's continuous control reader acts on it, resolving
    /// collisions and broadcasting the authoritative `MemberSync`). The durable
    /// `pending_hostname` intent + reconverge drain backstop the rest.
    async fn announce_rename_to_peers(
        &self,
        network: &str,
        my_identity: EndpointId,
        new_hostname: &str,
    ) {
        let peers = self.registry.peers.peers_for_network_with_conn(network);
        let net_pubkey = self.registry.networks.get(network).map(|h| h.network_key);
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
                    hostname: Some(new_hostname.to_string()),
                    device_cert: self.current_device_cert(),
                };
                if control::send_msg(&mut send, net_pubkey, &msg).await.is_ok() {
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

    // -----------------------------------------------------------------------
    // Invite + join-request handlers (coordinator only)
    // -----------------------------------------------------------------------
}

/// The confirmation line for a global key, rendered from the config as it
/// stands after the write. `reset` is set by `ConfigUnset`.
///
/// The keys that used to own an IPC variant keep the exact string their handler
/// produced: collapsing the handlers was the point of this refactor, changing
/// what the user reads was not. The rest get the generic wording `ray config
/// set` has always used.
///
/// The "Restart the daemon" clause on `download-dir`/`download-user` is
/// inherited verbatim and is not actually true (`resolve_download_target` reads
/// the config on every accept, so both take effect immediately). Correcting it
/// is a user-visible improvement and belongs in its own change, not smuggled
/// into a refactor whose whole constraint is that nothing user-visible moves.
fn global_set_message(cfg: &AppConfig, key: GlobalKey, reset: bool) -> String {
    let restart = "Restart the daemon for changes to take effect.";
    match key {
        GlobalKey::Mdns => format!(
            "mDNS discovery {}. {restart}",
            if cfg.mdns_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ),
        // "cleared" vs "set" keys off the resulting value, not off `reset`, so
        // `config set download-dir ""` reads the same as `--clear`.
        GlobalKey::DownloadDir if cfg.download_dir.is_none() => {
            format!("download-dir cleared. {restart}")
        }
        GlobalKey::DownloadDir => format!("download-dir set. {restart}"),
        GlobalKey::DownloadUser if cfg.download_user.is_none() => {
            format!("download-user cleared. {restart}")
        }
        GlobalKey::DownloadUser => format!("download-user set. {restart}"),
        // Spelled out rather than caught by `_`, so a new global key cannot
        // inherit this generic wording (and its "Restart the daemon" claim) by
        // default. `Ssh` and `V4Bridge` never reach here (`config_apply` routes
        // them to their own setters); they are listed only to keep the match
        // exhaustive.
        k @ (GlobalKey::Relay
        | GlobalKey::DiscoveryDns
        | GlobalKey::DnsUpstreams
        | GlobalKey::AutoUpdate
        | GlobalKey::OnDemand
        | GlobalKey::Ssh
        | GlobalKey::V4Bridge) => {
            if reset {
                format!("Reset {k} to default. {restart}")
            } else {
                format!("Set {k}. {restart}")
            }
        }
    }
}

/// The confirmation line for a per-network key, rendered from the network
/// config as it stands after the write. Each key keeps the exact string its old
/// handler produced, and, as with the firewall keys, without a "restart" clause:
/// all three take effect immediately.
fn net_set_message(net: &NetworkConfig, network: &str, key: NetworkKey) -> String {
    let on_off = |v: bool| if v { "enabled" } else { "disabled" };
    match key {
        NetworkKey::AutoAcceptFirewall => format!(
            "auto-accept firewall suggestions {} for '{network}'",
            on_off(net.auto_accept_firewall)
        ),
        NetworkKey::AutoAcceptFiles => format!(
            "auto-accept files from your own devices {} for '{network}'",
            on_off(net.auto_accept_files)
        ),
        NetworkKey::EphemeralTtl => match net.ephemeral_ttl_secs {
            Some(s) => format!("ephemeral policy on '{network}' set to {s}s"),
            None => format!("ephemeral policy on '{network}' disabled"),
        },
    }
}

/// Every confirmation line a migrated command prints, pinned byte-for-byte.
///
/// Collapsing fourteen IPC variants onto the settings registry was allowed to
/// delete handlers; it was not allowed to change a single character the user
/// reads. These strings used to live in the deleted handlers, where nothing
/// guarded them, and the first pass of this refactor did silently regress five
/// of them to the generic "Set {key}." wording. Anyone editing a `*_set_message`
/// function should have to update this test on purpose.
#[cfg(test)]
mod confirmation_message_tests {
    use super::*;

    fn mdns(v: bool) -> AppConfig {
        AppConfig {
            mdns_enabled: v,
            ..Default::default()
        }
    }

    fn download_dir(v: Option<&str>) -> AppConfig {
        AppConfig {
            download_dir: v.map(str::to_string),
            ..Default::default()
        }
    }

    fn download_user(v: Option<u32>) -> AppConfig {
        AppConfig {
            download_user: v,
            ..Default::default()
        }
    }

    #[test]
    fn global_keys_keep_the_exact_wording_their_handlers_printed() {
        assert_eq!(
            global_set_message(&mdns(true), GlobalKey::Mdns, false),
            "mDNS discovery enabled. Restart the daemon for changes to take effect."
        );
        assert_eq!(
            global_set_message(&mdns(false), GlobalKey::Mdns, false),
            "mDNS discovery disabled. Restart the daemon for changes to take effect."
        );

        assert_eq!(
            global_set_message(
                &download_dir(Some("/srv/inbox")),
                GlobalKey::DownloadDir,
                false
            ),
            "download-dir set. Restart the daemon for changes to take effect."
        );
        assert_eq!(
            global_set_message(&download_dir(None), GlobalKey::DownloadDir, true),
            "download-dir cleared. Restart the daemon for changes to take effect."
        );

        assert_eq!(
            global_set_message(&download_user(Some(501)), GlobalKey::DownloadUser, false),
            "download-user set. Restart the daemon for changes to take effect."
        );
        assert_eq!(
            global_set_message(&download_user(None), GlobalKey::DownloadUser, true),
            "download-user cleared. Restart the daemon for changes to take effect."
        );

        // A key that never had a handler of its own keeps `ray config set`'s
        // generic wording, set and unset.
        let cfg = AppConfig::default();
        assert_eq!(
            global_set_message(&cfg, GlobalKey::Relay, false),
            "Set relay. Restart the daemon for changes to take effect."
        );
        assert_eq!(
            global_set_message(&cfg, GlobalKey::Relay, true),
            "Reset relay to default. Restart the daemon for changes to take effect."
        );
    }

    /// `cleared` follows the resulting value, not the `reset` flag, so setting
    /// an empty value reads the same as `--clear`.
    #[test]
    fn download_keys_report_cleared_whenever_the_value_ends_up_unset() {
        let cfg = AppConfig::default();
        assert!(cfg.download_dir.is_none());
        assert_eq!(
            global_set_message(&cfg, GlobalKey::DownloadDir, false),
            "download-dir cleared. Restart the daemon for changes to take effect."
        );
    }

    #[test]
    fn network_keys_keep_the_exact_wording_their_handlers_printed() {
        let mut net = config::empty_network_config("gaming");
        net.auto_accept_firewall = true;
        assert_eq!(
            net_set_message(&net, "gaming", NetworkKey::AutoAcceptFirewall),
            "auto-accept firewall suggestions enabled for 'gaming'"
        );
        net.auto_accept_firewall = false;
        assert_eq!(
            net_set_message(&net, "gaming", NetworkKey::AutoAcceptFirewall),
            "auto-accept firewall suggestions disabled for 'gaming'"
        );

        net.auto_accept_files = true;
        assert_eq!(
            net_set_message(&net, "gaming", NetworkKey::AutoAcceptFiles),
            "auto-accept files from your own devices enabled for 'gaming'"
        );
        net.auto_accept_files = false;
        assert_eq!(
            net_set_message(&net, "gaming", NetworkKey::AutoAcceptFiles),
            "auto-accept files from your own devices disabled for 'gaming'"
        );

        net.ephemeral_ttl_secs = Some(7200);
        assert_eq!(
            net_set_message(&net, "gaming", NetworkKey::EphemeralTtl),
            "ephemeral policy on 'gaming' set to 7200s"
        );
        net.ephemeral_ttl_secs = None;
        assert_eq!(
            net_set_message(&net, "gaming", NetworkKey::EphemeralTtl),
            "ephemeral policy on 'gaming' disabled"
        );
    }

    /// None of the live-effect keys may claim a restart is needed: the firewall
    /// ones hot-swap the `ArcSwap` and the network ones are read on next use.
    #[test]
    fn live_keys_never_claim_a_restart_is_needed() {
        let net = config::empty_network_config("gaming");
        for &key in NetworkKey::ALL {
            let msg = net_set_message(&net, "gaming", key);
            assert!(!msg.contains("Restart"), "{key}: {msg}");
        }
    }
}

#[cfg(test)]
mod net_config_authz_tests {
    use super::*;

    /// A global or firewall key reaching the per-network handlers would write a
    /// key into `networks/<name>.toml` that nothing ever reads back, and (for
    /// the firewall keys) skip the live `ArcSwap` swap entirely. `NetConfigSet`
    /// carries a `NetworkKey`, which has no variant for either, so the mistake
    /// is unrepresentable rather than rejected at runtime; the parse that
    /// rejects the name (and names the command that does serve it) is tested in
    /// `ray-proto`.
    #[test]
    fn a_node_key_cannot_be_parsed_as_a_per_network_one() {
        for key in ["mdns", "ssh", "download-dir", "firewall.enabled"] {
            assert!(key.parse::<NetworkKey>().is_err(), "{key}");
        }
        assert_eq!(
            "net.ephemeral-ttl".parse::<NetworkKey>().unwrap(),
            NetworkKey::EphemeralTtl
        );
    }

    #[cfg(unix)]
    #[test]
    fn net_config_set_is_a_mutation_and_net_config_get_is_an_open_read() {
        let unprivileged = PeerIdentity::Unix {
            uid: 1000,
            gid: 1000,
        };
        let root = PeerIdentity::Unix { uid: 0, gid: 0 };
        let set = IpcMessage::NetConfigSet {
            network: "gaming".into(),
            key: NetworkKey::AutoAcceptFiles,
            value: "off".into(),
        };
        // Non-root, non-operator UID: mutations are refused, reads are not.
        assert!(Daemon::check_authorized(&set, Some(&unprivileged)).is_some());
        assert!(Daemon::check_authorized(&set, Some(&root)).is_none());

        let get = IpcMessage::NetConfigGet {
            network: "gaming".into(),
            key: None,
        };
        assert!(Daemon::check_authorized(&get, Some(&unprivileged)).is_none());
    }

    /// The Windows half of the same rule, which has no root to fall back on: an
    /// unelevated client that is not the stored operator gets refused, and each
    /// of the three ways to be authorized is enough on its own.
    #[cfg(windows)]
    #[test]
    fn windows_authorization_accepts_operator_system_and_elevated_admin_only() {
        let peer = |sid: &str, system: bool, admin: bool| PeerIdentity::Windows {
            sid: sid.to_owned(),
            is_local_system: system,
            is_elevated_admin: admin,
        };
        let operator = "S-1-5-21-1-2-3-1001";
        let stranger = peer("S-1-5-21-1-2-3-1002", false, false);

        assert!(!windows_peer_authorized(None, Some(operator)));
        assert!(!windows_peer_authorized(Some(&stranger), Some(operator)));
        // No operator claimed yet: only the elevated bootstrap gets in.
        assert!(!windows_peer_authorized(Some(&stranger), None));

        assert!(windows_peer_authorized(
            Some(&peer(operator, false, false)),
            Some(operator)
        ));
        assert!(windows_peer_authorized(
            Some(&peer("S-1-5-18", true, false)),
            None
        ));
        assert!(windows_peer_authorized(
            Some(&peer("S-1-5-21-1-2-3-500", false, true)),
            None
        ));
    }
}

pub(crate) fn guess_mime_type(filename: &str) -> String {
    mime_guess::from_path(filename)
        .first_or_octet_stream()
        .to_string()
}

pub(crate) fn format_size(bytes: u64) -> String {
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

/// Write `files` as a gzipped tar archive at a new, non-symlink `path`.
/// Each entry is `(name, bytes)`.
///
/// The bundle stays 0600 for its whole life when there is an `owner` to hand it
/// to: it packs the root daemon's `rayfish=debug` logs, status dump, peer ids
/// and mesh IPs, and `IpcMessage::Report` is an open read, so a world-readable
/// copy sitting in `/tmp` is those logs handed to every other local user. It
/// widens to 0644 only when the file is still root-owned and would otherwise be
/// unreadable by the very caller that asked for it.
fn write_bundle(
    path: &Path,
    files: &[(String, Vec<u8>)],
    owner: Option<&ReportRequester>,
) -> std::io::Result<()> {
    let mut file = create_bundle_file(path, owner)?;
    let result = (|| {
        let enc = flate2::write::GzEncoder::new(&mut file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            // `append_data` sets the path and recomputes the checksum.
            builder.append_data(&mut header, name, data.as_slice())?;
        }
        builder.into_inner()?.finish()?;
        file.sync_all()?;
        hand_bundle_to_requester(&file, owner)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// The bundle's file, created exclusively and readable by nobody else yet.
#[cfg(unix)]
fn create_bundle_file(path: &Path, _owner: Option<&ReportRequester>) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// The Windows counterpart. `CREATE_NEW` is what `O_NOFOLLOW` is here: it fails
/// on anything already at the path, a planted reparse point included. The DACL
/// names the requester at creation rather than being widened afterwards, since
/// Windows has no ownership handoff to widen *from*.
#[cfg(windows)]
fn create_bundle_file(path: &Path, owner: Option<&ReportRequester>) -> std::io::Result<File> {
    let ReportRequester::Windows { sid } = match owner {
        Some(owner) => owner,
        // No identified caller, so nobody beyond SYSTEM and Administrators gets
        // to read the daemon's logs.
        None => return crate::windows_security::create_report_file(path, None).map_err(to_io),
    };
    crate::windows_security::create_report_file(path, Some(sid)).map_err(to_io)
}

/// Flatten back to an `io::Error` **keeping the kind**. `create_report_bundle`
/// retries on `AlreadyExists` to survive a name collision, and it can only see
/// one if the kind survives the trip through `anyhow`; `io::Error::other` would
/// make every collision look like a hard failure and end the loop on its first
/// iteration.
#[cfg(windows)]
fn to_io(error: anyhow::Error) -> std::io::Error {
    let kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .map(std::io::Error::kind);
    match kind {
        Some(kind) => std::io::Error::new(kind, format!("{error:#}")),
        None => std::io::Error::other(format!("{error:#}")),
    }
}

/// Open the finished bundle to whoever asked for it.
///
/// Unix only: on Windows the DACL was set when the file was created, because
/// there is no equivalent of "still root-owned, so widen the mode".
#[cfg(unix)]
fn hand_bundle_to_requester(file: &File, owner: Option<&ReportRequester>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let given_to_requester = match owner {
        Some(ReportRequester::Unix { uid, gid }) => {
            let rc = unsafe { libc::fchown(file.as_raw_fd(), *uid, *gid) };
            if rc == 0 {
                true
            } else {
                // Best-effort, as it was before the fd move: a daemon
                // without CAP_CHOWN, or a /tmp on a mount that refuses
                // ownership changes, would otherwise have its finished
                // archive deleted by the cleanup below and report
                // "Operation not permitted" with nothing to attach.
                tracing::warn!(
                    error = %std::io::Error::last_os_error(),
                    "could not hand the report bundle to the requester"
                );
                false
            }
        }
        None => false,
    };
    if !given_to_requester {
        // Still root-owned, so the caller needs the wider mode to read it
        // at all. This is the only path that exposes the bundle.
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(windows)]
fn hand_bundle_to_requester(_file: &File, _owner: Option<&ReportRequester>) -> std::io::Result<()> {
    Ok(())
}

/// Delete `uid`'s earlier bundles in `dir`.
///
/// The old fixed `rayfish-report-{ts}.tgz` was truncated and reused within the
/// same second, which bounded a flood at one file. An unpredictable name closed
/// the symlink hole but took that bound away, and `IpcMessage::Report` is in the
/// open-reads arm of `check_authorized`: without this, any local account can
/// loop `ray report` and have the root daemon leave a fresh gzip of up to seven
/// days of debug logs in `/tmp` every time, forever.
///
/// `/tmp` is world-writable and this runs as root, so the unlink is deliberately
/// narrow: `symlink_metadata` does not follow a planted link, and only a regular
/// file owned by the same uid whose name matches the bundle pattern is removed.
/// A short, stable tag naming the principal a bundle belongs to, so the sweep
/// can pick out this caller's own without reading an owner back off the disk.
#[cfg(unix)]
fn requester_tag(owner: Option<&ReportRequester>) -> String {
    let uid = match owner {
        Some(ReportRequester::Unix { uid, .. }) => *uid,
        None => unsafe { libc::geteuid() },
    };
    format!("u{uid}")
}

/// The Windows counterpart. A hash of the SID rather than the SID itself: the
/// daemon's temp directory is `C:\Windows\Temp`, which any local account may
/// list, and who has run `ray report` is not their business. Truncating to 8
/// bytes is fine for telling a handful of local principals apart; a collision
/// costs one lost bundle, not access to one.
#[cfg(windows)]
fn requester_tag(owner: Option<&ReportRequester>) -> String {
    use sha2::{Digest, Sha256};

    let sid = match owner {
        Some(ReportRequester::Windows { sid }) => sid.as_str(),
        None => "",
    };
    format!("s{}", hex::encode(&Sha256::digest(sid.as_bytes())[..8]))
}

/// A reader holding one open keeps it until they close it.
fn sweep_prior_bundles(dir: &Path, owner: Option<&ReportRequester>) {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    // Only this caller's own bundles, matched by the tag their names carry.
    // The pipe DACL limits `Report` to LocalSystem, Administrators and the
    // operator, but that is still more than one principal, and
    // `create_report_file` grants read to exactly one of them per bundle. An
    // administrator running `ray report` must not unlink the bundle the daemon
    // just handed the operator and that they have not opened yet.
    let prefix = format!("rayfish-report-{}-", requester_tag(owner));
    // On Unix the name is a hint and the uid below is the decision, since `/tmp`
    // lets any account create a file with any name in it.
    #[cfg(unix)]
    let uid = match owner {
        Some(ReportRequester::Unix { uid, .. }) => *uid,
        None => unsafe { libc::geteuid() },
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) || !name.ends_with(".tgz") {
            continue;
        }
        let path = entry.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !md.is_file() {
            continue;
        }
        // `std::fs::Metadata` carries no owner on Windows, so there is no second
        // check to make there: the tag in the name is the whole scoping, which
        // is why it has to be in the name. A bundle someone still has open
        // refuses to be deleted, and the next sweep gets it.
        #[cfg(unix)]
        if md.uid() != uid {
            continue;
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// Create a report under `dir` with an unpredictable, exclusively-created name.
fn create_report_bundle(
    dir: &Path,
    files: &[(String, Vec<u8>)],
    owner: Option<&ReportRequester>,
) -> std::io::Result<PathBuf> {
    // Reclaim the caller's previous bundles first; the new one replaces them.
    sweep_prior_bundles(dir, owner);
    // The tag is what makes the sweep above find this caller's bundles and only
    // this caller's, so it has to go in every name the sweep is meant to match.
    let tag = requester_tag(owner);
    for _ in 0..16 {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce: u64 = rand::random();
        let path = dir.join(format!("rayfish-report-{tag}-{timestamp}-{nonce:016x}.tgz"));
        match write_bundle(&path, files, owner) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique report path",
    ))
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
async fn open_and_send(conn: &Connection, net: Option<EndpointId>, msg: &ControlMsg) -> Result<()> {
    let (mut send, _recv) = conn.open_bi().await.context("open control stream")?;
    control::send_msg(&mut send, net, msg).await
}

/// Reply to a `ray ping` probe by echoing `Pong{nonce}` over a fresh stream
/// (see [`open_and_send`] for why the reply can't ride the request stream back).
/// Connection-level (`net = None`): the ping/pong path isn't tied to a network.
async fn respond_pong(conn: &Connection, nonce: u64) {
    let _ = open_and_send(conn, None, &ControlMsg::Pong { nonce }).await;
}

/// How long to leave a roster member alone after a failed dial before trying it
/// again, so a network carrying genuinely offline devices doesn't pay a dial
/// timeout for each of them on every roster edit.
const ABSENT_DIAL_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Broadcast a `MemberSync` trigger for one network to every peer that shares it,
/// tagged with the network's public key so each receiver routes it correctly.
/// A single mesh connection carries several networks now, so this filters to the
/// network's own peers rather than blasting every connection.
///
/// Members holding no live connection are dialed in the background. "Not
/// connected" stopped meaning "unreachable" once on-demand peers began
/// idle-closing their links: a phone keeps its home relay open and stays dialable
/// the whole time it looks absent here. Without the dial it would learn about a
/// kick or a firewall change only at its next group poll, which is precisely the
/// poll we slow down on battery-powered nodes.
async fn broadcast_member_sync(
    registry: &Arc<NetworkRegistry>,
    net_pubkey: EndpointId,
    network_name: &str,
    exclude_ip: Option<Ipv6Addr>,
) {
    let mut reached: HashSet<EndpointId> = HashSet::new();
    for (id, ip, conn) in registry.peers.peers_for_network_with_conn(network_name) {
        if Some(ip) == exclude_ip {
            continue;
        }
        reached.insert(id);
        if let Err(e) = open_and_send(&conn, Some(net_pubkey), &ControlMsg::MemberSync).await {
            tracing::warn!(peer_ip = %ip, error = %e, "failed to sync members");
        }
    }
    spawn_absent_member_sync(registry, net_pubkey, network_name, exclude_ip, reached);
}

/// The roster members a trigger did not reach over a live connection and that
/// are worth dialing: not us, not the excluded peer, not already reached, and
/// not known-offline. Split out from [`spawn_absent_member_sync`] so the choice
/// of who gets dialed is testable without a live registry.
fn absent_member_ips(
    roster: &[Member],
    my_id: EndpointId,
    exclude_ip: Option<Ipv6Addr>,
    reached: &HashSet<EndpointId>,
    is_offline: impl Fn(&EndpointId) -> bool,
) -> Vec<Ipv6Addr> {
    roster
        .iter()
        .map(|m| (m, derive_ipv6(&m.identity)))
        .filter(|(m, _)| m.identity != my_id && !reached.contains(&m.identity))
        .filter(|(_, v6)| Some(*v6) != exclude_ip)
        .filter(|(m, _)| !is_offline(&m.identity))
        .map(|(_, v6)| v6)
        .collect()
}

/// Dial the roster members [`broadcast_member_sync`] could not reach over an
/// existing connection and deliver the trigger there. Spawned rather than
/// awaited: a coordinator's `ray kick` must not block on dialing every device on
/// the roster, and the trigger is a hint whose only cost when late is a slower
/// reconverge.
fn spawn_absent_member_sync(
    registry: &Arc<NetworkRegistry>,
    net_pubkey: EndpointId,
    network_name: &str,
    exclude_ip: Option<Ipv6Addr>,
    reached: HashSet<EndpointId>,
) {
    let my_id = registry.transport.identity.local_identity();
    let absent: Vec<peers::RouteTarget> = absent_member_ips(
        &registry.roster(network_name),
        my_id,
        exclude_ip,
        &reached,
        // A member whose last dial failed recently is offline for real rather
        // than idle-closed, so leave it to its own poll.
        |id| registry.reachability.is_offline(id, ABSENT_DIAL_COOLDOWN),
    )
    .into_iter()
    .filter_map(|ip| registry.resolve_route(IpAddr::V6(ip)))
    .collect();
    if absent.is_empty() {
        return;
    }
    let registry = registry.clone();
    let network_name = network_name.to_string();
    tokio::spawn(async move {
        tracing::debug!(
            network = %network_name,
            peers = absent.len(),
            "dialing absent members to deliver MemberSync"
        );
        for target in absent {
            if !registry.dial_target(&target).await {
                continue;
            }
            let Some(conn) = registry.peers.conn_for_ip(&target.ipv6) else {
                continue;
            };
            if let Err(e) = open_and_send(&conn, Some(net_pubkey), &ControlMsg::MemberSync).await {
                tracing::debug!(peer_ip = %target.ipv6, error = %e, "failed to sync dialed member");
            }
        }
    });
}

/// Broadcast a network-scoped control message to every peer that shares the
/// network, tagged with its public key. Same per-network filtering as
/// [`broadcast_member_sync`].
async fn broadcast_control_msg(
    peers: &PeerTable,
    net_pubkey: EndpointId,
    network_name: &str,
    msg: &ControlMsg,
) {
    let targets = peers.peers_for_network_with_conn(network_name);
    tracing::debug!(
        network = %network_name,
        peers = targets.len(),
        "broadcasting control message"
    );
    for (_id, ip, conn) in targets {
        if let Err(e) = open_and_send(&conn, Some(net_pubkey), msg).await {
            tracing::warn!(peer_ip = %ip, error = %e, "failed to send control message");
        }
    }
}

#[cfg(test)]
mod report_tests {
    use super::{ReportRequester, collect_recent_logs, requester_tag, sweep_prior_bundles};

    /// Some principal that is not this process, for asserting the sweep leaves
    /// other people's bundles alone.
    #[cfg(unix)]
    fn other_requester() -> ReportRequester {
        ReportRequester::Unix {
            uid: unsafe { libc::geteuid() } ^ 1,
            gid: unsafe { libc::getegid() },
        }
    }

    #[cfg(windows)]
    fn other_requester() -> ReportRequester {
        ReportRequester::Windows {
            sid: "S-1-5-21-0-0-0-4242".to_owned(),
        }
    }

    /// The identity a bundle is written for, so the sweep that reclaims it is
    /// scoped to a caller this process can actually stand in for.
    #[cfg(unix)]
    pub(super) fn current_requester() -> ReportRequester {
        // chowning a file to the uid/gid that already owns it is permitted for
        // an unprivileged owner, so this takes the success branch off root too.
        ReportRequester::Unix {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    #[cfg(windows)]
    pub(super) fn current_requester() -> ReportRequester {
        ReportRequester::Windows {
            sid: crate::windows_identity::current_user_sid()
                .expect("a running process always has a user SID"),
        }
    }

    /// The bound on `/tmp`: `Report` is an open read, so without the sweep any
    /// local account could loop `ray report` and leave a fresh gzip of the
    /// daemon's debug logs behind every time. Writing the bundles here rather
    /// than going through `create_report_bundle` keeps the test on both
    /// platforms: on Windows that path demands LocalSystem or an elevated
    /// Administrator, which a test process is not.
    #[test]
    fn the_sweep_reclaims_the_requesters_earlier_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = |who: &ReportRequester, nonce: &str| {
            dir.path().join(format!(
                "rayfish-report-{}-1-{nonce}.tgz",
                requester_tag(Some(who))
            ))
        };
        let stale = bundle(&current_requester(), "aaaaaaaaaaaaaaaa");
        // Another principal the pipe DACL also admits. On Windows the tag is the
        // only thing keeping this file: both bundles are the test process's own,
        // so no ownership check can tell them apart there.
        let theirs = bundle(&other_requester(), "bbbbbbbbbbbbbbbb");
        let unrelated = dir.path().join("someone-elses.tgz");
        std::fs::write(&stale, b"old bundle").unwrap();
        std::fs::write(&theirs, b"not the caller's").unwrap();
        std::fs::write(&unrelated, b"not ours").unwrap();

        sweep_prior_bundles(dir.path(), Some(&current_requester()));

        assert!(!stale.exists(), "the caller's previous bundle was kept");
        assert!(theirs.exists(), "another principal's bundle was deleted");
        assert!(unrelated.exists(), "an unrelated file was deleted");
    }

    #[test]
    fn test_collect_recent_logs_missing_dir_is_empty() {
        // The log dir may not exist in CI / non-root test runs; must not panic.
        let _ = collect_recent_logs();
    }
}

/// The rest of the bundle's guarantees are POSIX ones: `O_NOFOLLOW` and
/// `O_EXCL` on the create, `fchown` to hand it over, and mode bits to keep it
/// private. Windows reaches the same end through an SDDL DACL on `CreateFileW`
/// (`windows_security::create_report_file`), which only LocalSystem or an
/// elevated Administrator may write, so there is nothing here for a test
/// process on that platform to assert.
#[cfg(all(test, unix))]
mod report_permission_tests {
    use super::report_tests::current_requester;
    use super::{create_report_bundle, write_bundle};

    #[test]
    fn test_write_bundle_is_valid_targz() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tgz");
        let files = vec![
            ("sysinfo.txt".to_string(), b"rayfish 0.1.0\n".to_vec()),
            (
                "logs/rayfish.log.2026-06-23".to_string(),
                b"hello log\n".to_vec(),
            ),
        ];
        write_bundle(&path, &files, None).unwrap();

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
    }

    #[test]
    fn test_write_bundle_refuses_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("bundle.tgz");
        std::fs::write(&target, b"do not overwrite").unwrap();
        symlink(&target, &path).unwrap();

        let result = write_bundle(
            &path,
            &[("status.txt".to_string(), b"sensitive report".to_vec())],
            None,
        );

        assert!(result.is_err(), "a report destination symlink was followed");
        assert_eq!(std::fs::read(&target).unwrap(), b"do not overwrite");
    }

    /// The bundle used to be widened to 0644 even on the path that chowns it to
    /// the requester. `Report` is an open read and the archive packs the root
    /// daemon's debug logs, so that left any other local user free to read them
    /// out of `/tmp`.
    #[test]
    fn a_bundle_handed_to_its_requester_stays_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tgz");
        let files = vec![("status.txt".to_string(), b"peer ids and mesh ips".to_vec())];

        write_bundle(&path, &files, Some(&current_requester())).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "report bundle is readable by other local users"
        );
    }

    /// The fallback: with nobody to give it to the bundle stays root-owned, so
    /// it has to be readable or the caller cannot collect what it asked for.
    #[test]
    fn an_unowned_bundle_is_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tgz");

        write_bundle(&path, &[("status.txt".to_string(), b"x".to_vec())], None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    /// The existing symlink test points at a file that exists, which `O_EXCL`
    /// alone refuses. A dangling link is the case that would let a planted path
    /// be created at the target, and it must be refused too. Neither test can
    /// isolate `O_NOFOLLOW` while the open also carries `O_EXCL`, which fails on
    /// any symlink: the flag is there for a future helper that opens this path
    /// without it.
    #[test]
    fn test_write_bundle_refuses_a_dangling_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("not-there-yet");
        let path = dir.path().join("bundle.tgz");
        symlink(&target, &path).unwrap();

        let result = write_bundle(
            &path,
            &[("status.txt".to_string(), b"sensitive report".to_vec())],
            None,
        );

        assert!(
            result.is_err(),
            "a dangling destination symlink was followed"
        );
        assert!(!target.exists(), "the symlink target was created");
    }

    /// A random name per call closed the symlink hole but removed the only
    /// bound on `/tmp`: nothing ever deleted a bundle again, and `Report` is an
    /// open read, so an unprivileged caller could loop it to fill the disk.
    #[test]
    fn a_new_bundle_reclaims_the_requesters_earlier_ones() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        // Both names carry the caller's own tag, so the sweep treats them as
        // candidates and the symlink below is actually tested rather than
        // filtered out by the name before it gets there.
        let tag = super::requester_tag(Some(&current_requester()));
        let stale = dir
            .path()
            .join(format!("rayfish-report-{tag}-1-aaaaaaaaaaaaaaaa.tgz"));
        let unrelated = dir.path().join("someone-elses.tgz");
        let victim = dir.path().join("victim");
        let planted = dir
            .path()
            .join(format!("rayfish-report-{tag}-2-bbbbbbbbbbbbbbbb.tgz"));
        std::fs::write(&stale, b"old bundle").unwrap();
        std::fs::write(&unrelated, b"not ours").unwrap();
        std::fs::write(&victim, b"do not delete").unwrap();
        // A symlink wearing the bundle name: /tmp is world-writable and this
        // runs as root, so the sweep must not follow it.
        symlink(&victim, &planted).unwrap();

        let fresh = create_report_bundle(
            dir.path(),
            &[("status.txt".to_string(), b"report".to_vec())],
            Some(&current_requester()),
        )
        .unwrap();

        assert!(!stale.exists(), "the caller's previous bundle was kept");
        assert!(fresh.exists(), "the new bundle is missing");
        assert!(unrelated.exists(), "an unrelated file was deleted");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"do not delete",
            "the sweep followed a planted symlink"
        );
    }
}

#[cfg(test)]
mod absent_member_tests {
    use super::*;
    use iroh::SecretKey;

    fn id(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        SecretKey::from(b).public()
    }

    fn member(seed: u8) -> Member {
        Member {
            identity: id(seed),
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
        }
    }

    /// The whole point of the dial fallback: a member that holds no live
    /// connection is a dial candidate, because on-demand peers idle-close their
    /// links while staying reachable.
    #[test]
    fn unconnected_member_is_a_dial_candidate() {
        let roster = vec![member(1), member(2)];
        let reached: HashSet<EndpointId> = [id(1)].into_iter().collect();
        let got = absent_member_ips(&roster, id(9), None, &reached, |_| false);
        assert_eq!(got, vec![derive_ipv6(&id(2))]);
    }

    /// Self, the excluded peer, and anyone already reached over a live
    /// connection must never be dialed: the first is nonsense, the second is
    /// the peer the caller deliberately skipped, the third already got it.
    #[test]
    fn self_excluded_and_reached_are_skipped() {
        let roster = vec![member(1), member(2), member(3), member(4)];
        let reached: HashSet<EndpointId> = [id(3)].into_iter().collect();
        let got = absent_member_ips(&roster, id(1), Some(derive_ipv6(&id(2))), &reached, |_| {
            false
        });
        assert_eq!(got, vec![derive_ipv6(&id(4))]);
    }

    /// A member whose last dial failed recently is offline for real, not
    /// idle-closed. Re-dialing it on every roster edit would cost a timeout per
    /// edit and teach us nothing.
    #[test]
    fn known_offline_member_is_not_redialed() {
        let roster = vec![member(1), member(2)];
        let offline = id(1);
        let got = absent_member_ips(&roster, id(9), None, &HashSet::new(), |i| *i == offline);
        assert_eq!(got, vec![derive_ipv6(&id(2))]);
    }
}

#[cfg(test)]
mod accept_handler_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    // Build a minimal NetworkState for use in test AcceptHandler construction.
    fn make_network_state() -> SharedNetworkState {
        let net_secret = SecretKey::from_bytes(&[1u8; 32]);
        let net_pub = net_secret.public();
        Arc::new(RwLock::new(NetworkState {
            members: MemberList::new(),
            approved: ApprovedList::new(),
            snapshot: None,
            snapshot_commit: Arc::new(AsyncMutex::new(())),
            converged_hash: None,
            unconfirmed_durable_hash: None,
            network_secret_key: None,
            network_public_key: net_pub,
            network_name: Some("test-net".to_string()),
            group_name: Some("test-net".to_string()),
            mode: GroupMode::Restricted,
            suggested_firewall: SuggestedFirewall::default(),
            reusable_keys: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
            last_record_timestamp: None,
        }))
    }

    #[test]
    fn local_network_alias_never_rewrites_the_signed_group_name() {
        let state = make_network_state();
        let bytes = {
            let mut state = state.write().unwrap();
            state.network_name = Some("my-local-alias".to_string());
            state.group_name = Some("signed-network-name".to_string());
            state.refresh_snapshot();
            state.snapshot.as_ref().unwrap().msgpack_bytes.clone()
        };

        let blob = crate::membership::decode_group_blob(&bytes).unwrap();
        assert_eq!(blob.name.as_deref(), Some("signed-network-name"));
    }

    /// Convergence is tracked as the hash we accepted, not the hash of our own
    /// re-encoding, and the two differ whenever the publisher writes bytes we
    /// would not.
    ///
    /// The case that produces it is an upgrade: rmp-serde reads a struct from a
    /// map as well as an array, so a node on this build converges fine from a
    /// coordinator still writing the old named blob, and then re-encodes it
    /// compactly. Comparing the record against the snapshot hash there says "a
    /// different blob" on every poll forever, which refetches, reapplies, and
    /// skips the converged branch's steady-state work (self-nullify check,
    /// pending rename, exit-offer sync) for as long as the skew lasts.
    #[test]
    fn convergence_is_tracked_as_the_hash_we_accepted() {
        let state = make_network_state();
        let mut s = state.write().unwrap();
        let member_id = SecretKey::from_bytes(&[9u8; 32]).public();
        s.members = MemberList::from_members(vec![seated(member_id)]);
        s.refresh_snapshot();

        // The mismatch this exists for needs no version skew: `network_name` is
        // hashed into the blob and is a *local* string, so a member that joined
        // with `ray join <code> --name <alias>` re-encodes a name the coordinator
        // never published and can never match its record.
        let published = canonical_group_bytes(
            &s.members,
            &s.approved,
            &s.suggested_firewall,
            Some("what the coordinator published"),
            &s.reusable_keys,
            &s.nullifiers,
        );
        assert_ne!(
            blake3::hash(&published),
            s.snapshot.as_ref().unwrap().hash,
            "a local alias alone puts our re-encoding out of step with the record"
        );

        // Our own encoding is what we are converged on, so a coordinator (which
        // publishes exactly these bytes) sees the two agree.
        let ours = s.snapshot.as_ref().unwrap().hash;
        assert_eq!(s.converged_hash, Some(ours));

        // Applying a record whose bytes we cannot reproduce: the snapshot stays
        // what we would publish, and convergence follows the record.
        let published = blake3::hash(b"the publisher's bytes, not ours");
        s.converged_hash = Some(published);
        assert_eq!(
            s.snapshot.as_ref().unwrap().hash,
            ours,
            "the snapshot is still our own encoding, which is what we would publish"
        );

        // The decision every caller actually makes. This is the assertion that
        // fails if `needs_reconverge` reads the snapshot: polling the record we
        // just applied has to read as converged, or the poller refetches and
        // reapplies the whole roster on every tick for as long as the two
        // encodings differ.
        assert!(
            !s.needs_reconverge(published),
            "the record we applied is not a change"
        );
        assert!(
            s.needs_reconverge(blake3::hash(b"a genuinely newer blob")),
            "a record we have not applied still is one"
        );
    }

    /// The live state and context behind a handler, whichever role it is. Lets a
    /// test seat members and device bindings on a handler it just built.
    fn handler_parts(h: &AcceptHandler) -> (&SharedNetworkState, &MeshCtx) {
        match h {
            AcceptHandler::Coordinator(s) => (&s.state, &s.ctx),
            AcceptHandler::Member(s) => (&s.state, &s.ctx),
        }
    }

    fn seated(id: EndpointId) -> Member {
        Member {
            identity: id,
            is_coordinator: false,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
        }
    }

    /// The demux wall: a peer on the roster may speak for this network.
    #[tokio::test]
    async fn knows_sender_accepts_a_seated_member() {
        let h = sample_coordinator_handler().await;
        let (state, _) = handler_parts(&h);
        let member = SecretKey::from_bytes(&[9u8; 32]).public();
        state.write().unwrap().members.add(seated(member));
        assert!(h.knows_sender(member));
    }

    /// A peer approved but not yet seated is still accounted for: it is mid-join
    /// and its `MeshHello` is what completes the admission.
    #[tokio::test]
    async fn knows_sender_accepts_an_approved_peer() {
        let h = sample_coordinator_handler().await;
        let (state, _) = handler_parts(&h);
        let peer = SecretKey::from_bytes(&[10u8; 32]).public();
        {
            let mut s = state.write().unwrap();
            s.approved.approve(ApprovedEntry {
                identity: peer,
                hostname: None,
                user_identity: None,
                device_cert: None,
                roles: Default::default(),
            });
        }
        assert!(h.knows_sender(peer));
    }

    /// The branch the doc comment calls out: a paired peer can be on the roster
    /// under its *user* identity while its frames arrive under a device key, so
    /// the lookup has to try the resolved identity too.
    #[tokio::test]
    async fn knows_sender_resolves_a_device_to_its_roster_user() {
        let h = sample_coordinator_handler().await;
        let (state, ctx) = handler_parts(&h);
        let user = SecretKey::from_bytes(&[11u8; 32]).public();
        let device = SecretKey::from_bytes(&[12u8; 32]).public();
        state.write().unwrap().members.add(seated(user));
        // Unmapped, the device key is a stranger.
        assert!(!h.knows_sender(device));
        ctx.device_user_map.insert(device, user);
        assert!(h.knows_sender(device));
    }

    /// The case the wall exists for: knowing the room id is not being in the room.
    #[tokio::test]
    async fn knows_sender_refuses_a_stranger() {
        let h = sample_coordinator_handler().await;
        let (state, _) = handler_parts(&h);
        let member = SecretKey::from_bytes(&[13u8; 32]).public();
        state.write().unwrap().members.add(seated(member));
        let stranger = SecretKey::from_bytes(&[14u8; 32]).public();
        assert!(!h.knows_sender(stranger));
    }

    /// Throwaway [`MeshCtx`] for accept-handler tests: a fresh blob store and
    /// dummy handles, none of which the constructed handlers exercise here.
    fn sample_mesh_ctx(
        identity: IrohIdentityProvider,
        blob_store: FsStore,
        registry: Arc<NetworkRegistry>,
    ) -> MeshCtx {
        let (tun_tx, _) = tokio::sync::mpsc::channel(1);
        let (disconnect_tx, _) = tokio::sync::mpsc::channel(1);
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
            route_map: peers::RosterRouteMap::new(),
            disconnect_tx,
            registry,
        }
    }

    async fn sample_coordinator_handler() -> AcceptHandler {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = FsStore::load(tmp.path()).await.unwrap();
        let my_key = SecretKey::from_bytes(&[2u8; 32]);
        let my_id = my_key.public();
        let registry = sample_registry(
            sample_test_endpoint().await,
            IrohIdentityProvider::new(my_id),
            blob_store.clone(),
            my_id,
        );
        AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
            ctx: sample_mesh_ctx(IrohIdentityProvider::new(my_id), blob_store, registry),
            network_name: "test-net".to_string(),
            state: make_network_state(),
            dht_notify: None,
            invite_lock: Arc::new(AsyncMutex::new(())),
        }))
    }

    /// Throwaway [`NetworkRegistry`] for accept-handler tests: empty networks map
    /// and dummy foundation handles, none of which the constructed handlers touch.
    fn sample_registry(
        endpoint: Endpoint,
        identity: IrohIdentityProvider,
        blob_store: FsStore,
        contact: EndpointId,
    ) -> Arc<NetworkRegistry> {
        let transport = Arc::new(Transport::new(
            endpoint,
            identity,
            blob_store,
            Arc::new(ForwardMetrics::default()),
            contact,
            Arc::new(LanPeers::new()),
        ));
        let hostname_table = dns::new_hostname_table();
        let reverse_table = dns::new_reverse_table();
        let dns_resolver = Arc::new(crate::dns::resolver::Resolver::new(
            hostname_table.clone(),
            reverse_table.clone(),
        ));
        let dns = Arc::new(DnsService::new(
            hostname_table,
            reverse_table,
            dns_resolver,
            // No OS-DNS configuration runs in these tests, so the address the
            // macOS backend would publish is never read.
            std::net::Ipv6Addr::UNSPECIFIED,
        ));
        let (disconnect_tx, _disconnect_rx) = mpsc::channel::<forward::DisconnectEvent>(1);
        let (placeholder_tx, _placeholder_rx) = mpsc::channel::<Bytes>(1);
        Arc::new(NetworkRegistry::new(
            Arc::new(DashMap::new()),
            transport,
            PeerTable::new(),
            Arc::new(ConnectionManager::new()),
            dns,
            Arc::new(ArcSwap::from_pointee(String::from("test"))),
            None,
            CancellationToken::new(),
            SharedFirewall::new(firewall::FirewallConfig::default()),
            peers::DeviceUserMap::new(),
            Arc::new(arc_swap::ArcSwap::from_pointee(placeholder_tx)),
            Arc::new(DashSet::new()),
            disconnect_tx,
            false,
            Duration::from_secs(config::DEFAULT_IDLE_TIMEOUT_SECS),
        ))
    }

    async fn sample_member_handler() -> AcceptHandler {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = FsStore::load(tmp.path()).await.unwrap();
        let my_key = SecretKey::from_bytes(&[3u8; 32]);
        let my_id = my_key.public();
        let endpoint = sample_test_endpoint().await;
        let registry = sample_registry(
            endpoint.clone(),
            IrohIdentityProvider::new(my_id),
            blob_store.clone(),
            my_id,
        );
        AcceptHandler::Member(Arc::new(MemberAcceptState {
            ctx: sample_mesh_ctx(
                IrohIdentityProvider::new(my_id),
                blob_store.clone(),
                registry.clone(),
            ),
            network_name: "test-net".to_string(),
            state: make_network_state(),
            net_pubkey: SecretKey::from_bytes(&[1u8; 32]).public(),
            my_identity: my_id,
            endpoint,
            registry,
            invite_lock: Arc::new(AsyncMutex::new(())),
            reconverge_notify: Arc::new(tokio::sync::Notify::new()),
        }))
    }

    /// A throwaway bound endpoint for constructing a `MemberAcceptState` in tests
    /// (the handler is only inspected for its variant, never driven).
    async fn sample_test_endpoint() -> Endpoint {
        Endpoint::bind(iroh::endpoint::presets::N0).await.unwrap()
    }

    #[tokio::test]
    async fn register_replaces_member_handler_with_coordinator() {
        // AcceptHandler exposes whether it is the coordinator variant.
        assert!(!sample_member_handler().await.is_coordinator());
        assert!(sample_coordinator_handler().await.is_coordinator());
    }

    #[tokio::test]
    async fn exit_offer_is_recorded_by_every_handler_role() {
        // `ExitNodeOffer` must be handled identically by both accept-handler
        // roles: it once reached only the Member dispatch, so a plain
        // coordinator (the one node that can record the offer on the signed
        // roster) silently discarded it and no exit node was ever advertised.
        use crate::membership::{ExitFamilies, Member};
        for handler in [
            sample_coordinator_handler().await,
            sample_member_handler().await,
        ] {
            let (registry, state) = match &handler {
                AcceptHandler::Coordinator(s) => (s.ctx.registry.clone(), s.state.clone()),
                AcceptHandler::Member(s) => (s.ctx.registry.clone(), s.state.clone()),
            };
            // Hold the network key (recording needs it) and list the sender.
            let sender = SecretKey::from_bytes(&[9u8; 32]).public();
            {
                let mut s = state.write().unwrap();
                s.network_secret_key = Some(SecretKey::from_bytes(&[1u8; 32]));
                s.members.add(Member {
                    identity: sender,
                    is_coordinator: false,
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                    last_seen: None,
                    exit_node: false,
                    exit_families: ExitFamilies::Unknown,
                    roles: Default::default(),
                });
            }
            registry.networks.insert(
                "test-net".to_string(),
                NetworkHandle {
                    name: "test-net".to_string(),
                    network_key: state.read().unwrap().network_public_key,
                    role: NetworkRole::Coordinator,
                    state: state.clone(),
                    dht_notify: None,
                    cancel: CancellationToken::new(),
                    tasks: Vec::new(),
                    invite_lock: Arc::new(AsyncMutex::new(())),
                    incompatible: None,
                },
            );
            assert!(
                handler.handle_common(
                    sender,
                    &ControlMsg::ExitNodeOffer {
                        enabled: true,
                        exit_families: ExitFamilies::Dual,
                    },
                ),
                "ExitNodeOffer must be consumed by the role-independent dispatch"
            );
            // The recording runs off the demux loop; wait for it to land.
            let mut recorded = false;
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                // Both halves of the offer: the IPv6 claim rides the same message
                // and has to reach the signed roster with it, or an IPv6-only
                // client sees a gateway it will refuse to select.
                let done = state
                    .read()
                    .unwrap()
                    .members
                    .get(&sender)
                    .is_some_and(|m| m.exit_node && m.exit_families.carries_v6());
                if done {
                    recorded = true;
                    break;
                }
            }
            assert!(
                recorded,
                "exit offer not recorded (coordinator variant: {})",
                handler.is_coordinator()
            );
        }
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exit_offer_over_the_wire_reaches_the_coordinator_roster() {
        // End-to-end replication of the original bug: a member opens a real mesh
        // connection to a coordinator and sends `ExitNodeOffer` over it. The frame
        // has to travel through the connection demux into the coordinator's
        // recording path and flip the member's roster `exit_node` flag. Before the
        // fix the coordinator's accept handler dropped the frame on its catch-all,
        // so nothing was recorded and no exit node was ever advertised.
        use crate::membership::{ExitFamilies, Member};
        use iroh::endpoint::presets;
        use iroh::{Endpoint, RelayMode, SecretKey};

        let alpn = transport::mesh_alpn();

        // Coordinator (accepts) and member (dials), on loopback with relay
        // disabled for a deterministic direct connection.
        let coord_key = SecretKey::from_bytes(&[7u8; 32]);
        let coord_id = coord_key.public();
        let coord_ep = Endpoint::builder(presets::N0)
            .secret_key(coord_key)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let member_ep = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::from_bytes(&[8u8; 32]))
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let member_id = member_ep.id();

        // Coordinator registry holding the network key, member already in roster.
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = FsStore::load(tmp.path()).await.unwrap();
        let registry = sample_registry(
            coord_ep.clone(),
            IrohIdentityProvider::new(coord_id),
            blob_store.clone(),
            coord_id,
        );
        let state = make_network_state();
        let net_pubkey = state.read().unwrap().network_public_key;
        {
            let mut s = state.write().unwrap();
            s.network_secret_key = Some(SecretKey::from_bytes(&[1u8; 32]));
            s.members.add(Member {
                identity: member_id,
                is_coordinator: false,
                hostname: None,
                user_identity: None,
                device_cert: None,
                last_seen: None,
                exit_node: false,
                exit_families: ExitFamilies::Unknown,
                roles: Default::default(),
            });
        }
        registry.networks.insert(
            "test-net".to_string(),
            NetworkHandle {
                name: "test-net".to_string(),
                network_key: net_pubkey,
                role: NetworkRole::Coordinator,
                state: state.clone(),
                dht_notify: None,
                cancel: CancellationToken::new(),
                tasks: Vec::new(),
                invite_lock: Arc::new(AsyncMutex::new(())),
                incompatible: None,
            },
        );

        // Connection manager wired with the coordinator accept handler + dispatch,
        // both pointing at the same registry the frame must mutate.
        let connmgr = Arc::new(ConnectionManager::new());
        connmgr.set_mesh_dispatch(MeshDispatch {
            ctx: sample_mesh_ctx(
                IrohIdentityProvider::new(coord_id),
                blob_store.clone(),
                registry.clone(),
            ),
            token: CancellationToken::new(),
            on_peer_connected: Arc::new(|_| {}),
        });
        connmgr.register(
            net_pubkey,
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                ctx: sample_mesh_ctx(
                    IrohIdentityProvider::new(coord_id),
                    blob_store.clone(),
                    registry.clone(),
                ),
                network_name: "test-net".to_string(),
                state: state.clone(),
                dht_notify: None,
                invite_lock: Arc::new(AsyncMutex::new(())),
            })),
        );

        // Coordinator accepts and drives the demux; member dials.
        let coord_addr = coord_ep.addr();
        let accept = {
            let coord_ep = coord_ep.clone();
            let cm = connmgr.clone();
            tokio::spawn(async move {
                let conn = coord_ep
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("accept connection");
                cm.drive_mesh_connection(conn, false).await;
            })
        };
        let conn = member_ep
            .connect(coord_addr, &alpn)
            .await
            .expect("member dials coordinator");

        // Member advertises its exit-node offer over the wire.
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        control::send_msg(
            &mut send,
            Some(net_pubkey),
            &ControlMsg::ExitNodeOffer {
                enabled: true,
                exit_families: ExitFamilies::V4,
            },
        )
        .await
        .unwrap();

        // The coordinator's roster must reflect the offer.
        let mut recorded = false;
        for _ in 0..300 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if state
                .read()
                .unwrap()
                .members
                .get(&member_id)
                .is_some_and(|m| m.exit_node)
            {
                recorded = true;
                break;
            }
        }
        accept.abort();
        assert!(
            recorded,
            "coordinator did not record the member's exit-node offer received over the wire"
        );
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sync_exit_offers_delivers_over_the_retained_connection() {
        // Full replication of the live failure: an offering member runs the real
        // `sync_exit_offers` and the coordinator's roster must end up flagged.
        // The member delivers over its retained mesh connection (the one the
        // ConnectionManager owns); the earlier bug dialed a throwaway connection
        // and dropped it, so the frame never flushed and the coordinator's
        // roster never changed even though the sender logged "delivered".
        use crate::membership::{ExitFamilies, Member, derive_ipv6};
        use iroh::endpoint::presets;
        use iroh::{Endpoint, RelayMode, SecretKey};

        let alpn = transport::mesh_alpn();
        let net_secret = SecretKey::from_bytes(&[1u8; 32]);
        let net_pubkey = net_secret.public();

        let coord_key = SecretKey::from_bytes(&[7u8; 32]);
        let coord_id = coord_key.public();
        let coord_ep = Endpoint::builder(presets::N0)
            .secret_key(coord_key)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let member_key = SecretKey::from_bytes(&[8u8; 32]);
        let member_id = member_key.public();
        let member_ep = Endpoint::builder(presets::N0)
            .secret_key(member_key)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();

        // A roster both sides share: the coordinator (key holder) and the member.
        let roster = || {
            vec![
                Member {
                    identity: coord_id,
                    is_coordinator: true,
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                    last_seen: None,
                    exit_node: false,
                    exit_families: ExitFamilies::Unknown,
                    roles: Default::default(),
                },
                Member {
                    identity: member_id,
                    is_coordinator: false,
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                    last_seen: None,
                    exit_node: false,
                    exit_families: ExitFamilies::Unknown,
                    roles: Default::default(),
                },
            ]
        };

        // --- Coordinator side: holds the key, drives the demux. ---
        let coord_tmp = tempfile::tempdir().unwrap();
        let coord_blobs = FsStore::load(coord_tmp.path()).await.unwrap();
        let coord_reg = sample_registry(
            coord_ep.clone(),
            IrohIdentityProvider::new(coord_id),
            coord_blobs.clone(),
            coord_id,
        );
        let coord_state = make_network_state();
        {
            let mut s = coord_state.write().unwrap();
            s.network_secret_key = Some(net_secret.clone());
            s.members = MemberList::from_members(roster());
        }
        coord_reg.networks.insert(
            "test-net".to_string(),
            NetworkHandle {
                name: "test-net".to_string(),
                network_key: net_pubkey,
                role: NetworkRole::Coordinator,
                state: coord_state.clone(),
                dht_notify: None,
                cancel: CancellationToken::new(),
                tasks: Vec::new(),
                invite_lock: Arc::new(AsyncMutex::new(())),
                incompatible: None,
            },
        );
        let connmgr = Arc::new(ConnectionManager::new());
        connmgr.set_mesh_dispatch(MeshDispatch {
            ctx: sample_mesh_ctx(
                IrohIdentityProvider::new(coord_id),
                coord_blobs.clone(),
                coord_reg.clone(),
            ),
            token: CancellationToken::new(),
            on_peer_connected: Arc::new(|_| {}),
        });
        connmgr.register(
            net_pubkey,
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                ctx: sample_mesh_ctx(
                    IrohIdentityProvider::new(coord_id),
                    coord_blobs.clone(),
                    coord_reg.clone(),
                ),
                network_name: "test-net".to_string(),
                state: coord_state.clone(),
                dht_notify: None,
                invite_lock: Arc::new(AsyncMutex::new(())),
            })),
        );
        let accept = {
            let coord_ep = coord_ep.clone();
            let cm = connmgr.clone();
            tokio::spawn(async move {
                let conn = coord_ep
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("accept connection");
                cm.drive_mesh_connection(conn, false).await;
            })
        };

        // --- Member side: offers an exit, holds a retained connection to coord. ---
        let member_tmp = tempfile::tempdir().unwrap();
        let member_blobs = FsStore::load(member_tmp.path()).await.unwrap();
        let member_reg = sample_registry(
            member_ep.clone(),
            IrohIdentityProvider::new(member_id),
            member_blobs.clone(),
            member_id,
        );
        let member_state = make_network_state();
        {
            let mut s = member_state.write().unwrap();
            s.network_secret_key = None; // plain member
            s.members = MemberList::from_members(roster());
        }
        member_reg.networks.insert(
            "test-net".to_string(),
            NetworkHandle {
                name: "test-net".to_string(),
                network_key: net_pubkey,
                role: NetworkRole::Member,
                state: member_state.clone(),
                dht_notify: None,
                cancel: CancellationToken::new(),
                tasks: Vec::new(),
                invite_lock: Arc::new(AsyncMutex::new(())),
                incompatible: None,
            },
        );
        // Offering an exit, and the data plane is up so sync is enabled.
        member_reg
            .exit_server
            .reload([("test-net", ["*".to_string()].as_slice())]);
        member_reg
            .exit_sync_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // The member dials the coordinator and retains the connection in its
        // PeerTable, exactly like the live daemon keeps its coordinator link.
        let member_conn = member_ep
            .connect(coord_ep.addr(), &alpn)
            .await
            .expect("member dials coordinator");
        member_reg.peers.add(
            derive_ipv6(&coord_id),
            member_conn.clone(),
            coord_id,
            "test-net",
        );

        // Run the real reconcile: it must deliver the offer over the retained link.
        member_reg.sync_exit_offers().await;

        let mut recorded = false;
        for _ in 0..300 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if coord_state
                .read()
                .unwrap()
                .members
                .get(&member_id)
                .is_some_and(|m| m.exit_node)
            {
                recorded = true;
                break;
            }
        }
        accept.abort();
        assert!(
            recorded,
            "sync_exit_offers did not get the offer recorded on the coordinator over the retained connection"
        );
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
    use crate::membership::{ExitFamilies, Member};

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
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
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
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
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
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
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
            is_coordinator: coord,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
            roles: Default::default(),
        };
        // Only members are us (coordinator) and a plain member: nobody to gossip to.
        let members = vec![mk(me, true), mk(test_id(2), false)];
        assert!(super::gossip_targets(&members, me).is_empty());
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

        let daemon =
            tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
                .await
                .expect("build_headless should not hang")
                .expect("build_headless should succeed");

        // It returns a shared `Arc<DaemonState>`.
        assert!(Arc::strong_count(&daemon) >= 1);

        // The embedding `status()` API answers without a socket ever being bound.
        assert!(matches!(daemon.status(), IpcMessage::StatusResponse { .. }));
    }

    /// `net_config_apply` gates on the network's presence ON DISK, not in the
    /// live network map: the old `NetworkRegistry::contains` check it replaced
    /// gated on the live map instead, so a saved-but-inactive network used to
    /// error here. That drift was reviewed and kept deliberately (the daemon
    /// connects every saved network at startup, so "on disk" and "live" agree
    /// in practice); this test pins the disk-presence semantics so any future
    /// change to that gate is a deliberate decision, not an accident.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn net_config_apply_gates_on_the_network_existing_on_disk() {
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

        let daemon =
            tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
                .await
                .expect("build_headless should not hang")
                .expect("build_headless should succeed");

        // No network saved yet: not-found, matching the old live-map check.
        let msg = daemon
            .net_config_apply("gaming", NetworkKey::AutoAcceptFiles, "off")
            .await;
        assert!(
            matches!(&msg, IpcMessage::Error { message } if message.contains("not found")),
            "{msg:?}"
        );

        // Save the network to disk without registering it in the live map
        // (nothing here calls `create_network`/`join_network`), i.e. exactly
        // the "saved but inactive" case the review flagged.
        config::save_network(&config::empty_network_config("gaming")).unwrap();

        let msg = daemon
            .net_config_apply("gaming", NetworkKey::AutoAcceptFiles, "off")
            .await;
        assert!(matches!(msg, IpcMessage::Ok { .. }), "{msg:?}");

        let msg = daemon
            .net_config_apply("gaming", NetworkKey::EphemeralTtl, "3599")
            .await;
        assert!(
            matches!(&msg, IpcMessage::Error { message }
                if message == "ttl must be at least 3600 seconds (1 hour)"),
            "validation errors must not be mislabeled as save failures: {msg:?}"
        );
    }

    /// A stopped node must be rebuildable in the same process, which is the
    /// mobile disable/enable cycle (`Node::stop` then `Node::start`, both in one
    /// app process).
    ///
    /// What makes this sharp: two `FsStore`s over the same directory do not
    /// error, they *block*. redb waits for the lock on `blobs/blobs.db` rather
    /// than returning `DatabaseAlreadyOpen`, so a rebuild that overlaps a store
    /// the previous daemon has not released yet never returns at all, and on
    /// Android that wedges the thread `Node::start` was called on for the life of
    /// the process. Before `shutdown_and_close` shut the protocol router down,
    /// nothing in it released the store: the release happened later, if at all,
    /// when the router's accept task noticed the closed endpoint and dropped its
    /// handlers. This asserts the router is shut down before the call returns
    /// (which is what drives `BlobsProtocol::shutdown` -> `Store::shutdown`) and
    /// then reopens the store immediately, with the daemon `Arc` still held.
    ///
    /// See `build_headless_returns_usable_state_without_ipc_socket`: `ENV_LOCK`
    /// only serializes tests and guards no data across the awaits.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_and_close_releases_the_blob_store_for_a_rebuild() {
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // One config dir throughout: sharing `blobs/blobs.db` is the whole point,
        // so a per-build tempdir would pass even with the bug.
        let tmp = tempfile::tempdir().unwrap();
        let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

        let first = tokio::time::timeout(Duration::from_secs(30), build_headless(false))
            .await
            .expect("first build_headless should not hang")
            .expect("first build_headless should succeed");
        tokio::time::timeout(Duration::from_secs(30), first.shutdown_and_close())
            .await
            .expect("shutdown_and_close should not hang");
        assert!(
            first.router.is_shutdown(),
            "shutdown_and_close must shut the protocol router down, which is what \
             releases the blob store, rather than leaving it to the accept task"
        );

        // Still holding `first`, and reopening on the very next line. Waiting for
        // the last `Arc` to drop is not something a caller can arrange
        // (background tasks hold their own clones and wind down on their own
        // schedule), so releasing the store has to be something the call itself
        // guarantees before it returns.
        let blobs_dir = config::config_dir().unwrap().join("blobs");
        let reopened = tokio::time::timeout(
            Duration::from_secs(10),
            iroh_blobs::store::fs::FsStore::load(&blobs_dir),
        )
        .await
        .expect("the blob store is still locked after shutdown_and_close")
        .expect("reopening the blob store should succeed");
        let _ = reopened.shutdown().await;

        // And the whole rebuild works, which is what the app actually does.
        tokio::time::timeout(Duration::from_secs(30), build_headless(false))
            .await
            .expect("rebuild should not hang")
            .expect("rebuilding after shutdown_and_close should succeed");
    }

    // See `build_headless_returns_usable_state_without_ipc_socket`: `ENV_LOCK`
    // only serializes tests and guards no data across the awaits.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lan_peers_reach_status_and_the_scan_reply() {
        let _env_lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _env_guard = EnvVarGuard::set("RAYFISH_CONFIG_DIR", tmp.path());

        let daemon =
            tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
                .await
                .expect("build_headless should not hang")
                .expect("build_headless should succeed");

        // Nothing seen yet: the scan reply is empty and status counts nothing.
        match daemon.list_lan_peers() {
            IpcMessage::LanPeersList { peers, .. } => assert!(peers.is_empty()),
            other => panic!("expected LanPeersList, got {other:?}"),
        }

        // Feed the map the way the mDNS browse loop does.
        let peer = SecretKey::from_bytes(&[42u8; 32]).public();
        let addr = SocketAddr::from(([192, 168, 1, 24], 41641));
        daemon.transport.lan_peers.discovered(peer, vec![addr]);

        match daemon.list_lan_peers() {
            IpcMessage::LanPeersList {
                peers,
                mdns_enabled: _,
            } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].endpoint_id, peer);
                assert_eq!(peers[0].addrs, vec![addr.to_string()]);
                // We share no network with this sighting, so it is connectable.
                assert_eq!(peers[0].shared_network, None);
            }
            other => panic!("expected LanPeersList, got {other:?}"),
        }

        // The same sighting is listed in `ray status`, with its addresses.
        match daemon.status() {
            IpcMessage::StatusResponse { lan_peers, .. } => {
                assert_eq!(lan_peers.len(), 1);
                assert_eq!(lan_peers[0].endpoint_id, peer);
                assert_eq!(lan_peers[0].addrs, vec![addr.to_string()]);
            }
            other => panic!("expected StatusResponse, got {other:?}"),
        }

        // An expiry clears it from both.
        daemon.transport.lan_peers.expired(&peer);
        match daemon.status() {
            IpcMessage::StatusResponse { lan_peers, .. } => assert!(lan_peers.is_empty()),
            other => panic!("expected StatusResponse, got {other:?}"),
        }
    }

    /// In-memory TUN writer that records every written packet into a shared
    /// buffer, so a test can observe which writer the data plane routed to.
    #[derive(Clone, Default)]
    struct FakeTunWriter {
        written: Arc<Mutex<Vec<Vec<u8>>>>,
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
    async fn wait_for_len(sink: &Arc<Mutex<Vec<Vec<u8>>>>, want: usize) -> bool {
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

        let daemon =
            tokio::time::timeout(std::time::Duration::from_secs(30), build_headless(false))
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
