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
    NetworkRole, NetworkStatus, NodeStatus, PeerState, PeerStatus, ipc_err,
};
use crate::membership::{
    ApprovedEntry, ApprovedList, ExitFamilies, GroupBlob, GroupMode, IrohIdentityProvider, Member,
    MemberList, canonical_group_bytes, derive_ipv6, group_blob_hash, verify_group_blob,
};
use crate::network_name;
use crate::peers::{self, PeerTable};
use crate::stats::ForwardMetrics;
use crate::transport;
// The desktop TUN device and its CGNAT pre-flight check don't exist on Android
// or iOS, where the platform supplies the packet interface.
#[cfg(not(embedded_tun))]
use crate::tun;
use crate::tun::{TunRead, TunWrite};
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
mod windows_authorization_tests;

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
mod ipc_dispatch;
mod mesh;
mod op;
pub use op::*;
mod report;
use report::*;

// The mesh core's join handshake and background-task/reconvergence helpers were
// moved into `mesh/{join,background}.rs`; re-export them at the daemon level so
// `mod.rs` and the other `mesh/` submodules (via `use super::super::*`) call them
// by bare name, as before the split.
pub(crate) use mesh::*;
// `run_daemon` (the `ray daemon` entry point) stays public for the binary.
pub use mesh::run_daemon;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub use mesh::run_rootless;
// `build_headless` is the embedder (mobile) construction entry point.
pub use mesh::build_headless;
#[cfg(unix)]
pub use mesh::start_embedded_ipc;
#[cfg(unix)]
pub use mesh::{CleanupOutcome, cleanup_after_exit};

/// Undo the host changes a daemon that dies without its own teardown leaves
/// behind, for the panic hook and `ray daemon --cleanup`. Synchronous and
/// best-effort, and each step is a no-op when its state is absent.
///
/// - Hand DNS back to the OS: restore the backed-up resolv.conf, drop the
///   NetworkManager `dns=none` snippet and withdraw any resolvconf stanza, so
///   the host does not keep pointing at a dead resolver (which would blackhole
///   all DNS until a restart).
/// - Remove the exit-node forwarding and NAT, restoring the sysctls, so the host
///   is not left an open router.
/// - Remove the client full-tunnel rules, which would otherwise outlive the TUN
///   they point at.
pub fn restore_host_state() {
    if crate::instance::is_rootless() {
        return;
    }
    crate::dns::config::emergency_restore_resolv_conf();
    crate::dns::config::emergency_withdraw_resolvconf();
    crate::exit_node::disable();
    crate::exit_node::teardown_client_routing();
}

/// Legacy name for [`Daemon`], kept so embedders (`ray-mobile`) that were
/// written against `DaemonState` compile unchanged after the daemon refactor.
pub type DaemonState = Daemon;

// The process-lifetime network + storage foundation every service depends on.
mod foundation;
pub(crate) use foundation::{Transport, TransportBootstrap};

// The per-peer mesh connection driver (one connection per peer, frame demux).
mod connection_manager;
pub(crate) use connection_manager::{ConnectionManager, MeshDispatch};

// One live mesh connection + its control-plane demux loop, built by the manager.
mod mesh_connection;
pub(crate) use mesh_connection::MeshConnection;

// Shared outbound mesh dials, one in flight per peer.
mod mesh_dialer;
pub(crate) use mesh_dialer::{DialClaim, DialedPeer, MESH_DIAL_TIMEOUT, MeshDialer};

// The service that owns the set of active networks (M5 migration seam).
mod network_registry;
pub(crate) use network_registry::{
    DialTarget, NameOwner, NetworkRegistry, RegistryHandles, finish_interrupted_rename,
    missing_networks,
};

#[cfg(any(target_os = "android", target_os = "ios"))]
mod idle_transport;

// Domain satellites with their own owned state (and ALPN accept arms), held by
// `Daemon` as fields rather than loose on the core. See each module.
mod dns_service;
pub(crate) use dns_service::DnsService;

mod file_service;
pub(crate) use file_service::FileService;

/// In-flight transfer state, for progress reporting on both sides of a send.
pub mod transfers;

mod connect_service;
mod inbound;
mod invite_delivery;
mod invite_inbox;
pub(crate) use connect_service::ConnectService;
mod management_service;
pub(crate) use management_service::ManagementService;

// Nodes seen on the local network over mDNS (`ray mdns scan`).
mod lan_discovery;
pub(crate) use lan_discovery::LanPeers;
mod mdns;
use mdns::MdnsDiscovery;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// ALPN for the device-pairing protocol. The trailing number is its protocol
/// version - **bump it on any breaking change to the `PairMsg` handshake**;
/// peers on different versions can't negotiate a connection (transport-enforced).
/// Version 3 adds the unpair exchange (`PairMsg::UnpairRequest`).
const PAIR_ALPN: &[u8] = b"rayfish/pair/3";

/// The previous pairing protocol version, still served and offered so pairing
/// and the network list keep working between builds. A connection that
/// negotiates it is refused the version 3 messages, and it tells a device that
/// its primary cannot record an unpair yet.
const PAIR_V2_ALPN: &[u8] = b"rayfish/pair/2";

/// Dial `addr` for the pairing protocol, offering version 2 as well so that a
/// primary on an older build still answers. The caller checks the negotiated
/// ALPN before sending a version 3 message.
async fn connect_pair(endpoint: &Endpoint, addr: iroh::EndpointAddr) -> Result<Connection> {
    let options =
        iroh::endpoint::ConnectOptions::new().with_additional_alpns(vec![PAIR_V2_ALPN.to_vec()]);
    let connecting = endpoint.connect_with_opts(addr, PAIR_ALPN, options).await?;
    Ok(connecting.await?)
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
    announce_handles_with(peers, conn, peer_ip, |name| {
        config::load_network(name)
            .ok()
            .flatten()
            .and_then(|n| n.network_public_key)
    })
    .await;
}

/// [`announce_network_handles`] with the network key lookup passed in.
async fn announce_handles_with(
    peers: &PeerTable,
    conn: &Connection,
    peer_ip: Ipv6Addr,
    network_key: impl Fn(&str) -> Option<EndpointId>,
) {
    let Some(target) = peers.announce_target(&peer_ip) else {
        return;
    };
    // A simultaneous inbound and outbound handshake may have selected a
    // different physical connection while this caller was registering its
    // network. Announce on the selected link, which is where data will flow.
    let selected = if target.conn.close_reason().is_none() {
        target.conn
    } else {
        conn.clone()
    };
    // Concurrent callers (one per network lane, joins, the coordinator) each
    // send a full snapshot, and the peer keeps whichever stream it accepts
    // last. Take the snapshot and open the stream under one lock so a later
    // snapshot always goes out last.
    let _ordered = target.lock.lock().await;
    let entries: Vec<control::NetworkHandle> = peers
        .outbound_handles(&peer_ip)
        .into_iter()
        .filter_map(|(name, handle)| {
            Some(control::NetworkHandle {
                network: network_key(&name)?,
                handle,
            })
        })
        .collect();
    if entries.is_empty() {
        return;
    }
    let _ = open_and_send(
        &selected,
        None,
        &ControlMsg::NetworkHandles {
            entries,
            features: transport::FEATURE_IDLE_CLOSE,
            receive_mtu: peers.local_mtu(),
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
    /// What the signed group blob carries, exactly as this node would publish
    /// it: [`Self::refresh_snapshot`] encodes it as is.
    ///
    /// On a coordinator it is what it publishes; on a member it is what it last
    /// adopted from a verified blob. In it:
    /// - `name` is the network's own name, which a local join alias must not
    ///   replace, because a later promotion may make this node a publisher.
    /// - `suggested_firewall` holds the coordinator's suggested rules (keyed by
    ///   subject hostname, `*` for every node); a member materializes rules from
    ///   it.
    /// - `reusable_keys` are the join keys (keyed by hex `blake3(secret)`) that
    ///   any network-key holder validates redemptions against, reloaded on every
    ///   reconverge so any admin can admit and revocation propagates.
    /// - `nullifiers` are device keys nullified on this network (`ray unpair`).
    ///   A coordinator seeds them from its persisted `revoked_devices` and drops
    ///   nullified devices from `members`; a member adopts them on reconverge.
    ///   Admission, `MeshHello` and prune reject a cert whose device is listed.
    group: GroupBlob,
    snapshot: Option<GroupSnapshot>,
    /// Serializes durable snapshot-pointer updates with DHT publication for this
    /// network. Clone the Arc under the state read lock, then await it separately.
    snapshot_commit: Arc<AsyncMutex<()>>,
    /// Terminal even if an older snapshot commit is still in flight.
    destroyed: bool,
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
    /// Access mode (open auto-admits; restricted gates unknown joiners). Only the
    /// coordinator's accept path consults this; members default to `Restricted`.
    mode: GroupMode,
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
    /// Join requests and undelivered denials on a closed network (coordinator
    /// only, in-memory, never persisted or published).
    pending: HashMap<EndpointId, PendingJoin>,
}

/// A join request and its undelivered operator decision on a closed network.
pub(crate) struct PendingJoin {
    pub(crate) denied: bool,
    pub(crate) hostname: Option<String>,
    pub(crate) device_cert: Option<control::DeviceCert>,
    pub(crate) requested_at: Instant,
}

/// Resolve an exact hostname or an unambiguous identity prefix from a small
/// user-visible queue. Exact names win, which keeps a hostname made only of hex
/// digits usable even when it also happens to prefix an identity.
pub(crate) fn resolve_named_identity(
    selector: &str,
    candidates: impl IntoIterator<Item = (EndpointId, Option<String>)>,
) -> Result<Option<EndpointId>, ()> {
    let candidates: Vec<_> = candidates.into_iter().collect();
    let names: Vec<EndpointId> = candidates
        .iter()
        .filter(|(_, hostname)| hostname.as_deref() == Some(selector))
        .map(|(identity, _)| *identity)
        .collect();
    match names.as_slice() {
        [identity] => return Ok(Some(*identity)),
        [] => {}
        _ => return Err(()),
    }

    let identities: Vec<EndpointId> = candidates
        .iter()
        .filter(|(identity, _)| {
            identity.to_string().starts_with(selector)
                || identity.fmt_short().to_string().starts_with(selector)
        })
        .map(|(identity, _)| *identity)
        .collect();
    match identities.as_slice() {
        [] => Ok(None),
        [identity] => Ok(Some(*identity)),
        _ => Err(()),
    }
}

#[cfg(test)]
mod named_identity_tests;

impl NetworkState {
    /// Snapshot the current member roster as an owned `Vec` (the members map is
    /// the single source of truth; callers take a copy to release the lock).
    pub(crate) fn roster(&self) -> MemberList {
        self.group.members.clone()
    }

    /// Snapshot the current approved-but-not-yet-joined entries as an owned `Vec`.
    fn approved_snapshot(&self) -> ApprovedList {
        self.group.approved.clone()
    }

    /// Hostnames currently claimed by other members (excluding `except`), used to
    /// resolve a rename/join collision against the roster.
    fn taken_hostnames(&self, except: EndpointId) -> Vec<String> {
        self.group
            .members
            .iter()
            .filter(|m| m.identity != except)
            .filter_map(|m| m.hostname.clone())
            .collect()
    }

    fn refresh_snapshot(&mut self) {
        self.pending.retain(|identity, _| {
            !self.group.members.is_member(identity) && !self.group.approved.is_approved(identity)
        });
        let bytes = canonical_group_bytes(&self.group);
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
    #[cfg(any(target_os = "android", target_os = "ios"))]
    idle_transport: JoinHandle<()>,
}

impl TunTasks {
    /// Cancel the reader loop and abort every data-plane task.
    fn stop(self) {
        self.cancel.cancel();
        self.writer.abort();
        self.mesh.abort();
        #[cfg(any(target_os = "android", target_os = "ios"))]
        self.idle_transport.abort();
    }
}

/// A failure that should end the daemon process with an error, so the service
/// manager restarts it (the unit uses `Restart=on-failure`). Armed only by
/// [`run_daemon`]: an embedder owns its own lifecycle and gets a log line
/// instead of a cancelled node.
///
/// The case it exists for is the TUN read loop stopping on a device error, for
/// example after the interface was deleted out from under us. Nothing restarts
/// that loop, so without this the daemon would keep its links up and report the
/// VPN as up while carrying nothing in either direction.
#[derive(Default)]
pub(crate) struct FatalExit {
    armed: AtomicBool,
    reason: Mutex<Option<String>>,
}

impl FatalExit {
    /// Only the desktop daemon arms it, after creating its own TUN; Android
    /// and iOS get theirs from the embedding app.
    #[cfg(any(not(embedded_tun), test))]
    pub(crate) fn arm(&self) {
        self.armed.store(true, Ordering::Relaxed);
    }

    /// Record `reason` and cancel `token`, which ends [`run_daemon`]. Returns
    /// false, doing nothing, when not armed. The first reason wins.
    pub(crate) fn trigger(&self, token: &CancellationToken, reason: String) -> bool {
        if !self.armed.load(Ordering::Relaxed) {
            return false;
        }
        self.reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_or_insert(reason);
        token.cancel();
        true
    }

    pub(crate) fn take(&self) -> Option<String> {
        self.reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

#[cfg(test)]
mod fatal_exit_tests;

pub struct Daemon {
    /// Recent RTT samples per peer, shared by successive status requests.
    connection_history: Mutex<mesh::diagnostics::ConnectionHistory>,
    /// The process-lifetime foundation (endpoint, identity, blob store, metrics),
    /// grouped so extracted services can depend on `Arc<Transport>`
    /// instead of the whole daemon.
    transport: Arc<Transport>,
    /// When the daemon process started, used for uptime in diagnostics.
    start: Instant,
    /// The network-owning service. Owns the `networks` map, `peers`, `firewall`,
    /// `device_user_map`, `pruned_peers`, the DNS service, the TUN name and
    /// writer cell, and the shutdown token; Daemon reaches all of them
    /// through `self.registry` rather than keeping its own copies. The
    /// daemon delegates coordinator registration / promotion to it, and hands
    /// clones to services (FileService) and control readers (MemberAcceptState)
    /// so they call it directly instead of signalling the daemon over a channel.
    registry: Arc<NetworkRegistry>,
    paired_network_joins: Arc<DashSet<EndpointId>>,
    protocol_router: Arc<ProtocolRouter>,
    mdns: Arc<MdnsDiscovery>,
    /// Whether this node opted into automatic stable updates
    /// (`ray config set auto-update on` / `ray install --auto-update`). Read at
    /// startup; when set, `run_daemon` spawns the periodic update task. Echoed
    /// back in `ray status`.
    auto_update: bool,
    /// Handles for the packet-forwarding tasks spawned by
    /// [`Daemon::attach_tun`], kept so a future `down()`/detach can stop them.
    tun_tasks: Mutex<Option<TunTasks>>,
    /// Set when the data plane fails in a way only a restart repairs.
    pub(crate) fatal: Arc<FatalExit>,
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
    /// Delegated machine enrollment and direct management protocol.
    management: Arc<ManagementService>,
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
    /// standby). Set by [`Daemon::start_ssh`], cleared by `stop_ssh`, and read
    /// by the periodic host-firewall check, all desktop-only, so the field does
    /// not exist on an Android build at all.
    #[cfg(feature = "desktop")]
    ssh_token: Mutex<Option<CancellationToken>>,
    /// Only an OS-owned macOS tunnel delegates SSH to the app's launchd helper.
    #[cfg(all(target_os = "macos", feature = "desktop"))]
    app_ssh_helper: AtomicBool,
    /// Cancellation token for the IPv4 listener bridge (`None` when off / on
    /// standby). Same shape and same reason as `ssh_token`: it binds the mesh
    /// address, so it lives and dies with the data plane. See
    /// [`crate::v4bridge`].
    #[cfg(feature = "desktop")]
    v4_bridge_token: Mutex<Option<CancellationToken>>,
    /// Stops the watcher that restores the TUN's link, address and route while
    /// the data plane is up (see `tun::spawn_repair_watcher`).
    #[cfg(target_os = "linux")]
    tun_watch_token: Mutex<Option<CancellationToken>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.mdns.abort();
    }
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
        // Same cert the registry was built with; see
        // `NetworkRegistry::current_device_cert` for why the on-disk copy wins.
        self.registry.current_device_cert()
    }

    /// Coalesced invalidations for incoming offers and transfer status. Subscribe
    /// before reading a snapshot; the receiver does not keep this daemon alive.
    pub fn subscribe_file_changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.transfers.subscribe()
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
    /// Shutting the protocol router down is what releases the blob store,
    /// and it is not optional for an embedder either: `Router::shutdown` is the
    /// only thing that drives `BlobsProtocol::shutdown` -> `Store::shutdown`,
    /// which is what drops the store's redb `Database` and with it the exclusive
    /// file lock on `blobs/blobs.db`. Without it the lock outlives this call, and
    /// a second open does not fail, it waits: the next `build_headless` in the
    /// same process then blocks until whatever eventually drops the old store
    /// does, if anything does, which on mobile is how a disabled node never comes
    /// back. Close the endpoint concurrently so connection termination does not
    /// wait for the store to flush. Both must finish before this call returns.
    ///
    /// After this the `Daemon` is spent; build a new one to come back online.
    pub async fn shutdown_and_close(&self) {
        let started = Instant::now();
        let tun_attached = self.tun_tasks.lock().unwrap().is_some();
        tracing::info!(tun_attached, "shutdown: cancelling token, closing endpoint");
        self.registry.shutdown_token.cancel();
        self.mdns.stop().await;
        self.management.stop_announcements().await;
        // The DNS background tasks run on bare `tokio::spawn`s that observe their
        // own tokens, not `shutdown_token`, so cancelling the token above does not
        // reach them. They also hold an `Arc<DnsService>`, which on an embedder
        // that rebuilds a daemon in the same process keeps the whole dead service
        // alive; see `DnsService::shutdown_background`.
        self.registry.dns.shutdown_background();
        // Accept handlers hold the registry, which owns the manager they are
        // registered on; drop them so the registry can go with the daemon.
        self.registry.conn.unregister_all();
        let (router_result, ()) =
            tokio::join!(self.router.shutdown(), self.transport.endpoint.close(),);
        if let Err(error) = router_result {
            tracing::warn!(%error, "shutdown: protocol router failed");
        }
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "shutdown: router stopped, blob store released, endpoint closed"
        );
    }

    #[cfg(all(target_os = "linux", feature = "desktop"))]
    pub(crate) async fn rootless_resolve(&self, name: &str) -> Option<Ipv6Addr> {
        self.registry
            .resolve_peer_name(name.trim_end_matches('.'))
            .await
            .map(|id| derive_ipv6(&id))
    }

    #[cfg(all(target_os = "linux", feature = "desktop"))]
    pub(crate) fn rootless_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Part of the embedding API (used by `ray-mobile`): the host OS observed a
    /// network change (Wi-Fi/cellular switch, roam, airplane mode). On desktop,
    /// netwatch sees route changes itself; on Android its route monitor is a
    /// stub (apps cannot subscribe to netlink route updates), so without this
    /// forward the endpoint sits on dead sockets until something else rebuilds
    /// them. iroh rebinds and re-probes its paths in response.
    pub async fn network_changed(&self) {
        // An idle phone is outgoing-only. Waking the transport rebinds anyway,
        // so a roam while idle costs nothing until the phone sends something.
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if self.transport.is_suspended() {
            tracing::debug!("host reported a network change while idle; deferring rebind");
            return;
        }
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
        self.registry.peers.set_local_mtu(writer.mtu());
        // Fresh channel per attach. The previous writer (if any) was torn down by
        // `detach_tun`, which dropped the old receiver; swapping in the new sender
        // reconnects every incoming send-site to this writer.
        let (new_tx, new_rx) = mpsc::channel::<Bytes>(256);
        self.registry.tun_tx.store(Arc::new(new_tx.clone()));

        // A dedicated child token so the data plane can be stopped independently
        // of a full daemon shutdown; it still cancels when `shutdown_token` does.
        let cancel = self.registry.shutdown_token.child_token();
        let writer_handle = forward::spawn_tun_writer(
            writer,
            new_rx,
            Arc::clone(&self.active),
            Arc::clone(&self.transport.stats),
        );
        let mesh_handle = {
            let peers = self.registry.peers.clone();
            let firewall = self.registry.firewall.clone();
            let cancel = cancel.clone();
            let stats = Arc::clone(&self.transport.stats);
            let resolver = Arc::clone(&self.registry.dns.resolver);
            // The registry is the forwarding loop's on-demand dial mechanism: when a
            // packet has no live route, the loop asks it to dial the roster member.
            // Present on every node so any peer stays reachable-on-demand after a link
            // idle-closes.
            let dialer = Some(Arc::clone(&self.registry));
            let local_ipv6 = self.transport.identity.local_ipv6();
            let fatal = Arc::clone(&self.fatal);
            let shutdown = self.registry.shutdown_token.clone();
            tokio::spawn(async move {
                if let Err(e) = (forward::MeshForwarder {
                    tun: reader,
                    local_ipv6,
                    peers,
                    firewall,
                    token: cancel,
                    stats,
                    resolver,
                    tun_tx: new_tx,
                    dialer,
                })
                .run()
                .await
                {
                    let reason = format!("TUN read loop stopped: {e:#}");
                    if fatal.trigger(&shutdown, reason) {
                        tracing::error!(error = %e, "TUN read loop stopped; exiting so the service manager restarts the daemon");
                    } else {
                        tracing::warn!(error = %e, "mesh forwarding loop exited with error");
                    }
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
            #[cfg(any(target_os = "android", target_os = "ios"))]
            idle_transport: idle_transport::spawn(
                Arc::clone(&self.registry),
                self.registry.shutdown_token.child_token(),
            ),
        };
        let old = self.tun_tasks.lock().unwrap().replace(new_tasks);
        if let Some(old) = old {
            old.stop();
        }
        // Connections survive mobile VPN toggles; refresh the receive limit for
        // already-connected peers as well as announcing it on future connects.
        let peers = self.registry.peers.clone();
        for (ip, conn) in peers.all_connections() {
            let peers = peers.clone();
            let token = self.registry.shutdown_token.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => {},
                    _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        announce_network_handles(&peers, &conn, ip),
                    ) => {},
                }
            });
        }
    }

    /// Start forwarding through an interface whose link, routes, and DNS are
    /// already configured by the embedder (for example, NetworkExtension).
    /// Unlike `activate`, this does not change the host network configuration.
    /// Stop it with `detach_tun` before the embedder removes the interface.
    pub async fn attach_external_tun<R: TunRead, W: TunWrite>(
        self: &Arc<Self>,
        reader: R,
        writer: W,
    ) {
        #[cfg(all(target_os = "macos", feature = "desktop"))]
        self.app_ssh_helper.store(true, Ordering::SeqCst);
        self.attach_tun(reader, writer).await;
        self.active.store(true, Ordering::SeqCst);
        #[cfg(feature = "desktop")]
        {
            if config::load().is_ok_and(|settings| settings.ssh_enabled) {
                self.start_ssh();
            }
            if config::load()
                .map(|settings| settings.v4_bridge)
                .unwrap_or(true)
            {
                self.start_v4_bridge();
            }
        }
        self.registry.poll_nudge.notify_waiters();
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
        #[cfg(feature = "desktop")]
        {
            self.stop_ssh();
            self.stop_v4_bridge();
        }
        self.active
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(tasks) = self.tun_tasks.lock().unwrap().take() {
            tracing::info!("detach_tun: aborting TUN writer + mesh forwarding tasks");
            tasks.stop();
        } else {
            tracing::debug!("detach_tun: no TUN attached");
        }
    }

    /// Point the Magic DNS resolver at the given upstream servers so non-`.ray`
    /// queries are forwarded there instead of refused. The desktop path captures
    /// upstreams from the system resolver config; Android has none to capture, so
    /// the platform reads the underlying network's DNS servers and passes them in.
    pub fn set_dns_upstreams(&self, servers: Vec<Ipv4Addr>) {
        self.registry.dns.resolver.set_upstreams(servers);
    }

    /// Point the Magic DNS resolver at explicit `ip:port` upstreams. Android uses
    /// this to target a loopback `DnsResolver.rawQuery` proxy so non-`.ray`
    /// lookups honor the system Private DNS (DoT/DoH) rather than being forwarded
    /// as cleartext UDP on port 53.
    pub fn set_dns_upstream_addrs(&self, servers: Vec<SocketAddr>) {
        self.registry.dns.resolver.set_upstream_addrs(servers);
    }

    // -----------------------------------------------------------------------
    // Hostname
    // -----------------------------------------------------------------------

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    pub async fn set_hostname(&self, network: &str, hostname: &str) -> OpResult<Done> {
        use crate::hostname;

        if !hostname::is_valid_hostname(hostname) {
            return Err(OpError::msg(
                "invalid hostname (lowercase ASCII, 1-63 chars)",
            ));
        }

        let (is_coord, state, dht_notify) = match self.registry.networks.get(network) {
            Some(h) => (
                h.role.is_coordinator(),
                Arc::clone(&h.state),
                h.dht_notify.clone(),
            ),
            None => {
                return Err(OpError::msg(format!("network '{network}' not found")));
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

        // Persist to config first, so a failed save changes nothing. A member
        // also records the rename as a durable pending intent so it keeps
        // being delivered to a coordinator across reconnects/restarts until the
        // signed blob confirms it; a coordinator publishes authoritatively, so
        // it clears any pending intent.
        if let Err(error) = config::update_network(network, |net| {
            net.my_hostname = Some(new_hostname.clone());
            net.pending_hostname = if is_coord {
                None
            } else {
                Some(new_hostname.clone())
            };
            Ok(())
        }) {
            return Err(OpError::msg(format!("could not save hostname: {error:#}")));
        }

        // Update our own member entry.
        if let Ok(mut s) = state.write()
            && let Some(me) = s.group.members.get_mut(&my_identity)
        {
            me.hostname = Some(new_hostname.clone());
        }

        // Update DNS table: remove old entry for our IP, insert new one.
        dns::remove_hostname_by_ip(
            &self.registry.dns.hostname_table,
            &self.registry.dns.reverse_table,
            network,
            derive_ipv6(&self.transport.identity.local_identity()),
        )
        .await;
        dns::update_hostname(
            &self.registry.dns.hostname_table,
            &self.registry.dns.reverse_table,
            network,
            &new_hostname,
            derive_ipv6(&self.transport.identity.local_identity()),
        )
        .await;

        // Deliver the rename to connected peers via `MeshHello`, regardless of
        // role. Coordinators act on it (`handle_member_hello` applies the rename
        // and republishes the signed record); plain members ignore the claim and
        // pick the name up from that record. A peer coordinator only learns a
        // self-rename this way: it does not act on a `MemberSync`/`BlobUpdated`
        // trigger, and coordinators don't run the group poller.
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
        Ok(Done(format!("hostname set to {new_hostname} ({dns_name})")))
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
        GlobalKey::FileAutoAcceptPeers => "File auto-accept peers updated.".to_string(),
        GlobalKey::Inbound => "Inbound policy updated.".to_string(),
        GlobalKey::Blocked => "Block list updated.".to_string(),
        GlobalKey::Mdns => format!(
            "mDNS discovery {}.",
            if cfg.mdns_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ),
        GlobalKey::Dns => match cfg.dns_mode {
            config::DnsMode::On => "DNS enabled.".to_string(),
            config::DnsMode::Partial => "DNS limited to .ray names.".to_string(),
            config::DnsMode::Off => "DNS disabled.".to_string(),
        },
        GlobalKey::QuicEngine => {
            format!("QUIC engine set to {}. {restart}", cfg.quic_engine.as_ref())
        }
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
        // them to their own setters, as does `PfPassthrough`); they are listed
        // only to keep the match exhaustive.
        k @ (GlobalKey::Relay
        | GlobalKey::DiscoveryDns
        | GlobalKey::DnsUpstreams
        | GlobalKey::AutoUpdate
        | GlobalKey::OnDemand
        | GlobalKey::Ssh
        | GlobalKey::SshPort
        | GlobalKey::V4Bridge
        | GlobalKey::PfPassthrough) => {
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
mod confirmation_message_tests;

#[cfg(test)]
mod net_config_authz_tests;

pub(crate) fn guess_mime_type(filename: &str) -> String {
    mime_guess::from_path(filename)
        .first_or_octet_stream()
        .to_string()
}

pub(crate) fn format_size(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
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

/// Send one control message on a fresh stream and wait until the peer has
/// acknowledged all of it. For a sender about to close the link: `ray leave`
/// tears the network down right after, which closes every link sharing no other
/// network, and a close discards whatever is still unsent (the same wait as
/// `send_welcome`).
async fn send_confirmed(
    conn: &Connection,
    net: Option<EndpointId>,
    msg: &ControlMsg,
) -> Result<()> {
    let (mut send, _recv) = conn.open_bi().await.context("open control stream")?;
    control::send_msg(&mut send, net, msg).await?;
    // A reader that took the frame but not the FIN stops the stream with code 0.
    if let Some(code) = send.stopped().await.context("await delivery")?
        && code != VarInt::from_u32(0)
    {
        anyhow::bail!("peer stopped the stream: {code}");
    }
    Ok(())
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
    roster: &MemberList,
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

/// The coordinators a departure must still reach after the live links carried it:
/// every coordinator on the roster but us that `reached` lacks. Only a coordinator
/// prunes a member, so these are dialed whatever their recent dial history: unlike
/// the `MemberSync` hint [`absent_member_ips`] serves, a leave is never retried.
fn leave_recipients(
    roster: &MemberList,
    my_id: EndpointId,
    reached: &HashSet<EndpointId>,
) -> Vec<Ipv6Addr> {
    roster
        .iter()
        .filter(|m| m.is_coordinator && m.identity != my_id && !reached.contains(&m.identity))
        .map(|m| derive_ipv6(&m.identity))
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
    let registry = Arc::clone(registry);
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
mod absent_member_tests;

#[cfg(test)]
pub(crate) mod accept_handler_tests;

#[cfg(test)]
mod coordinator_dial_order_tests;

#[cfg(test)]
mod headless_tests;

#[cfg(test)]
mod announce_order_tests;
