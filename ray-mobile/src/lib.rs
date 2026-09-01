//! `ray-mobile`: a UniFFI cdylib that drives the `rayfish` mesh core on Android.
//!
//! The `Node` wraps a real headless [`rayfish::daemon::DaemonState`]
//! (`build_headless`), reusing the desktop daemon's create/join/pair/status
//! logic instead of reimplementing any protocol. The control plane (endpoint,
//! network connections) comes up on [`Node::start`]; the data plane (the
//! zero-copy forward loop over the `VpnService` fd) is attached on [`Node::up`]
//! and stopped on [`Node::down`], leaving the control plane connected.
//!
//! No platform specifics leak into the core: the fd handling lives in
//! [`android_tun`], and everything else is a thin map from the core's
//! `IpcMessage` results to the UniFFI records below.

#[cfg(target_os = "android")]
mod android_tun;
mod diag;

/// JNI bridge that hands the Android `JavaVM` + app `Context` to the two Rust
/// dependencies that need them: `ndk-context` (so iroh-dns can read the system
/// DNS servers) and `rustls-platform-verifier` (so relay/discovery TLS can reach
/// Android's trust store). Kotlin calls `RustlsInit.nativeInit(context)` once
/// (after `System.loadLibrary("ray_mobile")`) before starting the node; without
/// it, `build_headless` panics with "android context was not initialized".
#[cfg(target_os = "android")]
mod android_jni {
    use std::ffi::c_void;

    use jni::EnvUnowned;
    use jni::objects::{JClass, JObject};

    /// Backs `external fun nativeInit(context: Context)` on `RustlsInit` in the
    /// `xyz.rayfish.android` package. The JVM hands us an `EnvUnowned`;
    /// `with_env` upgrades it to the `&mut Env` the JNI calls need. Must run
    /// exactly once per process: `ndk_context::initialize_android_context`
    /// asserts it has not been set before. `RustlsInit` guards that on the
    /// Kotlin side.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_xyz_rayfish_android_RustlsInit_nativeInit<'local>(
        mut env: EnvUnowned<'local>,
        _class: JClass<'local>,
        context: JObject<'local>,
    ) {
        let _ = env.with_env(|env| -> Result<(), jni::errors::Error> {
            // Register the JavaVM + a process-lived global Context ref so
            // iroh-dns's system-DNS reader can call into the JVM. The global ref
            // is leaked on purpose: ndk-context stores the raw pointer and reads
            // it for the life of the process, so it must never be deleted.
            let vm_ptr = env.get_java_vm()?.get_raw() as *mut c_void;
            let global_ctx = env.new_global_ref(&context)?;
            let ctx_ptr = global_ctx.as_obj().as_raw() as *mut c_void;
            std::mem::forget(global_ctx);
            // SAFETY: pointers are valid for the process lifetime, and this runs
            // once (RustlsInit.done), so the crate's single-init assert holds.
            unsafe { ndk_context::initialize_android_context(vm_ptr, ctx_ptr) };

            if let Err(e) = rustls_platform_verifier::android::init_with_env(env, context) {
                eprintln!("rayfish: rustls-platform-verifier init failed: {e:?}");
            }
            Ok(())
        });
    }
}

use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "android")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "android")]
use android_tun::{AndroidTunReader, AndroidTunWriter};
use rayfish::config;
use rayfish::control;
use rayfish::daemon::transfers;
use rayfish::daemon::{DaemonState, build_headless};
use rayfish::deeplink::{self, RayfishLink};
use rayfish::firewall::{Action, Direction, Protocol};
use rayfish::hostname;
use rayfish::identity;
use rayfish::invite;
use rayfish::ipc::{self, IpcMessage};
use rayfish::keybackup;
use rayfish::membership::{self, GroupMode};
use tokio::runtime::Runtime;
use tokio::time::timeout;

uniffi::setup_scaffolding!();

/// How long [`Node::stop`] waits for the daemon to close before giving up. Long
/// enough for QUIC connections to terminate cleanly and the blob store to flush,
/// short enough that a caller on an Android main/binder thread is never held for
/// what the system would count as an ANR.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`Node::start`] waits for the daemon to build. Generous, because a
/// cold start does disk and network work (identity, endpoint bind, relay probe)
/// on a phone that may be on a bad link; this is a backstop against a build that
/// never returns at all, not a latency budget.
const START_TIMEOUT: Duration = Duration::from_secs(45);

/// Structured error surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RayError {
    /// A method that needs the daemon was called before [`Node::start`].
    #[error("node not started")]
    NotStarted,
    /// The supplied invite/pairing code could not be decoded.
    #[error("bad code: {0}")]
    BadCode(String),
    /// Joining a network failed (dial, handshake, or admission).
    #[error("join failed: {0}")]
    JoinFailed(String),
    /// Pairing with a primary device failed.
    #[error("pair failed: {0}")]
    PairFailed(String),
    /// Any other core error: identity load, endpoint bind, create, or an
    /// unexpected protocol response.
    #[error("{0}")]
    Network(String),
    /// A backup code would not decode, or the password was wrong. The two are
    /// one case: the AEAD cannot tell them apart.
    #[error("{0}")]
    BadBackup(String),
    /// [`Node::restore_identity`] found an identity already on the device and
    /// was not told to replace it. Carries the existing public key so the UI can
    /// name what it is about to overwrite. Not a failure on its own: the caller
    /// is expected to confirm with the user and call again with
    /// `replace_existing`.
    #[error("device already has identity {0}")]
    IdentityExists(String),
    /// A restore was attempted while the node was running. The endpoint is bound
    /// to the old key, so the identity cannot change under it; stop first.
    #[error("stop the node before restoring an identity")]
    NodeRunning,
}

impl RayError {
    fn network(e: impl std::fmt::Display) -> Self {
        RayError::Network(e.to_string())
    }
}

/// Snapshot returned by `create` / `join`.
#[derive(uniffi::Record)]
pub struct NetworkInfo {
    pub name: String,
    pub node_id: String,
    pub ipv6: String,
    /// True when the join was queued for coordinator approval (no IP yet).
    pub pending: bool,
}

/// An encrypted identity backup and the public key it restores to.
#[derive(uniffi::Record)]
pub struct IdentityBackup {
    /// The base58 `enc1` blob. This is the secret: anyone holding it and the
    /// password holds the identity, so it belongs in a password manager or
    /// behind the file picker, never in a log or a share sheet preview.
    pub code: String,
    /// The identity the code restores to, for showing the user which one they
    /// just wrote out.
    pub public_key: String,
}

/// Three-state peer liveness, mirroring [`ipc::PeerState`]. `Idle` is not
/// "unreachable": on an on-demand node (which mobile always is) every link
/// self-closes after the idle timeout, so a reachable peer sits in `Idle` until
/// something dials it. Only `Offline` means a reach attempt recently failed.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnState {
    Active,
    Idle,
    Offline,
}

impl From<ipc::PeerState> for PeerConnState {
    fn from(s: ipc::PeerState) -> Self {
        match s {
            ipc::PeerState::Active => Self::Active,
            ipc::PeerState::Idle => Self::Idle,
            ipc::PeerState::Offline => Self::Offline,
        }
    }
}

/// One peer in a network snapshot.
#[derive(uniffi::Record)]
pub struct PeerInfo {
    /// The peer's mesh IPv6, derived from its identity. The only address it has:
    /// the overlay carries no IPv4.
    pub ipv6: String,
    pub node_id: String,
    pub hostname: String,
    pub state: PeerConnState,
}

/// Whether the daemon has this network registered, for the UI's status dot.
///
/// A saved network the daemon has not registered yet still has to be listed.
/// Dropping it makes every network vanish for the seconds a cold start spends
/// restoring them, and makes a restore that never lands indistinguishable from a
/// network the user never joined. `ray status` has always shown these (its
/// `inactive_networks` block); this is the same thing for the phone.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkConnState {
    /// Registered by the daemon: the rest of this snapshot is live.
    Connected,
    /// Saved, restore still in flight and not yet failed once.
    Connecting,
    /// Saved but carrying nothing: either a restore that has failed at least
    /// once (see [`NetworkDetail::reason`]) or a deliberately stopped node.
    NotConnected,
}

/// One network this node belongs to, with its peers.
#[derive(uniffi::Record)]
pub struct NetworkDetail {
    pub name: String,
    pub ipv6: String,
    pub hostname: String,
    pub is_coordinator: bool,
    pub peers: Vec<PeerInfo>,
    pub state: NetworkConnState,
    /// The daemon's one-line reason for the last failed restore, when `state` is
    /// [`NetworkConnState::NotConnected`] because of one. `None` otherwise.
    pub reason: Option<String>,
}

/// Health/addresses/networks snapshot for the UI.
#[derive(uniffi::Record)]
pub struct Status {
    pub running: bool,
    pub node_id: String,
    pub ipv6: String,
    pub peers: Vec<PeerInfo>,
    pub networks: Vec<NetworkDetail>,
    pub pending_networks: Vec<String>,
}

/// One network's liveness, for the health snapshot.
#[derive(uniffi::Record)]
pub struct NetworkHealth {
    pub name: String,
    pub connected: bool,
}

/// Lightweight health vitals for auto-telemetry. Cheap to build (reads a status
/// snapshot + the diagnostics counters); safe to call before `start`.
#[derive(uniffi::Record)]
pub struct HealthSnapshot {
    pub running: bool,
    pub network_count: u32,
    pub peers_online: u32,
    pub networks: Vec<NetworkHealth>,
    pub mesh_up: bool,
    pub node_id: String,
    pub mesh_ipv6: String,
    pub warn_count: u64,
    pub error_count: u64,
    pub recent_errors: Vec<String>,
}

/// One firewall rule as shown in the UI.
#[derive(uniffi::Record)]
pub struct FirewallRuleInfo {
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub port: String,
    pub peer: String,
    pub network: String,
}

/// Current firewall posture and rules, for the UI.
#[derive(uniffi::Record)]
pub struct FirewallStateInfo {
    pub default_inbound: String,
    pub default_outbound: String,
    pub disabled: bool,
    pub rules: Vec<FirewallRuleInfo>,
}

/// A pending incoming file offer, for the notifications UI.
#[derive(uniffi::Record)]
pub struct FileOffer {
    pub id: u64,
    pub from: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
    /// True when the sender is one of this user's own paired devices. The UI
    /// auto-accepts these (own-device shares) without a manual tap.
    pub own_device: bool,
}

/// An outbound send still queued for a peer that hasn't taken the offer yet.
/// `id` is what [`Node::cancel_send`] takes; it is the outbox's own id, not a
/// transfer-registry id.
#[derive(uniffi::Record)]
pub struct QueuedSend {
    pub id: u64,
    /// The recipient's short endpoint id.
    pub peer: String,
    pub filename: String,
    pub size: u64,
}

/// Where a transfer is. A send is `Offered` until the peer accepts and starts
/// pulling the bytes: `send_file` returns once the offer lands, not once the file
/// has arrived, so `Done` on an outgoing transfer is the real "they have it".
#[derive(uniffi::Enum)]
pub enum TransferState {
    Offered,
    Transferring,
    Done,
    Failed,
}

/// One in-flight (or recently finished) file transfer, either direction.
#[derive(uniffi::Record)]
pub struct Transfer {
    pub id: u64,
    pub outgoing: bool,
    pub peer: String,
    pub filename: String,
    pub size: u64,
    pub transferred: u64,
    pub state: TransferState,
}

/// A pending request awaiting the user's decision: an incoming `ray connect`
/// friend request, or a network-join request on a network we coordinate.
#[derive(uniffi::Record)]
pub struct PendingRequest {
    pub short_id: String,
    pub hostname: Option<String>,
    pub waiting_secs: u64,
}

/// The outcome of following a `rayfish://` deep link, reflected in the UI.
#[derive(uniffi::Enum)]
pub enum LinkAction {
    Joined(NetworkInfo),
    Paired,
}

/// The FFI object. Owns a multi-thread tokio runtime and, once started, an
/// `Arc<DaemonState>` shared with the core's background tasks.
#[derive(uniffi::Object)]
pub struct Node {
    runtime: Runtime,
    // Never held across a `runtime.block_on(...)`: lock briefly to read/clone the
    // `Arc<DaemonState>` or to commit `start`, release, then run async work.
    state: Mutex<Option<Arc<DaemonState>>>,
}

impl Node {
    /// Clone out the started `DaemonState`, or `NotStarted`. Releases the lock
    /// before returning so callers never hold it across `block_on`.
    fn state(&self) -> Result<Arc<DaemonState>, RayError> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .cloned()
            .ok_or(RayError::NotStarted)
    }

    /// This node's endpoint id, read from a fresh `status()` snapshot.
    fn node_id(state: &Arc<DaemonState>) -> String {
        match state.status() {
            IpcMessage::StatusResponse { endpoint_id, .. } => endpoint_id.to_string(),
            _ => String::new(),
        }
    }
}

/// One roster entry as the UI's [`PeerInfo`]. The mesh address is derived from
/// the identity rather than taken from `PeerStatus::ipv6` so live and saved
/// projections agree on it by construction.
fn peer_info(p: &ipc::PeerStatus) -> PeerInfo {
    PeerInfo {
        ipv6: membership::derive_ipv6(&p.endpoint_id).to_string(),
        node_id: p.endpoint_id.to_string(),
        hostname: p.hostname.clone().unwrap_or_default(),
        state: p.state.into(),
    }
}

/// Project a saved network the daemon has not registered into a [`NetworkDetail`].
///
/// `reason` is the daemon's record of the last restore failure and is `None`
/// until one has actually happened, which is exactly the distinction the UI
/// needs: no failure yet means the restore is still in flight (`Connecting`),
/// and a failure means it is stuck with something to say about why.
///
/// `fallback_ipv6` is this device's own mesh address, used for the name-only row
/// a daemon predating the `saved` projection produces.
fn inactive_network_detail(net: &ipc::InactiveNetwork, fallback_ipv6: &str) -> NetworkDetail {
    let state = match net.reason {
        None => NetworkConnState::Connecting,
        Some(_) => NetworkConnState::NotConnected,
    };
    let Some(saved) = net.saved.as_ref() else {
        return NetworkDetail {
            name: net.name.clone(),
            ipv6: fallback_ipv6.to_string(),
            hostname: String::new(),
            is_coordinator: false,
            peers: Vec::new(),
            state,
            reason: net.reason.clone(),
        };
    };
    NetworkDetail {
        name: saved.name.clone(),
        ipv6: saved.my_ipv6.to_string(),
        hostname: saved.my_hostname.clone().unwrap_or_default(),
        is_coordinator: saved.role.is_coordinator(),
        peers: saved.peers.iter().map(peer_info).collect(),
        state,
        reason: net.reason.clone(),
    }
}

/// Fold the daemon's unregistered networks in with the live ones and sort the
/// result. One list rather than two so a network keeps its place in the UI when
/// its restore lands, instead of jumping out of a "connecting" section.
fn merge_networks(
    mut live: Vec<NetworkDetail>,
    inactive: &[ipc::InactiveNetwork],
    fallback_ipv6: &str,
) -> Vec<NetworkDetail> {
    live.extend(
        inactive
            .iter()
            .map(|n| inactive_network_detail(n, fallback_ipv6)),
    );
    // Stable alphabetical order so the list does not shuffle between status
    // refreshes with the core's iteration order.
    live.sort_by_key(|n| n.name.to_lowercase());
    live
}

/// Build an offline status snapshot from the on-disk config, used when the node
/// is stopped so the UI can still show the user's saved networks. Everything is
/// reported offline: `running` is false and every peer's state is `Offline`. The
/// per-network address/hostname come straight from the saved membership.
///
/// The device's own node id and mesh addresses are derived from the persisted
/// identity, so they stay populated while stopped (they never change with the
/// tunnel state) instead of blanking to "-" in the UI.
fn saved_networks_status() -> Status {
    let empty = Status {
        running: false,
        node_id: String::new(),
        ipv6: String::new(),
        // A stopped node has no data plane, so it is in no mode at all.
        peers: Vec::new(),
        networks: Vec::new(),
        pending_networks: Vec::new(),
    };
    let Ok(cfg) = config::load() else {
        return empty;
    };
    // Derive this device's stable identity-based fields off disk. Without a
    // persisted identity there are no saved networks to show either, so fall
    // back to the empty snapshot.
    let (node_id, device_ipv6) = match identity::load_or_create() {
        Ok(secret) => {
            let id = secret.public();
            (id.to_string(), membership::derive_ipv6(&id).to_string())
        }
        Err(_) => return empty,
    };
    // Same stable alphabetical order as the live snapshot below.
    let mut sorted = cfg.networks.clone();
    sorted.sort_by_key(|n| n.name.to_lowercase());
    let networks = sorted
        .iter()
        .map(|net| {
            // Exclude our own roster entry so the peer list mirrors the live
            // snapshot, which lists only the other members.
            let peers = net
                .members
                .iter()
                .filter(|m| m.identity.to_string() != node_id)
                .map(|m| PeerInfo {
                    ipv6: membership::derive_ipv6(&m.identity).to_string(),
                    node_id: m.identity.to_string(),
                    hostname: m.hostname.clone().unwrap_or_default(),
                    state: PeerConnState::Offline,
                })
                .collect();
            NetworkDetail {
                name: net.name.clone(),
                ipv6: device_ipv6.clone(),
                hostname: net.my_hostname.clone().unwrap_or_default(),
                is_coordinator: net.network_secret_key.is_some(),
                peers,
                // Stopped on purpose, so there is nothing in progress and no
                // failure to explain.
                state: NetworkConnState::NotConnected,
                reason: None,
            }
        })
        .collect();
    Status {
        node_id,
        ipv6: device_ipv6,
        networks,
        ..empty
    }
}

#[uniffi::export]
impl Node {
    /// `config_dir` is the app-private directory (Kotlin `Context.getFilesDir()`)
    /// where identity + config live. It is published to the core through
    /// `config::set_config_dir_override`, which `config::config_dir()` honors
    /// ahead of `RAYFISH_CONFIG_DIR` on every platform.
    #[uniffi::constructor]
    pub fn new(config_dir: String) -> Arc<Self> {
        // Capture the core's tracing output for Android diagnostics. Idempotent;
        // safe to call once per process (Node is a process singleton).
        diag::install();
        // Set before any core call reads config. Not an environment write: that
        // is undefined behaviour once the runtime's threads are up, and it also
        // let one test redirect another's config reads mid-test.
        config::set_config_dir_override(PathBuf::from(&config_dir));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        Arc::new(Self {
            runtime,
            state: Mutex::new(None),
        })
    }

    /// Build the headless daemon (identity, endpoint, blob store, resolver) and
    /// bring the saved networks' control plane up. Idempotent: a second call is a
    /// no-op success. Must run before `join`/`create`/`pair`/`up`.
    ///
    pub fn start(&self) -> Result<(), RayError> {
        // Fast path: already started. Check briefly, then release the lock.
        if self.state.lock().unwrap().is_some() {
            return Ok(());
        }

        // Bounded, because the one way this call can fail to return is fatal to
        // the app: opening the blob store takes redb's exclusive lock on
        // `blobs.db`, and a second open does not fail, it waits. So a rebuild
        // that overlaps a store the previous daemon has not released yet would
        // block here forever, on a thread that holds NodeHolder's monitor, and
        // every later start/stop/up would queue behind it (the reported "the
        // phone never came back online"). Failing is recoverable; wedging is not.
        let state = self
            .runtime
            .block_on(async { timeout(START_TIMEOUT, build_headless(true)).await })
            .map_err(|_| {
                tracing::error!(
                    timeout_secs = START_TIMEOUT.as_secs(),
                    "Node.start: building the daemon timed out"
                );
                RayError::Network("node start timed out".to_string())
            })?
            .map_err(RayError::network)?;

        // Commit under the lock, re-checking for a racing `start` that won while
        // we were building. If one did, keep the winner and shut ours down: a
        // plain drop would leave a second endpoint live and, worse, a second
        // blob store holding the exclusive redb lock on `blobs.db`, which no
        // later `start` in this process could then reopen.
        let loser = {
            let mut guard = self.state.lock().unwrap();
            match guard.is_none() {
                true => {
                    *guard = Some(state);
                    None
                }
                false => Some(state),
            }
        };
        if let Some(loser) = loser {
            tracing::warn!("Node.start: a concurrent start won; shutting the extra daemon down");
            self.runtime.block_on(loser.shutdown_and_close());
        }
        Ok(())
    }

    /// Join an existing network by invite code (or a bare room id / network
    /// pubkey). Maps the core's `IpcMessage` result to a [`NetworkInfo`].
    pub fn join(&self, code: String) -> Result<NetworkInfo, RayError> {
        let state = self.state()?;

        // `code` is either a self-contained invite (network key + coordinator +
        // secret) or a bare room id (the network pubkey). Mirrors the CLI's
        // `ipc_join` fallback: on decode failure, treat the input as a room id.
        let (network_key, invite, coordinator) = match invite::decode_invite_code(&code) {
            Ok((net_pubkey, coord, secret)) => (net_pubkey.to_string(), Some(secret), Some(coord)),
            Err(_) => (code.clone(), None, None),
        };

        let result = self.runtime.block_on(state.join_network(
            &network_key,
            None,
            None,
            invite,
            coordinator,
            false, // auto_accept_firewall
            true,  // auto_accept_files (own-device offers, identity-checked)
        ));

        match result {
            IpcMessage::Joined { name, my_ipv6 } => Ok(NetworkInfo {
                name,
                node_id: Self::node_id(&state),
                ipv6: my_ipv6.to_string(),
                pending: false,
            }),
            // Closed network without a valid invite: queued for coordinator approval
            // and retried in the background. Report it as pending so the UI can say so.
            IpcMessage::Ok { .. } => Ok(NetworkInfo {
                name: network_key,
                node_id: Self::node_id(&state),
                ipv6: String::new(),
                pending: true,
            }),
            IpcMessage::Error { message } => Err(RayError::JoinFailed(message)),
            other => Err(RayError::JoinFailed(format!(
                "unexpected join response: {other:?}"
            ))),
        }
    }

    /// Create a new network (default CLOSED membership) and register this node as
    /// its coordinator. `name` is optional; the core generates one if absent.
    pub fn create(&self, name: Option<String>) -> Result<NetworkInfo, RayError> {
        let state = self.state()?;

        // Default (CLOSED) membership: `GroupMode::Restricted`. No `--open`
        // affordance on mobile.
        let result = self
            .runtime
            .block_on(state.create_network(GroupMode::default(), name, None));

        match result {
            IpcMessage::Created { name, my_ipv6, .. } => Ok(NetworkInfo {
                name,
                node_id: Self::node_id(&state),
                ipv6: my_ipv6.to_string(),
                pending: false,
            }),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected create response: {other:?}"
            ))),
        }
    }

    /// Mint a single-use invite code for `network` (default 7d TTL), to share.
    pub fn invite(&self, network: String) -> Result<String, RayError> {
        let state = self.state()?;
        // 7 days, single-use, coordinator-picked hostname (None).
        let result =
            self.runtime
                .block_on(state.invite_create(&network, 7 * 24 * 60 * 60, None, false));
        match result {
            IpcMessage::InviteCreated { code, .. } => Ok(code),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected invite response: {other:?}"
            ))),
        }
    }

    /// Leave `network`: tears down its runtime and removes it from config.
    pub fn leave(&self, network: String) -> Result<(), RayError> {
        let state = self.state()?;
        match self.runtime.block_on(state.leave_network(&network)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected leave response: {other:?}"
            ))),
        }
    }

    /// Set this device's hostname on `network`. Validated by the core.
    pub fn set_hostname(&self, network: String, hostname: String) -> Result<(), RayError> {
        let state = self.state()?;
        match self
            .runtime
            .block_on(state.set_hostname(&network, &hostname))
        {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::BadCode(message)),
            other => Err(RayError::Network(format!(
                "unexpected set_hostname response: {other:?}"
            ))),
        }
    }

    /// The device's default hostname (seeds every join, incl. pairing
    /// auto-joins). Empty when unset. Config-only; safe before `start`.
    pub fn default_hostname(&self) -> String {
        config::load()
            .ok()
            .and_then(|c| c.default_hostname)
            .unwrap_or_default()
    }

    /// Set the device's default hostname. Validated with the core's hostname
    /// rules; rejected names leave the stored value untouched. Config-only;
    /// safe before `start`.
    pub fn set_default_hostname(&self, name: String) -> Result<(), RayError> {
        if !hostname::is_valid_hostname(&name) {
            return Err(RayError::BadCode(format!(
                "invalid hostname '{name}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
            )));
        }
        config::update_settings(|cfg| {
            cfg.default_hostname = Some(name);
            Ok(())
        })
        .map_err(RayError::network)?;
        Ok(())
    }

    /// Current firewall posture and rules.
    pub fn firewall_show(&self) -> Result<FirewallStateInfo, RayError> {
        let state = self.state()?;
        let IpcMessage::FirewallState {
            default_inbound,
            default_outbound,
            disabled,
            rules,
            ..
        } = state.firewall_show()
        else {
            return Err(RayError::Network(
                "unexpected firewall response".to_string(),
            ));
        };
        Ok(FirewallStateInfo {
            default_inbound: default_inbound.to_string(),
            default_outbound: default_outbound.to_string(),
            disabled,
            rules: rules
                .into_iter()
                .map(|v| FirewallRuleInfo {
                    direction: v.direction.to_string(),
                    action: v.action.to_string(),
                    protocol: v.protocol.to_string(),
                    port: v.port,
                    peer: v.peer,
                    network: v.network,
                })
                .collect(),
        })
    }

    /// Add a firewall rule. `port`/`peer`/`network` are optional.
    pub fn firewall_add(
        &self,
        direction: String,
        action: String,
        protocol: String,
        port: Option<String>,
        peer: Option<String>,
        network: Option<String>,
    ) -> Result<(), RayError> {
        let state = self.state()?;
        let direction: Direction = direction.parse().map_err(RayError::Network)?;
        let action: Action = action.parse().map_err(RayError::Network)?;
        let protocol: Protocol = protocol.parse().map_err(RayError::Network)?;
        let result = self.runtime.block_on(state.firewall_add(
            direction,
            action,
            protocol,
            port.as_deref(),
            peer.as_deref(),
            network.as_deref(),
        ));
        match result {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected firewall response: {other:?}"
            ))),
        }
    }

    /// Remove the rule at the given index (as shown by firewall_show).
    pub fn firewall_remove(&self, index: u32) -> Result<(), RayError> {
        let state = self.state()?;
        match state.firewall_remove(index as usize) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected firewall response: {other:?}"
            ))),
        }
    }

    /// Set the inbound default action ("allow" or "deny"). The outbound default
    /// stays "allow"; inbound ICMP-allow is a separate built-in and is unaffected.
    pub fn firewall_set_default_inbound(&self, action: String) -> Result<(), RayError> {
        let state = self.state()?;
        let action: Action = action.parse().map_err(RayError::Network)?;
        match state.firewall_default(action) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected firewall response: {other:?}"
            ))),
        }
    }

    // --- Notifications: pending file offers, connect requests, join requests ---

    /// Send a file to a peer. `path` is a readable file path (the core reads its
    /// bytes and adds them to the blob store); `peer` is any identifier the core
    /// resolves: a hostname, mesh address, short id, or full endpoint id.
    /// Offers the file over `FILES_ALPN`; the recipient pulls the bytes on accept
    /// (or auto-accepts if it is one of the sender's own paired devices). Needs
    /// only the control plane ([`Node::start`]), not the tunnel, but the peer must
    /// be reachable. Runs to completion synchronously; callers drive it off the UI
    /// thread (Android's share flow runs it in a foreground service).
    /// The host OS reported a network change (Wi-Fi/cellular switch, roam,
    /// airplane-mode flip). Android blocks netlink route updates for apps, so
    /// the core cannot observe these itself (netwatch's Android monitor is a
    /// stub): the app must forward `ConnectivityManager` default-network
    /// callbacks here. The core rebinds its QUIC socket and re-probes paths.
    /// Cheap, idempotent, safe to call on every callback; a no-op before
    /// [`Node::start`].
    pub fn network_changed(&self) {
        if let Ok(state) = self.state() {
            self.runtime.block_on(state.network_changed());
        }
    }

    /// Dial an idle peer to check it is really reachable before sending to it,
    /// and leave the link up so the file offer lands on an awake device. Returns
    /// false when the peer did not answer; the caller can still send, the offer
    /// just parks in the outbox until the peer comes back.
    ///
    /// Blocks for up to the core's lazy-dial timeout. Cheap and immediate when a
    /// live connection already exists. A stopped node returns false.
    pub fn wake_peer(&self, peer: String) -> bool {
        let Ok(state) = self.state() else {
            return false;
        };
        self.runtime.block_on(state.wake_peer(&peer))
    }

    pub fn send_file(&self, path: String, peer: String) -> Result<(), RayError> {
        let state = self.state()?;
        match self.runtime.block_on(state.send_file(&path, &peer)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected send response: {other:?}"
            ))),
        }
    }

    /// Incoming file offers waiting to be accepted or declined.
    pub fn list_file_offers(&self) -> Result<Vec<FileOffer>, RayError> {
        let state = self.state()?;
        match state.list_files() {
            IpcMessage::FileList { files, .. } => Ok(files
                .into_iter()
                .map(|f| FileOffer {
                    id: f.id,
                    from: f.from,
                    filename: f.filename,
                    size: f.size,
                    mime_type: f.mime_type,
                    own_device: f.own_device,
                })
                .collect()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected files response: {other:?}"
            ))),
        }
    }

    /// Outbound sends still sitting in the daemon's outbox, waiting for their
    /// peer. These are the only sends that can still be called off: once the
    /// offer is delivered the entry leaves the outbox and the file is the
    /// recipient's to accept or decline.
    pub fn list_queued_sends(&self) -> Result<Vec<QueuedSend>, RayError> {
        let state = self.state()?;
        match state.list_files() {
            IpcMessage::FileList { outbox, .. } => Ok(outbox
                .into_iter()
                .map(|e| QueuedSend {
                    id: e.id,
                    peer: e.peer,
                    filename: e.filename,
                    size: e.size,
                })
                .collect()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected files response: {other:?}"
            ))),
        }
    }

    /// Call off a queued send, by the id from [`Node::list_queued_sends`].
    /// Fails if the offer has already been delivered, since there is nothing
    /// left on this side to withdraw.
    pub fn cancel_send(&self, id: u64) -> Result<(), RayError> {
        let state = self.state()?;
        match state.cancel_send(id) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected cancel response: {other:?}"
            ))),
        }
    }

    /// In-flight and recently finished transfers, both directions. Terminal entries
    /// linger for 60s so a poller can see them before they expire. Cheap: safe to
    /// poll on a timer while a notification is on screen.
    pub fn list_transfers(&self) -> Result<Vec<Transfer>, RayError> {
        let state = self.state()?;
        Ok(state
            .list_transfers()
            .into_iter()
            .map(|t| Transfer {
                id: t.id,
                outgoing: t.outgoing,
                peer: t.peer,
                filename: t.filename,
                size: t.size,
                transferred: t.transferred,
                state: match t.state {
                    transfers::TransferState::Offered => TransferState::Offered,
                    transfers::TransferState::Transferring => TransferState::Transferring,
                    transfers::TransferState::Done => TransferState::Done,
                    transfers::TransferState::Failed => TransferState::Failed,
                },
            })
            .collect())
    }

    /// Accept a file offer, saving it under `output_dir` (an app-writable path).
    pub fn accept_file_offer(&self, id: u64, output_dir: String) -> Result<(), RayError> {
        let state = self.state()?;
        let out = if output_dir.is_empty() {
            None
        } else {
            Some(output_dir)
        };
        match self.runtime.block_on(state.accept_file(id, out, None)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected files response: {other:?}"
            ))),
        }
    }

    /// Decline a file offer without downloading it.
    pub fn reject_file_offer(&self, id: u64) -> Result<(), RayError> {
        let state = self.state()?;
        match state.reject_file(id) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected files response: {other:?}"
            ))),
        }
    }

    /// Incoming `ray connect` friend requests waiting for a decision.
    pub fn list_connect_requests(&self) -> Result<Vec<PendingRequest>, RayError> {
        let state = self.state()?;
        match state.list_connections() {
            IpcMessage::PendingRequests { requests } => Ok(requests
                .into_iter()
                .map(|r| PendingRequest {
                    short_id: r.short_id,
                    hostname: r.hostname,
                    waiting_secs: r.waiting_secs,
                })
                .collect()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected connections response: {other:?}"
            ))),
        }
    }

    /// Approve an incoming connect request (mints a direct 2-peer network).
    pub fn approve_connect_request(&self, short_id: String) -> Result<(), RayError> {
        let state = self.state()?;
        match self.runtime.block_on(state.approve_connection(&short_id)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected connections response: {other:?}"
            ))),
        }
    }

    /// Decline an incoming connect request.
    pub fn reject_connect_request(&self, short_id: String) -> Result<(), RayError> {
        let state = self.state()?;
        match state.reject_connect(&short_id) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected connections response: {other:?}"
            ))),
        }
    }

    /// Join requests awaiting approval on a network we coordinate.
    pub fn list_join_requests(&self, network: String) -> Result<Vec<PendingRequest>, RayError> {
        let state = self.state()?;
        match state.list_requests(&network) {
            IpcMessage::PendingRequests { requests } => Ok(requests
                .into_iter()
                .map(|r| PendingRequest {
                    short_id: r.short_id,
                    hostname: r.hostname,
                    waiting_secs: r.waiting_secs,
                })
                .collect()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected requests response: {other:?}"
            ))),
        }
    }

    /// Approve a pending join request on a network we coordinate.
    pub fn accept_join_request(&self, network: String, short_id: String) -> Result<(), RayError> {
        let state = self.state()?;
        match self
            .runtime
            .block_on(state.accept_request(&network, &short_id))
        {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected requests response: {other:?}"
            ))),
        }
    }

    /// Deny a pending join request on a network we coordinate.
    pub fn deny_join_request(&self, network: String, short_id: String) -> Result<(), RayError> {
        let state = self.state()?;
        match state.deny_request(&network, &short_id) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected requests response: {other:?}"
            ))),
        }
    }

    /// Whether this device already holds a device cert (it was paired to a
    /// primary). A paired device cannot start or accept further pairing, so the
    /// UI hides the pairing controls when this is true. Returns false before
    /// [`Node::start`] or when no cert is present.
    pub fn is_paired(&self) -> bool {
        self.state()
            .map(|s| s.current_device_cert().is_some())
            .unwrap_or(false)
    }

    /// Begin pairing: returns a ticket to show (as QR) to a device that will
    /// scan and call `pair`.
    pub fn start_pairing(&self) -> Result<String, RayError> {
        let state = self.state()?;
        match state.start_pairing() {
            IpcMessage::PairingTicket { ticket } => Ok(ticket),
            IpcMessage::Error { message } => Err(RayError::PairFailed(message)),
            other => Err(RayError::PairFailed(format!(
                "unexpected pairing response: {other:?}"
            ))),
        }
    }

    /// Pair this device with a primary device using a scanned/pasted pairing
    /// ticket (`bs58(endpoint_id[32] || secret[32])`).
    pub fn pair(&self, ticket: String) -> Result<(), RayError> {
        let state = self.state()?;

        let (endpoint, secret) = control::decode_pairing_ticket(&ticket)
            .map_err(|e| RayError::BadCode(e.to_string()))?;

        let result = self
            .runtime
            .block_on(state.pair_with_device(endpoint, secret.to_vec()));

        match result {
            IpcMessage::PairingComplete { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::PairFailed(message)),
            other => Err(RayError::PairFailed(format!(
                "unexpected pair response: {other:?}"
            ))),
        }
    }

    /// Unpair this device from its primary: leave every network it joined under
    /// the shared identity (peers drop it right away) and delete the stored
    /// device cert. Only meaningful when [`Node::is_paired`] is true; a node with
    /// no cert returns an error. Requires [`Node::start`].
    pub fn unpair(&self) -> Result<(), RayError> {
        let state = self.state()?;
        match self.runtime.block_on(state.unpair_self()) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::PairFailed(message)),
            other => Err(RayError::PairFailed(format!(
                "unexpected unpair response: {other:?}"
            ))),
        }
    }

    /// Whether this device has an identity on disk yet.
    ///
    /// False only before anything has started the node, since the first start
    /// mints one. That makes it the "has this person used the app" question, so
    /// the platform can offer a restore on a fresh install and never show that
    /// screen again, with no first-run flag of its own to keep in step.
    ///
    /// Reads a file. Does not need (and does not do) a [`Node::start`].
    pub fn has_identity(&self) -> bool {
        identity::load_existing()
            .map(|k| k.is_some())
            .unwrap_or(false)
    }

    /// Encrypt this device's identity under `password` and return the backup
    /// code, for the platform to hand to a file picker (Drive, Files, whatever
    /// the user has) or a password manager. Format and threat model are in
    /// [`keybackup`]; the same code restores on desktop with
    /// `ray pair restore <code>`.
    ///
    /// Does not need [`Node::start`]: the key is read off disk, and mints one if
    /// the device has none yet, exactly as a start would.
    pub fn backup_identity(&self, password: String) -> Result<IdentityBackup, RayError> {
        let backup = keybackup::backup_current_identity(&password).map_err(RayError::network)?;
        // The public key is fine to log; the code never is.
        tracing::info!(id = %backup.public_key, "wrote identity backup");
        Ok(IdentityBackup {
            code: backup.code,
            public_key: backup.public_key,
        })
    }

    /// Replace this device's identity with the one in `code`.
    ///
    /// Refuses in two cases the caller is expected to handle rather than force:
    /// [`RayError::NodeRunning`] if the node has not been stopped (the endpoint
    /// is bound to the old key), and [`RayError::IdentityExists`] if a different
    /// identity is already on the device and `replace_existing` is false. Call
    /// again with the flag once the user has confirmed.
    ///
    /// Restoring makes this device the primary holder of the identity, so any
    /// device cert from a previous pairing is deleted: it attests the old key
    /// and would otherwise sit there claiming this device is somebody's
    /// secondary. Restoring the identity already on the device is a no-op
    /// success.
    ///
    /// Returns the restored identity's public key. The caller must restart the
    /// node afterwards for it to take effect.
    pub fn restore_identity(
        &self,
        code: String,
        password: String,
        replace_existing: bool,
    ) -> Result<String, RayError> {
        if self.state.lock().unwrap().is_some() {
            return Err(RayError::NodeRunning);
        }

        let key =
            keybackup::decrypt(&code, &password).map_err(|e| RayError::BadBackup(e.to_string()))?;
        let restored = key.public().to_string();

        // Deliberately not `load_or_create`: on a device with no identity yet
        // that would mint one, and the restore would then have to ask the user
        // for permission to overwrite a key it had just invented.
        if let Some(existing) = identity::load_existing().map_err(RayError::network)? {
            if existing.public() == key.public() {
                tracing::info!(id = %restored, "restore: identity already on this device");
                return Ok(restored);
            }
            if !replace_existing {
                return Err(RayError::IdentityExists(existing.public().to_string()));
            }
        }

        identity::store_secret_key(&key).map_err(RayError::network)?;
        identity::delete_device_cert().map_err(RayError::network)?;

        tracing::info!(id = %restored, "restored identity from backup");
        Ok(restored)
    }

    /// Point the Magic DNS resolver at the phone's DNS so non-`.ray` queries are
    /// forwarded instead of refused. On Android there is no `resolv.conf` to
    /// capture (the desktop path), so the platform passes upstreams here before
    /// the tunnel captures all DNS. Requires [`Node::start`] first.
    ///
    /// Each entry may be a bare IPv4 (forwarded as cleartext UDP on port 53) or
    /// an `ip:port` socket address. The platform points this at a loopback
    /// `DnsResolver.rawQuery` proxy (`127.0.0.1:<port>`) so non-`.ray` lookups
    /// honor the system Private DNS (DoT/DoH); entries that parse as neither are
    /// ignored.
    pub fn set_dns_upstreams(&self, servers: Vec<String>) -> Result<(), RayError> {
        let state = self.state()?;
        let parsed: Vec<SocketAddr> = servers
            .iter()
            .filter_map(|s| {
                s.parse::<SocketAddr>().ok().or_else(|| {
                    s.parse::<Ipv4Addr>()
                        .ok()
                        .map(|ip| SocketAddr::from((ip, 53u16)))
                })
            })
            .collect();
        state.set_dns_upstream_addrs(parsed);
        Ok(())
    }

    /// Bring the data plane up over the `VpnService` fd: attach the fd's
    /// reader/writer to the running daemon and mark the data plane active.
    /// Requires [`Node::start`] first.
    pub fn up(&self, tun_fd: i32) -> Result<(), RayError> {
        #[cfg(not(target_os = "android"))]
        {
            let _ = tun_fd;
            Err(RayError::Network(
                "VpnService data plane is only supported on Android".to_owned(),
            ))
        }
        #[cfg(target_os = "android")]
        {
            // Kotlin calls `up(pfd.detachFd())`, so this descriptor is ours before
            // the first line of the body runs: its `ParcelFileDescriptor` no longer
            // owns anything and cannot close it for us. Take ownership here, ahead
            // of anything fallible, so every early return below closes it.
            //
            // Leaking it on a failure path is not a mere fd leak: the fd is the only
            // handle on the `VpnService` interface, so an unowned one keeps that
            // interface established for the life of the process. Android tears the
            // VPN down when the interface disappears (the framework's
            // `interfaceRemoved` observer), so a stranded fd leaves the system
            // showing a connected VPN while the app has fallen back to standby and
            // reports the tunnel off, with no way to disconnect short of Settings.
            // SAFETY: `tun_fd` came from Kotlin's `detachFd()`; nothing else owns or
            // closes it, so wrapping it here closes it exactly once.
            let tun = unsafe { OwnedFd::from_raw_fd(tun_fd) };

            let state = self.state()?;

            // `AndroidTunReader`/`AndroidTunWriter` wrap the fd in a `tokio` `AsyncFd`,
            // which registers with the reactor and must be built inside the runtime
            // context. `up` runs on a plain service thread, so enter the runtime for
            // the duration of this call before constructing them.
            let _guard = self.runtime.enter();

            // The writer owns a single `dup` of the fd; the reader consumes the
            // detached fd itself. Build the writer's dup first, while `tun` is still
            // owned here, so a failure closes it. Two owned fds, each closed exactly
            // once on drop (when `detach_tun`/`Drop` tears the tasks down).
            let writer = AndroidTunWriter::new(tun.as_raw_fd()).map_err(RayError::network)?;
            let reader = AndroidTunReader::new(tun).map_err(RayError::network)?;

            self.runtime.block_on(async {
                state.attach_tun(reader, writer).await;
                // Mark the data plane active (and configure Magic DNS) the same way
                // `run_daemon` does after attaching the desktop TUN.
                state.activate(None).await;
            });
            Ok(())
        }
    }

    /// Tear the data plane down (stop the forward loop, close the fds) while
    /// keeping the control plane connected. Requires [`Node::start`] first.
    pub fn down(&self) -> Result<(), RayError> {
        #[cfg(not(target_os = "android"))]
        {
            Err(RayError::Network(
                "VpnService data plane is only supported on Android".to_owned(),
            ))
        }
        #[cfg(target_os = "android")]
        {
            let state = self.state()?;
            state.detach_tun();
            Ok(())
        }
    }

    /// Fully tear down the control plane so the device goes offline: peers can
    /// no longer reach it and it drops out of every network's membership view.
    /// Cancels the daemon shutdown token and releases the shared state; the
    /// endpoint closes once the background tasks wind down. A later
    /// [`Node::start`] rebuilds from scratch. No-op if not started.
    ///
    /// This is the mobile "disable" semantics: unlike [`Node::down`] (standby,
    /// control plane stays connected), `stop` takes the node offline outright.
    pub fn stop(&self) {
        // Take the Arc out under the lock so the next `start` sees `None` and
        // rebuilds a fresh daemon. Block until the endpoint has closed so the
        // rebuilt endpoint does not overlap the old one (which would leave a
        // coordinator holding a stale session and the device showing offline).
        tracing::info!("Node.stop: taking node fully offline (mobile disable)");
        let state = self.state.lock().unwrap().take();
        if let Some(state) = state {
            // Tear the data plane down first: abort the TUN writer + mesh tasks so
            // both dups of the Android VPN fd close and the interface comes down.
            // `shutdown_and_close` cancels the token, shuts the router down and
            // closes the endpoint, but never touches the TUN tasks; the writer
            // does not observe the token either, so without this the fd would
            // leak and the tunnel would linger after disable.
            state.detach_tun();
            // Bounded: this runs on an Android main/binder thread by way of
            // NodeHolder.stopNode, so a wedged protocol handler or store actor
            // must not hang the app. Giving up here can leave the blob store's
            // redb lock held, in which case the next start() waits out its own
            // timeout and reports a failure. A recoverable failure beats a frozen
            // UI.
            let closed = self.runtime.block_on(async {
                timeout(SHUTDOWN_TIMEOUT, state.shutdown_and_close())
                    .await
                    .is_ok()
            });
            if closed {
                tracing::info!("Node.stop: data plane detached and endpoint closed");
            } else {
                tracing::error!(
                    timeout_secs = SHUTDOWN_TIMEOUT.as_secs(),
                    "Node.stop: shutdown timed out; the node may not restart until the app is restarted"
                );
            }
        } else {
            tracing::info!("Node.stop: no live state (already stopped)");
        }
    }

    /// Peers + addresses + running flag + per-network detail for the UI.
    /// Empty snapshot before [`Node::start`].
    pub fn status(&self) -> Status {
        let Some(state) = self.state.lock().unwrap().as_ref().cloned() else {
            // Stopped (the user disabled the tunnel): the control plane is gone,
            // so there is no live snapshot. Read the saved networks off disk and
            // present them offline (running: false, every peer offline) so the UI
            // can still list the user's networks with a red status dot.
            return saved_networks_status();
        };

        let IpcMessage::StatusResponse {
            endpoint_id,
            active,
            networks,
            pending_networks,
            inactive_networks,
            ..
        } = state.status()
        else {
            // Not the reply we asked for. Fall back to the saved networks rather
            // than a blank snapshot: an empty list is indistinguishable from
            // having joined none, which is the worst thing to show here.
            return saved_networks_status();
        };

        let mut detail = Vec::with_capacity(networks.len() + inactive_networks.len());
        let mut flat_peers = Vec::new();
        for n in &networks {
            let peers: Vec<PeerInfo> = n.peers.iter().map(peer_info).collect();
            flat_peers.extend(peers.iter().map(|p| PeerInfo {
                ipv6: p.ipv6.clone(),
                node_id: p.node_id.clone(),
                hostname: p.hostname.clone(),
                state: p.state,
            }));
            detail.push(NetworkDetail {
                name: n.name.clone(),
                ipv6: n.my_ipv6.to_string(),
                hostname: n.my_hostname.clone().unwrap_or_default(),
                is_coordinator: n.role.is_coordinator(),
                peers,
                state: NetworkConnState::Connected,
                reason: None,
            });
        }
        // The node's own mesh address derives from its identity, so it needs no
        // joined network to be known. It is what the tunnel binds.
        let ipv6 = rayfish::membership::derive_ipv6(&endpoint_id).to_string();
        // `flat_peers` stays live-only on purpose: it is the set of peers we
        // hold connection state for, and an unregistered network has none.
        let detail = merge_networks(detail, &inactive_networks, &ipv6);

        Status {
            running: active,
            node_id: endpoint_id.to_string(),
            ipv6,
            peers: flat_peers,
            networks: detail,
            pending_networks,
        }
    }

    /// Lightweight health vitals for auto-telemetry. Reuses `status()` for mesh
    /// state and reads the diagnostics counters. Cumulative WARN/ERROR counts
    /// (since process start); reading does not reset them.
    pub fn health_snapshot(&self) -> HealthSnapshot {
        let s = self.status();
        let networks: Vec<NetworkHealth> = s
            .networks
            .iter()
            .map(|n| NetworkHealth {
                name: n.name.clone(),
                connected: n.peers.iter().any(|p| p.state == PeerConnState::Active),
            })
            .collect();
        let peers_online = s
            .peers
            .iter()
            .filter(|p| p.state == PeerConnState::Active)
            .count() as u32;
        HealthSnapshot {
            running: s.running,
            network_count: s.networks.len() as u32,
            peers_online,
            networks,
            mesh_up: peers_online > 0,
            node_id: s.node_id.chars().take(10).collect(),
            mesh_ipv6: s.ipv6.clone(),
            warn_count: diag::warn_count(),
            error_count: diag::error_count(),
            recent_errors: diag::recent_errors(),
        }
    }

    /// The full buffered core log, for the "Send diagnostics" button.
    pub fn log_snapshot(&self) -> String {
        diag::snapshot()
    }

    /// Follow a `rayfish://join/<code>` or `rayfish://pair/<ticket>` deep link,
    /// dispatching to [`Node::join`] / [`Node::pair`]. Requires [`Node::start`].
    pub fn handle_link(&self, uri: String) -> Result<LinkAction, RayError> {
        let link =
            deeplink::parse_rayfish_uri(&uri).map_err(|e| RayError::BadCode(e.to_string()))?;
        match link {
            RayfishLink::Join(code) => self.join(code).map(LinkAction::Joined),
            RayfishLink::Pair(ticket) => self.pair(ticket).map(|()| LinkAction::Paired),
        }
    }

    /// Accept any code the user pastes or scans and route it: a `rayfish://`
    /// deep link, a bare invite code, or a bare pairing ticket. The two bare
    /// forms are distinct encodings, so we can tell them apart. A pairing ticket
    /// is checked before falling through to `join`, because otherwise it would
    /// hit `join`'s bare-room-id fallback and fail with a confusing "invalid
    /// network key" error. Everything that is not a pairing ticket goes to
    /// `join`, which still handles both a full invite and a bare room id.
    pub fn submit_code(&self, input: String) -> Result<LinkAction, RayError> {
        let code = input.trim().to_string();
        if code.starts_with("rayfish://") {
            return self.handle_link(code);
        }
        if control::decode_pairing_ticket(&code).is_ok() {
            return self.pair(code).map(|()| LinkAction::Paired);
        }
        self.join(code).map(LinkAction::Joined)
    }
}

/// Process-wide lock serializing tests that construct a [`Node`], since
/// `Node::new` points the process-wide config override at its argument and lib
/// tests share one process across parallel threads. Without it a second
/// `Node::new` redirects config reads out from under a test that is midway
/// through writing and reading its own config dir, and the write lands in one
/// directory while the read comes back empty from another.
#[cfg(test)]
static CONFIG_DIR_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod device_name_tests {
    use super::*;

    #[test]
    fn set_default_hostname_persists_and_rejects_invalid() {
        // Serialize against the other test that builds a Node, so its config
        // directory cannot bleed into the reads below.
        let _dir_lock = CONFIG_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Isolated config dir; Node::new points the config override at it.
        let dir = std::env::temp_dir().join(format!("rayfish-dn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let node = Node::new(dir.to_string_lossy().to_string());

        #[cfg(not(windows))]
        {
            node.set_default_hostname("my-phone".into()).unwrap();
            assert_eq!(node.default_hostname(), "my-phone");
            assert_eq!(
                rayfish::config::load().unwrap().default_hostname.as_deref(),
                Some("my-phone")
            );

            // Invalid name is rejected and does not overwrite the stored value.
            assert!(node.set_default_hostname("BAD NAME".into()).is_err());
            assert_eq!(node.default_hostname(), "my-phone");
        }

        assert!(node.up(-1).is_err());
        assert!(node.down().is_err());
    }
}

#[cfg(all(test, target_os = "android"))]
mod tun_fd_ownership_tests {
    use super::*;
    use std::os::fd::RawFd;
    use std::time::Duration;

    /// A connected socket pair standing in for the `VpnService` tun fd: one end
    /// is handed to `up()` (as Kotlin hands over the fd it detached), the other
    /// is kept here to observe whether that end was closed. Watching the peer
    /// rather than the fd number itself makes the assertion immune to another
    /// thread reopening the same number.
    fn socket_pair() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0,
            "socketpair should succeed"
        );
        // The observer end must not block when the other end is still open.
        let flags = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
        assert_ne!(flags, -1);
        assert_ne!(
            unsafe { libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1
        );
        (fds[0], fds[1])
    }

    /// True once `peer`'s counterpart has been closed: a read on a socket whose
    /// peer is gone returns 0 (EOF), where a live peer with no data pending
    /// returns -1/EAGAIN. Polled briefly because the close can land on a runtime
    /// worker thread rather than the calling one.
    fn peer_closed(peer: RawFd) -> bool {
        let mut byte = 0u8;
        for _ in 0..200 {
            let n = unsafe { libc::read(peer, (&raw mut byte).cast::<libc::c_void>(), 1) };
            if n == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    /// Kotlin calls `up(pfd.detachFd())`, so the fd is already detached by the
    /// time `up` is entered: it owns that descriptor on every path out,
    /// including the failures. Leaking it leaves the `VpnService` interface
    /// established with nobody able to close it, so Android keeps showing a
    /// connected VPN while the app believes the tunnel is off (issue #116).
    #[test]
    fn up_closes_the_detached_fd_when_the_node_is_not_started() {
        // Held for the whole test: Node::new below moves the config override,
        // which another test's config reads would otherwise pick up.
        let _dir_lock = CONFIG_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = std::env::temp_dir().join(format!("rayfish-updfd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let node = Node::new(dir.to_string_lossy().to_string());

        let (tun, observer) = socket_pair();
        // Never started, so this is the `NotStarted` early return.
        assert!(node.up(tun).is_err(), "up() should fail on a stopped node");
        assert!(
            peer_closed(observer),
            "up() must close the fd it was handed when it fails, or the tunnel lingers"
        );
        unsafe { libc::close(observer) };
    }
}

#[cfg(test)]
mod network_state_tests {
    use std::collections::BTreeMap;
    use std::net::Ipv6Addr;

    use rayfish::ipc::{InactiveNetwork, NetworkRole, NetworkStatus, PeerState, PeerStatus};

    use super::*;

    fn peer(hostname: &str) -> PeerStatus {
        PeerStatus {
            endpoint_id: iroh::SecretKey::generate().public(),
            ipv6: Ipv6Addr::LOCALHOST,
            hostname: Some(hostname.to_string()),
            user_identity: None,
            is_own_device: false,
            incompatible: false,
            connection: None,
            // The daemon projects a saved network's roster with every peer
            // offline: it is not registered, so there is no link to any of them.
            state: PeerState::Offline,
            exit_node: false,
            exit_in_use: false,
            is_coordinator: false,
        }
    }

    fn saved(name: &str, peers: Vec<PeerStatus>) -> NetworkStatus {
        NetworkStatus {
            name: name.to_string(),
            role: NetworkRole::Member,
            my_ipv6: Ipv6Addr::LOCALHOST,
            my_hostname: Some("phone".to_string()),
            network_key: None,
            member_count: peers.len(),
            peers,
            pending_suggestions: 0,
            pending_requests: 0,
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            my_exit_node: None,
            exit_offering: false,
            incompatible: None,
        }
    }

    fn live(name: &str) -> NetworkDetail {
        NetworkDetail {
            name: name.to_string(),
            ipv6: "200::1".to_string(),
            hostname: "phone".to_string(),
            is_coordinator: false,
            peers: Vec::new(),
            state: NetworkConnState::Connected,
            reason: None,
        }
    }

    /// A cold start has every saved network unregistered for the seconds its
    /// restore takes. Nothing has failed yet, so the row reads as in progress —
    /// not as an error, and above all not as absent.
    #[test]
    fn a_restore_that_has_not_failed_yet_reads_as_connecting() {
        let net = InactiveNetwork {
            name: "field".to_string(),
            reason: None,
            saved: Some(saved("field", vec![])),
        };
        let detail = inactive_network_detail(&net, "200::9");
        assert_eq!(detail.state, NetworkConnState::Connecting);
        assert_eq!(detail.reason, None);
    }

    /// Once an attempt has actually failed, the daemon has a one-line reason and
    /// the row has to carry it: it is the only place the user can see why, short
    /// of reading the log off the device.
    #[test]
    fn a_failed_restore_reads_as_not_connected_and_keeps_the_reason() {
        let net = InactiveNetwork {
            name: "dgrr-peer".to_string(),
            reason: Some("could not fetch group blob from any peer".to_string()),
            saved: Some(saved("dgrr-peer", vec![])),
        };
        let detail = inactive_network_detail(&net, "200::9");
        assert_eq!(detail.state, NetworkConnState::NotConnected);
        assert_eq!(
            detail.reason.as_deref(),
            Some("could not fetch group blob from any peer")
        );
    }

    /// The saved projection is what makes the row worth opening: its roster,
    /// hostname and address come from the daemon's config, so a network that is
    /// still connecting shows its members rather than an empty card.
    #[test]
    fn an_unregistered_network_carries_its_saved_roster_offline() {
        let net = InactiveNetwork {
            name: "field".to_string(),
            reason: None,
            saved: Some(saved("field", vec![peer("laptop"), peer("desktop")])),
        };
        let detail = inactive_network_detail(&net, "200::9");
        assert_eq!(detail.hostname, "phone");
        assert_eq!(detail.ipv6, Ipv6Addr::LOCALHOST.to_string());
        assert_eq!(detail.peers.len(), 2);
        assert!(
            detail
                .peers
                .iter()
                .all(|p| p.state == PeerConnState::Offline),
            "an unregistered network has no link to any of its peers"
        );
    }

    /// A daemon predating the `saved` projection sends the name alone. The row
    /// still has to appear, addressed with this device's own mesh address.
    #[test]
    fn a_network_without_a_saved_projection_degrades_to_a_name_only_row() {
        let net = InactiveNetwork {
            name: "homelab".to_string(),
            reason: Some("runs mesh protocol v2".to_string()),
            saved: None,
        };
        let detail = inactive_network_detail(&net, "200::9");
        assert_eq!(detail.name, "homelab");
        assert_eq!(detail.ipv6, "200::9");
        assert!(detail.peers.is_empty());
        assert_eq!(detail.state, NetworkConnState::NotConnected);
    }

    /// Live and unregistered networks share one alphabetically sorted list, so a
    /// network does not jump position when its restore lands.
    #[test]
    fn merged_networks_are_one_alphabetical_list() {
        let inactive = [
            InactiveNetwork {
                name: "alpha".to_string(),
                reason: None,
                saved: Some(saved("alpha", vec![])),
            },
            InactiveNetwork {
                name: "zulu".to_string(),
                reason: None,
                saved: Some(saved("zulu", vec![])),
            },
        ];
        let merged = merge_networks(vec![live("Mike"), live("bravo")], &inactive, "200::9");
        let names: Vec<&str> = merged.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["alpha", "bravo", "Mike", "zulu"]);
        assert_eq!(merged[1].state, NetworkConnState::Connected);
        assert_eq!(merged[3].state, NetworkConnState::Connecting);
    }
}
