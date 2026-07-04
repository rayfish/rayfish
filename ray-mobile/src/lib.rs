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

mod android_tun;

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

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use android_tun::{AndroidTunReader, AndroidTunWriter};
use rayfish::config;
use rayfish::control;
use rayfish::daemon::{DaemonState, build_headless};
use rayfish::deeplink::{self, RayfishLink};
use rayfish::firewall::{Action, Direction, Protocol};
use rayfish::identity;
use rayfish::invite;
use rayfish::ipc::IpcMessage;
use rayfish::membership::{self, GroupMode};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

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
    pub ipv4: String,
    pub ipv6: String,
    /// True when the join was queued for coordinator approval (no IP yet).
    pub pending: bool,
}

/// One peer in a network snapshot. `online` reflects a live connection.
#[derive(uniffi::Record)]
pub struct PeerInfo {
    pub ipv4: String,
    pub node_id: String,
    pub hostname: String,
    pub online: bool,
}

/// One network this node belongs to, with its peers.
#[derive(uniffi::Record)]
pub struct NetworkDetail {
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub hostname: String,
    pub is_coordinator: bool,
    pub peers: Vec<PeerInfo>,
}

/// Health/addresses/networks snapshot for the UI.
#[derive(uniffi::Record)]
pub struct Status {
    pub running: bool,
    pub node_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub peers: Vec<PeerInfo>,
    pub networks: Vec<NetworkDetail>,
    pub pending_networks: Vec<String>,
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

/// Build an offline status snapshot from the on-disk config, used when the node
/// is stopped so the UI can still show the user's saved networks. Everything is
/// reported offline: `running` is false and every peer's `online` is false. The
/// per-network address/hostname come straight from the saved membership.
///
/// The device's own node id and mesh addresses are derived from the persisted
/// identity, so they stay populated while stopped (they never change with the
/// tunnel state) instead of blanking to "-" in the UI.
fn saved_networks_status() -> Status {
    let empty = Status {
        running: false,
        node_id: String::new(),
        ipv4: String::new(),
        ipv6: String::new(),
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
    let (node_id, device_ipv4, device_ipv6) = match identity::load_or_create() {
        Ok(secret) => {
            let id = secret.public();
            // Prefer the assigned per-network IPv4 (it accounts for any
            // collision-avoidance offset); otherwise use the base derived
            // address. IPv6 is always derived from the identity.
            let ipv4 = cfg
                .networks
                .iter()
                .find_map(|n| n.my_ip)
                .unwrap_or_else(|| membership::derive_ip(&id));
            (
                id.to_string(),
                ipv4.to_string(),
                membership::derive_ipv6(&id).to_string(),
            )
        }
        Err(_) => return empty,
    };
    // Same stable alphabetical order as the live snapshot below.
    let mut sorted = cfg.networks.clone();
    sorted.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    let networks = sorted
        .iter()
        .map(|net| {
            // Exclude our own roster entry (matched by our IP) so the peer list
            // mirrors the live snapshot, which lists only the other members.
            let peers = net
                .members
                .iter()
                .filter(|m| Some(m.ip) != net.my_ip)
                .map(|m| PeerInfo {
                    ipv4: m.ip.to_string(),
                    node_id: m.identity.to_string(),
                    hostname: m.hostname.clone().unwrap_or_default(),
                    online: false,
                })
                .collect();
            NetworkDetail {
                name: net.name.clone(),
                ipv4: net.my_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                ipv6: String::new(),
                hostname: net.my_hostname.clone().unwrap_or_default(),
                is_coordinator: net.network_secret_key.is_some(),
                peers,
            }
        })
        .collect();
    Status {
        node_id,
        ipv4: device_ipv4,
        ipv6: device_ipv6,
        networks,
        ..empty
    }
}

#[uniffi::export]
impl Node {
    /// `config_dir` is the app-private directory (Kotlin `Context.getFilesDir()`)
    /// where identity + config live. It is exported to the core through
    /// `RAYFISH_CONFIG_DIR`, which `config::config_dir()` honors on Android.
    #[uniffi::constructor]
    pub fn new(config_dir: String) -> Arc<Self> {
        // SAFETY-ish: set before any core call reads config. Single-threaded at
        // construction time.
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", &config_dir) };
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
    pub fn start(&self) -> Result<(), RayError> {
        // Fast path: already started. Check briefly, then release the lock.
        if self.state.lock().unwrap().is_some() {
            return Ok(());
        }

        let state = self
            .runtime
            .block_on(build_headless())
            .map_err(RayError::network)?;

        // Commit under the lock, re-checking for a racing `start` that won while
        // we were building. If one did, keep the winner and drop ours.
        let mut guard = self.state.lock().unwrap();
        if guard.is_none() {
            *guard = Some(state);
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
            false, // auto_accept_files
        ));

        match result {
            IpcMessage::Joined {
                name,
                my_ip,
                my_ipv6,
            } => Ok(NetworkInfo {
                name,
                node_id: Self::node_id(&state),
                ipv4: my_ip.to_string(),
                ipv6: my_ipv6.map(|v| v.to_string()).unwrap_or_default(),
                pending: false,
            }),
            // Closed network without a valid invite: queued for coordinator approval
            // and retried in the background. Report it as pending so the UI can say so.
            IpcMessage::Ok { .. } => Ok(NetworkInfo {
                name: network_key,
                node_id: Self::node_id(&state),
                ipv4: String::new(),
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
            IpcMessage::Created {
                name,
                my_ip,
                my_ipv6,
                ..
            } => Ok(NetworkInfo {
                name,
                node_id: Self::node_id(&state),
                ipv4: my_ip.to_string(),
                ipv6: my_ipv6.map(|v| v.to_string()).unwrap_or_default(),
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

    /// Incoming file offers waiting to be accepted or declined.
    pub fn list_file_offers(&self) -> Result<Vec<FileOffer>, RayError> {
        let state = self.state()?;
        match state.list_files() {
            IpcMessage::FileList { files } => Ok(files
                .into_iter()
                .map(|f| FileOffer {
                    id: f.id,
                    from: f.from,
                    filename: f.filename,
                    size: f.size,
                    mime_type: f.mime_type,
                })
                .collect()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected files response: {other:?}"
            ))),
        }
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

    /// Point the Magic DNS resolver at the phone's real DNS servers so
    /// non-`.ray` queries are forwarded instead of refused. On Android there is
    /// no `resolv.conf` to capture (the desktop path), so the platform reads the
    /// underlying network's DNS servers and passes them here before the tunnel
    /// captures all DNS. Non-IPv4 entries are ignored (the resolver forwards
    /// over IPv4). Requires [`Node::start`] first.
    pub fn set_dns_upstreams(&self, servers: Vec<String>) -> Result<(), RayError> {
        let state = self.state()?;
        let parsed: Vec<Ipv4Addr> = servers.iter().filter_map(|s| s.parse().ok()).collect();
        state.set_dns_upstreams(parsed);
        Ok(())
    }

    /// Bring the data plane up over the `VpnService` fd: attach the fd's
    /// reader/writer to the running daemon and mark the data plane active.
    /// Requires [`Node::start`] first.
    pub fn up(&self, tun_fd: i32) -> Result<(), RayError> {
        let state = self.state()?;

        // `AndroidTunReader`/`AndroidTunWriter` wrap the fd in a `tokio` `AsyncFd`,
        // which registers with the reactor and must be built inside the runtime
        // context. `up` runs on a plain service thread, so enter the runtime for
        // the duration of this call before constructing them.
        let _guard = self.runtime.enter();

        // The writer owns a single `dup` of the fd; the reader takes ownership of
        // the detached fd itself. Build the writer's dup first so that if it fails
        // we have not yet consumed the original fd. Two owned fds, each closed
        // exactly once on drop (when `detach_tun`/`Drop` tears the tasks down).
        let writer = AndroidTunWriter::new(tun_fd).map_err(RayError::network)?;
        // SAFETY: `tun_fd` is the fd Kotlin transferred to us via `detachFd()`;
        // nothing else owns or closes it, so the reader may take ownership.
        let reader =
            unsafe { AndroidTunReader::from_owned_fd(tun_fd) }.map_err(RayError::network)?;

        self.runtime.block_on(async {
            state.attach_tun(reader, writer).await;
            // Mark the data plane active (and configure Magic DNS) the same way
            // `run_daemon` does after attaching the desktop TUN.
            state.activate(None).await;
        });
        Ok(())
    }

    /// Tear the data plane down (stop the forward loop, close the fds) while
    /// keeping the control plane connected. Requires [`Node::start`] first.
    pub fn down(&self) -> Result<(), RayError> {
        let state = self.state()?;
        state.detach_tun();
        Ok(())
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
        let state = self.state.lock().unwrap().take();
        if let Some(state) = state {
            self.runtime.block_on(state.shutdown_and_close());
        }
    }

    /// Peers + addresses + running flag + per-network detail for the UI.
    /// Empty snapshot before [`Node::start`].
    pub fn status(&self) -> Status {
        let empty = || Status {
            running: false,
            node_id: String::new(),
            ipv4: String::new(),
            ipv6: String::new(),
            peers: Vec::new(),
            networks: Vec::new(),
            pending_networks: Vec::new(),
        };
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
            ..
        } = state.status()
        else {
            return empty();
        };

        let mut detail = Vec::with_capacity(networks.len());
        let mut flat_peers = Vec::new();
        for n in &networks {
            let peers: Vec<PeerInfo> = n
                .peers
                .iter()
                .map(|p| PeerInfo {
                    ipv4: p.ip.to_string(),
                    node_id: p.endpoint_id.to_string(),
                    hostname: p.hostname.clone().unwrap_or_default(),
                    online: p.connection.is_some(),
                })
                .collect();
            flat_peers.extend(peers.iter().map(|p| PeerInfo {
                ipv4: p.ipv4.clone(),
                node_id: p.node_id.clone(),
                hostname: p.hostname.clone(),
                online: p.online,
            }));
            detail.push(NetworkDetail {
                name: n.name.clone(),
                ipv4: n.my_ip.to_string(),
                ipv6: n.my_ipv6.map(|v| v.to_string()).unwrap_or_default(),
                hostname: n.my_hostname.clone().unwrap_or_default(),
                is_coordinator: n.role.is_coordinator(),
                peers,
            });
        }
        // Present networks in a stable alphabetical order so the UI list does
        // not shuffle between status refreshes with the core's iteration order.
        detail.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        // The node's own mesh IPs are the same across networks (derived
        // from its identity); take them from the first network if any. With no
        // networks yet, derive the IPv4 from our identity so the tunnel still
        // gets our real mesh address (the same value every network would use)
        // instead of a placeholder.
        let (ipv4, ipv6) = networks
            .first()
            .map(|n| {
                (
                    n.my_ip.to_string(),
                    n.my_ipv6.map(|v| v.to_string()).unwrap_or_default(),
                )
            })
            .unwrap_or_else(|| {
                (
                    rayfish::membership::derive_ip(&endpoint_id).to_string(),
                    String::new(),
                )
            });

        Status {
            running: active,
            node_id: endpoint_id.to_string(),
            ipv4,
            ipv6,
            peers: flat_peers,
            networks: detail,
            pending_networks,
        }
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
