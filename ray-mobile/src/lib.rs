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

use std::sync::{Arc, Mutex};

use android_tun::{AndroidTunReader, AndroidTunWriter};
use rayfish::control;
use rayfish::daemon::{DaemonState, build_headless};
use rayfish::deeplink::{self, RayfishLink};
use rayfish::invite;
use rayfish::ipc::IpcMessage;
use rayfish::membership::GroupMode;
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
            Ok((net_pubkey, coord, secret)) => {
                (net_pubkey.to_string(), Some(secret), Some(coord))
            }
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
        let result = self.runtime.block_on(
            state.invite_create(&network, 7 * 24 * 60 * 60, None, false),
        );
        match result {
            IpcMessage::InviteCreated { code, .. } => Ok(code),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!("unexpected invite response: {other:?}"))),
        }
    }

    /// Leave `network`: tears down its runtime and removes it from config.
    pub fn leave(&self, network: String) -> Result<(), RayError> {
        let state = self.state()?;
        match self.runtime.block_on(state.leave_network(&network)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!("unexpected leave response: {other:?}"))),
        }
    }

    /// Set this device's hostname on `network`. Validated by the core.
    pub fn set_hostname(&self, network: String, hostname: String) -> Result<(), RayError> {
        let state = self.state()?;
        match self.runtime.block_on(state.set_hostname(&network, &hostname)) {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message } => Err(RayError::BadCode(message)),
            other => Err(RayError::Network(format!("unexpected set_hostname response: {other:?}"))),
        }
    }

    /// Begin pairing: returns a ticket to show (as QR) to a device that will
    /// scan and call `pair`.
    pub fn start_pairing(&self) -> Result<String, RayError> {
        let state = self.state()?;
        match state.start_pairing() {
            IpcMessage::PairingTicket { ticket } => Ok(ticket),
            IpcMessage::Error { message } => Err(RayError::PairFailed(message)),
            other => Err(RayError::PairFailed(format!("unexpected pairing response: {other:?}"))),
        }
    }

    /// Pair this device with a primary device using a scanned/pasted pairing
    /// ticket (`bs58(endpoint_id[32] || secret[32])`).
    pub fn pair(&self, ticket: String) -> Result<(), RayError> {
        let state = self.state()?;

        let (endpoint, secret) =
            control::decode_pairing_ticket(&ticket).map_err(|e| RayError::BadCode(e.to_string()))?;

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
        };
        let Some(state) = self.state.lock().unwrap().as_ref().cloned() else {
            return empty();
        };

        let IpcMessage::StatusResponse {
            endpoint_id,
            active,
            networks,
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
        // The node's own mesh IPs are the same across networks (derived
        // from its identity); take them from the first network if any.
        let (ipv4, ipv6) = networks
            .first()
            .map(|n| {
                (
                    n.my_ip.to_string(),
                    n.my_ipv6.map(|v| v.to_string()).unwrap_or_default(),
                )
            })
            .unwrap_or_default();

        Status {
            running: active,
            node_id: endpoint_id.to_string(),
            ipv4,
            ipv6,
            peers: flat_peers,
            networks: detail,
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
