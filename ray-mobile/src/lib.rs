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
}

/// One connected peer in a [`Status`] snapshot.
#[derive(uniffi::Record)]
pub struct PeerInfo {
    pub ipv4: String,
    pub node_id: String,
}

/// Health/peers/addresses snapshot for the UI.
#[derive(uniffi::Record)]
pub struct Status {
    pub running: bool,
    pub node_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub peers: Vec<PeerInfo>,
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
            }),
            // Closed network without a valid invite: queued for coordinator
            // approval and retried in the background. Report it as a successful
            // join-in-progress; the mesh IP is assigned once approved, so the UI
            // polls `status()` for it.
            IpcMessage::Ok { .. } => Ok(NetworkInfo {
                name: network_key,
                node_id: Self::node_id(&state),
                ipv4: String::new(),
                ipv6: String::new(),
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
            }),
            IpcMessage::Error { message } => Err(RayError::Network(message)),
            other => Err(RayError::Network(format!(
                "unexpected create response: {other:?}"
            ))),
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

    /// Peers + addresses + running flag for the UI. Empty snapshot before
    /// [`Node::start`].
    pub fn status(&self) -> Status {
        let Some(state) = self.state.lock().unwrap().as_ref().cloned() else {
            return Status {
                running: false,
                node_id: String::new(),
                ipv4: String::new(),
                ipv6: String::new(),
                peers: Vec::new(),
            };
        };

        match state.status() {
            IpcMessage::StatusResponse {
                endpoint_id,
                active,
                networks,
                ..
            } => {
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
                let peers = networks
                    .iter()
                    .flat_map(|n| &n.peers)
                    .map(|p| PeerInfo {
                        ipv4: p.ip.to_string(),
                        node_id: p.endpoint_id.to_string(),
                    })
                    .collect();
                Status {
                    running: active,
                    node_id: endpoint_id.to_string(),
                    ipv4,
                    ipv6,
                    peers,
                }
            }
            _ => Status {
                running: false,
                node_id: String::new(),
                ipv4: String::new(),
                ipv6: String::new(),
                peers: Vec::new(),
            },
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
}
