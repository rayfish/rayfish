//! `ray-mobile`: a UniFFI cdylib that drives the `rayfish` mesh core on Android.
//!
//! The Kotlin app owns a `VpnService` and hands its packet fd to [`Node::up`],
//! which brings up an iroh endpoint (reusing the desktop `build_daemon` bring-up
//! path) and runs the zero-copy forward loop over the fd via
//! [`android_tun::AndroidTunReader`] / [`android_tun::AndroidTunWriter`]. No
//! protocol logic is reimplemented here; everything calls into `rayfish::`.

mod android_tun;

use std::sync::{Arc, Mutex};

use android_tun::{AndroidTunReader, AndroidTunWriter};
use rayfish::membership::{IdentityProvider, IrohIdentityProvider, derive_ipv6};
use rayfish::{config, dns, dns_resolver, firewall, forward, identity, peers, stats, transport};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

uniffi::setup_scaffolding!();

/// Structured error surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RayError {
    /// A verb whose full wiring needs desktop-only membership persistence that
    /// M2 does not reach yet.
    #[error("not yet wired: {0}")]
    NotWired(String),
    /// The node is already up (or already down) for the requested transition.
    #[error("invalid state: {0}")]
    InvalidState(String),
    /// Anything from the core: identity load, endpoint bind, fd setup.
    #[error("{0}")]
    Internal(String),
}

impl RayError {
    fn internal(e: impl std::fmt::Display) -> Self {
        RayError::Internal(e.to_string())
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

/// Live handles for a running data plane, torn down by [`Node::down`].
struct Running {
    token: CancellationToken,
    endpoint: iroh::Endpoint,
    peers: peers::PeerTable,
    active: Arc<AtomicBool>,
    node_id: String,
    ipv4: String,
    ipv6: String,
}

/// The FFI object. Owns a multi-thread tokio runtime and, while up, the forward
/// path over the Android fd.
#[derive(uniffi::Object)]
pub struct Node {
    runtime: Runtime,
    running: Mutex<Option<Running>>,
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
            running: Mutex::new(None),
        })
    }

    /// STUB (M2): creating a network needs coordinator/membership persistence
    /// that the desktop daemon owns and M2 does not wire. Returns `NotWired`.
    pub fn create(&self, _name: String) -> Result<NetworkInfo, RayError> {
        Err(RayError::NotWired(
            "create: membership persistence not wired in M2".into(),
        ))
    }

    /// STUB (M2): joining via invite code needs the join handshake + membership
    /// persistence. Returns `NotWired`.
    pub fn join(&self, _invite_code: String) -> Result<NetworkInfo, RayError> {
        Err(RayError::NotWired(
            "join: invite handshake not wired in M2".into(),
        ))
    }

    /// Bring the data plane up over the `VpnService` fd: load identity, bind the
    /// iroh endpoint, and spawn the forward loop + TUN writer over the fd. Mirrors
    /// `build_daemon` steps 1-6 (identity, endpoint, forward wire-up, resolver).
    pub fn up(&self, tun_fd: i32) -> Result<(), RayError> {
        // Reject a double-`up` up front, but do NOT hold the lock across the
        // async bring-up below: a concurrent `status()`/`down()` would otherwise
        // block for the whole endpoint bind. We build everything first, then take
        // the lock only briefly to commit (re-checking for a racing `up`).
        if self.running.lock().unwrap().is_some() {
            return Err(RayError::InvalidState("node already up".into()));
        }

        let running = self.runtime.block_on(async move {
            // --- Identity (step 1) ---
            let key = identity::load_or_create().map_err(RayError::internal)?;
            let public_key = key.public();
            let collision_index = identity::load_collision_index().map_err(RayError::internal)?;
            let id = IrohIdentityProvider::new(public_key, collision_index);
            let my_ip = id.local_ip();
            let my_ipv6 = derive_ipv6(&id.local_identity());

            // --- iroh endpoint (step 2) ---
            let app_config = config::load().map_err(RayError::internal)?;
            let mut alpns: Vec<Vec<u8>> = app_config
                .networks
                .iter()
                .filter_map(|net| net.network_public_key.as_ref().map(transport::network_alpn))
                .collect();
            // iroh-blobs ALPN (`iroh_blobs::protocol::ALPN`), matching
            // `build_daemon`'s `initial_alpns` so the node accepts the same
            // network-independent protocols.
            alpns.push(b"/iroh-bytes/4".to_vec());
            alpns.push(transport::FILES_ALPN.to_vec());
            alpns.push(transport::CONNECT_ALPN.to_vec());
            let endpoint = transport::create_endpoint_with_alpns(
                key.clone(),
                alpns,
                false,
                &app_config.relay,
                &app_config.discovery_dns,
            )
            .await
            .map_err(RayError::internal)?;

            // --- Forward path over the Android fd (steps 3-6) ---
            let token = CancellationToken::new();
            let metrics = Arc::new(stats::ForwardMetrics::default());
            let peer_table = peers::PeerTable::new();
            let shared_firewall =
                firewall::SharedFirewall::new(firewall::FirewallConfig::default());
            shared_firewall.clone().spawn_evictor(token.clone());
            let active = Arc::new(AtomicBool::new(true));

            let resolver = Arc::new(dns_resolver::Resolver::new(
                dns::new_hostname_table(),
                dns::new_reverse_table(),
            ));

            // The writer owns a single `dup` of the fd; the reader takes
            // ownership of the detached fd itself. Build the writer's dup first so
            // that if it fails we have not yet consumed the original fd.
            let writer = AndroidTunWriter::new(tun_fd).map_err(RayError::internal)?;
            // SAFETY: `tun_fd` is the fd Kotlin transferred to us via `detachFd()`;
            // nothing else owns or closes it, so the reader may take ownership.
            let reader =
                unsafe { AndroidTunReader::from_owned_fd(tun_fd) }.map_err(RayError::internal)?;

            let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(256);
            forward::spawn_tun_writer(writer, tun_rx, active.clone());
            self.runtime.spawn(forward::run_mesh(
                reader,
                peer_table.clone(),
                shared_firewall.clone(),
                token.clone(),
                metrics.clone(),
                resolver.clone(),
                tun_tx.clone(),
            ));

            Ok::<Running, RayError>(Running {
                token,
                node_id: endpoint.id().to_string(),
                endpoint,
                peers: peer_table,
                active,
                ipv4: my_ip.to_string(),
                ipv6: my_ipv6.to_string(),
            })
        })?;

        // Commit under the lock, re-checking for a racing `up` that won while we
        // were building. If one did, drop `running` here (cancelling its token /
        // closing its fds via Drop) and report the same double-`up` error.
        let mut guard = self.running.lock().unwrap();
        if guard.is_some() {
            running.active.store(false, Ordering::Relaxed);
            running.token.cancel();
            return Err(RayError::InvalidState("node already up".into()));
        }
        *guard = Some(running);
        Ok(())
    }


    /// Tear the data plane down: cancel the forward loop and close the endpoint.
    pub fn down(&self) -> Result<(), RayError> {
        let running = self.running.lock().unwrap().take();
        let Some(running) = running else {
            return Err(RayError::InvalidState("node not up".into()));
        };
        running.active.store(false, Ordering::Relaxed);
        running.token.cancel();
        let endpoint = running.endpoint;
        self.runtime.block_on(async move { endpoint.close().await });
        Ok(())
    }

    /// Peers + addresses + running flag for the UI.
    pub fn status(&self) -> Status {
        let guard = self.running.lock().unwrap();
        match guard.as_ref() {
            None => Status {
                running: false,
                node_id: String::new(),
                ipv4: String::new(),
                ipv6: String::new(),
                peers: Vec::new(),
            },
            Some(r) => Status {
                running: true,
                node_id: r.node_id.clone(),
                ipv4: r.ipv4.clone(),
                ipv6: r.ipv6.clone(),
                peers: r
                    .peers
                    .all_connections()
                    .into_iter()
                    .map(|(ip, conn)| PeerInfo {
                        ipv4: ip.to_string(),
                        node_id: conn.remote_id().to_string(),
                    })
                    .collect(),
            },
        }
    }
}
