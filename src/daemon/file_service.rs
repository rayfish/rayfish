//! File-transfer and device-pairing state, owned as one unit instead of being
//! split across `ProtocolRouter` (pending offers, id counter, pairing secret,
//! signing key) and `Daemon`.
//!
//! The two ALPN accept arms (`FILES_ALPN` file offers, `PAIR_ALPN` pairing) live
//! here; the `ProtocolRouter` accept loop holds an `Arc<FileService>` and
//! delegates to them. The IPC handlers (`send_file`/`accept_file`/`start_pairing`
//! /…) stay on `Daemon` since they orchestrate over core handles (endpoint,
//! peers, the shared blob store) and read this service's state.

use super::*;
use std::ffi::CString;
use std::path::PathBuf;

/// A received file offer awaiting `ray files accept`.
pub(crate) struct PendingFile {
    pub(crate) id: u64,
    pub(crate) from: EndpointId,
    pub(crate) filename: String,
    pub(crate) size: u64,
    pub(crate) mime_type: String,
    pub(crate) blob_hash: blake3::Hash,
}

pub(crate) struct FileService {
    /// Received file offers awaiting `ray files accept`.
    pub(crate) pending_files: Arc<std::sync::Mutex<Vec<PendingFile>>>,
    /// Monotonic id source for pending offers.
    pub(crate) file_id_counter: Arc<AtomicU64>,
    /// Active pairing secret (set by `start_pairing`, consumed by a pair request).
    pub(crate) pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    /// This node's transport secret key, used to sign device certs on pairing.
    secret_key: SecretKey,
    /// Foundation handles (endpoint + blob store) for fetching accepted files.
    transport: Arc<Transport>,
    /// The network-owning service, for the own-device auto-accept membership gate.
    registry: Arc<NetworkRegistry>,
    /// This device's cert (if paired), to resolve our own user identity.
    device_cert: Option<control::DeviceCert>,
    /// Transport-key → user-identity map, to resolve a file sender's owner.
    device_user_map: peers::DeviceUserMap,
}

impl FileService {
    pub(crate) fn new(
        secret_key: SecretKey,
        transport: Arc<Transport>,
        registry: Arc<NetworkRegistry>,
        device_cert: Option<control::DeviceCert>,
        device_user_map: peers::DeviceUserMap,
    ) -> Self {
        Self {
            pending_files: Arc::new(std::sync::Mutex::new(Vec::new())),
            file_id_counter: Arc::new(AtomicU64::new(1)),
            pairing_secret: Arc::new(std::sync::Mutex::new(None)),
            secret_key,
            transport,
            registry,
            device_cert,
            device_user_map,
        }
    }

    /// `FILES_ALPN`: read a single `FileOffer` and queue it for `ray files`.
    /// Rejects offers whose claimed sender doesn't match the dialing identity.
    pub(crate) async fn accept_file_offer(&self, conn: Connection) {
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
                            // Evaluate own-device auto-accept directly: it accepts
                            // only offers from our own paired devices on an opted-in
                            // network, and no-ops otherwise, so the offer stays
                            // queued for `ray files accept` unless it qualifies. We
                            // are already in a per-connection task, so awaiting the
                            // fetch here blocks only this offer.
                            self.try_auto_accept_file(id).await;
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

    /// Whether a file sender resolves to *our own* user identity (a paired
    /// device of ours), the gate for own-device file auto-accept. An unpaired
    /// node uses its endpoint id as its own user identity, so a stranger can
    /// never match. Shared by `try_auto_accept_file` and `list_files`.
    pub(crate) fn is_own_device_sender(&self, from: EndpointId) -> bool {
        let own_user = self
            .device_cert
            .as_ref()
            .map(|c| c.user_identity)
            .unwrap_or_else(|| self.transport.endpoint.id());
        self.device_user_map.resolve(&from) == own_user
    }

    /// Evaluate a newly-queued (or already-pending) file offer against the
    /// own-devices auto-accept policy and, if it qualifies, accept it without
    /// user action. A no-op (offer stays queued) unless: the sender resolves to
    /// *our own* user identity (a paired device) **and** it is a member of at
    /// least one network with `auto_accept_files` enabled. Never removes the
    /// pending entry unless it actually accepts (via `accept_file`).
    pub(crate) async fn try_auto_accept_file(&self, id: u64) {
        // Peek the offer's sender without consuming the queue entry.
        let from = {
            let pending = self.pending_files.lock().unwrap();
            match pending.iter().find(|f| f.id == id) {
                Some(f) => f.from,
                None => return,
            }
        };

        // Own-device gate: the sender must resolve to one of our own paired
        // devices.
        if !self.is_own_device_sender(from) {
            return;
        }

        // Network gate: the sender must be a member of a network we've enabled.
        if !self.registry.member_on_autoaccept_network(from) {
            return;
        }

        // Placement must be explicitly resolvable (download-dir / download-user /
        // operator). With none configured we do not write as root: leave the
        // offer queued for manual `ray files accept`.
        let (dir, cred) = match resolve_download_target() {
            Some((dir, cred)) => (dir, cred),
            None => {
                tracing::warn!(
                    from = %from.fmt_short(),
                    "auto-accept: no download target configured (set `ray files download-dir` or `download-user`); leaving offer queued"
                );
                return;
            }
        };
        let output = Some(dir.to_string_lossy().into_owned());

        match self.accept_file(id, output, cred).await {
            IpcMessage::Ok { message } => {
                tracing::info!(from = %from.fmt_short(), %message, "file auto-accepted from own device");
            }
            IpcMessage::Error { message } => {
                tracing::warn!(from = %from.fmt_short(), %message, "file auto-accept failed");
            }
            _ => {}
        }
    }

    /// Fetch a pending file's blob from its sender, write it to disk, and (when a
    /// `peer_cred` is given) chown it to that user. Removes the pending entry.
    pub(crate) async fn accept_file(
        &self,
        id: u64,
        output: Option<String>,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        let pending_file = {
            let mut pending = self.pending_files.lock().unwrap();
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
            &self.transport.endpoint,
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
            .transport
            .blob_store
            .remote()
            .fetch(conn, iroh_blobs::HashAndFormat::raw(blob_hash))
            .await
        {
            return IpcMessage::Error {
                message: format!("blob fetch failed: {e}"),
            };
        }

        let bytes = match self.transport.blob_store.blobs().get_bytes(blob_hash).await {
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
            if let Ok(c) = CString::new(dest.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
            if let Ok(c) = CString::new(dir.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
        }

        IpcMessage::Ok {
            message: format!("saved to {}", dest.display()),
        }
    }

    /// This device's pairing cert. On-disk authoritative (a cleanly-absent file
    /// means unpaired); only a genuine read error falls back to the boot copy.
    fn current_device_cert(&self) -> Option<control::DeviceCert> {
        match identity::load_device_cert() {
            Ok(cert) => cert,
            Err(_) => self.device_cert.clone(),
        }
    }

    /// This user's identity: the cert's `user_identity` (paired secondary) or our
    /// own endpoint id (primary/unpaired).
    fn own_user_identity(&self) -> EndpointId {
        self.current_device_cert()
            .map(|c| c.user_identity)
            .unwrap_or_else(|| self.transport.endpoint.id())
    }

    /// `ray pair list`: enumerate this user's other paired devices as roster
    /// members sharing our `user_identity` but a different device id.
    pub(crate) fn list_paired_devices(&self) -> IpcMessage {
        let own_user = self.own_user_identity();
        let own_device = self.transport.endpoint.id();
        let mut by_device: HashMap<EndpointId, (Option<String>, Vec<String>)> = HashMap::new();
        for entry in self.registry.networks.iter() {
            let net_name = entry.key().clone();
            let roster = entry.value().state.read().unwrap().roster();
            for m in roster {
                if m.user_identity == Some(own_user)
                    && m.identity != own_user
                    && m.identity != own_device
                {
                    let e = by_device
                        .entry(m.identity)
                        .or_insert_with(|| (m.hostname.clone(), Vec::new()));
                    if e.0.is_none() {
                        e.0 = m.hostname.clone();
                    }
                    e.1.push(net_name.clone());
                }
            }
        }
        let devices = by_device
            .into_iter()
            .map(|(device_id, (hostname, mut networks))| {
                networks.sort();
                networks.dedup();
                ipc::PairedDeviceInfo {
                    device_id,
                    short_id: device_id.fmt_short().to_string(),
                    hostname,
                    networks,
                }
            })
            .collect();
        IpcMessage::PairedDevices { devices }
    }

    /// Add a file to the blob store and offer it to a peer over `FILES_ALPN`.
    pub(crate) async fn send_file(&self, path: &str, peer: &str) -> IpcMessage {
        let peer_id = match self.registry.resolve_peer_flexible(peer).await {
            Some(id) => id,
            None => {
                return IpcMessage::Error {
                    message: format!("unknown peer '{peer}'"),
                };
            }
        };

        let file_path = Path::new(path);
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

        if let Err(e) = self.transport.blob_store.blobs().add_slice(&file_bytes).await {
            return IpcMessage::Error {
                message: format!("blob store error: {e}"),
            };
        }

        let msg = control::ControlMsg::FileOffer {
            from: self.transport.endpoint.id(),
            filename: filename.clone(),
            size,
            mime_type: mime_type.clone(),
            blob_hash: hash,
        };

        match transport::connect_to_peer_with_alpn(
            &self.transport.endpoint,
            peer_id,
            transport::FILES_ALPN,
        )
        .await
        {
            Ok(conn) => match conn.open_bi().await {
                Ok((mut send, _)) => {
                    // File offers ride the separate FILES_ALPN, not the mesh demux,
                    // so they carry no network scope.
                    if let Err(e) = control::send_msg(&mut send, None, &msg).await {
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

    /// List pending file offers awaiting `ray files accept`, tagging each with
    /// whether it came from one of our own paired devices.
    pub(crate) fn list_files(&self) -> IpcMessage {
        let pending = self.pending_files.lock().unwrap();
        let files = pending
            .iter()
            .map(|f| ipc::PendingFileInfo {
                id: f.id,
                from: f.from.fmt_short().to_string(),
                filename: f.filename.clone(),
                size: f.size,
                mime_type: f.mime_type.clone(),
                own_device: self.is_own_device_sender(f.from),
            })
            .collect();
        IpcMessage::FileList { files }
    }

    /// Decline a pending file offer: drop it from the queue without fetching the
    /// blob. In-memory only, mirroring how `accept_file` consumes the entry.
    pub(crate) fn reject_file(&self, id: u64) -> IpcMessage {
        let mut pending = self.pending_files.lock().unwrap();
        match pending.iter().position(|f| f.id == id) {
            Some(i) => {
                pending.remove(i);
                IpcMessage::Ok {
                    message: format!("declined file {id}"),
                }
            }
            None => IpcMessage::Error {
                message: format!("no pending file with id {id}"),
            },
        }
    }

    /// Toggle this node's per-network auto-accept of file offers from our own
    /// paired devices (persisted in config). Turning it on also drains any
    /// already-queued offers that now qualify.
    pub(crate) async fn files_auto_accept(&self, network: &str, enabled: bool) -> IpcMessage {
        if !self.registry.contains(network) {
            return IpcMessage::Error {
                message: format!("network '{network}' not found"),
            };
        }
        match config::load_network(network) {
            Ok(Some(mut nc)) => {
                nc.auto_accept_files = enabled;
                if let Err(e) = config::save_network(&nc) {
                    return IpcMessage::Error {
                        message: format!("failed to persist auto-accept setting: {e}"),
                    };
                }
            }
            Ok(None) => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found in config"),
                };
            }
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        }
        // On enable, sweep any already-queued offers so a file that arrived
        // before the toggle still lands.
        if enabled {
            let ids: Vec<u64> = self
                .pending_files
                .lock()
                .unwrap()
                .iter()
                .map(|f| f.id)
                .collect();
            for id in ids {
                self.try_auto_accept_file(id).await;
            }
        }
        IpcMessage::Ok {
            message: format!(
                "auto-accept files from your own devices {} for '{network}'",
                if enabled { "enabled" } else { "disabled" }
            ),
        }
    }

    /// Mint a pairing ticket for this device. Only a primary (holding no cert of
    /// its own) may mint device certs; a secondary is refused so a new device
    /// can't be bound to the wrong identity.
    pub(crate) fn start_pairing(&self) -> IpcMessage {
        if self.current_device_cert().is_some() {
            return IpcMessage::Error {
                message: "this device is already paired; add new devices from your primary device"
                    .to_string(),
            };
        }

        let secret: [u8; 32] = rand::random();

        let endpoint_id = self.transport.endpoint.id();
        let mut ticket_bytes = Vec::with_capacity(64);
        ticket_bytes.extend_from_slice(endpoint_id.as_bytes());
        ticket_bytes.extend_from_slice(&secret);
        let ticket = bs58::encode(&ticket_bytes).into_string();

        *self.pairing_secret.lock().unwrap() = Some(secret);

        tracing::info!("pairing session opened; awaiting a secondary to scan the ticket");
        IpcMessage::PairingTicket { ticket }
    }

    /// `PAIR_ALPN`: complete a device-pairing handshake. Verifies the dialer's
    /// secret against the active pairing session and, on match, signs and returns
    /// a `DeviceCert` binding the new device key to our identity.
    pub(crate) async fn accept_pair_request(&self, conn: Connection) {
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
                                // A deliberate (re-)pair re-authorizes this device.
                                // Clear any nullifier for it (durable seed + every
                                // coordinated blob) so admission stops rejecting the
                                // fresh cert; otherwise the device would reconnect-
                                // loop. Spawned so the reseal/publish doesn't delay
                                // the cert response the joiner is waiting on.
                                let registry = self.registry.clone();
                                tokio::spawn(async move {
                                    registry.reauth_device(device_pubkey).await;
                                });
                                let generation =
                                    config::load().map(|c| c.cert_generation).unwrap_or(0);
                                let cert = control::DeviceCert::create(
                                    &secret_key,
                                    &device_pubkey,
                                    generation,
                                );
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
                                // which RSTs the stream: without this the joiner often sees
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
}
