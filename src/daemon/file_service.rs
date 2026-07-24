//! File-transfer and device-pairing state, owned as one unit instead of being
//! split across `ProtocolRouter` (pending offers, id counter, pairing secret,
//! signing key) and `Daemon`.
//!
//! The two ALPN accept arms (`FILES_ALPN` file offers, `PAIR_ALPN` pairing) live
//! here; the `ProtocolRouter` accept loop holds an `Arc<FileService>` and
//! delegates to them. The IPC handlers (`send_file`/`accept_file`/`start_pairing`
//! /…) stay on `Daemon` since they orchestrate over core handles (endpoint,
//! peers, the shared blob store) and read this service's state.

use super::transfers;
use super::*;
use std::ffi::CString;
use std::io::Read;
use std::path::PathBuf;

use futures::StreamExt;
use iroh_blobs::api::remote::GetProgressItem;
use serde::{Deserialize, Serialize};

/// Upper bound on one background offer dial. `Endpoint::connect` retries
/// discovery with no timeout of its own; the outbox retries on the next
/// peer-connected event anyway, so a stuck dial must not pin the flush task.
const OFFER_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How often the outbox re-attempts delivery to peers that currently hold a
/// live mesh connection. The peer-connected hook is the primary trigger; this
/// sweep only catches offers whose delivery failed transiently while the
/// connection stayed up.
pub(crate) const OUTBOX_SWEEP_INTERVAL: Duration = Duration::from_secs(120);

fn outbox_path() -> Option<PathBuf> {
    config::config_dir().ok().map(|d| d.join("outbox.json"))
}

fn load_outbox() -> Vec<OutboxEntry> {
    let Some(path) = outbox_path() else {
        return Vec::new();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "unreadable send outbox; starting empty");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

/// An outbound send waiting for its peer. Persisted (JSON, in the config dir)
/// so a queued send survives a daemon restart; the bytes themselves already
/// live in the persistent blob store. `id` is session-local, reassigned on load.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OutboxEntry {
    #[serde(skip)]
    pub(crate) id: u64,
    pub(crate) peer: EndpointId,
    pub(crate) filename: String,
    pub(crate) size: u64,
    pub(crate) blob_hash: blake3::Hash,
}

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
    /// In-flight transfers, for progress reporting.
    pub(crate) transfers: Arc<transfers::TransferRegistry>,
    /// Outbound sends awaiting delivery (peer offline, or the offer dial
    /// failed). Flushed on every peer-connected event and by a slow sweep.
    /// Ids come from `file_id_counter`, shared with inbound pending offers.
    outbox: Arc<std::sync::Mutex<Vec<OutboxEntry>>>,
    /// Peers with a flush in flight, so a burst of connect events (or the
    /// sweep racing a connect) can't deliver the same offer twice.
    flushing: Arc<DashSet<EndpointId>>,
}

impl FileService {
    pub(crate) fn new(
        secret_key: SecretKey,
        transport: Arc<Transport>,
        registry: Arc<NetworkRegistry>,
        device_cert: Option<control::DeviceCert>,
        device_user_map: peers::DeviceUserMap,
        transfers: Arc<transfers::TransferRegistry>,
    ) -> Self {
        // Reload queued sends from the previous run. Ids and transfer entries
        // are session-local: reassign fresh ones (the transfer re-registers as
        // Offered so provider events find it by hash+peer when the peer pulls).
        let mut queued = load_outbox();
        let ids = AtomicU64::new(1);
        for entry in &mut queued {
            entry.id = ids.fetch_add(1, Ordering::Relaxed);
            transfers.register_send(
                entry.peer,
                entry.filename.clone(),
                entry.size,
                iroh_blobs::Hash::from_bytes(*entry.blob_hash.as_bytes()),
            );
        }
        Self {
            pending_files: Arc::new(std::sync::Mutex::new(Vec::new())),
            file_id_counter: Arc::new(ids),
            pairing_secret: Arc::new(std::sync::Mutex::new(None)),
            secret_key,
            transport,
            registry,
            device_cert,
            device_user_map,
            transfers,
            outbox: Arc::new(std::sync::Mutex::new(queued)),
            flushing: Arc::new(DashSet::new()),
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
                    return ipc_err(format!("no pending file with id {id}"));
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
                return ipc_err(format!("cannot reach sender: {e}"));
            }
        };

        let peer_label = pending_file.from.fmt_short().to_string();
        let transfer_id = self.transfers.register_receive(
            peer_label,
            pending_file.filename.clone(),
            pending_file.size,
        );
        // Guards against a cancelled fetch (or an early return below) leaving
        // the entry stuck in `Transferring`: its `Drop` marks the transfer
        // failed unless `success()` disarms it first, which only happens once
        // the file is actually on disk.
        let finish_guard = transfers::FinishGuard::new(self.transfers.clone(), transfer_id);

        // `fetch` returns a `GetProgress`: awaiting it directly discards the
        // progress, so take the stream instead and report bytes as they land. It
        // yields `Progress(n)` items (n = payload bytes read so far) and exactly
        // one terminal `Done`/`Error` item. Note: reaching `Done` here means only
        // the fetch succeeded, not the transfer; the registry is not finished
        // until the file is written to disk below.
        let mut stream = Box::pin(
            self.transport
                .blob_store
                .remote()
                .fetch(conn, iroh_blobs::HashAndFormat::raw(blob_hash))
                .stream(),
        );
        loop {
            match stream.next().await {
                Some(GetProgressItem::Progress(n)) => self.transfers.note_progress(transfer_id, n),
                Some(GetProgressItem::Done(_)) => break,
                Some(GetProgressItem::Error(e)) => {
                    return ipc_err(format!("blob fetch failed: {e}"));
                }
                None => {
                    return ipc_err("blob fetch ended without a result".to_string());
                }
            }
        }

        let bytes = match self.transport.blob_store.blobs().get_bytes(blob_hash).await {
            Ok(b) => b,
            Err(e) => {
                return ipc_err(format!("blob read failed: {e}"));
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
            return ipc_err(format!("cannot create directory '{}': {e}", dir.display()));
        }

        let dest = dir.join(&pending_file.filename);
        if let Err(e) = std::fs::write(&dest, &bytes) {
            return ipc_err(format!("write failed: {e}"));
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

        // The file is fully on disk (chown failures are ignored, by design,
        // and never fail the transfer): only now is the transfer really done.
        finish_guard.success();

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
    /// The read happens daemon-side, so this only works for paths the daemon
    /// itself can see; IPC clients use `send_file_fd`. Kept for in-process
    /// callers (ray-mobile), where daemon and app share one privilege domain.
    pub(crate) async fn send_file(self: &Arc<Self>, path: &str, peer: &str) -> IpcMessage {
        let file_path = Path::new(path);
        let file_bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                return ipc_err(format!("cannot read '{}': {e}", file_path.display()));
            }
        };
        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        self.send_bytes(file_bytes, filename, peer).await
    }

    /// `send_file` for a descriptor received over IPC (`SendFileFd`): the
    /// client opened the file with its own privileges, the daemon never
    /// resolves a path. This is what lets `ray send` reach TCC-protected
    /// folders on macOS and files the daemon can't read but the caller can.
    pub(crate) async fn send_file_fd(
        self: &Arc<Self>,
        fd: OwnedFd,
        filename: &str,
        peer: &str,
    ) -> IpcMessage {
        let mut file = File::from(fd);
        // fstat before reading: an fd is attacker-chosen input, and reading a
        // FIFO or a device (/dev/zero) here would stall or balloon the daemon.
        match file.metadata() {
            Ok(m) if m.is_file() => {}
            Ok(_) => return ipc_err("not a regular file"),
            Err(e) => return ipc_err(format!("cannot stat file: {e}")),
        }
        let mut file_bytes = Vec::new();
        if let Err(e) = file.read_to_end(&mut file_bytes) {
            return ipc_err(format!("cannot read file: {e}"));
        }
        // The client names the file; keep only the basename so a hostile
        // client can't smuggle path components into the offer.
        let filename = Path::new(filename)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        self.send_bytes(file_bytes, filename, peer).await
    }

    /// Shared tail of the send flow: blob-store the bytes, queue the offer,
    /// and reply immediately. Delivery is asynchronous: a background flush
    /// attempts it right away, and the outbox re-flushes whenever a mesh
    /// connection to the peer comes up, so a send to an offline peer parks
    /// here instead of making the caller wait on an unbounded dial.
    async fn send_bytes(
        self: &Arc<Self>,
        file_bytes: Vec<u8>,
        filename: String,
        peer: &str,
    ) -> IpcMessage {
        let peer_id = match self.registry.resolve_peer_flexible(peer).await {
            Some(id) => id,
            None => {
                return ipc_err(format!("unknown peer '{peer}'"));
            }
        };

        let size = file_bytes.len() as u64;
        let hash = blake3::hash(&file_bytes);

        if let Err(e) = self
            .transport
            .blob_store
            .blobs()
            .add_slice(&file_bytes)
            .await
        {
            return ipc_err(format!("blob store error: {e}"));
        }

        // Register the transfer now, before the peer can possibly learn the hash:
        // it is only after `add_slice` above that the blob exists to be pulled,
        // and on auto-accept the receiver can fetch the entire blob the moment
        // the offer lands, so every provider event (Started/Progress/Completed)
        // must find the entry already registered.
        self.transfers.register_send(
            peer_id,
            filename.clone(),
            size,
            iroh_blobs::Hash::from_bytes(*hash.as_bytes()),
        );

        let entry = OutboxEntry {
            id: self.file_id_counter.fetch_add(1, Ordering::Relaxed),
            peer: peer_id,
            filename: filename.clone(),
            size,
            blob_hash: hash,
        };
        self.outbox.lock().unwrap().push(entry);
        self.save_outbox();

        // Kick delivery in the background either way: even a peer with no live
        // mesh connection may be dialable (fresh mDNS discovery, say), and the
        // attempt is bounded by OFFER_CONNECT_TIMEOUT.
        let svc = Arc::clone(self);
        tokio::spawn(async move { svc.flush_outbox_for(peer_id).await });

        let message = if self.peer_connected(peer_id) {
            format!("sending {} ({}) to {}", filename, format_size(size), peer)
        } else {
            format!(
                "queued {} ({}) for {}; it delivers when the peer comes online (see `ray files`)",
                filename,
                format_size(size),
                peer
            )
        };
        IpcMessage::Ok { message }
    }

    /// Distinct peers with queued sends that hold a live mesh connection right
    /// now: the periodic sweep's work list (it never dials offline peers).
    pub(crate) fn outbox_peers(&self) -> Vec<EndpointId> {
        let mut peers: Vec<EndpointId> =
            self.outbox.lock().unwrap().iter().map(|e| e.peer).collect();
        peers.sort();
        peers.dedup();
        peers.retain(|p| self.peer_connected(*p));
        peers
    }

    /// True when any shared network holds a live mesh connection to `peer`.
    fn peer_connected(&self, peer: EndpointId) -> bool {
        self.registry.networks.iter().any(|entry| {
            self.registry
                .peers
                .peers_for_network_with_conn(entry.key())
                .iter()
                .any(|(pid, _, _)| *pid == peer)
        })
    }

    /// Deliver every queued offer for `peer`, stopping at the first failure
    /// (the next peer-connected event or sweep retries). Called from the
    /// mesh-connection hook, the enqueue path, and the periodic sweep; the
    /// `flushing` guard collapses concurrent triggers so an offer can't be
    /// delivered twice.
    pub(crate) async fn flush_outbox_for(self: Arc<Self>, peer: EndpointId) {
        if !self.flushing.insert(peer) {
            return;
        }
        loop {
            let Some(entry) = self
                .outbox
                .lock()
                .unwrap()
                .iter()
                .find(|e| e.peer == peer)
                .cloned()
            else {
                break;
            };
            match self.deliver_offer(&entry).await {
                Ok(()) => {
                    tracing::info!(
                        peer = %peer.fmt_short(),
                        filename = %entry.filename,
                        "queued file offer delivered"
                    );
                    self.outbox.lock().unwrap().retain(|e| e.id != entry.id);
                    self.save_outbox();
                }
                Err(e) => {
                    tracing::debug!(
                        peer = %peer.fmt_short(),
                        filename = %entry.filename,
                        error = %e,
                        "outbox delivery attempt failed; will retry"
                    );
                    break;
                }
            }
        }
        self.flushing.remove(&peer);
    }

    /// One bounded delivery attempt: dial `FILES_ALPN`, send the offer, wait
    /// for the peer to read it. The transfer entry stays Offered afterwards;
    /// the peer pulling the blob is what moves it (provider events).
    async fn deliver_offer(&self, entry: &OutboxEntry) -> Result<(), String> {
        let msg = control::ControlMsg::FileOffer {
            from: self.transport.endpoint.id(),
            filename: entry.filename.clone(),
            size: entry.size,
            mime_type: guess_mime_type(&entry.filename),
            blob_hash: entry.blob_hash,
        };
        let conn = tokio::time::timeout(
            OFFER_CONNECT_TIMEOUT,
            transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
                entry.peer,
                transport::FILES_ALPN,
            ),
        )
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect failed: {e}"))?;
        let (mut send, _recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("failed to open stream: {e}"))?;
        // File offers ride the separate FILES_ALPN, not the mesh demux, so they
        // carry no network scope.
        control::send_msg(&mut send, None, &msg)
            .await
            .map_err(|e| format!("failed to send offer: {e}"))?;
        // send_msg already finished the stream; wait for the peer to read the
        // offer so it flushes before this `conn` is dropped.
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        Ok(())
    }

    /// `ray files cancel <id>`: drop a queued send that hasn't been delivered.
    pub(crate) fn cancel_send(&self, id: u64) -> IpcMessage {
        let removed = {
            let mut outbox = self.outbox.lock().unwrap();
            let i = outbox.iter().position(|e| e.id == id);
            i.map(|i| outbox.remove(i))
        };
        match removed {
            Some(entry) => {
                self.transfers.fail_offer_by(
                    iroh_blobs::Hash::from_bytes(*entry.blob_hash.as_bytes()),
                    entry.peer,
                );
                self.save_outbox();
                IpcMessage::Ok {
                    message: format!(
                        "canceled queued send of {} to {}",
                        entry.filename,
                        entry.peer.fmt_short()
                    ),
                }
            }
            None => ipc_err(format!("no queued send with id {id}")),
        }
    }

    /// Persist the outbox (atomic write via `config::write_file`). Filenames
    /// and peers are not secrets in the config-dir threat model, but keep the
    /// file root-only like the rest of the daemon state.
    fn save_outbox(&self) {
        let Some(path) = outbox_path() else { return };
        let entries = self.outbox.lock().unwrap().clone();
        match serde_json::to_vec_pretty(&entries) {
            Ok(bytes) => {
                if let Err(e) = config::write_file(&path, &bytes, true) {
                    tracing::warn!(error = %e, "failed to persist send outbox");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to serialize send outbox"),
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
        let outbox = self
            .outbox
            .lock()
            .unwrap()
            .iter()
            .map(|e| ipc::OutboxFileInfo {
                id: e.id,
                peer: e.peer.fmt_short().to_string(),
                filename: e.filename.clone(),
                size: e.size,
            })
            .collect();
        IpcMessage::FileList { files, outbox }
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
            None => ipc_err(format!("no pending file with id {id}")),
        }
    }

    /// Toggle this node's per-network auto-accept of file offers from our own
    /// paired devices (persisted in config). Turning it on also drains any
    /// already-queued offers that now qualify.
    pub(crate) async fn files_auto_accept(&self, network: &str, enabled: bool) -> IpcMessage {
        if !self.registry.contains(network) {
            return ipc_err(format!("network '{network}' not found"));
        }
        match config::load_network(network) {
            Ok(Some(mut nc)) => {
                nc.auto_accept_files = enabled;
                if let Err(e) = config::save_network(&nc) {
                    return ipc_err(format!("failed to persist auto-accept setting: {e}"));
                }
            }
            Ok(None) => {
                return ipc_err(format!("network '{network}' not found in config"));
            }
            Err(e) => {
                return ipc_err(format!("failed to load config: {e}"));
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
            return ipc_err(
                "this device is already paired; add new devices from your primary device"
                    .to_string(),
            );
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
                let request: control::PairMsg = match control::recv_framed(&mut recv).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read pair request");
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
                                if let Err(e) = control::send_framed(&mut send, &response).await {
                                    tracing::warn!(error = %e, "failed to send pair response");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the outbox persistence format: `EndpointId` and `blake3::Hash`
    /// must survive a JSON round trip (the file is reloaded across daemon
    /// restarts, so a serde-shape regression would silently drop the queue).
    #[test]
    fn outbox_entry_roundtrips_through_json() {
        let peer = SecretKey::from([7u8; 32]).public();
        let entry = OutboxEntry {
            id: 3,
            peer,
            filename: "report.pdf".to_string(),
            size: 42,
            blob_hash: blake3::hash(b"payload"),
        };
        let bytes = serde_json::to_vec(&vec![entry.clone()]).unwrap();
        let loaded: Vec<OutboxEntry> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded.len(), 1);
        // `id` is #[serde(skip)]: session-local, reassigned on load.
        assert_eq!(loaded[0].id, 0);
        assert_eq!(loaded[0].peer, entry.peer);
        assert_eq!(loaded[0].filename, entry.filename);
        assert_eq!(loaded[0].size, entry.size);
        assert_eq!(loaded[0].blob_hash, entry.blob_hash);
    }
}
