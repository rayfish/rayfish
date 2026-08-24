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
use std::hint::black_box;
use std::path::PathBuf;

use futures::StreamExt;
use iroh_blobs::api::remote::GetProgressItem;
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;

/// Upper bound on one background offer dial. `Endpoint::connect` retries
/// discovery with no timeout of its own; the outbox retries on the next
/// peer-connected event anyway, so a stuck dial must not pin the flush task.
const OFFER_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How often the outbox re-attempts delivery to peers that currently hold a
/// live mesh connection. The peer-connected hook is the primary trigger; this
/// sweep only catches offers whose delivery failed transiently while the
/// connection stayed up.
pub(crate) const OUTBOX_SWEEP_INTERVAL: Duration = Duration::from_secs(120);

/// Tag naming for transfer blobs, and the reclaim that follows a tag going away.
///
/// A blob in the store is kept alive by a tag; GC sweeps whatever no tag points
/// at. Nothing here used to delete tags, so `config_dir()/blobs` grew forever:
/// every file ever sent stayed next to the original, and every file ever
/// received stayed next to the copy in Downloads. Both ends now tag for exactly
/// as long as they need the bytes and reclaim afterwards.
///
/// Names are derived, not stored: the sender's tag is keyed by `(hash, peer)`,
/// so the right tag can be found again after a restart without persisting
/// anything alongside the outbox.
///
/// Both names are per-transfer rather than per-blob, and that is what makes the
/// refcount work. The same file can go to several people, so two outstanding
/// sends of one file are two tags over one blob and the bytes survive until the
/// last of them is picked up; likewise two offers of the same file from
/// different senders are two receive tags, so accepting one cannot sweep the
/// blob the other is still fetching.
mod blob_tags {
    use super::*;

    pub(super) fn send(hash: &blake3::Hash, peer: &EndpointId) -> String {
        format!("send/{}/{}", hash.to_hex(), peer.fmt_short())
    }

    /// Keyed by the pending offer's id, which is unique per received offer.
    pub(super) fn recv(hash: &iroh_blobs::Hash, offer_id: u64) -> String {
        format!("recv/{hash}/{offer_id}")
    }
}

impl FileService {
    /// Drop `tag`, making its blob collectable if nothing else points at it. The
    /// store's periodic GC (see `BLOB_GC_INTERVAL`) does the actual reclaim;
    /// `Blobs::delete` is private precisely so callers go through GC.
    ///
    /// Best-effort and detached: a failed reclaim wastes disk, it never fails
    /// the transfer that triggered it, so the error is logged and swallowed.
    fn reclaim_blob(self: &Arc<Self>, tag: String) {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = svc.transport.blob_store.tags().delete(&tag).await {
                tracing::warn!(%tag, error = %e, "could not drop blob tag");
            }
        });
    }

    /// Point a persistent tag at a freshly imported blob so GC leaves it alone,
    /// and release the import's temp tag now that something durable holds it.
    async fn tag_blob(&self, tag: String, temp: iroh_blobs::api::TempTag) -> Result<(), String> {
        let haf = temp.hash_and_format();
        self.transport
            .blob_store
            .tags()
            .set(tag, haf)
            .await
            .map_err(|e| format!("blob store error: {e}"))
    }
}

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

/// An open pairing session: the secret the ticket carries, and when it opened.
/// Held rather than a bare secret so [`PAIRING_TTL`] has something to measure.
pub(crate) struct PairingSession {
    secret: [u8; 32],
    opened: Instant,
}

/// Cap on the queue of unaccepted incoming file offers.
///
/// `FILES_ALPN` takes an offer from any dialer that knows our endpoint id, and
/// each one appends attacker-sized `filename` and `mime_type` strings, so the
/// queue is memory a stranger can grow one dial at a time. Same policy as the
/// join and connect queues: at the cap the oldest unanswered offer makes way.
///
/// The offer is only a description; the bytes are not fetched until `ray files
/// accept`, so an evicted entry costs nothing that was not already the sender's
/// to retry.
pub(crate) const MAX_PENDING_FILES: usize = 256;

/// Drop the oldest queued offer when `pending` is at `cap`, returning its id.
/// Offers are pushed in arrival order, so the oldest is the front.
pub(crate) fn evict_oldest_file(pending: &mut Vec<PendingFile>, cap: usize) -> Option<u64> {
    if pending.len() < cap {
        return None;
    }
    let dropped = pending.remove(0);
    tracing::warn!(
        evicted = dropped.id,
        from = %dropped.from.fmt_short(),
        "pending file-offer queue full; evicted oldest offer"
    );
    Some(dropped.id)
}

/// How long an open pairing session stays open.
///
/// Nothing else closes it. A wrong secret deliberately does not (that was the bug
/// this replaced: any dialer could end the user's pairing window), a successful
/// pair does, and there is no cancel command, so without a deadline `ray pair` on
/// a machine that was then interrupted would leave a standing "sign a DeviceCert
/// for whoever presents these 32 bytes" on a public ALPN until the daemon
/// restarted. The ticket is a QR code people screenshot and paste, so the
/// credential outliving its session by days is the worse failure of the two.
///
/// Five minutes is the scan-it-now window the ticket is for.
pub(crate) const PAIRING_TTL: Duration = Duration::from_secs(300);

/// Whether two pairing secrets match, in time independent of *where* they differ.
///
/// Hand-rolled rather than a `subtle` dependency for one call site. The
/// accumulate-then-compare shape is what keeps it branch-free: every byte is read
/// on every call, and `black_box` stops the optimizer from noticing it could stop
/// once `diff` is nonzero.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    black_box(diff) == 0
}

/// Outcome of checking a presented pairing secret. Separate from the stored value
/// so the lock is dropped before the (slow) success path runs.
enum PairCheck {
    Accepted,
    Mismatch,
    NoSession,
}

pub(crate) struct FileService {
    /// Received file offers awaiting `ray files accept`.
    pub(crate) pending_files: Arc<Mutex<Vec<PendingFile>>>,
    /// Monotonic id source for pending offers.
    pub(crate) file_id_counter: Arc<AtomicU64>,
    /// Active pairing secret and when it was opened (set by `start_pairing`,
    /// consumed by a matching pair request, and expired by [`PAIRING_TTL`]).
    pub(crate) pairing_secret: Arc<Mutex<Option<PairingSession>>>,
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
    outbox: Arc<Mutex<Vec<OutboxEntry>>>,
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
            pending_files: Arc::new(Mutex::new(Vec::new())),
            file_id_counter: Arc::new(ids),
            pairing_secret: Arc::new(Mutex::new(None)),
            secret_key,
            transport,
            registry,
            device_cert,
            device_user_map,
            transfers,
            outbox: Arc::new(Mutex::new(queued)),
            flushing: Arc::new(DashSet::new()),
        }
    }

    /// `FILES_ALPN`: read a single `FileOffer` and queue it for `ray files`.
    /// Rejects offers whose claimed sender doesn't match the dialing identity.
    pub(crate) async fn accept_file_offer(self: &Arc<Self>, conn: Connection) {
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
                            {
                                let mut queue = pending.lock().unwrap();
                                evict_oldest_file(&mut queue, MAX_PENDING_FILES);
                                queue.push(PendingFile {
                                    id,
                                    from,
                                    filename,
                                    size,
                                    mime_type,
                                    blob_hash,
                                });
                            }
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
    pub(crate) async fn try_auto_accept_file(self: &Arc<Self>, id: u64) {
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
        self: &Arc<Self>,
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

        // Claim the blob before fetching it. `fetch` leaves what it downloads
        // untagged, so a GC triggered by some other transfer finishing mid-fetch
        // would sweep the bytes out from under us. The tag is dropped again as
        // soon as the file reaches its destination, on every exit path below.
        let recv_tag = blob_tags::recv(&blob_hash, pending_file.id);
        if let Err(e) = self
            .transport
            .blob_store
            .tags()
            .set(&recv_tag, iroh_blobs::HashAndFormat::raw(blob_hash))
            .await
        {
            return ipc_err(format!("blob store error: {e}"));
        }

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
                    self.reclaim_blob(recv_tag);
                    return ipc_err(format!("blob fetch failed: {e}"));
                }
                None => {
                    self.reclaim_blob(recv_tag);
                    return ipc_err("blob fetch ended without a result".to_string());
                }
            }
        }

        let dir = match output {
            Some(ref p) => PathBuf::from(p),
            None => dirs::download_dir().unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("Downloads")
            }),
        };

        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.reclaim_blob(recv_tag);
            return ipc_err(format!("cannot create directory '{}': {e}", dir.display()));
        }

        // Export straight from the blob store to the destination. The obvious
        // alternative, `get_bytes` + `fs::write`, materializes the whole file in
        // memory first (iroh-blobs documents it as "will run out of memory when
        // called for very large blobs"), which on a phone sharing a video is a
        // kill, not a slowdown. The fetch above already streamed the bytes to
        // disk, so there is no reason to route them through RAM again.
        let dest = dir.join(&pending_file.filename);
        if let Err(e) = self
            .transport
            .blob_store
            .blobs()
            .export(blob_hash, &dest)
            .await
        {
            self.reclaim_blob(recv_tag);
            return ipc_err(format!("write failed: {e}"));
        }
        // The file is where the user wanted it, so the store's copy is now pure
        // duplication: every accepted file used to be kept twice, forever.
        self.reclaim_blob(recv_tag);

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
        // Same guard the fd path applies: a FIFO or a character device would
        // stall or balloon the import.
        let size = match std::fs::metadata(file_path) {
            Ok(m) if m.is_file() => m.len(),
            Ok(_) => return ipc_err(format!("not a regular file: '{}'", file_path.display())),
            Err(e) => return ipc_err(format!("cannot read '{}': {e}", file_path.display())),
        };
        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let peer_id = match self.registry.resolve_peer_flexible(peer).await {
            Some(id) => id,
            None => return ipc_err(format!("unknown peer '{peer}'")),
        };
        // `add_path` streams the file into the blob store a chunk at a time (and
        // reflinks instead of copying where the filesystem supports it). Reading
        // the whole file into a `Vec` first, as this used to, meant peak memory of
        // one full file per concurrent send, which is what killed the Android app
        // on large videos.
        let temp = match self
            .transport
            .blob_store
            .blobs()
            .add_path(file_path)
            .temp_tag()
            .await
        {
            Ok(t) => t,
            Err(e) => return ipc_err(format!("blob store error: {e}")),
        };
        self.queue_offer(peer_id, peer, filename, size, temp).await
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
        let file = File::from(fd);
        // fstat before reading: an fd is attacker-chosen input, and reading a
        // FIFO or a device (/dev/zero) here would stall or balloon the daemon.
        let size = match file.metadata() {
            Ok(m) if m.is_file() => m.len(),
            Ok(_) => return ipc_err("not a regular file"),
            Err(e) => return ipc_err(format!("cannot stat file: {e}")),
        };
        // The client names the file; keep only the basename so a hostile
        // client can't smuggle path components into the offer.
        let filename = Path::new(filename)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let peer_id = match self.registry.resolve_peer_flexible(peer).await {
            Some(id) => id,
            None => return ipc_err(format!("unknown peer '{peer}'")),
        };
        // There is no path to hand `add_path` here, only the caller's fd, so feed
        // the store a chunk stream off the descriptor. Same reason as the path
        // case: `read_to_end` into a `Vec` put the whole file in RAM.
        let chunks = ReaderStream::new(tokio::fs::File::from_std(file));
        let temp = match self
            .transport
            .blob_store
            .blobs()
            .add_stream(chunks)
            .await
            .temp_tag()
            .await
        {
            Ok(t) => t,
            Err(e) => return ipc_err(format!("blob store error: {e}")),
        };
        self.queue_offer(peer_id, peer, filename, size, temp).await
    }

    /// Shared tail of the send flow: pin the imported blob with a durable tag,
    /// queue the offer, and reply immediately. Delivery is asynchronous: a
    /// background flush attempts it right away, and the outbox re-flushes
    /// whenever a mesh connection to the peer comes up, so a send to an offline
    /// peer parks here instead of making the caller wait on an unbounded dial.
    ///
    /// `temp` is the import's temp tag. It keeps the blob alive only as long as
    /// it is held, so the durable `send/<hash>/<peer>` tag has to be in place
    /// before it drops at the end of this function. The sender's copy is
    /// reclaimed when the peer finishes pulling it (see `note_send_completed`),
    /// not here: the offer can sit undelivered for days, and the bytes have to
    /// outlive that wait.
    async fn queue_offer(
        self: &Arc<Self>,
        peer_id: EndpointId,
        peer: &str,
        filename: String,
        size: u64,
        temp: iroh_blobs::api::TempTag,
    ) -> IpcMessage {
        let hash = blake3::Hash::from_bytes(*temp.hash().as_bytes());
        if let Err(e) = self.tag_blob(blob_tags::send(&hash, &peer_id), temp).await {
            return ipc_err(e);
        }

        // Register the transfer now, before the peer can possibly learn the hash:
        // it is only after the import above that the blob exists to be pulled,
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

    /// The peer finished pulling a blob we offered it: our copy has done its job,
    /// so drop this send's tag and let GC reclaim the bytes if nothing else
    /// points at them. Driven by the provider's `Completed` event, which is the
    /// only authoritative "they got it" a sender ever gets.
    ///
    /// Not called on an aborted pull: a peer that gave up halfway will retry, and
    /// the outbox offer is still live.
    pub(crate) fn note_send_completed(self: &Arc<Self>, hash: iroh_blobs::Hash, peer: EndpointId) {
        let hash = blake3::Hash::from_bytes(*hash.as_bytes());
        self.reclaim_blob(blob_tags::send(&hash, &peer));
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

    /// Sweep the queued file offers, accepting any that now qualify. Called
    /// after `net.auto-accept-files` is turned on so a file that arrived before
    /// the toggle still lands, instead of sitting in the queue until the sender
    /// retries.
    pub(crate) async fn drain_auto_acceptable(self: &Arc<Self>) {
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

        *self.pairing_secret.lock().unwrap() = Some(PairingSession {
            secret,
            opened: Instant::now(),
        });

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
                        // Certify the key that actually dialed us. The client
                        // always sends its own endpoint id here (`mesh/files.rs`),
                        // so requiring it costs nothing and removes the question
                        // of what a cert for a third key would mean if a ticket
                        // were ever relayed.
                        if device_pubkey != remote_id {
                            tracing::warn!(
                                claimed = %device_pubkey.fmt_short(),
                                actual = %remote_id.fmt_short(),
                                "pair request asks to certify a different key; refusing"
                            );
                            return;
                        }
                        // Compare against the stored pairing secret and consume
                        // it only on a match, both under one lock. Taking it
                        // first meant any dialer that sent the wrong bytes (or
                        // garbage) closed the user's pairing window from across
                        // the internet: the ticket names our endpoint and nothing
                        // else gates this ALPN.
                        //
                        // Leaving the secret in place on a mismatch is what makes
                        // the comparison's timing matter, so it is constant-time.
                        // A wrong guess no longer ends the session, so guesses are
                        // now unlimited for as long as the window is open, and an
                        // early-exiting `==` over 32 bytes would answer how much
                        // of the prefix was right.
                        let check = {
                            let mut held = pairing_secret.lock().unwrap();
                            match held.as_ref() {
                                // Expired: clear it on the way past, so the state
                                // does not outlive the window the user opened.
                                Some(s) if s.opened.elapsed() >= PAIRING_TTL => {
                                    held.take();
                                    PairCheck::NoSession
                                }
                                Some(s) if ct_eq(&s.secret, &secret) => {
                                    held.take();
                                    PairCheck::Accepted
                                }
                                // Keep the window open for the real device.
                                Some(_) => PairCheck::Mismatch,
                                None => PairCheck::NoSession,
                            }
                        };
                        match check {
                            PairCheck::Accepted => {
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
                                                // The new device fetches and opens
                                                // the blob before it is admitted,
                                                // so the key has to travel with
                                                // the network it names.
                                                read_key: n.read_key.map(|rk| rk.to_bytes()),
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
                            PairCheck::Mismatch => {
                                tracing::warn!(peer = %remote_id.fmt_short(), "pairing secret mismatch");
                            }
                            PairCheck::NoSession => {
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
    use iroh_blobs::Hash;
    use std::time::Instant;

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

    /// Two outstanding sends of one file must be two tags over one blob, so the
    /// first pickup cannot sweep the bytes the second recipient still needs.
    #[test]
    fn send_tags_are_per_recipient() {
        let hash = blake3::hash(b"same file");
        let a = SecretKey::from([1u8; 32]).public();
        let b = SecretKey::from([2u8; 32]).public();
        assert_ne!(blob_tags::send(&hash, &a), blob_tags::send(&hash, &b));
        // ...and stable, since the name is re-derived rather than stored: the
        // reclaim after a daemon restart has to find the same tag.
        assert_eq!(blob_tags::send(&hash, &a), blob_tags::send(&hash, &a));
    }

    /// Same, for two senders offering identical content: accepting one offer
    /// must not collect the blob the other is still fetching.
    #[test]
    fn recv_tags_are_per_offer() {
        let hash = iroh_blobs::Hash::from_bytes(*blake3::hash(b"same file").as_bytes());
        assert_ne!(blob_tags::recv(&hash, 1), blob_tags::recv(&hash, 2));
    }

    /// A short-interval store, so a test can watch a sweep happen instead of
    /// waiting out `BLOB_GC_INTERVAL`.
    async fn gc_store(dir: &std::path::Path) -> FsStore {
        let mut opts = iroh_blobs::store::fs::options::Options::new(dir);
        opts.gc = Some(iroh_blobs::store::GcConfig {
            interval: Duration::from_millis(100),
            add_protected: None,
        });
        FsStore::load_with_opts(dir.join("blobs.db"), opts)
            .await
            .unwrap()
    }

    /// An untagged blob, there to be collected. Its disappearance is the only
    /// sound signal that a sweep ran to completion, so every assertion below
    /// waits on one instead of on the clock.
    async fn canary(store: &FsStore, dir: &std::path::Path, name: &str) -> Hash {
        let path = dir.join(name);
        // Past the 16 KiB inline threshold, so this is a real on-disk blob.
        std::fs::write(&path, vec![3u8; 64 * 1024]).unwrap();
        let temp = store.blobs().add_path(&path).temp_tag().await.unwrap();
        temp.hash()
    }

    /// Wait for a sweep to collect `hash`. A fixed sleep here is a deadline the
    /// test loses whenever the runner is slow enough: the sweep is a background
    /// task on a 100ms timer, and on a loaded two-core CI box it does not always
    /// land inside the budget a fast laptop never misses. Poll for the effect,
    /// and keep the timeout far above any real sweep so a failure means gc is
    /// broken rather than busy.
    async fn collected(store: &FsStore, hash: Hash, what: &str) {
        let start = Instant::now();
        while store.blobs().has(hash).await.unwrap() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "gc never collected {what}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The invariant the whole reclaim design rests on: a tagged blob survives
    /// garbage collection, and dropping its tag is what frees the bytes. If GC
    /// ever stopped honoring tags this would delete files mid-transfer; if it
    /// stopped collecting untagged blobs the store would grow forever, which is
    /// the bug this replaced.
    #[tokio::test]
    async fn dropping_a_tag_is_what_frees_the_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let store = gc_store(tmp.path()).await;

        // Import past the 16 KiB inline threshold, so this exercises a real
        // on-disk blob rather than one stored inside the metadata db.
        let src = tmp.path().join("payload.bin");
        std::fs::write(&src, vec![7u8; 64 * 1024]).unwrap();
        let temp = store.blobs().add_path(&src).temp_tag().await.unwrap();
        let hash = temp.hash();
        let tag = "send/test".to_string();
        store
            .tags()
            .set(&tag, iroh_blobs::HashAndFormat::raw(hash))
            .await
            .unwrap();
        drop(temp);

        // Added after the tag, so the sweep that takes it is one that already
        // saw the tag: surviving that sweep is the thing being asserted.
        let canary = canary(&store, tmp.path(), "canary.bin").await;
        collected(&store, canary, "the untagged canary").await;
        assert!(
            store.blobs().has(hash).await.unwrap(),
            "a tagged blob must survive gc"
        );

        store.tags().delete(&tag).await.unwrap();
        collected(&store, hash, "the blob whose tag was deleted").await;
    }

    /// `accept_file` tags the blob *before* fetching it, so for a moment the tag
    /// names a hash the store does not have yet. That must neither error nor
    /// abort the sweep, or a GC firing mid-fetch would take out unrelated
    /// in-flight transfers.
    #[tokio::test]
    async fn a_tag_for_an_absent_blob_does_not_break_gc() {
        let tmp = tempfile::tempdir().unwrap();
        let store = gc_store(tmp.path()).await;

        let absent = iroh_blobs::Hash::from_bytes(*blake3::hash(b"never fetched").as_bytes());
        store
            .tags()
            .set("recv/pending", iroh_blobs::HashAndFormat::raw(absent))
            .await
            .unwrap();

        // A real, tagged blob alongside it: if the dangling tag aborted the mark
        // phase, the sweep would either skip everything or collect this.
        let src = tmp.path().join("payload.bin");
        std::fs::write(&src, vec![9u8; 64 * 1024]).unwrap();
        let temp = store.blobs().add_path(&src).temp_tag().await.unwrap();
        let present = temp.hash();
        store
            .tags()
            .set("send/live", iroh_blobs::HashAndFormat::raw(present))
            .await
            .unwrap();
        drop(temp);

        // An untagged blob, purely so the assertions below can tell "gc ran and
        // behaved" apart from "gc never ran". Without it every assertion here
        // would also hold if the sweep had silently aborted.
        let junk_hash = canary(&store, tmp.path(), "junk.bin").await;

        collected(&store, junk_hash, "the untagged canary").await;
        assert!(
            store.blobs().has(present).await.unwrap(),
            "gc must still protect tagged blobs despite a dangling tag"
        );
        assert!(!store.blobs().has(absent).await.unwrap());
    }
}

#[cfg(test)]
mod pairing_secret_tests {
    use super::ct_eq;

    /// The comparison has to be exact wherever the difference falls, since the
    /// whole point of the constant-time form is that it does not stop early.
    #[test]
    fn ct_eq_matches_equality() {
        let a = [7u8; 32];
        assert!(ct_eq(&a, &a));
        for pos in [0usize, 15, 31] {
            let mut b = a;
            b[pos] ^= 1;
            assert!(!ct_eq(&a, &b), "must differ at byte {pos}");
        }
        assert!(!ct_eq(&a, &[0u8; 32]));
    }
}
