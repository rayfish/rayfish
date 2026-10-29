//! File-transfer and device-pairing state, owned as one unit instead of being
//! split across `ProtocolRouter` (pending offers, id counter, pairing secret,
//! signing key) and `Daemon`.
//!
//! The file and pairing ALPN accept arms live
//! here; the `ProtocolRouter` accept loop holds an `Arc<FileService>` and
//! delegates to them. The IPC handlers (`send_file`/`accept_file`/`start_pairing`
//! /…) stay on `Daemon` since they orchestrate over core handles (endpoint,
//! peers, the shared blob store) and read this service's state.

use super::transfers;
use super::*;
#[cfg(unix)]
use std::ffi::CString;
use std::hint::black_box;
use std::path::PathBuf;

use futures::StreamExt;
use iroh_blobs::api::remote::GetProgressItem;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
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
struct FlushGuard {
    flushing: Arc<DashSet<EndpointId>>,
    peer: EndpointId,
}

impl Drop for FlushGuard {
    fn drop(&mut self) {
        self.flushing.remove(&self.peer);
    }
}

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

    pub(super) fn send(hash: &iroh_blobs::Hash, peer: &EndpointId) -> String {
        format!("send/{hash}/{}", peer.fmt_short())
    }

    pub(super) fn send_offer(
        hash: &iroh_blobs::Hash,
        peer: &EndpointId,
        offer_id: control::FileOfferId,
    ) -> String {
        format!(
            "{}/{}",
            send(hash, peer),
            blake3::Hash::from_bytes(offer_id.0)
        )
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
    fn reclaim_blob(&self, tag: String) {
        reclaim_blob(self.transport.blob_store.clone(), tag);
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

fn reclaim_blob(store: FsStore, tag: String) {
    tokio::spawn(async move {
        if let Err(e) = store.tags().delete(&tag).await {
            tracing::warn!(%tag, error = %e, "could not drop blob tag");
        }
    });
}

/// Return an unsuccessful receive to the queue, including when its task is canceled.
struct ReceiveOfferGuard {
    file: Option<PendingFile>,
    pending: Arc<Mutex<Vec<PendingFile>>>,
    active: Arc<Mutex<Vec<PendingFile>>>,
    offer_id: control::FileOfferId,
    transfers: Arc<transfers::TransferRegistry>,
    store: FsStore,
}

impl Drop for ReceiveOfferGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let mut queue = self.pending.lock().unwrap();
            let mut active = self.active.lock().unwrap();
            active.retain(|entry| entry.offer_id != self.offer_id);
            make_room(&mut queue, &self.store);
            queue.push(file);
            let durable: Vec<_> = queue.iter().chain(active.iter()).cloned().collect();
            if let Err(error) = save_pending_files(&durable) {
                tracing::warn!(%error, "could not persist restored file offer");
            }
            self.transfers.changed();
        }
    }
}

/// Evict the oldest queued offer if the queue is full, and release the receive
/// tag that kept its partially fetched data.
fn make_room(queue: &mut Vec<PendingFile>, store: &FsStore) {
    if let Some(evicted) = evict_oldest_file(queue, MAX_PENDING_FILES) {
        reclaim_blob(
            store.clone(),
            blob_tags::recv(&evicted.blob_hash, evicted.id),
        );
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

#[derive(Clone, Serialize, Deserialize)]
struct FileDecision {
    #[serde(default)]
    accepted: bool,
    peer: EndpointId,
    offer_id: control::FileOfferId,
    delivered: bool,
}

fn decline_path() -> Option<PathBuf> {
    config::config_dir()
        .ok()
        .map(|dir| dir.join("file-decisions.json"))
}

fn load_declines() -> Vec<FileDecision> {
    let Some(path) = decline_path() else {
        return Vec::new();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Vec<FileDecision>>(&bytes)
            .map(|mut entries| {
                entries.truncate(MAX_PENDING_FILES);
                entries
            })
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "could not read file declines");
                Vec::new()
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            tracing::warn!(%error, "could not read file declines");
            Vec::new()
        }
    }
}

/// An outbound send waiting for its peer. Persisted (JSON, in the config dir)
/// so a queued send survives a daemon restart; the bytes themselves already
/// live in the persistent blob store. `id` is session-local, reassigned on load.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OutboxEntry {
    #[serde(default)]
    offer_id: control::FileOfferId,
    #[serde(default)]
    delivered: bool,
    #[serde(default)]
    blob_tag: Option<String>,
    #[serde(skip)]
    transfer_id: u64,
    #[serde(skip)]
    pub(crate) id: u64,
    pub(crate) peer: EndpointId,
    pub(crate) filename: String,
    pub(crate) size: u64,
    pub(crate) blob_hash: blake3::Hash,
}

/// A received file offer awaiting `ray files accept`.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PendingFile {
    offer_id: control::FileOfferId,
    pub(crate) id: u64,
    pub(crate) from: EndpointId,
    pub(crate) filename: String,
    pub(crate) size: u64,
    pub(crate) mime_type: String,
    pub(crate) blob_hash: iroh_blobs::Hash,
}

fn pending_files_path() -> Option<PathBuf> {
    config::config_dir()
        .ok()
        .map(|dir| dir.join("pending-files.json"))
}

fn load_pending_files() -> Vec<PendingFile> {
    let Some(path) = pending_files_path() else {
        return Vec::new();
    };
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Vec<PendingFile>>(&bytes)
            .map(|mut files| {
                files.truncate(MAX_PENDING_FILES);
                files
            })
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "could not load pending files");
                Vec::new()
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            tracing::warn!(%error, "could not load pending files");
            Vec::new()
        }
    }
}

fn save_pending_files(pending: &[PendingFile]) -> Result<(), String> {
    let path = pending_files_path().ok_or_else(|| "cannot resolve config directory".to_string())?;
    let bytes = serde_json::to_vec(pending).map_err(|error| error.to_string())?;
    config::write_file(&path, &bytes, true).map_err(|error| error.to_string())
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

/// Drop the oldest queued offer when `pending` is at `cap`, returning it.
/// Offers are pushed in arrival order, so the oldest is the front.
pub(crate) fn evict_oldest_file(pending: &mut Vec<PendingFile>, cap: usize) -> Option<PendingFile> {
    if pending.len() < cap {
        return None;
    }
    let dropped = pending.remove(0);
    tracing::warn!(
        evicted = dropped.id,
        from = %dropped.from.fmt_short(),
        "pending file-offer queue full; evicted oldest offer"
    );
    Some(dropped)
}

/// Take the queued offer with `id` out of `pending`, if it is still there.
/// Shared by accept and reject. Taking an offer prevents a second accept or
/// reject from racing with its receive; a failed receive puts it back.
pub(crate) fn take_pending(pending: &mut Vec<PendingFile>, id: u64) -> Option<PendingFile> {
    let i = pending.iter().position(|f| f.id == id)?;
    Some(pending.remove(i))
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

fn saved_pair_networks() -> Result<Vec<control::PairNetwork>> {
    Ok(config::load()?
        .networks
        .into_iter()
        .filter_map(|network| {
            network.network_public_key.map(|key| control::PairNetwork {
                name: network.name,
                network_key: key.to_string(),
            })
        })
        .collect())
}

fn authorized_network_sync(
    cert: &control::DeviceCert,
    remote: EndpointId,
    primary: EndpointId,
    revoked: &[EndpointId],
) -> bool {
    cert.verify()
        && cert.device_key == remote
        && cert.user_identity == primary
        && !revoked.contains(&remote)
}

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

/// How long a primary waits, after sending a device its certificate, for the
/// device to confirm it saved it.
const CERTIFICATE_SAVED_TIMEOUT: Duration = Duration::from_secs(10);

/// Wait for the device that was just sent its certificate at `generation` to
/// confirm it saved it (`PairMsg::CertificateSaved`), save that, then close the
/// connection, which the device waits for. Until a device confirms, an unpair
/// request about its earlier pairing still revokes it.
async fn await_certificate_saved(conn: &Connection, device: EndpointId, generation: u64) {
    let confirmation = async {
        let (_send, mut recv) = conn.accept_bi().await?;
        control::recv_framed::<control::PairMsg>(&mut recv).await
    };
    match tokio::time::timeout(CERTIFICATE_SAVED_TIMEOUT, confirmation).await {
        Ok(Ok(control::PairMsg::CertificateSaved { generation: saved })) if saved == generation => {
            if let Err(error) = save_certificate_saved(device, generation) {
                tracing::warn!(device = %device.fmt_short(), error = %format!("{error:#}"), "could not save that the device saved its certificate");
            }
            conn.close(VarInt::from_u32(0), b"saved");
        }
        Ok(Ok(_)) => {
            tracing::warn!(device = %device.fmt_short(), "unexpected message after pairing");
        }
        Ok(Err(error)) => {
            tracing::debug!(device = %device.fmt_short(), error = %format!("{error:#}"), "device did not confirm it saved its certificate");
        }
        Err(_) => {
            tracing::debug!(device = %device.fmt_short(), "timed out waiting for the device to confirm it saved its certificate");
        }
    }
}

/// Outcome of checking a presented pairing secret. Separate from the stored value
/// so the lock is dropped before the (slow) success path runs.
enum PairCheck {
    Accepted,
    Mismatch,
    NoSession,
}

struct FileOfferOutcome {
    offer_id: control::FileOfferId,
    reply: control::FileReply,
    auto_accept: Option<u64>,
}

impl FileOfferOutcome {
    fn declined(offer_id: control::FileOfferId, reason: impl Into<String>) -> Self {
        Self {
            offer_id,
            reply: control::FileReply::Declined {
                reason: reason.into(),
            },
            auto_accept: None,
        }
    }
}

pub(crate) struct FileService {
    /// Received file offers awaiting `ray files accept`.
    pub(crate) pending_files: Arc<Mutex<Vec<PendingFile>>>,
    /// Monotonic id source for pending offers.
    file_id_counter: AtomicU64,
    active_files: Arc<Mutex<Vec<PendingFile>>>,
    /// Active pairing secret and when it was opened (set by `start_pairing`,
    /// consumed by a matching pair request, and expired by [`PAIRING_TTL`]).
    pairing_secret: Mutex<Option<PairingSession>>,
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
    declines: Mutex<Vec<FileDecision>>,
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
            entry.transfer_id = transfers.register_send(
                entry.peer,
                entry.filename.clone(),
                entry.size,
                entry.blob_hash.into(),
            );
        }
        let declines = load_declines();
        let pending: Vec<_> = load_pending_files()
            .into_iter()
            .filter(|file| {
                !declines
                    .iter()
                    .any(|entry| entry.peer == file.from && entry.offer_id == file.offer_id)
            })
            .collect();
        // Preserve incoming IDs because receive blob tags are derived from them.
        for file in &pending {
            ids.fetch_max(file.id.saturating_add(1), Ordering::Relaxed);
        }
        Self {
            pending_files: Arc::new(Mutex::new(pending)),
            file_id_counter: ids,
            active_files: Arc::new(Mutex::new(Vec::new())),
            pairing_secret: Mutex::new(None),
            secret_key,
            transport,
            registry,
            device_cert,
            device_user_map,
            transfers,
            outbox: Arc::new(Mutex::new(queued)),
            flushing: Arc::new(DashSet::new()),
            declines: Mutex::new(declines),
        }
    }

    /// `FILES_ALPN`: read a single `FileOffer` and queue it for `ray files`.
    /// Rejects offers whose claimed sender doesn't match the dialing identity.
    /// An idle Android node also checks the current roster before reading an
    /// offer, so unknown endpoints cannot make the phone process file metadata.
    pub(crate) async fn accept_file_offer(self: &Arc<Self>, conn: Connection) {
        let remote_id = conn.remote_id();
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if self.transport.is_suspended()
            && self
                .registry
                .resolve_route(IpAddr::V6(derive_ipv6(&remote_id)))
                .is_none()
        {
            conn.close(VarInt::from_u32(0), b"unknown file sender");
            return;
        }
        let exchange = async {
            let (mut send, mut recv) = conn.accept_bi().await?;
            let outcome = match control::recv_msg(&mut recv).await? {
                control::ControlMsg::FileOffer {
                    from,
                    filename,
                    size,
                    mime_type,
                    blob_hash,
                    offer_id,
                } => self.queue_incoming_offer(
                    remote_id,
                    PendingFile {
                        id: self.file_id_counter.fetch_add(1, Ordering::Relaxed),
                        offer_id,
                        from,
                        filename,
                        size,
                        mime_type,
                        blob_hash: blob_hash.into(),
                    },
                ),
                control::ControlMsg::FileCompleted { offer_id } => {
                    match self.record_remote_completion(remote_id, offer_id) {
                        Ok(()) => FileOfferOutcome {
                            offer_id,
                            reply: control::FileReply::Received,
                            auto_accept: None,
                        },
                        Err(error) => FileOfferOutcome::declined(
                            offer_id,
                            format!("could not save file completion: {error}"),
                        ),
                    }
                }
                control::ControlMsg::FileDeclined { offer_id, reason } => {
                    match self.record_remote_decline(remote_id, offer_id, reason) {
                        Ok(()) => FileOfferOutcome {
                            offer_id,
                            reply: control::FileReply::Received,
                            auto_accept: None,
                        },
                        Err(error) => FileOfferOutcome::declined(
                            offer_id,
                            format!("could not save file decline: {error}"),
                        ),
                    }
                }
                _ => anyhow::bail!("unexpected file message"),
            };
            control::send_msg(
                &mut send,
                None,
                &control::ControlMsg::FileOfferReply {
                    offer_id: outcome.offer_id,
                    reply: outcome.reply,
                },
            )
            .await?;
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
            anyhow::Ok(outcome.auto_accept)
        };
        match tokio::time::timeout(OFFER_CONNECT_TIMEOUT, exchange).await {
            Ok(Ok(Some(id))) => self.try_auto_accept_file(id).await,
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, peer = %remote_id.fmt_short(), "file exchange failed")
            }
            Err(error) => {
                tracing::warn!(%error, peer = %remote_id.fmt_short(), "file exchange timed out")
            }
        }
    }

    fn queue_incoming_offer(&self, remote: EndpointId, file: PendingFile) -> FileOfferOutcome {
        let offer_id = file.offer_id;
        if file.from != remote {
            return FileOfferOutcome::declined(offer_id, "file offer sender identity mismatch");
        }
        let decisions = self.declines.lock().unwrap();
        if let Some(decision) = decisions
            .iter()
            .find(|entry| entry.peer == remote && entry.offer_id == offer_id)
        {
            return if decision.accepted {
                FileOfferOutcome {
                    offer_id,
                    reply: control::FileReply::Completed,
                    auto_accept: None,
                }
            } else {
                FileOfferOutcome::declined(offer_id, "recipient declined the file")
            };
        }
        let unanswered = decisions.iter().filter(|entry| !entry.delivered).count();
        drop(decisions);
        let mut queue = self.pending_files.lock().unwrap();
        if let Some(existing) = queue
            .iter()
            .find(|entry| entry.from == remote && entry.offer_id == offer_id)
        {
            return FileOfferOutcome {
                offer_id,
                reply: control::FileReply::Received,
                auto_accept: Some(existing.id),
            };
        }
        let active = self.active_files.lock().unwrap();
        if active
            .iter()
            .any(|entry| entry.from == remote && entry.offer_id == offer_id)
        {
            return FileOfferOutcome {
                offer_id,
                reply: control::FileReply::Received,
                auto_accept: None,
            };
        }
        if queue.len() + active.len() + unanswered >= MAX_PENDING_FILES {
            return FileOfferOutcome::declined(offer_id, "recipient file offer queue is full");
        }
        let id = file.id;
        queue.push(file);
        let durable: Vec<_> = queue.iter().chain(active.iter()).cloned().collect();
        if let Err(error) = save_pending_files(&durable) {
            queue.pop();
            return FileOfferOutcome::declined(
                offer_id,
                format!("could not save file offer: {error}"),
            );
        }
        self.transfers.changed();
        FileOfferOutcome {
            offer_id,
            reply: control::FileReply::Received,
            auto_accept: Some(id),
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

    pub(crate) fn should_auto_accept_file(&self, from: EndpointId) -> bool {
        let trusted = config::load()
            .map(|cfg| cfg.file_auto_accept_peers.contains(&from))
            .unwrap_or(false);
        trusted
            || (self.is_own_device_sender(from) && self.registry.member_on_autoaccept_network(from))
    }

    /// Evaluate a newly-queued (or already-pending) file offer against the
    /// trusted-peer or own-device policy. Explicit trust applies to the exact
    /// sender identity. Own devices still require an opted-in shared network.
    /// Leaves the offer queued unless it actually accepts via `accept_file`.
    pub(crate) async fn try_auto_accept_file(self: &Arc<Self>, id: u64) {
        // Peek the offer's sender without consuming the queue entry.
        let from = {
            let pending = self.pending_files.lock().unwrap();
            match pending.iter().find(|f| f.id == id) {
                Some(f) => f.from,
                None => return,
            }
        };

        if !self.should_auto_accept_file(from) {
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
                tracing::info!(from = %from.fmt_short(), %message, "file auto-accepted");
            }
            IpcMessage::Error { message } => {
                tracing::warn!(from = %from.fmt_short(), %message, "file auto-accept failed");
            }
            _ => {}
        }
    }

    /// Fetch a pending file's blob from its sender, write it to disk, and (when a
    /// `peer_cred` is given) chown it to that user. Failed receives stay queued
    /// with their downloaded ranges so the destination can retry.
    pub(crate) async fn accept_file(
        self: &Arc<Self>,
        id: u64,
        output: Option<String>,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        let pending_file = {
            let mut pending = self.pending_files.lock().unwrap();
            match take_pending(&mut pending, id) {
                Some(file) => {
                    self.active_files.lock().unwrap().push(file.clone());
                    file
                }
                None => {
                    return ipc_err(format!("no pending file with id {id}"));
                }
            }
        };

        let mut offer = ReceiveOfferGuard {
            offer_id: pending_file.offer_id,
            file: Some(pending_file),
            pending: Arc::clone(&self.pending_files),
            active: Arc::clone(&self.active_files),
            transfers: Arc::clone(&self.transfers),
            store: self.transport.blob_store.clone(),
        };
        let file = offer
            .file
            .as_ref()
            .expect("the offer is held until the receive succeeds");
        let peer = file.from;
        let response = self.receive_file(file, output, peer_cred).await;
        match response {
            IpcMessage::Ok { .. } => {
                if let Some(file) = offer.file.as_ref()
                    && let Err(error) = self.record_completed_offer(file)
                {
                    return ipc_err(format!(
                        "file saved but could not record delivery confirmation: {error}; retry with `ray files accept {id}`"
                    ));
                }
                offer.file.take();
                let pending = self.pending_files.lock().unwrap();
                let mut active = self.active_files.lock().unwrap();
                active.retain(|entry| entry.offer_id != offer.offer_id);
                let durable: Vec<_> = pending.iter().chain(active.iter()).cloned().collect();
                if let Err(error) = save_pending_files(&durable) {
                    tracing::warn!(%error, "could not persist completed incoming file");
                }
                drop(active);
                drop(pending);
                let service = Arc::clone(self);
                tokio::spawn(async move { service.flush_outbox_for(peer).await });
                response
            }
            IpcMessage::Error { message } => {
                ipc_err(format!("{message}; retry with `ray files accept {id}`"))
            }
            other => other,
        }
    }

    async fn receive_file(
        &self,
        pending_file: &PendingFile,
        output: Option<String>,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        #[cfg(windows)]
        let _ = peer_cred;
        let blob_hash = pending_file.blob_hash;
        let peer_label = pending_file.from.fmt_short().to_string();
        let transfer_id = self.transfers.register_receive(
            peer_label,
            pending_file.filename.clone(),
            pending_file.size,
        );
        // The offer is gone from the queue, but the receive stays visible
        // while the connection and fetch are in progress.
        let finish_guard = transfers::FinishGuard::new(Arc::clone(&self.transfers), transfer_id);

        // Claim the blob before fetching it. `fetch` leaves what it downloads
        // untagged, so a GC triggered by some other transfer finishing mid-fetch
        // would sweep the bytes out from under us. The tag is dropped again as
        // soon as the file reaches its destination or the offer is rejected.
        // Failed receives keep the tag so a retry can reuse the downloaded ranges.
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

        let local = match self.transport.blob_store.remote().local(blob_hash).await {
            Ok(local) => local,
            Err(e) => return ipc_err(format!("blob store error: {e}")),
        };
        let downloaded = local.local_bytes();
        self.transfers.note_progress(transfer_id, downloaded);
        if !local.is_complete() {
            let connect = transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
                pending_file.from,
                iroh_blobs::protocol::ALPN,
            );
            let conn = match tokio::time::timeout(OFFER_CONNECT_TIMEOUT, connect).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => return ipc_err(format!("cannot reach sender: {e}")),
                Err(_) => return ipc_err("cannot reach sender: connection timed out"),
            };

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
                    Some(GetProgressItem::Progress(n)) => self
                        .transfers
                        .note_progress(transfer_id, downloaded.saturating_add(n)),
                    Some(GetProgressItem::Done(_)) => break,
                    Some(GetProgressItem::Error(e)) => {
                        return ipc_err(format!("blob fetch failed: {e}"));
                    }
                    None => {
                        return ipc_err("blob fetch ended without a result".to_string());
                    }
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
            return ipc_err(format!("write failed: {e}"));
        }
        // The file is where the user wanted it, so the store's copy is now pure
        // duplication: every accepted file used to be kept twice, forever.
        self.reclaim_blob(recv_tag);

        #[cfg(unix)]
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
        let destination = std::fs::canonicalize(&dest).unwrap_or(dest.clone());
        finish_guard.success(&destination);

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

    /// `ray pair list`: enumerate this user's other paired devices as roster
    /// members sharing our `user_identity` but a different device id.
    pub(crate) fn list_paired_devices(&self) -> IpcMessage {
        let own_user = self.registry.own_identity();
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
        self.send_file_named(path, None, peer).await
    }

    pub(crate) async fn send_file_named(
        self: &Arc<Self>,
        path: &str,
        requested_filename: Option<&str>,
        peer: &str,
    ) -> IpcMessage {
        let file_path = Path::new(path);
        // Same guard the fd path applies: a FIFO or a character device would
        // stall or balloon the import.
        let size = match std::fs::metadata(file_path) {
            Ok(m) if m.is_file() => m.len(),
            Ok(_) => return ipc_err(format!("not a regular file: '{}'", file_path.display())),
            Err(e) => return ipc_err(format!("cannot read '{}': {e}", file_path.display())),
        };
        let filename = requested_filename
            .and_then(|name| Path::new(name).file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .or_else(|| {
                file_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
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
    #[cfg(unix)]
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
    /// it is held, so its durable per-offer tag has to be in place
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
        if self.outbox.lock().unwrap().len() >= MAX_PENDING_FILES {
            return ipc_err("file send queue is full; cancel a pending send first");
        }
        let hash = temp.hash();
        let offer_id = control::FileOfferId::new();
        let blob_tag = blob_tags::send_offer(&hash, &peer_id, offer_id);
        if let Err(e) = self.tag_blob(blob_tag.clone(), temp).await {
            return ipc_err(e);
        }

        // Register the transfer now, before the peer can possibly learn the hash:
        // it is only after the import above that the blob exists to be pulled,
        // and on auto-accept the receiver can fetch the entire blob the moment
        // the offer lands, so every provider event (Started/Progress/Completed)
        // must find the entry already registered.
        let transfer_id = self
            .transfers
            .register_send(peer_id, filename.clone(), size, hash);

        let entry = OutboxEntry {
            offer_id,
            delivered: false,
            blob_tag: Some(blob_tag.clone()),
            transfer_id,
            id: self.file_id_counter.fetch_add(1, Ordering::Relaxed),
            peer: peer_id,
            filename: filename.clone(),
            size,
            blob_hash: hash.into(),
        };
        let offer_id = entry.offer_id;
        {
            let mut outbox = self.outbox.lock().unwrap();
            if outbox.len() >= MAX_PENDING_FILES {
                drop(outbox);
                self.transfers.fail_offer(transfer_id);
                self.reclaim_blob(blob_tag);
                return ipc_err("file send queue is full; cancel a pending send first");
            }
            outbox.push(entry);
        }
        if let Err(error) = self.persist_outbox() {
            self.outbox
                .lock()
                .unwrap()
                .retain(|entry| entry.offer_id != offer_id);
            self.transfers.fail_offer(transfer_id);
            self.reclaim_blob(blob_tag);
            return ipc_err(format!("could not save queued file offer: {error}"));
        }

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
    /// blob-read completion signal. Cached receives confirm by offer identity.
    ///
    /// Not called on an aborted pull: keep the bytes for the receiver's retry.
    pub(crate) fn note_send_completed(self: &Arc<Self>, hash: iroh_blobs::Hash, peer: EndpointId) {
        let removed = {
            let mut entries = self.outbox.lock().unwrap();
            entries
                .iter()
                .position(|entry| {
                    entry.blob_tag.is_none()
                        && entry.peer == peer
                        && iroh_blobs::Hash::from(entry.blob_hash) == hash
                })
                .map(|index| entries.remove(index))
        };
        self.save_outbox();
        if let Some(entry) = removed {
            self.reclaim_send(&entry);
        }
    }

    fn reclaim_send(&self, entry: &OutboxEntry) {
        if let Some(tag) = &entry.blob_tag {
            self.reclaim_blob(tag.clone());
        } else {
            self.reclaim_send_if_unused(entry.blob_hash.into(), entry.peer);
        }
    }

    fn reclaim_send_if_unused(&self, hash: iroh_blobs::Hash, peer: EndpointId) {
        if !self
            .outbox
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry.peer == peer && iroh_blobs::Hash::from(entry.blob_hash) == hash)
        {
            self.reclaim_blob(blob_tags::send(&hash, &peer));
        }
    }

    fn record_remote_decline(
        &self,
        peer: EndpointId,
        offer_id: control::FileOfferId,
        reason: String,
    ) -> Result<(), String> {
        let removed = {
            let mut entries = self.outbox.lock().unwrap();
            entries
                .iter()
                .position(|entry| entry.peer == peer && entry.offer_id == offer_id)
                .map(|index| entries.remove(index))
        };
        if let Some(entry) = removed {
            if let Err(error) = self.persist_outbox() {
                self.outbox.lock().unwrap().push(entry);
                return Err(error);
            }
            self.transfers.decline_offer(entry.transfer_id, reason);
            self.reclaim_send(&entry);
        }
        Ok(())
    }

    fn record_remote_completion(
        &self,
        peer: EndpointId,
        offer_id: control::FileOfferId,
    ) -> Result<(), String> {
        let removed = {
            let mut entries = self.outbox.lock().unwrap();
            entries
                .iter()
                .position(|entry| entry.peer == peer && entry.offer_id == offer_id)
                .map(|index| entries.remove(index))
        };
        if let Some(entry) = removed {
            if let Err(error) = self.persist_outbox() {
                self.outbox.lock().unwrap().push(entry);
                return Err(error);
            }
            self.transfers.finish(entry.transfer_id, true);
            self.reclaim_send(&entry);
        }
        Ok(())
    }

    /// Distinct peers with queued sends that hold a live mesh connection right
    /// now: the periodic sweep's work list (it never dials offline peers).
    pub(crate) fn outbox_peers(&self) -> Vec<EndpointId> {
        let mut peers: Vec<EndpointId> =
            self.outbox.lock().unwrap().iter().map(|e| e.peer).collect();
        peers.extend(
            self.declines
                .lock()
                .unwrap()
                .iter()
                .filter(|entry| !entry.delivered)
                .map(|entry| entry.peer),
        );
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
        let _guard = FlushGuard {
            flushing: Arc::clone(&self.flushing),
            peer,
        };
        let entries: Vec<_> = self
            .outbox
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.peer == peer && !entry.delivered)
            .cloned()
            .collect();
        for entry in entries {
            // Upgraded outbox entries receive a new identity on load. Save it
            // before sending so a lost receipt and restart reuse that identity.
            if let Err(error) = self.persist_outbox() {
                tracing::warn!(%error, "could not save file offer before delivery");
                break;
            }
            match self.deliver_offer(&entry).await {
                Ok(control::FileReply::Received) => {
                    if let Some(queued) = self
                        .outbox
                        .lock()
                        .unwrap()
                        .iter_mut()
                        .find(|queued| queued.offer_id == entry.offer_id)
                    {
                        queued.delivered = true;
                    }
                    self.save_outbox();
                    self.transfers.changed();
                }
                Ok(control::FileReply::Completed) => {
                    if let Err(error) = self.record_remote_completion(peer, entry.offer_id) {
                        tracing::warn!(%error, "could not save completed send");
                        break;
                    }
                }
                Ok(control::FileReply::Declined { reason }) => {
                    if let Err(error) = self.record_remote_decline(peer, entry.offer_id, reason) {
                        tracing::warn!(%error, "could not save declined send");
                        break;
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, peer = %peer.fmt_short(), "file offer delivery failed; will retry");
                    break;
                }
            }
        }
        let declines: Vec<_> = self
            .declines
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.peer == peer && !entry.delivered)
            .cloned()
            .collect();
        for entry in declines {
            let msg = if entry.accepted {
                control::ControlMsg::FileCompleted {
                    offer_id: entry.offer_id,
                }
            } else {
                control::ControlMsg::FileDeclined {
                    offer_id: entry.offer_id,
                    reason: "recipient declined the file".into(),
                }
            };
            match self.exchange_file_message(peer, entry.offer_id, &msg).await {
                Ok(control::FileReply::Received) => {
                    if let Some(queued) = self
                        .declines
                        .lock()
                        .unwrap()
                        .iter_mut()
                        .find(|queued| queued.peer == peer && queued.offer_id == entry.offer_id)
                    {
                        queued.delivered = true;
                    }
                    if let Err(error) = self.save_declines() {
                        tracing::warn!(%error, "could not persist file decline delivery");
                    }
                }
                result => {
                    tracing::debug!(?result, peer = %peer.fmt_short(), "file decline delivery failed; will retry");
                    break;
                }
            }
        }
    }

    /// One bounded delivery attempt: dial `FILES_ALPN`, send the offer, wait
    /// for the peer to read it. The transfer entry stays Offered afterwards;
    /// the peer pulling the blob is what moves it (provider events).
    async fn deliver_offer(&self, entry: &OutboxEntry) -> Result<control::FileReply, String> {
        let msg = control::ControlMsg::FileOffer {
            from: self.transport.endpoint.id(),
            filename: entry.filename.clone(),
            size: entry.size,
            mime_type: guess_mime_type(&entry.filename),
            blob_hash: entry.blob_hash,
            offer_id: entry.offer_id,
        };
        self.exchange_file_message(entry.peer, entry.offer_id, &msg)
            .await
    }

    async fn exchange_file_message(
        &self,
        peer: EndpointId,
        offer_id: control::FileOfferId,
        msg: &control::ControlMsg,
    ) -> Result<control::FileReply, String> {
        tokio::time::timeout(
            OFFER_CONNECT_TIMEOUT,
            self.exchange_file_message_inner(peer, offer_id, msg),
        )
        .await
        .map_err(|_| "file exchange timed out".to_string())?
    }

    async fn exchange_file_message_inner(
        &self,
        peer: EndpointId,
        offer_id: control::FileOfferId,
        msg: &control::ControlMsg,
    ) -> Result<control::FileReply, String> {
        let conn = match transport::connect_to_peer_with_alpn(
            &self.transport.endpoint,
            peer,
            transport::FILES_ALPN,
        )
        .await
        {
            Ok(conn) => conn,
            Err(error) if transport::is_alpn_mismatch(&format!("{error:#}")) => {
                return Ok(control::FileReply::Declined {
                    reason: "peer uses an incompatible file protocol; update the peer".into(),
                });
            }
            Err(error) => return Err(format!("connect failed: {error}")),
        };
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("failed to open stream: {e}"))?;
        // File offers ride the separate FILES_ALPN, not the mesh demux, so they
        // carry no network scope.
        control::send_msg(&mut send, None, msg)
            .await
            .map_err(|e| format!("failed to send offer: {e}"))?;
        let response = control::recv_msg(&mut recv)
            .await
            .map_err(|error| format!("failed to read file reply: {error}"))?;
        match response {
            control::ControlMsg::FileOfferReply {
                offer_id: reply_id,
                reply,
            } if reply_id == offer_id => {
                conn.close(VarInt::from_u32(0), b"file reply received");
                Ok(reply)
            }
            _ => Err("unexpected file reply".to_string()),
        }
    }

    /// `ray files cancel <id>`: drop a queued send that hasn't been delivered.
    pub(crate) fn cancel_send(&self, id: u64) -> IpcMessage {
        let removed = {
            let mut outbox = self.outbox.lock().unwrap();
            let i = outbox.iter().position(|e| e.id == id && !e.delivered);
            i.map(|i| outbox.remove(i))
        };
        match removed {
            Some(entry) => {
                self.transfers.fail_offer(entry.transfer_id);
                self.save_outbox();
                self.reclaim_send(&entry);
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

    /// Cancel an outgoing transfer after its offer was delivered. A packet
    /// already in flight may finish, but this transfer cannot be revived and
    /// the local blob is released for GC.
    pub(crate) fn cancel_transfer(&self, id: u64) -> IpcMessage {
        match self.transfers.cancel(id) {
            Some((hash, peer)) => {
                let removed = {
                    let mut outbox = self.outbox.lock().unwrap();
                    outbox
                        .iter()
                        .position(|entry| entry.transfer_id == id)
                        .map(|index| outbox.remove(index))
                };
                self.save_outbox();
                if let Some(entry) = removed {
                    self.reclaim_send(&entry);
                } else {
                    self.reclaim_send_if_unused(hash, peer);
                }
                IpcMessage::Ok {
                    message: format!("canceled file transfer {id}"),
                }
            }
            None => ipc_err(format!("no active outgoing transfer with id {id}")),
        }
    }

    /// Persist the outbox (atomic write via `config::write_file`). Filenames
    /// and peers are not secrets in the config-dir threat model, but keep the
    /// file root-only like the rest of the daemon state.
    fn save_outbox(&self) {
        if let Err(error) = self.persist_outbox() {
            tracing::warn!(%error, "could not persist file send outbox");
        }
    }

    fn persist_outbox(&self) -> Result<(), String> {
        let path = outbox_path().ok_or_else(|| "cannot resolve config directory".to_string())?;
        let entries = self.outbox.lock().unwrap();
        let bytes = serde_json::to_vec(&*entries).map_err(|error| error.to_string())?;
        config::write_file(&path, &bytes, true).map_err(|error| error.to_string())
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
            .filter(|entry| !entry.delivered)
            .map(|e| ipc::OutboxFileInfo {
                id: e.id,
                peer: e.peer.fmt_short().to_string(),
                filename: e.filename.clone(),
                size: e.size,
            })
            .collect();
        let transfers = self
            .transfers
            .list()
            .into_iter()
            .map(|t| ipc::TransferFileInfo {
                id: t.id,
                outgoing: t.outgoing,
                peer: t.peer,
                filename: t.filename,
                size: t.size,
                transferred: t.transferred,
                state: match t.state {
                    transfers::TransferState::Offered => ipc::TransferFileState::Offered,
                    transfers::TransferState::Transferring => ipc::TransferFileState::Transferring,
                    transfers::TransferState::Done => ipc::TransferFileState::Done,
                    transfers::TransferState::Failed => ipc::TransferFileState::Failed,
                },
                destination: t.destination,
                error: t.error,
            })
            .collect();
        IpcMessage::FileList {
            files,
            outbox,
            transfers,
        }
    }

    /// Decline a pending file offer: drop it from the queue without fetching the
    /// blob. Release any data retained from an unsuccessful receive.
    pub(crate) fn reject_file(self: &Arc<Self>, id: u64) -> IpcMessage {
        let mut pending = self.pending_files.lock().unwrap();
        let Some(file) = pending.iter().find(|file| file.id == id) else {
            return ipc_err(format!("no pending file with id {id}"));
        };
        {
            let mut declines = self.declines.lock().unwrap();
            if declines.len() >= MAX_PENDING_FILES {
                if let Some(index) = declines.iter().position(|entry| entry.delivered) {
                    declines.remove(index);
                } else {
                    return ipc_err("file decline queue is full; retry after peers reconnect");
                }
            }
            declines.push(FileDecision {
                accepted: false,
                peer: file.from,
                offer_id: file.offer_id,
                delivered: false,
            });
        }
        if let Err(error) = self.save_declines() {
            self.declines
                .lock()
                .unwrap()
                .retain(|entry| entry.peer != file.from || entry.offer_id != file.offer_id);
            return ipc_err(format!("could not save file decline: {error}"));
        }
        let file =
            take_pending(&mut pending, id).expect("the offer remains locked until it is taken");
        let active = self.active_files.lock().unwrap();
        let durable: Vec<_> = pending.iter().chain(active.iter()).cloned().collect();
        if let Err(error) = save_pending_files(&durable) {
            tracing::warn!(%error, "could not persist removed incoming file");
        }
        drop(active);
        drop(pending);
        self.reclaim_blob(blob_tags::recv(&file.blob_hash, file.id));
        self.transfers.changed();
        let service = Arc::clone(self);
        let peer = file.from;
        tokio::spawn(async move { service.flush_outbox_for(peer).await });
        IpcMessage::Ok {
            message: format!("declined {} from {}", file.filename, peer.fmt_short()),
        }
    }

    fn record_completed_offer(&self, file: &PendingFile) -> Result<(), String> {
        {
            let mut decisions = self.declines.lock().unwrap();
            if decisions.len() >= MAX_PENDING_FILES {
                let index = decisions
                    .iter()
                    .position(|entry| entry.delivered)
                    .ok_or_else(|| "file decision queue is full".to_string())?;
                decisions.remove(index);
            }
            decisions.push(FileDecision {
                peer: file.from,
                offer_id: file.offer_id,
                accepted: true,
                delivered: false,
            });
        }
        if let Err(error) = self.save_declines() {
            self.declines
                .lock()
                .unwrap()
                .retain(|entry| entry.peer != file.from || entry.offer_id != file.offer_id);
            return Err(error);
        }
        Ok(())
    }

    fn save_declines(&self) -> Result<(), String> {
        let path = decline_path().ok_or_else(|| "cannot resolve config directory".to_string())?;
        let entries = self.declines.lock().unwrap();
        let bytes = serde_json::to_vec(&*entries).map_err(|error| error.to_string())?;
        config::write_file(&path, &bytes, true).map_err(|error| error.to_string())
    }

    /// Sweep the queued file offers, accepting any that now qualify. Called
    /// after a peer is trusted or own-device auto-accept is enabled, so earlier
    /// offers do not wait for the sender to retry.
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
    /// a `DeviceCert` binding the new device key to our identity. Also answers a
    /// paired device's network list request and, over version 3 only, its
    /// unpair request.
    pub(crate) async fn accept_pair_request(&self, conn: Connection) {
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                // Read one length-prefixed pairing protocol message.
                let request: control::PairMsg = match control::recv_framed(&mut recv).await {
                    Ok(request) => request,
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
                            let mut held = self.pairing_secret.lock().unwrap();
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
                                if let Err(error) = self
                                    .registry
                                    .remember_independent_paired_device(device_pubkey)
                                {
                                    tracing::warn!(%error, "could not record existing memberships before pairing");
                                    return;
                                }
                                // The pairing's generation, one above the device's
                                // last, saved before it gets the cert signed at it,
                                // in the same write that ends the notices `ray
                                // unpair` left it. A notice or request about an
                                // earlier pairing names a lower generation, so
                                // neither undoes this one if it is acted on late.
                                // A deliberate (re-)pair also re-authorizes this
                                // device first, clearing any nullifier for it
                                // (durable seed + every coordinated blob) with
                                // the records published: the device joins the
                                // networks shared below at once, and a record
                                // still nullifying it would end the new pairing.
                                let generation = match self
                                    .registry
                                    .save_new_pairing(device_pubkey)
                                    .await
                                {
                                    Ok(generation) => generation,
                                    Err(message) => {
                                        tracing::warn!(device = %device_pubkey.fmt_short(), %message, "could not save the pairing; refusing it");
                                        conn.close(
                                            VarInt::from_u32(0),
                                            b"the primary could not save the pairing; pair again",
                                        );
                                        return;
                                    }
                                };
                                // Sign the device's public key
                                // Share our saved networks so the new device can auto-join them. Only
                                // networks with a known public key (skips freshly created, unsynced ones).
                                let networks = saved_pair_networks().unwrap_or_default();
                                let cert = control::DeviceCert::create(
                                    &self.secret_key,
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
                                // A device on version 3 confirms once the cert is
                                // saved, which is what makes a request about its
                                // earlier pairing obsolete.
                                if conn.alpn() == PAIR_ALPN {
                                    await_certificate_saved(&conn, device_pubkey, generation).await;
                                }
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
                    control::PairMsg::NetworkListRequest { cert } => {
                        let Ok(cfg) = config::load() else {
                            return;
                        };
                        if !authorized_network_sync(
                            &cert,
                            remote_id,
                            self.transport.endpoint.id(),
                            &config::revoked_device_ids(&cfg),
                        ) {
                            tracing::warn!(device = %remote_id.fmt_short(), "refused paired network sync");
                            return;
                        }
                        let Ok(networks) = saved_pair_networks() else {
                            return;
                        };
                        let response = control::PairMsg::NetworkListResponse { networks };
                        if control::send_framed(&mut send, &response).await.is_ok() {
                            let _ = send.finish();
                            let _ =
                                tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                        }
                    }
                    control::PairMsg::UnpairRequest { cert } => {
                        // New in version 3; a version 2 peer never sends it.
                        if conn.alpn() != PAIR_ALPN {
                            tracing::warn!(device = %remote_id.fmt_short(), "unpair request over pairing version 2; ignoring");
                            return;
                        }
                        // The certificate is the evidence of the pairing, checked in
                        // place of the rosters, which a device that left its
                        // networks is no longer on: it must be ours, and for the
                        // key that dialed.
                        if !cert.verify()
                            || cert.user_identity != self.transport.endpoint.id()
                            || cert.device_key != remote_id
                        {
                            tracing::warn!(device = %remote_id.fmt_short(), "refused unpair request without a certificate we issued to it");
                            return;
                        }
                        // Answered only once the revocation is saved, and again
                        // when it already was, so a lost answer is safe to ask for.
                        // A pairing the device has replaced since, and confirmed
                        // the replacement of, is answered without a revocation,
                        // which would end the new one.
                        match self
                            .registry
                            .record_unpair(remote_id, cert.generation)
                            .await
                        {
                            Ok(true) => {
                                tracing::info!(device = %remote_id.fmt_short(), "recorded unpair requested by the device");
                            }
                            Ok(false) => {
                                tracing::info!(device = %remote_id.fmt_short(), "unpair request for a pairing the device has since replaced; nothing to revoke");
                            }
                            Err(error) => {
                                tracing::warn!(device = %remote_id.fmt_short(), %error, "could not record unpair request");
                                return;
                            }
                        }
                        if control::send_framed(&mut send, &control::PairMsg::UnpairRecorded)
                            .await
                            .is_ok()
                        {
                            let _ = send.finish();
                            let _ =
                                tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
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

    async fn file_service(endpoint: Endpoint, dir: &Path) -> Arc<FileService> {
        let store = FsStore::load(dir).await.unwrap();
        let registry = crate::daemon::accept_handler_tests::sample_registry(
            endpoint.clone(),
            IrohIdentityProvider::new(endpoint.id()),
            store,
        );
        Arc::new(FileService::new(
            SecretKey::generate(),
            Arc::clone(&registry.transport),
            registry,
            None,
            peers::DeviceUserMap::new(),
            Arc::new(transfers::TransferRegistry::new()),
        ))
    }

    async fn file_endpoint(lookup: iroh::address_lookup::memory::MemoryLookup) -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![transport::FILES_ALPN.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .address_lookup(lookup)
            .bind()
            .await
            .unwrap()
    }

    fn outgoing(service: &FileService, peer: EndpointId, seed: u8) -> OutboxEntry {
        let hash = blake3::hash(b"payload");
        OutboxEntry {
            id: u64::from(seed),
            offer_id: control::FileOfferId([seed; 32]),
            delivered: false,
            blob_tag: None,
            transfer_id: service
                .transfers
                .register_send(peer, "file.bin".into(), 7, hash.into()),
            peer,
            filename: "file.bin".into(),
            size: 7,
            blob_hash: hash,
        }
    }

    #[tokio::test]
    async fn file_receipt_deduplicates_and_survives_a_receiver_restart() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let sender_endpoint = file_endpoint(lookup.clone()).await;
        let receiver_endpoint = file_endpoint(lookup.clone()).await;
        lookup.add_endpoint_info(sender_endpoint.addr());
        lookup.add_endpoint_info(receiver_endpoint.addr());
        let sender = file_service(sender_endpoint, &tmp.path().join("sender")).await;
        let receiver = file_service(receiver_endpoint.clone(), &tmp.path().join("receiver")).await;
        let entry = outgoing(&sender, receiver_endpoint.id(), 1);
        for _ in 0..2 {
            let (reply, ()) = tokio::join!(sender.deliver_offer(&entry), async {
                let conn = receiver_endpoint.accept().await.unwrap().await.unwrap();
                receiver.accept_file_offer(conn).await;
            });
            assert!(matches!(reply.unwrap(), control::FileReply::Received));
        }
        assert_eq!(receiver.pending_files.lock().unwrap().len(), 1);
        let restarted =
            file_service(receiver_endpoint.clone(), &tmp.path().join("restarted")).await;
        assert_eq!(restarted.pending_files.lock().unwrap().len(), 1);
        let (reply, ()) = tokio::join!(sender.deliver_offer(&entry), async {
            let conn = receiver_endpoint.accept().await.unwrap().await.unwrap();
            restarted.accept_file_offer(conn).await;
        });
        assert!(matches!(reply.unwrap(), control::FileReply::Received));
        assert_eq!(restarted.pending_files.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_offer_without_an_application_receipt_stays_queued() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let sender_endpoint = file_endpoint(lookup.clone()).await;
        let receiver_endpoint = file_endpoint(lookup.clone()).await;
        lookup.add_endpoint_info(receiver_endpoint.addr());
        let sender = file_service(sender_endpoint, &tmp.path().join("sender")).await;
        sender
            .outbox
            .lock()
            .unwrap()
            .push(outgoing(&sender, receiver_endpoint.id(), 1));
        let ((), ()) = tokio::join!(
            Arc::clone(&sender).flush_outbox_for(receiver_endpoint.id()),
            async {
                let conn = receiver_endpoint.accept().await.unwrap().await.unwrap();
                let (_send, mut recv) = conn.accept_bi().await.unwrap();
                assert!(matches!(
                    control::recv_msg(&mut recv).await.unwrap(),
                    control::ControlMsg::FileOffer { .. }
                ));
                conn.close(VarInt::from_u32(0), b"no receipt");
            }
        );
        let queued = sender.outbox.lock().unwrap();
        assert!(!queued[0].delivered);
        let saved = load_outbox();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].offer_id, queued[0].offer_id);
    }

    #[tokio::test]
    async fn decline_retries_after_a_lost_connection_and_fails_only_its_offer() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let sender_endpoint = file_endpoint(lookup.clone()).await;
        let receiver_endpoint = file_endpoint(lookup.clone()).await;
        lookup.add_endpoint_info(sender_endpoint.addr());
        lookup.add_endpoint_info(receiver_endpoint.addr());
        let sender = file_service(sender_endpoint.clone(), &tmp.path().join("sender")).await;
        let receiver = file_service(receiver_endpoint.clone(), &tmp.path().join("receiver")).await;
        let mut first = outgoing(&sender, receiver_endpoint.id(), 1);
        first.delivered = true;
        let mut second = outgoing(&sender, receiver_endpoint.id(), 2);
        second.delivered = true;
        let first_id = first.transfer_id;
        let second_id = second.transfer_id;
        let offer_id = second.offer_id;
        sender.outbox.lock().unwrap().extend([first, second]);
        sender.save_outbox();
        receiver.declines.lock().unwrap().push(FileDecision {
            accepted: false,
            peer: sender_endpoint.id(),
            offer_id,
            delivered: false,
        });
        receiver.save_declines().unwrap();
        let ((), ()) = tokio::join!(
            Arc::clone(&receiver).flush_outbox_for(sender_endpoint.id()),
            async {
                let conn = sender_endpoint.accept().await.unwrap().await.unwrap();
                let (_send, mut recv) = conn.accept_bi().await.unwrap();
                assert!(matches!(
                    control::recv_msg(&mut recv).await.unwrap(),
                    control::ControlMsg::FileDeclined { .. }
                ));
                conn.close(VarInt::from_u32(0), b"lost connection");
            }
        );
        assert!(!receiver.declines.lock().unwrap()[0].delivered);
        assert!(!load_declines()[0].delivered);
        let ((), ()) = tokio::join!(
            Arc::clone(&receiver).flush_outbox_for(sender_endpoint.id()),
            async {
                let conn = sender_endpoint.accept().await.unwrap().await.unwrap();
                sender.accept_file_offer(conn).await;
            }
        );
        assert!(receiver.declines.lock().unwrap()[0].delivered);
        let entries = sender.transfers.list();
        let first = entries.iter().find(|entry| entry.id == first_id).unwrap();
        let second = entries.iter().find(|entry| entry.id == second_id).unwrap();
        assert_eq!(first.state, transfers::TransferState::Offered);
        assert_eq!(second.state, transfers::TransferState::Failed);
        assert_eq!(second.error.as_deref(), Some("recipient declined the file"));
        sender
            .transfers
            .provider_started(blake3::hash(b"payload").into(), receiver_endpoint.id());
        assert_eq!(
            sender
                .transfers
                .list()
                .iter()
                .find(|entry| entry.id == second_id)
                .unwrap()
                .state,
            transfers::TransferState::Failed
        );
        assert_eq!(load_outbox().len(), 1);
        assert!(load_declines()[0].delivered);
    }

    #[tokio::test]
    async fn a_completed_offer_is_acknowledged_without_being_queued_again() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let endpoint = file_endpoint(iroh::address_lookup::memory::MemoryLookup::new()).await;
        let service = file_service(endpoint.clone(), &tmp.path().join("receiver")).await;
        let file = pending(1);
        service.record_completed_offer(&file).unwrap();
        let restarted = file_service(endpoint, &tmp.path().join("restarted")).await;
        let outcome = restarted.queue_incoming_offer(file.from, file);
        assert!(matches!(outcome.reply, control::FileReply::Completed));
        assert!(outcome.auto_accept.is_none());
        assert!(restarted.pending_files.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_incompatible_file_protocol_fails_instead_of_retrying() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let sender_endpoint = file_endpoint(lookup.clone()).await;
        let receiver_endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![b"rayfish/files/2".to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(receiver_endpoint.addr());
        let sender = file_service(sender_endpoint, &tmp.path().join("sender")).await;
        let entry = outgoing(&sender, receiver_endpoint.id(), 1);
        let transfer_id = entry.transfer_id;
        sender.outbox.lock().unwrap().push(entry);
        let ((), ()) = tokio::join!(
            Arc::clone(&sender).flush_outbox_for(receiver_endpoint.id()),
            async {
                assert!(receiver_endpoint.accept().await.unwrap().await.is_err());
            }
        );
        assert!(sender.outbox.lock().unwrap().is_empty());
        let transfers = sender.transfers.list();
        let transfer = transfers
            .iter()
            .find(|entry| entry.id == transfer_id)
            .unwrap();
        assert_eq!(transfer.state, transfers::TransferState::Failed);
        assert_eq!(
            transfer.error.as_deref(),
            Some("peer uses an incompatible file protocol; update the peer")
        );
    }

    #[tokio::test]
    async fn active_receive_survives_new_offers_retries_and_cancellation() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let endpoint = file_endpoint(iroh::address_lookup::memory::MemoryLookup::new()).await;
        let service = file_service(endpoint, &tmp.path().join("receiver")).await;
        let first = pending(1);
        let from = first.from;
        let offer_id = first.offer_id;
        service.queue_incoming_offer(from, first);
        let file = take_pending(&mut service.pending_files.lock().unwrap(), 1).unwrap();
        service.active_files.lock().unwrap().push(file.clone());
        let guard = ReceiveOfferGuard {
            file: Some(file),
            offer_id,
            pending: Arc::clone(&service.pending_files),
            active: Arc::clone(&service.active_files),
            transfers: Arc::clone(&service.transfers),
            store: service.transport.blob_store.clone(),
        };
        let second = pending(2);
        service.queue_incoming_offer(second.from, second);
        assert_eq!(load_pending_files().len(), 2);
        let outcome = service.queue_incoming_offer(from, pending(1));
        assert!(matches!(outcome.reply, control::FileReply::Received));
        assert!(outcome.auto_accept.is_none());
        assert_eq!(service.pending_files.lock().unwrap().len(), 1);
        drop(guard);
        assert!(service.active_files.lock().unwrap().is_empty());
        assert_eq!(service.pending_files.lock().unwrap().len(), 2);
        assert_eq!(load_pending_files().len(), 2);
    }

    #[tokio::test]
    async fn a_cached_receive_completes_the_sender_without_a_provider_event() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let sender_endpoint = file_endpoint(lookup.clone()).await;
        let receiver_endpoint = file_endpoint(lookup.clone()).await;
        lookup.add_endpoint_info(sender_endpoint.addr());
        lookup.add_endpoint_info(receiver_endpoint.addr());
        let sender = file_service(sender_endpoint.clone(), &tmp.path().join("sender")).await;
        let receiver = file_service(receiver_endpoint.clone(), &tmp.path().join("receiver")).await;
        let mut entry = outgoing(&sender, receiver_endpoint.id(), 1);
        entry.delivered = true;
        let transfer_id = entry.transfer_id;
        let mut file = pending(1);
        file.from = sender_endpoint.id();
        file.offer_id = entry.offer_id;
        file.filename = "file.bin".into();
        file.size = 7;
        sender.outbox.lock().unwrap().push(entry);
        let source = tmp.path().join("cached.bin");
        std::fs::write(&source, b"payload").unwrap();
        let _tag = receiver
            .transport
            .blob_store
            .blobs()
            .add_path(&source)
            .temp_tag()
            .await
            .unwrap();
        receiver.queue_incoming_offer(sender_endpoint.id(), file);
        let (response, ()) = tokio::join!(
            receiver.accept_file(
                1,
                Some(tmp.path().join("downloads").to_string_lossy().into_owned()),
                None
            ),
            async {
                let conn = sender_endpoint.accept().await.unwrap().await.unwrap();
                sender.accept_file_offer(conn).await;
            }
        );
        assert!(matches!(response, IpcMessage::Ok { .. }));
        assert_eq!(
            std::fs::read(tmp.path().join("downloads/file.bin")).unwrap(),
            b"payload"
        );
        assert!(sender.outbox.lock().unwrap().is_empty());
        assert_eq!(
            sender
                .transfers
                .list()
                .iter()
                .find(|entry| entry.id == transfer_id)
                .unwrap()
                .state,
            transfers::TransferState::Done
        );
    }

    #[tokio::test]
    async fn failed_completion_persistence_keeps_the_saved_offer_retryable() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let endpoint = file_endpoint(iroh::address_lookup::memory::MemoryLookup::new()).await;
        let service = file_service(endpoint, &tmp.path().join("receiver")).await;
        let mut file = pending(1);
        file.filename = "file.bin".into();
        file.size = 7;
        let source = tmp.path().join("cached.bin");
        std::fs::write(&source, b"payload").unwrap();
        let _tag = service
            .transport
            .blob_store
            .blobs()
            .add_path(&source)
            .temp_tag()
            .await
            .unwrap();
        service.queue_incoming_offer(file.from, file);
        std::fs::create_dir(decline_path().unwrap()).unwrap();
        let response = service
            .accept_file(
                1,
                Some(tmp.path().join("downloads").to_string_lossy().into_owned()),
                None,
            )
            .await;
        let IpcMessage::Error { message } = response else {
            panic!("confirmation failure must be reported")
        };
        assert!(message.contains("file saved but could not record delivery confirmation"));
        assert_eq!(
            std::fs::read(tmp.path().join("downloads/file.bin")).unwrap(),
            b"payload"
        );
        assert_eq!(service.pending_files.lock().unwrap().len(), 1);
        assert!(service.active_files.lock().unwrap().is_empty());
        assert!(service.declines.lock().unwrap().is_empty());
        assert_eq!(load_pending_files().len(), 1);
    }

    #[tokio::test]
    async fn provider_completion_keeps_modern_same_content_offers_until_exact_replies() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let endpoint = file_endpoint(iroh::address_lookup::memory::MemoryLookup::new()).await;
        let service = file_service(endpoint, &tmp.path().join("sender")).await;
        let peer = SecretKey::generate().public();
        let mut first = outgoing(&service, peer, 1);
        let mut second = outgoing(&service, peer, 2);
        let first_id = first.transfer_id;
        let second_id = second.transfer_id;
        let first_offer = first.offer_id;
        let second_offer = second.offer_id;
        let hash = first.blob_hash.into();
        first.blob_tag = Some(blob_tags::send_offer(&hash, &peer, first_offer));
        second.blob_tag = Some(blob_tags::send_offer(&hash, &peer, second_offer));
        service.outbox.lock().unwrap().extend([first, second]);
        service.transfers.provider_finished(hash, peer, true);
        service.note_send_completed(hash, peer);
        assert_eq!(service.outbox.lock().unwrap().len(), 2);
        service
            .record_remote_decline(peer, first_offer, "recipient declined the file".into())
            .unwrap();
        service
            .record_remote_completion(peer, second_offer)
            .unwrap();
        assert!(service.outbox.lock().unwrap().is_empty());
        let entries = service.transfers.list();
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.id == first_id)
                .unwrap()
                .state,
            transfers::TransferState::Failed
        );
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.id == second_id)
                .unwrap()
                .state,
            transfers::TransferState::Done
        );
    }

    #[tokio::test]
    async fn invalid_or_full_file_offers_receive_an_explicit_decline() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let endpoint = file_endpoint(iroh::address_lookup::memory::MemoryLookup::new()).await;
        let service = file_service(endpoint, &tmp.path().join("receiver")).await;
        let from = pending(1).from;
        assert!(matches!(
            service.queue_incoming_offer(from, pending(2)).reply,
            control::FileReply::Declined { .. }
        ));
        *service.pending_files.lock().unwrap() =
            (1..=MAX_PENDING_FILES as u64).map(pending).collect();
        let mut file = pending(999);
        file.offer_id = control::FileOfferId::new();
        assert!(matches!(
            service.queue_incoming_offer(file.from, file).reply,
            control::FileReply::Declined { .. }
        ));
    }

    #[test]
    fn paired_network_list_requires_a_valid_cert_for_the_dialer() {
        let primary = SecretKey::generate();
        let device = SecretKey::generate().public();
        let stranger = SecretKey::generate().public();
        let cert = control::DeviceCert::create(&primary, &device, 0);
        assert!(authorized_network_sync(
            &cert,
            device,
            primary.public(),
            &[]
        ));
        assert!(!authorized_network_sync(
            &cert,
            stranger,
            primary.public(),
            &[]
        ));
        assert!(!authorized_network_sync(&cert, device, stranger, &[]));
        assert!(!authorized_network_sync(
            &cert,
            device,
            primary.public(),
            &[device],
        ));
        let mut forged = cert;
        forged.user_identity = stranger;
        assert!(!authorized_network_sync(&forged, device, stranger, &[]));
    }

    fn pending(id: u64) -> PendingFile {
        PendingFile {
            offer_id: control::FileOfferId([id as u8; 32]),
            id,
            from: SecretKey::from([id as u8; 32]).public(),
            filename: format!("file{id}.bin"),
            size: 1,
            mime_type: "application/octet-stream".to_string(),
            blob_hash: blake3::hash(b"payload").into(),
        }
    }

    /// `ray files accept` and `ray files reject` both consume the offer, so a
    /// second command on the same id must find nothing left to act on.
    #[test]
    fn taking_a_pending_offer_removes_only_that_one() {
        let mut queue = vec![pending(1), pending(2), pending(3)];

        let taken = take_pending(&mut queue, 2).expect("id 2 is queued");
        assert_eq!(taken.id, 2);
        assert_eq!(
            queue.iter().map(|f| f.id).collect::<Vec<_>>(),
            vec![1, 3],
            "the other offers stay queued, in order"
        );

        assert!(
            take_pending(&mut queue, 2).is_none(),
            "an id already taken is gone, not taken twice"
        );
        assert!(take_pending(&mut queue, 99).is_none());
        assert_eq!(queue.len(), 2, "a miss leaves the queue untouched");
    }

    #[tokio::test]
    async fn canceled_receive_restores_the_offer_and_keeps_its_blob() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let store = gc_store(tmp.path()).await;
        let src = tmp.path().join("payload.bin");
        std::fs::write(&src, vec![7u8; 64 * 1024]).unwrap();
        let temp = store.blobs().add_path(&src).temp_tag().await.unwrap();
        let hash = temp.hash();
        let tag = blob_tags::recv(&hash, 1);
        store
            .tags()
            .set(&tag, temp.hash_and_format())
            .await
            .unwrap();
        drop(temp);

        let mut file = pending(1);
        file.blob_hash = hash;
        let queue = Arc::new(Mutex::new(vec![file, pending(2)]));
        let transfers = Arc::new(transfers::TransferRegistry::new());
        let mut changes = transfers.subscribe();
        let offer = ReceiveOfferGuard {
            file: take_pending(&mut queue.lock().unwrap(), 1),
            pending: Arc::clone(&queue),
            active: Arc::new(Mutex::new(Vec::new())),
            offer_id: control::FileOfferId::new(),
            transfers,
            store: store.clone(),
        };
        assert!(take_pending(&mut queue.lock().unwrap(), 1).is_none());
        assert!(!changes.has_changed().unwrap());
        drop(offer);
        changes.changed().await.unwrap();

        let retried = take_pending(&mut queue.lock().unwrap(), 1).unwrap();
        assert_eq!(retried.blob_hash, hash);
        assert_eq!(queue.lock().unwrap()[0].id, 2);
        let junk = canary(&store, tmp.path(), "canary.bin").await;
        collected(&store, junk, "the untagged canary").await;
        assert!(store.blobs().has(hash).await.unwrap());

        // Once the retained receive tag is released, GC can collect the data.
        reclaim_blob(store.clone(), tag);
        collected(&store, hash, "the rejected receive").await;
    }

    #[tokio::test]
    async fn successful_receive_does_not_restore_the_offer() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let store = FsStore::load(tmp.path()).await.unwrap();
        let queue = Arc::new(Mutex::new(vec![pending(2)]));
        let mut offer = ReceiveOfferGuard {
            file: Some(pending(1)),
            pending: Arc::clone(&queue),
            active: Arc::new(Mutex::new(Vec::new())),
            offer_id: control::FileOfferId::new(),
            transfers: Arc::new(transfers::TransferRegistry::new()),
            store,
        };
        offer.file.take();
        drop(offer);
        assert!(take_pending(&mut queue.lock().unwrap(), 1).is_none());
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn restored_receive_caps_the_queue_and_reclaims_evicted_data() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let store = gc_store(tmp.path()).await;
        let src = tmp.path().join("payload.bin");
        std::fs::write(&src, vec![5u8; 64 * 1024]).unwrap();
        let temp = store.blobs().add_path(&src).temp_tag().await.unwrap();
        let hash = temp.hash();
        store
            .tags()
            .set(blob_tags::recv(&hash, 1), temp.hash_and_format())
            .await
            .unwrap();
        drop(temp);
        let mut files: Vec<_> = (1..=MAX_PENDING_FILES as u64).map(pending).collect();
        files[0].blob_hash = hash;
        let queue = Arc::new(Mutex::new(files));
        let offer = ReceiveOfferGuard {
            file: Some(pending(999)),
            pending: Arc::clone(&queue),
            active: Arc::new(Mutex::new(Vec::new())),
            offer_id: control::FileOfferId::new(),
            transfers: Arc::new(transfers::TransferRegistry::new()),
            store: store.clone(),
        };
        drop(offer);
        assert_eq!(queue.lock().unwrap().len(), MAX_PENDING_FILES);
        assert!(take_pending(&mut queue.lock().unwrap(), 1).is_none());
        assert!(take_pending(&mut queue.lock().unwrap(), 999).is_some());
        collected(&store, hash, "the evicted receive").await;
    }

    /// Pins the outbox persistence format: `EndpointId` and `blake3::Hash`
    /// must survive a JSON round trip (the file is reloaded across daemon
    /// restarts, so a serde-shape regression would silently drop the queue).
    #[test]
    fn outbox_entry_roundtrips_through_json() {
        let peer = SecretKey::from([7u8; 32]).public();
        let entry = OutboxEntry {
            offer_id: control::FileOfferId([3; 32]),
            delivered: false,
            blob_tag: None,
            transfer_id: 0,
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
        let content = blake3::hash(b"same file");
        let hash = iroh_blobs::Hash::from(content);
        let a = SecretKey::from([1u8; 32]).public();
        let b = SecretKey::from([2u8; 32]).public();
        // The name is persisted in the blob store, so it must keep the shape it
        // had when it was built from the blake3 hash directly.
        assert_eq!(
            blob_tags::send(&hash, &a),
            format!("send/{}/{}", content.to_hex(), a.fmt_short())
        );
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
