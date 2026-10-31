//! Running an accepted receive, and resuming it when the connection drops.
//!
//! An accepted file is fetched by a task the service owns, not by the request
//! that accepted it. `ray files accept` waits for the outcome and the macOS app
//! does not, but the receive depends on neither: a CLI that is killed, or a
//! laptop that sleeps through a download, leaves the task running.
//!
//! When a fetch is interrupted (the sender is unreachable, the connection
//! drops, or the stream stops moving), the task waits with capped exponential
//! backoff and fetches again. iroh-blobs only asks for the ranges the store is
//! missing, and the receive tag keeps the partial data out of GC, so each
//! attempt continues where the last one stopped. This is the same thing a
//! manual re-accept used to do.
//!
//! The sender keeps an offer's blob tagged until the receiver confirms or
//! declines it, or the sender cancels; there is no expiry on that side. So the
//! retries are bounded on this side instead: [`ResumePolicy::give_up_after`]
//! without a single new byte ends the receive. Giving up, like any other
//! failure, returns the offer to the queue with its downloaded ranges, so a
//! later `ray files accept` still resumes it.
//!
//! Errors that another attempt cannot fix end the receive at once: the sender
//! no longer having the file, data that does not match the offered hash, and
//! local store or disk failures.
//!
//! An accepted receive is saved with its destination in `pending-files.json`,
//! so a daemon restart picks it up again ([`FileService::resume_accepted_receives`])
//! instead of returning it to the queue. Only a failure or a cancel turns it
//! back into a plain offer.

use super::*;

use iroh::endpoint::{ReadError, WriteError};
use iroh_blobs::get::GetError;
use iroh_blobs::get::fsm::{AtBlobHeaderNextError, ConnectedNextError, DecodeError};
use tokio::sync::{Semaphore, oneshot};

/// Receives fetching at once. Auto-accept can start a whole queue together;
/// the rest wait their turn while showing as in progress.
pub(super) const MAX_CONCURRENT_RECEIVES: usize = 4;

const SENDER_GONE: &str =
    "the sender no longer has this file (the send may have been canceled); reject the offer";

/// Timing for one receive's attempts.
#[derive(Debug, Clone, Copy)]
pub(super) struct ResumePolicy {
    /// Bound on dialing the sender.
    pub(super) connect_timeout: Duration,
    /// A fetch that yields no progress for this long is treated as a dead
    /// connection. After a suspend the QUIC connection is gone, but a stream
    /// read can still wait on it; this makes sure it ends.
    pub(super) idle_timeout: Duration,
    /// Wait before the first retry, doubled after each failed attempt that
    /// moved no bytes.
    pub(super) first_backoff: Duration,
    pub(super) max_backoff: Duration,
    /// How long to keep trying without receiving a single byte. Counted as
    /// the time spent trying (see [`NoProgress`]), not as time elapsed, so a
    /// night with the lid closed does not count against it on any platform.
    pub(super) give_up_after: Duration,
}

/// How long a receive whose caller waits for it, the phone apps' accept, keeps
/// trying without progress. Short, since the caller is blocked for all of it;
/// what arrived is kept, so accepting again carries on from there.
const BLOCKING_GIVE_UP_AFTER: Duration = Duration::from_secs(2 * 60);

impl ResumePolicy {
    /// This policy for a caller that blocks until the receive ends.
    pub(super) fn for_blocking_call(self) -> Self {
        Self {
            give_up_after: self.give_up_after.min(BLOCKING_GIVE_UP_AFTER),
            ..self
        }
    }
}

impl Default for ResumePolicy {
    fn default() -> Self {
        Self {
            connect_timeout: OFFER_CONNECT_TIMEOUT,
            idle_timeout: Duration::from_secs(60),
            first_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            give_up_after: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// Time spent trying since a receive last moved a byte, for
/// [`ResumePolicy::give_up_after`].
///
/// Not the time elapsed: whether a clock counts a suspend differs between
/// platforms (Windows' can), and a laptop that sleeps through a night with one
/// attempt pending must not come back to a receive it gave up on. So it adds
/// up the backoff waits it asked for and each failed attempt's own duration,
/// with an attempt capped at the longest one could take awake (a connect
/// timeout, then an idle one). However long a suspend inside either lasts,
/// it counts as at most that.
#[derive(Debug)]
struct NoProgress {
    spent: Duration,
    longest_attempt: Duration,
}

impl NoProgress {
    fn new(policy: &ResumePolicy) -> Self {
        Self {
            spent: Duration::ZERO,
            longest_attempt: policy.connect_timeout.saturating_add(policy.idle_timeout),
        }
    }

    /// Bytes moved: start counting again.
    fn reset(&mut self) {
        self.spent = Duration::ZERO;
    }

    /// An attempt that moved nothing, as long as it took by the clock.
    fn failed_attempt(&mut self, took: Duration) {
        self.spent = self.spent.saturating_add(took.min(self.longest_attempt));
    }

    /// A backoff wait that was asked for.
    fn waited(&mut self, wait: Duration) {
        self.spent = self.spent.saturating_add(wait);
    }

    /// Whether waiting `next` more would go past `limit`.
    fn exhausted(&self, next: Duration, limit: Duration) -> bool {
        self.spent.saturating_add(next) > limit
    }
}

/// Why one fetch attempt stopped.
#[derive(Debug)]
enum FetchError {
    /// The connection failed; another attempt can continue the fetch.
    Interrupted { reason: String, progressed: bool },
    /// Retrying cannot help.
    Fatal(String),
}

/// The in-flight receives, keyed by transfer id, so `cancel-transfer` can
/// stop one. Each token is a child of the daemon's shutdown token.
pub(super) type ActiveReceives = Arc<Mutex<HashMap<u64, CancellationToken>>>;

pub(super) fn receive_slots() -> Semaphore {
    Semaphore::new(MAX_CONCURRENT_RECEIVES)
}

impl FileService {
    /// Check that offer `id` could be saved where it is going, then start
    /// receiving it. A directory the file could never be saved in is refused
    /// here, before anything is downloaded, with the offer left queued.
    pub(super) async fn begin_receive(
        self: &Arc<Self>,
        id: u64,
        output: Option<String>,
        recipient: Recipient,
        policy: ResumePolicy,
    ) -> OpResult<oneshot::Receiver<OpResult<Done>>> {
        let filename = {
            let pending = self.pending_files.lock().unwrap();
            let Some(file) = pending.iter().find(|file| file.id == id) else {
                return op_err(format!("no pending file with id {id}"));
            };
            file.filename.clone()
        };
        let dir = receive_dir(output.as_deref());
        let checked = recipient.clone();
        let usable =
            tokio::task::spawn_blocking(move || receive_dest::check(&dir, &filename, &checked))
                .await
                .map_err(|e| OpError::msg(format!("destination check failed: {e}")))?;
        if let Err(e) = usable {
            return op_err(format!("cannot save the file: {e}"));
        }
        self.start_receive(id, output, recipient, policy)
    }

    /// Take pending offer `id` and start receiving it in a task the service
    /// owns, retrying as `policy` says. The returned channel carries the
    /// outcome; dropping it leaves the receive running.
    pub(super) fn start_receive(
        self: &Arc<Self>,
        id: u64,
        output: Option<String>,
        recipient: Recipient,
        policy: ResumePolicy,
    ) -> OpResult<oneshot::Receiver<OpResult<Done>>> {
        let file = {
            let mut pending = self.pending_files.lock().unwrap();
            let Some(mut file) = take_pending(&mut pending, id) else {
                return op_err(format!("no pending file with id {id}"));
            };
            file.accepted = recipient.survives_restart().then(|| AcceptedReceive {
                output: output.clone(),
                recipient: recipient.clone(),
            });

            let mut active = self.active_files.lock().unwrap();
            active.push(file.clone());
            let durable: Vec<_> = pending.iter().chain(active.iter()).cloned().collect();
            if let Err(error) = save_pending_files(&durable) {
                tracing::warn!(%error, "could not save accepted file; it will not resume after a restart");
            }
            file
        };
        let transfer_id = self.transfers.register_receive(
            file.from.fmt_short().to_string(),
            file.filename.clone(),
            file.size,
        );
        // The offer is gone from the queue, but the receive stays visible
        // while it connects, fetches and retries.
        let finish = transfers::FinishGuard::new(Arc::clone(&self.transfers), transfer_id);
        let offer = ReceiveOfferGuard {
            shutdown: self.registry.shutdown_token.clone(),
            offer_id: file.offer_id,
            file: Some(file.clone()),
            pending: Arc::clone(&self.pending_files),
            active: Arc::clone(&self.active_files),
            transfers: Arc::clone(&self.transfers),
            store: self.transport.blob_store.clone(),
        };
        let cancel = self.registry.shutdown_token.child_token();
        self.receives
            .lock()
            .unwrap()
            .insert(transfer_id, cancel.clone());
        let (outcome_tx, outcome_rx) = oneshot::channel();
        let service = Arc::clone(self);
        let to = AcceptedReceive { output, recipient };
        tokio::spawn(async move {
            // Biased so a receive that finished in the same poll as a cancel
            // counts as finished.
            let written = tokio::select! {
                biased;
                written = service.run_receive(&file, transfer_id, to, policy) => written,
                () = cancel.cancelled() => Err("receive canceled".to_string()),
            };
            service.receives.lock().unwrap().remove(&transfer_id);
            // Naming the complete file is not canceled: once the rename has
            // happened, the outcome has to say so.
            let received = match written {
                Ok(written) => written
                    .commit()
                    .await
                    .map_err(|e| format!("write failed: {e}")),
                Err(error) => Err(error),
            };
            let outcome = service.finish_receive(offer, finish, received);
            match &outcome {
                Ok(Done(message)) => {
                    tracing::info!(from = %file.from.fmt_short(), %message, "file received")
                }
                Err(error) => {
                    tracing::warn!(from = %file.from.fmt_short(), %error, "file receive failed")
                }
            }
            // The caller may have stopped waiting; the outcome is logged above.
            let _ = outcome_tx.send(outcome);
        });
        Ok(outcome_rx)
    }

    /// Restart the receives that were accepted and still running when the
    /// daemon last stopped, into the destination they were accepted to. Not
    /// on Android, see the call site.
    #[cfg(not(target_os = "android"))]
    pub(crate) fn resume_accepted_receives(self: &Arc<Self>) {
        let accepted: Vec<_> = self
            .pending_files
            .lock()
            .unwrap()
            .iter()
            .filter_map(|file| file.accepted.clone().map(|to| (file.id, to)))
            .collect();
        for (id, to) in accepted {
            // Not awaited, as for auto-accept: the task logs its own outcome.
            match self.start_receive(id, to.output, to.recipient, self.resume) {
                Ok(_) => tracing::info!(id, "resuming accepted file receive"),
                Err(error) => tracing::warn!(id, %error, "could not resume file receive"),
            }
        }
    }

    /// Settle a finished receive: on success record the delivery and drop the
    /// offer for good; on failure leave it to `offer`, which returns it to the
    /// queue with its downloaded data.
    ///
    /// The delivery is recorded before the transfer is marked done and the
    /// blob released. If recording fails the file is still saved, so the offer
    /// is not queued again: accepting it a second time would only download it
    /// once more and save it beside the first copy.
    fn finish_receive(
        self: &Arc<Self>,
        mut offer: ReceiveOfferGuard,
        finish: transfers::FinishGuard,
        received: Result<PathBuf, String>,
    ) -> OpResult<Done> {
        let Some(file) = offer.file.take() else {
            return op_err("receive lost its offer");
        };
        let id = file.id;
        let dest = match received {
            Ok(dest) => dest,
            Err(error) => {
                offer.file = Some(file);
                finish.fail(error.clone());
                return op_err(format!("{error}; retry with `ray files accept {id}`"));
            }
        };
        let recorded = self.record_completed_offer(&file);
        self.forget_active(offer.offer_id);
        // The file is where the user wanted it, so the store's copy is now pure
        // duplication: every accepted file used to be kept twice, forever.
        self.reclaim_blob(blob_tags::recv(&file.blob_hash, file.id));
        if let Err(error) = recorded {
            let reason = format!(
                "saved to {} but could not record delivery confirmation: {error}",
                dest.display()
            );
            finish.fail(reason.clone());
            return op_err(reason);
        }
        // The file is fully on disk (chown failures are ignored, by design,
        // and never fail the transfer): only now is the transfer really done.
        let destination = std::fs::canonicalize(&dest).unwrap_or_else(|_| dest.clone());
        finish.success(&destination);
        let service = Arc::clone(self);
        let peer = file.from;
        tokio::spawn(async move { service.flush_outbox_for(peer).await });
        Ok(Done(format!("saved to {}", dest.display())))
    }

    /// Drop a finished receive from the active list and the saved queue.
    fn forget_active(&self, offer_id: control::FileOfferId) {
        let pending = self.pending_files.lock().unwrap();
        let mut active = self.active_files.lock().unwrap();
        active.retain(|entry| entry.offer_id != offer_id);
        let durable: Vec<_> = pending.iter().chain(active.iter()).cloned().collect();
        if let Err(error) = save_pending_files(&durable) {
            tracing::warn!(%error, "could not persist completed incoming file");
        }
    }

    /// Fetch the offer's blob, retrying interruptions, and write it to its
    /// destination under a temporary name.
    async fn run_receive(
        &self,
        file: &PendingFile,
        transfer_id: u64,
        to: AcceptedReceive,
        policy: ResumePolicy,
    ) -> Result<Written, String> {
        // Checked again here, not only when the offer was queued: offers saved
        // by an older daemon were never validated.
        if !is_safe_file_name(&file.filename) {
            return Err(format!("invalid file name '{}'", file.filename));
        }
        // Claim the blob before fetching it. `fetch` leaves what it downloads
        // untagged, so a GC triggered by some other transfer finishing mid-fetch
        // would sweep the bytes out from under us. The tag is dropped again as
        // soon as the file reaches its destination or the offer is rejected.
        // Failed receives keep the tag so a retry can reuse the downloaded ranges.
        // A finished one releases it in `finish_receive`.
        let recv_tag = blob_tags::recv(&file.blob_hash, file.id);
        self.transport
            .blob_store
            .tags()
            .set(&recv_tag, iroh_blobs::HashAndFormat::raw(file.blob_hash))
            .await
            .map_err(|e| format!("blob store error: {e}"))?;
        self.fetch_resuming(file, transfer_id, policy).await?;
        self.save_received(file, to).await
    }

    /// Fetch until the blob is complete, waiting out interruptions.
    async fn fetch_resuming(
        &self,
        file: &PendingFile,
        transfer_id: u64,
        policy: ResumePolicy,
    ) -> Result<(), String> {
        let mut backoff = policy.first_backoff;
        let mut stalled = NoProgress::new(&policy);
        loop {
            let (attempt, took) = {
                let _slot = self
                    .receive_slots
                    .acquire()
                    .await
                    .map_err(|_| "file receives are shutting down".to_string())?;
                // Timed once the slot is held: waiting for other receives to
                // finish is not trying.
                let started = Instant::now();
                let attempt = self.fetch_once(file, transfer_id, &policy).await;
                (attempt, started.elapsed())
            };
            let reason = match attempt {
                Ok(()) => return Ok(()),
                Err(FetchError::Fatal(reason)) => return Err(reason),
                Err(FetchError::Interrupted { reason, progressed }) => {
                    if progressed {
                        backoff = policy.first_backoff;
                        stalled.reset();
                    } else {
                        stalled.failed_attempt(took);
                    }
                    reason
                }
            };
            if stalled.exhausted(backoff, policy.give_up_after) {
                return Err(format!(
                    "{reason}; gave up after {} hours without progress",
                    policy.give_up_after.as_secs() / 3600
                ));
            }
            tracing::info!(
                from = %file.from.fmt_short(),
                file = %file.filename,
                %reason,
                retry_in = ?backoff,
                "file receive interrupted; retrying"
            );
            self.transfers.note_retrying(transfer_id, &reason);
            tokio::time::sleep(backoff).await;
            stalled.waited(backoff);
            backoff = backoff.saturating_mul(2).min(policy.max_backoff);
        }
    }

    /// One connection's worth of fetching. Ranges already in the store are
    /// not requested again.
    async fn fetch_once(
        &self,
        file: &PendingFile,
        transfer_id: u64,
        policy: &ResumePolicy,
    ) -> Result<(), FetchError> {
        let hash = file.blob_hash;
        let store = &self.transport.blob_store;
        let local = store
            .remote()
            .local(hash)
            .await
            .map_err(|e| FetchError::Fatal(format!("blob store error: {e}")))?;
        let downloaded = local.local_bytes();
        self.transfers.note_progress(transfer_id, downloaded);
        if local.is_complete() {
            return Ok(());
        }
        let connect = transport::connect_to_peer_with_alpn(
            &self.transport.endpoint,
            file.from,
            iroh_blobs::protocol::ALPN,
        );
        let conn = match tokio::time::timeout(policy.connect_timeout, connect).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                return Err(FetchError::Interrupted {
                    reason: format!("cannot reach sender: {e:#}"),
                    progressed: false,
                });
            }
            Err(_) => {
                return Err(FetchError::Interrupted {
                    reason: "cannot reach sender: connection timed out".to_string(),
                    progressed: false,
                });
            }
        };
        let probe = conn.clone();

        // `fetch` returns a `GetProgress`: awaiting it directly discards the
        // progress, so take the stream instead and report bytes as they land. It
        // yields `Progress(n)` items (n = payload bytes read so far) and exactly
        // one terminal `Done`/`Error` item. Reaching `Done` means only the fetch
        // succeeded; the transfer is not finished until the file is written.
        let mut stream = Box::pin(
            store
                .remote()
                .fetch(conn, iroh_blobs::HashAndFormat::raw(hash))
                .stream(),
        );
        let mut progressed = false;
        loop {
            let Ok(item) = tokio::time::timeout(policy.idle_timeout, stream.next()).await else {
                probe.close(VarInt::from_u32(0), b"stalled");
                return Err(FetchError::Interrupted {
                    reason: "the transfer stalled".to_string(),
                    progressed,
                });
            };
            match item {
                Some(GetProgressItem::Progress(n)) => {
                    progressed |= n > 0;
                    self.transfers
                        .note_progress(transfer_id, downloaded.saturating_add(n));
                }
                Some(GetProgressItem::Done(_)) => return Ok(()),
                Some(GetProgressItem::Error(e)) => {
                    return Err(classify(&e, probe.close_reason().is_some(), progressed));
                }
                None => {
                    return Err(FetchError::Interrupted {
                        reason: "blob fetch ended without a result".to_string(),
                        progressed,
                    });
                }
            }
        }
    }

    /// Write the fetched blob to the destination directory.
    async fn save_received(
        &self,
        file: &PendingFile,
        to: AcceptedReceive,
    ) -> Result<Written, String> {
        let dir = receive_dir(to.output.as_deref());
        self.write_received(file.blob_hash, dir, &file.filename, to.recipient)
            .await
            .map_err(|e| format!("write failed: {e}"))
    }
}

/// The directory a receive saves into: the one asked for, or the daemon
/// user's Downloads.
fn receive_dir(output: Option<&str>) -> PathBuf {
    match output {
        Some(p) => PathBuf::from(p),
        None => dirs::download_dir().unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("Downloads")
        }),
    }
}

/// Sort a fetch error into one worth retrying and one that is not.
/// `connection_closed` is whether the connection was gone when it failed.
fn classify(error: &GetError, connection_closed: bool, progressed: bool) -> FetchError {
    let interrupted = |reason: String| FetchError::Interrupted { reason, progressed };
    match error {
        // The sender answered and ended the stream without the data. It drops
        // a blob only once the offer is settled or canceled on its side.
        GetError::AtBlobHeaderNext {
            source: AtBlobHeaderNextError::NotFound { .. },
            ..
        }
        | GetError::Decode {
            source:
                DecodeError::ChunkNotFound { .. }
                | DecodeError::ParentNotFound { .. }
                | DecodeError::LeafNotFound { .. },
            ..
        } => FetchError::Fatal(SENDER_GONE.to_string()),
        GetError::Decode {
            source: DecodeError::ParentHashMismatch { .. } | DecodeError::LeafHashMismatch { .. },
            ..
        } => FetchError::Fatal("the sender's data does not match the offered file".to_string()),
        _ => match stream_refusal(error) {
            Some(code) if code == iroh_blobs::protocol::ERR_LIMIT => {
                interrupted("the sender is busy".to_string())
            }
            // A provider without the blob resets the stream with
            // `ERR_INTERNAL`. Other internal errors on the sender look the
            // same, but none of them is something waiting would fix.
            Some(_) => FetchError::Fatal(SENDER_GONE.to_string()),
            // Opening a stream on a dead connection surfaces as a local
            // failure, so a closed connection outranks the variant.
            None if connection_closed => interrupted(format!("connection to sender lost: {error}")),
            None => match error {
                GetError::LocalFailure { .. }
                | GetError::BadRequest { .. }
                | GetError::IrpcSend { .. }
                | GetError::Decode {
                    source: DecodeError::Write { .. },
                    ..
                }
                | GetError::ConnectedNext {
                    source:
                        ConnectedNextError::PostcardSer { .. }
                        | ConnectedNextError::RequestTooBig { .. },
                    ..
                } => FetchError::Fatal(format!("blob fetch failed: {error}")),
                _ => interrupted(format!("blob fetch failed: {error}")),
            },
        },
    }
}

/// The error code when the sender reset our stream or stopped reading our
/// request: a refusal of this request on a connection that is otherwise fine.
fn stream_refusal(error: &GetError) -> Option<VarInt> {
    let read = error
        .remote_read()
        .and_then(|e| e.get_ref())
        .and_then(|e| e.downcast_ref::<ReadError>());
    if let Some(ReadError::Reset(code)) = read {
        return Some(*code);
    }
    let write = error
        .remote_write()
        .and_then(|e| e.get_ref())
        .and_then(|e| e.downcast_ref::<WriteError>());
    match write {
        Some(WriteError::Stopped(code)) => Some(*code),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::protocol::Router;
    use iroh_blobs::provider::events::{EventMask, EventSender, ProviderMessage, ThrottleMode};

    use crate::daemon::file_service::tests::{file_endpoint, file_service};

    /// Chunks the first sender lets through before it holds the transfer.
    const CHUNKS_BEFORE_STALL: usize = 32;

    fn quick_retries() -> ResumePolicy {
        ResumePolicy {
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(5),
            first_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(200),
            give_up_after: Duration::from_secs(3600),
        }
    }

    /// A suspend in the middle of an attempt or a wait, however long, must
    /// not use up the give-up window by itself.
    #[test]
    fn a_long_sleep_alone_does_not_give_up() {
        let policy = ResumePolicy::default();
        let day = policy.give_up_after;
        let mut stalled = NoProgress::new(&policy);
        // One attempt that the clock says took two days: the machine slept
        // through it.
        stalled.failed_attempt(2 * day);
        assert!(!stalled.exhausted(policy.max_backoff, day));
        // A day's worth of waiting that really happened does give up.
        while !stalled.exhausted(policy.max_backoff, day) {
            stalled.waited(policy.max_backoff);
            stalled.failed_attempt(Duration::from_secs(1));
        }
        assert!(stalled.spent >= day - policy.max_backoff);
        stalled.reset();
        assert!(!stalled.exhausted(policy.max_backoff, day));
    }

    /// The Android accept blocks its caller, so it must not wait out a day.
    #[test]
    fn a_blocking_accept_gives_up_within_minutes() {
        let policy = ResumePolicy::default();
        let blocking = policy.for_blocking_call();
        assert_eq!(blocking.give_up_after, BLOCKING_GIVE_UP_AFTER);
        assert_eq!(blocking.max_backoff, policy.max_backoff);
        let quick = quick_retries();
        assert_eq!(
            quick.for_blocking_call().give_up_after,
            BLOCKING_GIVE_UP_AFTER
        );
    }

    fn payload() -> Vec<u8> {
        (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect()
    }

    struct Sender {
        router: Router,
        _store: FsStore,
    }

    /// A blobs provider under `key`, holding `data` if given. With `allow`,
    /// it lets that many chunks through, signals `stalled`, and then holds
    /// the transfer without closing it.
    async fn sender(
        key: &SecretKey,
        lookup: &MemoryLookup,
        dir: &Path,
        data: Option<&[u8]>,
        allow: Option<(usize, oneshot::Sender<()>)>,
    ) -> Sender {
        let store = FsStore::load(dir).await.unwrap();
        if let Some(data) = data {
            let tag = store.blobs().add_slice(data).temp_tag().await.unwrap();
            store
                .tags()
                .set("test", tag.hash_and_format())
                .await
                .unwrap();
        }
        let events = allow.map(|(allow, stalled)| {
            let (events, mut rx) = EventSender::channel(
                16,
                EventMask {
                    throttle: ThrottleMode::Intercept,
                    ..EventMask::DEFAULT
                },
            );
            tokio::spawn(async move {
                let mut stalled = Some(stalled);
                let mut held = Vec::new();
                let mut passed = 0;
                while let Some(message) = rx.recv().await {
                    if let ProviderMessage::Throttle(message) = message {
                        if passed < allow {
                            passed += 1;
                            message.tx.send(Ok(())).await.ok();
                        } else {
                            held.push(message);
                            if let Some(stalled) = stalled.take() {
                                stalled.send(()).ok();
                            }
                        }
                    }
                }
            });
            events
        });
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(key.clone())
            .relay_mode(iroh::RelayMode::Disabled)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(endpoint.addr());
        let router = Router::builder(endpoint)
            .accept(
                iroh_blobs::protocol::ALPN,
                BlobsProtocol::new(&store, events),
            )
            .spawn();
        Sender {
            router,
            _store: store,
        }
    }

    /// Queue an offer of `data` from `from` as pending file 1.
    fn offer(service: &FileService, from: EndpointId, data: &[u8]) {
        service.pending_files.lock().unwrap().push(PendingFile {
            id: 1,
            offer_id: control::FileOfferId::new(),
            accepted: None,
            from,
            filename: "big.bin".into(),
            size: u64::try_from(data.len()).unwrap(),
            mime_type: "application/octet-stream".into(),
            blob_hash: blake3::hash(data).into(),
        });
    }

    fn receive(service: &FileService) -> transfers::TransferInfo {
        service
            .transfers
            .list()
            .into_iter()
            .find(|t| !t.outgoing)
            .expect("the receive is registered")
    }

    /// Wait on the registry's change feed until the receive matches `done`.
    async fn wait_for(
        service: &FileService,
        changes: &mut tokio::sync::watch::Receiver<()>,
        done: impl Fn(&transfers::TransferInfo) -> bool,
    ) -> transfers::TransferInfo {
        loop {
            if let Some(info) = service
                .transfers
                .list()
                .into_iter()
                .find(|t| !t.outgoing && done(t))
            {
                return info;
            }
            changes.changed().await.unwrap();
        }
    }

    fn retrying(info: &transfers::TransferInfo) -> bool {
        info.error
            .as_deref()
            .is_some_and(|e| e.starts_with("interrupted, retrying"))
    }

    #[tokio::test]
    async fn an_interrupted_receive_resumes_without_a_second_accept() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let data = payload();
        let lookup = MemoryLookup::new();
        let key = SecretKey::generate();
        let (stalled_tx, stalled_rx) = oneshot::channel();
        let first = sender(
            &key,
            &lookup,
            &tmp.path().join("sender-1"),
            Some(&data),
            Some((CHUNKS_BEFORE_STALL, stalled_tx)),
        )
        .await;
        let mut receiver =
            file_service(file_endpoint(lookup.clone()).await, &tmp.path().join("r")).await;
        Arc::get_mut(&mut receiver).unwrap().resume = quick_retries();
        offer(&receiver, key.public(), &data);
        let mut changes = receiver.transfers.subscribe();
        let downloads = tmp.path().join("downloads");
        let accept = tokio::spawn({
            let receiver = Arc::clone(&receiver);
            let output = Some(downloads.to_string_lossy().into_owned());
            async move { receiver.accept_file(1, output, None).await }
        });

        // Partway through, the sender goes away, as a sleeping laptop would.
        stalled_rx.await.unwrap();
        let moving = wait_for(&receiver, &mut changes, |t| t.transferred > 0).await;
        assert!(moving.transferred < moving.size, "{moving:?}");
        first.router.endpoint().close().await;
        let interrupted = wait_for(&receiver, &mut changes, retrying).await;
        assert_eq!(interrupted.state, transfers::TransferState::Transferring);
        // What arrived before the drop is kept for the retry.
        let partial = receiver
            .transport
            .blob_store
            .remote()
            .local(iroh_blobs::Hash::from(blake3::hash(&data)))
            .await
            .unwrap();
        assert!(partial.local_bytes() > 0, "nothing was kept");
        assert!(!partial.is_complete());
        assert!(receiver.pending_files.lock().unwrap().is_empty());

        // The sender comes back under the same identity.
        let _second = sender(
            &key,
            &lookup,
            &tmp.path().join("sender-2"),
            Some(&data),
            None,
        )
        .await;
        let saved = accept.await.unwrap().expect("the receive resumes");
        assert!(saved.0.starts_with("saved to"), "{saved:?}");
        assert_eq!(std::fs::read(downloads.join("big.bin")).unwrap(), data);
        let done = receive(&receiver);
        assert_eq!(done.state, transfers::TransferState::Done);
        assert_eq!(done.error, None);
        assert!(receiver.pending_files.lock().unwrap().is_empty());
        assert!(receiver.active_files.lock().unwrap().is_empty());
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn an_accepted_receive_resumes_after_a_restart() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let data = payload();
        let lookup = MemoryLookup::new();
        let key = SecretKey::generate();
        let (stalled_tx, stalled_rx) = oneshot::channel();
        let first = sender(
            &key,
            &lookup,
            &tmp.path().join("sender-1"),
            Some(&data),
            Some((CHUNKS_BEFORE_STALL, stalled_tx)),
        )
        .await;
        let mut receiver =
            file_service(file_endpoint(lookup.clone()).await, &tmp.path().join("r")).await;
        Arc::get_mut(&mut receiver).unwrap().resume = quick_retries();
        offer(&receiver, key.public(), &data);
        let mut changes = receiver.transfers.subscribe();
        let downloads = tmp.path().join("downloads");
        let output = Some(downloads.to_string_lossy().into_owned());
        let recipient = Recipient {
            owner: None,
            caller_chose_dir: true,
        };
        let _outcome = receiver
            .start_receive(1, output.clone(), recipient.clone(), quick_retries())
            .unwrap();
        stalled_rx.await.unwrap();
        wait_for(&receiver, &mut changes, |t| t.transferred > 0).await;

        // The daemon stops partway through. The offer guard puts the entry
        // back in the queue and rewrites the file under the queue lock, so
        // once it is back in memory the saved copy is the guard's.
        receiver.registry.shutdown_token.cancel();
        while receiver.pending_files.lock().unwrap().is_empty() {
            changes.changed().await.unwrap();
        }
        first.router.endpoint().close().await;
        let saved = load_pending_files();
        assert_eq!(saved.len(), 1);
        assert_eq!(
            saved[0].accepted,
            Some(AcceptedReceive { output, recipient })
        );

        // It starts again with the sender back, and nobody accepts it twice.
        let _second = sender(
            &key,
            &lookup,
            &tmp.path().join("sender-2"),
            Some(&data),
            None,
        )
        .await;
        let mut restarted =
            file_service(file_endpoint(lookup.clone()).await, &tmp.path().join("r2")).await;
        Arc::get_mut(&mut restarted).unwrap().resume = quick_retries();
        let mut changes = restarted.transfers.subscribe();
        restarted.resume_accepted_receives();
        assert!(restarted.pending_files.lock().unwrap().is_empty());
        let done = wait_for(&restarted, &mut changes, |t| {
            t.state != transfers::TransferState::Transferring
        })
        .await;
        assert_eq!(done.state, transfers::TransferState::Done, "{done:?}");
        assert_eq!(std::fs::read(downloads.join("big.bin")).unwrap(), data);
        assert!(load_pending_files().is_empty());
    }

    #[tokio::test]
    async fn starting_an_accept_returns_before_the_download_ends() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let data = payload();
        let lookup = MemoryLookup::new();
        let key = SecretKey::generate();
        let (stalled_tx, stalled_rx) = oneshot::channel();
        // Holds every chunk, so the download cannot finish while we look.
        let _sender = sender(
            &key,
            &lookup,
            &tmp.path().join("sender"),
            Some(&data),
            Some((0, stalled_tx)),
        )
        .await;
        let mut receiver =
            file_service(file_endpoint(lookup.clone()).await, &tmp.path().join("r")).await;
        Arc::get_mut(&mut receiver).unwrap().resume = quick_retries();
        offer(&receiver, key.public(), &data);
        let output = Some(tmp.path().join("downloads").to_string_lossy().into_owned());

        let started = receiver
            .start_accepting_file(1, output, None)
            .await
            .unwrap();
        assert!(started.0.contains("receiving"), "{started:?}");
        assert!(receiver.pending_files.lock().unwrap().is_empty());
        let running = receive(&receiver);
        assert_eq!(running.state, transfers::TransferState::Transferring);
        stalled_rx.await.unwrap();
        assert_eq!(
            receive(&receiver).state,
            transfers::TransferState::Transferring
        );

        receiver.cancel_transfer(running.id).unwrap();
    }

    #[tokio::test]
    async fn a_sender_without_the_blob_ends_the_receive() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let data = payload();
        let lookup = MemoryLookup::new();
        let key = SecretKey::generate();
        let _sender = sender(&key, &lookup, &tmp.path().join("sender"), None, None).await;
        let mut receiver =
            file_service(file_endpoint(lookup.clone()).await, &tmp.path().join("r")).await;
        Arc::get_mut(&mut receiver).unwrap().resume = quick_retries();
        offer(&receiver, key.public(), &data);
        let output = Some(tmp.path().join("downloads").to_string_lossy().into_owned());

        let error = receiver.accept_file(1, output, None).await.unwrap_err();
        assert!(error.message().contains(SENDER_GONE), "{error}");
        let failed = receive(&receiver);
        assert_eq!(failed.state, transfers::TransferState::Failed);
        assert_eq!(failed.error.as_deref(), Some(SENDER_GONE));
        // Back in the queue, so it can be rejected.
        assert_eq!(receiver.pending_files.lock().unwrap().len(), 1);
        assert!(load_pending_files()[0].accepted.is_none());
        assert!(receiver.active_files.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_stalled_receive_is_retried_until_canceled() {
        let tmp = tempfile::tempdir().unwrap();
        config::set_thread_config_dir(tmp.path().join("config"));
        let data = payload();
        let lookup = MemoryLookup::new();
        let key = SecretKey::generate();
        let (stalled_tx, stalled_rx) = oneshot::channel();
        // Holds every chunk: the connection stays up but nothing moves.
        let _sender = sender(
            &key,
            &lookup,
            &tmp.path().join("sender"),
            Some(&data),
            Some((0, stalled_tx)),
        )
        .await;
        let mut receiver =
            file_service(file_endpoint(lookup.clone()).await, &tmp.path().join("r")).await;
        Arc::get_mut(&mut receiver).unwrap().resume = ResumePolicy {
            idle_timeout: Duration::from_millis(200),
            ..quick_retries()
        };
        offer(&receiver, key.public(), &data);
        let mut changes = receiver.transfers.subscribe();
        let accept = tokio::spawn({
            let receiver = Arc::clone(&receiver);
            let output = Some(tmp.path().join("downloads").to_string_lossy().into_owned());
            async move { receiver.accept_file(1, output, None).await }
        });
        stalled_rx.await.unwrap();
        let stalled = wait_for(&receiver, &mut changes, retrying).await;
        assert!(
            stalled.error.as_deref().unwrap().contains("stalled"),
            "{stalled:?}"
        );

        receiver.cancel_transfer(stalled.id).unwrap();
        let error = accept.await.unwrap().unwrap_err();
        assert!(error.message().contains("canceled"), "{error}");
        assert_eq!(receive(&receiver).state, transfers::TransferState::Failed);
        assert!(receiver.receives.lock().unwrap().is_empty());
        assert_eq!(receiver.pending_files.lock().unwrap().len(), 1);
        // Canceled by the user, it is a plain offer again, also after a restart.
        assert!(load_pending_files()[0].accepted.is_none());
    }
}
