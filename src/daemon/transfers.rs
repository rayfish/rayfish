//! In-flight file transfers, for progress reporting.
//!
//! Fed from both directions of a transfer:
//!
//! - **Receive:** `FileService::accept_file` consumes the `GetProgress` stream from
//!   `blob_store.remote().fetch(..)` and reports bytes as they land.
//! - **Send:** `send_file` returns as soon as the *offer* is delivered; the peer
//!   pulls the bytes whenever it accepts (immediately on auto-accept, minutes or
//!   never on a manual one). Provider events report reads from our blob store.
//!   A recipient also confirms completion by offer identity, including when it
//!   already has the bytes cached, and reports an explicit decline.
//!
//! Provider events are keyed by blob hash *and* the resolved peer endpoint id, not
//! by transfer. The roster (group blob) fetches ride the same blobs ALPN, so a
//! hash we never registered as an outgoing file send is ignored, and requiring the
//! peer to match too means the same file offered to two different peers can only
//! ever be completed by the peer it was actually sent to: a pull by one can never
//! complete the other's entry, and a pull by an unrelated third party (anyone who
//! learned the hash) can't complete anyone's entry at all.
//!
//! An aborted pull does not end a send. The receiver resumes an interrupted
//! receive by itself, for up to a day, and can accept it again after that, so
//! the sender keeps the entry in progress with a note until the pull completes,
//! the receiver confirms or declines, or the send is canceled. Nothing tells
//! the sender when the receiver gives up or cancels, which puts the offer back
//! in its queue, so a send with no new pull for [`RESUME_WINDOW`] goes back to
//! `Offered`: what it then is on both sides. It is not dropped, since the
//! offer is still outstanding and has to stay cancelable here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::EndpointId;
use iroh_blobs::Hash;

/// How long a finished transfer stays listable, so a poller can observe the
/// terminal state before it disappears.
const TERMINAL_TTL: Duration = Duration::from_secs(60);

/// Most finished transfers kept listable at once. A burst of short transfers
/// inside one [`TERMINAL_TTL`] otherwise keeps every one of them.
const MAX_FINISHED: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Outgoing: the offer is delivered, the peer has not started pulling yet.
    Offered,
    /// Bytes are moving.
    Transferring,
    /// The recipient has every byte, fetched or already cached.
    Done,
    /// The transfer failed or was aborted.
    Failed,
}

#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub id: u64,
    pub outgoing: bool,
    pub peer: String,
    pub filename: String,
    pub size: u64,
    pub transferred: u64,
    pub state: TransferState,
    pub destination: Option<PathBuf>,
    pub error: Option<String>,
}

struct Entry {
    info: TransferInfo,
    /// Outgoing only: the blob and the peer it was offered to, used to match
    /// provider events.
    send: Option<SendKey>,
    /// When the transfer reached a terminal state, for TTL expiry.
    finished_at: Option<Instant>,
    /// Outgoing only: when the peer's last pull stopped partway, until it
    /// pulls again. See [`RESUME_WINDOW`].
    interrupted_at: Option<Instant>,
}

/// Which provider events belong to an outgoing entry. An event must match both
/// fields to touch the entry, so a pull by a different peer (another recipient
/// of the same file, or anyone else who learned the hash) can never complete it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendKey {
    /// The blob the peer will pull.
    hash: Hash,
    /// The peer this offer was sent to.
    peer: EndpointId,
}

/// The note on a send whose pull stopped partway.
pub(crate) const SEND_INTERRUPTED: &str = "interrupted; the recipient resumes it when it can";

/// The note on a send whose interrupted pull was not resumed in time.
pub(crate) const SEND_NOT_RESUMED: &str =
    "the recipient stopped receiving; it can still accept the offer";

/// How long an interrupted send waits for the recipient to pull again before
/// it counts as offered rather than in progress: the receiver's own retry
/// window, measured here as plain time since the sender cannot see the
/// receiver's.
const RESUME_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

pub struct TransferRegistry {
    entries: Mutex<HashMap<u64, Entry>>,
    next_id: AtomicU64,
    changes: tokio::sync::watch::Sender<()>,
}

/// Ids start at 1, so `Default` goes through `new` rather than deriving a zero.
impl Default for TransferRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            changes: tokio::sync::watch::Sender::default(),
        }
    }

    /// Subscribe before taking the initial snapshot. A watch channel coalesces
    /// bursts and retains a change that races with snapshot reconciliation.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.changes.subscribe()
    }

    /// Also used for incoming-offer queue changes, which share the mobile UI.
    pub(crate) fn changed(&self) {
        self.changes.send_replace(());
    }

    /// An outgoing offer is about to be sent to `peer`. The bytes move later, when
    /// the peer accepts and pulls them, which arrives as provider events keyed by
    /// `hash` *and* `peer`. Must be called before the offer can possibly reach the
    /// peer (i.e. before dialing), so that a peer who pulls immediately can never
    /// race ahead of its own registration; the caller finishes the entry with
    /// `finish(id, false)` if the send fails after this point.
    ///
    /// The display label is always the resolved peer id's short form, matching
    /// `register_receive`, not whatever string the caller typed at the CLI.
    pub fn register_send(&self, peer: EndpointId, filename: String, size: u64, hash: Hash) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut entries = self.entries.lock().unwrap();
        prune_finished(&mut entries, Instant::now());
        entries.insert(
            id,
            Entry {
                info: TransferInfo {
                    id,
                    outgoing: true,
                    peer: peer.fmt_short().to_string(),
                    filename,
                    size,
                    transferred: 0,
                    state: TransferState::Offered,
                    destination: None,
                    error: None,
                },
                send: Some(SendKey { hash, peer }),
                finished_at: None,
                interrupted_at: None,
            },
        );
        self.changed();
        id
    }

    /// An incoming transfer we drive ourselves, so it is moving from the start.
    pub fn register_receive(&self, peer: String, filename: String, size: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut entries = self.entries.lock().unwrap();
        prune_finished(&mut entries, Instant::now());
        entries.insert(
            id,
            Entry {
                info: TransferInfo {
                    id,
                    outgoing: false,
                    peer,
                    filename,
                    size,
                    transferred: 0,
                    state: TransferState::Transferring,
                    destination: None,
                    error: None,
                },
                send: None,
                finished_at: None,
                interrupted_at: None,
            },
        );
        self.changed();
        id
    }

    pub fn note_progress(&self, id: u64, transferred: u64) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            let transferred = transferred.min(e.info.size);
            // New bytes mean a resumed receive is moving again, so the note
            // left by `note_retrying` no longer describes it.
            if transferred > e.info.transferred {
                e.info.error = None;
            }
            e.info.transferred = transferred;
            e.info.state = TransferState::Transferring;
            self.changed();
        }
    }

    /// A receive was interrupted and will be retried. It stays
    /// `Transferring`, with the reason in `error`, so `ray files` shows it as
    /// still under way rather than failed.
    pub(crate) fn note_retrying(&self, id: u64, reason: &str) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            e.info.error = Some(format!("interrupted, retrying: {reason}"));
            self.changed();
        }
    }

    /// A receive gave up, with the reason shown next to the failure.
    fn fail_receive(&self, id: u64, reason: String) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            finish_entry(e, false);
            e.info.error = Some(reason);
            self.changed();
        }
    }

    pub fn finish(&self, id: u64, ok: bool) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            finish_entry(e, ok);
            self.changed();
        }
    }

    pub fn finish_receive(&self, id: u64, destination: &Path) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            e.info.destination = Some(destination.to_path_buf());
            finish_entry(e, true);
            self.changed();
        }
    }

    /// An outgoing offer failed before the peer could ever pull it, or was
    /// dropped from the queue.
    pub fn fail_offer(&self, id: u64) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            finish_entry(e, false);
            self.changed();
        }
    }

    /// A recipient's explicit refusal is terminal and cannot be revived by a pull.
    pub(crate) fn decline_offer(&self, id: u64, reason: String) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(&id) {
            finish_entry(entry, false);
            entry.info.error = Some(reason);
            self.changed();
        }
    }

    /// Cancel an outgoing offer or pull. Returns the blob identity so the
    /// caller can release the sender's durable tag as well.
    pub fn cancel(&self, id: u64) -> Option<(Hash, EndpointId)> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get_mut(&id)?;
        if !entry.info.outgoing
            || !matches!(
                entry.info.state,
                TransferState::Offered | TransferState::Transferring
            )
        {
            return None;
        }
        let SendKey { hash, peer } = entry.send?;
        finish_entry(entry, false);
        self.changed();
        Some((hash, peer))
    }

    /// A peer started pulling a blob, for the first time or to resume.
    pub fn provider_started(&self, hash: Hash, peer: EndpointId) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash, peer) {
            let e = entries.get_mut(&id).expect("id came from this map");
            e.info.state = TransferState::Transferring;
            e.info.error = None;
            e.interrupted_at = None;
            self.changed();
        }
    }

    pub fn provider_progress(&self, hash: Hash, peer: EndpointId, end_offset: u64) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash, peer) {
            let e = entries.get_mut(&id).expect("id came from this map");
            e.info.transferred = end_offset.min(e.info.size);
            e.info.state = TransferState::Transferring;
            e.interrupted_at = None;
            self.changed();
        }
    }

    /// A pull ended. A complete one finishes the send; an aborted one leaves
    /// it in progress with [`SEND_INTERRUPTED`], since the recipient resumes
    /// it, for up to [`RESUME_WINDOW`].
    pub fn provider_finished(&self, hash: Hash, peer: EndpointId, ok: bool) {
        self.provider_finished_at(hash, peer, ok, Instant::now());
    }

    fn provider_finished_at(&self, hash: Hash, peer: EndpointId, ok: bool, now: Instant) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash, peer) {
            let e = entries.get_mut(&id).expect("id came from this map");
            if ok {
                finish_entry(e, true);
            } else {
                e.info.error = Some(SEND_INTERRUPTED.to_string());
                e.interrupted_at = Some(now);
            }
            self.changed();
        }
    }

    pub fn list(&self) -> Vec<TransferInfo> {
        self.list_at(Instant::now())
    }

    fn list_at(&self, now: Instant) -> Vec<TransferInfo> {
        let mut entries = self.entries.lock().unwrap();
        prune_finished(&mut entries, now);
        let mut out: Vec<TransferInfo> = entries.values().map(|e| e.info.clone()).collect();
        out.sort_by_key(|t| t.id);
        out
    }
}

/// Guards a registered transfer against a cancelled future leaving it stuck in
/// `Transferring` forever. Held across every fallible step of a receive; its
/// `Drop` marks the transfer failed unless [`FinishGuard::success`] disarmed
/// it first. Cheap and unconditionally correct: the only way to reach `Done`
/// is through `success`, so a dropped future (or an early `return`) can never
/// leave a completion notification pointing at a file that was never written.
pub struct FinishGuard {
    registry: Arc<TransferRegistry>,
    id: u64,
    armed: bool,
}

impl FinishGuard {
    pub fn new(registry: Arc<TransferRegistry>, id: u64) -> Self {
        Self {
            registry,
            id,
            armed: true,
        }
    }

    /// Mark the transfer done and disarm the guard. Call this only once the
    /// work the transfer represents (fetch + write to disk) has fully
    /// succeeded.
    pub fn success(mut self, destination: &Path) {
        self.armed = false;
        self.registry.finish_receive(self.id, destination);
    }

    /// Mark the transfer failed for `reason` and disarm the guard.
    pub(crate) fn fail(mut self, reason: String) {
        self.armed = false;
        self.registry.fail_receive(self.id, reason);
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        if self.armed {
            self.registry.finish(self.id, false);
        }
    }
}

/// Drop finished entries older than [`TERMINAL_TTL`], then the oldest finished
/// ones past [`MAX_FINISHED`], and return sends interrupted for longer than
/// [`RESUME_WINDOW`] to `Offered`. Runs on every insert as well as every
/// listing, so the map stays bounded when nothing polls it.
fn prune_finished(entries: &mut HashMap<u64, Entry>, now: Instant) {
    for e in entries.values_mut() {
        if e.interrupted_at
            .is_some_and(|at| now.duration_since(at) >= RESUME_WINDOW)
        {
            e.interrupted_at = None;
            e.info.state = TransferState::Offered;
            e.info.error = Some(SEND_NOT_RESUMED.to_string());
        }
    }
    entries.retain(|_, e| match e.finished_at {
        Some(at) => now.duration_since(at) < TERMINAL_TTL,
        None => true,
    });
    let mut finished: Vec<(Instant, u64)> = entries
        .values()
        .filter_map(|e| e.finished_at.map(|at| (at, e.info.id)))
        .collect();
    if finished.len() <= MAX_FINISHED {
        return;
    }
    finished.sort_unstable();
    let excess = finished.len() - MAX_FINISHED;
    for (_, id) in &finished[..excess] {
        entries.remove(id);
    }
}

/// A finished transfer reads as complete: a Done that showed 60/100 because the
/// last progress event was coarse would be a worse lie than rounding up.
fn finish_entry(e: &mut Entry, ok: bool) {
    e.info.state = if ok {
        e.info.transferred = e.info.size;
        TransferState::Done
    } else {
        TransferState::Failed
    };
    e.finished_at = Some(Instant::now());
    e.interrupted_at = None;
}

/// The transfer a provider event belongs to: the oldest outgoing, not-yet-finished
/// entry for this `(hash, peer)` pair. Returns `None` for a hash we never
/// registered as an outgoing file send (a roster blob fetch, say) or for a peer
/// that never received this exact offer, which is how both get ignored: a hash
/// alone is not enough to identify who a send actually went to.
fn oldest_live_outgoing(
    entries: &HashMap<u64, Entry>,
    hash: Hash,
    peer: EndpointId,
) -> Option<u64> {
    entries
        .values()
        .filter(|e| e.send == Some(SendKey { hash, peer }) && e.finished_at.is_none())
        .map(|e| e.info.id)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriptions_observe_receive_progress_and_completion_without_polling() {
        let registry = TransferRegistry::new();
        let mut first = registry.subscribe();
        let mut second = registry.subscribe();
        assert!(!first.has_changed().unwrap());
        let id = registry.register_receive("peer".into(), "file".into(), 100);
        assert!(first.has_changed().unwrap());
        first.borrow_and_update();
        assert!(second.has_changed().unwrap());
        second.borrow_and_update();
        for n in 1..=100 {
            registry.note_progress(id, n);
        }
        assert!(first.has_changed().unwrap());
        first.borrow_and_update();
        assert_eq!(registry.list()[0].transferred, 100);
        registry.finish_receive(id, Path::new("/path/to/work/file"));
        assert!(first.has_changed().unwrap());
        first.borrow_and_update();
        assert_eq!(registry.list()[0].state, TransferState::Done);
        assert_eq!(
            registry.list()[0].destination.as_deref(),
            Some(Path::new("/path/to/work/file"))
        );
        assert!(!first.has_changed().unwrap());
    }

    #[test]
    fn subscriptions_ignore_unrelated_provider_traffic_and_follow_send_retries() {
        let registry = TransferRegistry::new();
        let mut changes = registry.subscribe();
        registry.provider_started(hash(1), peer(1));
        registry.provider_progress(hash(1), peer(1), 10);
        registry.provider_finished(hash(1), peer(1), true);
        assert!(!changes.has_changed().unwrap());
        registry.register_send(peer(1), "file".into(), 100, hash(1));
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        registry.provider_started(hash(1), peer(1));
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        registry.provider_finished(hash(1), peer(1), false);
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        registry.provider_started(hash(1), peer(1));
        assert!(changes.has_changed().unwrap());
        assert_eq!(registry.list()[0].state, TransferState::Transferring);
    }
    #[test]
    fn a_retrying_receive_stays_in_progress_until_bytes_move() {
        let registry = Arc::new(TransferRegistry::new());
        let id = registry.register_receive("peer".into(), "file".into(), 100);
        registry.note_progress(id, 40);
        registry.note_retrying(id, "connection to sender lost");
        let retrying = &registry.list()[0];
        assert_eq!(retrying.state, TransferState::Transferring);
        assert_eq!(
            retrying.error.as_deref(),
            Some("interrupted, retrying: connection to sender lost")
        );
        // Reconnecting reports the bytes already held; only new ones clear it.
        registry.note_progress(id, 40);
        assert!(registry.list()[0].error.is_some());
        registry.note_progress(id, 41);
        assert_eq!(registry.list()[0].error, None);

        registry.note_retrying(id, "the transfer stalled");
        FinishGuard::new(Arc::clone(&registry), id).fail("gave up".into());
        let failed = &registry.list()[0];
        assert_eq!(failed.state, TransferState::Failed);
        assert_eq!(failed.error.as_deref(), Some("gave up"));
    }
    use iroh::SecretKey;

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn peer(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        SecretKey::from(key_bytes).public()
    }

    /// Finished transfers are pruned as new ones arrive, not only when
    /// something lists them, so a daemon nobody polls stays bounded.
    #[test]
    fn finished_transfers_are_pruned_without_a_listing() {
        let reg = TransferRegistry::new();
        let live = reg.register_receive("peer".into(), "live".into(), 1);
        for n in 0..MAX_FINISHED * 2 {
            let id = reg.register_receive("peer".into(), format!("file-{n}"), 1);
            reg.finish(id, true);
        }
        reg.register_receive("peer".into(), "last".into(), 1);
        let entries = reg.entries.lock().unwrap();
        let finished = entries.values().filter(|e| e.finished_at.is_some()).count();
        assert!(finished <= MAX_FINISHED, "{finished} finished entries kept");
        assert!(entries.contains_key(&live), "a live transfer was pruned");
    }

    #[test]
    fn send_starts_offered_then_tracks_the_peer_pulling_it() {
        let reg = TransferRegistry::new();
        let a = peer(1);
        let id = reg.register_send(a, "photo.jpg".into(), 100, hash(1));

        let t = &reg.list()[0];
        assert_eq!(t.id, id);
        assert!(t.outgoing);
        assert_eq!(t.state, TransferState::Offered);
        assert_eq!(t.transferred, 0);
        // The display label is the resolved peer's short id, same format as a
        // receive's, not whatever string the CLI caller typed.
        assert_eq!(t.peer, a.fmt_short().to_string());

        // The peer accepts and starts reading the blob out of our store.
        reg.provider_started(hash(1), a);
        assert_eq!(reg.list()[0].state, TransferState::Transferring);

        reg.provider_progress(hash(1), a, 60);
        assert_eq!(reg.list()[0].transferred, 60);

        reg.provider_finished(hash(1), a, true);
        let t = &reg.list()[0];
        assert_eq!(t.state, TransferState::Done);
        // A completed transfer reads as 100%, whatever the last progress event said.
        assert_eq!(t.transferred, 100);
    }

    #[test]
    fn an_aborted_pull_stays_in_progress_until_the_recipient_resumes_it() {
        let reg = TransferRegistry::new();
        let a = peer(1);
        reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1), a);
        reg.provider_progress(hash(1), a, 40);
        reg.provider_finished(hash(1), a, false);
        let t = &reg.list()[0];
        assert_eq!(t.state, TransferState::Transferring);
        assert_eq!(t.transferred, 40);
        assert_eq!(t.error.as_deref(), Some(SEND_INTERRUPTED));

        // The recipient retries for hours, so the entry must outlive the
        // listing window of finished transfers.
        let later = Instant::now() + TERMINAL_TTL + Duration::from_secs(1);
        assert_eq!(reg.list_at(later).len(), 1);

        reg.provider_started(hash(1), a);
        let t = &reg.list()[0];
        assert_eq!(t.state, TransferState::Transferring);
        assert_eq!(t.error, None);
        reg.provider_finished(hash(1), a, true);
        assert_eq!(reg.list()[0].state, TransferState::Done);
    }

    /// Nothing tells the sender that the recipient gave up or canceled, so an
    /// interrupted send that is never pulled again must not stay in progress
    /// for good. It is still an outstanding offer, cancelable here.
    #[test]
    fn an_interrupted_send_not_resumed_in_time_is_offered_again() {
        let reg = TransferRegistry::new();
        let a = peer(1);
        let id = reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1), a);
        reg.provider_progress(hash(1), a, 40);
        let now = Instant::now();
        reg.provider_finished_at(hash(1), a, false, now);
        let almost = now + RESUME_WINDOW - Duration::from_secs(1);
        assert_eq!(reg.list_at(almost)[0].state, TransferState::Transferring);

        let t = &reg.list_at(now + RESUME_WINDOW)[0];
        assert_eq!(t.state, TransferState::Offered);
        assert_eq!(t.error.as_deref(), Some(SEND_NOT_RESUMED));
        // A pull later still shows, and the send can still be canceled.
        reg.provider_started(hash(1), a);
        assert_eq!(reg.list()[0].state, TransferState::Transferring);
        assert_eq!(reg.cancel(id), Some((hash(1), a)));
    }

    #[test]
    fn provider_events_for_unregistered_hashes_are_ignored() {
        // The roster/group-blob fetches ride the same blobs ALPN. They must not
        // show up as file transfers.
        let reg = TransferRegistry::new();
        let a = peer(1);
        reg.provider_started(hash(9), a);
        reg.provider_progress(hash(9), a, 10);
        reg.provider_finished(hash(9), a, true);
        assert!(reg.list().is_empty());
    }

    #[test]
    fn a_pull_by_one_peer_cannot_complete_another_peers_entry() {
        // The same file offered to two different peers: only the peer it was
        // actually sent to can drive its own entry to Done. Matching on hash
        // alone (the old behavior) would let B's pull complete A's entry and lie
        // to the user about who actually received the file.
        let reg = TransferRegistry::new();
        let a = peer(1);
        let b = peer(2);
        let to_a = reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        let to_b = reg.register_send(b, "photo.jpg".into(), 100, hash(1));

        // B accepts and pulls; A never does.
        reg.provider_started(hash(1), b);
        reg.provider_progress(hash(1), b, 100);
        reg.provider_finished(hash(1), b, true);

        let list = reg.list();
        let entry_a = list.iter().find(|t| t.id == to_a).unwrap();
        let entry_b = list.iter().find(|t| t.id == to_b).unwrap();
        assert_eq!(
            entry_a.state,
            TransferState::Offered,
            "A's entry must be untouched by B's pull"
        );
        assert_eq!(entry_b.state, TransferState::Done);
    }

    #[test]
    fn a_pull_from_an_unresolved_peer_completes_nothing() {
        // A pull attributed to a peer id we never registered this hash for (a
        // stranger who somehow learned the hash, or a connection whose
        // ClientConnected event we missed) must not complete a registered send:
        // falling back to hash-only matching here would reopen the false-Sent bug.
        let reg = TransferRegistry::new();
        let a = peer(1);
        let stranger = peer(99);
        let id = reg.register_send(a, "photo.jpg".into(), 100, hash(1));

        reg.provider_started(hash(1), stranger);
        reg.provider_finished(hash(1), stranger, true);

        assert_eq!(
            reg.list()[0].state,
            TransferState::Offered,
            "id {id} must be unaffected"
        );
    }

    #[test]
    fn a_started_event_does_not_revive_an_offer_path_failure() {
        // `send_file` calls `fail_offer` (not `finish`) when the dial, `open_bi`,
        // or the offer message itself fails: the peer never received the offer,
        // so there is no pull to retry. A later Started for the same (hash, peer)
        // must not revive it, or the sender would show a false Done for a send
        // whose offer never got out.
        let reg = TransferRegistry::new();
        let a = peer(1);
        let id = reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.fail_offer(id);
        assert_eq!(reg.list()[0].state, TransferState::Failed);

        // Somehow (a coincidental resend under the same hash, say) a Started
        // shows up for this (hash, peer) pair anyway.
        reg.provider_started(hash(1), a);
        assert_eq!(
            reg.list()[0].state,
            TransferState::Failed,
            "an offer-path failure is not revivable"
        );
    }

    #[test]
    fn the_same_blob_sent_twice_resolves_oldest_offer_first() {
        let reg = TransferRegistry::new();
        let a = peer(1);
        let first = reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        let second = reg.register_send(a, "photo.jpg".into(), 100, hash(1));

        reg.provider_started(hash(1), a);
        reg.provider_finished(hash(1), a, true);

        let list = reg.list();
        let a_entry = list.iter().find(|t| t.id == first).unwrap();
        let b_entry = list.iter().find(|t| t.id == second).unwrap();
        assert_eq!(a_entry.state, TransferState::Done);
        assert_eq!(
            b_entry.state,
            TransferState::Offered,
            "the second offer is untouched"
        );
    }

    #[test]
    fn receive_tracks_bytes_and_completes() {
        let reg = TransferRegistry::new();
        let id = reg.register_receive("laptop".into(), "photo.jpg".into(), 100);

        let t = &reg.list()[0];
        assert!(!t.outgoing);
        // A receive we drive ourselves is moving from the moment it is registered.
        assert_eq!(t.state, TransferState::Transferring);

        reg.note_progress(id, 40);
        assert_eq!(reg.list()[0].transferred, 40);

        reg.finish(id, true);
        let t = &reg.list()[0];
        assert_eq!(t.state, TransferState::Done);
        assert_eq!(t.transferred, 100);
    }

    #[test]
    fn sending_the_same_file_again_after_it_finished_does_not_reopen_it() {
        let reg = TransferRegistry::new();
        let a = peer(1);
        let first = reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1), a);
        reg.provider_finished(hash(1), a, true);
        assert_eq!(reg.list()[0].state, TransferState::Done);

        // The user sends the same file again: a new entry for the same hash.
        let second = reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1), a);
        reg.provider_finished(hash(1), a, true);

        let list = reg.list();
        assert_eq!(
            list.len(),
            2,
            "the finished first send is still listed alongside the new one"
        );
        let a = list.iter().find(|t| t.id == first).unwrap();
        let b = list.iter().find(|t| t.id == second).unwrap();
        assert_eq!(
            a.state,
            TransferState::Done,
            "the first send must not be reopened"
        );
        assert_eq!(b.state, TransferState::Done);
    }

    #[test]
    fn a_failed_receive_fails() {
        let reg = TransferRegistry::new();
        let id = reg.register_receive("laptop".into(), "photo.jpg".into(), 100);
        reg.finish(id, false);
        assert_eq!(reg.list()[0].state, TransferState::Failed);
    }

    #[test]
    fn finished_transfers_expire_but_live_ones_do_not() {
        let reg = TransferRegistry::new();
        let done = reg.register_receive("laptop".into(), "a.jpg".into(), 10);
        reg.finish(done, true);
        reg.register_receive("laptop".into(), "b.jpg".into(), 10);

        let now = Instant::now();
        assert_eq!(reg.list_at(now).len(), 2, "both visible right away");

        let later = now + TERMINAL_TTL + Duration::from_secs(1);
        let list = reg.list_at(later);
        assert_eq!(list.len(), 1, "the finished one expired");
        assert_eq!(list[0].filename, "b.jpg");
    }
}
