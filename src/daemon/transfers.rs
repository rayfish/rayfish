//! In-flight file transfers, for progress reporting.
//!
//! Fed from both directions of a transfer:
//!
//! - **Receive:** `FileService::accept_file` consumes the `GetProgress` stream from
//!   `blob_store.remote().fetch(..)` and reports bytes as they land.
//! - **Send:** `send_file` returns as soon as the *offer* is delivered; the peer
//!   pulls the bytes whenever it accepts (immediately on auto-accept, minutes or
//!   never on a manual one). So the sender learns the real outcome only from
//!   iroh-blobs *provider* events, which fire when a peer actually reads the blob
//!   out of our store. `TransferCompleted` is the authoritative "they got it".
//!
//! Provider events are keyed by blob hash *and* the resolved peer endpoint id, not
//! by transfer. The roster (group blob) fetches ride the same blobs ALPN, so a
//! hash we never registered as an outgoing file send is ignored, and requiring the
//! peer to match too means the same file offered to two different peers can only
//! ever be completed by the peer it was actually sent to: a pull by one can never
//! complete the other's entry, and a pull by an unrelated third party (anyone who
//! learned the hash) can't complete anyone's entry at all.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::EndpointId;
use iroh_blobs::Hash;

/// How long a finished transfer stays listable, so a poller can observe the
/// terminal state before it disappears.
const TERMINAL_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Outgoing: the offer is delivered, the peer has not started pulling yet.
    Offered,
    /// Bytes are moving.
    Transferring,
    /// Every byte transferred. For a send this means the peer actually pulled it.
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
}

struct Entry {
    info: TransferInfo,
    /// Outgoing only: the blob the peer will pull, used to match provider events.
    hash: Option<Hash>,
    /// Outgoing only: the peer this offer was sent to. A provider event must match
    /// both this and `hash` to complete the entry, so a pull by a different peer
    /// (another recipient of the same file, or anyone else who learned the hash)
    /// can never complete it.
    peer_id: Option<EndpointId>,
    /// When the transfer reached a terminal state, for TTL expiry.
    finished_at: Option<Instant>,
    /// Outgoing only: how a `Failed` entry got there. Only a pull that was
    /// aborted partway through is worth reviving on a retried `Started`; an
    /// offer that never reached the peer (the dial, `open_bi`, or the offer
    /// message itself failed) has nothing to retry, because the peer never
    /// even knew about it.
    failure: Option<FailureKind>,
}

/// How an outgoing entry reached `Failed`. Only set on the send side: a
/// receive's `finish(id, false)` never needs to distinguish these, since
/// nothing ever revives a receive entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    /// The offer itself never reached the peer (dial, `open_bi`, or the offer
    /// message failed). Not revivable: there is no pull to retry.
    Offer,
    /// The peer received the offer and started pulling, but the pull was
    /// aborted. Revivable: a later `Started` for the same `(hash, peer)` is a
    /// genuine retry.
    Abort,
}

#[derive(Default)]
pub struct TransferRegistry {
    entries: Mutex<HashMap<u64, Entry>>,
    next_id: AtomicU64,
}

impl TransferRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
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
        self.entries.lock().unwrap().insert(
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
                },
                hash: Some(hash),
                peer_id: Some(peer),
                finished_at: None,
                failure: None,
            },
        );
        id
    }

    /// An incoming transfer we drive ourselves, so it is moving from the start.
    pub fn register_receive(&self, peer: String, filename: String, size: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().unwrap().insert(
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
                },
                hash: None,
                peer_id: None,
                finished_at: None,
                failure: None,
            },
        );
        id
    }

    pub fn note_progress(&self, id: u64, transferred: u64) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            e.info.transferred = transferred.min(e.info.size);
            e.info.state = TransferState::Transferring;
        }
    }

    pub fn finish(&self, id: u64, ok: bool) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            finish_entry(e, ok, None);
        }
    }

    /// An outgoing offer failed before the peer could ever pull it: the dial,
    /// `open_bi`, or the offer message itself failed. Distinct from `finish`
    /// so this can be tagged not-revivable (see [`FailureKind::Offer`]):
    /// nothing the peer does can retry a pull of an offer it never received.
    pub fn fail_offer(&self, id: u64) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            finish_entry(e, false, Some(FailureKind::Offer));
        }
    }

    /// `fail_offer` addressed by `(hash, peer)` instead of registry id, for the
    /// send outbox: a canceled queued send registered its transfer at enqueue
    /// (see `register_send`'s ordering contract) and only knows the blob and
    /// peer. Touches only the still-`Offered` entry, never a moving transfer.
    pub fn fail_offer_by(&self, hash: Hash, peer: EndpointId) {
        if let Some(e) = self.entries.lock().unwrap().values_mut().find(|e| {
            e.info.outgoing
                && e.hash == Some(hash)
                && e.peer_id == Some(peer)
                && e.info.state == TransferState::Offered
        }) {
            finish_entry(e, false, Some(FailureKind::Offer));
        }
    }

    /// A peer started pulling a blob. If the only entry for this `(hash, peer)`
    /// pair already finished as `Failed` from an aborted pull (not an offer that
    /// never reached the peer, see [`FailureKind`]), and it failed recently
    /// enough to still be live (within `TERMINAL_TTL`; terminal entries are only
    /// evicted lazily in `list_at`, so an older one could otherwise sit around
    /// forever waiting to be revived), a fresh `Started` revives it rather than
    /// leaving the sender stuck showing a failure for a file that is now
    /// actually arriving: a retried pull after an aborted one still deserves to
    /// end up `Done`.
    pub fn provider_started(&self, hash: Hash, peer: EndpointId) {
        self.provider_started_at(hash, peer, Instant::now());
    }

    fn provider_started_at(&self, hash: Hash, peer: EndpointId, now: Instant) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash, peer) {
            let e = entries.get_mut(&id).expect("id came from this map");
            e.info.state = TransferState::Transferring;
        } else if let Some(id) = oldest_revivable_outgoing(&entries, hash, peer, now) {
            let e = entries.get_mut(&id).expect("id came from this map");
            e.finished_at = None;
            e.failure = None;
            e.info.transferred = 0;
            e.info.state = TransferState::Transferring;
        }
    }

    pub fn provider_progress(&self, hash: Hash, peer: EndpointId, end_offset: u64) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash, peer) {
            let e = entries.get_mut(&id).expect("id came from this map");
            e.info.transferred = end_offset.min(e.info.size);
            e.info.state = TransferState::Transferring;
        }
    }

    pub fn provider_finished(&self, hash: Hash, peer: EndpointId, ok: bool) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash, peer) {
            let e = entries.get_mut(&id).expect("id came from this map");
            finish_entry(e, ok, Some(FailureKind::Abort));
        }
    }

    pub fn list(&self) -> Vec<TransferInfo> {
        self.list_at(Instant::now())
    }

    fn list_at(&self, now: Instant) -> Vec<TransferInfo> {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, e| match e.finished_at {
            Some(at) => now.duration_since(at) < TERMINAL_TTL,
            None => true,
        });
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
    pub fn success(mut self) {
        self.armed = false;
        self.registry.finish(self.id, true);
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        if self.armed {
            self.registry.finish(self.id, false);
        }
    }
}

/// A finished transfer reads as complete: a Done that showed 60/100 because the
/// last progress event was coarse would be a worse lie than rounding up.
///
/// `failure` records why an outgoing entry failed (ignored when `ok` is true,
/// and for receive entries, which never get revived): see [`FailureKind`].
fn finish_entry(e: &mut Entry, ok: bool, failure: Option<FailureKind>) {
    e.info.state = if ok {
        e.info.transferred = e.info.size;
        TransferState::Done
    } else {
        TransferState::Failed
    };
    e.finished_at = Some(Instant::now());
    e.failure = if ok { None } else { failure };
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
        .filter(|e| e.hash == Some(hash) && e.peer_id == Some(peer) && e.finished_at.is_none())
        .map(|e| e.info.id)
        .min()
}

/// Like [`oldest_live_outgoing`] but for an entry worth reviving on a fresh
/// `Started` event (see `provider_started`): it must have failed on the pull
/// path (not the offer path, which the peer never even received), and recently
/// enough that it has not already aged past `TERMINAL_TTL`. Terminal entries
/// are only evicted lazily inside `list_at`, so without the TTL check an entry
/// that is logically dead but hasn't been swept yet could be revived and then
/// never expire at all.
fn oldest_revivable_outgoing(
    entries: &HashMap<u64, Entry>,
    hash: Hash,
    peer: EndpointId,
    now: Instant,
) -> Option<u64> {
    entries
        .values()
        .filter(|e| {
            e.hash == Some(hash)
                && e.peer_id == Some(peer)
                && e.info.state == TransferState::Failed
                && e.failure == Some(FailureKind::Abort)
                && e.finished_at
                    .is_some_and(|at| now.duration_since(at) < TERMINAL_TTL)
        })
        .map(|e| e.info.id)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn peer(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        SecretKey::from(key_bytes).public()
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
    fn an_aborted_send_fails() {
        let reg = TransferRegistry::new();
        let a = peer(1);
        reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1), a);
        reg.provider_finished(hash(1), a, false);
        assert_eq!(reg.list()[0].state, TransferState::Failed);
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
    fn a_started_event_revives_a_failed_send_on_retry() {
        // An aborted pull marks the send Failed; if the same peer later retries
        // and actually completes the pull, the sender should end up Done, not
        // stuck showing a failure for a file that did arrive.
        let reg = TransferRegistry::new();
        let a = peer(1);
        reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1), a);
        reg.provider_finished(hash(1), a, false);
        assert_eq!(reg.list()[0].state, TransferState::Failed);

        // The retry.
        reg.provider_started(hash(1), a);
        assert_eq!(reg.list()[0].state, TransferState::Transferring);
        reg.provider_finished(hash(1), a, true);
        assert_eq!(reg.list()[0].state, TransferState::Done);
    }

    #[test]
    fn a_started_event_does_not_revive_a_failed_send_past_its_ttl() {
        // An entry that failed long enough ago to be past TERMINAL_TTL is dead:
        // it is only evicted lazily inside `list_at`, so one that hasn't been
        // swept yet must still not be revived, or it would become permanently
        // live again with no terminal event ever following.
        let reg = TransferRegistry::new();
        let a = peer(1);
        reg.register_send(a, "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1), a);
        reg.provider_finished(hash(1), a, false);
        assert_eq!(reg.list()[0].state, TransferState::Failed);

        let later = Instant::now() + TERMINAL_TTL + Duration::from_secs(1);
        reg.provider_started_at(hash(1), a, later);
        assert!(
            reg.list_at(later).is_empty(),
            "a Started arriving after the entry aged out must not revive it: it is dead, \
             so it is just evicted like any other expired terminal entry"
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
