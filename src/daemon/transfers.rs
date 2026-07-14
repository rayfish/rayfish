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
//! Provider events are keyed by blob hash, not by transfer, and the roster
//! (group blob) fetches ride the same blobs ALPN. So hashes we never registered as
//! an outgoing file send are ignored, and a hash registered more than once (the
//! same file sent to two peers) resolves oldest-offer-first.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    /// When the transfer reached a terminal state, for TTL expiry.
    finished_at: Option<Instant>,
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

    /// An outgoing offer has been delivered. The bytes move later, when the peer
    /// accepts and pulls them, which arrives as provider events keyed by `hash`.
    pub fn register_send(&self, peer: String, filename: String, size: u64, hash: Hash) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().unwrap().insert(
            id,
            Entry {
                info: TransferInfo {
                    id,
                    outgoing: true,
                    peer,
                    filename,
                    size,
                    transferred: 0,
                    state: TransferState::Offered,
                },
                hash: Some(hash),
                finished_at: None,
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
                finished_at: None,
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
            finish_entry(e, ok);
        }
    }

    pub fn provider_started(&self, hash: Hash) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash) {
            let e = entries.get_mut(&id).expect("id came from this map");
            e.info.state = TransferState::Transferring;
        }
    }

    pub fn provider_progress(&self, hash: Hash, end_offset: u64) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash) {
            let e = entries.get_mut(&id).expect("id came from this map");
            e.info.transferred = end_offset.min(e.info.size);
            e.info.state = TransferState::Transferring;
        }
    }

    pub fn provider_finished(&self, hash: Hash, ok: bool) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(id) = oldest_live_outgoing(&entries, hash) {
            let e = entries.get_mut(&id).expect("id came from this map");
            finish_entry(e, ok);
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
}

/// The transfer a provider event belongs to: the oldest outgoing entry for this
/// hash that has not finished. Returns `None` for a hash we never registered as an
/// outgoing file send (a roster blob fetch, say), which is how those get ignored.
fn oldest_live_outgoing(entries: &HashMap<u64, Entry>, hash: Hash) -> Option<u64> {
    entries
        .values()
        .filter(|e| e.hash == Some(hash) && e.finished_at.is_none())
        .map(|e| e.info.id)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    #[test]
    fn send_starts_offered_then_tracks_the_peer_pulling_it() {
        let reg = TransferRegistry::new();
        let id = reg.register_send("laptop".into(), "photo.jpg".into(), 100, hash(1));

        let t = &reg.list()[0];
        assert_eq!(t.id, id);
        assert!(t.outgoing);
        assert_eq!(t.state, TransferState::Offered);
        assert_eq!(t.transferred, 0);

        // The peer accepts and starts reading the blob out of our store.
        reg.provider_started(hash(1));
        assert_eq!(reg.list()[0].state, TransferState::Transferring);

        reg.provider_progress(hash(1), 60);
        assert_eq!(reg.list()[0].transferred, 60);

        reg.provider_finished(hash(1), true);
        let t = &reg.list()[0];
        assert_eq!(t.state, TransferState::Done);
        // A completed transfer reads as 100%, whatever the last progress event said.
        assert_eq!(t.transferred, 100);
    }

    #[test]
    fn an_aborted_send_fails() {
        let reg = TransferRegistry::new();
        reg.register_send("laptop".into(), "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1));
        reg.provider_finished(hash(1), false);
        assert_eq!(reg.list()[0].state, TransferState::Failed);
    }

    #[test]
    fn provider_events_for_unregistered_hashes_are_ignored() {
        // The roster/group-blob fetches ride the same blobs ALPN. They must not
        // show up as file transfers.
        let reg = TransferRegistry::new();
        reg.provider_started(hash(9));
        reg.provider_progress(hash(9), 10);
        reg.provider_finished(hash(9), true);
        assert!(reg.list().is_empty());
    }

    #[test]
    fn the_same_blob_sent_twice_resolves_oldest_offer_first() {
        let reg = TransferRegistry::new();
        let first = reg.register_send("laptop".into(), "photo.jpg".into(), 100, hash(1));
        let second = reg.register_send("phone".into(), "photo.jpg".into(), 100, hash(1));

        reg.provider_started(hash(1));
        reg.provider_finished(hash(1), true);

        let list = reg.list();
        let a = list.iter().find(|t| t.id == first).unwrap();
        let b = list.iter().find(|t| t.id == second).unwrap();
        assert_eq!(a.state, TransferState::Done);
        assert_eq!(b.state, TransferState::Offered, "the second offer is untouched");
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
        let first = reg.register_send("laptop".into(), "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1));
        reg.provider_finished(hash(1), true);
        assert_eq!(reg.list()[0].state, TransferState::Done);

        // The user sends the same file again: a new entry for the same hash.
        let second = reg.register_send("laptop".into(), "photo.jpg".into(), 100, hash(1));
        reg.provider_started(hash(1));
        reg.provider_finished(hash(1), true);

        let list = reg.list();
        assert_eq!(list.len(), 2, "the finished first send is still listed alongside the new one");
        let a = list.iter().find(|t| t.id == first).unwrap();
        let b = list.iter().find(|t| t.id == second).unwrap();
        assert_eq!(a.state, TransferState::Done, "the first send must not be reopened");
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
