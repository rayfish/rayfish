//! Limits on concurrent mesh SSH connections.
//!
//! A connection is admitted against the total on accept, before anything is
//! known about it, so that cap has to hold against peers that will never log
//! in. A total alone lets one source hold every place through the login grace
//! and reconnect, so once the connection is identified it also claims a place
//! under its source: the mesh peer it came from, or for self-SSH the local uid
//! that owns the client socket (every local account shares one address).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iroh::EndpointId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Who a connection counts against.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Source {
    Peer(EndpointId),
    LocalUid(u32),
}

type Counts = Arc<Mutex<HashMap<Source, usize>>>;

pub(super) struct ConnectionSlots {
    total: Arc<Semaphore>,
    per_source: usize,
    counts: Counts,
}

/// A connection's place under its source; dropping it frees the place.
pub(super) struct SourceSlot {
    source: Source,
    counts: Counts,
}

impl ConnectionSlots {
    pub(super) fn new(total: usize, per_source: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            per_source,
            counts: Arc::default(),
        }
    }

    /// A place among all connections, or `None` when the server is full.
    pub(super) fn admit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.total).try_acquire_owned().ok()
    }

    /// A place under `source`, or `None` when that source is at its limit.
    pub(super) fn claim(&self, source: Source) -> Option<SourceSlot> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.get(&source).copied().unwrap_or(0);
        if count >= self.per_source {
            return None;
        }
        counts.insert(source, count + 1);
        Some(SourceSlot {
            source,
            counts: Arc::clone(&self.counts),
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> Source {
        let mut b = [0u8; 32];
        b[0] = seed;
        Source::Peer(iroh::SecretKey::from(b).public())
    }

    #[test]
    fn one_source_cannot_take_every_place() {
        let slots = ConnectionSlots::new(8, 2);
        let held: Vec<_> = (0..2).map(|_| slots.claim(peer(1))).collect();
        assert!(held.iter().all(Option::is_some));
        assert!(slots.claim(peer(1)).is_none(), "past the source cap");
        assert!(slots.claim(peer(2)).is_some(), "another peer still fits");
    }

    #[test]
    fn local_accounts_are_separate_sources() {
        let slots = ConnectionSlots::new(8, 1);
        let _user = slots.claim(Source::LocalUid(1000)).expect("first user");
        assert!(slots.claim(Source::LocalUid(1000)).is_none());
        assert!(
            slots.claim(Source::LocalUid(0)).is_some(),
            "one local user must not lock out another"
        );
    }

    #[test]
    fn the_total_cap_holds_across_sources() {
        let slots = ConnectionSlots::new(2, 2);
        let _a = slots.admit().expect("first");
        let _b = slots.admit().expect("second");
        assert!(slots.admit().is_none(), "past the total cap");
    }

    #[test]
    fn closed_and_refused_connections_leave_nothing_behind() {
        let slots = ConnectionSlots::new(8, 1);
        let held = slots.claim(peer(1)).expect("first");
        assert!(slots.claim(peer(1)).is_none());
        drop(held);
        assert!(slots.claim(peer(1)).is_some(), "place not returned");
        assert!(
            slots.counts.lock().expect("lock").is_empty(),
            "an entry outlived its connections"
        );
    }
}
