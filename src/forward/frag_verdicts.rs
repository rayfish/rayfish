//! Firewall verdicts for IPv6 fragments.
//!
//! An IP packet larger than the path is split by the sending host into
//! fragments, and only the first carries the ports the firewall matches on.
//! Refusing every fragment blackholed any UDP send past the MTU. Instead the
//! first fragment is judged like a whole packet, and when it passes, its key
//! (source, destination, identification) is remembered here for a short time;
//! a later fragment goes through only if its first did.
//!
//! This is not reassembly: fragments are forwarded as they come and the
//! receiving host reassembles them. A later fragment that arrives before its
//! first is dropped, as is everything after a first fragment that was refused.
//! The table is bounded, oldest out first, so a flood of first fragments costs
//! at most [`CAPACITY`] entries.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use tokio::time::Instant;

use crate::firewall::FragmentKey;

/// How long a first fragment's verdict holds for the rest. Fragments of one
/// packet leave the sender back to back; this is only slack for queueing.
const TTL: Duration = Duration::from_secs(10);

/// Most packets with a verdict held at once.
const CAPACITY: usize = 1024;

#[derive(Default)]
pub(super) struct FragmentVerdicts {
    allowed: HashSet<FragmentKey>,
    /// Insertion order with expiry, one entry per key in `allowed`.
    order: VecDeque<(FragmentKey, Instant)>,
}

impl FragmentVerdicts {
    /// Records that the first fragment of `key` was let through.
    pub(super) fn allow(&mut self, key: FragmentKey, now: Instant) {
        self.expire(now);
        if self.allowed.contains(&key) {
            return;
        }
        while self.allowed.len() >= CAPACITY {
            let Some((oldest, _)) = self.order.pop_front() else {
                break;
            };
            self.allowed.remove(&oldest);
        }
        self.allowed.insert(key);
        self.order.push_back((key, now + TTL));
    }

    /// Whether a later fragment of `key` may follow its first.
    pub(super) fn admits(&mut self, key: &FragmentKey, now: Instant) -> bool {
        self.expire(now);
        self.allowed.contains(key)
    }

    fn expire(&mut self, now: Instant) {
        while let Some((key, deadline)) = self.order.front() {
            if *deadline > now {
                break;
            }
            self.allowed.remove(key);
            self.order.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn key(id: u32) -> FragmentKey {
        FragmentKey {
            src: Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 1),
            dst: Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 2),
            id,
        }
    }

    #[test]
    fn later_fragments_follow_an_allowed_first() {
        let now = Instant::now();
        let mut verdicts = FragmentVerdicts::default();
        assert!(!verdicts.admits(&key(1), now), "no first fragment seen");
        verdicts.allow(key(1), now);
        assert!(verdicts.admits(&key(1), now));
        assert!(!verdicts.admits(&key(2), now), "another packet's id");
        let mut other_dst = key(1);
        other_dst.dst = Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 3);
        assert!(!verdicts.admits(&other_dst, now), "another destination");
    }

    #[test]
    fn a_verdict_expires() {
        let now = Instant::now();
        let mut verdicts = FragmentVerdicts::default();
        verdicts.allow(key(1), now);
        assert!(verdicts.admits(&key(1), now + TTL - Duration::from_millis(1)));
        assert!(!verdicts.admits(&key(1), now + TTL));
        assert!(verdicts.order.is_empty());
    }

    /// A repeated first fragment must not grow the table.
    #[test]
    fn the_table_stays_bounded() {
        let now = Instant::now();
        let mut verdicts = FragmentVerdicts::default();
        for _ in 0..10 {
            verdicts.allow(key(0), now);
        }
        assert_eq!(verdicts.order.len(), 1);
        for id in 1..=CAPACITY as u32 + 10 {
            verdicts.allow(key(id), now);
        }
        assert_eq!(verdicts.allowed.len(), CAPACITY);
        assert_eq!(verdicts.order.len(), CAPACITY);
        assert!(!verdicts.admits(&key(0), now), "oldest out first");
        assert!(verdicts.admits(&key(CAPACITY as u32 + 10), now));
    }
}
