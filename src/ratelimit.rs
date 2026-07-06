//! Per-connection rate limiting for inbound control streams.
//!
//! Control-plane messages (`MemberSync`/`BlobUpdated` triggers, `MeshHello`,
//! invite gossip) are cheap to send but can be expensive to process: a single
//! `MemberSync` drives a pkarr resolve and, on a hash change, a blob fetch + DNS
//! rebuild + firewall re-materialize. They carry no per-message authentication,
//! so any peer sharing a network can spam them. [`ControlGate`] guards each
//! control-listener task with a token bucket (the `ratelimit` crate) plus a
//! strike counter: over-budget messages are dropped, and a peer that sustains a
//! flood eventually trips [`Verdict::Close`] so the caller can drop the
//! connection. A peer that only bursts briefly is never penalized: strikes
//! decay on every admitted message.
//!
//! One [`ControlGate`] lives per listener task (each task owns exactly one
//! peer's connection), so there is no shared state and no locking.

use std::time::Duration;

use ratelimit::Ratelimiter;

/// Burst of control messages absorbed instantly before throttling kicks in.
const CAPACITY: u64 = 20;
/// Sustained refill rate, in tokens per second.
const REFILL_PER_SEC: u64 = 2;
/// Net over-budget messages (drops minus admits) before the connection is closed.
const STRIKE_LIMIT: u32 = 100;

/// What to do with one inbound control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A token was available, dispatch the message normally.
    Allow,
    /// Over budget, drop the message; the connection is still healthy.
    Drop,
    /// Sustained flood: drop the message and close the connection.
    Close,
}

/// Token-bucket guard over one connection's inbound control messages.
pub struct ControlGate {
    limiter: Ratelimiter,
    strikes: u32,
    strike_limit: u32,
}

impl ControlGate {
    /// Build a gate with the default capacity/refill/strike policy.
    pub fn new() -> Self {
        Self::with_params(CAPACITY, REFILL_PER_SEC, STRIKE_LIMIT)
    }

    /// Build a gate with explicit parameters (used by tests).
    pub fn with_params(capacity: u64, refill_per_sec: u64, strike_limit: u32) -> Self {
        let limiter = Ratelimiter::builder(refill_per_sec, Duration::from_secs(1))
            .max_tokens(capacity)
            .initial_available(capacity)
            .build()
            .expect("valid ratelimiter parameters");
        Self {
            limiter,
            strikes: 0,
            strike_limit,
        }
    }

    /// Account for one inbound control message and decide what to do with it.
    pub fn check(&mut self) -> Verdict {
        match self.limiter.try_wait() {
            Ok(()) => {
                self.strikes = self.strikes.saturating_sub(1);
                Verdict::Allow
            }
            Err(_) => {
                self.strikes = self.strikes.saturating_add(1);
                if self.strikes >= self.strike_limit {
                    Verdict::Close
                } else {
                    Verdict::Drop
                }
            }
        }
    }
}

impl Default for ControlGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_a_burst_up_to_capacity() {
        let mut gate = ControlGate::with_params(5, 1, 100);
        // The initial bucket holds `capacity` tokens, all admitted instantly.
        for _ in 0..5 {
            assert_eq!(gate.check(), Verdict::Allow);
        }
        // The next message has no token left this instant: dropped, not closed.
        assert_eq!(gate.check(), Verdict::Drop);
    }

    #[test]
    fn sustained_flood_trips_close() {
        let mut gate = ControlGate::with_params(3, 1, 10);
        // Drain the bucket.
        for _ in 0..3 {
            assert_eq!(gate.check(), Verdict::Allow);
        }
        // Keep hammering with no refill: strikes climb to the limit, then Close.
        let mut verdicts = Vec::new();
        for _ in 0..20 {
            verdicts.push(gate.check());
        }
        assert!(
            verdicts.contains(&Verdict::Close),
            "expected a Close verdict under sustained flood"
        );
    }

    #[test]
    fn strikes_decay_so_a_chatty_peer_is_never_closed() {
        // A run of admits drives strikes back down to zero, so an earlier short
        // burst of drops can never accumulate into a Close.
        let mut gate = ControlGate::with_params(2, 1, 5);
        gate.strikes = 4; // simulate a prior near-miss burst
        // Two admitted messages (capacity 2) decay strikes by two.
        assert_eq!(gate.check(), Verdict::Allow);
        assert_eq!(gate.check(), Verdict::Allow);
        assert_eq!(gate.strikes, 2);
        // The next over-budget message is a Drop (strikes 3 < limit 5), not Close.
        assert_eq!(gate.check(), Verdict::Drop);
    }
}
