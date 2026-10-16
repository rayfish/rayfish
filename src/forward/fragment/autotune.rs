//! Bounded receiver-local capacity trials. The metadata-only observer sees the
//! same valid fragments at the old limit; it neither retains payload nor delivers
//! packets. A trial must improve complete packet and byte delivery to be kept.
//!
//! Start at 64, trial powers of two up to 512 after three local capacity
//! evictions in 50 ms, and retain only an observed packet AND byte gain. Pending
//! observer packets are charged against that gain to avoid treating delayed
//! completion at the window edge as a loss. Failed/ambiguous trials back off;
//! downward trials and idle reset are deliberately slower. These receiver-local
//! heuristics never change wire framing, retransmission, or the five-second TTL.
//!
//! Observer memory is reserved BEFORE cloning any metadata, inside the existing
//! process budget. At most two observers exist, each with at most 512 entries.
//! Connection quotas are soft, with global admission remaining authoritative.
//! A lower limit does not purge the table. On each subsequent new admission an
//! oversized table reclaims at most one additional old assembly. Without that
//! bounded drain, continuous orphan replacements could preserve the old size
//! forever. The observer models the same rule when evaluating a lower limit.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::stats::ForwardMetrics;

const MAX_PENDING: usize = 512;
const SHADOW_COST: usize = 512;
const SHADOW_RESERVATION: usize = MAX_PENDING * SHADOW_COST;
const POLL: Duration = Duration::from_millis(250);
const PRESSURE_WINDOW: Duration = Duration::from_millis(50);
const TRIAL: Duration = Duration::from_secs(5);
const MAX_TRIAL: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(30);
const DOWN_INTERVAL: Duration = Duration::from_secs(60);

pub(super) struct Budget {
    pub(super) memory: Arc<Semaphore>,
    total: usize,
    observers: Arc<Semaphore>,
    active: AtomicUsize,
}

impl Budget {
    pub(super) fn new(total: usize) -> Arc<Self> {
        Arc::new(Self {
            memory: Arc::new(Semaphore::new(total)),
            total,
            observers: Arc::new(Semaphore::new(2)),
            active: AtomicUsize::new(0),
        })
    }

    fn used(&self) -> usize {
        self.total - self.memory.available_permits()
    }

    fn quota(&self) -> usize {
        let peers = self.active.load(Ordering::Relaxed).max(1);
        let slots = self.total.saturating_mul(3) / 4 / peers / ASSEMBLY_COST;
        [512, 256, 128, 64]
            .into_iter()
            .find(|&limit| slots >= limit)
            .unwrap_or(64)
    }

    fn can_grow(&self) -> bool {
        self.used() < self.total * 3 / 4
    }
}

#[derive(Default)]
pub(super) struct Events {
    pub(super) expired: usize,
    pub(super) local: usize,
    pub(super) global: usize,
    pub(super) rejected: usize,
    pub(super) started: usize,
    pub(super) promoted: usize,
    pub(super) rolled_back: usize,
    pub(super) inconclusive: usize,
    pub(super) resource_limited: usize,
    pub(super) completed: usize,
    pub(super) bytes: usize,
}

#[derive(Default)]
struct Delivered {
    packets: u64,
    bytes: u64,
}

impl Delivered {
    fn record(&mut self, bytes: usize) {
        self.packets += 1;
        self.bytes += bytes as u64;
    }
}

struct Observer {
    limit: usize,
    pending: HashMap<AssemblyKey, Progress>,
    delivered: Delivered,
}

impl Observer {
    fn expire(&mut self, now: Instant) {
        self.pending.retain(|_, part| now < part.deadline);
    }

    fn accept(&mut self, fragment: Fragment, now: Instant) {
        if self
            .pending
            .get(&fragment.key)
            .is_some_and(|part| now >= part.deadline)
        {
            self.pending.remove(&fragment.key);
            return;
        }
        if !self.pending.contains_key(&fragment.key) {
            self.expire(now);
            if self.pending.len() > self.limit {
                let oldest = self.oldest();
                self.pending.remove(&oldest);
            }
            if self.pending.len() >= self.limit {
                let oldest = self.oldest();
                self.pending.remove(&oldest);
            }
            self.pending
                .insert(fragment.key, Progress::new(fragment.total, now + TIMEOUT));
        }
        let part = self.pending.get_mut(&fragment.key).unwrap();
        if part.total != fragment.total {
            self.pending.remove(&fragment.key);
            return;
        }
        part.cover(fragment.offset, fragment.len);
        if part.received == part.total {
            self.pending.remove(&fragment.key);
            self.delivered.record(fragment.total);
        }
    }

    fn oldest(&self) -> AssemblyKey {
        self.pending
            .iter()
            .min_by_key(|(key, part)| (part.deadline, key.handle, key.id))
            .map(|(&key, _)| key)
            .expect("a full observer is nonempty")
    }
}

struct Probe {
    base: usize,
    down: bool,
    started: Instant,
    observer: Observer,
    delivered: Delivered,
    _memory: OwnedSemaphorePermit,
    _slot: OwnedSemaphorePermit,
}

pub(super) struct Controller {
    pub(super) limit: usize,
    enabled: bool,
    probe: Option<Probe>,
    next_poll: Option<Instant>,
    next_down: Instant,
    cooldown: Instant,
    failures: u32,
    pressure_since: Instant,
    pressure_count: usize,
    last_activity: Instant,
    active_until: Option<Instant>,
    restore: Option<(usize, Instant)>,
}

impl Controller {
    pub(super) fn new(now: Instant, enabled: bool) -> Self {
        Self {
            limit: super::MAX_PENDING,
            enabled,
            probe: None,
            next_poll: None,
            next_down: now + DOWN_INTERVAL,
            cooldown: now,
            failures: 0,
            pressure_since: now,
            pressure_count: 0,
            last_activity: now,
            active_until: None,
            restore: None,
        }
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.next_poll.into_iter().chain(self.active_until).min()
    }

    pub(super) fn observe(&mut self, fragment: Fragment, bytes: Option<usize>, now: Instant) {
        if let Some(probe) = &mut self.probe {
            probe.observer.accept(fragment, now);
            if let Some(bytes) = bytes {
                probe.delivered.record(bytes);
            }
        }
    }
}

impl Reassembler {
    pub(super) fn touch_fragment(&mut self, now: Instant) {
        if !self.control.enabled {
            return;
        }
        self.autotune_tick(now);
        self.control.last_activity = now;
        if self.control.active_until.is_none() {
            self.budget.active.fetch_add(1, Ordering::Relaxed);
        }
        self.control.active_until = Some(now + TIMEOUT);
    }

    fn start_probe(&mut self, now: Instant, down: bool) -> bool {
        if !self.budget.can_grow() || now < self.control.cooldown {
            return false;
        }
        let Ok(slot) = Arc::clone(&self.budget.observers).try_acquire_owned() else {
            return false;
        };
        let Ok(memory) =
            Arc::clone(&self.budget.memory).try_acquire_many_owned(SHADOW_RESERVATION as u32)
        else {
            return false;
        };
        // Leave room for ordinary connections, including the reservation itself.
        if !self.budget.can_grow() {
            return false;
        }
        let base = self.control.limit;
        let observer_limit = if down { base / 2 } else { base };
        self.control.probe = Some(Probe {
            base,
            down,
            started: now,
            observer: Observer {
                limit: observer_limit,
                pending: self
                    .pending
                    .iter()
                    .map(|(&key, part)| (key, part.progress.clone()))
                    .collect(),
                delivered: Delivered::default(),
            },
            delivered: Delivered::default(),
            _memory: memory,
            _slot: slot,
        });
        if !down {
            self.control.limit = (base * 2).min(self.budget.quota()).min(MAX_PENDING);
        }
        self.control.next_poll = Some(now + POLL);
        self.events.started += 1;
        tracing::debug!(
            base,
            limit = self.control.limit,
            down,
            "reassembly capacity trial started"
        );
        true
    }

    pub(super) fn capacity_pressure(&mut self, now: Instant) {
        if !self.control.enabled || !self.budget.can_grow() {
            return;
        }
        if now.duration_since(self.control.pressure_since) > PRESSURE_WINDOW {
            self.control.pressure_since = now;
            self.control.pressure_count = 0;
        }
        self.control.pressure_count += 1;
        if self.control.pressure_count < 3 {
            return;
        }
        self.control.pressure_count = 0;
        if let Some(probe) = &self.control.probe {
            if !probe.down {
                let previous = self.control.limit;
                self.control.limit = (self.control.limit * 2)
                    .min(self.budget.quota())
                    .min(MAX_PENDING);
                if self.control.limit != previous {
                    tracing::debug!(
                        previous,
                        limit = self.control.limit,
                        "reassembly trial expanded again"
                    );
                }
            }
            return;
        }
        if let Some((limit, until)) = self.control.restore
            && now < until
            && limit <= self.budget.quota()
        {
            self.control.limit = limit;
            self.control.restore = None;
            self.control.next_poll = Some(now + POLL);
            self.control.next_down = now + DOWN_INTERVAL;
            self.events.promoted += 1;
            return;
        }
        if self.control.limit < self.budget.quota() && self.control.limit < MAX_PENDING {
            self.start_probe(now, false);
        }
    }

    pub(super) fn abort_probe(&mut self, now: Instant, resource: bool) {
        let Some(probe) = self.control.probe.take() else {
            return;
        };
        self.control.limit = probe.base.min(self.budget.quota());
        tracing::debug!(
            limit = self.control.limit,
            resource,
            "reassembly capacity trial cancelled"
        );
        self.events.rolled_back += 1;
        if resource {
            self.events.resource_limited += 1;
        } else {
            self.events.inconclusive += 1;
        }
        self.backoff(now);
    }

    fn backoff(&mut self, now: Instant) {
        self.control.cooldown = now + Duration::from_secs(30 << self.control.failures.min(2));
        self.control.failures = self.control.failures.saturating_add(1);
        self.control.pressure_count = 0;
        self.control.next_down = now + DOWN_INTERVAL;
        self.control.next_poll = (self.control.limit > super::MAX_PENDING).then_some(now + POLL);
    }

    pub(super) fn autotune_tick(&mut self, now: Instant) {
        if !self.control.enabled {
            return;
        }
        if self.control.active_until.is_some_and(|until| now >= until) {
            self.budget.active.fetch_sub(1, Ordering::Relaxed);
            self.control.active_until = None;
        }
        if self.control.next_poll.is_none_or(|next| now < next) {
            return;
        }
        self.control.next_poll = Some(now + POLL);
        let quota = self.budget.quota();
        if self.budget.used() >= self.budget.total * 9 / 10 || self.control.limit > quota {
            self.abort_probe(now, true);
            self.control.limit = self.control.limit.min(quota);
        }
        if let Some(probe) = &mut self.control.probe {
            probe.observer.expire(now);
            if now.duration_since(probe.started) < TRIAL {
                return;
            }
            let real = &probe.delivered;
            let shadow = &probe.observer.delivered;
            let pending_bytes: u64 = probe
                .observer
                .pending
                .values()
                .map(|p| p.total as u64)
                .sum();
            let gain = real.packets >= shadow.packets + probe.observer.pending.len() as u64 + 8
                && real.bytes >= shadow.bytes + pending_bytes + 16 * 1024;
            let smaller_is_equal =
                real.packets >= 100 && shadow.packets >= real.packets && shadow.bytes >= real.bytes;
            let keep = if probe.down { smaller_is_equal } else { gain };
            let insufficient = real.packets < 8;
            if !keep
                && now.duration_since(probe.started) < MAX_TRIAL
                && !probe.observer.pending.is_empty()
            {
                return;
            }
            let probe = self.control.probe.take().unwrap();
            if keep {
                if probe.down {
                    self.control.limit = probe.observer.limit;
                    self.control.restore = Some((probe.base, now + IDLE));
                }
                self.control.failures = 0;
                self.control.cooldown = now + Duration::from_secs(2);
                self.control.next_down = now + DOWN_INTERVAL;
                self.events.promoted += 1;
                tracing::debug!(
                    limit = self.control.limit,
                    down = probe.down,
                    "reassembly capacity trial retained"
                );
            } else {
                self.control.limit = probe.base;
                self.events.rolled_back += 1;
                if insufficient {
                    self.events.inconclusive += 1;
                }
                self.backoff(now);
                tracing::debug!(
                    limit = self.control.limit,
                    "reassembly capacity trial rolled back"
                );
            }
        }
        if self.control.probe.is_none() {
            if self.pending.is_empty() && now.duration_since(self.control.last_activity) >= IDLE {
                self.control.limit = super::MAX_PENDING;
                self.control.restore = None;
            } else if self.control.limit > super::MAX_PENDING && now >= self.control.next_down {
                self.control.next_down = now + DOWN_INTERVAL;
                self.start_probe(now, true);
            }
        }
        if self.control.limit == super::MAX_PENDING && self.control.probe.is_none() {
            self.control.next_poll = None;
        }
    }

    pub(in crate::forward) fn record_metrics(&mut self, stats: &ForwardMetrics) {
        let events = std::mem::take(&mut self.events);
        // Most batches have no trial/drop events. Avoid zero-valued atomic
        // updates on shared metric cache lines, especially for whole packets.
        for (counter, value) in [
            (&stats.reassembly_evicted_local, events.local),
            (&stats.reassembly_evicted_global, events.global),
            (&stats.reassembly_rejected_global, events.rejected),
            (&stats.reassembly_trials, events.started),
            (&stats.reassembly_retained, events.promoted),
            (&stats.reassembly_rolled_back, events.rolled_back),
            (&stats.reassembly_inconclusive, events.inconclusive),
            (&stats.reassembly_resource_limited, events.resource_limited),
            (&stats.reassembly_completed, events.completed),
            (&stats.reassembly_completed_bytes, events.bytes),
        ] {
            if value != 0 {
                counter.inc_by(value as u64);
            }
        }
        for _ in 0..events.expired {
            stats.record_drop(DropReason::ReassemblyTimeout);
        }
        for _ in 0..self.take_evicted() {
            stats.record_drop(DropReason::ReassemblyLimit);
        }
    }
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        if self.control.active_until.is_some() {
            self.budget.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receiver(enabled: bool) -> Reassembler {
        Reassembler::with_budget(Budget::new(GLOBAL_BUDGET), enabled)
    }

    fn packet() -> Vec<u8> {
        let mut p = vec![0x42; MAX_PACKET];
        p[0] = 0x60;
        p
    }

    fn frames() -> Vec<Bytes> {
        let encoded = encode(7, &packet(), 1162).unwrap();
        assert_eq!(encoded.datagrams().len(), 2);
        encoded.datagrams().to_vec()
    }

    fn burst(receiver: &mut Reassembler, count: usize, start: Instant) -> usize {
        let parts: Vec<_> = (0..count).map(|_| frames()).collect();
        for (i, parts) in parts.iter().enumerate() {
            assert_eq!(
                receiver.accept(parts[0].clone(), start + Duration::from_micros(i as u64)),
                Ok(None)
            );
        }
        let mut delivered = 0;
        for (i, parts) in parts.iter().enumerate() {
            if let Some(p) = receiver
                .accept(
                    parts[1].clone(),
                    start + Duration::from_millis(10) + Duration::from_micros(i as u64),
                )
                .unwrap()
            {
                assert_eq!(p.as_ref(), packet().as_slice());
                delivered += 1;
            }
        }
        delivered
    }

    #[test]
    fn grows_during_loss_free_bursts_and_keeps_measured_gain() {
        for count in [65, 129, 257] {
            let mut fixed = receiver(false);
            let mut adaptive = receiver(true);
            let now = Instant::now();
            assert_eq!(burst(&mut fixed, count, now), 0);
            let delivered = burst(&mut adaptive, count, now);
            assert!(
                delivered >= count - 8,
                "count={count}, delivered={delivered}"
            );
            assert!(adaptive.control.limit > 64);
            assert!(adaptive.control.limit <= MAX_PENDING);
            adaptive.expire(now + Duration::from_secs(6));
            assert!(adaptive.control.probe.is_none());
            assert_eq!(adaptive.events.promoted, 1);
            assert!(adaptive.control.limit > 64);
        }
    }

    #[test]
    fn ordinary_packets_need_no_observer_or_growth() {
        let mut r = receiver(true);
        let now = Instant::now();
        for i in 0..1000 {
            for f in frames() {
                r.accept(f, now + Duration::from_micros(i)).unwrap();
            }
        }
        assert_eq!(r.events.completed, 1000);
        assert_eq!(r.events.started, 0);
        assert_eq!(r.control.limit, 64);
        assert_eq!(r.budget.memory.available_permits(), GLOBAL_BUDGET);
    }

    #[test]
    fn orphaned_packets_do_not_block_healthy_packets_or_require_growth() {
        let mut r = receiver(true);
        let now = Instant::now();
        for i in 0..64 {
            r.accept(frames()[0].clone(), now + Duration::from_micros(i))
                .unwrap();
        }
        for i in 0..1000 {
            for f in frames() {
                r.accept(f, now + Duration::from_millis(1 + i)).unwrap();
            }
        }
        assert_eq!(r.events.completed, 1000);
        assert_eq!(r.events.started, 0);
        assert_eq!(r.take_evicted(), 1);
    }

    #[test]
    fn permanent_loss_rolls_back_with_cooldown_and_releases_observer() {
        let mut r = receiver(true);
        let now = Instant::now();
        for i in 0..400 {
            r.accept(frames()[0].clone(), now + Duration::from_micros(i))
                .unwrap();
        }
        assert_eq!(r.events.started, 1);
        assert!(r.control.limit > 64);
        r.expire(now + Duration::from_secs(6));
        assert_eq!(r.control.limit, 64);
        assert!(r.control.probe.is_none());
        assert_eq!(r.events.rolled_back, 1);
        assert_eq!(r.budget.memory.available_permits(), GLOBAL_BUDGET);
        assert!(r.control.cooldown > now + Duration::from_secs(30));
        for i in 0..200 {
            r.accept(
                frames()[0].clone(),
                now + Duration::from_secs(7) + Duration::from_micros(i),
            )
            .unwrap();
        }
        assert_eq!(r.events.started, 1);
        assert_eq!(r.control.limit, 64);
    }

    #[test]
    fn duplicate_fragments_do_not_make_progress_or_extend_deadline() {
        let mut r = receiver(true);
        let now = Instant::now();
        let head = frames()[0].clone();
        for i in 0..1000 {
            r.accept(head.clone(), now + Duration::from_millis(i))
                .unwrap();
        }
        assert_eq!(r.pending.len(), 1);
        assert_eq!(r.events.started, 0);
        assert_eq!(r.expire(now + TIMEOUT), 1);
        assert!(r.pending.is_empty());
    }

    #[test]
    fn corrupt_overlap_invalidates_trial_and_releases_its_memory() {
        let mut r = receiver(true);
        let now = Instant::now();
        burst(&mut r, 65, now);
        assert!(r.control.probe.is_some());
        let f = frames();
        r.accept(f[0].clone(), now + Duration::from_millis(20))
            .unwrap();
        let mut corrupt = f[0].to_vec();
        corrupt[HEADER] ^= 1;
        assert_eq!(
            r.accept(Bytes::from(corrupt), now + Duration::from_millis(21)),
            Err(DropReason::Malformed)
        );
        assert!(r.control.probe.is_none());
        assert_eq!(r.events.inconclusive, 1);
        assert_eq!(
            r.budget.memory.available_permits(),
            GLOBAL_BUDGET - r.pending.len() * ASSEMBLY_COST
        );
    }

    #[test]
    fn shared_budget_exhaustion_is_not_local_capacity_evidence() {
        let budget = Budget::new(64 * ASSEMBLY_COST);
        let mut r = Reassembler::with_budget(Arc::clone(&budget), true);
        let now = Instant::now();
        for _ in 0..100 {
            r.accept(frames()[0].clone(), now).unwrap();
        }
        assert_eq!(r.events.started, 0);
        assert_eq!(r.pending.len(), 64);
        let mut other = Reassembler::with_budget(Arc::clone(&budget), true);
        assert_eq!(
            other.accept(frames()[0].clone(), now),
            Err(DropReason::ReassemblyLimit)
        );
        assert_eq!(other.events.rejected, 1);
        assert_eq!(r.pending.len(), 64);
        drop(r);
        assert_eq!(budget.memory.available_permits(), 64 * ASSEMBLY_COST);
    }

    #[test]
    fn observers_are_globally_bounded_and_all_permits_are_released() {
        let budget = Budget::new(GLOBAL_BUDGET);
        let mut a = Reassembler::with_budget(Arc::clone(&budget), true);
        let mut b = Reassembler::with_budget(Arc::clone(&budget), true);
        let mut c = Reassembler::with_budget(Arc::clone(&budget), true);
        let now = Instant::now();
        assert!(a.start_probe(now, false));
        assert!(b.start_probe(now, false));
        assert!(!c.start_probe(now, false));
        assert_eq!(budget.used(), 512 * 1024);
        drop(a);
        assert!(c.start_probe(now, false));
        drop(b);
        drop(c);
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.observers.available_permits(), 2);
    }

    #[test]
    fn global_pressure_cancels_trial_without_evicting_existing_data() {
        let mut r = receiver(true);
        let now = Instant::now();
        burst(&mut r, 65, now);
        let pending = r.pending.len();
        let external = Arc::clone(&r.budget.memory)
            .try_acquire_many_owned((GLOBAL_BUDGET * 9 / 10 - r.budget.used()) as u32)
            .unwrap();
        r.expire(now + POLL + Duration::from_millis(20));
        assert!(r.control.probe.is_none());
        assert_eq!(r.control.limit, 64);
        assert_eq!(r.pending.len(), pending);
        assert_eq!(r.events.resource_limited, 1);
        drop(external);
    }

    #[test]
    fn successful_window_resets_after_idle_without_a_live_timer_loop() {
        let mut r = receiver(true);
        let now = Instant::now();
        burst(&mut r, 65, now);
        r.expire(now + Duration::from_secs(6));
        assert!(r.control.limit > 64);
        r.expire(now + Duration::from_secs(31));
        assert_eq!(r.control.limit, 64);
        assert!(r.deadline().is_none());
        assert_eq!(r.budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn down_trial_preserves_existing_entries_then_reduces_admission() {
        let mut r = receiver(true);
        let now = Instant::now();
        r.control.limit = 256;
        for i in 0..150 {
            r.accept(frames()[0].clone(), now + Duration::from_micros(i))
                .unwrap();
        }
        assert!(r.start_probe(now + Duration::from_millis(1), true));
        assert_eq!(r.pending.len(), 150);
        assert_eq!(
            r.control.probe.as_ref().unwrap().observer.pending.len(),
            150
        );
        for i in 0..100 {
            for f in frames() {
                r.accept(f, now + Duration::from_millis(2 + i)).unwrap();
            }
        }
        r.expire(now + Duration::from_secs(6));
        assert_eq!(r.control.limit, 128);
        assert_eq!(r.events.promoted, 1);
        assert!(r.control.restore.is_some());
    }

    #[test]
    fn growth_and_metadata_never_exceed_the_hard_connection_bound() {
        let mut r = receiver(true);
        let budget = Arc::clone(&r.budget);
        let now = Instant::now();
        for i in 0..2000 {
            r.accept(frames()[0].clone(), now + Duration::from_micros(i))
                .unwrap();
            assert!(r.pending.len() <= MAX_PENDING);
            if let Some(probe) = &r.control.probe {
                assert!(probe.observer.pending.len() <= MAX_PENDING);
            }
        }
        assert_eq!(r.control.limit, MAX_PENDING);
        assert!(budget.used() <= MAX_PENDING * ASSEMBLY_COST + SHADOW_RESERVATION);
        drop(r);
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metadata_observer_matches_fixed_policy_for_reordering_and_duplicates() {
        let mut r = receiver(false);
        let mut observer = Observer {
            limit: 64,
            pending: HashMap::new(),
            delivered: Delivered::default(),
        };
        let mut stream = Vec::new();
        for _ in 0..200 {
            stream.extend(frames());
        }
        let mut state = 12345u64;
        for i in (1..stream.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            stream.swap(i, (state as usize) % (i + 1));
        }
        let now = Instant::now();
        for (i, frame) in stream.iter().enumerate() {
            // Include equal-deadline entries: tie-breaking must be identical.
            let at = now + Duration::from_micros((i / 4) as u64);
            let fragment = Fragment {
                key: AssemblyKey {
                    handle: u16::from_be_bytes(frame[..2].try_into().unwrap()),
                    id: u64::from_be_bytes(frame[3..11].try_into().unwrap()),
                },
                total: u16::from_be_bytes(frame[11..13].try_into().unwrap()) as usize,
                offset: u16::from_be_bytes(frame[13..15].try_into().unwrap()) as usize,
                len: frame.len() - HEADER,
            };
            for _ in 0..if i % 3 == 0 { 2 } else { 1 } {
                r.accept(frame.clone(), at).unwrap();
                observer.accept(fragment, at);
                assert_eq!(observer.delivered.packets, r.events.completed as u64);
                assert_eq!(observer.delivered.bytes, r.events.bytes as u64);
                assert_eq!(observer.pending.len(), r.pending.len());
                for (key, part) in &r.pending {
                    let shadow = observer.pending.get(key).unwrap();
                    assert_eq!(shadow.covered, part.progress.covered);
                    assert_eq!(shadow.deadline, part.progress.deadline);
                }
            }
        }
    }

    #[test]
    fn soft_quota_counts_recent_fragment_users_and_releases_on_disconnect() {
        let budget = Budget::new(GLOBAL_BUDGET);
        let now = Instant::now();
        let mut readers: Vec<_> = (0..16)
            .map(|_| Reassembler::with_budget(Arc::clone(&budget), true))
            .collect();
        assert_eq!(budget.quota(), 512);
        for reader in &mut readers {
            reader.touch_fragment(now);
        }
        assert_eq!(budget.quota(), 128);
        assert_eq!(budget.active.load(Ordering::Relaxed), 16);
        for reader in &mut readers {
            reader.expire(now + TIMEOUT);
        }
        assert_eq!(budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(budget.quota(), 512);
        drop(readers);
        assert_eq!(budget.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn range_coverage_matches_byte_coverage_across_word_edges_and_duplicates() {
        let now = Instant::now();
        for start in [0, 1, 62, 63, 64, 65, 127, 128, 1459, 1499] {
            for end in start..=MAX_PACKET {
                let mut range = Progress::new(MAX_PACKET, now + TIMEOUT);
                let mut bytes = range.clone();
                for (offset, len) in [
                    (start, end - start),
                    (start, end - start),
                    (0, start),
                    (end, MAX_PACKET - end),
                ] {
                    range.cover(offset, len);
                    for pos in offset..offset + len {
                        bytes.mark(pos);
                    }
                    assert_eq!(range.covered, bytes.covered);
                    assert_eq!(range.received, bytes.received);
                }
            }
        }
    }

    #[test]
    fn metrics_drain_once_and_keep_eviction_units_distinct_from_rejection() {
        let budget = Budget::new(ASSEMBLY_COST);
        let mut r = Reassembler::with_budget(Arc::clone(&budget), false);
        let stats = ForwardMetrics::default();
        let now = Instant::now();
        r.accept(frames()[0].clone(), now).unwrap();
        r.expire(now + TIMEOUT);
        r.record_metrics(&stats);
        r.record_metrics(&stats);
        assert_eq!(stats.drop_count(DropReason::ReassemblyTimeout), 1);
        let at = now + TIMEOUT + Duration::from_secs(1);
        r.accept(frames()[0].clone(), at).unwrap();
        r.accept(frames()[0].clone(), at).unwrap();
        r.record_metrics(&stats);
        assert_eq!(stats.drop_count(DropReason::ReassemblyLimit), 1);
        assert_eq!(stats.reassembly_evicted_global.get(), 1);
        assert_eq!(stats.reassembly_evicted_local.get(), 0);
        let mut other = Reassembler::with_budget(budget, false);
        let error = other.accept(frames()[0].clone(), at).unwrap_err();
        stats.record_drop(error); // The reader already records a returned error.
        other.record_metrics(&stats);
        assert_eq!(stats.reassembly_rejected_global.get(), 1);
        assert_eq!(stats.drop_count(DropReason::ReassemblyLimit), 2);
    }

    #[test]
    fn recently_validated_capacity_is_restored_after_pressure_returns() {
        let mut r = receiver(true);
        r.control.limit = 256;
        let now = Instant::now();
        assert!(r.start_probe(now, true));
        for i in 0..100 {
            for frame in frames() {
                r.accept(frame, now + Duration::from_millis(i)).unwrap();
            }
        }
        r.expire(now + Duration::from_secs(6));
        assert_eq!(r.control.limit, 128);
        burst(&mut r, 129, now + Duration::from_secs(7));
        assert_eq!(r.control.limit, 256);
        assert_eq!(r.events.started, 1);
        assert_eq!(r.events.promoted, 2);
        assert!(r.control.restore.is_none());
    }

    #[test]
    fn whole_packets_do_not_keep_an_unused_reassembly_window_expanded() {
        let mut r = receiver(true);
        let now = Instant::now();
        burst(&mut r, 65, now);
        r.expire(now + Duration::from_secs(6));
        assert!(r.control.limit > 64);
        let whole = tag_datagram(7, &packet());
        for second in 7..=32 {
            // The reader's existing deadline branch drives control/expiry even
            // when the intervening traffic is entirely unfragmented.
            r.expire(now + Duration::from_secs(second));
            assert!(
                r.accept(whole.clone(), now + Duration::from_secs(second))
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(r.control.limit, 64);
        assert!(r.deadline().is_none());
    }

    #[test]
    fn lower_limit_converges_under_continuous_loss_without_blocking_new_packets() {
        let mut r = receiver(true);
        let now = Instant::now();
        for i in 0..400 {
            r.accept(frames()[0].clone(), now + Duration::from_micros(i))
                .unwrap();
        }
        let before = r.pending.len();
        assert!(before > 64);
        // Aborting a trial changes only the limit, not all existing entries.
        r.abort_probe(now + Duration::from_millis(1), false);
        assert_eq!(r.pending.len(), before);
        assert_eq!(r.control.limit, 64);
        for i in 0..before {
            r.accept(
                frames()[0].clone(),
                now + Duration::from_millis(2) + Duration::from_micros(i as u64),
            )
            .unwrap();
        }
        assert_eq!(r.pending.len(), 64);
        for frame in frames() {
            r.accept(frame, now + Duration::from_millis(3)).unwrap();
        }
        assert_eq!(r.events.completed, 1);
        assert_eq!(r.events.started, 1);
    }
}
