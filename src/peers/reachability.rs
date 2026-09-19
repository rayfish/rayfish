use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::EndpointId;

use super::FastDashMap;

/// Recent dial outcomes used by status and the retry cooldown.
#[derive(Clone, Default)]
pub struct Reachability {
    inner: Arc<FastDashMap<EndpointId, ReachState>>,
}

#[derive(Clone, Copy, Default)]
struct ReachState {
    last_ok: Option<Instant>,
    last_fail: Option<Instant>,
}

impl ReachState {
    fn failing_within(&self, window: Duration) -> bool {
        match self.last_fail {
            Some(f) => f.elapsed() < window && self.last_ok.is_none_or(|ok| ok < f),
            None => false,
        }
    }
}

impl Reachability {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note_ok(&self, id: EndpointId) {
        self.inner.entry(id).or_default().last_ok = Some(Instant::now());
    }

    pub fn note_fail(&self, id: EndpointId) {
        self.inner.entry(id).or_default().last_fail = Some(Instant::now());
    }

    /// Whether the latest recent reachability result is a failure.
    pub fn is_offline(&self, id: &EndpointId, staleness: Duration) -> bool {
        self.inner
            .get(id)
            .is_some_and(|s| s.failing_within(staleness))
    }
}
