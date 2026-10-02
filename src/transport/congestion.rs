//! QUIC congestion controller selection for the data plane.
//!
//! Every DATAGRAM frame counts against the congestion window, so the outer
//! controller caps how fast tunnelled packets can leave even though QUIC never
//! retransmits them. The TCP flows inside the tunnel run their own congestion
//! control, so the outer one mostly adds a second, loss-driven brake: Cubic
//! reads random loss on a consumer uplink as congestion and shrinks the window
//! below what the path carries, and the overflow is dropped from the datagram
//! send buffer.
//!
//! The controller is the `quic-congestion` setting
//! ([`QuicCongestion`]), read once at bind:
//!
//! - `cubic` (default): noq's default, unchanged behaviour.
//! - `loss-tolerant`: [`LossTolerant`], which ignores ordinary loss and leaves
//!   rate control to the inner flows, the way WireGuard does, with a window
//!   ceiling and a persistent-congestion reset as the safety bound.
//!
//! noq's BBR3 is not offered. On a netem-shaped link (40 ms RTT, 100 Mbit/s,
//! 0 to 2% loss) it was slower than Cubic in every case, with ping spikes up to
//! a second under load from overfilling the bottleneck queue.
//!
//! The choice only governs what this node sends. Each side of a connection
//! runs its own controller.

use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

use iroh::endpoint::{Controller, ControllerFactory, RttEstimator};

use crate::config::QuicCongestion;

/// The factory to install for `cc`, or `None` to keep noq's default (Cubic).
pub(crate) fn controller_factory(
    cc: QuicCongestion,
) -> Option<Arc<dyn ControllerFactory + Send + Sync + 'static>> {
    match cc {
        QuicCongestion::Cubic => None,
        QuicCongestion::LossTolerant => Some(Arc::new(LossTolerantConfig::default())),
    }
}

/// Starting window, matching noq's Cubic default (about ten
/// 1200-byte datagrams) so a new path does not burst.
const INITIAL_WINDOW: u64 = 14_720;

/// Window ceiling: roughly the bandwidth-delay product of 1 Gbit/s at 130 ms.
/// It bounds the queue one peer can build at a bottleneck when the inner
/// traffic does not back off on its own (UDP, or a misbehaving sender).
const MAX_WINDOW: u64 = 16 * 1024 * 1024;

/// Configuration for [`LossTolerant`].
#[derive(Debug, Clone)]
pub(crate) struct LossTolerantConfig {
    initial_window: u64,
    max_window: u64,
}

impl Default for LossTolerantConfig {
    fn default() -> Self {
        Self {
            initial_window: INITIAL_WINDOW,
            max_window: MAX_WINDOW,
        }
    }
}

impl ControllerFactory for LossTolerantConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(LossTolerant::new(self, current_mtu))
    }
}

/// A controller that does not treat packet loss as congestion.
///
/// The window grows by every acknowledged byte (slow start, never left) up to
/// the configured ceiling, and ordinary loss leaves it alone: the inner TCP
/// flows already see that loss and back off, so a second reaction here only
/// throttles them twice. Two signals still count:
///
/// - ECN CE marks, which a router sets only when its queue is building, halve
///   the window.
/// - Persistent congestion (every packet lost across several PTOs) drops the
///   window to the minimum, so a path that has gone dark or is badly
///   overloaded is probed again from the bottom instead of flooded.
#[derive(Debug, Clone)]
pub(crate) struct LossTolerant {
    config: Arc<LossTolerantConfig>,
    current_mtu: u64,
    window: u64,
}

impl LossTolerant {
    fn new(config: Arc<LossTolerantConfig>, current_mtu: u16) -> Self {
        Self {
            window: config.initial_window,
            current_mtu: u64::from(current_mtu),
            config,
        }
    }

    fn minimum_window(&self) -> u64 {
        2 * self.current_mtu
    }

    fn grow(&mut self, acked: u64, app_limited: bool) {
        // An app-limited ack says nothing about what the path can carry, so
        // growing on it would inflate the window past anything ever tested.
        if app_limited {
            return;
        }
        self.window = self
            .window
            .saturating_add(acked)
            .min(self.config.max_window);
    }
}

impl Controller for LossTolerant {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _pn: u64,
        app_limited: bool,
        _rtt: &RttEstimator,
    ) {
        self.grow(bytes, app_limited);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        _lost_bytes: u64,
        _largest_lost_pn: u64,
    ) {
        if is_persistent_congestion {
            self.window = self.minimum_window();
        } else if is_ecn {
            self.window = (self.window / 2).max(self.minimum_window());
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu);
        self.window = self.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: u16 = 1200;

    fn controller() -> LossTolerant {
        LossTolerant::new(Arc::new(LossTolerantConfig::default()), MTU)
    }

    // `RttEstimator` has no public constructor, so acks enter through `grow`,
    // the whole of what `on_ack` does.
    fn ack(cc: &mut LossTolerant, bytes: u64, app_limited: bool) {
        cc.grow(bytes, app_limited);
    }

    fn congestion(cc: &mut LossTolerant, persistent: bool, ecn: bool) {
        let now = Instant::now();
        cc.on_congestion_event(now, now, persistent, ecn, 1200, 0);
    }

    #[test]
    fn cubic_keeps_the_noq_default() {
        assert!(controller_factory(QuicCongestion::Cubic).is_none());
        assert!(controller_factory(QuicCongestion::LossTolerant).is_some());
    }

    #[test]
    fn ordinary_loss_leaves_the_window_alone() {
        let mut cc = controller();
        ack(&mut cc, 100_000, false);
        let before = cc.window();
        congestion(&mut cc, false, false);
        assert_eq!(cc.window(), before);
    }

    #[test]
    fn window_grows_on_acks_up_to_the_ceiling() {
        let mut cc = controller();
        ack(&mut cc, 1_000, false);
        assert_eq!(cc.window(), INITIAL_WINDOW + 1_000);
        ack(&mut cc, u64::MAX, false);
        assert_eq!(cc.window(), MAX_WINDOW);
    }

    #[test]
    fn app_limited_acks_do_not_grow_the_window() {
        let mut cc = controller();
        ack(&mut cc, 1_000_000, true);
        assert_eq!(cc.window(), INITIAL_WINDOW);
    }

    #[test]
    fn ecn_halves_and_persistent_congestion_resets() {
        let mut cc = controller();
        ack(&mut cc, 1_000_000, false);
        let grown = cc.window();
        congestion(&mut cc, false, true);
        assert_eq!(cc.window(), grown / 2);
        congestion(&mut cc, true, false);
        assert_eq!(cc.window(), 2 * u64::from(MTU));
    }

    #[test]
    fn mtu_growth_raises_the_floor() {
        let mut cc = controller();
        congestion(&mut cc, true, false);
        cc.on_mtu_update(9000);
        assert_eq!(cc.window(), 18_000);
    }
}
