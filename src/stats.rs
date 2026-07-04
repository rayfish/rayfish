//! Packet and byte counters using iroh-metrics with Prometheus-compatible export.
//!
//! Replaces hand-rolled atomics with `iroh_metrics::Counter` and labeled drop
//! counters via `Family<DropLabels, Counter>`. A background logger prints
//! 30-second interval deltas and a session summary on shutdown.

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh_metrics::{Counter, EncodeLabelSet, EncodeLabelValue, Family, Gauge, MetricsGroup};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::peers::PeerTable;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, EncodeLabelValue)]
pub enum DropReason {
    Firewall,
    SendFailure,
    NoPeer,
    Malformed,
    /// Outbound packet dropped at the application boundary because the peer's
    /// QUIC datagram send buffer was too full to accept it without evicting an
    /// already-queued (older) packet. Dropping the *new* packet here (drop-newest)
    /// is preferable to letting QUIC drop the *oldest* queued one — for a VPN the
    /// oldest queued packet is more likely to be useful (already-accepted work)
    /// than a fresh one arriving into a saturated link.
    Backpressure,
    /// Inbound datagram whose source IP did not match the sending peer's
    /// assigned mesh address (ingress anti-spoofing). A peer may only inject
    /// packets sourced from its own mesh IP.
    Spoof,
}

impl DropReason {
    const ALL: [DropReason; 6] = [
        DropReason::Firewall,
        DropReason::SendFailure,
        DropReason::NoPeer,
        DropReason::Malformed,
        DropReason::Backpressure,
        DropReason::Spoof,
    ];
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, EncodeLabelSet)]
pub struct DropLabels {
    pub reason: DropReason,
}

/// A point-in-time copy of the forwarding counters, suitable for diagnostics
/// bundles. Serializable so it can be rendered or embedded as needed.
#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    /// `(reason, count)` for each drop reason, in `DropReason::ALL` order.
    pub drops: Vec<(String, u64)>,
    pub uptime_secs: u64,
}

#[derive(Debug, MetricsGroup)]
#[metrics(name = "rayfish", default)]
pub struct ForwardMetrics {
    /// Total packets received from peers
    pub packets_rx: Counter,
    /// Total packets sent to peers
    pub packets_tx: Counter,
    /// Total bytes received from peers
    pub bytes_rx: Counter,
    /// Total bytes sent to peers
    pub bytes_tx: Counter,
    /// Dropped packets by reason
    pub drops: Family<DropLabels, Counter>,
    /// REJECT replies sent (TCP RST / ICMP unreachable) when fail-fast mode is on
    pub rejects_sent: Counter,
}

impl ForwardMetrics {
    pub fn record_rx(&self, bytes: usize) {
        self.packets_rx.inc();
        self.bytes_rx.inc_by(bytes as u64);
    }

    pub fn record_tx(&self, bytes: usize) {
        self.packets_tx.inc();
        self.bytes_tx.inc_by(bytes as u64);
    }

    pub fn record_drop(&self, reason: DropReason) {
        self.drops.get_or_create(&DropLabels { reason }).inc();
    }

    pub fn record_reject(&self) {
        self.rejects_sent.inc();
    }

    fn drop_count(&self, reason: DropReason) -> u64 {
        self.drops
            .get(&DropLabels { reason })
            .map(|c| c.get())
            .unwrap_or(0)
    }

    fn total_drops(&self) -> u64 {
        DropReason::ALL.iter().map(|r| self.drop_count(*r)).sum()
    }

    /// Read the current counters into a serializable snapshot for diagnostics
    /// (`ray report`) and ad-hoc inspection. `start` is the daemon start time,
    /// used to compute uptime.
    pub fn snapshot(&self, start: Instant) -> MetricsSnapshot {
        let drops = DropReason::ALL
            .iter()
            .map(|r| (format!("{r:?}"), self.drop_count(*r)))
            .collect();
        MetricsSnapshot {
            packets_rx: self.packets_rx.get(),
            packets_tx: self.packets_tx.get(),
            bytes_rx: self.bytes_rx.get(),
            bytes_tx: self.bytes_tx.get(),
            drops,
            uptime_secs: start.elapsed().as_secs(),
        }
    }

    pub fn spawn_logger(self: &Arc<Self>, token: CancellationToken) {
        let stats = self.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            let mut prev_rx = 0u64;
            let mut prev_tx = 0u64;
            let mut prev_bytes_rx = 0u64;
            let mut prev_bytes_tx = 0u64;
            let mut prev_drops = 0u64;

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        let rx = stats.packets_rx.get();
                        let tx = stats.packets_tx.get();
                        let brx = stats.bytes_rx.get();
                        let btx = stats.bytes_tx.get();
                        let drops = stats.total_drops();

                        tracing::info!(
                            rx = rx - prev_rx,
                            tx = tx - prev_tx,
                            bytes_rx = brx - prev_bytes_rx,
                            bytes_tx = btx - prev_bytes_tx,
                            drops = drops - prev_drops,
                            "(30s)"
                        );

                        prev_rx = rx;
                        prev_tx = tx;
                        prev_bytes_rx = brx;
                        prev_bytes_tx = btx;
                        prev_drops = drops;
                    }
                    _ = token.cancelled() => {
                        let duration = start.elapsed();
                        let mins = duration.as_secs() / 60;
                        let secs = duration.as_secs() % 60;
                        let total_bytes = stats.bytes_rx.get() + stats.bytes_tx.get();

                        tracing::info!(
                            duration = format!("{}m{}s", mins, secs),
                            total_rx = stats.packets_rx.get(),
                            total_tx = stats.packets_tx.get(),
                            total_bytes,
                            "session complete"
                        );
                        return;
                    }
                }
            }
        });
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, EncodeLabelSet)]
pub struct PeerLabels {
    pub peer: String,
}

#[derive(Debug, MetricsGroup)]
#[metrics(name = "rayfish_peer", default)]
pub struct PeerMetrics {
    /// RTT to peer in microseconds
    pub rtt_us: Family<PeerLabels, Gauge>,
    /// Bytes sent to peer (from iroh connection stats)
    pub bytes_tx: Family<PeerLabels, Gauge>,
    /// Bytes received from peer (from iroh connection stats)
    pub bytes_rx: Family<PeerLabels, Gauge>,
    /// Packets lost to peer
    pub lost_packets: Family<PeerLabels, Gauge>,
}

impl PeerMetrics {
    pub fn spawn_collector(self: &Arc<Self>, peers: PeerTable, token: CancellationToken) {
        let metrics = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        for (ip, conn) in peers.all_connections() {
                            let label = PeerLabels {
                                peer: ip.to_string(),
                            };

                            let paths = conn.paths();
                            if let Some(path) = paths.iter().find(|p| p.is_selected()) {
                                let rtt_us = path.rtt().as_micros() as i64;
                                metrics.rtt_us.get_or_create(&label).set(rtt_us);
                            }

                            let stats = conn.stats();
                            metrics.bytes_tx.get_or_create(&label).set(stats.udp_tx.bytes as i64);
                            metrics.bytes_rx.get_or_create(&label).set(stats.udp_rx.bytes as i64);
                            metrics.lost_packets.get_or_create(&label).set(stats.lost_packets as i64);
                        }
                    }
                    _ = token.cancelled() => return,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_rx() {
        let stats = ForwardMetrics::default();
        stats.record_rx(100);
        stats.record_rx(200);
        assert_eq!(stats.packets_rx.get(), 2);
        assert_eq!(stats.bytes_rx.get(), 300);
    }

    #[test]
    fn test_record_tx() {
        let stats = ForwardMetrics::default();
        stats.record_tx(500);
        assert_eq!(stats.packets_tx.get(), 1);
        assert_eq!(stats.bytes_tx.get(), 500);
    }

    #[test]
    fn test_record_drop() {
        let stats = ForwardMetrics::default();
        stats.record_drop(DropReason::Firewall);
        stats.record_drop(DropReason::NoPeer);
        stats.record_drop(DropReason::Firewall);
        assert_eq!(
            stats
                .drops
                .get(&DropLabels {
                    reason: DropReason::Firewall
                })
                .unwrap()
                .get(),
            2
        );
        assert_eq!(
            stats
                .drops
                .get(&DropLabels {
                    reason: DropReason::NoPeer
                })
                .unwrap()
                .get(),
            1
        );
        assert_eq!(stats.total_drops(), 3);
    }

    #[test]
    fn test_snapshot() {
        let stats = ForwardMetrics::default();
        stats.record_rx(100);
        stats.record_tx(50);
        stats.record_drop(DropReason::NoPeer);

        let snap = stats.snapshot(Instant::now());
        assert_eq!(snap.packets_rx, 1);
        assert_eq!(snap.bytes_rx, 100);
        assert_eq!(snap.packets_tx, 1);
        assert_eq!(snap.bytes_tx, 50);
        // One entry per drop reason, in DropReason::ALL order.
        assert_eq!(snap.drops.len(), DropReason::ALL.len());
        let no_peer = snap
            .drops
            .iter()
            .find(|(r, _)| r == "NoPeer")
            .map(|(_, c)| *c);
        assert_eq!(no_peer, Some(1));
    }
}
