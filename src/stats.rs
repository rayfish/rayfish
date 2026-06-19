use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio_util::sync::CancellationToken;

pub struct Stats {
    packets_rx: AtomicU64,
    packets_tx: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    drops: AtomicU64,
    start_time: Instant,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            packets_rx: AtomicU64::new(0),
            packets_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            start_time: Instant::now(),
        })
    }

    pub fn record_rx(&self, bytes: usize) {
        self.packets_rx.fetch_add(1, Ordering::Relaxed);
        self.bytes_rx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_tx(&self, bytes: usize) {
        self.packets_tx.fetch_add(1, Ordering::Relaxed);
        self.bytes_tx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn spawn_logger(self: &Arc<Self>, token: CancellationToken) {
        let stats = self.clone();
        tokio::spawn(async move {
            let mut prev_rx = 0u64;
            let mut prev_tx = 0u64;
            let mut prev_bytes_rx = 0u64;
            let mut prev_bytes_tx = 0u64;

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        let rx = stats.packets_rx.load(Ordering::Relaxed);
                        let tx = stats.packets_tx.load(Ordering::Relaxed);
                        let brx = stats.bytes_rx.load(Ordering::Relaxed);
                        let btx = stats.bytes_tx.load(Ordering::Relaxed);
                        let drops = stats.drops.load(Ordering::Relaxed);

                        tracing::info!(
                            rx = rx - prev_rx,
                            tx = tx - prev_tx,
                            bytes_rx = format_bytes(brx - prev_bytes_rx),
                            bytes_tx = format_bytes(btx - prev_bytes_tx),
                            drops,
                            "(30s)"
                        );

                        prev_rx = rx;
                        prev_tx = tx;
                        prev_bytes_rx = brx;
                        prev_bytes_tx = btx;
                    }
                    _ = token.cancelled() => {
                        stats.log_summary();
                        return;
                    }
                }
            }
        });
    }

    fn log_summary(&self) {
        let duration = self.start_time.elapsed();
        let mins = duration.as_secs() / 60;
        let secs = duration.as_secs() % 60;

        let total_bytes = self.bytes_rx.load(Ordering::Relaxed)
            + self.bytes_tx.load(Ordering::Relaxed);

        tracing::info!(
            duration = format!("{}m{}s", mins, secs),
            total_rx = self.packets_rx.load(Ordering::Relaxed),
            total_tx = self.packets_tx.load(Ordering::Relaxed),
            total_bytes = format_bytes(total_bytes),
            "session complete"
        );
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_rx() {
        let stats = Stats::new();
        stats.record_rx(100);
        stats.record_rx(200);
        assert_eq!(stats.packets_rx.load(Ordering::Relaxed), 2);
        assert_eq!(stats.bytes_rx.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn test_record_tx() {
        let stats = Stats::new();
        stats.record_tx(500);
        assert_eq!(stats.packets_tx.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_tx.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn test_record_drop() {
        let stats = Stats::new();
        stats.record_drop();
        stats.record_drop();
        assert_eq!(stats.drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(87244), "85.2KB");
        assert_eq!(format_bytes(1_153_434), "1.1MB");
    }
}
