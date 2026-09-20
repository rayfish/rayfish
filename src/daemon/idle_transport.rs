//! Android-only idle suspension for the mesh transport.
//!
//! The VPN service, TUN interface, and DNS path remain alive. This task only
//! watches outgoing TUN activity and suspends the iroh transport after a quiet
//! period.

use std::sync::Arc;
use std::sync::atomic;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::NetworkRegistry;

const CHECK: Duration = Duration::from_secs(15);
const IDLE: Duration = Duration::from_secs(120);

pub(crate) fn spawn(
    registry: Arc<NetworkRegistry>,
    shutdown_token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut observed = registry
            .transport
            .activity_seq
            .load(atomic::Ordering::Relaxed);
        let mut unchanged_checks: u64 = 0;

        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => break,
                _ = tokio::time::sleep(CHECK) => {
                    let current = registry
                        .transport
                        .activity_seq
                        .load(atomic::Ordering::Relaxed);
                    if current == observed {
                        unchanged_checks += 1;
                        if unchanged_checks * CHECK.as_secs() >= IDLE.as_secs() {
                            registry.suspend_transport().await;
                        }
                    } else {
                        observed = current;
                        unchanged_checks = 0;
                    }
                }
            }
        }
    })
}
