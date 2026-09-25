//! Coalesced file-state invalidations for embedders. No idle polling timer and
//! no queue of per-packet progress events; consumers reconcile current state.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[uniffi::export(callback_interface)]
pub trait FileChangeListener: Send + Sync {
    /// Enqueue a reconciliation on a platform worker; never block this callback.
    fn on_change(&self);
}

/// Dropping or closing the subscription stops delivery. It owns no daemon
/// reference, so a forgotten subscription cannot keep the node alive.
#[derive(uniffi::Object)]
pub struct FileWatch {
    task: Mutex<Option<JoinHandle<()>>>,
}

impl FileWatch {
    pub(crate) fn start(
        runtime: &tokio::runtime::Runtime,
        changes: watch::Receiver<()>,
        listener: Box<dyn FileChangeListener>,
    ) -> Arc<Self> {
        Arc::new(Self {
            task: Mutex::new(Some(runtime.spawn(deliver(changes, listener)))),
        })
    }
}

#[uniffi::export]
impl FileWatch {
    /// Idempotent. A callback already executing can finish; the platform must
    /// also discard queued work after closing its observer.
    pub fn cancel(&self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

impl Drop for FileWatch {
    fn drop(&mut self) {
        self.cancel();
    }
}

async fn deliver(mut changes: watch::Receiver<()>, listener: Box<dyn FileChangeListener>) {
    changes.borrow_and_update();
    listener.on_change(); // Reconcile offers that predate subscription.
    while changes.changed().await.is_ok() {
        // Only armed by a change. Collapse progress bursts, including changes
        // during the delay, without postponing delivery indefinitely.
        tokio::time::sleep(Duration::from_millis(250)).await;
        changes.borrow_and_update();
        listener.on_change();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Listener(tokio::sync::mpsc::UnboundedSender<()>);
    impl FileChangeListener for Listener {
        fn on_change(&self) {
            self.0.send(()).unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_discards_pending_delivery_and_is_idempotent() {
        let (tx, rx) = watch::channel(());
        let (calls, mut received) = tokio::sync::mpsc::unbounded_channel();
        let watch = FileWatch {
            task: Mutex::new(Some(tokio::spawn(deliver(rx, Box::new(Listener(calls)))))),
        };
        received.recv().await.unwrap();
        tx.send_replace(());
        tokio::task::yield_now().await;
        watch.cancel();
        watch.cancel();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(received.recv().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn delivers_initial_state_coalesces_bursts_and_stays_idle() {
        let (tx, rx) = watch::channel(());
        let (calls, mut received) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(deliver(rx, Box::new(Listener(calls))));
        received.recv().await.unwrap();
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(received.try_recv().is_err(), "idle must not poll");
        for _ in 0..100 {
            tx.send_replace(());
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(250)).await;
        received.recv().await.unwrap();
        assert!(received.try_recv().is_err());
        tx.send_replace(());
        received.recv().await.unwrap();
        drop(tx);
        task.await.unwrap();
        assert!(received.recv().await.is_none());
    }
}
