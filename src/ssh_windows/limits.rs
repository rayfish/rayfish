//! Session task limits include process creation and cleanup after channel close.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

#[derive(Clone)]
pub(super) struct SshLimits {
    pub logons: Arc<Semaphore>,
    pub sessions: Arc<Semaphore>,
}

impl Default for SshLimits {
    fn default() -> Self {
        Self {
            logons: Arc::new(Semaphore::new(super::MAX_LOGONS)),
            sessions: Arc::new(Semaphore::new(64)),
        }
    }
}

pub(super) struct SessionTasks {
    global: Arc<Semaphore>,
    connection: Arc<Semaphore>,
}

impl SessionTasks {
    pub fn new(global: Arc<Semaphore>, connection: usize) -> Self {
        Self {
            global,
            connection: Arc::new(Semaphore::new(connection)),
        }
    }

    pub fn spawn<F>(&self, tracker: &TaskTracker, make: impl FnOnce() -> Option<F>) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Ok(global) = Arc::clone(&self.global).try_acquire_owned() else {
            return false;
        };
        let Ok(connection) = Arc::clone(&self.connection).try_acquire_owned() else {
            return false;
        };
        let Some(task) = make() else { return false };
        tracker.spawn(async move {
            let (_global, _connection) = (global, connection);
            task.await;
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test]
    async fn closing_channels_does_not_free_sessions_that_are_still_cleaning_up() {
        let global = Arc::new(Semaphore::new(1));
        let tasks = SessionTasks::new(Arc::clone(&global), 1);
        let other_connection = SessionTasks::new(global, 1);
        let tracker = TaskTracker::new();
        let cancel = CancellationToken::new();
        let closed = cancel.clone();
        let (started, running) = oneshot::channel();
        let (cleaning, cleanup_started) = oneshot::channel();
        let (finish, cleaned) = oneshot::channel();
        assert!(tasks.spawn(&tracker, || Some(async move {
            started.send(()).unwrap();
            closed.cancelled().await;
            cleaning.send(()).unwrap();
            cleaned.await.unwrap();
        })));
        running.await.unwrap();
        cancel.cancel();
        cleanup_started.await.unwrap();
        for candidate in [&tasks, &other_connection] {
            assert!(
                !candidate.spawn(&tracker, || -> Option<std::future::Ready<()>> {
                    panic!("a closed channel's process is still cleaning up");
                })
            );
        }
        finish.send(()).unwrap();
        tracker.close();
        tracker.wait().await;
        assert!(other_connection.spawn(&tracker, || Some(async {})));
        tracker.wait().await;
    }
}
