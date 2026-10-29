//! Retired connections stay ineligible for registration until QUIC is closed.
//! Both stream directions must drain before either peer closes the connection.

use std::sync::Arc;
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use iroh::endpoint::{Connection, VarInt};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_util::task::AbortOnDropHandle;

use super::FastDashMap;
use crate::control::{self, ControlMsg};
use crate::forward::REPLACED_CONNECTION_CODE;

const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
pub(super) struct RetiringConnections {
    connections: Arc<FastDashMap<usize, Retirement>>,
}

struct Retirement {
    inbound_drained: Arc<Notify>,
    // The registry owns the task, and dropping the registry cancels it.
    _task: AbortOnDropHandle<()>,
}

impl RetiringConnections {
    pub(super) fn contains(&self, conn: &Connection) -> bool {
        self.connections.contains_key(&conn.stable_id())
    }

    pub(super) fn retire(&self, conn: &Connection, reason: &'static [u8]) {
        self.start(conn, reason, false);
    }

    pub(super) fn received_close(&self, conn: &Connection) {
        self.start(conn, b"replaced", true);
    }

    fn start(&self, conn: &Connection, reason: &'static [u8], inbound_drained: bool) {
        if conn.close_reason().is_some() {
            return;
        }
        let entry = match self.connections.entry(conn.stable_id()) {
            Entry::Occupied(entry) => {
                if inbound_drained {
                    entry.get().inbound_drained.notify_one();
                }
                return;
            }
            Entry::Vacant(entry) => entry,
        };
        let Ok(runtime) = Handle::try_current() else {
            conn.close(VarInt::from_u32(REPLACED_CONNECTION_CODE), reason);
            return;
        };
        let drained = Arc::new(Notify::new());
        if inbound_drained {
            drained.notify_one();
        }
        let task_drained = Arc::clone(&drained);
        // A weak reference lets the registry cancel its tasks when its owner
        // goes away, without a cycle through the task handles.
        let connections = Arc::downgrade(&self.connections);
        let conn = conn.clone();
        let task = runtime.spawn(async move {
            close_after_drain(&conn, &task_drained, reason).await;
            if let Some(connections) = connections.upgrade() {
                // close_after_drain closes QUIC before releasing the marker, so
                // a queued registration cannot revive this connection.
                connections.remove(&conn.stable_id());
            }
        });
        entry.insert(Retirement {
            inbound_drained: drained,
            _task: AbortOnDropHandle::new(task),
        });
    }
}

async fn close_after_drain(conn: &Connection, inbound_drained: &Notify, reason: &'static [u8]) {
    let exchange = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        control::send_msg(&mut send, None, &ControlMsg::Close).await?;
        anyhow::ensure!(
            matches!(control::recv_msg(&mut recv).await?, ControlMsg::CloseAck),
            "peer did not acknowledge mesh close"
        );
        // The ack only covers our outbound streams. The receive loop signals
        // after handling the peer's Close, which follows its outbound streams.
        inbound_drained.notified().await;
        Ok::<(), anyhow::Error>(())
    };
    let acknowledged = tokio::select! {
        _ = conn.closed() => return,
        result = timeout(CLOSE_TIMEOUT, exchange) => result.is_ok_and(|result| result.is_ok()),
    };
    if !acknowledged {
        tracing::debug!(peer = %conn.remote_id().fmt_short(), "mesh close drain unavailable; closing after timeout or error");
    }
    conn.close(VarInt::from_u32(REPLACED_CONNECTION_CODE), reason);
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::poll;
    use iroh::endpoint::ConnectionError;
    use tokio::pin;
    use tokio::time::{advance, pause};

    use crate::peers::tests::connected_pair;

    #[tokio::test]
    async fn simultaneous_retirement_waits_for_earlier_inbound_streams() {
        let (_server, _client, a, b) = connected_pair().await;
        let (mut earlier_send, _earlier_reply) = b.open_bi().await.unwrap();
        let frame = control::encode_msg(None, &ControlMsg::Ping { nonce: 1 });
        earlier_send.write_all(&frame[..4]).await.unwrap();
        let (_earlier_send, mut earlier_recv) = a.accept_bi().await.unwrap();
        let mut length = [0; 4];
        earlier_recv.read_exact(&mut length).await.unwrap();

        let b_retirement = RetiringConnections::default();
        b_retirement.retire(&b, b"replaced");
        let inbound_drained = Notify::new();
        let retirement = close_after_drain(&a, &inbound_drained, b"replaced");
        pin!(retirement);
        let (mut ack_send, mut close_recv) = tokio::select! {
            _ = &mut retirement => panic!("closed before either direction drained"),
            accepted = b.accept_bi() => accepted.unwrap(),
        };
        assert!(matches!(
            control::recv_msg(&mut close_recv).await.unwrap(),
            ControlMsg::Close
        ));
        b_retirement.received_close(&b);
        control::send_msg(&mut ack_send, None, &ControlMsg::CloseAck)
            .await
            .unwrap();
        // Wait for transport delivery so the next poll can consume the ack.
        ack_send.stopped().await.unwrap();
        assert!(poll!(&mut retirement).is_pending());
        earlier_send.write_all(&frame[4..]).await.unwrap();
        earlier_send.finish().unwrap();
        let mut body = vec![0; frame.len() - 4];
        earlier_recv.read_exact(&mut body).await.unwrap();
        assert_eq!(body, frame[4..]);

        let (_send, mut recv) = a.accept_bi().await.unwrap();
        assert!(matches!(
            control::recv_msg(&mut recv).await.unwrap(),
            ControlMsg::Close
        ));
        inbound_drained.notify_one();
        retirement.await;
        assert!(a.close_reason().is_some());
        let closed = timeout(Duration::from_secs(5), b.closed()).await.unwrap();
        // Either retirement task may finish first once both directions drain.
        match closed {
            ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code, VarInt::from_u32(REPLACED_CONNECTION_CODE));
            }
            ConnectionError::LocallyClosed => {}
            reason => panic!("unexpected retirement outcome: {reason:?}"),
        }
    }

    #[tokio::test]
    async fn inbound_close_waits_for_outbound_ack() {
        let (_server, _client, a, b) = connected_pair().await;
        let inbound_drained = Notify::new();
        // A Close that precedes the wait must not lose its notification.
        inbound_drained.notify_one();
        let retirement = close_after_drain(&a, &inbound_drained, b"replaced");
        pin!(retirement);
        let (mut send, mut recv) = tokio::select! {
            _ = &mut retirement => panic!("closed before outbound acknowledgement"),
            accepted = b.accept_bi() => accepted.unwrap(),
        };
        assert!(matches!(
            control::recv_msg(&mut recv).await.unwrap(),
            ControlMsg::Close
        ));
        assert!(poll!(&mut retirement).is_pending());
        assert!(a.close_reason().is_none());
        control::send_msg(&mut send, None, &ControlMsg::CloseAck)
            .await
            .unwrap();
        retirement.await;
        assert!(a.close_reason().is_some());
    }

    #[tokio::test]
    async fn peer_close_starts_the_reciprocal_drain() {
        let (_server, _client, a, b) = connected_pair().await;
        let retiring = RetiringConnections::default();
        retiring.received_close(&a);
        let (mut send, mut recv) = b.accept_bi().await.unwrap();
        assert!(matches!(
            control::recv_msg(&mut recv).await.unwrap(),
            ControlMsg::Close
        ));
        control::send_msg(&mut send, None, &ControlMsg::CloseAck)
            .await
            .unwrap();
        assert!(matches!(
            timeout(Duration::from_secs(5), b.closed()).await.unwrap(),
            ConnectionError::ApplicationClosed(close)
                if close.error_code == VarInt::from_u32(REPLACED_CONNECTION_CODE)
        ));
    }

    #[tokio::test]
    async fn missing_ack_or_reciprocal_close_times_out() {
        for acknowledge in [false, true] {
            let (_server, _client, a, b) = connected_pair().await;
            let retiring = RetiringConnections::default();
            retiring.retire(&a, b"replaced");
            let (mut send, mut recv) = b.accept_bi().await.unwrap();
            assert!(matches!(
                control::recv_msg(&mut recv).await.unwrap(),
                ControlMsg::Close
            ));
            if acknowledge {
                control::send_msg(&mut send, None, &ControlMsg::CloseAck)
                    .await
                    .unwrap();
                send.stopped().await.unwrap();
            }
            pause();
            advance(CLOSE_TIMEOUT).await;
            assert!(matches!(a.closed().await, ConnectionError::LocallyClosed));
            tokio::time::resume();
        }
    }
}
