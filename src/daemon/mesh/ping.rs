//! One ping probe observes its own connection and selected-path window. This
//! never claims that a selected path is the actual route of a Ping/Pong packet.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::{FutureExt, StreamExt};
use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathEvent, WeakConnectionHandle};
use tokio::sync::oneshot;

use crate::control::{self, ControlMsg};
use crate::ipc::{ConnType, PingProbeDetails, PingProbeOutcome, PingSelectedPath};

const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
type PendingPongs = Arc<DashMap<u64, oneshot::Sender<()>>>;

/// Cancellation must not leave a nonce registered forever.
struct PendingProbe {
    nonce: u64,
    pending: PendingPongs,
}

impl Drop for PendingProbe {
    fn drop(&mut self) {
        self.pending.remove(&self.nonce);
    }
}

fn path_snapshot(addr: &TransportAddr) -> PingSelectedPath {
    PingSelectedPath {
        conn_type: match addr {
            TransportAddr::Ip(_) => ConnType::Direct,
            TransportAddr::Relay(_) => ConnType::Relay,
            TransportAddr::Custom(_) => ConnType::Tor,
            _ => ConnType::Unknown,
        },
        remote_addr: addr.to_string(),
    }
}

fn selected_path(conn: &Connection) -> Option<PingSelectedPath> {
    conn.paths()
        .iter()
        .find(|path| path.is_selected())
        .map(|path| path_snapshot(path.remote_addr()))
}

#[derive(Default)]
struct PathObservation {
    selection_changed: bool,
    incomplete: bool,
}

impl PathObservation {
    fn changed_since(
        &self,
        before: &Option<PingSelectedPath>,
        after: &Option<PingSelectedPath>,
    ) -> bool {
        self.selection_changed || before != after
    }

    fn selected(&mut self) {
        // An event still matters when its remote address equals the initial
        // snapshot (a switch away and back, or another path to the same peer).
        self.selection_changed = true;
    }

    fn observe(&mut self, event: PathEvent) {
        match event {
            PathEvent::Selected { .. } => self.selected(),
            PathEvent::Lagged { .. } => self.incomplete = true,
            _ => {}
        }
    }
}

async fn probe_connection(
    conn: &Connection,
    pending: &PendingPongs,
) -> (Option<f64>, PingProbeDetails) {
    // Subscribe before taking the first snapshot so a mid-probe switch cannot
    // disappear merely because the final selected address matches the first.
    let mut events = conn.path_events();
    let before = selected_path(conn);
    let mut observation = PathObservation::default();
    let nonce = rand::random();
    let (tx, rx) = oneshot::channel();
    pending.insert(nonce, tx);
    let _slot = PendingProbe {
        nonce,
        pending: Arc::clone(pending),
    };
    let sent = Instant::now();
    let exchange = tokio::time::timeout(PROBE_TIMEOUT, async {
        let (mut send, _) = conn
            .open_bi()
            .await
            .map_err(|_| PingProbeOutcome::SendFailed)?;
        control::send_msg(&mut send, None, &ControlMsg::Ping { nonce })
            .await
            .map_err(|_| PingProbeOutcome::SendFailed)?;
        rx.await.map_err(|_| PingProbeOutcome::ReplyWaitFailed)
    });
    tokio::pin!(exchange);
    let mut events_open = true;
    let result = loop {
        tokio::select! {
            result = &mut exchange => break result,
            event = events.next(), if events_open => match event {
                Some(event) => observation.observe(event),
                None => events_open = false,
            },
        }
    };
    let elapsed = sent.elapsed();
    // A Pong and a path event may become ready together. Include events already
    // queued at completion, with a bound against an endlessly busy publisher.
    for index in 0..32 {
        match events.next().now_or_never() {
            Some(Some(event)) => observation.observe(event),
            _ => break,
        }
        if index == 31 {
            observation.incomplete = true;
        }
    }
    let after = selected_path(conn);
    let (rtt, outcome) = match result {
        Ok(Ok(())) => (
            Some(elapsed.as_secs_f64() * 1000.0),
            PingProbeOutcome::Reply,
        ),
        _ if conn.close_reason().is_some() => (None, PingProbeOutcome::ConnectionClosed),
        Ok(Err(outcome)) => (None, outcome),
        Err(_) => (None, PingProbeOutcome::Timeout),
    };
    let selection_changed = observation.changed_since(&before, &after);
    (
        rtt,
        PingProbeDetails {
            outcome,
            selected_path_before: before,
            selected_path_after: after,
            selection_changed,
            path_history_incomplete: observation.incomplete,
            connection_changed: false,
        },
    )
}

pub(super) struct PingRun {
    pub probes: Vec<Option<f64>>,
    pub details: Vec<PingProbeDetails>,
}

/// Compare against the previous live connection without keeping it alive.
/// A stale `stable_id()` alone is insufficient: allocators can reuse the
/// address after the previous connection has been dropped.
fn connection_replaced(previous: Option<&WeakConnectionHandle>, current: &Connection) -> bool {
    previous.is_some_and(|weak| match weak.upgrade() {
        Some(old) => old.stable_id() != current.stable_id(),
        None => true,
    })
}

pub(super) async fn run_probes(
    count: u32,
    interval_ms: u64,
    pending: &PendingPongs,
    mut current_connection: impl FnMut() -> Option<Connection>,
) -> PingRun {
    let count = count.clamp(1, 100);
    let mut run = PingRun {
        probes: Vec::with_capacity(count as usize),
        details: Vec::with_capacity(count as usize),
    };
    // Track the previous handle weakly, so a retired connection can be freed.
    // Keep this across missing routes to detect the next replacement.
    let mut previous_connection: Option<WeakConnectionHandle> = None;
    for seq in 0..count {
        if seq > 0 {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
        // Re-read the live route for every probe. A background reconnect must
        // not leave the rest of this run probing a retired connection handle.
        let Some(conn) = current_connection() else {
            run.probes.push(None);
            run.details.push(PingProbeDetails {
                outcome: PingProbeOutcome::NoConnection,
                selected_path_before: None,
                selected_path_after: None,
                selection_changed: false,
                path_history_incomplete: false,
                connection_changed: false,
            });
            continue;
        };
        let connection_changed = connection_replaced(previous_connection.as_ref(), &conn);
        previous_connection = Some(conn.weak_handle());
        let (rtt, mut detail) = probe_connection(&conn, pending).await;
        detail.connection_changed = connection_changed;
        run.probes.push(rtt);
        run.details.push(detail);
    }
    run
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{
        Endpoint,
        endpoint::{QuicTransportConfig, presets},
    };

    const ALPN: &[u8] = b"rayfish-ping-test";

    async fn connection_pair(block_streams: bool) -> (Endpoint, Endpoint, Connection, Connection) {
        let mut server = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]);
        if block_streams {
            server = server.transport_config(
                QuicTransportConfig::builder()
                    .max_concurrent_bidi_streams(0u32.into())
                    .build(),
            );
        }
        let server = server
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let (local, remote) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client.connect(server.addr(), ALPN), async {
                server.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        (client, server, local.unwrap(), remote.unwrap())
    }

    async fn received_ping(conn: &Connection) -> u64 {
        let (_, mut recv) = conn.accept_bi().await.unwrap();
        let ControlMsg::Ping { nonce } = control::recv_msg(&mut recv).await.unwrap() else {
            panic!("expected ping");
        };
        nonce
    }

    async fn reply_once(remote: Connection, local: Connection, pending: PendingPongs) {
        let nonce = received_ping(&remote).await;
        let (mut send, _) = remote.open_bi().await.unwrap();
        control::send_msg(&mut send, None, &ControlMsg::Pong { nonce })
            .await
            .unwrap();
        // Drive the same Pong/nonce dispatch as the mesh connection reader,
        // after a real reliable-stream round trip on loopback QUIC.
        let (_, mut recv) = local.accept_bi().await.unwrap();
        let ControlMsg::Pong { nonce: reply } = control::recv_msg(&mut recv).await.unwrap() else {
            panic!("expected pong");
        };
        assert_eq!(reply, nonce);
        pending.remove(&reply).unwrap().1.send(()).unwrap();
    }

    #[tokio::test]
    async fn ping_refreshes_connection_between_probes_and_reports_missing_routes() {
        let (client_a, server_a, old, _) = connection_pair(false).await;
        let (client_b, server_b, current, remote) = connection_pair(false).await;
        old.close(0u32.into(), b"retired by background reconnect");
        let pending = PendingPongs::default();
        let reply = tokio::spawn(reply_once(remote, current.clone(), Arc::clone(&pending)));
        let mut routes = [Some(old), None, Some(current.clone())].into_iter();
        let run = run_probes(3, 0, &pending, || routes.next().unwrap()).await;
        assert_eq!(run.probes.len(), 3);
        assert_eq!(run.details[0].outcome, PingProbeOutcome::ConnectionClosed);
        assert_eq!(run.details[1].outcome, PingProbeOutcome::NoConnection);
        assert_eq!(run.details[2].outcome, PingProbeOutcome::Reply);
        assert!(run.probes[2].is_some());
        assert!(run.details[2].connection_changed);
        assert!(routes.next().is_none());
        assert!(pending.is_empty());
        tokio::time::timeout(Duration::from_secs(5), reply)
            .await
            .unwrap()
            .unwrap();
        tokio::join!(
            client_a.close(),
            server_a.close(),
            client_b.close(),
            server_b.close()
        );
    }

    #[tokio::test]
    async fn ping_connection_tracking_detects_expired_and_live_replacements() {
        let (client_a, server_a, old, remote_a) = connection_pair(false).await;
        let (client_b, server_b, replacement, remote_b) = connection_pair(false).await;
        let previous = old.weak_handle();

        // The first probe is not a reconnect; clones are the same connection.
        assert!(!connection_replaced(None, &old));
        assert!(!connection_replaced(Some(&previous), &old));
        assert!(!connection_replaced(Some(&previous), &old.clone()));
        // Different simultaneously live connections must be distinguished.
        assert!(connection_replaced(Some(&previous), &replacement));

        // Dropping one application handle is not sufficient: the QUIC
        // endpoint may still hold the connection while it is shutting down.
        old.close(0u32.into(), b"retired");
        drop(old);
        drop(remote_a);
        tokio::join!(client_a.close(), server_a.close());
        drop(client_a);
        drop(server_a);
        tokio::time::timeout(Duration::from_secs(5), async {
            while previous.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retired connection should eventually release its strong handles");

        // An expired weak handle proves replacement even if a later
        // connection eventually reuses the same stable_id allocation.
        assert!(connection_replaced(Some(&previous), &replacement));

        drop(replacement);
        drop(remote_b);
        tokio::join!(client_b.close(), server_b.close());
    }

    #[tokio::test]
    async fn ping_timeout_includes_waiting_for_stream_capacity() {
        let (client, server, local, _remote) = connection_pair(true).await;
        let pending = PendingPongs::default();
        tokio::time::pause();
        let probe = tokio::spawn({
            let pending = Arc::clone(&pending);
            async move { probe_connection(&local, &pending).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(pending.len(), 1);
        tokio::time::advance(PROBE_TIMEOUT + Duration::from_millis(1)).await;
        let (rtt, detail) = probe.await.unwrap();
        assert!(rtt.is_none());
        assert_eq!(detail.outcome, PingProbeOutcome::Timeout);
        assert!(pending.is_empty());
        tokio::join!(client.close(), server.close());
    }

    #[tokio::test]
    async fn ping_cancellation_removes_the_pending_nonce() {
        let (client, server, local, remote) = connection_pair(false).await;
        let pending = PendingPongs::default();
        let probe = tokio::spawn({
            let pending = Arc::clone(&pending);
            async move { probe_connection(&local, &pending).await }
        });
        let nonce = tokio::time::timeout(Duration::from_secs(5), received_ping(&remote))
            .await
            .unwrap();
        assert!(pending.contains_key(&nonce));
        probe.abort();
        assert!(probe.await.unwrap_err().is_cancelled());
        assert!(pending.is_empty());
        tokio::join!(client.close(), server.close());
    }

    #[tokio::test]
    async fn ping_reports_an_interrupted_reply_wait_separately_from_a_send_failure() {
        let (client, server, local, remote) = connection_pair(false).await;
        let pending = PendingPongs::default();
        let probe = tokio::spawn({
            let pending = Arc::clone(&pending);
            async move { probe_connection(&local, &pending).await }
        });
        let nonce = tokio::time::timeout(Duration::from_secs(5), received_ping(&remote))
            .await
            .unwrap();
        // The peer already received Ping, so losing its reply waiter cannot
        // honestly be described as a failure to send that Ping.
        drop(pending.remove(&nonce).unwrap());
        let (rtt, detail) = probe.await.unwrap();
        assert!(rtt.is_none());
        assert_eq!(detail.outcome, PingProbeOutcome::ReplyWaitFailed);
        assert!(pending.is_empty());
        tokio::join!(client.close(), server.close());
    }

    #[test]
    fn ping_detects_a_selection_change_even_when_it_returns_to_the_same_address() {
        let path = Some(path_snapshot(&TransportAddr::Ip(
            "192.0.2.1:41383".parse().unwrap(),
        )));
        let mut observation = PathObservation::default();
        assert!(!observation.changed_since(&path, &path));
        observation.selected(); // Direct -> Relay
        observation.selected(); // Relay -> same Direct address
        assert!(observation.changed_since(&path, &path));
        assert!(PathObservation::default().changed_since(&path, &None));
    }
}
