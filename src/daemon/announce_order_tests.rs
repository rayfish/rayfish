use super::*;
use iroh::RelayMode;
use iroh::endpoint::presets;
use std::sync::mpsc as std_mpsc;

async fn mesh_endpoint() -> Endpoint {
    Endpoint::builder(presets::N0)
        .alpns(vec![transport::mesh_alpn()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("bind a loopback endpoint")
}

fn network_key(name: &str) -> Option<EndpointId> {
    Some(SecretKey::from_bytes(&[name.as_bytes()[0]; 32]).public())
}

/// Two announces race: the first stalls after taking its snapshot, and the
/// second, taken after another network was shared, must still reach the
/// peer last. The peer keeps the last table it accepts, so the other order
/// would leave it unable to decode the new network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_snapshot_is_announced_last() {
    let client = mesh_endpoint().await;
    let server = mesh_endpoint().await;
    let alpn = transport::mesh_alpn();
    let (conn, accepted) = tokio::join!(client.connect(server.addr(), &alpn), async {
        server
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("accept")
    });
    let conn = conn.expect("dial");
    let peer_ip = derive_ipv6(&server.id());
    let peers = PeerTable::new();
    peers.add(peer_ip, conn.clone(), server.id(), "a");

    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel::<()>();
    let (release_tx, release_rx) = std_mpsc::channel::<()>();
    let first = tokio::spawn({
        let peers = peers.clone();
        let conn = conn.clone();
        async move {
            announce_handles_with(&peers, &conn, peer_ip, move |name| {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
                network_key(name)
            })
            .await;
        }
    });
    entered_rx
        .recv()
        .await
        .expect("the first announce resolves");
    peers.attach_network(&peer_ip, "b");
    let second = tokio::spawn({
        let peers = peers.clone();
        let conn = conn.clone();
        async move { announce_handles_with(&peers, &conn, peer_ip, network_key).await }
    });
    // Give the second announce the chance to overtake, then let the first go.
    tokio::time::sleep(Duration::from_millis(200)).await;
    release_tx.send(()).expect("the first announce is waiting");
    first.await.expect("first announce");
    second.await.expect("second announce");

    let mut tables = Vec::new();
    for _ in 0..2 {
        let (_send, mut recv) = tokio::time::timeout(Duration::from_secs(2), accepted.accept_bi())
            .await
            .expect("an announcement arrives")
            .expect("accept stream");
        match control::recv_frame(&mut recv).await.expect("read frame") {
            control::FrameRead::Frame(frame) => match frame.msg {
                ControlMsg::NetworkHandles { entries, .. } => tables.push(entries.len()),
                _ => panic!("expected NetworkHandles"),
            },
            control::FrameRead::Unknown { .. } => panic!("unknown frame"),
        }
    }
    assert_eq!(tables, vec![1, 2], "the newer snapshot must arrive last");
    client.close().await;
    server.close().await;
}
