#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_reply_connect_rejection_is_terminal_on_next_poll() {
    for block in [false, true] {
        let env = TestConfigDir::new();
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let receiver = loopback_endpoint(iroh::address_lookup::memory::MemoryLookup::new()).await;
        let requester = loopback_endpoint(lookup.clone()).await;
        lookup.add_endpoint_info(receiver.addr());
        let registry = registry_on(&receiver, &env.dir.path().join("blobs")).await;
        let service = Arc::new(ConnectService::new(registry));
        service.pending_connects.insert(
            requester.id(),
            connect_service::PendingConnect {
                from_endpoint: requester.id(),
                hostname: Some("tablet".into()),
                requested_at: Instant::now(),
                stranger: true,
            },
        );
        let answer = if block {
            service.deny_connection("tablet").await
        } else {
            service.reject_connection("tablet")
        };
        assert!(matches!(answer, IpcMessage::Ok { .. }), "{answer:?}");
        let server = tokio::spawn({
            let service = Arc::clone(&service);
            let receiver = receiver.clone();
            async move {
                let conn = receiver.accept().await.unwrap().await.unwrap();
                service.accept_connect_request(conn).await;
            }
        });
        let conn = transport::connect_to_peer_with_alpn(
            &requester,
            receiver.id(),
            transport::CONNECT_ALPN,
        )
        .await
        .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        // A refusal can close its receive stream before the requester writes.
        let _sent = control::send_framed(
            &mut send,
            &control::ConnectMsg::Request {
                from_identity: requester.id(),
                from_endpoint: requester.id(),
                hostname: Some("tablet".into()),
            },
        )
        .await;
        let reply = control::recv_framed::<control::ConnectMsg>(&mut recv)
            .await
            .unwrap();
        assert!(
            matches!(reply, control::ConnectMsg::Denied { .. }),
            "{reply:?}"
        );
        recv.read_to_end(0).await.unwrap();
        server.await.unwrap();
        conn.close(0u32.into(), b"done");
        assert!(service.pending_connects.is_empty());
        if !block {
            let next_server = tokio::spawn({
                let service = Arc::clone(&service);
                let receiver = receiver.clone();
                async move {
                    let conn = receiver.accept().await.unwrap().await.unwrap();
                    service.accept_connect_request(conn).await;
                }
            });
            let conn = transport::connect_to_peer_with_alpn(
                &requester,
                receiver.id(),
                transport::CONNECT_ALPN,
            )
            .await
            .unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            control::send_framed(
                &mut send,
                &control::ConnectMsg::Request {
                    from_identity: requester.id(),
                    from_endpoint: requester.id(),
                    hostname: Some("tablet".into()),
                },
            )
            .await
            .unwrap();
            let reply = control::recv_framed::<control::ConnectMsg>(&mut recv)
                .await
                .unwrap();
            assert_eq!(reply, control::ConnectMsg::Pending);
            conn.close(0u32.into(), b"done");
            next_server.await.unwrap();
        }
        requester.close().await;
        receiver.close().await;
    }
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_reply_declined_delivery_is_recorded_and_stops_polling() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let (sender, service, _) = delivering_service(env.dir.path(), lookup.clone()).await;
    let (receiver, inbox) = receiving_service(env.dir.path()).await;
    lookup.add_endpoint_info(receiver.addr());
    let server = tokio::spawn({
        let receiver = receiver.clone();
        let inbox = Arc::clone(&inbox);
        async move {
            for _ in 0..2 {
                let conn = receiver.accept().await.unwrap().await.unwrap();
                inbox.accept_connect_request(conn).await;
            }
        }
    });
    let first = service.deliver_invite("sample-net", receiver.id()).await;
    assert!(matches!(first, IpcMessage::Ok { .. }), "{first:?}");
    let invitations = invitations_of(&inbox).await;
    let declined = inbox.decline_invitation(&invitations[0].id).await;
    assert!(matches!(declined, IpcMessage::Ok { .. }), "{declined:?}");
    service.sweep_deliveries(&CancellationToken::new()).await;
    server.await.unwrap();
    let store = crate::invite::InviteStore::load("sample-net").unwrap();
    assert!(store.deliveries_to_check().is_empty());
    assert!(store.list()[0].status.starts_with("refused:"));
    let retry = service.deliver_invite("sample-net", receiver.id()).await;
    assert!(matches!(retry, IpcMessage::Error { message } if message.contains("refused")));
    sender.close().await;
    receiver.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_reply_invalid_invite_reports_refusal() {
    let env = TestConfigDir::new();
    let lookup = iroh::address_lookup::memory::MemoryLookup::new();
    let requester = loopback_endpoint(lookup.clone()).await;
    let (receiver, inbox) = receiving_service(env.dir.path()).await;
    lookup.add_endpoint_info(receiver.addr());
    let server = tokio::spawn({
        let receiver = receiver.clone();
        async move {
            let conn = receiver.accept().await.unwrap().await.unwrap();
            inbox.accept_connect_request(conn).await;
        }
    });
    let conn =
        transport::connect_to_peer_with_alpn(&requester, receiver.id(), transport::INVITE_ALPN)
            .await
            .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    control::send_framed(
        &mut send,
        &control::ConnectMsg::InviteOffer {
            network: ipc::NetworkName::new("sample-net".into()),
            code: invite_from(SecretKey::generate().public()),
        },
    )
    .await
    .unwrap();
    let reply = control::recv_framed::<control::ConnectMsg>(&mut recv)
        .await
        .unwrap();
    assert!(
        matches!(reply, control::ConnectMsg::Denied { reason } if reason.contains("coordinator"))
    );
    conn.close(0u32.into(), b"done");
    server.await.unwrap();
    requester.close().await;
    receiver.close().await;
}
