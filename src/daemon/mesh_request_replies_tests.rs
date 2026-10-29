async fn mesh_request_reply(
    connection: &Connection,
    network: EndpointId,
    message: &ControlMsg,
) -> ControlMsg {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    control::send_msg(&mut send, Some(network), message)
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), control::recv_msg(&mut recv))
        .await
        .unwrap()
        .unwrap();
    assert!(recv.read_to_end(0).await.unwrap().is_empty());
    reply
}

#[tokio::test]
async fn rejected_join_certificates_and_destroyed_networks_explain_the_refusal() {
    use iroh::address_lookup::memory::MemoryLookup;

    let env = TestConfigDir::new();
    let alpn = transport::mesh_alpn();
    let coordinator = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let joiner = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let store = FsStore::load(env.dir.path().join("blobs")).await.unwrap();
    let registry = sample_registry(
        coordinator.clone(),
        IrohIdentityProvider::new(coordinator.id()),
        store.clone(),
    );
    let state = make_network_state();
    let key = state.read().unwrap().network_public_key;
    let accepting = serve_coordinator(
        &coordinator,
        &store,
        &registry,
        vec![ServedNetwork {
            key,
            name: "test-net",
            state: Arc::clone(&state),
        }],
    );
    let connection = joiner.connect(coordinator.addr(), &alpn).await.unwrap();
    let owner = SecretKey::generate();
    let mut invalid = control::DeviceCert::create(&owner, &joiner.id(), 1);
    invalid.generation += 1;
    let wrong_device = control::DeviceCert::create(&owner, &SecretKey::generate().public(), 1);
    let revoked = control::DeviceCert::create(&owner, &joiner.id(), 1);
    for (cert, expected) in [
        (invalid, "invalid device certificate"),
        (wrong_device, "invalid device certificate"),
        (revoked, "device certificate has been revoked"),
    ] {
        if expected.contains("revoked") {
            state.write().unwrap().nullifiers.insert(joiner.id());
        }
        let reply = mesh_request_reply(
            &connection,
            key,
            &ControlMsg::JoinRequest {
                invite_secret: None,
                hostname: None,
                device_cert: Some(cert),
            },
        )
        .await;
        assert_eq!(
            reply,
            ControlMsg::JoinDenied {
                reason: expected.to_string()
            }
        );
        assert!(state.read().unwrap().pending.is_empty());
    }
    state.write().unwrap().destroyed = true;
    let reply = mesh_request_reply(
        &connection,
        key,
        &ControlMsg::JoinRequest {
            invite_secret: None,
            hostname: None,
            device_cert: None,
        },
    )
    .await;
    assert_eq!(
        reply,
        ControlMsg::JoinDenied {
            reason: "network has been destroyed".to_string()
        }
    );
    accepting.abort();
    joiner.close().await;
    coordinator.close().await;
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn unavailable_network_returns_a_retryable_error_instead_of_dropping_the_join() {
    use iroh::address_lookup::memory::MemoryLookup;

    let env = TestConfigDir::new();
    let alpn = transport::mesh_alpn();
    let server = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let client = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let store = FsStore::load(env.dir.path().join("blobs")).await.unwrap();
    let registry = sample_registry(
        server.clone(),
        IrohIdentityProvider::new(server.id()),
        store.clone(),
    );
    let accepting = serve_coordinator(&server, &store, &registry, Vec::new());
    let connection = client.connect(server.addr(), &alpn).await.unwrap();
    let reply = mesh_request_reply(
        &connection,
        SecretKey::generate().public(),
        &ControlMsg::JoinRequest {
            invite_secret: None,
            hostname: None,
            device_cert: None,
        },
    )
    .await;
    assert_eq!(
        reply,
        ControlMsg::JoinUnavailable {
            reason: "network is not active on this peer".to_string()
        }
    );
    accepting.abort();
    client.close().await;
    server.close().await;
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn member_replies_to_join_and_invalid_admin_grant() {
    use iroh::address_lookup::memory::MemoryLookup;

    let env = TestConfigDir::new();
    let alpn = transport::mesh_alpn();
    let server = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let client = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let store = FsStore::load(env.dir.path().join("blobs")).await.unwrap();
    let registry = sample_registry(
        server.clone(),
        IrohIdentityProvider::new(server.id()),
        store.clone(),
    );
    let state = make_network_state();
    state.write().unwrap().members.add(seated(client.id()));
    let key = state.read().unwrap().network_public_key;
    let ctx = sample_mesh_ctx(
        IrohIdentityProvider::new(server.id()),
        store.clone(),
        Arc::clone(&registry),
    );
    let manager = Arc::new(ConnectionManager::new());
    manager.set_mesh_dispatch(MeshDispatch {
        ctx: ctx.clone(),
        token: CancellationToken::new(),
        on_peer_connected: Arc::new(|_| {}),
    });
    manager.register(
        key,
        AcceptHandler::Member(Arc::new(MemberAcceptState {
            ctx,
            network_name: "test-net".to_string(),
            state: Arc::clone(&state),
            net_pubkey: key,
            my_identity: server.id(),
            endpoint: server.clone(),
            registry,
            invite_lock: Arc::new(AsyncMutex::new(())),
            reconverge_notify: Arc::new(tokio::sync::Notify::new()),
        })),
    );
    let accepting = {
        let server = server.clone();
        tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            manager.drive_mesh_connection(conn, false).await;
        })
    };
    let connection = client.connect(server.addr(), &alpn).await.unwrap();
    let reply = mesh_request_reply(
        &connection,
        key,
        &ControlMsg::JoinRequest {
            invite_secret: None,
            hostname: None,
            device_cert: None,
        },
    )
    .await;
    assert_eq!(
        reply,
        ControlMsg::JoinUnavailable {
            reason: "peer is not a coordinator for this network".to_string()
        }
    );
    let reply = mesh_request_reply(
        &connection,
        key,
        &ControlMsg::AdminGrant {
            network_pubkey: key,
            secret_key: SecretKey::generate().to_bytes(),
        },
    )
    .await;
    assert!(
        matches!(reply, ControlMsg::AdminGrantResult { network_pubkey, error: Some(error) }
        if network_pubkey == key && error == "admin grant key does not match network public key")
    );
    let reply = mesh_request_reply(
        &connection,
        key,
        &ControlMsg::AdminGrant {
            network_pubkey: key,
            secret_key: SecretKey::from_bytes(&[1; 32]).to_bytes(),
        },
    )
    .await;
    assert!(
        matches!(reply, ControlMsg::AdminGrantResult { error: Some(error), .. }
        if error.contains("durably committed") || error.contains("persist admin grant"))
    );
    assert!(state.read().unwrap().network_secret_key.is_none());
    let reply = mesh_request_reply(
        &connection,
        key,
        &ControlMsg::MeshHello {
            identity: SecretKey::generate().public(),
            hostname: None,
            device_cert: None,
        },
    )
    .await;
    assert!(
        matches!(reply, ControlMsg::JoinDenied { reason } if reason.contains("identity claim"))
    );
    state.write().unwrap().members.remove(&client.id());
    let reply = mesh_request_reply(
        &connection,
        key,
        &ControlMsg::MeshHello {
            identity: client.id(),
            hostname: None,
            device_cert: None,
        },
    )
    .await;
    assert!(matches!(reply, ControlMsg::JoinDenied { reason } if reason.contains("not a member")));
    accepting.abort();
    client.close().await;
    server.close().await;
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn coordinator_acknowledges_repeated_grants_with_a_durable_key() {
    use iroh::address_lookup::memory::MemoryLookup;

    let env = TestConfigDir::new();
    let alpn = transport::mesh_alpn();
    let server = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let client = loopback_endpoint_on(MemoryLookup::new(), vec![alpn.clone()]).await;
    let store = FsStore::load(env.dir.path().join("blobs")).await.unwrap();
    let registry = sample_registry(
        server.clone(),
        IrohIdentityProvider::new(server.id()),
        store.clone(),
    );
    let state = make_network_state();
    let secret = SecretKey::from_bytes(&[1; 32]);
    let key = secret.public();
    state.write().unwrap().network_secret_key = Some(secret.clone());
    state.write().unwrap().members.add(seated(client.id()));
    config::save_network(&config::NetworkConfig {
        name: "test-net".to_string(),
        network_secret_key: Some(secret.clone()),
        network_public_key: Some(key),
        ..Default::default()
    })
    .unwrap();
    let accepting = serve_coordinator(
        &server,
        &store,
        &registry,
        vec![ServedNetwork {
            key,
            name: "test-net",
            state: Arc::clone(&state),
        }],
    );
    let connection = client.connect(server.addr(), &alpn).await.unwrap();
    for _ in 0..2 {
        let reply = mesh_request_reply(
            &connection,
            key,
            &ControlMsg::AdminGrant {
                network_pubkey: key,
                secret_key: secret.to_bytes(),
            },
        )
        .await;
        assert_eq!(
            reply,
            ControlMsg::AdminGrantResult {
                network_pubkey: key,
                error: None
            }
        );
    }
    accepting.abort();
    client.close().await;
    server.close().await;
    store.shutdown().await.unwrap();
}
