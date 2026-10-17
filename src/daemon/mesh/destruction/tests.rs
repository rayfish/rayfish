use std::ffi::OsString;

use iroh::{RelayMode, endpoint::presets};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use super::*;

struct ConfigDir(Option<OsString>);

impl ConfigDir {
    fn set(path: &Path) -> Self {
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", path) };
        Self(previous)
    }
}

impl Drop for ConfigDir {
    fn drop(&mut self) {
        unsafe {
            match &self.0 {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}

/// A local discovery relay. Requests go through the real pkarr client and its
/// signature verification; no production discovery service is used.
struct Relay {
    url: Url,
    records: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    fail: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let records = Arc::new(RwLock::new(HashMap::new()));
        let fail = Arc::new(AtomicBool::new(false));
        let task = {
            let records = Arc::clone(&records);
            let fail = Arc::clone(&fail);
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let records = Arc::clone(&records);
                    let fail = Arc::clone(&fail);
                    tokio::spawn(async move { serve(stream, records, fail).await.unwrap() });
                }
            })
        };
        Self {
            url,
            records,
            fail,
            task,
        }
    }

    fn configure(&self) {
        config::update_settings(|cfg| {
            cfg.mdns_enabled = false;
            cfg.discovery_dns = config::ServerOverride {
                servers: vec![self.url.to_string()],
                replace: true,
            };
            Ok(())
        })
        .unwrap();
    }

    fn insert(&self, packet: &SignedPacket) {
        self.records.write().unwrap().insert(
            format!("/{}", packet.public_key().to_z32()),
            packet.to_relay_payload().to_vec(),
        );
    }
}

async fn serve(
    mut stream: TcpStream,
    records: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    fail: Arc<AtomicBool>,
) -> Result<()> {
    let mut request = Vec::new();
    let end = loop {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).await?;
        anyhow::ensure!(
            count > 0 && request.len() < 16384,
            "incomplete test request"
        );
        request.extend_from_slice(&chunk[..count]);
        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let header = String::from_utf8(request[..end].to_vec())?;
    let mut line = header.lines().next().unwrap().split_whitespace();
    let method = line.next().unwrap();
    let path = line.next().unwrap();
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    if request.len() < end + length {
        let present = request.len();
        request.resize(end + length, 0);
        stream.read_exact(&mut request[present..]).await?;
    }
    let mut status = "200 OK";
    let mut body = Vec::new();
    if fail.load(Ordering::Relaxed) {
        status = "503 Service Unavailable";
    } else if method == "PUT" {
        records
            .write()
            .unwrap()
            .insert(path.to_string(), request[end..end + length].to_vec());
    } else if let Some(record) = records.read().unwrap().get(path) {
        body = record.clone();
    } else {
        status = "404 Not Found";
    }
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

async fn create(daemon: &Daemon, name: &str) -> config::NetworkConfig {
    let result = daemon
        .create_network(
            GroupMode::Restricted,
            Some(name.to_string()),
            Some("test-node".to_string()),
        )
        .await;
    assert!(matches!(result, IpcMessage::Created { .. }), "{result:?}");
    config::load_network(name).unwrap().unwrap()
}

/// `ray rename` brings a live network back under its new name, with its saved
/// config and the firewall rules that name it (#36). Its links close with the
/// idle code: on the leave code a coordinator would prune us.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn rename_restarts_a_live_network_under_its_new_name() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    let peer = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![transport::mesh_alpn()])
        .bind()
        .await
        .unwrap();
    daemon.transport.warm_lookup.add_endpoint_info(peer.addr());
    let net = create(&daemon, "home").await;
    let net_pubkey = net.network_secret_key.unwrap().public();
    let roster = {
        let handle = daemon.registry.networks.get("home").unwrap();
        let mut state = handle.state.write().unwrap();
        let template = state.members.all()[0].clone();
        state.members.add(Member {
            identity: peer.id(),
            is_coordinator: false,
            hostname: Some("laptop".to_string()),
            ..template
        });
        state.roster()
    };
    daemon.registry.seed_route_map("home", &roster);
    // The peer's end: complete each `MeshHello`, then report how its link closed.
    let (closed_tx, mut closed) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn({
        let peer = peer.clone();
        async move {
            while let Some(incoming) = peer.accept().await {
                let Ok(conn) = incoming.await else {
                    continue;
                };
                let closed_tx = closed_tx.clone();
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        if let Ok(control::FrameRead::Frame(frame)) =
                            control::recv_frame(&mut recv).await
                            && matches!(frame.msg, ControlMsg::MeshHello { .. })
                        {
                            let _ = send.finish();
                        }
                    }
                    let _ = closed_tx.send(conn.close_reason());
                });
            }
        }
    });
    let target = daemon
        .registry
        .resolve_route(IpAddr::V6(derive_ipv6(&peer.id())))
        .unwrap();
    assert!(daemon.registry.dial_target(&target).await);
    let scoped = firewall::FirewallRule {
        direction: firewall::Direction::In,
        action: firewall::Action::Deny,
        protocol: firewall::Protocol::Tcp,
        port: Some(firewall::PortRange { start: 22, end: 22 }),
        peer: firewall::PeerFilter::Any,
        network: Some("home".to_string()),
        origin: firewall::RuleOrigin::Local,
    };
    let mut rules = (*daemon.registry.firewall.get_config()).clone();
    rules.rules.push(scoped);
    daemon.registry.firewall.update(rules);

    let result = daemon.registry.rename_network("home", "lab").await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let reason = tokio::time::timeout(Duration::from_secs(5), closed.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            &reason,
            Some(iroh::endpoint::ConnectionError::ApplicationClosed(close))
                if close.error_code == VarInt::from_u32(forward::IDLE_CODE)
        ),
        "{reason:?}"
    );
    assert!(config::load_network("home").unwrap().is_none());
    let saved = config::load_network("lab").unwrap().unwrap();
    assert_eq!(saved.network_public_key, Some(net_pubkey));
    assert!(!daemon.registry.networks.contains_key("home"));
    assert_eq!(
        daemon.registry.networks.get("lab").map(|h| h.network_key),
        Some(net_pubkey)
    );
    let scoped_to = |rules: &[firewall::FirewallRule]| {
        rules
            .iter()
            .filter_map(|r| r.network.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        scoped_to(&daemon.registry.firewall.get_config().rules),
        ["lab"]
    );
    assert_eq!(
        scoped_to(&firewall::load_firewall().unwrap().rules),
        ["lab"]
    );
    peer.close().await;
    daemon.shutdown_and_close().await;
}

/// What restarting a network does not rebuild moves to its new name: the exit
/// policy a gateway forwards by, a full tunnel's exit selection, the SSH
/// allow-lists, and the peers pruned from the network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn rename_moves_live_state_filed_under_the_name() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    create(&daemon, "home").await;
    let user = SecretKey::generate().public();
    config::update_network("home", |net| {
        net.exit_allow = vec!["*".to_string()];
        net.ssh_allow = vec![config::SshRule {
            peer: "*".to_string(),
            users: Vec::new(),
        }];
        Ok(())
    })
    .unwrap()
    .unwrap();
    // As `ray up` loads them, then a full tunnel through a peer on the network.
    assert!(daemon.registry.reload_exit_state().is_none());
    #[cfg(feature = "desktop")]
    daemon.rebuild_ssh_authz();
    daemon
        .registry
        .exit_client
        .set(Some(crate::exit_node::ExitSelection {
            peer_user: user,
            ipv6: derive_ipv6(&user),
            network: "home".into(),
            carries: crate::membership::ExitFamilies::V6,
        }));
    daemon
        .registry
        .pruned_peers
        .insert(("home".to_string(), user));
    assert!(daemon.registry.exit_server.allows("home", &user));

    let rename = IpcMessage::RenameNetwork {
        network: "home".to_string(),
        new_name: "lab".to_string(),
    };
    let result = daemon
        .handle_authorized_request(rename, None, Vec::new())
        .await;
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert!(daemon.registry.exit_server.allows("lab", &user));
    assert!(!daemon.registry.exit_server.allows("home", &user));
    assert_eq!(
        daemon
            .registry
            .exit_client
            .selection()
            .map(|s| s.network.clone()),
        Some("lab".into())
    );
    #[cfg(feature = "desktop")]
    {
        let authz = daemon.ssh_authz.load();
        assert!(authz.contains_key("lab"));
        assert!(!authz.contains_key("home"));
    }
    assert!(
        daemon
            .registry
            .pruned_peers
            .contains(&("lab".to_string(), user))
    );
    assert!(
        !daemon
            .registry
            .pruned_peers
            .contains(&("home".to_string(), user))
    );
    daemon.shutdown_and_close().await;
}

/// A crash between moving a network's file and rewriting the name inside it
/// leaves the network listed under a name that cannot load it. The next start
/// finishes the rename from its saved intent before restoring anything, firewall
/// rules included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_restart_finishes_an_interrupted_rename() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    let net_pubkey = create(&daemon, "home")
        .await
        .network_secret_key
        .unwrap()
        .public();
    let mut rules = firewall::load_firewall().unwrap();
    rules.rules.push(firewall::FirewallRule {
        direction: firewall::Direction::In,
        action: firewall::Action::Deny,
        protocol: firewall::Protocol::Tcp,
        port: Some(firewall::PortRange { start: 22, end: 22 }),
        peer: firewall::PeerFilter::Any,
        network: Some("home".to_string()),
        origin: firewall::RuleOrigin::Local,
    });
    firewall::save_firewall(&rules).unwrap();
    daemon.shutdown_and_close().await;

    // The intent saved and the file moved, but the old name still inside it and
    // the firewall rules not yet renamed.
    let moved = config::rename_network("home", "lab").unwrap().unwrap();
    let unrewritten = config::NetworkConfig {
        name: "home".to_string(),
        ..moved
    };
    std::fs::write(
        dir.path().join("networks").join("lab.toml"),
        ::toml::to_string_pretty(&unrewritten).unwrap(),
    )
    .unwrap();
    assert_eq!(config::load().unwrap().networks[0].name, "home");
    assert!(config::load_network("home").unwrap().is_none());

    let daemon = build_headless(false).await.unwrap();
    assert_eq!(
        daemon.registry.networks.get("lab").map(|h| h.network_key),
        Some(net_pubkey)
    );
    assert!(!daemon.registry.networks.contains_key("home"));
    assert!(config::rename_intent().unwrap().is_none());
    assert_eq!(config::load_network("lab").unwrap().unwrap().name, "lab");
    assert_eq!(config::load().unwrap().networks.len(), 1);
    let scoped_to = |rules: &[firewall::FirewallRule]| {
        rules
            .iter()
            .filter_map(|r| r.network.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        scoped_to(&daemon.registry.firewall.get_config().rules),
        ["lab"]
    );
    assert_eq!(
        scoped_to(&firewall::load_firewall().unwrap().rules),
        ["lab"]
    );
    daemon.shutdown_and_close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn last_coordinator_nuke_delivers_proof_and_preserves_shared_links() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    let net = create(&daemon, "doomed").await;
    create(&daemon, "survivor").await;
    let key = net.network_secret_key.as_ref().unwrap();
    let client = dht::create_pkarr_client(&daemon.transport.endpoint, &relay.url).unwrap();
    // A real 404 is absence; a relay outage must not authorize republishing.
    assert!(
        destruction::resolve(
            &client,
            destruction::discovery_key(key).public(),
            key.public()
        )
        .await
        .unwrap()
        .is_none()
    );
    relay.fail.store(true, Ordering::Relaxed);
    assert!(
        destruction::resolve(
            &client,
            destruction::discovery_key(key).public(),
            key.public()
        )
        .await
        .is_err()
    );
    relay.fail.store(false, Ordering::Relaxed);

    let alpn = transport::mesh_alpn();
    let peer = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![alpn.clone()])
        .bind()
        .await
        .unwrap();
    let (outbound, inbound) = tokio::join!(
        daemon.transport.endpoint.connect(peer.addr(), &alpn),
        async { peer.accept().await.unwrap().await.unwrap() },
    );
    let conn = outbound.unwrap();
    let ip = derive_ipv6(&peer.id());
    daemon
        .registry
        .peers
        .add(ip, conn.clone(), peer.id(), "doomed");
    daemon
        .registry
        .peers
        .add(ip, conn.clone(), peer.id(), "survivor");
    let state = Arc::clone(&daemon.registry.networks.get("doomed").unwrap().state);
    {
        let mut state = state.write().unwrap();
        let mut member = state.members.all()[0].clone();
        member.identity = peer.id();
        member.hostname = Some("member-node".to_string());
        member.is_coordinator = false;
        state.members.add(member);
    }
    assert!(matches!(
        daemon.registry.nuke_network("doomed", false).await,
        IpcMessage::Error { .. }
    ));
    let receive = async {
        let (_, mut recv) = inbound.accept_bi().await.unwrap();
        let message = control::recv_msg(&mut recv).await.unwrap();
        let ControlMsg::SignedRecord { packet } = message else {
            panic!("expected signed destruction")
        };
        let proof = dht::verify_network_record(&packet, key.public()).unwrap();
        assert!(destruction::is_destroyed(&proof));
    };
    let (result, ()) = tokio::join!(daemon.registry.nuke_network("doomed", true), receive);
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert!(!daemon.registry.networks.contains_key("doomed"));
    assert!(config::load_network("doomed").unwrap().is_none());
    assert!(state.read().unwrap().destroyed);
    assert!(!commit_current_snapshot(&state, &daemon.transport.blob_store, &None).await);
    assert!(config::save_network(&net).is_err());
    assert!(daemon.registry.networks.contains_key("survivor"));
    assert!(daemon.registry.peers.shares_network_v6(&ip, "survivor"));
    assert!(!daemon.registry.peers.shares_network_v6(&ip, "doomed"));
    assert!(conn.close_reason().is_none());

    // A delayed roster write cannot erase the independent deletion record.
    let stale = dht::encode_network_record(key, &net.last_group_hash.unwrap(), &[]).unwrap();
    relay.insert(&stale);
    assert!(destruction::is_destroyed(
        &dht::resolve_network_packet(&client, key.public())
            .await
            .unwrap()
    ));
    daemon.shutdown_and_close().await;
    peer.close().await;
    drop(daemon);
    drop(env);

    // A former coordinator has stale config and missed the broadcast.
    let offline_dir = tempfile::tempdir().unwrap();
    let _offline_env = ConfigDir::set(offline_dir.path());
    relay.configure();
    config::save_network(&net).unwrap();
    let restored = build_headless(false).await.unwrap();
    assert!(!restored.registry.networks.contains_key("doomed"));
    assert!(config::load_network("doomed").unwrap().is_none());
    assert!(config::destruction::load(key.public()).unwrap().is_some());
    restored.shutdown_and_close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn nuke_leaves_network_to_remaining_coordinator_even_when_offline() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    let alpn = transport::mesh_alpn();
    let peer = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![alpn.clone()])
        .bind()
        .await
        .unwrap();
    let (outbound, inbound) = tokio::join!(
        daemon.transport.endpoint.connect(peer.addr(), &alpn),
        async { peer.accept().await.unwrap().await.unwrap() },
    );
    let conn = outbound.unwrap();
    let ip = derive_ipv6(&peer.id());
    create(&daemon, "survivor").await;
    daemon
        .registry
        .peers
        .add(ip, conn.clone(), peer.id(), "survivor");
    let client = dht::create_pkarr_client(&daemon.transport.endpoint, &relay.url).unwrap();

    for connected in [true, false] {
        let name = if connected {
            "online-owner"
        } else {
            "offline-owner"
        };
        let net = create(&daemon, name).await;
        let key = net.network_secret_key.as_ref().unwrap();
        let state = Arc::clone(&daemon.registry.networks.get(name).unwrap().state);
        {
            let mut state = state.write().unwrap();
            let template = state.members.all()[0].clone();
            state.members.add(Member {
                identity: peer.id(),
                is_coordinator: true,
                hostname: Some("other-coordinator".to_string()),
                ..template
            });
        }
        if connected {
            daemon.registry.peers.add(ip, conn.clone(), peer.id(), name);
        }
        assert!(matches!(
            daemon.registry.nuke_network(name, false).await,
            IpcMessage::Error { .. }
        ));
        if !connected {
            relay.fail.store(true, Ordering::Relaxed);
            assert!(matches!(
                daemon.registry.nuke_network(name, true).await,
                IpcMessage::Error { .. }
            ));
            assert!(daemon.registry.networks.contains_key(name));
            assert!(config::load_network(name).unwrap().is_some());
            relay.fail.store(false, Ordering::Relaxed);
        }
        let receive = async {
            if connected {
                let (_, mut recv) = inbound.accept_bi().await.unwrap();
                assert!(matches!(
                    control::recv_msg(&mut recv).await.unwrap(),
                    ControlMsg::LeaveNetwork
                ));
            }
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(daemon.registry.nuke_network(name, true), receive)
        })
        .await
        .unwrap();
        assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
        assert!(!daemon.registry.networks.contains_key(name));
        assert!(config::load_network(name).unwrap().is_none());
        assert!(!state.read().unwrap().destroyed);
        assert!(config::destruction::load(key.public()).unwrap().is_none());
        assert!(
            destruction::resolve(
                &client,
                destruction::discovery_key(key).public(),
                key.public(),
            )
            .await
            .unwrap()
            .is_none()
        );
        assert!(!destruction::is_destroyed(
            &dht::resolve_network_packet(&client, key.public())
                .await
                .unwrap()
        ));
        let record = dht::resolve_network_packet(&client, key.public())
            .await
            .unwrap();
        let (hash, seeds) = dht::decode_network_record(&record).unwrap();
        assert!(seeds.contains(&peer.id()));
        assert!(seeds.contains(&daemon.transport.endpoint.id()));
        let bytes = daemon
            .transport
            .blob_store
            .blobs()
            .get_bytes(iroh_blobs::Hash::from_bytes(*hash.as_bytes()))
            .await
            .unwrap();
        let roster = verify_group_blob(&bytes, &hash).unwrap();
        assert!(
            roster
                .members
                .iter()
                .any(|member| member.identity == peer.id())
        );
        assert!(
            !roster
                .members
                .iter()
                .any(|member| member.identity == daemon.transport.endpoint.id())
        );
        assert!(conn.close_reason().is_none());
        // The remaining coordinator can still persist and publish this key.
        config::save_network(&net).unwrap();
        let record = dht::encode_network_record(key, &net.last_group_hash.unwrap(), &[]).unwrap();
        destruction::publish(&client, &record).await.unwrap();
        assert!(!destruction::is_destroyed(
            &dht::resolve_network_packet(&client, key.public())
                .await
                .unwrap()
        ));
        config::delete_network(name).unwrap();
    }
    daemon.shutdown_and_close().await;
    peer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn both_roles_accept_network_signed_proof_with_stale_roster() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    for role in [NetworkRole::Coordinator, NetworkRole::Member] {
        let net = create(&daemon, "doomed").await;
        let key = net.network_secret_key.as_ref().unwrap();
        let coordinator = SecretKey::from([90; 32]).public();
        let member = SecretKey::from([91; 32]).public();
        let stranger = SecretKey::from([92; 32]);
        {
            let handle = daemon.registry.networks.get("doomed").unwrap();
            let mut state = handle.state.write().unwrap();
            let template = state.members.all()[0].clone();
            for (identity, is_coordinator) in [(coordinator, true), (member, false)] {
                state.members.add(Member {
                    identity,
                    is_coordinator,
                    hostname: None,
                    ..template.clone()
                });
            }
        }
        let handler = if role == NetworkRole::Coordinator {
            daemon.registry.conn.handler_for(&key.public()).unwrap()
        } else {
            let handle = daemon.registry.networks.get("doomed").unwrap();
            handle.state.write().unwrap().network_secret_key = None;
            config::update_network("doomed", |net| {
                net.network_secret_key = None;
                Ok(())
            })
            .unwrap();
            AcceptHandler::Member(Arc::new(MemberAcceptState {
                ctx: daemon.registry.mesh_ctx(),
                network_name: "doomed".to_string(),
                state: Arc::clone(&handle.state),
                net_pubkey: key.public(),
                my_identity: daemon.transport.endpoint.id(),
                endpoint: daemon.transport.endpoint.clone(),
                registry: Arc::clone(&daemon.registry),
                invite_lock: Arc::clone(&handle.invite_lock),
                reconverge_notify: Arc::new(Notify::new()),
            }))
        };
        let wrong = destruction::encode(&stranger).unwrap();
        assert!(!handler.handle_common(
            coordinator,
            &ControlMsg::SignedRecord {
                packet: wrong.as_bytes().to_vec()
            }
        ));
        assert!(daemon.registry.networks.contains_key("doomed"));
        let proof = destruction::encode(key).unwrap();
        let handle = daemon.registry.networks.get("doomed").unwrap();
        handle.state.write().unwrap().members.remove(&coordinator);
        drop(handle);
        assert!(handler.handle_common(
            coordinator,
            &ControlMsg::SignedRecord {
                packet: proof.as_bytes().to_vec()
            }
        ));
        tokio::time::timeout(Duration::from_secs(30), async {
            while daemon.registry.networks.contains_key("doomed") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(config::load_network("doomed").unwrap().is_none());
        assert!(config::destruction::load(key.public()).unwrap().is_some());
    }
    let net = create(&daemon, "unavailable").await;
    relay.fail.store(true, Ordering::Relaxed);
    let result = daemon.registry.nuke_network("unavailable", false).await;
    assert!(matches!(result, IpcMessage::Error { .. }));
    assert!(config::load_network("unavailable").unwrap().is_none());
    assert!(
        config::destruction::load(net.network_public_key.unwrap())
            .unwrap()
            .is_some()
    );
    daemon.shutdown_and_close().await;
    drop(daemon);
    relay.fail.store(false, Ordering::Relaxed);
    let restarted = build_headless(false).await.unwrap();
    let client = dht::create_pkarr_client(&restarted.transport.endpoint, &relay.url).unwrap();
    let key = net.network_secret_key.as_ref().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if destruction::resolve(
                &client,
                destruction::discovery_key(key).public(),
                key.public(),
            )
            .await
            .unwrap()
            .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!restarted.registry.networks.contains_key("unavailable"));
    restarted.shutdown_and_close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn member_poller_learns_destruction_without_a_broadcast() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    let net = create(&daemon, "missed-notice").await;
    let key = net.network_secret_key.as_ref().unwrap();
    let proof = destruction::encode(key).unwrap();
    relay.insert(&proof);
    config::update_network("missed-notice", |net| {
        net.network_secret_key = None;
        Ok(())
    })
    .unwrap();
    {
        let mut handle = daemon.registry.networks.get_mut("missed-notice").unwrap();
        handle.role = NetworkRole::Member;
        handle.state.write().unwrap().network_secret_key = None;
        let poller = spawn_group_poller(
            dht::create_pkarr_client(&daemon.transport.endpoint, &relay.url).unwrap(),
            key.public(),
            Arc::clone(&handle.state),
            daemon.transport.endpoint.clone(),
            daemon.registry.mesh_ctx(),
            "missed-notice".to_string(),
            handle.cancel.clone(),
        );
        handle.tasks.push(poller);
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while daemon.registry.networks.contains_key("missed-notice") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(config::load_network("missed-notice").unwrap().is_none());
    assert!(config::destruction::load(key.public()).unwrap().is_some());
    daemon.shutdown_and_close().await;
}

/// A member whose link to its coordinator has idle-closed still gets its leave
/// there (#129). The coordinator is dialed even though the last dial to it
/// failed, and has the message before the member tears the network down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn leave_dials_a_coordinator_with_no_live_link() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let _env = ConfigDir::set(dir.path());
    let relay = Relay::start().await;
    relay.configure();
    let daemon = build_headless(false).await.unwrap();
    let coordinator = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![transport::mesh_alpn()])
        .bind()
        .await
        .unwrap();
    daemon
        .transport
        .warm_lookup
        .add_endpoint_info(coordinator.addr());

    let net = create(&daemon, "home").await;
    let net_pubkey = net.network_secret_key.as_ref().unwrap().public();
    let roster = {
        let mut handle = daemon.registry.networks.get_mut("home").unwrap();
        handle.role = NetworkRole::Member;
        let mut state = handle.state.write().unwrap();
        state.network_secret_key = None;
        let template = state.members.all()[0].clone();
        state.members.add(Member {
            identity: coordinator.id(),
            is_coordinator: true,
            hostname: Some("laptop".to_string()),
            ..template
        });
        state.roster()
    };
    daemon.registry.seed_route_map("home", &roster);
    // No live link, and a recent failed dial: a `MemberSync` would skip it.
    daemon.registry.reachability.note_fail(coordinator.id());
    assert!(
        daemon
            .registry
            .peers
            .conn_for_ip(&derive_ipv6(&coordinator.id()))
            .is_none()
    );

    // The coordinator's end: complete each `MeshHello`, then report the network
    // a `LeaveNetwork` names. The link is returned to stay open until the leave
    // has finished.
    let receive = async {
        let conn = coordinator.accept().await.unwrap().await.unwrap();
        loop {
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let control::FrameRead::Frame(frame) = control::recv_frame(&mut recv).await.unwrap()
            else {
                continue;
            };
            match frame.msg {
                ControlMsg::MeshHello { .. } => send.finish().unwrap(),
                ControlMsg::LeaveNetwork => return (frame.net, conn),
                _ => {}
            }
        }
    };
    let (result, (left, _link)) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(daemon.registry.leave_network("home"), receive)
    })
    .await
    .unwrap();
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    assert_eq!(left, Some(net_pubkey));
    assert!(!daemon.registry.networks.contains_key("home"));
    assert!(config::load_network("home").unwrap().is_none());
    coordinator.close().await;
    daemon.shutdown_and_close().await;
}
