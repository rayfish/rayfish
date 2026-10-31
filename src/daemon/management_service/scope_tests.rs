//! A controller may only make a machine join or leave networks it coordinates.
//! Each test drives the production handler over real QUIC, on the current ALPN
//! and on v1, which old controllers still speak.

use super::compatibility_tests::{V1Action, V1Message, exchange_v1};
use super::recovery_tests::{TestConfig, exchange, peer};
use super::*;

/// Install a live network on the machine whose signed roster holds `members`.
fn hold_network(daemon: &Daemon, name: &str, members: &[(EndpointId, bool)]) {
    let network_key = SecretKey::generate().public();
    let mut list = MemberList::new();
    for &(identity, is_coordinator) in members {
        list.add(Member {
            identity,
            is_coordinator,
            hostname: None,
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::Unknown,
        });
    }
    let mut state = NetworkState {
        group: GroupBlob {
            members: list,
            approved: ApprovedList::new(),
            suggested_firewall: SuggestedFirewall::default(),
            name: Some(name.to_string()),
            reusable_keys: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        },
        snapshot: None,
        snapshot_commit: Arc::new(AsyncMutex::new(())),
        destroyed: false,
        converged_hash: None,
        unconfirmed_durable_hash: None,
        network_secret_key: None,
        network_public_key: network_key,
        network_name: Some(name.to_string()),
        mode: GroupMode::Restricted,
        pending_suggestions: Vec::new(),
        pending: HashMap::new(),
        last_record_timestamp: None,
    };
    state.refresh_snapshot();
    daemon.registry.networks.insert(
        name.to_string(),
        NetworkHandle {
            name: name.to_string(),
            network_key,
            role: NetworkRole::Member,
            state: Arc::new(RwLock::new(state)),
            dht_notify: None,
            cancel: CancellationToken::new(),
            tasks: vec![],
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
}

fn authorize(controller: EndpointId) {
    config::update_settings(|settings| {
        settings.controllers.push(config::ControllerGrant {
            identity: controller,
            enrolled_at: now(),
            receipt: None,
        });
        Ok(())
    })
    .unwrap();
}

fn request(action: ManagementAction) -> ManagementMsg {
    ManagementMsg::Request {
        request_id: ManagementRequestId::generate(),
        action,
    }
}

fn leave(name: &str) -> ManagementAction {
    ManagementAction::Leave {
        network_name: NetworkName::new(name.to_string()),
    }
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn controller_can_only_leave_networks_it_coordinates() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let remote = peer(&SecretKey::generate()).await;
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    let server = &daemon.transport.endpoint;
    authorize(remote.id());
    let other_coordinator = SecretKey::generate().public();
    // The controller is an ordinary member here, which is not enough.
    hold_network(
        &daemon,
        "foreign",
        &[(other_coordinator, true), (remote.id(), false)],
    );
    hold_network(&daemon, "managed", &[(remote.id(), true)]);

    let reply = exchange(&remote, server, request(leave("foreign"))).await;
    let ManagementMsg::Response {
        result: ManagementResult::Error { message },
        ..
    } = reply
    else {
        panic!("leave of a foreign network was not refused: {reply:?}");
    };
    assert!(message.contains("does not coordinate"), "{message}");
    let v1 = exchange_v1(
        &remote,
        server,
        &V1Message::Request {
            request_id: ManagementRequestId::generate(),
            action: V1Action::Leave {
                network_name: NetworkName::new("foreign".to_string()),
            },
        },
    )
    .await;
    assert!(
        matches!(
            v1,
            V1Message::Response {
                result: ManagementResult::Error { .. },
                ..
            }
        ),
        "{v1:?}"
    );
    assert!(daemon.registry.networks.contains_key("foreign"));

    let reply = exchange(&remote, server, request(leave("managed"))).await;
    assert!(
        matches!(
            reply,
            ManagementMsg::Response {
                result: ManagementResult::Applied { .. },
                ..
            }
        ),
        "{reply:?}"
    );
    assert!(!daemon.registry.networks.contains_key("managed"));
    assert!(daemon.registry.networks.contains_key("foreign"));
    daemon.shutdown_and_close().await;
    remote.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn controller_cannot_join_a_machine_with_a_foreign_invite() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let remote = peer(&SecretKey::generate()).await;
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    let server = &daemon.transport.endpoint;
    authorize(remote.id());
    let invite = crate::invite::encode_invite_code(
        &SecretKey::generate().public(),
        &SecretKey::generate().public(),
        &[7; 16],
    );
    let join = |invite: &str| ManagementAction::Join {
        invite: NetworkInvite::new(invite.to_string()),
        network_name: NetworkName::new("elsewhere".to_string()),
        hostname: "managed-test".parse().unwrap(),
        auto_accept_firewall: false,
        auto_accept_files: false,
    };

    let reply = exchange(&remote, server, request(join(&invite))).await;
    let ManagementMsg::Response {
        result: ManagementResult::Error { message },
        ..
    } = reply
    else {
        panic!("join with a foreign invite was not refused: {reply:?}");
    };
    assert!(
        message.contains("not issued by this controller"),
        "{message}"
    );
    let v1 = exchange_v1(
        &remote,
        server,
        &V1Message::Request {
            request_id: ManagementRequestId::generate(),
            action: V1Action::Join {
                invite: NetworkInvite::new(invite.clone()),
                network_name: NetworkName::new("elsewhere".to_string()),
                hostname: "managed-test".parse().unwrap(),
                auto_accept_firewall: false,
                auto_accept_files: false,
            },
        },
    )
    .await;
    assert!(
        matches!(
            v1,
            V1Message::Response {
                result: ManagementResult::Error { .. },
                ..
            }
        ),
        "{v1:?}"
    );
    let settings = config::load().unwrap();
    assert!(settings.pending_joins.is_empty());
    assert!(config::load_network("elsewhere").unwrap().is_none());
    assert!(daemon.registry.networks.is_empty());
    daemon.shutdown_and_close().await;
    remote.close().await;
}
