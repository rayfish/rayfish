use super::recovery_tests::{TestConfig, peer};
use super::*;
use crate::management::{ALPN, LEGACY_ALPN};
use serde::{Deserialize, Serialize};

// Frozen v1 shapes. In particular, Enrolled must remain a unit variant and
// Request must never contain one of the receipt-only actions on this ALPN.
#[derive(Debug, Serialize, Deserialize)]
enum V1Message {
    Enroll {
        secret: EnrollmentSecret,
        hostname: MachineHostname,
    },
    Enrolled,
    EnrollmentRejected {
        message: String,
    },
    ProtocolError {
        message: String,
    },
    Request {
        request_id: ManagementRequestId,
        action: V1Action,
    },
    Response {
        request_id: ManagementRequestId,
        result: ManagementResult,
    },
}

#[derive(Debug, Serialize, Deserialize)]
enum V1Action {
    Status,
    Join {
        invite: NetworkInvite,
        network_name: NetworkName,
        hostname: MachineHostname,
        auto_accept_firewall: bool,
        auto_accept_files: bool,
    },
    Leave {
        network_name: NetworkName,
    },
}

async fn exchange_v1<M: Serialize>(peer: &Endpoint, server: &Endpoint, message: &M) -> V1Message {
    tokio::time::timeout(Duration::from_secs(10), async {
        let connection = peer.connect(server.addr(), LEGACY_ALPN).await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        control::send_framed(&mut send, message).await.unwrap();
        let reply = control::recv_framed(&mut recv).await.unwrap();
        connection.close(0u32.into(), b"test received v1 reply");
        reply
    })
    .await
    .unwrap()
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn old_peers_can_enroll_and_manage_new_nodes_but_cannot_use_receipts_on_v1() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let key = SecretKey::generate();
    let remote = peer(&key).await;
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    let server = &daemon.transport.endpoint;
    let preferred = connect_management(&remote, server.addr()).await.unwrap();
    assert_eq!(preferred.alpn(), ALPN, "updated peers must prefer receipts");
    preferred.close(0u32.into(), b"negotiation checked");
    let IpcMessage::MachineEnrollmentCreated { ticket, .. } = daemon
        .management
        .create_enrollment(Duration::from_secs(60), false)
    else {
        panic!("expected ticket");
    };
    let enrolled = exchange_v1(
        &remote,
        server,
        &V1Message::Enroll {
            secret: EnrollmentSecret::from_bytes(*ticket.secret()),
            hostname: "old-machine".parse().unwrap(),
        },
    )
    .await;
    assert!(matches!(enrolled, V1Message::Enrolled), "{enrolled:?}");
    assert_eq!(
        config::load().unwrap().managed_machines[0].identity,
        remote.id()
    );
    let status = V1Message::Request {
        request_id: ManagementRequestId::generate(),
        action: V1Action::Status,
    };
    assert!(matches!(
        exchange_v1(&remote, server, &status).await,
        V1Message::Response {
            result: ManagementResult::Unauthorized,
            ..
        }
    ));
    config::update_settings(|settings| {
        settings.controllers.push(config::ControllerGrant {
            identity: remote.id(),
            enrolled_at: now(),
            receipt: None,
        });
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        exchange_v1(&remote, server, &status).await,
        V1Message::Response {
            result: ManagementResult::Status { .. },
            ..
        }
    ));
    // Invalid input reaches the existing handlers, rather than failing to decode.
    for action in [
        V1Action::Join {
            invite: NetworkInvite::new("invalid".to_string()),
            network_name: NetworkName::new("missing".to_string()),
            hostname: "old-machine".parse().unwrap(),
            auto_accept_firewall: false,
            auto_accept_files: false,
        },
        V1Action::Leave {
            network_name: NetworkName::new("missing".to_string()),
        },
    ] {
        let request = V1Message::Request {
            request_id: ManagementRequestId::generate(),
            action,
        };
        assert!(matches!(
            exchange_v1(&remote, server, &request).await,
            V1Message::Response {
                result: ManagementResult::Error { .. },
                ..
            }
        ));
    }
    let receipt = EnrollmentReceipt::issue(&key, server.id(), now());
    let confirm = ManagementMsg::Request {
        request_id: ManagementRequestId::generate(),
        action: ManagementAction::ConfirmEnrollment { receipt },
    };
    assert!(matches!(
        exchange_v1(&remote, server, &confirm).await,
        V1Message::ProtocolError { .. }
    ));
    assert!(config::load().unwrap().controllers[0].receipt.is_none());
    let receipt = EnrollmentReceipt::issue(&daemon.management.secret_key, remote.id(), now());
    let hello = ManagementMsg::ControllerHello {
        receipt,
        hostname: "changed".parse().unwrap(),
    };
    assert!(matches!(
        exchange_v1(&remote, server, &hello).await,
        V1Message::ProtocolError { .. }
    ));
    assert_eq!(
        config::load().unwrap().managed_machines[0]
            .hostname
            .as_ref(),
        "old-machine"
    );
    daemon.shutdown_and_close().await;
    remote.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn new_nodes_negotiate_v1_for_old_peers_without_claiming_receipt_support() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let remote = peer(&SecretKey::generate()).await;
    remote.set_alpns(vec![LEGACY_ALPN.to_vec()]);
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    let secret = EnrollmentSecret::generate();
    let ticket = ipc::EnrollmentTicket::new(remote.addr(), secret.to_bytes());
    let old_controller = async {
        let connection = remote.accept().await.unwrap().await.unwrap();
        assert_eq!(connection.alpn(), LEGACY_ALPN);
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let V1Message::Enroll {
            secret: received, ..
        } = control::recv_framed(&mut recv).await.unwrap()
        else {
            panic!("expected v1 enrollment");
        };
        assert_eq!(received.hash(), secret.hash());
        control::send_framed(&mut send, &V1Message::Enrolled)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            daemon.management.enroll_with_ticket(&ticket),
            old_controller
        )
    })
    .await
    .unwrap();
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let grants = config::load().unwrap().controllers;
    assert_eq!(grants.len(), 1);
    assert!(grants[0].receipt.is_none());

    for action in [
        ManagementAction::Status,
        ManagementAction::Join {
            invite: NetworkInvite::new("test-invite".to_string()),
            network_name: NetworkName::new("test-net".to_string()),
            hostname: "old-machine".parse().unwrap(),
            auto_accept_firewall: true,
            auto_accept_files: false,
        },
        ManagementAction::Leave {
            network_name: NetworkName::new("test-net".to_string()),
        },
    ] {
        let old_machine = async {
            let connection = remote.accept().await.unwrap().await.unwrap();
            assert_eq!(connection.alpn(), LEGACY_ALPN);
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let V1Message::Request { request_id, action } =
                control::recv_framed(&mut recv).await.unwrap()
            else {
                panic!("expected v1 request");
            };
            let result = match action {
                V1Action::Status => ManagementResult::Status {
                    hostname: "old-machine".parse().unwrap(),
                    networks: Vec::new(),
                },
                V1Action::Join { .. } | V1Action::Leave { .. } => ManagementResult::Applied {
                    message: "applied".to_string(),
                },
            };
            control::send_framed(&mut send, &V1Message::Response { request_id, result })
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                daemon.management.send_request(remote.id(), action),
                old_machine
            )
        })
        .await
        .unwrap();
        assert!(
            matches!(
                result,
                Ok(ManagementResult::Status { .. } | ManagementResult::Applied { .. })
            ),
            "{result:?}"
        );
    }
    let no_confirmation = async {
        let connection = remote.accept().await.unwrap().await.unwrap();
        assert_eq!(connection.alpn(), LEGACY_ALPN);
        assert!(
            connection.accept_bi().await.is_err(),
            "must not send v2 actions to v1 peers"
        );
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            daemon.management.confirm_machine(remote.id()),
            no_confirmation
        )
    })
    .await
    .unwrap();
    assert!(matches!(result, IpcMessage::Error { message } if message.contains("upgrade")));
    assert!(config::load().unwrap().managed_machines.is_empty());
    daemon.shutdown_and_close().await;
    remote.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn unsigned_v1_acknowledgement_is_not_accepted_on_v2() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let remote = peer(&SecretKey::generate()).await;
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    let ticket = ipc::EnrollmentTicket::new(remote.addr(), EnrollmentSecret::generate().to_bytes());
    let unsigned_controller = async {
        let connection = remote.accept().await.unwrap().await.unwrap();
        assert_eq!(connection.alpn(), ALPN);
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let _: V1Message = control::recv_framed(&mut recv).await.unwrap();
        control::send_framed(&mut send, &V1Message::Enrolled)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            daemon.management.enroll_with_ticket(&ticket),
            unsigned_controller
        )
    })
    .await
    .unwrap();
    assert!(matches!(result, IpcMessage::Error { .. }));
    assert!(config::load().unwrap().controllers.is_empty());
    daemon.shutdown_and_close().await;
    remote.close().await;
}
