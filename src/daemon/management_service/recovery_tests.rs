//! Real QUIC exchanges against the production management handler and worker.
//! One daemon per test keeps its process-wide config isolated; the other endpoint
//! speaks the wire protocol directly. Neither endpoint needs a TUN or a network.

use super::*;
use iroh::RelayMode;
use iroh::endpoint::presets;
use std::ffi::OsString;
use tempfile::TempDir;

pub(super) struct TestConfig {
    _directory: TempDir,
    previous: Option<OsString>,
}

impl TestConfig {
    pub(super) fn new(peer: &Endpoint) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        // Callers hold CONFIG_ENV_LOCK for the full daemon lifetime.
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", directory.path()) };
        config::update_settings(|settings| {
            settings.mdns_enabled = false;
            settings.dns_enabled = false;
            settings.default_hostname = Some("managed-test".to_string());
            settings.endpoint_hints = vec![peer.addr()];
            Ok(())
        })
        .unwrap();
        Self {
            _directory: directory,
            previous,
        }
    }
}

impl Drop for TestConfig {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}

pub(super) async fn peer(key: &SecretKey) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(key.clone())
        .alpns(vec![crate::management::ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

async fn exchange(peer: &Endpoint, server: &Endpoint, message: ManagementMsg) -> ManagementMsg {
    tokio::time::timeout(Duration::from_secs(10), async {
        let connection = peer
            .connect(server.addr(), crate::management::ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        control::send_framed(&mut send, &message).await.unwrap();
        let reply = control::recv_framed(&mut recv).await.unwrap();
        connection.close(0u32.into(), b"test received reply");
        reply
    })
    .await
    .expect("management exchange timed out")
}

async fn receive_hello(peer: &Endpoint, machine: EndpointId) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let connection = peer.accept().await.unwrap().await.unwrap();
        assert_eq!(connection.remote_id(), machine);
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let ManagementMsg::ControllerHello { receipt, hostname } =
            control::recv_framed(&mut recv).await.unwrap()
        else {
            panic!("expected automatic controller hello");
        };
        assert!(receipt.verify(peer.id(), machine));
        assert_eq!(hostname.as_ref(), "managed-test");
        control::send_framed(&mut send, &ManagementMsg::HelloAccepted)
            .await
            .unwrap();
        connection.closed().await;
    })
    .await
    .expect("machine did not announce itself")
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn enrollment_receipt_recovers_lost_inventory_but_not_forgotten_inventory() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let remote = peer(&SecretKey::generate()).await;
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    assert!(
        Daemon::check_authorized(
            &IpcMessage::ManagedMachineConfirm {
                machine: remote.id()
            },
            None
        )
        .is_some()
    );
    let IpcMessage::MachineEnrollmentCreated { ticket, .. } = daemon
        .management
        .create_enrollment(Duration::from_secs(60), false)
    else {
        panic!("expected enrollment ticket");
    };
    let ManagementMsg::EnrolledWithReceipt { receipt } = exchange(
        &remote,
        &daemon.transport.endpoint,
        ManagementMsg::Enroll {
            secret: EnrollmentSecret::from_bytes(*ticket.secret()),
            hostname: "remote-test".parse().unwrap(),
        },
    )
    .await
    else {
        panic!("expected signed enrollment receipt");
    };
    assert!(receipt.verify(daemon.transport.endpoint.id(), remote.id()));
    // Reproduce the reported failure: identity survives, inventory and enrollment
    // credentials disappear. Recovery must not need the original ticket.
    config::update_settings(|settings| {
        settings.managed_machines.clear();
        settings.enrollment_credentials.clear();
        Ok(())
    })
    .unwrap();
    let hello = ManagementMsg::ControllerHello {
        receipt: receipt.clone(),
        hostname: "remote-test".parse().unwrap(),
    };
    let stranger = peer(&SecretKey::generate()).await;
    assert!(matches!(
        exchange(&stranger, &daemon.transport.endpoint, hello.clone()).await,
        ManagementMsg::HelloRejected { .. }
    ));
    assert!(config::load().unwrap().managed_machines.is_empty());
    for _ in 0..2 {
        assert!(matches!(
            exchange(&remote, &daemon.transport.endpoint, hello.clone()).await,
            ManagementMsg::HelloAccepted
        ));
    }
    assert_eq!(config::load().unwrap().managed_machines.len(), 1);
    assert!(matches!(
        daemon
            .management
            .forget_machine(&"remote-test".parse().unwrap()),
        IpcMessage::Ok { .. }
    ));
    daemon.shutdown_and_close().await;
    let daemon = build_headless(true).await.unwrap();
    assert!(matches!(
        exchange(&remote, &daemon.transport.endpoint, hello).await,
        ManagementMsg::HelloRejected { .. }
    ));
    assert!(config::load().unwrap().managed_machines.is_empty());

    // The explicit confirmation command can restore a forgotten or legacy entry.
    let confirm_target = async {
        let connection = remote.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let ManagementMsg::Request {
            request_id,
            action: ManagementAction::ConfirmEnrollment { receipt },
        } = control::recv_framed(&mut recv).await.unwrap()
        else {
            panic!("expected explicit enrollment confirmation");
        };
        assert!(receipt.verify(connection.remote_id(), remote.id()));
        control::send_framed(
            &mut send,
            &ManagementMsg::Response {
                request_id,
                result: ManagementResult::Status {
                    hostname: "remote-test".parse().unwrap(),
                    networks: Vec::new(),
                },
            },
        )
        .await
        .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            daemon.management.confirm_machine(remote.id()),
            confirm_target
        )
    })
    .await
    .unwrap();
    assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
    let settings = config::load().unwrap();
    assert!(settings.forgotten_machines.is_empty());
    assert_eq!(settings.managed_machines.len(), 1);
    daemon.shutdown_and_close().await;
    remote.close().await;
    stranger.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn legacy_confirmation_announces_on_receipt_reconnect_and_restart() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let controller_key = SecretKey::generate();
    let remote = peer(&controller_key).await;
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    let machine = daemon.transport.endpoint.id();
    let receipt = EnrollmentReceipt::issue(&controller_key, machine, now());
    let confirm = ManagementMsg::Request {
        request_id: ManagementRequestId::generate(),
        action: ManagementAction::ConfirmEnrollment {
            receipt: receipt.clone(),
        },
    };
    // A signed receipt alone must never grant its signer control of this machine.
    assert!(matches!(
        exchange(&remote, &daemon.transport.endpoint, confirm.clone()).await,
        ManagementMsg::Response {
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
    let (reply, ()) = tokio::join!(
        exchange(&remote, &daemon.transport.endpoint, confirm.clone()),
        receive_hello(&remote, machine),
    );
    assert!(matches!(
        reply,
        ManagementMsg::Response {
            result: ManagementResult::Status { .. },
            ..
        }
    ));
    assert_eq!(
        config::load().unwrap().controllers[0].receipt.as_ref(),
        Some(&receipt)
    );

    daemon.management.connection_established(remote.id());
    receive_hello(&remote, machine).await;
    daemon.shutdown_and_close().await;
    let daemon = build_headless(true).await.unwrap();
    assert_eq!(daemon.transport.endpoint.id(), machine);
    receive_hello(&remote, machine).await;

    assert!(matches!(
        daemon.management.revoke_controller(None).await,
        IpcMessage::Ok { .. }
    ));
    assert!(matches!(
        exchange(&remote, &daemon.transport.endpoint, confirm).await,
        ManagementMsg::Response {
            result: ManagementResult::Unauthorized,
            ..
        }
    ));
    daemon.management.announce_controllers().await.unwrap();
    assert!(config::load().unwrap().controllers.is_empty());
    daemon.shutdown_and_close().await;
    assert!(daemon.management.hello_task.lock().unwrap().is_none());
    remote.close().await;
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn enrollment_persists_only_a_valid_receipt_and_announces_it() {
    let _lock = config::CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let controller_key = SecretKey::generate();
    let remote = peer(&controller_key).await;
    let _config = TestConfig::new(&remote);
    let daemon = build_headless(true).await.unwrap();
    let machine = daemon.transport.endpoint.id();
    let secret = EnrollmentSecret::generate();
    let ticket = ipc::EnrollmentTicket::new(remote.addr(), secret.to_bytes());
    for valid in [false, true] {
        let target = if valid {
            machine
        } else {
            SecretKey::generate().public()
        };
        let receipt = EnrollmentReceipt::issue(&controller_key, target, now());
        let controller = async {
            let connection = remote.accept().await.unwrap().await.unwrap();
            assert_eq!(connection.remote_id(), machine);
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let ManagementMsg::Enroll {
                secret: received, ..
            } = control::recv_framed(&mut recv).await.unwrap()
            else {
                panic!("expected enrollment request");
            };
            assert_eq!(received.hash(), secret.hash());
            control::send_framed(
                &mut send,
                &ManagementMsg::EnrolledWithReceipt {
                    receipt: receipt.clone(),
                },
            )
            .await
            .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
            if valid {
                receive_hello(&remote, machine).await;
            }
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(daemon.management.enroll_with_ticket(&ticket), controller)
        })
        .await
        .unwrap();
        let grants = config::load().unwrap().controllers;
        if valid {
            assert!(matches!(result, IpcMessage::Ok { .. }), "{result:?}");
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].receipt.as_ref(), Some(&receipt));
        } else {
            assert!(matches!(result, IpcMessage::Error { .. }));
            assert!(grants.is_empty());
        }
    }
    daemon.shutdown_and_close().await;
    remote.close().await;
}
