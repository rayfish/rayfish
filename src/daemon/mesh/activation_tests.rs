use tokio::sync::oneshot;

use super::*;

#[tokio::test]
async fn required_peer_route_failure_closes_forwarding_before_cleanup_and_returns_error() {
    let active = AtomicBool::new(true);
    let cleaned = AtomicBool::new(false);
    let (entered, mut started) = oneshot::channel();
    let (release, blocked) = oneshot::channel();
    let result = require_tun_setup(
        &active,
        Err(anyhow::anyhow!("controlled peer-route failure")),
        "failed to route IPv6 peer range into TUN",
        async {
            assert!(!active.load(Ordering::SeqCst));
            entered.send(()).unwrap();
            blocked.await.unwrap();
            cleaned.store(true, Ordering::SeqCst);
            IpcMessage::Ok {
                message: "standby".into(),
            }
        },
    );
    tokio::pin!(result);
    assert!(futures::poll!(&mut result).is_pending());
    started.try_recv().unwrap();
    assert!(!active.load(Ordering::SeqCst));
    assert!(!cleaned.load(Ordering::SeqCst));
    release.send(()).unwrap();
    assert!(matches!(result.await, Err(message)
        if message.contains("failed to route IPv6 peer range into TUN")
            && message.contains("controlled peer-route failure")));
    assert!(cleaned.load(Ordering::SeqCst));
    assert!(!active.load(Ordering::SeqCst));
}

#[tokio::test]
async fn required_peer_route_success_does_not_run_standby_cleanup() {
    let active = AtomicBool::new(true);
    let result = require_tun_setup(&active, Ok(()), "peer-route setup", async {
        panic!("successful setup must not run standby cleanup")
    })
    .await;
    assert!(result.is_ok());
    assert!(active.load(Ordering::SeqCst));
}

#[tokio::test]
async fn windows_activation_publishes_connected_only_after_setup_finishes() {
    let active = AtomicBool::new(false);
    let (complete, setup) = oneshot::channel();
    let activation = publish_activation(&active, async {
        setup.await.unwrap();
        IpcMessage::Ok {
            message: "VPN up".into(),
        }
    });
    tokio::pin!(activation);
    assert!(futures::poll!(&mut activation).is_pending());
    assert!(!active.load(Ordering::SeqCst));
    complete.send(()).unwrap();
    assert!(matches!(activation.await, IpcMessage::Ok { .. }));
    assert!(active.load(Ordering::SeqCst));
}

#[tokio::test]
async fn windows_route_failure_cannot_publish_connected_even_after_cleanup() {
    let active = AtomicBool::new(false);
    let cleaned = AtomicBool::new(false);
    let response = publish_activation(&active, async {
        match require_tun_setup(
            &active,
            Err(anyhow::anyhow!("controlled native route error")),
            "failed to route IPv6 peer range into TUN",
            async {
                cleaned.store(true, Ordering::SeqCst);
                IpcMessage::Ok {
                    message: "standby".into(),
                }
            },
        )
        .await
        {
            Ok(()) => IpcMessage::Ok {
                message: "VPN up".into(),
            },
            Err(error) => ipc_err(error),
        }
    })
    .await;
    assert!(
        matches!(response, IpcMessage::Error { message } if message.contains("controlled native route error"))
    );
    assert!(cleaned.load(Ordering::SeqCst));
    assert!(!active.load(Ordering::SeqCst));
}
