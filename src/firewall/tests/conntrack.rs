use super::*;
use tokio::time::advance;

fn firewall() -> SharedFirewall {
    SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Allow,
        rules: Vec::new(),
        ..Default::default()
    })
}

fn evaluate(firewall: &SharedFirewall, direction: Direction, flags: u8) -> Action {
    let local = Ipv4Addr::new(192, 0, 2, 1);
    let remote = Ipv4Addr::new(192, 0, 2, 2);
    let packet = match direction {
        Direction::Out => tcp_pkt(local, 50000, remote, 443, flags),
        Direction::In => tcp_pkt(remote, 443, local, 50000, flags),
    };
    firewall.evaluate_packet(direction, &packet, &test_id(2), |_| false)
}

fn inbound_rule(action: Action) -> FirewallRule {
    FirewallRule {
        direction: Direction::In,
        action,
        protocol: Protocol::Tcp,
        port: None,
        peer: PeerFilter::Any,
        network: None,
        origin: RuleOrigin::Local,
    }
}

#[tokio::test(start_paused = true)]
async fn both_fin_orders_allow_final_ack_and_retransmissions_for_a_fixed_grace() {
    for first in [Direction::In, Direction::Out] {
        let firewall = firewall();
        let second = match first {
            Direction::In => Direction::Out,
            Direction::Out => Direction::In,
        };
        assert_eq!(evaluate(&firewall, Direction::Out, SYN), Action::Allow);
        assert_eq!(evaluate(&firewall, first, FIN | ACK), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::Out, ACK), Action::Allow);
        assert_eq!(evaluate(&firewall, second, FIN | ACK), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::Out, ACK), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::In, FIN | ACK), Action::Allow);
        // A new incoming handshake must not reuse a closing return allowance.
        assert_eq!(evaluate(&firewall, Direction::In, SYN), Action::Deny);
        advance(TCP_CLOSING_TIMEOUT - Duration::from_secs(1)).await;
        assert_eq!(evaluate(&firewall, Direction::In, FIN | ACK), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::Out, ACK), Action::Allow);
        advance(Duration::from_secs(1)).await;
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
        // A final ACK or retransmitted FIN cannot extend this closing entry's grace.
        assert_eq!(evaluate(&firewall, Direction::Out, ACK), Action::Allow);
        assert_eq!(
            evaluate(&firewall, Direction::Out, FIN | ACK),
            Action::Allow
        );
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
    }
}

#[tokio::test(start_paused = true)]
async fn one_sided_close_keeps_the_normal_idle_timeout() {
    let firewall = firewall();
    assert_eq!(evaluate(&firewall, Direction::Out, SYN), Action::Allow);
    assert_eq!(
        evaluate(&firewall, Direction::Out, FIN | ACK),
        Action::Allow
    );
    for _ in 0..2 {
        advance(TCP_FLOW_TIMEOUT - Duration::from_secs(1)).await;
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Allow);
    }
    advance(TCP_FLOW_TIMEOUT).await;
    assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
    assert_eq!(
        evaluate(&firewall, Direction::Out, FIN | ACK),
        Action::Allow
    );
    assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
}

#[test]
fn resets_in_either_direction_remove_the_return_allowance() {
    for direction in [Direction::In, Direction::Out] {
        let firewall = firewall();
        assert_eq!(evaluate(&firewall, Direction::Out, SYN), Action::Allow);
        assert_eq!(evaluate(&firewall, direction, RST | ACK), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
    }
}

#[test]
fn stray_fin_and_reset_do_not_open_a_return_allowance() {
    for flags in [FIN | ACK, RST | ACK, SYN | RST] {
        let firewall = firewall();
        assert_eq!(evaluate(&firewall, Direction::Out, flags), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
    }
}

#[tokio::test(start_paused = true)]
async fn explicitly_allowed_inbound_fin_and_reset_update_existing_tracking() {
    for flags in [FIN | ACK, RST | ACK] {
        let firewall = firewall();
        let mut config = (*firewall.get_config()).clone();
        config.rules.push(inbound_rule(Action::Allow));
        firewall.update(config.clone());
        assert_eq!(evaluate(&firewall, Direction::Out, SYN), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::In, flags), Action::Allow);
        config.rules.clear();
        firewall.update(config);
        if flags & FIN != 0 {
            assert_eq!(
                evaluate(&firewall, Direction::Out, FIN | ACK),
                Action::Allow
            );
            assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Allow);
            advance(TCP_CLOSING_TIMEOUT).await;
        }
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
    }
}

#[test]
fn an_explicitly_denied_inbound_reset_cannot_remove_tracking() {
    let firewall = firewall();
    assert_eq!(evaluate(&firewall, Direction::Out, SYN), Action::Allow);
    let mut config = (*firewall.get_config()).clone();
    config.rules.push(inbound_rule(Action::Deny));
    firewall.update(config.clone());
    assert_eq!(evaluate(&firewall, Direction::In, RST | ACK), Action::Deny);
    config.rules.clear();
    firewall.update(config);
    assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Allow);
}

#[tokio::test(start_paused = true)]
async fn a_new_outbound_handshake_reuses_the_tuple_with_fresh_tracking() {
    for flags in [SYN, SYN | ACK] {
        let firewall = firewall();
        assert_eq!(evaluate(&firewall, Direction::Out, SYN), Action::Allow);
        assert_eq!(
            evaluate(&firewall, Direction::Out, FIN | ACK),
            Action::Allow
        );
        assert_eq!(evaluate(&firewall, Direction::In, FIN | ACK), Action::Allow);
        advance(TCP_CLOSING_TIMEOUT).await;
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
        assert_eq!(evaluate(&firewall, Direction::Out, flags), Action::Allow);
        assert_eq!(evaluate(&firewall, Direction::In, SYN | ACK), Action::Allow);
        advance(TCP_CLOSING_TIMEOUT).await;
        assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Allow);
    }
}

#[tokio::test(start_paused = true)]
async fn eviction_releases_closed_state_and_preserves_outbound_midstream_tracking() {
    let firewall = firewall();
    let token = CancellationToken::new();
    firewall.clone().spawn_evictor(token.clone());
    tokio::task::yield_now().await;
    assert_eq!(evaluate(&firewall, Direction::Out, SYN), Action::Allow);
    assert_eq!(
        evaluate(&firewall, Direction::Out, FIN | ACK),
        Action::Allow
    );
    assert_eq!(evaluate(&firewall, Direction::In, FIN | ACK), Action::Allow);
    advance(Duration::from_secs(60)).await;
    tokio::task::yield_now().await;
    assert!(
        firewall.conntrack.is_empty(),
        "the evictor releases closed entries"
    );
    assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Deny);
    // Existing policy permits resuming an idle outbound flow without a new SYN.
    assert_eq!(evaluate(&firewall, Direction::Out, ACK), Action::Allow);
    assert_eq!(evaluate(&firewall, Direction::In, ACK), Action::Allow);
    token.cancel();
}

#[tokio::test(start_paused = true)]
async fn exit_replies_follow_tcp_close_and_reset_tracking() {
    let local = Ipv4Addr::new(192, 0, 2, 1);
    let remote = Ipv4Addr::new(203, 0, 113, 1);
    for reset in [false, true] {
        let firewall = firewall();
        let outbound = tcp_pkt(local, 50000, remote, 443, SYN);
        let reply = |flags| tcp_pkt(remote, 443, local, 50000, flags);
        assert!(!firewall.admits_reply(&reply(SYN)));
        assert_eq!(
            firewall.evaluate_packet(Direction::Out, &outbound, &test_id(2), |_| false),
            Action::Allow
        );
        assert!(firewall.admits_reply(&reply(SYN | ACK)));
        let fin = tcp_pkt(local, 50000, remote, 443, FIN | ACK);
        assert_eq!(
            firewall.evaluate_packet(Direction::Out, &fin, &test_id(2), |_| false),
            Action::Allow
        );
        advance(TCP_CLOSING_TIMEOUT).await;
        assert!(
            firewall.admits_reply(&reply(ACK)),
            "half-close permits replies"
        );
        if reset {
            assert!(firewall.admits_reply(&reply(RST | ACK)));
        } else {
            assert!(firewall.admits_reply(&reply(FIN | ACK)));
            assert!(!firewall.admits_reply(&reply(SYN)));
            advance(TCP_CLOSING_TIMEOUT).await;
        }
        assert!(
            !firewall.admits_reply(&reply(ACK)),
            "closed flows reject replies"
        );
    }
}
