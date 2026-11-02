use super::*;

/// An embedder never armed it, so a failed TUN loop must not cancel its node.
#[test]
fn an_unarmed_fatal_exit_leaves_the_daemon_running() {
    let fatal = FatalExit::default();
    let token = CancellationToken::new();
    assert!(!fatal.trigger(&token, "gone".into()));
    assert!(!token.is_cancelled());
    assert_eq!(fatal.take(), None);
}

#[test]
fn an_armed_fatal_exit_stops_the_daemon_with_the_first_reason() {
    let fatal = FatalExit::default();
    fatal.arm();
    let token = CancellationToken::new();
    assert!(fatal.trigger(&token, "first".into()));
    assert!(fatal.trigger(&token, "second".into()));
    assert!(token.is_cancelled());
    assert_eq!(fatal.take().as_deref(), Some("first"));
}
