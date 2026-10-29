use super::{PeerIdentity, windows_peer_authorized};

fn peer(sid: &str, system: bool, admin: bool) -> PeerIdentity {
    PeerIdentity::Windows {
        sid: sid.to_owned(),
        is_local_system: system,
        is_elevated_admin: admin,
    }
}

#[test]
fn zombie_authorization_matrix_fails_closed() {
    let operator = "S-1-5-21-1-2-3-1001";
    assert!(!windows_peer_authorized(None, Some(operator)));
    assert!(!windows_peer_authorized(
        Some(&peer("S-1-5-21-1-2-3-1002", false, false)),
        Some(operator)
    ));
    assert!(windows_peer_authorized(
        Some(&peer(operator, false, false)),
        Some(operator)
    ));
    assert!(windows_peer_authorized(
        Some(&peer("S-1-5-18", true, false)),
        None
    ));
    assert!(windows_peer_authorized(
        Some(&peer("S-1-5-21-1-2-3-500", false, true)),
        None
    ));
}
