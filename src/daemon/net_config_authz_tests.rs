use super::*;

/// A global or firewall key reaching the per-network handlers would write a
/// key into `networks/<name>.toml` that nothing ever reads back, and (for
/// the firewall keys) skip the live `ArcSwap` swap entirely. `NetConfigSet`
/// carries a `NetworkKey`, which has no variant for either, so the mistake
/// is unrepresentable rather than rejected at runtime; the parse that
/// rejects the name (and names the command that does serve it) is tested in
/// `ray-proto`.
#[test]
fn a_node_key_cannot_be_parsed_as_a_per_network_one() {
    for key in ["mdns", "ssh", "download-dir", "firewall.enabled"] {
        assert!(key.parse::<NetworkKey>().is_err(), "{key}");
    }
    assert_eq!(
        "net.ephemeral-ttl".parse::<NetworkKey>().unwrap(),
        NetworkKey::EphemeralTtl
    );
}

#[cfg(unix)]
#[test]
fn net_config_set_is_a_mutation_and_net_config_get_is_an_open_read() {
    let unprivileged = PeerIdentity::Unix {
        uid: 1000,
        gid: 1000,
    };
    let root = PeerIdentity::Unix { uid: 0, gid: 0 };
    let set = IpcMessage::NetConfigSet {
        network: "gaming".into(),
        key: NetworkKey::AutoAcceptFiles,
        value: "off".into(),
    };
    // Non-root, non-operator UID: mutations are refused, reads are not.
    assert!(Daemon::check_authorized(&set, Some(&unprivileged)).is_some());
    assert!(Daemon::check_authorized(&set, Some(&root)).is_none());

    let get = IpcMessage::NetConfigGet {
        network: "gaming".into(),
        key: None,
    };
    assert!(Daemon::check_authorized(&get, Some(&unprivileged)).is_none());
}

/// A path send has the daemon open the path itself, so only root may ask
/// for one; the operator sends an open descriptor instead.
#[cfg(unix)]
#[test]
fn only_root_may_send_a_file_by_path() {
    let tmp = tempfile::tempdir().unwrap();
    config::set_thread_config_dir(tmp.path().to_path_buf());
    config::update_settings(|cfg| {
        cfg.operator_uid = Some(1000);
        Ok(())
    })
    .unwrap();
    let operator = PeerIdentity::Unix {
        uid: 1000,
        gid: 1000,
    };
    let root = PeerIdentity::Unix { uid: 0, gid: 0 };
    let by_path = IpcMessage::SendFile {
        path: "/etc/shadow".into(),
        peer: "laptop".into(),
    };
    let by_fd = IpcMessage::SendFileFd {
        filename: "notes.txt".into(),
        peer: "laptop".into(),
    };
    assert!(Daemon::check_authorized(&by_path, Some(&operator)).is_some());
    assert!(Daemon::check_authorized(&by_path, Some(&root)).is_none());
    assert!(Daemon::check_authorized(&by_fd, Some(&operator)).is_none());
}

/// The Windows half of the same rule, which has no root to fall back on: an
/// unelevated client that is not the stored operator gets refused, and each
/// of the three ways to be authorized is enough on its own.
#[cfg(windows)]
#[test]
fn windows_authorization_accepts_operator_system_and_elevated_admin_only() {
    let peer = |sid: &str, system: bool, admin: bool| PeerIdentity::Windows {
        sid: sid.to_owned(),
        is_local_system: system,
        is_elevated_admin: admin,
    };
    let operator = "S-1-5-21-1-2-3-1001";
    let stranger = peer("S-1-5-21-1-2-3-1002", false, false);

    assert!(!windows_peer_authorized(None, Some(operator)));
    assert!(!windows_peer_authorized(Some(&stranger), Some(operator)));
    // No operator claimed yet: only the elevated bootstrap gets in.
    assert!(!windows_peer_authorized(Some(&stranger), None));

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
