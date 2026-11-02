use super::*;

fn mdns(v: bool) -> AppConfig {
    AppConfig {
        mdns_enabled: v,
        ..Default::default()
    }
}

fn download_dir(v: Option<&str>) -> AppConfig {
    AppConfig {
        download_dir: v.map(str::to_string),
        ..Default::default()
    }
}

fn download_user(v: Option<u32>) -> AppConfig {
    AppConfig {
        download_user: v,
        ..Default::default()
    }
}

#[test]
fn global_keys_keep_the_exact_wording_their_handlers_printed() {
    assert_eq!(
        global_set_message(&AppConfig::default(), GlobalKey::Inbound, false),
        "Inbound policy updated."
    );
    assert_eq!(
        global_set_message(&AppConfig::default(), GlobalKey::Blocked, false),
        "Block list updated."
    );
    assert_eq!(
        global_set_message(&mdns(true), GlobalKey::Mdns, false),
        "mDNS discovery enabled."
    );
    assert_eq!(
        global_set_message(&mdns(false), GlobalKey::Mdns, false),
        "mDNS discovery disabled."
    );

    assert_eq!(
        global_set_message(
            &download_dir(Some("/srv/inbox")),
            GlobalKey::DownloadDir,
            false
        ),
        "download-dir set. Restart the daemon for changes to take effect."
    );
    assert_eq!(
        global_set_message(&download_dir(None), GlobalKey::DownloadDir, true),
        "download-dir cleared. Restart the daemon for changes to take effect."
    );

    assert_eq!(
        global_set_message(&download_user(Some(501)), GlobalKey::DownloadUser, false),
        "download-user set. Restart the daemon for changes to take effect."
    );
    assert_eq!(
        global_set_message(&download_user(None), GlobalKey::DownloadUser, true),
        "download-user cleared. Restart the daemon for changes to take effect."
    );

    // A key that never had a handler of its own keeps `ray config set`'s
    // generic wording, set and unset.
    let cfg = AppConfig::default();
    assert_eq!(
        global_set_message(&cfg, GlobalKey::Relay, false),
        "Set relay. Restart the daemon for changes to take effect."
    );
    assert_eq!(
        global_set_message(&cfg, GlobalKey::Relay, true),
        "Reset relay to default. Restart the daemon for changes to take effect."
    );
}

/// `cleared` follows the resulting value, not the `reset` flag, so setting
/// an empty value reads the same as `--clear`.
#[test]
fn download_keys_report_cleared_whenever_the_value_ends_up_unset() {
    let cfg = AppConfig::default();
    assert!(cfg.download_dir.is_none());
    assert_eq!(
        global_set_message(&cfg, GlobalKey::DownloadDir, false),
        "download-dir cleared. Restart the daemon for changes to take effect."
    );
}

#[test]
fn network_keys_keep_the_exact_wording_their_handlers_printed() {
    let mut net = config::empty_network_config("gaming");
    net.auto_accept_firewall = true;
    assert_eq!(
        net_set_message(&net, "gaming", NetworkKey::AutoAcceptFirewall),
        "auto-accept firewall suggestions enabled for 'gaming'"
    );
    net.auto_accept_firewall = false;
    assert_eq!(
        net_set_message(&net, "gaming", NetworkKey::AutoAcceptFirewall),
        "auto-accept firewall suggestions disabled for 'gaming'"
    );

    net.auto_accept_files = true;
    assert_eq!(
        net_set_message(&net, "gaming", NetworkKey::AutoAcceptFiles),
        "auto-accept files from your own devices enabled for 'gaming'"
    );
    net.auto_accept_files = false;
    assert_eq!(
        net_set_message(&net, "gaming", NetworkKey::AutoAcceptFiles),
        "auto-accept files from your own devices disabled for 'gaming'"
    );

    net.ephemeral_ttl_secs = Some(7200);
    assert_eq!(
        net_set_message(&net, "gaming", NetworkKey::EphemeralTtl),
        "ephemeral policy on 'gaming' set to 7200s"
    );
    net.ephemeral_ttl_secs = None;
    assert_eq!(
        net_set_message(&net, "gaming", NetworkKey::EphemeralTtl),
        "ephemeral policy on 'gaming' disabled"
    );
}

/// None of the live-effect keys may claim a restart is needed: the firewall
/// ones hot-swap the `ArcSwap` and the network ones are read on next use.
#[test]
fn live_keys_never_claim_a_restart_is_needed() {
    let net = config::empty_network_config("gaming");
    for &key in NetworkKey::ALL {
        let msg = net_set_message(&net, "gaming", key);
        assert!(!msg.contains("Restart"), "{key}: {msg}");
    }
}
