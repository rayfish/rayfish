//! The embedder's IPv6-only argument wins over `settings.toml`.
//!
//! This is the whole point of the argument. On Android the config directory is
//! app-private and the user's choice lives in the app's own preferences, so a
//! daemon that could only read the mode from the file would never be in it.
//!
//! Its own integration binary, not a `#[cfg(test)]` module, because building a
//! daemon in this mode sets the process-wide IPv6-only flags in `forward` and
//! `dns::config`. Under the lib tests, which share one process and run in
//! parallel, that reaches every other test's forwarding and resolv.conf
//! assertions mid-run. Here the process is ours alone.

use std::net::IpAddr;

use rayfish::daemon::build_headless;
use rayfish::dns::MAGIC_DNS_V6;
use rayfish::dns::config::resolver_addr;
use rayfish::ipc::IpcMessage;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_only_argument_overrides_config() {
    let tmp = tempfile::tempdir().unwrap();
    // Isolate identity/config/blobs from the system config dir.
    unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", tmp.path()) };

    // A fresh config dir, so the on-disk setting is at its default: off. The
    // argument below is the only thing asking for IPv6-only.
    assert!(!rayfish::config::load().unwrap().ipv6_only);

    // Bounded like the other headless-build tests: a startup regression should
    // fail fast rather than hang the suite.
    let daemon = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        build_headless(false, true),
    )
    .await
    .expect("build_headless should not hang")
    .expect("build_headless should succeed");

    match daemon.status() {
        IpcMessage::StatusResponse { ipv6_only, .. } => {
            assert!(ipv6_only, "the daemon runs in the mode it was asked for")
        }
        other => panic!("expected a status response, got {other:?}"),
    }

    // The mode has to reach the DNS side too: Magic DNS moves to `200::53`,
    // since the v4 address sits in the range this mode does not claim.
    assert_eq!(resolver_addr(), IpAddr::V6(MAGIC_DNS_V6));

    daemon.shutdown_and_close().await;
}
