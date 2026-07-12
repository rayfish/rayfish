//! Kernel-plumbing tests for the exit node: they actually run the `nft` and `ip`
//! commands that `exit_node::enable` / `install_client_routing` emit and assert the
//! resulting kernel state, then assert teardown restores it.
//!
//! These need Linux + root + `nft`/`ip` + a mutable network namespace, so they are
//! opt-in: they no-op unless `RAYFISH_KERNEL_TEST=1`. Run them in a throwaway
//! privileged container (never on your workstation — they touch real routing
//! rules and sysctls):
//!
//! ```sh
//! just e2e-kernel
//! ```
//!
//! This is the one part of the exit-node feature that unit tests can't reach: a
//! typo in an `ip rule` argument only fails at runtime, on Linux, as root.

#![cfg(target_os = "linux")]

use std::process::Command;

use rayfish::exit_node;

/// The dummy link the tests point the tunnel routes at (a real device must exist
/// for `ip route ... dev <x>` to succeed).
const TEST_TUN: &str = "raytest0";

fn enabled() -> bool {
    std::env::var("RAYFISH_KERNEL_TEST").as_deref() == Ok("1")
}

fn sh(cmd: &str) -> String {
    let out = Command::new("sh")
        .args(["-c", cmd])
        .output()
        .unwrap_or_else(|e| panic!("running `{cmd}`: {e}"));
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn read_sysctl(path: &str) -> String {
    std::fs::read_to_string(format!("/proc/sys/{path}"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn make_dummy_link() {
    let _ = sh(&format!("ip link del {TEST_TUN}"));
    let out = Command::new("sh")
        .args(["-c", &format!("ip link add {TEST_TUN} type dummy")])
        .output()
        .expect("ip link add");
    assert!(
        out.status.success(),
        "could not create dummy link: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    sh(&format!("ip link set {TEST_TUN} up"));
}

fn del_dummy_link() {
    let _ = sh(&format!("ip link del {TEST_TUN}"));
}

/// Server role: forwarding sysctls + the nft masquerade table go up on `enable`
/// and are fully restored on `disable`.
#[test]
fn exit_server_enable_installs_nat_and_forwarding_then_restores() {
    if !enabled() {
        eprintln!("skipping: set RAYFISH_KERNEL_TEST=1 (needs root + a throwaway netns)");
        return;
    }
    make_dummy_link();

    // Start from a known-off state so the restore assertion is meaningful.
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "0").unwrap();
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "0").unwrap();

    let snapshot = exit_node::enable(TEST_TUN).expect("enable exit node");

    assert_eq!(read_sysctl("net/ipv4/ip_forward"), "1", "ipv4 forwarding on");
    assert_eq!(
        read_sysctl("net/ipv6/conf/all/forwarding"),
        "1",
        "ipv6 forwarding on"
    );

    // The nft table exists and carries both a masquerade and a forward chain.
    let table = sh("nft list table inet rayfish_exit");
    assert!(
        table.contains("masquerade"),
        "expected a masquerade rule, got:\n{table}"
    );
    assert!(
        table.contains("hook postrouting"),
        "expected a nat postrouting chain, got:\n{table}"
    );
    assert!(
        table.contains("hook forward"),
        "expected a filter forward chain, got:\n{table}"
    );
    // The masquerade must exempt the TUN itself (only traffic leaving an uplink).
    assert!(
        table.contains(TEST_TUN),
        "masquerade should reference the tun ({TEST_TUN}), got:\n{table}"
    );
    // Both overlay families are masqueraded.
    assert!(table.contains("100.64.0.0/10"), "v4 overlay masqueraded");
    assert!(table.contains("200::/7"), "v6 overlay masqueraded");

    exit_node::disable(&snapshot);

    assert_eq!(
        read_sysctl("net/ipv4/ip_forward"),
        "0",
        "ipv4 forwarding restored to its pre-enable value"
    );
    assert_eq!(
        read_sysctl("net/ipv6/conf/all/forwarding"),
        "0",
        "ipv6 forwarding restored to its pre-enable value"
    );
    let tables = sh("nft list tables");
    assert!(
        !tables.contains("rayfish_exit"),
        "nft table should be gone after disable, got:\n{tables}"
    );

    del_dummy_link();
}

/// Server role: a crash (panic hook) restores forwarding and removes the table
/// from the on-disk snapshot, with no in-memory state.
#[test]
fn exit_server_emergency_teardown_restores_from_disk() {
    if !enabled() {
        eprintln!("skipping: set RAYFISH_KERNEL_TEST=1");
        return;
    }
    make_dummy_link();
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "0").unwrap();

    let _snapshot = exit_node::enable(TEST_TUN).expect("enable exit node");
    assert_eq!(read_sysctl("net/ipv4/ip_forward"), "1");

    // Simulate the panic-hook path: no snapshot in hand, only what's on disk.
    exit_node::emergency_teardown();

    assert_eq!(
        read_sysctl("net/ipv4/ip_forward"),
        "0",
        "emergency teardown restored forwarding from the on-disk snapshot"
    );
    let tables = sh("nft list tables");
    assert!(
        !tables.contains("rayfish_exit"),
        "emergency teardown removed the nft table"
    );

    del_dummy_link();
}

/// Client role: the full-tunnel policy routing (tunnel table + the three ip rules)
/// installs for both families and tears down cleanly. This is the loop-prevention
/// setup: the fwmark rule is what keeps iroh's own transport off the tunnel.
#[test]
fn exit_client_routing_installs_rules_and_tunnel_table_then_removes() {
    if !enabled() {
        eprintln!("skipping: set RAYFISH_KERNEL_TEST=1");
        return;
    }
    make_dummy_link();

    exit_node::install_client_routing(TEST_TUN).expect("install client routing");

    for (family, flag) in [("v4", "-4"), ("v6", "-6")] {
        let rules = sh(&format!("ip {flag} rule show"));
        // 1. marked (iroh's own underlay) traffic bypasses the tunnel via main.
        assert!(
            rules.contains("0x7261") && rules.contains("lookup main"),
            "{family}: expected the fwmark bypass rule, got:\n{rules}"
        );
        // 2. main's specific routes still win (LAN / overlay / connected).
        assert!(
            rules.contains("suppress_prefixlength 0"),
            "{family}: expected the suppress_prefixlength rule, got:\n{rules}"
        );
        // 3. everything else falls to the tunnel table.
        assert!(
            rules.contains("29793"),
            "{family}: expected the tunnel-table rule, got:\n{rules}"
        );

        // The tunnel table carries a default route into the TUN.
        let routes = sh(&format!("ip {flag} route show table 29793"));
        assert!(
            routes.contains("default") && routes.contains(TEST_TUN),
            "{family}: expected `default dev {TEST_TUN}` in the tunnel table, got:\n{routes}"
        );
    }

    // Ordering matters: the bypass rule must be evaluated before the tunnel rule,
    // or iroh's marked packets would still be swallowed by the tunnel default.
    let rules = sh("ip -4 rule show");
    let bypass = rules.find("0x7261").expect("bypass rule present");
    let tunnel = rules.find("29793").expect("tunnel rule present");
    assert!(
        bypass < tunnel,
        "the fwmark bypass rule must sort before the tunnel rule, got:\n{rules}"
    );

    exit_node::teardown_client_routing();

    for flag in ["-4", "-6"] {
        let rules = sh(&format!("ip {flag} rule show"));
        assert!(
            !rules.contains("0x7261"),
            "fwmark rule should be gone after teardown, got:\n{rules}"
        );
        assert!(
            !rules.contains("29793"),
            "tunnel rule should be gone after teardown, got:\n{rules}"
        );
        let routes = sh(&format!("ip {flag} route show table 29793"));
        assert!(
            routes.trim().is_empty(),
            "tunnel table should be flushed, got:\n{routes}"
        );
    }

    del_dummy_link();
}

/// Installing twice in a row must not stack duplicate rules (a live
/// `ray exit-node use` change re-runs the install while already up).
#[test]
fn exit_client_routing_is_idempotent() {
    if !enabled() {
        eprintln!("skipping: set RAYFISH_KERNEL_TEST=1");
        return;
    }
    make_dummy_link();

    exit_node::install_client_routing(TEST_TUN).expect("first install");
    exit_node::install_client_routing(TEST_TUN).expect("second install");

    let rules = sh("ip -4 rule show");
    let marked = rules.matches("0x7261").count();
    assert_eq!(marked, 1, "fwmark rule must not be duplicated, got:\n{rules}");
    let tunnel = rules.matches("29793").count();
    assert_eq!(tunnel, 1, "tunnel rule must not be duplicated, got:\n{rules}");

    exit_node::teardown_client_routing();
    del_dummy_link();
}
