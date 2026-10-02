use super::*;

// ---------------------------------------------------------------------------
// Linux kernel state (nftables + policy routing)
// ---------------------------------------------------------------------------

/// The nftables tables we own (one per role, so gateway and client are
/// independent) and the sysctls and routing state the two roles need.
#[cfg(target_os = "linux")]
mod names {
    pub(in crate::exit_node) const SERVER_TABLE: &str = "rayfish_exit";
    pub(in crate::exit_node) const CLIENT_TABLE: &str = "rayfish_exit_client";
    /// Policy-routing table holding the client's full-tunnel default route
    /// (`default dev <tun>`), separate from `main` so marked traffic can bypass it.
    pub(in crate::exit_node) const EXIT_TABLE: &str = "29793";
    /// `ip rule` preferences (lower = higher priority). Named so install and
    /// teardown stay in sync.
    // Legacy bypass preferences, retained only to remove rules during upgrade.
    pub(in crate::exit_node) const PREF_FOREIGN: &str = "98";
    pub(in crate::exit_node) const PREF_SRC: &str = "99";
    pub(in crate::exit_node) const PREF_BYPASS: &str = "100";
    pub(in crate::exit_node) const PREF_MAIN: &str = "101";
    pub(in crate::exit_node) const PREF_TUNNEL: &str = "102";
}
#[cfg(target_os = "linux")]
pub(super) use names::*;

/// Turn this host into an exit node: enable IPv4/IPv6 forwarding and install an
/// nftables table that masquerades overlay-sourced traffic that arrived on the
/// TUN and is leaving by another interface, so replies come back to us and we
/// can un-NAT them to the client.
///
/// The `iifname` half of that match is what keeps the rule to our own traffic.
/// `100.64.0.0/10` is not exclusively ours (Tailscale allocates from it too), so
/// matching on the source range alone would also masquerade another VPN's
/// forwarded packets on a host that routes for both. Locally-generated traffic
/// has no input interface and so never matches, which is correct: nothing this
/// host originates is a peer's transit traffic.
///
/// Nothing here opens the forward path: with no other ruleset the kernel forwards
/// once the sysctls are on, and a host firewall that drops forwarding (ufw,
/// firewalld, Docker's iptables policy) cannot be overridden from our own table
/// anyway (an `accept` ends only the chain it is in, never another chain's drop).
/// Such a host must be told to permit forwarding on its own terms.
///
/// Idempotent, and safe to re-run while already enabled: the prior sysctl values
/// are snapshotted to disk exactly once (a re-apply must not capture the values we
/// set ourselves), and the nft ruleset is replaced wholesale. That same file is
/// what [`disable`] restores from, including when it runs from the panic hook, so a
/// crash can never leave the host acting as an open router. Writing it is therefore
/// a precondition, not a nicety: without it we could turn forwarding on and never
/// be able to put it back, so we refuse instead. Linux only.
///
/// Returns whether the IPv4 lease pool is routed. A route that overlaps it
/// leaves IPv4 transit off and IPv6 working.
#[cfg(target_os = "linux")]
pub(super) fn enable(tun_name: &str) -> Result<bool> {
    let path = snapshot_path().context("no config dir to snapshot the forwarding sysctls into")?;
    if !path.exists() {
        Snapshot {
            v4: read_sysctl(V4_FORWARD),
            v6: read_sysctl(V6_FORWARD),
            pf_token: None,
            tun_name: Some(tun_name.to_owned()),
        }
        .save(&path)?;
    }
    let v4_pool = match ensure_ipv4_routes_available(tun_name, ipv4::AddressSpace::Gateway) {
        Ok(()) => {
            run_ip(&[
                "-4",
                "route",
                "replace",
                ipv4::SERVER_PREFIX,
                "dev",
                tun_name,
            ])?;
            true
        }
        Err(error) => {
            tracing::warn!(%error, "IPv4 exit transit disabled");
            let _ = run_ip(&["-4", "route", "del", ipv4::SERVER_PREFIX, "dev", tun_name]);
            false
        }
    };
    write_sysctl(V4_FORWARD, "1")?;
    write_sysctl(V6_FORWARD, "1")?;
    nft_load(&server_nft_ruleset(tun_name))?;
    tracing::info!(
        tun = tun_name,
        v4_pool,
        "exit node forwarding + NAT enabled"
    );
    Ok(v4_pool)
}

/// Masquerade authenticated transit arriving on our TUN. The mark keeps gateway
/// transit on the physical uplink even when this host also uses an exit node.
#[cfg(target_os = "linux")]
pub(super) fn server_nft_ruleset(tun_name: &str) -> String {
    format!(
        "{reset}\
         table inet {t} {{\n\
         \tchain transit {{\n\
         \t\ttype filter hook prerouting priority mangle; policy accept;\n\
         \t\tiifname \"{tun}\" ip saddr {v4} meta mark set {mark}\n\
         \t\tiifname \"{tun}\" ip6 saddr {v6} meta mark set {mark}\n\
         \t}}\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tiifname \"{tun}\" ip saddr {v4} oifname != \"{tun}\" masquerade\n\
         \t\tiifname \"{tun}\" ip6 saddr {v6} oifname != \"{tun}\" masquerade\n\
         \t}}\n\
         }}\n",
        reset = drop_table(SERVER_TABLE),
        t = SERVER_TABLE,
        v6 = V6_OVERLAY,
        v4 = ipv4::SERVER_PREFIX,
        mark = SOCKET_MARK,
        tun = tun_name,
    )
}

/// Remove the exit-node gateway state: drop our nftables table and restore the
/// forwarding sysctls to the values captured by [`enable`]. Reads the on-disk
/// snapshot rather than in-memory state, so the same call works from the panic hook
/// (which `abort()`s, and must not leave the host an open router/NAT). Best-effort
/// and idempotent: a no-op when no snapshot exists (never enabled, or already torn
/// down). Linux only.
#[cfg(target_os = "linux")]
pub fn disable() {
    let Some(path) = snapshot_path() else { return };
    if !path.exists() {
        return;
    }
    let _ = nft_load(&drop_table(SERVER_TABLE));
    let snap = Snapshot::load(&path);
    if let Some(tun) = &snap.tun_name {
        let _ = run_ip(&["-4", "route", "del", ipv4::SERVER_PREFIX, "dev", tun]);
    }
    snap.restore_sysctls();
    let _ = fs::remove_file(&path);
    tracing::info!("exit node forwarding + NAT disabled");
}

mod client;
pub use client::install_client_routing;

/// Remove the client full-tunnel policy routing installed by
/// [`install_client_routing`]: drop the rules, flush the tunnel table, remove the
/// conntrack-mark table. Best-effort and idempotent (the TUN going down also drops
/// its routes). Linux only.
#[cfg(target_os = "linux")]
pub fn teardown_client_routing() {
    for family in ["-4", "-6"] {
        remove_client_rules(family, RuleSweep::All);
        let _ = run_ip(&[family, "route", "flush", "table", EXIT_TABLE]);
    }
    remove_ipv4_client_address();
    let _ = nft_load(&drop_table(CLIENT_TABLE));
    tracing::info!("exit-node client full-tunnel routing removed");
}

/// How much of our rule set [`remove_client_rules`] takes down.
///
/// Teardown wants [`RuleSweep::All`]. A re-install wants
/// [`RuleSweep::KeepCatchAll`], because the catch-all at [`PREF_TUNNEL`] is the
/// only thing standing between tunnel-bound traffic and `main`: drop it and every
/// packet leaves the physical uplink, sourced from this host's real address,
/// until the rebuild puts it back. That is not instant: every rule is a separate
/// `ip` process, and the mirrored routes that go in first are one process per
/// foreign prefix, which a co-resident VPN can have hundreds of. Since the rule
/// never varies (`table <EXIT_TABLE> pref <PREF_TUNNEL>`, no per-run content),
/// leaving it standing across the rebuild costs nothing and closes the window:
/// the routes underneath it are updated with `route replace`, which is atomic per
/// destination.
///
/// Keeping it standing is only safe because the rebuild puts the three bypass
/// rules back *first*: with the catch-all up and those down, ours is the
/// highest-priority rule matching anything, and the daemon's own transport goes
/// into the tunnel it is carrying.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RuleSweep {
    All,
    KeepCatchAll,
}

/// Whether our catch-all rule is already installed for one family, read back from
/// `ip rule show` the same way the other rule readbacks work.
#[cfg(target_os = "linux")]
pub(super) fn catch_all_installed(family: &str) -> bool {
    let out = match Command::new("ip").args([family, "rule", "show"]).output() {
        Ok(out) if out.status.success() => out.stdout,
        _ => return false,
    };
    parse_catch_all(&String::from_utf8_lossy(&out))
}

/// Whether `ip rule show` output contains our catch-all: at [`PREF_TUNNEL`], no
/// selector, looking up our table.
///
/// The table is matched by *position*, not by its printed value, because the
/// value is not stable: `ip rule show` prints a table's **name** when
/// `/etc/iproute2/rt_tables` maps our id, so a host that happens to have named
/// `29793` reads back as `lookup <name>`. Only the pref distinguishes it from a
/// co-resident VPN's catch-all, and the pref is ours by construction. Getting
/// this wrong is not cosmetic: a false negative here used to fail the whole
/// install, which the caller answers by tearing the tunnel down.
#[cfg(target_os = "linux")]
pub(super) fn parse_catch_all(show: &str) -> bool {
    show.lines().any(|line| {
        let Some((pref, rest)) = line.split_once(':') else {
            return false;
        };
        if pref.trim() != PREF_TUNNEL {
            return false;
        }
        // Same readback convention as `parse_source_rules`: iproute2 prints the
        // `from all` selector even though the rule was added without one.
        let f: Vec<&str> = rest.split_whitespace().collect();
        matches!(f.as_slice(), ["from", "all", "lookup", _])
    })
}

/// The source addresses of the [`PREF_SRC`] rules currently installed for one
/// family, read back from `ip rule show`. Matches only our own shape
/// (`<pref>: from <addr> lookup main`) so a foreign rule sharing the pref is left
/// alone. See [`parse_source_rules`] for the parsing.
#[cfg(target_os = "linux")]
pub(super) fn installed_source_rules(family: &str) -> Vec<String> {
    let out = match Command::new("ip").args([family, "rule", "show"]).output() {
        Ok(out) if out.status.success() => out.stdout,
        _ => return Vec::new(),
    };
    parse_source_rules(&String::from_utf8_lossy(&out))
}

/// Pull the addresses out of `ip rule show` output for rules that are ours: at
/// [`PREF_SRC`], `from <addr>`, looking up `main`.
#[cfg(target_os = "linux")]
pub(super) fn parse_source_rules(show: &str) -> Vec<String> {
    show.lines()
        .filter_map(|line| {
            let (pref, rest) = line.split_once(':')?;
            if pref.trim() != PREF_SRC {
                return None;
            }
            let f: Vec<&str> = rest.split_whitespace().collect();
            match f.as_slice() {
                ["from", addr, "lookup", "main"] => Some((*addr).to_string()),
                _ => None,
            }
        })
        .collect()
}

/// The one [`PREF_FOREIGN`] rule, as `ip` argv. `verb` is `add` or `del`.
///
/// Split out because the add and the del have to name the *same* rule and are
/// several hundred lines apart: `ip rule del` matches on the keys it is given, so
/// a del that omits `suppress_prefixlength` finds nothing and leaves the rule
/// installed, which stacks a duplicate on the next add. The whole spelling is also
/// what makes the rule mean "every prefix in our table except the default", so a
/// test can pin it rather than the constants around it.
#[cfg(target_os = "linux")]
pub(super) fn foreign_rule_args<'a>(family: &'a str, verb: &'a str) -> [&'a str; 9] {
    [
        family,
        "rule",
        verb,
        "table",
        EXIT_TABLE,
        "suppress_prefixlength",
        "0",
        "pref",
        PREF_FOREIGN,
    ]
}

/// The destinations of any per-prefix [`PREF_FOREIGN`] rules still installed: the
/// shape this branch used to add, before one `suppress_prefixlength` rule replaced
/// the lot.
///
/// Kept only as a cleanup path. Matching is deliberately loose on the table (a
/// name or our id, since `ip rule show` prints whichever `/etc/iproute2/rt_tables`
/// says) and strict on the shape, so it reclaims our own leftovers without
/// touching a foreign rule that happens to sit at the same preference.
#[cfg(target_os = "linux")]
pub(super) fn strays_at_our_pref(family: &str) -> Vec<String> {
    match ip_output(&[family, "rule", "show"]) {
        Some(out) => parse_strays(&out),
        None => Vec::new(),
    }
}

/// The text half of [`strays_at_our_pref`], split out to be testable.
#[cfg(target_os = "linux")]
pub(super) fn parse_strays(show: &str) -> Vec<String> {
    show.lines()
        .filter_map(|line| {
            let (pref, rest) = line.split_once(':')?;
            if pref.trim() != PREF_FOREIGN {
                return None;
            }
            match rest.split_whitespace().collect::<Vec<_>>().as_slice() {
                ["from", "all", "to", dest, "lookup", _] => Some((*dest).to_string()),
                _ => None,
            }
        })
        .collect()
}

/// Delete our policy rules for one address family, ignoring "not found".
/// Each del names the full rule spec, mirroring the adds in
/// [`install_client_routing`], never the pref alone: `ip rule del` removes the
/// first rule matching only the keys given, so a bare `del pref 100` would
/// destroy a foreign rule (another VPN's, systemd-networkd's) that happens to
/// sit at one of our preference numbers.
#[cfg(target_os = "linux")]
pub(super) fn remove_client_rules(family: &str, sweep: RuleSweep) {
    // Source rules are removed by reading back what is actually installed, not by
    // re-deriving the address list: a lease change between install and teardown
    // would otherwise strand a rule pointing at an address we no longer hold. Only
    // rules matching our exact shape at our pref are touched.
    for addr in installed_source_rules(family) {
        let _ = run_ip(&[
            family, "rule", "del", "from", &addr, "table", "main", "pref", PREF_SRC,
        ]);
    }
    // One rule, deleted by its full spec, so this needs no readback at all.
    // While it was a rule per mirrored prefix it did, and that readback carried
    // the same bug `parse_catch_all` had: `ip rule show` prints a table *name*
    // where `/etc/iproute2/rt_tables` maps our id, and a rule whose table did not
    // match the numeric string was left behind to accumulate on every re-apply.
    let _ = run_ip(&foreign_rule_args(family, "del"));
    // Then whatever the *old* shape left behind. Kernel rules outlive the process
    // and the panic hook `abort()`s, so a host that ran a build with the per-prefix
    // rules and then swapped the binary keeps them: the del above names a spec they
    // do not match, and nothing else looks at pref 98 any more. A stranded
    // `to <prefix> lookup 29793` outlives the mirrored route it depends on, and
    // once the co-resident VPN drops that prefix it sends those destinations to the
    // tunnel default sitting in the same table, which is the exact failure the
    // single-rule form was meant to make impossible.
    //
    // By pref alone, which the comment above warns against for every other rule,
    // and safe only here: `remove_stray_rules` deletes only rules that look like
    // the shape we used to install, so a foreign rule parked at 98 is left alone.
    for stray in strays_at_our_pref(family) {
        let _ = run_ip(&[
            family,
            "rule",
            "del",
            "to",
            &stray,
            "table",
            EXIT_TABLE,
            "pref",
            PREF_FOREIGN,
        ]);
    }
    let prefix = if family == "-4" {
        ipv4::SERVER_PREFIX
    } else {
        V6_OVERLAY
    };
    let _ = run_ip(&[
        family, "rule", "del", "to", prefix, "table", "main", "pref", PREF_MAIN,
    ]);
    let mark = format!("{SOCKET_MARK:#x}");
    let _ = run_ip(&[
        family,
        "rule",
        "del",
        "fwmark",
        &mark,
        "table",
        "main",
        "pref",
        PREF_BYPASS,
    ]);
    let _ = run_ip(&[
        family,
        "rule",
        "del",
        "table",
        "main",
        "suppress_prefixlength",
        "0",
        "pref",
        PREF_MAIN,
    ]);
    if sweep == RuleSweep::All {
        let _ = run_ip(&[
            family,
            "rule",
            "del",
            "table",
            EXIT_TABLE,
            "pref",
            PREF_TUNNEL,
        ]);
    }
}

/// `ip <args>` stdout, or `None` when it could not be run or failed. The read-only
/// counterpart to [`run_ip`], which reports the failure instead.
#[cfg(target_os = "linux")]
pub(super) fn ip_output(args: &[&str]) -> Option<String> {
    let out = Command::new("ip").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// nft script fragment that removes `table`, whether or not it exists: `delete
/// table` alone fails when absent, so create it first. Prefixed to an install to
/// make it a wholesale replace.
#[cfg(target_os = "linux")]
pub(super) fn drop_table(table: &str) -> String {
    format!("table inet {table}\ndelete table inet {table}\n")
}

#[cfg(target_os = "linux")]
pub(super) fn nft_load(script: &str) -> Result<()> {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `nft -f -`")?;
    child
        .stdin
        .take()
        .context("nft stdin unavailable")?
        .write_all(script.as_bytes())
        .context("writing nft script")?;
    let out = child.wait_with_output().context("waiting for nft")?;
    if !out.status.success() {
        anyhow::bail!(
            "nft ruleset load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn run_ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("running `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        anyhow::bail!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The sysctl's current value, or `""` if it can't be read (then it is not
/// restored on teardown).
#[cfg(target_os = "linux")]
pub(super) fn read_sysctl(path: &str) -> String {
    fs::read_to_string(format!("/proc/sys/{path}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
pub(super) fn write_sysctl(path: &str, value: &str) -> Result<()> {
    fs::write(format!("/proc/sys/{path}"), value)
        .with_context(|| format!("writing sysctl {path}={value}"))
}

fn remove_ipv4_client_address() {
    let Ok(dir) = crate::config::config_dir() else {
        return;
    };
    let path = dir.join("exit-ipv4-client-interface");
    if let Ok(tun) = fs::read_to_string(&path) {
        let _ = run_ip(&[
            "-4",
            "addr",
            "del",
            &format!("{}/32", ipv4::CLIENT_ADDR),
            "dev",
            tun.trim(),
        ]);
        let _ = fs::remove_file(path);
    }
}

/// Do not take an address or a specific route from another interface or VPN.
fn ensure_ipv4_routes_available(tun_name: &str, space: ipv4::AddressSpace) -> Result<()> {
    let routes = ip_output(&["-4", "route", "show", "table", "all"])
        .context("read IPv4 routes before installing exit routing")?;
    for line in routes.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.windows(2).any(|pair| pair == ["dev", tun_name]) {
            continue;
        }
        for field in fields.iter().take(2) {
            if ipv4::conflicts_with_route(field, space) {
                anyhow::bail!("IPv4 exit address space overlaps an existing route: {line}");
            }
        }
    }
    Ok(())
}
