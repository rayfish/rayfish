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
    /// Destinations another VPN's own table owns -> our table, where
    /// `mirror_foreign_routes` put a copy of its route. Above `PREF_SRC` because
    /// the two rules below it both look up `main`, which is exactly the table a
    /// policy-routing VPN does *not* keep its prefixes in: without this, that
    /// VPN's traffic reaches `main`, misses, and takes main's default out the
    /// physical uplink. The mirror alone only rescues the `PREF_TUNNEL` path.
    pub(in crate::exit_node) const PREF_FOREIGN: &str = "98";
    pub(in crate::exit_node) const PREF_SRC: &str = "99"; // physical-sourced traffic -> main table
    pub(in crate::exit_node) const PREF_BYPASS: &str = "100"; // marked traffic -> main table
    pub(in crate::exit_node) const PREF_MAIN: &str = "101"; // main table minus its default route
    pub(in crate::exit_node) const PREF_TUNNEL: &str = "102"; // everything else -> the tunnel
}
#[cfg(target_os = "linux")]
pub(super) use names::*;

pub(super) use crate::sysctl::{ipv6_conf, read_sysctl, write_sysctl};

#[cfg(target_os = "linux")]
use crate::hostfw;

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
/// A host firewall that drops forwarding (ufw, firewalld, Docker's ip6tables
/// policy) cannot be overridden from our own table (an `accept` ends only the chain
/// it is in, never another chain's drop), so [`forward_fw::allow`] puts two accepts
/// for the TUN at the top of the chain that drops, the way Tailscale does. Where
/// that fails the warning names the command for the firewall in charge.
///
/// Turning on `all/forwarding` also makes the kernel ignore router advertisements
/// on every interface left at `accept_ra=1`, so a host that learned its IPv6
/// default route from one would lose it when the route expires, and with it the
/// uplink the exit node exists to provide. Those interfaces are raised to
/// `accept_ra=2` first (accept RAs even while forwarding) and put back on
/// teardown. A host that was already forwarding had chosen to ignore RAs, so it is
/// left alone.
///
/// Idempotent, and safe to re-run while already enabled: the prior sysctl values
/// are snapshotted to disk exactly once (a re-apply must not capture the values we
/// set ourselves), and the nft ruleset is replaced wholesale. That same file is
/// what [`disable`] restores from, including when it runs from the panic hook, so a
/// crash can never leave the host acting as an open router. Writing it is therefore
/// a precondition, not a nicety: without it we could turn forwarding on and never
/// be able to put it back, so we refuse instead. Linux only.
///
/// IPv4 transit is optional. It needs an IPv4 uplink (`v4_uplink`) and the lease
/// pool routed to the TUN, and a host route overlapping the pool leaves it off.
/// Without both, `ip_forward` stays at its original value: turning it on would
/// make the host an IPv4 router between all of its interfaces for a family it
/// does not carry. Returns whether IPv4 transit is on.
#[cfg(target_os = "linux")]
pub(super) fn enable(tun_name: &str, v4_uplink: bool) -> Result<bool> {
    let path = snapshot_path().context("no config dir to snapshot the forwarding sysctls into")?;
    let mut snap = if path.exists() {
        Snapshot::load(&path)
    } else {
        let snap = Snapshot {
            v4: String::new(),
            v6: read_sysctl(V6_FORWARD),
            pf_token: None,
            tun_name: Some(tun_name.to_owned()),
            // Writing `all/forwarding` sets every interface's own value, so
            // restoring `all` alone would flatten whatever they held before.
            extra: interface_forwarding(),
        };
        snap.save(&path)?;
        snap
    };
    if snap.v6 != "1" {
        keep_accepting_ras(tun_name, &mut snap, &path)?;
    }
    let v4_pool = v4_uplink
        && match read_ipv4_routes()
            .and_then(|routes| ensure_ipv4_routes_available(&routes, tun_name))
        {
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
                false
            }
        };
    if !v4_pool {
        let _ = run_ip(&["-4", "route", "del", ipv4::SERVER_PREFIX, "dev", tun_name]);
    }
    // A re-apply after the pool lost its route or the uplink went away puts
    // back whatever this host had before we first turned it on.
    snap.set_v4_forwarding(&path, v4_pool)?;
    write_sysctl(V6_FORWARD, "1")?;
    nft_load(&server_nft_ruleset(tun_name))?;
    let report = forward_fw::allow(tun_name);
    if let Some(fix) = &report.manual_fix {
        tracing::warn!(
            tun = tun_name,
            fix,
            "the host firewall drops forwarded traffic and rayfish could not add an \
             exception, so exit-node clients will get no replies until you run the fix"
        );
    }
    tracing::info!(
        tun = tun_name,
        v4_pool,
        "exit node forwarding + NAT enabled"
    );
    Ok(v4_pool)
}

/// Re-add the host-firewall forwarding exceptions a firewall reload dropped, for
/// the periodic kernel check once [`check_kernel_state`] said they need it. Only
/// a debug line when they cannot be added: [`enable`] already warned with the fix.
#[cfg(target_os = "linux")]
pub fn reassert_forward_firewall(tun_name: &str) {
    let dumps = forward_fw::ForwardDumps::read(hostfw::run(&forward_fw::NFT_RULESET));
    if let Some(fix) = forward_fw::reassert(tun_name, &dumps) {
        tracing::debug!(fix, "host firewall still drops exit-node forwarding");
    }
}

/// What one pass of the periodic kernel check found missing.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct KernelCheck {
    /// The gateway's forwarding sysctl or nft table.
    pub gateway: bool,
    /// The client full tunnel's table, rules or default route.
    pub client: bool,
    /// The host-firewall forwarding exceptions (see [`reassert_forward_firewall`]).
    pub forward_firewall: bool,
}

#[cfg(target_os = "linux")]
impl KernelCheck {
    pub fn is_clean(&self) -> bool {
        !self.gateway && !self.client && !self.forward_firewall
    }

    /// The roles to re-apply, for the log line.
    pub fn missing(&self) -> Vec<&'static str> {
        [(self.gateway, "gateway"), (self.client, "client tunnel")]
            .into_iter()
            .filter_map(|(gone, name)| gone.then_some(name))
            .collect()
    }
}

/// Read what the gateway (when `serving`) and the client tunnel (when `using`)
/// need from the kernel, changing nothing. One `nft list ruleset` answers for
/// both tables and the forwarding exceptions.
#[cfg(target_os = "linux")]
pub fn check_kernel_state(serving: bool, using: bool, tun_name: &str) -> KernelCheck {
    let ruleset = hostfw::run(&forward_fw::NFT_RULESET);
    let mut check = KernelCheck::default();
    if using {
        check.client = !client_state_intact(ruleset.as_deref());
    }
    if serving {
        check.gateway = !server_state_intact(ruleset.as_deref());
        check.forward_firewall = !check.gateway
            && forward_fw::needs_reassert(tun_name, &forward_fw::ForwardDumps::read(ruleset));
    }
    check
}

/// Every interface's own IPv6 `forwarding` value (and `default`'s), for the
/// snapshot. `all` is left out: it is the snapshot's `v6`.
#[cfg(target_os = "linux")]
fn interface_forwarding() -> Vec<SavedSysctl> {
    ipv6_conf_interfaces()
        .into_iter()
        .filter(|name| name != "all")
        .filter_map(|name| {
            let path = ipv6_conf(&name, "forwarding");
            let value = read_sysctl(&path);
            (!value.is_empty()).then_some(SavedSysctl { path, value })
        })
        .collect()
}

/// The entries of `/proc/sys/net/ipv6/conf`: every interface plus `all` and
/// `default`. Empty when IPv6 is disabled.
#[cfg(target_os = "linux")]
fn ipv6_conf_interfaces() -> Vec<String> {
    let Ok(dir) = fs::read_dir("/proc/sys/net/ipv6/conf") else {
        return Vec::new();
    };
    dir.filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect()
}

/// Raise `accept_ra` from 1 to 2 on every interface that has it, recording the
/// original in the snapshot (and saving it) before the write. See [`enable`].
///
/// Runs on every enable, not just the first, so an interface that appeared or was
/// reset since is covered too; one already recorded is not recorded twice.
#[cfg(target_os = "linux")]
fn keep_accepting_ras(tun_name: &str, snap: &mut Snapshot, path: &Path) -> Result<()> {
    let current: Vec<(String, String)> = ipv6_conf_interfaces()
        .into_iter()
        .map(|name| {
            let value = read_sysctl(&accept_ra_path(&name));
            (name, value)
        })
        .collect();
    // The values from before we turned `all/forwarding` on, which rewrote
    // every interface's own: on a re-enable the live ones all read 1.
    let forwarding: Vec<String> = current
        .iter()
        .filter(|(name, _)| {
            let own = ipv6_conf(name, "forwarding");
            snap.extra.iter().any(|s| s.path == own && s.value == "1")
        })
        .map(|(name, _)| name.clone())
        .collect();
    let raise = ra_interfaces_to_raise(&current, tun_name, &forwarding);
    if raise.is_empty() {
        return Ok(());
    }
    for name in &raise {
        let path = accept_ra_path(name);
        if !snap.extra.iter().any(|s| s.path == path) {
            snap.extra.push(SavedSysctl {
                path,
                value: "1".to_string(),
            });
        }
    }
    snap.save(path)?;
    for name in &raise {
        if let Err(e) = write_sysctl(&accept_ra_path(name), "2") {
            tracing::warn!(interface = %name, error = %e, "could not keep accepting router advertisements");
        }
    }
    tracing::warn!(
        interfaces = %raise.join(","),
        "IPv6 forwarding makes the kernel ignore router advertisements on these \
         interfaces; set accept_ra=2 so their RA-learned routes survive (restored \
         when the exit node is turned off)"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn accept_ra_path(name: &str) -> String {
    ipv6_conf(name, "accept_ra")
}

/// Which of `(interface, accept_ra)` need raising to 2: those at exactly 1,
/// other than the `all`/`default` templates, loopback, our own TUN, and the
/// ones in `forwarding`, which were already forwarding on their own and so had
/// already chosen to ignore RAs.
#[cfg(target_os = "linux")]
pub(super) fn ra_interfaces_to_raise(
    current: &[(String, String)],
    tun_name: &str,
    forwarding: &[String],
) -> Vec<String> {
    current
        .iter()
        .filter(|(name, value)| {
            value == "1"
                && !matches!(name.as_str(), "all" | "default" | "lo")
                && name != tun_name
                && !forwarding.contains(name)
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Whether the gateway's kernel state is still what [`enable`] left: forwarding on
/// and our table loaded. A firewall reload or `nft flush ruleset` removes the
/// table, and with it the masquerade, without telling us.
#[cfg(target_os = "linux")]
fn server_state_intact(ruleset: Option<&str>) -> bool {
    read_sysctl(V6_FORWARD) == "1" && nft_table_exists(ruleset, SERVER_TABLE)
}

/// Whether the client full tunnel is still installed: our nft table, and for each
/// family, the bypass and catch-all rules and the tunnel table's default route.
#[cfg(target_os = "linux")]
fn client_state_intact(ruleset: Option<&str>) -> bool {
    nft_table_exists(ruleset, CLIENT_TABLE)
        && ["-4", "-6"].iter().all(|family| {
            ip_output(&[family, "rule", "show"]).is_some_and(|show| client_rules_present(&show))
                && ip_output(&[family, "route", "show", "table", EXIT_TABLE])
                    .is_some_and(|routes| routes.lines().any(|l| l.starts_with("default")))
        })
}

/// Whether `ip rule show` output still has the rules the tunnel cannot work
/// without: the mark bypass, the `main` lookup, and the catch-all.
#[cfg(target_os = "linux")]
pub(super) fn client_rules_present(show: &str) -> bool {
    let mark = fwmark_selector();
    let at = |pref: &str, want: &[&str]| {
        show.lines().any(|line| {
            line.split_once(':').is_some_and(|(p, rest)| {
                let f: Vec<&str> = rest.split_whitespace().collect();
                p.trim() == pref && f == want
            })
        })
    };
    at(
        PREF_BYPASS,
        &["from", "all", "fwmark", &mark, "lookup", "main"],
    ) && at(
        PREF_MAIN,
        &[
            "from",
            "all",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
        ],
    ) && parse_catch_all(show)
}

/// Whether `ruleset` (`nft -j list ruleset` output) has our `inet` table.
/// Without a readable JSON dump (a failed run, or an `nft` built without JSON
/// support) that is unknown rather than no, so ask `nft list table` instead:
/// reading it as missing would re-apply the rules on every check.
#[cfg(target_os = "linux")]
fn nft_table_exists(ruleset: Option<&str>, table: &str) -> bool {
    nft_table_exists_with(ruleset, table, || {
        hostfw::run(&["nft", "list", "table", "inet", table]).is_some()
    })
}

#[cfg(target_os = "linux")]
pub(super) fn nft_table_exists_with(
    ruleset: Option<&str>,
    table: &str,
    listed: impl FnOnce() -> bool,
) -> bool {
    match ruleset.filter(|json| forward_fw::nft_json_readable(json)) {
        Some(json) => forward_fw::nft_has_table(json, "inet", table),
        None => listed(),
    }
}

/// The largest TCP MSS that fits the 1280-byte TUN: its MTU less the IPv6 and
/// TCP headers.
#[cfg(target_os = "linux")]
pub(super) const TUN_MSS: u16 = crate::tun::MIN_TUN_MTU - 40 - 20;

/// The nftables ruleset masquerading overlay traffic out of `tun_name`'s host.
///
/// IPv4 transit arrives sourced from the lease pool ([`ipv4::SERVER_PREFIX`]),
/// which the forwarder writes after authenticating the peer. The `transit` chain
/// marks both families with [`SOCKET_MARK`], so a gateway that also uses an exit
/// of its own sends its clients' traffic out the physical uplink rather than into
/// its own tunnel.
///
/// The `forward` chain clamps the MSS of TCP SYNs crossing the TUN, in both
/// directions, to [`TUN_MSS`]. The TUN is 1280 (see `tun::PREFERRED_TUN_MTU`),
/// narrower than the 1500-byte path a remote or a mesh client usually has, and
/// a remote that drops the ICMPv6 Packet Too Big would otherwise stall every
/// full-sized segment. `rt mtu` is no good here: for a SYN arriving from the
/// TUN it reads the uplink's route, typically 1500, so a 1500-MTU client's MSS
/// of 1440 would pass. The fixed ceiling holds for either direction, since no
/// IPv6 uplink is narrower than 1280.
///
/// The same chain refuses flows that start outside the TUN and head for a
/// client. The pool route makes every lease reachable from the uplink's
/// segment, and a client's mesh rules judge such a packet as the gateway's own,
/// so only replies to masqueraded flows may cross into the TUN.
#[cfg(target_os = "linux")]
pub(super) fn server_nft_ruleset(tun_name: &str) -> String {
    format!(
        "{reset}\
         table inet {t} {{\n\
         \tchain transit {{\n\
         \t\ttype filter hook prerouting priority mangle; policy accept;\n\
         \t\tiifname \"{tun}\" ip saddr {v4} meta mark set meta mark | {mark}\n\
         \t\tiifname \"{tun}\" ip6 saddr {v6} meta mark set meta mark | {mark}\n\
         \t}}\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tiifname \"{tun}\" ip saddr {v4} oifname != \"{tun}\" masquerade\n\
         \t\tiifname \"{tun}\" ip6 saddr {v6} oifname != \"{tun}\" masquerade\n\
         \t}}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority mangle; policy accept;\n\
         \t\tiifname \"{tun}\" tcp flags & (syn | rst) == syn tcp option maxseg size > {mss} tcp option maxseg size set {mss}\n\
         \t\toifname \"{tun}\" tcp flags & (syn | rst) == syn tcp option maxseg size > {mss} tcp option maxseg size set {mss}\n\
         \t\tiifname != \"{tun}\" oifname \"{tun}\" ip daddr {v4} ct direction original drop\n\
         \t\tiifname != \"{tun}\" oifname \"{tun}\" ip6 daddr {v6} ct direction original drop\n\
         \t}}\n\
         }}\n",
        reset = drop_table(SERVER_TABLE),
        t = SERVER_TABLE,
        v6 = V6_OVERLAY,
        v4 = ipv4::SERVER_PREFIX,
        mark = format_args!("{SOCKET_MARK:#x}"),
        tun = tun_name,
        mss = TUN_MSS,
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
    forward_fw::remove();
    let _ = fs::remove_file(&path);
    tracing::info!("exit node forwarding + NAT disabled");
}

/// Whether a local address should get a "leave via the physical uplink" rule at
/// [`PREF_SRC`]. True for the host's own globally-routable addresses; false for the
/// overlay (traffic entering the TUN is sourced from there, and bypassing the tunnel
/// for it would leak exactly what the tunnel is meant to carry) and for addresses
/// that never leave the host.
#[cfg(target_os = "linux")]
pub(super) fn is_bypass_source(addr: IpAddr) -> bool {
    if crate::membership::is_overlay_ip(addr)
        || matches!(addr, IpAddr::V4(v4) if crate::membership::is_cgnat_range(v4) || v4 == ipv4::CLIENT_ADDR)
    {
        return false;
    }
    match addr {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                // Link-local fe80::/10: no `is_unicast_link_local` on stable.
                && (v6.segments()[0] & 0xffc0 != 0xfe80)
        }
    }
}

/// The host's own addresses that need a source rule: everything [`is_bypass_source`]
/// accepts, read from `ip -o addr show scope global`. Read fresh at install time,
/// because which addresses exist is exactly what a DHCP lease or a new interface
/// changes between one `exit-node use` and the next.
#[cfg(target_os = "linux")]
pub(super) fn bypass_source_addrs(family: &str) -> Vec<IpAddr> {
    let out = match Command::new("ip")
        .args([family, "-o", "addr", "show", "scope", "global"])
        .output()
    {
        Ok(out) if out.status.success() => out.stdout,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3))
        .filter_map(|cidr| cidr.split('/').next()?.parse::<IpAddr>().ok())
        .filter(|addr| is_bypass_source(*addr))
        .collect()
}

/// The client-side nftables table.
///
/// **Conntrack marks** keep connections that reached this host from *outside*
/// the tunnel answering out the interface they arrived on, so a headless box does
/// not cut itself off the instant it starts using an exit node. `prerouting` tags
/// connections arriving on a non-TUN interface for this host (and marks the packet
/// itself, so the reverse-path check resolves against `main`); `output` puts that
/// mark back on the locally-generated replies, and `type route` forces a re-route
/// once it is set.
///
/// Every mark is OR'd in and matched under a mask, never assigned: other tools
/// (wg-quick, Mullvad, kube-proxy) keep their own bits in the same mark, and
/// overwriting them breaks their routing. `fib daddr type local` keeps forwarded
/// traffic (containers, VMs) out of it: that is not a connection to this host, and
/// marking it would send it around the tunnel. `output` only touches packets
/// without a mark of their own, because a socket that sets one (a WireGuard
/// socket, say) is matched exactly by its owner's rules and must reach them as it
/// was sent.
///
/// This covers connections that arrive *after* the tunnel is up. Ones that predate
/// it cannot be handled here: loading this table is what loads conntrack, so at
/// that instant they are untracked, and the first packet conntrack sees on them is
/// our own outgoing reply, which registers the entry with its direction inverted.
/// The [`PREF_SRC`] source rules in [`install_client_routing`] route those, and the
/// guard lets them through because it only refuses new flows.
///
/// **The guard** is what keeps a selected exit failing closed when the routing
/// does not hold: our rules flushed by a network manager, or another VPN's rule
/// ranked above ours taking the default. It refuses to *start* a flow to a public
/// destination outside the tunnel, and lets everything else through: the TUN and
/// loopback, our marked transport, replies, mid-flow TCP (connections that predate
/// the tunnel), link configuration, and every destination in `local`, which holds
/// the special-purpose ranges and whatever this host or a co-resident VPN routes
/// on purpose (see [`guarded_exceptions`]). Both base chains are `policy accept`
/// and only drop: a packet that is not starting a public flow is never touched.
#[cfg(target_os = "linux")]
pub(super) fn client_nft_script(tun_name: &str, local: &GuardExceptions) -> String {
    let mark = format!("{SOCKET_MARK:#x}");
    let set = |prefixes: &[String]| prefixes.join(", ");
    let mut guard = String::new();
    if !local.v4.is_empty() {
        guard.push_str(&format!("\t\tip daddr {{ {} }} return\n", set(&local.v4)));
    }
    if !local.v6.is_empty() {
        guard.push_str(&format!("\t\tip6 daddr {{ {} }} return\n", set(&local.v6)));
    }
    format!(
        "{reset}\
         table inet {t} {{\n\
         \tchain prerouting {{\n\
         \t\ttype filter hook prerouting priority mangle; policy accept;\n\
         \t\tiifname \"{tun}\" return\n\
         \t\tfib daddr type local ct mark set ct mark | {mark}\n\
         \t\tfib daddr type local meta mark set meta mark | {mark}\n\
         \t}}\n\
         \tchain output {{\n\
         \t\ttype route hook output priority mangle; policy accept;\n\
         \t\tmeta mark == 0 ct mark & {mark} == {mark} meta mark set meta mark | {mark}\n\
         \t}}\n\
         \tchain guard {{\n\
         \t\toifname {{ \"lo\", \"{tun}\" }} return\n\
         \t\tmeta mark & {mark} == {mark} return\n\
         \t\tct direction reply return\n\
         \t\tct mark & {mark} == {mark} return\n\
         \t\tudp sport 68 udp dport 67 return\n\
         \t\tudp sport 546 udp dport 547 return\n\
         \t\ticmpv6 type {{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} return\n\
         {guard}\
         \t\ttcp flags & (syn | ack) != syn return\n\
         \t\tct state new drop\n\
         \t}}\n\
         \tchain guard_output {{\n\
         \t\ttype filter hook output priority filter; policy accept;\n\
         \t\tjump guard\n\
         \t}}\n\
         \tchain guard_forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tjump guard\n\
         \t}}\n\
         }}\n",
        reset = drop_table(CLIENT_TABLE),
        t = CLIENT_TABLE,
        tun = tun_name,
    )
}

/// The metric of the `unreachable default` behind the tunnel's own default in
/// [`EXIT_TABLE`]: the largest there is, so it only answers when ours is gone.
#[cfg(target_os = "linux")]
const FALLBACK_METRIC: &str = "4294967295";

/// Destinations the guard in [`client_nft_script`] never blocks, one list per
/// family, each already free of overlapping prefixes (nft refuses a set whose
/// intervals overlap).
#[cfg(target_os = "linux")]
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct GuardExceptions {
    pub(super) v4: Vec<String>,
    pub(super) v6: Vec<String>,
}

/// What the guard lets through: [`NON_INTERNET_V4`]/[`NON_INTERNET_V6`] plus every prefix a
/// routing table here names besides a default, read from `ip route show table
/// all`. That is the on-link subnets (a LAN on public IPv6 addresses), static
/// routes, and the prefixes a co-resident VPN serves: the destinations the
/// routing rules already send around the tunnel, which the guard must agree with.
///
/// Read at install, so a prefix that appears later is blocked until the next
/// apply, unless it falls in the fixed ranges, which cover the usual LAN.
#[cfg(target_os = "linux")]
pub(super) fn guarded_exceptions(routes: &RouteTables, tun_name: &str) -> GuardExceptions {
    let read = |show: Option<&str>, fixed: &[&str]| {
        let mut prefixes: Vec<String> = fixed.iter().map(|p| (*p).to_string()).collect();
        if let Some(show) = show {
            prefixes.extend(parse_routed_prefixes(show, tun_name));
        }
        merge_prefixes(prefixes)
    };
    GuardExceptions {
        v4: read(routes.v4.as_deref(), &NON_INTERNET_V4),
        v6: read(routes.v6.as_deref(), &NON_INTERNET_V6),
    }
}

/// `ip route show table all` per family, read once per install and shared by
/// the guard and the foreign-route mirror. `None` where the read failed.
#[cfg(target_os = "linux")]
pub(super) struct RouteTables {
    v4: Option<String>,
    v6: Option<String>,
}

#[cfg(target_os = "linux")]
impl RouteTables {
    fn read() -> Self {
        Self {
            v4: ip_output(&["-4", "route", "show", "table", "all"]),
            v6: ip_output(&["-6", "route", "show", "table", "all"]),
        }
    }

    fn family(&self, family: &str) -> Option<&str> {
        if family == "-4" { &self.v4 } else { &self.v6 }.as_deref()
    }
}

/// The unicast, non-default destinations in `ip route show` output, other than
/// our own TUN's and our own table's.
#[cfg(target_os = "linux")]
pub(super) fn parse_routed_prefixes(show: &str, tun_name: &str) -> Vec<String> {
    show.lines()
        .filter(|line| !line.starts_with([' ', '\t']))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let dest = *fields.first()?;
            let after = |key: &str| {
                fields
                    .iter()
                    .position(|f| *f == key)
                    .and_then(|i| fields.get(i + 1))
                    .copied()
            };
            if after("dev") == Some(tun_name) || after("table") == Some(EXIT_TABLE) {
                return None;
            }
            // `default`, and typed routes (`local`, `broadcast`, `unreachable`)
            // that lead with their type, are not a prefix to let through.
            let (addr, len) = match dest.split_once('/') {
                Some((addr, len)) => (addr, Some(len)),
                None => (dest, None),
            };
            let addr: IpAddr = addr.parse().ok()?;
            let full = if addr.is_ipv4() { 32 } else { 128 };
            let len: u8 = len.map_or(Some(full), |l| l.parse().ok())?;
            Some(format!("{addr}/{len}"))
        })
        .collect()
}

/// `prefixes` with every one that another contains removed, and duplicates
/// dropped. Entries that do not parse are dropped too.
#[cfg(target_os = "linux")]
pub(super) fn merge_prefixes(prefixes: Vec<String>) -> Vec<String> {
    let parsed: Vec<(IpAddr, u8)> = prefixes
        .iter()
        .filter_map(|p| {
            let (addr, len) = p.split_once('/')?;
            Some((addr.parse().ok()?, len.parse().ok()?))
        })
        .collect();
    let mut kept: Vec<(IpAddr, u8)> = Vec::new();
    for (i, &(addr, len)) in parsed.iter().enumerate() {
        let covered = parsed.iter().enumerate().any(|(j, &(other, other_len))| {
            j != i && prefix_contains(other, other_len, addr, len) && (other_len < len || j < i)
        });
        if !covered {
            kept.push((addr, len));
        }
    }
    kept.iter()
        .map(|(addr, len)| format!("{addr}/{len}"))
        .collect()
}

/// Whether `outer/outer_len` contains `inner/inner_len`. Different families
/// never contain each other.
#[cfg(target_os = "linux")]
fn prefix_contains(outer: IpAddr, outer_len: u8, inner: IpAddr, inner_len: u8) -> bool {
    // Left-align both families in a u128, so one mask works for either.
    let bits = |addr: IpAddr| match addr {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)) << 96, 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    };
    let ((outer, width), (inner, inner_width)) = (bits(outer), bits(inner));
    if width != inner_width || outer_len > inner_len || outer_len > width {
        return false;
    }
    let mask = u128::MAX
        .checked_shl(128 - u32::from(outer_len))
        .unwrap_or(0);
    outer & mask == inner & mask
}

/// Install the client full-tunnel: route all non-mesh traffic through the TUN, and
/// keep two classes of traffic out of it.
///
/// A `default` route into `<tun>` lives in a dedicated table [`EXIT_TABLE`]; three
/// `ip rule`s then select it: packets marked with [`SOCKET_MARK`] go to `main` and
/// egress normally; `main`'s specific routes (LAN, connected, the overlay ranges)
/// still win via `suppress_prefixlength 0`; everything else falls to the tunnel
/// table.
///
/// Two things carry the mark. **iroh's own underlay sockets** set it directly
/// (`SO_MARK`), without which the node's transport would be routed into the tunnel
/// it is itself carrying and the link would deadlock. And an nftables `conntrack`
/// pair marks **connections that arrived from outside the tunnel**, restoring the
/// mark on their replies: without it, the replies of an inbound connection (an SSH
/// session to this host's public IP, say) would egress via the exit node and get
/// masqueraded to *its* address, so the peer would see answers from a stranger and
/// the connection would die the moment the tunnel came up.
///
/// Idempotent (routes use `replace`, rules are deleted before re-adding, the nft
/// table is replaced wholesale). Linux only.
///
/// Both families go into the tunnel whatever the gateway carries, so a family it
/// cannot return is dropped at the forwarder rather than leaving directly.
#[cfg(target_os = "linux")]
pub fn install_client_routing(tun_name: &str) -> Result<()> {
    // The client table loads first: nothing routes into the tunnel until the
    // `ip rule`s below go in, but the moment they do, an inbound connection's
    // replies depend on this table already restoring the mark. Loading it after
    // the rules would open a window (or, on a mid-way failure, a permanent state)
    // where an SSH session to this host's public IP is routed into the tunnel and
    // cut. The routes are read before our own go in; the address and routes
    // added below are on the TUN or in our table, which every reader skips.
    let routes = RouteTables::read();
    nft_load(&client_nft_script(
        tun_name,
        &guarded_exceptions(&routes, tun_name),
    ))?;
    run_ip(&[
        "-4",
        "addr",
        "replace",
        &format!("{}/32", ipv4::CLIENT_ADDR),
        "dev",
        tun_name,
    ])?;
    for family in ["-4", "-6"] {
        // Give the tunnel table the prefixes another VPN serves out of a table of
        // its own, or our catch-all rule swallows them (see the fn docs).
        let mirrored = routes
            .family(family)
            .map_or(0, |show| mirror_foreign_routes(family, show, tun_name));
        let mut default = argv(&[
            "route", "replace", "default", "dev", tun_name, "table", EXIT_TABLE,
        ]);
        if family == "-4" {
            default.extend(["src".to_string(), ipv4::CLIENT_ADDR.to_string()]);
        }
        // Behind the tunnel default, so a lookup that loses it (the TUN went
        // away, or someone flushed its route) stops here instead of falling
        // through to `main`'s default and leaving directly.
        let fallback = argv(&[
            "route",
            "replace",
            "unreachable",
            "default",
            "metric",
            FALLBACK_METRIC,
            "table",
            EXIT_TABLE,
        ]);
        run_ip_batch(family, &[default, fallback], false)?;
        // Keeps the catch-all standing: everything below is a rebuild, deleted
        // and re-added in two `ip` processes. See [`RuleSweep`].
        remove_client_rules(family, RuleSweep::KeepCatchAll);
        // The three bypasses go back **first**, because the catch-all now stays up
        // across the rebuild. That closed the window where traffic leaked out the
        // physical uplink, and it opened a worse one in the other direction: with
        // the catch-all standing and these three gone, the highest-priority rule
        // matching anything is ours, so for the length of the rebuild the daemon's
        // own QUIC underlay is routed into the tunnel it is carrying, along with
        // every pre-existing physical-sourced connection. That is precisely what
        // `PREF_BYPASS` and `PREF_SRC` exist to prevent, and it kills the mesh
        // rather than leaking past it. So they go in as one `ip -batch` process,
        // which shrinks the window to the netlink round trips themselves.
        //
        // Ahead of everything else: traffic sourced from one of this host's own
        // physical addresses leaves the way it always did. That is every connection
        // that existed before the tunnel, whose socket is already bound to that
        // address and cannot be re-bound. Without this they are routed into the
        // tunnel mid-flight and stall on retransmits until something inbound
        // arrives, which is minutes for an idle peer (an SSH session watching the
        // command that turned the tunnel on, for instance). The conntrack table
        // below cannot cover them: it is what *loads* conntrack, so those
        // connections are untracked at that moment and get registered with their
        // direction inverted. Traffic bound for the tunnel is sourced from the
        // overlay address instead, so it does not match.
        let mut adds: Vec<Vec<String>> = bypass_source_addrs(family)
            .into_iter()
            .map(|addr| {
                argv(&[
                    "rule",
                    "add",
                    "from",
                    &addr.to_string(),
                    "table",
                    "main",
                    "pref",
                    PREF_SRC,
                ])
            })
            .collect();
        adds.push(bypass_rule_args("add"));
        adds.push(argv(&[
            "rule",
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
            "pref",
            PREF_MAIN,
        ]));
        // The mirrored destinations, in one rule. It outranks the two `main`
        // rules above, because neither of them can find a co-resident VPN's
        // prefixes: those live in its own table, and `PREF_MAIN`'s
        // `suppress_prefixlength 0` only rescues routes that are in `main` to
        // begin with. Sending those destinations to our table instead hits the
        // copy `mirror_foreign_routes` just made, so they go back out the
        // interface that owned them.
        //
        // `suppress_prefixlength 0` is what keeps this to one rule rather than
        // one per prefix: the rule consults `EXIT_TABLE` and a match on a
        // prefix length of 0, our own default route, is suppressed, so the
        // lookup succeeds for exactly the mirrored prefixes and falls through
        // for everything else. Same trick as `PREF_MAIN`, pointed at our table
        // instead of `main`.
        //
        // It also makes the pairing with the mirror structural instead of
        // bookkept. The rule reads the routes rather than naming them, so it
        // cannot outlive one that failed to install and send its prefix to the
        // tunnel default sitting in the same table, and the count no longer
        // grows with the other VPN's route count.
        //
        // Safe to be last despite outranking them: until the rule lands, those
        // destinations still resolve through the catch-all into `EXIT_TABLE`,
        // where longest-prefix picks the mirrored route over our default. The
        // rule exists for the traffic that would otherwise stop at `PREF_SRC` or
        // `PREF_BYPASS` above and look up `main`.
        if mirrored > 0 {
            adds.push(argv(&foreign_rule_args(family, "add")[1..]));
        }
        run_ip_batch(family, &adds, false)?;
        // Only if the rebuild did not inherit it: `ip rule add` is not idempotent,
        // so adding it unconditionally would stack a duplicate on every re-apply,
        // and `remove_client_rules` deletes one match at a time. `EEXIST` is
        // tolerated rather than propagated: a false negative from the readback
        // (`ip rule show` prints a table *name* where `/etc/iproute2/rt_tables`
        // maps our id, or the command simply failed) would otherwise fail the
        // whole install, and the caller answers a failed install by tearing the
        // tunnel down. The rule being there already is the state we wanted.
        if !catch_all_installed(family)
            && let Err(e) = run_ip(&[
                family,
                "rule",
                "add",
                "table",
                EXIT_TABLE,
                "pref",
                PREF_TUNNEL,
            ])
        {
            if !is_already_exists(&e) {
                return Err(e);
            }
            tracing::debug!(family, "catch-all rule was already installed");
        }
    }
    tracing::info!(
        tun = tun_name,
        "exit-node client full-tunnel routing installed"
    );
    Ok(())
}

/// Remove the client full-tunnel policy routing installed by
/// [`install_client_routing`]: drop the rules, flush the tunnel table, remove the
/// conntrack-mark table. Best-effort and idempotent (the TUN going down also drops
/// its routes). `tun_name` is the TUN still carrying the client IPv4 address, or
/// `None` when the TUN dies with the process and takes the address along. Linux
/// only.
#[cfg(target_os = "linux")]
pub fn teardown_client_routing(tun_name: Option<&str>) {
    for family in ["-4", "-6"] {
        remove_client_rules(family, RuleSweep::All);
        let _ = run_ip(&[family, "route", "flush", "table", EXIT_TABLE]);
    }
    if let Some(tun) = tun_name {
        let address = format!("{}/32", ipv4::CLIENT_ADDR);
        let _ = run_ip(&["-4", "addr", "del", &address, "dev", tun]);
    }
    let _ = nft_load(&drop_table(CLIENT_TABLE));
    tracing::info!("exit-node client full-tunnel routing removed");
}

/// How much of our rule set [`remove_client_rules`] takes down.
///
/// Teardown wants [`RuleSweep::All`]. A re-install wants
/// [`RuleSweep::KeepCatchAll`], because the catch-all at [`PREF_TUNNEL`] is the
/// only thing standing between tunnel-bound traffic and `main`: drop it and every
/// packet leaves the physical uplink, sourced from this host's real address,
/// until the rebuild puts it back. That is not instant: the rules are deleted and
/// re-added by separate `ip` processes, and the mirrored routes that go in first are one process per
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
    let mut dels: Vec<Vec<String>> = installed_source_rules(family)
        .into_iter()
        .map(|addr| {
            argv(&[
                "rule", "del", "from", &addr, "table", "main", "pref", PREF_SRC,
            ])
        })
        .collect();
    // One rule, deleted by its full spec, so this needs no readback at all.
    // While it was a rule per mirrored prefix it did, and that readback carried
    // the same bug `parse_catch_all` had: `ip rule show` prints a table *name*
    // where `/etc/iproute2/rt_tables` maps our id, and a rule whose table did not
    // match the numeric string was left behind to accumulate on every re-apply.
    dels.push(argv(&foreign_rule_args(family, "del")[1..]));
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
        dels.push(argv(&[
            "rule",
            "del",
            "to",
            &stray,
            "table",
            EXIT_TABLE,
            "pref",
            PREF_FOREIGN,
        ]));
    }
    dels.push(bypass_rule_args("del"));
    // The unmasked spelling older builds installed. The kernel reads a del
    // with no mask as mask 0xffffffff, so it matches only that old rule and
    // never the masked one; each del removes its own spelling, in either
    // order, and the batch's `-force` keeps a miss from stopping the rest.
    let legacy_mark = format!("{SOCKET_MARK:#x}");
    dels.push(argv(&[
        "rule",
        "del",
        "fwmark",
        &legacy_mark,
        "table",
        "main",
        "pref",
        PREF_BYPASS,
    ]));
    dels.push(argv(&[
        "rule",
        "del",
        "table",
        "main",
        "suppress_prefixlength",
        "0",
        "pref",
        PREF_MAIN,
    ]));
    if sweep == RuleSweep::All {
        dels.push(argv(&[
            "rule",
            "del",
            "table",
            EXIT_TABLE,
            "pref",
            PREF_TUNNEL,
        ]));
    }
    // `-force` so one "not found" does not stop the rest; the exit status then
    // reports that some failed, which for a sweep is expected.
    let _ = run_ip_batch(family, &dels, true);
}

/// The `fwmark` selector of the [`PREF_BYPASS`] rule: our mark under its own
/// mask, so a packet that also carries another tool's bits still matches.
#[cfg(target_os = "linux")]
pub(super) fn fwmark_selector() -> String {
    format!("{SOCKET_MARK:#x}/{SOCKET_MARK:#x}")
}

/// The [`PREF_BYPASS`] rule for `ip -batch`, `verb` being `add` or `del`, so the
/// two spell it identically.
#[cfg(target_os = "linux")]
pub(super) fn bypass_rule_args(verb: &str) -> Vec<String> {
    argv(&[
        "rule",
        verb,
        "fwmark",
        &fwmark_selector(),
        "table",
        "main",
        "pref",
        PREF_BYPASS,
    ])
}

#[cfg(target_os = "linux")]
fn argv(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_string()).collect()
}

/// The stdin of `ip -batch -`: one command per line, without the leading `ip`
/// and without the family, which [`run_ip_batch`] passes once for all of them.
#[cfg(target_os = "linux")]
pub(super) fn batch_script(commands: &[Vec<String>]) -> String {
    commands.iter().map(|c| c.join(" ") + "\n").collect()
}

/// Run several `ip` commands in one process. Without `force`, `ip` stops at the
/// first failure and so does the result.
#[cfg(target_os = "linux")]
pub(super) fn run_ip_batch(family: &str, commands: &[Vec<String>], force: bool) -> Result<()> {
    use std::io::Write as _;
    use std::process::Stdio;
    if commands.is_empty() {
        return Ok(());
    }
    let mut args = vec![family];
    if force {
        args.push("-force");
    }
    args.extend(["-batch", "-"]);
    let mut child = Command::new("ip")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `ip -batch -`")?;
    child
        .stdin
        .take()
        .context("ip stdin unavailable")?
        .write_all(batch_script(commands).as_bytes())
        .context("writing ip batch")?;
    let out = child.wait_with_output().context("waiting for ip")?;
    if !out.status.success() {
        anyhow::bail!(
            "`ip {family} -batch` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// One route, as [`parse_foreign_routes`] reads it back off `ip route show`.
/// `spec` is the route minus its destination and its `table` clause, in the order
/// `ip` printed it, so re-emitting it is a matter of appending our own table.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct MirroredRoute {
    pub(super) dest: String,
    pub(super) spec: Vec<String>,
}

/// Copy into the tunnel table every prefix another VPN serves out of a routing
/// table of its own, so that VPN keeps working while our full tunnel is up.
///
/// [`PREF_TUNNEL`] is a catch-all, and it sits far above the preferences a peer
/// VPN uses (Tailscale's are 5210-5270), so once it is in, that VPN's own rules are
/// never reached. [`PREF_MAIN`] does not save them: `suppress_prefixlength 0` only
/// rescues routes in `main`, and a policy-routing VPN keeps its prefixes in a
/// private table (Tailscale's `100.64.0.0/10` and `fd7a:115c:a1e0::/48` live in
/// table 52). The result would be the co-resident VPN black-holed the moment we
/// route anything, which is precisely what leaving `100.64.0.0/10` alone buys.
///
/// Mirroring is one-directional: we only ever write our own table, never a foreign
/// rule or a foreign table, and the teardown flush drops the copies with the
/// default. Inside the table longest-prefix decides, so a mirrored `/48` beats our
/// own `default` without either needing to know about the other, and insertion
/// order is irrelevant.
///
/// Reconciled rather than merely added to: a prefix the other VPN has since
/// dropped is deleted here, so a re-apply cannot leave traffic pointed at a tunnel
/// that no longer claims it. Our own default is never touched, so there is no
/// moment where the table is empty and traffic leaks past the tunnel.
///
/// Deliberately broader than the case it is named for: every non-default route in
/// every non-main table is copied, whatever `ip rule` selectors reach that table.
/// A prefix another VPN serves only for certain source addresses, or a VRF's
/// table, becomes unconditional for our tunnel-bound traffic. That is the right
/// trade against black-holing those destinations outright, but it is a real
/// widening, so it is written down rather than implied: narrowing it would mean
/// mirroring only tables named by a selector-free rule, and treating everything
/// else as unreachable.
///
/// Best-effort throughout: this is an accommodation for someone else's routing, and
/// failing to read or write one route must not fail the install.
/// The `ip` arguments that copy one foreign route into [`EXIT_TABLE`].
///
/// Split out to be testable, because the ordering is load-bearing and invisible
/// in the parser that feeds it: `table` must come **before** the spec. iproute2
/// parses everything after the first `nexthop` as a nexthop list to end of line,
/// so a trailing `table` is rejected ("nexthop or end of line is expected instead
/// of table") and every multipath mirror fails. The position is valid for the
/// single-path form too, so there is one order rather than two.
#[cfg(target_os = "linux")]
pub(super) fn mirror_args(family: &str, route: &MirroredRoute) -> Vec<String> {
    let mut args: Vec<String> = ["route", "replace"].iter().map(|s| s.to_string()).collect();
    args.insert(0, family.to_string());
    args.push(route.dest.clone());
    args.extend(["table".to_string(), EXIT_TABLE.to_string()]);
    args.extend(route.spec.iter().cloned());
    args
}

#[cfg(target_os = "linux")]
pub(super) fn mirror_foreign_routes(family: &str, show: &str, tun_name: &str) -> usize {
    let wanted = parse_foreign_routes(show, tun_name);
    // Drop copies whose source route is gone. Read from our own table, where the
    // only other entry is the default we install below and never mirror.
    if let Some(out) = ip_output(&[family, "route", "show", "table", EXIT_TABLE]) {
        for stale in parse_table_routes(&out)
            .into_iter()
            .filter(|r| r.dest != "default" && !wanted.iter().any(|w| w.dest == r.dest))
        {
            let _ = run_ip(&[family, "route", "del", &stale.dest, "table", EXIT_TABLE]);
        }
    }
    let mut installed = Vec::new();
    for route in &wanted {
        let args = mirror_args(family, route);
        match run_ip(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
            Ok(()) => installed.push(route.dest.clone()),
            Err(e) => tracing::warn!(
                dest = %route.dest,
                error = %e,
                "could not mirror a foreign route into the tunnel table; \
                 its destinations will take the tunnel"
            ),
        }
    }
    if !installed.is_empty() {
        tracing::debug!(
            family,
            mirrored = installed.len(),
            "mirrored another VPN's routes into the tunnel table"
        );
    }
    // How many went in, so the caller can skip the rule when there is nothing for
    // it to find. Which ones no longer matters: the rule reads the table rather
    // than naming destinations, so a route that failed to install simply is not
    // matched, instead of being pointed at a table where nothing answers.
    installed.len()
}

/// The routes in `ip <family> route show table all` that belong to somebody else's
/// policy-routing table, so [`mirror_foreign_routes`] can copy them.
///
/// Kept only when all of these hold, which between them is the definition of "a
/// route our catch-all rule would otherwise steal":
///
/// - it names a `table` that is not `main`, `local`, `default`, or our own. `main`
///   is already rescued by [`PREF_MAIN`], and the kernel's `local` table is
///   reached ahead of every rule we install.
/// - its destination is a real prefix. A foreign `default` is another full tunnel,
///   and mirroring it would hand our egress straight back rather than tunnel it.
/// - it does not leave by our own TUN, which would be a copy of the route we are
///   installing anyway.
///
/// Only `via`, `dev` and `metric` are carried over. `ip route show` prints plenty
/// besides (`proto`, `scope`, `src`, `pref`, `expires`, and bare flags like
/// `onlink`), some of which take a value and some of which do not; rather than
/// guess each one's arity we re-emit the three clauses that decide where a packet
/// goes and let the kernel derive the rest. A copy in our own table has no need to
/// resemble the original in anything else.
///
/// A multipath route is the one shape that does not fit on its line: its nexthops
/// are printed as indented continuation lines and the route line itself carries no
/// `dev` at all, so it is read as a group. Dropping it is not harmless, which is
/// why it is handled rather than excluded: the prefix then falls to our catch-all
/// and that VPN's destinations go into our tunnel and nowhere.
///
/// Non-unicast entries (`unreachable`, `blackhole`, `prohibit`) are still skipped,
/// since they lead with the type instead of a destination. That is a deliberate
/// gap and not the same failure: those destinations are ones the other VPN wants
/// to fail, so tunnelling them costs a wrong answer rather than a lost route.
#[cfg(target_os = "linux")]
pub(super) fn parse_foreign_routes(show: &str, tun_name: &str) -> Vec<MirroredRoute> {
    // Group each route with the indented `nexthop` lines that belong to it.
    let mut groups: Vec<Vec<&str>> = Vec::new();
    for line in show.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = groups.last_mut() {
                last.push(line);
            }
        } else if !line.trim().is_empty() {
            groups.push(vec![line]);
        }
    }
    groups
        .into_iter()
        .filter_map(|group| {
            let line = group[0];
            let nexthops = &group[1..];
            let fields: Vec<&str> = line.split_whitespace().collect();
            let dest = *fields.first()?;
            // A default is another full tunnel: mirroring it would hand our egress
            // straight back. A non-unicast type (`local`, `broadcast`,
            // `unreachable`, `blackhole`, ...) leads with the type instead of a
            // destination, so anything that is not an address is not ours to copy.
            if dest == "default"
                || dest
                    .split('/')
                    .next()
                    .is_none_or(|a| a.parse::<IpAddr>().is_err())
            {
                return None;
            }
            let value_after = |key: &str| {
                fields
                    .iter()
                    .position(|f| *f == key)
                    .and_then(|i| fields.get(i + 1))
                    .copied()
            };
            let table = value_after("table")?;
            if matches!(table, "main" | "local" | "default") || table == EXIT_TABLE {
                return None;
            }
            let mut spec: Vec<String> = Vec::new();
            match value_after("dev") {
                Some(dev) => {
                    if dev == tun_name {
                        return None;
                    }
                    if let Some(via) = value_after("via") {
                        spec.extend(["via".to_string(), via.to_string()]);
                    }
                    spec.extend(["dev".to_string(), dev.to_string()]);
                    if let Some(metric) = value_after("metric") {
                        spec.extend(["metric".to_string(), metric.to_string()]);
                    }
                }
                // Multipath: the nexthops carry the `dev`, one per continuation
                // line. Re-emitted in full rather than collapsed to the first,
                // since `ip route replace` takes the same syntax back.
                None => {
                    for hop in nexthops {
                        let f: Vec<&str> = hop.split_whitespace().collect();
                        if f.first() != Some(&"nexthop") {
                            continue;
                        }
                        let at = |key: &str| {
                            f.iter()
                                .position(|x| *x == key)
                                .and_then(|i| f.get(i + 1))
                                .copied()
                        };
                        let dev = at("dev")?;
                        // Our own TUN among the nexthops makes the copy partly a
                        // copy of the route we are installing: leave the whole
                        // thing alone rather than mirror half of it.
                        if dev == tun_name {
                            return None;
                        }
                        spec.push("nexthop".to_string());
                        if let Some(via) = at("via") {
                            spec.extend(["via".to_string(), via.to_string()]);
                        }
                        spec.extend(["dev".to_string(), dev.to_string()]);
                        if let Some(weight) = at("weight") {
                            spec.extend(["weight".to_string(), weight.to_string()]);
                        }
                    }
                    if spec.is_empty() {
                        return None;
                    }
                }
            }
            Some(MirroredRoute {
                dest: dest.to_string(),
                spec,
            })
        })
        .collect()
}

/// The destinations currently in one table, for the stale-copy sweep in
/// [`mirror_foreign_routes`]. Only `dest` is used; `spec` comes along because the
/// two parses share a shape.
///
/// Indented lines are skipped for the same reason [`parse_foreign_routes`] groups
/// them: a multipath route prints its nexthops as continuation lines, and reading
/// the first token of one yields a destination called `nexthop`, which is in no
/// wanted set and so is "swept" with a `route del nexthop` that fails on every
/// re-apply. Our own table holds mirrors of exactly the routes that parse feeds
/// it, multipath included, so this is the same input read twice.
#[cfg(target_os = "linux")]
pub(super) fn parse_table_routes(show: &str) -> Vec<MirroredRoute> {
    show.lines()
        .filter(|line| !line.starts_with([' ', '\t']))
        .filter_map(|line| {
            let dest = line.split_whitespace().next()?;
            // Our `unreachable default` fallback leads with its type.
            if dest == "unreachable" {
                return None;
            }
            Some(MirroredRoute {
                dest: dest.to_string(),
                spec: Vec::new(),
            })
        })
        .collect()
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

/// Whether a [`run_ip`] failure is the kernel saying the object is already there.
///
/// `ip` reports it as `RTNETLINK answers: File exists` on stderr, which `run_ip`
/// folds into its message. Matched on the errno text rather than the prefix,
/// which differs between the `rule` and `route` subcommands.
#[cfg(target_os = "linux")]
pub(super) fn is_already_exists(e: &anyhow::Error) -> bool {
    e.to_string().contains("File exists")
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

#[cfg(target_os = "linux")]
fn read_ipv4_routes() -> Result<String> {
    ip_output(&["-4", "route", "show", "table", "all"])
        .context("read IPv4 routes before installing exit routing")
}

/// Do not take the gateway pool's route from another interface or VPN.
/// `routes` is `ip -4 route show table all`.
#[cfg(target_os = "linux")]
fn ensure_ipv4_routes_available(routes: &str, tun_name: &str) -> Result<()> {
    // `ip route` puts a route type such as `unreachable` before the destination.
    let ours = |fields: &[&str]| fields.windows(2).any(|pair| pair == ["dev", tun_name]);
    if let Some(line) = ipv4::conflicting_route(routes, 2, ours) {
        anyhow::bail!("IPv4 exit address space overlaps an existing route: {line}");
    }
    Ok(())
}
