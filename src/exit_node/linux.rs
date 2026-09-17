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
#[cfg(target_os = "linux")]
pub(super) fn enable(tun_name: &str) -> Result<()> {
    let path = snapshot_path().context("no config dir to snapshot the forwarding sysctls into")?;
    if !path.exists() {
        Snapshot {
            v4: read_sysctl(V4_FORWARD),
            v6: read_sysctl(V6_FORWARD),
            pf_token: None,
        }
        .save(&path)?;
    }
    // IPv6 alone. The overlay routes no IPv4, so nothing can ever enter the TUN
    // from `100.64.0.0/10` to be masqueraded, and turning on `ip_forward` would
    // make the host a router for a family we cannot deliver. The snapshot still
    // carries `v4` and `disable` still restores it: an older build did set it,
    // and teardown may not assume which build turned it on.
    write_sysctl(V6_FORWARD, "1")?;
    nft_load(&server_nft_ruleset(tun_name))?;
    tracing::info!(tun = tun_name, "exit node forwarding + NAT enabled");
    Ok(())
}

/// The nftables ruleset masquerading overlay traffic out of `tun_name`'s host.
///
/// The BSD twin's reasoning applies here too: there is no IPv4 rule because there
/// is no mesh IPv4 to masquerade. This one was merely dead rather than dangerous
/// (`iifname "<tun>"` scopes it to packets arriving on our own TUN, and an inbound
/// IPv4 packet is dropped as spoofed long before it could get there), but a rule
/// that cannot match is a rule that misleads whoever reads `nft list ruleset` next.
#[cfg(target_os = "linux")]
pub(super) fn server_nft_ruleset(tun_name: &str) -> String {
    format!(
        "{reset}\
         table inet {t} {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tiifname \"{tun}\" ip6 saddr {v6} oifname != \"{tun}\" masquerade\n\
         \t}}\n\
         }}\n",
        reset = drop_table(SERVER_TABLE),
        t = SERVER_TABLE,
        v6 = V6_OVERLAY,
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
    Snapshot::load(&path).restore_sysctls();
    let _ = fs::remove_file(&path);
    tracing::info!("exit node forwarding + NAT disabled");
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
/// Whether a local address should get a "leave via the physical uplink" rule at
/// [`PREF_SRC`]. True for the host's own globally-routable addresses; false for the
/// overlay (traffic entering the TUN is sourced from there, and bypassing the tunnel
/// for it would leak exactly what the tunnel is meant to carry) and for addresses
/// that never leave the host.
#[cfg(target_os = "linux")]
pub(super) fn is_bypass_source(addr: IpAddr) -> bool {
    if crate::membership::is_overlay_ip(addr)
        || matches!(addr, IpAddr::V4(v4) if crate::membership::is_cgnat_range(v4))
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

/// The client-side conntrack-mark ruleset: what keeps connections that reached this
/// host from *outside* the tunnel answering out the interface they arrived on, so a
/// headless box does not cut itself off the instant it starts using an exit node.
///
/// `prerouting` tags anything arriving on a non-TUN interface (and marks the packet
/// itself, so the reverse-path check resolves against `main`); `output` puts that
/// mark back on the locally-generated replies, and `type route` forces a re-route
/// once it is set.
///
/// This covers connections that arrive *after* the tunnel is up. Ones that predate
/// it cannot be handled here at all: loading this table is what loads conntrack, so
/// at that instant they are untracked, and the first packet conntrack sees on them is
/// our own outgoing reply, which registers the entry with its direction inverted.
/// Neither their ctmark nor their `ct direction` says what they are. The [`PREF_SRC`]
/// source rules in [`install_client_routing`] are what keeps those alive.
#[cfg(target_os = "linux")]
pub(super) fn client_nft_script(tun_name: &str) -> String {
    let mark = format!("{SOCKET_MARK:#x}");
    format!(
        "{reset}\
         table inet {t} {{\n\
         \tchain prerouting {{\n\
         \t\ttype filter hook prerouting priority mangle; policy accept;\n\
         \t\tiifname \"{tun}\" return\n\
         \t\tct mark set {mark}\n\
         \t\tmeta mark set {mark}\n\
         \t}}\n\
         \tchain output {{\n\
         \t\ttype route hook output priority mangle; policy accept;\n\
         \t\tct mark {mark} meta mark set {mark}\n\
         \t}}\n\
         }}\n",
        reset = drop_table(CLIENT_TABLE),
        t = CLIENT_TABLE,
        tun = tun_name,
    )
}

/// The `ip` family flags a client full tunnel is installed for.
///
/// `carries` is [`ExitFamilies::tunnelled`], the gateway's claim narrowed to its
/// IPv6 half. The overlay routes no IPv4, so claiming the host's IPv4 egress would
/// source transit from a range the daemon deliberately leaves unrouted and pull
/// IPv4 out from under whatever else shares the host; and a gateway that cannot
/// return IPv6 has nothing left to carry, which is why `Neither` is refused.
///
/// Teardown is not symmetric with this: it always sweeps both families, so a
/// daemon restarted with a different selection still cleans up what the last one
/// left.
///
/// [`ExitFamilies::Unknown`] is not a `tunnelled()` output, and is read here as
/// both families, since that is what an absent claim meant before the field
/// existed.
#[cfg(target_os = "linux")]
pub(super) fn tunnel_families(carries: ExitFamilies) -> &'static [&'static str] {
    match (
        carries.carries_v4() || carries.is_unknown(),
        carries.carries_v6() || carries.is_unknown(),
    ) {
        (true, true) => &["-4", "-6"],
        (true, false) => &["-4"],
        (false, true) => &["-6"],
        (false, false) => &[],
    }
}

#[cfg(target_os = "linux")]
pub fn install_client_routing(tun_name: &str, carries: ExitFamilies) -> Result<()> {
    // The conntrack-mark table loads first: nothing routes into the tunnel until
    // the `ip rule`s below go in, but the moment they do, an inbound connection's
    // replies depend on this table already restoring the mark. Loading it after
    // the rules would open a window (or, on a mid-way failure, a permanent state)
    // where an SSH session to this host's public IP is routed into the tunnel and
    // cut.
    nft_load(&client_nft_script(tun_name))?;
    // Kernel rules outlive the process, so install has to tear down the family it
    // stopped claiming, the way teardown already does. A daemon killed (or aborted
    // by the panic hook) while an older build's dual-stack tunnel was up, restarted
    // with the selection still in config, would otherwise install `-6` and leave
    // the previous run's `-4` rules and default in place: IPv4 policy-routed into a
    // tunnel that no longer claims it, sourced from an address the overlay no
    // longer assigns, taking the co-resident VPN's IPv4 down with it.
    for family in ["-4", "-6"] {
        if !tunnel_families(carries).contains(&family) {
            remove_client_rules(family, RuleSweep::All);
            let _ = run_ip(&[family, "route", "flush", "table", EXIT_TABLE]);
        }
    }
    let mark = format!("{SOCKET_MARK:#x}");
    for family in tunnel_families(carries).iter().copied() {
        // Give the tunnel table the prefixes another VPN serves out of a table of
        // its own, or our catch-all rule swallows them (see the fn docs).
        let mirrored = mirror_foreign_routes(family, tun_name);
        run_ip(&[
            family, "route", "replace", "default", "dev", tun_name, "table", EXIT_TABLE,
        ])?;
        // Keeps the catch-all standing: everything below is a rebuild, and the
        // rules are re-added one `ip` process at a time. See [`RuleSweep`].
        remove_client_rules(family, RuleSweep::KeepCatchAll);
        // The three bypasses go back **first**, because the catch-all now stays up
        // across the rebuild. That closed the window where traffic leaked out the
        // physical uplink, and it opened a worse one in the other direction: with
        // the catch-all standing and these three gone, the highest-priority rule
        // matching anything is ours, so for the length of the rebuild the daemon's
        // own QUIC underlay is routed into the tunnel it is carrying, along with
        // every pre-existing physical-sourced connection. That is precisely what
        // `PREF_BYPASS` and `PREF_SRC` exist to prevent, and it kills the mesh
        // rather than leaking past it. Each of these is a separate `ip` process,
        // so the window is real even now that it is a handful of them.
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
        for addr in bypass_source_addrs(family) {
            run_ip(&[
                family,
                "rule",
                "add",
                "from",
                &addr.to_string(),
                "table",
                "main",
                "pref",
                PREF_SRC,
            ])?;
        }
        run_ip(&[
            family,
            "rule",
            "add",
            "fwmark",
            &mark,
            "table",
            "main",
            "pref",
            PREF_BYPASS,
        ])?;
        run_ip(&[
            family,
            "rule",
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
            "pref",
            PREF_MAIN,
        ])?;
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
            run_ip(&foreign_rule_args(family, "add"))?;
        }
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
/// its routes). Linux only.
#[cfg(target_os = "linux")]
pub fn teardown_client_routing() {
    for family in ["-4", "-6"] {
        remove_client_rules(family, RuleSweep::All);
        let _ = run_ip(&[family, "route", "flush", "table", EXIT_TABLE]);
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
pub(super) fn mirror_foreign_routes(family: &str, tun_name: &str) -> usize {
    let wanted = match ip_output(&[family, "route", "show", "table", "all"]) {
        Some(out) => parse_foreign_routes(&out, tun_name),
        None => return 0,
    };
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
