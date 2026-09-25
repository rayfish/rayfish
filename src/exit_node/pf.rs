use super::*;

// ---------------------------------------------------------------------------
// macOS / FreeBSD kernel state (pf)
// ---------------------------------------------------------------------------

/// The pf anchor our NAT rules live in.
///
/// pf only evaluates an anchor that the *main* ruleset references, and the main
/// ruleset belongs to the host, not to us: rewriting it would trample whatever
/// firewall the operator (or another tool) already has loaded. So we never touch
/// it, and instead load into an anchor it already points at.
///
/// macOS's stock `/etc/pf.conf` carries `nat-anchor "com.apple/*"`, so a sub-anchor
/// beneath `com.apple` is evaluated with no change to any file we don't own.
/// FreeBSD has no such convention: there, the operator adds `nat-anchor
/// "rayfish_exit"` to `pf.conf` themselves. Either way [`ensure_anchor_referenced`]
/// checks the reference is really there, because a rule loaded into an unreferenced
/// anchor is silently never matched, and a gateway that forwards without
/// masquerading is worse than one that refuses to start.
/// Written as a `cfg!` rather than two `#[cfg]` definitions on purpose: nothing we
/// have builds FreeBSD (it is in neither CI nor the release matrix), so a
/// FreeBSD-only item would be code no compiler ever sees until it reaches a user.
/// This way both arms are type-checked wherever this file builds at all.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) const ANCHOR: &str = if cfg!(target_os = "macos") {
    "com.apple/rayfish_exit"
} else {
    "rayfish_exit"
};

/// What the main ruleset has to name for [`ANCHOR`] to be reached. On macOS that is
/// Apple's wildcard, which our anchor sits under; on FreeBSD it is our anchor itself.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) const ANCHOR_REF: &str = if cfg!(target_os = "macos") {
    "com.apple/*"
} else {
    "rayfish_exit"
};

/// Turn this host into an exit node: enable IPv4/IPv6 forwarding and load a pf
/// anchor that NATs overlay-sourced traffic to the address of the uplink it leaves
/// by, so replies come back to us and we can un-NAT them to the client.
///
/// Idempotent, and safe to re-run while already enabled: the prior sysctls are
/// snapshotted exactly once (a re-apply must not capture the values we set
/// ourselves), pf is only enabled if we are not already holding a token for it, and
/// the anchor is replaced wholesale.
///
/// As on Linux, this does not open the forward path: a host whose pf ruleset blocks
/// forwarding has to be told to permit it on its own terms.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn enable(_tun_name: &str) -> Result<()> {
    let path = snapshot_path().context("no config dir to snapshot the forwarding sysctls into")?;
    let mut snap = if path.exists() {
        Snapshot::load(&path)
    } else {
        let snap = Snapshot {
            v4: read_sysctl(V4_FORWARD),
            v6: read_sysctl(V6_FORWARD),
            pf_token: None,
        };
        snap.save(&path)?;
        snap
    };
    // IPv6 alone; see the Linux twin for why `ip_forward` is left where it was.
    write_sysctl(V6_FORWARD, "1")?;

    // Enable pf before loading the anchor (an unloaded ruleset has no anchors to
    // reference), and record the token first: if anything below fails, `disable`
    // reads this file to give pf back, and a token we never wrote is a reference
    // count we could never release.
    if snap.pf_token.is_none()
        && let Some(token) = pf_enable()?
    {
        snap.pf_token = Some(token);
        snap.save(&path)?;
    }
    ensure_anchor_referenced()?;

    let v6 = default_interface("-inet6");
    pf_load_anchor(ANCHOR, &nat_rules(v6.as_deref()))?;
    tracing::info!(v6 = ?v6, "exit node forwarding + NAT enabled");
    Ok(())
}

/// The pf ruleset masquerading overlay traffic out the given IPv6 uplink, or an
/// empty ruleset when there is none.
///
/// NAT is scoped to the interface the IPv6 default route leaves by, and rewrites to
/// that interface's *current* address: the parentheses tell pf to re-resolve it, so
/// a DHCP renewal doesn't strand the rule on a stale IP.
///
/// There is no IPv4 half. `nat on <uplink> inet` matches on the *uplink*, not our
/// TUN, so with no mesh IPv4 left the only traffic such a rule could still catch is
/// a co-resident VPN's: it would be us claiming `100.64.0.0/10`, which is the one
/// thing the overlay promises not to do.
///
/// Empty rather than `None` on a host with no IPv6 uplink: that host has nothing to
/// masquerade, but it is not an error, and refusing here would clear the offer and
/// leave clients reading "does not advertise an exit node" instead of the reason
/// [`ExitFamilies::Neither`] gives them. Loading an empty anchor flushes it.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn nat_rules(v6: Option<&str>) -> String {
    match v6 {
        Some(iface) => format!("nat on {iface} inet6 from {V6_OVERLAY} to any -> ({iface})\n"),
        None => String::new(),
    }
}

/// Remove the exit-node gateway state: flush our pf anchor, release our reference on
/// pf, and restore the forwarding sysctls to the values captured by [`enable`].
/// Reads the on-disk snapshot rather than in-memory state, so the same call works
/// from the panic hook (which `abort()`s, and must not leave the host an open
/// router/NAT). Best-effort and idempotent: a no-op when no snapshot exists (never
/// enabled, or already torn down).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn disable() {
    let Some(path) = snapshot_path() else { return };
    if !path.exists() {
        return;
    }
    let snap = Snapshot::load(&path);
    let _ = pfctl(&["-a", ANCHOR, "-F", "all"]);
    if let Some(token) = &snap.pf_token {
        pf_release(token);
    }
    snap.restore_sysctls();
    let _ = fs::remove_file(&path);
    tracing::info!("exit node forwarding + NAT disabled");
}

/// Take our reference on pf, returning the handle [`disable`] later gives back
/// via [`pf_release`], or `None` when pf was already up and we hold nothing.
///
/// macOS's pfctl has the reference-counted `-E`/`-X <token>` (an Apple
/// extension), so enabling never disturbs a pf that is already up and releasing
/// never takes one down that somebody else still wants. FreeBSD's pfctl has only
/// plain `-e`/`-d`, so the same guarantee is made by hand: enable pf only when
/// it is not already running, record that we did (a fixed marker in the token
/// slot), and let [`pf_release`] turn pf off only in that case, so an operator's
/// own running pf is never touched.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn pf_enable() -> Result<Option<String>> {
    if cfg!(target_os = "macos") {
        let out = pfctl(&["-E"])?;
        return out
            .lines()
            .find_map(|l| l.split_once("Token :"))
            .map(|(_, t)| Some(t.trim().to_string()))
            .context("`pfctl -E` did not report a token");
    }
    if pf_running() {
        return Ok(None);
    }
    pfctl(&["-e"])?;
    Ok(Some(PF_ENABLED_BY_US.to_string()))
}

/// Give back the reference [`pf_enable`] took: on macOS release the token, on
/// FreeBSD disable pf (only ever reached when we were the one to enable it).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn pf_release(token: &str) {
    if cfg!(target_os = "macos") {
        let _ = pfctl(&["-X", token]);
    } else {
        let _ = pfctl(&["-d"]);
    }
}

/// The marker stored in the snapshot's token slot on FreeBSD when [`pf_enable`]
/// was the one to turn pf on.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) const PF_ENABLED_BY_US: &str = "pf-enabled-by-rayfish";

/// Whether pf is currently enabled (`pfctl -s info` reports `Status: Enabled`).
/// Errs on the side of "running": claiming a running pf is down would make
/// [`pf_enable`] flip it on and hand [`pf_release`] the right to turn it off.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn pf_running() -> bool {
    pfctl(&["-s", "info"])
        .map(|out| {
            out.lines().any(|l| {
                l.trim_start()
                    .strip_prefix("Status:")
                    .is_some_and(|s| s.trim_start().starts_with("Enabled"))
            })
        })
        .unwrap_or(true)
}

/// Replace `anchor`'s ruleset with `rules`. Shared with [`crate::hostfw`], which
/// loads a second anchor of ours for a different job; the pf primitives live
/// here because this module is where the rest of them already are.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn pf_load_anchor(anchor: &str, rules: &str) -> Result<()> {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = Command::new("pfctl")
        .args(["-a", anchor, "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `pfctl -f -`")?;
    child
        .stdin
        .take()
        .context("pfctl stdin unavailable")?
        .write_all(rules.as_bytes())
        .context("writing pf ruleset")?;
    let out = child.wait_with_output().context("waiting for pfctl")?;
    if !out.status.success() {
        anyhow::bail!(
            "pf ruleset load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Fail unless pf's active ruleset actually reaches [`ANCHOR`].
///
/// On macOS pf is off by default and its ruleset starts out empty, so `pfctl -E`
/// alone leaves nothing referencing anything. An empty ruleset is nobody's, so we
/// load the host's own `/etc/pf.conf` (exactly what the system would have done) to
/// get Apple's anchors in place. A *non*-empty ruleset that still doesn't reach us
/// belongs to someone else and we refuse rather than overwrite it.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn ensure_anchor_referenced() -> Result<()> {
    if pfctl(&["-sn"]).is_ok_and(|r| r.contains(ANCHOR_REF)) {
        return Ok(());
    }
    let empty = pfctl(&["-sn"]).is_ok_and(|r| r.trim().is_empty())
        && pfctl(&["-sr"]).is_ok_and(|r| r.trim().is_empty());
    if empty && Path::new(PF_CONF).exists() {
        let _ = pfctl(&["-f", PF_CONF]);
    }
    if pfctl(&["-sn"]).is_ok_and(|r| r.contains(ANCHOR_REF)) {
        return Ok(());
    }
    anyhow::bail!(
        "pf's active ruleset does not reference the `{ANCHOR_REF}` nat anchor, so an \
         exit node's NAT rules would never be matched. Add `nat-anchor \"{ANCHOR_REF}\"` \
         to {PF_CONF} and reload it (`pfctl -f {PF_CONF}`)."
    )
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) const PF_CONF: &str = "/etc/pf.conf";

/// The interface the default route for one family (`-inet` / `-inet6`) leaves by,
/// or `None` if there is no default route for it.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn default_interface(family: &str) -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", family, "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .map(|i| i.trim().to_string())
        .filter(|i| !i.is_empty())
}

/// Run `pfctl` and return its combined output (it reports most of what we ask for on
/// stderr). Errors if it exits non-zero.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn pfctl(args: &[&str]) -> Result<String> {
    let out = Command::new("pfctl")
        .args(args)
        .output()
        .with_context(|| format!("running `pfctl {}`", args.join(" ")))?;
    if !out.status.success() {
        anyhow::bail!(
            "`pfctl {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(combined)
}

/// The sysctl's current value, or `""` if it can't be read (then it is not
/// restored on teardown).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn read_sysctl(name: &str) -> String {
    Command::new("sysctl")
        .args(["-n", name])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn write_sysctl(name: &str, value: &str) -> Result<()> {
    let out = Command::new("sysctl")
        .arg(format!("{name}={value}"))
        .output()
        .with_context(|| format!("running `sysctl {name}={value}`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "setting sysctl {name}={value} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
