//! Exit-node server plumbing: the runtime allow policy consulted on the inbound
//! data path, and the Linux kernel forwarding/NAT that turns this host into an
//! internet gateway for the mesh.
//!
//! Rayfish's own firewall is entirely userspace (peer -> daemon -> TUN), but
//! forwarding a client's internet-bound packet out to the real uplink is a kernel
//! job: once the daemon writes the packet to the TUN with a public destination,
//! the kernel routes it, and it needs `ip_forward` plus a NAT masquerade so
//! replies find their way back. That kernel state (Linux only) lives in [`enable`]
//! / [`disable`]; the per-network allow decision lives in [`ExitServer`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use iroh::EndpointId;

/// Per-network allow policy for peers using this node as an exit node, consulted
/// on the server's inbound data path (`forward::evaluate_inbound`). Cheap to clone
/// (Arc-backed) and swapped wholesale whenever the allow-lists change. Empty until
/// the data plane activates and populates it from config, so a node that offers no
/// exit (or is on standby) transits nothing.
#[derive(Clone, Default)]
pub struct ExitServer {
    inner: Arc<ArcSwap<Policy>>,
    /// Set while the kernel forwarding/NAT is installed (Linux). Holds the prior
    /// sysctl values so teardown can restore them. `Some` == OS state is live.
    /// Only touched on Linux (`apply_os`/`teardown_os` are no-ops elsewhere).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    snapshot: Arc<ArcSwapOption<ForwardSnapshot>>,
}

#[derive(Default)]
struct Policy {
    /// network name -> who may route out through us on it.
    nets: HashMap<String, Allow>,
}

#[derive(Default)]
struct Allow {
    /// `ray exit-node allow <net> '*'`: any member of the network.
    any: bool,
    /// Specific permitted user identities.
    users: HashSet<EndpointId>,
}

impl Allow {
    fn permits(&self, user: &EndpointId) -> bool {
        self.any || self.users.contains(user)
    }
}

impl ExitServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `user` may route non-mesh traffic out through us on `network`.
    /// False unless the data plane is up and the network lists the user (or `*`).
    pub fn allows(&self, network: &str, user: &EndpointId) -> bool {
        self.inner
            .load()
            .nets
            .get(network)
            .is_some_and(|a| a.permits(user))
    }

    /// Whether we currently offer an exit node on any network (drives whether the
    /// kernel forwarding/NAT should be installed).
    pub fn is_active(&self) -> bool {
        !self.inner.load().nets.is_empty()
    }

    /// Rebuild the policy from `(network name, allow-list)` pairs. An allow entry
    /// is `"*"` (any member) or a user-identity hex; unparseable entries are
    /// skipped. Networks with an empty list are omitted, so `is_active` reflects
    /// real offers.
    pub fn reload<'a>(&self, entries: impl IntoIterator<Item = (&'a str, &'a [String])>) {
        let mut nets = HashMap::new();
        for (name, allow_list) in entries {
            if allow_list.is_empty() {
                continue;
            }
            let mut allow = Allow::default();
            for entry in allow_list {
                if entry == "*" {
                    allow.any = true;
                } else if let Ok(id) = entry.parse::<EndpointId>() {
                    allow.users.insert(id);
                }
            }
            nets.insert(name.to_string(), allow);
        }
        self.inner.store(Arc::new(Policy { nets }));
    }

    /// Drop all exit offers (data plane going to standby).
    pub fn clear(&self) {
        self.inner.store(Arc::new(Policy::default()));
    }

    /// Reconcile the kernel forwarding/NAT with the current offer state on
    /// `tun_name`: install it when we now offer an exit and it isn't up yet, tear
    /// it down when we no longer offer one. Idempotent and Linux only (a no-op on
    /// other platforms, where client full-tunnel is unsupported anyway). Call
    /// after [`reload`] whenever the data plane is active.
    pub fn apply_os(&self, tun_name: &str) {
        #[cfg(target_os = "linux")]
        {
            let want = self.is_active();
            let live = self.snapshot.load().is_some();
            if want && !live {
                match enable(tun_name) {
                    Ok(snap) => self.snapshot.store(Some(Arc::new(snap))),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to enable exit-node forwarding/NAT")
                    }
                }
            } else if !want && live {
                self.teardown_os();
            }
            // want && live: the nft rules are static (user gating lives in
            // `allows`, not the kernel), so there is nothing to reinstall.
        }
        #[cfg(not(target_os = "linux"))]
        let _ = tun_name;
    }

    /// Remove the kernel forwarding/NAT and restore the saved sysctls, if up.
    /// Idempotent; called on `deactivate()` and when the last offer is withdrawn.
    pub fn teardown_os(&self) {
        #[cfg(target_os = "linux")]
        if let Some(snap) = self.snapshot.swap(None) {
            disable(&snap);
        }
    }
}

/// The two overlay source ranges masqueraded when forwarding out an uplink.
#[cfg(target_os = "linux")]
const V4_OVERLAY: &str = "100.64.0.0/10";
#[cfg(target_os = "linux")]
const V6_OVERLAY: &str = "200::/7";
#[cfg(target_os = "linux")]
const NFT_TABLE: &str = "rayfish_exit";

/// Prior `ip_forward` / `forwarding` sysctl values captured at [`enable`] so
/// [`disable`] can restore them instead of blindly zeroing (they may have been on
/// for unrelated reasons). Cross-platform so [`ExitServer`]'s snapshot field has a
/// concrete type everywhere; only populated on Linux.
#[derive(Clone, Default)]
pub struct ForwardSnapshot {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    v4: Option<String>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    v6: Option<String>,
}

/// Turn this host into an exit node: enable IPv4/IPv6 forwarding and install an
/// nftables table that masquerades overlay-sourced traffic leaving any non-TUN
/// interface (plus a permissive forward chain for the common case of no
/// restrictive host firewall). Idempotent: the nft script deletes and recreates
/// our own table, and forwarding is snapshotted then set. The snapshot is also
/// persisted to disk so a crash (the panic hook `abort()`s) can restore the
/// sysctls via [`emergency_teardown`]. Linux only.
#[cfg(target_os = "linux")]
pub fn enable(tun_name: &str) -> anyhow::Result<ForwardSnapshot> {
    let snapshot = ForwardSnapshot {
        v4: read_sysctl("net/ipv4/ip_forward"),
        v6: read_sysctl("net/ipv6/conf/all/forwarding"),
    };
    write_sysctl("net/ipv4/ip_forward", "1")?;
    write_sysctl("net/ipv6/conf/all/forwarding", "1")?;
    install_nft(tun_name)?;
    persist_snapshot(&snapshot);
    tracing::info!(tun = tun_name, "exit node forwarding + NAT enabled");
    Ok(snapshot)
}

/// Tear down the exit-node kernel state: remove our nftables table and restore the
/// forwarding sysctls to their pre-`enable` values. Best-effort (logs on failure)
/// so a partial teardown never blocks going to standby. Linux only.
#[cfg(target_os = "linux")]
pub fn disable(snapshot: &ForwardSnapshot) {
    delete_nft_table();
    if let Some(v) = &snapshot.v4 {
        let _ = write_sysctl("net/ipv4/ip_forward", v);
    }
    if let Some(v) = &snapshot.v6 {
        let _ = write_sysctl("net/ipv6/conf/all/forwarding", v);
    }
    if let Some(path) = snapshot_path() {
        let _ = std::fs::remove_file(path);
    }
    tracing::info!("exit node forwarding + NAT disabled");
}

/// Synchronous emergency teardown, safe to call from the panic hook before
/// `abort()`. Removes our nftables table and, if a snapshot from a prior [`enable`]
/// is on disk, restores the forwarding sysctls to their captured values so a crash
/// can't leave the host acting as an open router/NAT. No-op when no snapshot exists
/// (never enabled, or cleanly disabled). Linux only.
#[cfg(target_os = "linux")]
pub fn emergency_teardown() {
    let Some(path) = snapshot_path() else { return };
    if !path.exists() {
        return;
    }
    delete_nft_table();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        for line in contents.lines() {
            match line.split_once('=') {
                Some(("v4", v)) => {
                    let _ = write_sysctl("net/ipv4/ip_forward", v);
                }
                Some(("v6", v)) => {
                    let _ = write_sysctl("net/ipv6/conf/all/forwarding", v);
                }
                _ => {}
            }
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// No-op on non-Linux: exit-node kernel state only exists on Linux.
#[cfg(not(target_os = "linux"))]
pub fn emergency_teardown() {}

#[cfg(target_os = "linux")]
fn snapshot_path() -> Option<std::path::PathBuf> {
    crate::config::config_dir()
        .ok()
        .map(|d| d.join("exit-forward.snapshot"))
}

/// Persist the pre-enable sysctl values so a crash can restore them. Best-effort:
/// a missing snapshot just means the emergency path skips the sysctl restore.
#[cfg(target_os = "linux")]
fn persist_snapshot(snapshot: &ForwardSnapshot) {
    let Some(path) = snapshot_path() else { return };
    let body = format!(
        "v4={}\nv6={}\n",
        snapshot.v4.as_deref().unwrap_or(""),
        snapshot.v6.as_deref().unwrap_or(""),
    );
    if let Err(e) = crate::config::write_file(&path, body.as_bytes(), false) {
        tracing::warn!(error = %e, "failed to persist exit-node forwarding snapshot");
    }
}

#[cfg(target_os = "linux")]
fn delete_nft_table() {
    if let Err(e) = run_nft(&format!("delete table inet {NFT_TABLE}")) {
        // A missing table is fine (never enabled, or already removed).
        tracing::debug!(error = %e, "exit-node nft table already absent");
    }
}

#[cfg(target_os = "linux")]
fn install_nft(tun_name: &str) -> anyhow::Result<()> {
    // The leading create+delete makes the recreate idempotent: `delete table`
    // fails if absent, so we create-then-delete first to guarantee a clean slate.
    let script = format!(
        "table inet {t}\n\
         delete table inet {t}\n\
         table inet {t} {{\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tip saddr {v4} accept\n\
         \t\tip daddr {v4} accept\n\
         \t\tip6 saddr {v6} accept\n\
         \t\tip6 daddr {v6} accept\n\
         \t}}\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tip saddr {v4} oifname != \"{tun}\" masquerade\n\
         \t\tip6 saddr {v6} oifname != \"{tun}\" masquerade\n\
         \t}}\n\
         }}\n",
        t = NFT_TABLE,
        v4 = V4_OVERLAY,
        v6 = V6_OVERLAY,
        tun = tun_name,
    );
    run_nft_stdin(&script)
}

#[cfg(target_os = "linux")]
fn run_nft(args: &str) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let out = std::process::Command::new("nft")
        .args(args.split_whitespace())
        .output()
        .with_context(|| format!("running `nft {args}`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`nft {args}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_nft_stdin(script: &str) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::io::Write as _;
    use std::process::{Command, Stdio};
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
fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/sys/{path}"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn write_sysctl(path: &str, value: &str) -> anyhow::Result<()> {
    use anyhow::Context as _;
    std::fs::write(format!("/proc/sys/{path}"), value)
        .with_context(|| format!("writing sysctl {path}={value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn wildcard_allows_any_user() {
        let s = ExitServer::new();
        let allow = strs(&["*"]);
        s.reload([("n", allow.as_slice())]);
        let user = iroh::SecretKey::generate().public();
        assert!(s.allows("n", &user));
        assert!(s.is_active());
    }

    #[test]
    fn specific_user_gated() {
        let allowed = iroh::SecretKey::generate().public();
        let other = iroh::SecretKey::generate().public();
        let s = ExitServer::new();
        let allow = strs(&[&allowed.to_string()]);
        s.reload([("n", allow.as_slice())]);
        assert!(s.allows("n", &allowed));
        assert!(!s.allows("n", &other));
        // Unknown network is never an exit.
        assert!(!s.allows("other", &allowed));
    }

    #[test]
    fn empty_allow_is_not_active() {
        let s = ExitServer::new();
        let allow: Vec<String> = vec![];
        s.reload([("n", allow.as_slice())]);
        assert!(!s.is_active());
        let user = iroh::SecretKey::generate().public();
        assert!(!s.allows("n", &user));
    }

    #[test]
    fn clear_drops_all_offers() {
        let s = ExitServer::new();
        let allow = strs(&["*"]);
        s.reload([("n", allow.as_slice())]);
        s.clear();
        assert!(!s.is_active());
    }
}
