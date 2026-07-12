//! Exit nodes: the runtime policy consulted on the data path, and the Linux kernel
//! state (forwarding, NAT, policy routing) that a gateway and its clients need.
//!
//! Rayfish's own firewall is entirely userspace (peer -> daemon -> TUN), but an
//! exit node is a kernel job on both ends. On the **gateway**, once the daemon
//! writes a client's packet to the TUN with a public destination the kernel has to
//! route it out the uplink, which needs `ip_forward` plus a NAT masquerade so
//! replies come back ([`ExitServer::apply_os`] -> [`enable`] / [`disable`]). On the
//! **client**, a full tunnel means every route decision changes, including for the
//! node's own iroh transport ([`install_client_routing`]).
//!
//! The per-network allow decision ([`ExitServer`]) and the client's selection
//! ([`ExitClient`]) are plain userspace state, live on every platform, and are
//! bundled for the data path as [`ExitContext`].

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::{fs, path::PathBuf, process::Command};

#[cfg(target_os = "linux")]
use anyhow::{Context as _, Result};
use arc_swap::{ArcSwap, ArcSwapOption};
use iroh::EndpointId;
use smol_str::SmolStr;

/// Linux fwmark set on iroh's underlay UDP sockets (via the forked
/// `Endpoint::builder().socket_mark`) and on the replies of any connection that
/// arrived from outside the tunnel. A matching `ip rule` sends marked packets to
/// the main routing table, so both bypass the client's full-tunnel default route
/// (the standard WireGuard/Tailscale loop prevention). Arbitrary non-zero value.
pub const SOCKET_MARK: u32 = 0x7261; // "ra"

/// Per-network allow policy for peers using this node as an exit node, consulted
/// on the gateway's inbound data path (`forward::evaluate_inbound`). Cheap to clone
/// (Arc-backed) and swapped wholesale whenever the allow-lists change. Empty until
/// the data plane activates and populates it from config, so a node that offers no
/// exit (or is on standby) transits nothing.
#[derive(Clone, Default)]
pub struct ExitServer {
    nets: Arc<ArcSwap<HashMap<SmolStr, Allow>>>,
}

/// Who may route out through us on one network.
#[derive(Default)]
struct Allow {
    /// `ray exit-node allow <net> '*'`: any member of the network.
    any: bool,
    /// Specific permitted user identities.
    users: HashSet<EndpointId>,
}

impl ExitServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `user` may route non-mesh traffic out through us on `network`.
    /// False unless the data plane is up and the network lists the user (or `*`).
    pub fn allows(&self, network: &str, user: &EndpointId) -> bool {
        self.nets
            .load()
            .get(network)
            .is_some_and(|a| a.any || a.users.contains(user))
    }

    /// Whether we currently offer an exit node on any network (drives whether the
    /// kernel forwarding/NAT should be installed).
    pub fn is_active(&self) -> bool {
        !self.nets.load().is_empty()
    }

    /// Rebuild the policy from `(network name, allow-list)` pairs. An allow entry
    /// is `"*"` (any member) or a user-identity hex; unparseable entries are
    /// skipped. Networks with an empty list are omitted, so `is_active` reflects
    /// real offers.
    pub fn reload<'a>(&self, entries: impl IntoIterator<Item = (&'a str, &'a [String])>) {
        let mut nets: HashMap<SmolStr, Allow> = HashMap::new();
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
            nets.insert(SmolStr::new(name), allow);
        }
        self.nets.store(Arc::new(nets));
    }

    /// Drop all exit offers (data plane going to standby). Pair with
    /// [`apply_os`](Self::apply_os) to take the kernel state down with them.
    pub fn clear(&self) {
        self.nets.store(Arc::default());
    }

    /// Reconcile the kernel forwarding/NAT with the current offer state: install it
    /// when we offer an exit on some network, remove it when we don't. Both
    /// directions are idempotent, so this is safe to call on every change. Linux
    /// only (a no-op elsewhere, where client full-tunnel is unsupported anyway).
    pub fn apply_os(&self, tun_name: &str) {
        #[cfg(target_os = "linux")]
        if self.is_active() {
            if let Err(e) = enable(tun_name) {
                tracing::warn!(error = %e, "failed to enable exit-node forwarding/NAT");
            }
        } else {
            disable();
        }
        #[cfg(not(target_os = "linux"))]
        let _ = tun_name;
    }
}

/// Client-side exit-node selection: the peer this node routes all its non-mesh
/// traffic through, on a specific network. Consulted by the forwarding loop
/// (outbound routing to the exit peer) and the inbound path (accepting the exit
/// peer's return traffic). Cheap to clone (Arc-backed); `None` == direct egress.
#[derive(Clone, Default)]
pub struct ExitClient {
    inner: Arc<ArcSwapOption<ExitSelection>>,
}

/// The resolved exit peer for the client role.
#[derive(Clone)]
pub struct ExitSelection {
    /// The exit peer's user identity, matched against a datagram sender to accept
    /// its return traffic. (Folds multi-device peers via the device/user map.)
    pub peer_user: EndpointId,
    /// The exit peer's mesh IPv4, used to look up its live route and to dial it.
    pub ipv4: Ipv4Addr,
    /// The network we route through the exit peer on (so we tag the datagram with
    /// that network's handle, which its allow-list is scoped to).
    pub network: SmolStr,
}

impl ExitClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current exit selection, if any.
    pub fn selection(&self) -> Option<Arc<ExitSelection>> {
        self.inner.load_full()
    }

    /// Whether we route non-mesh traffic through an exit peer.
    pub fn is_active(&self) -> bool {
        self.inner.load().is_some()
    }

    /// Whether a datagram arriving on `network` from sender `peer_user` is our own
    /// exit-node return traffic (the sender is our chosen exit peer for it).
    pub fn is_return_traffic(&self, network: &str, peer_user: &EndpointId) -> bool {
        self.inner
            .load()
            .as_ref()
            .is_some_and(|s| s.network == network && &s.peer_user == peer_user)
    }

    /// Set (or with `None`, clear) the exit selection.
    pub fn set(&self, selection: Option<ExitSelection>) {
        self.inner.store(selection.map(Arc::new));
    }
}

/// This node's exit-node state as the inbound data path needs it: the gateway allow
/// policy, our own client selection, and our mesh addresses (to confirm that return
/// traffic from the exit peer is really addressed to us). Cheap to clone; built per
/// peer reader from the daemon's registry.
#[derive(Clone)]
pub struct ExitContext {
    pub server: ExitServer,
    pub client: ExitClient,
    pub my_v4: Ipv4Addr,
    pub my_v6: Ipv6Addr,
}

impl Default for ExitContext {
    fn default() -> Self {
        Self {
            server: ExitServer::new(),
            client: ExitClient::new(),
            my_v4: Ipv4Addr::UNSPECIFIED,
            my_v6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

// ---------------------------------------------------------------------------
// Linux kernel state
// ---------------------------------------------------------------------------

/// The overlay source ranges we masquerade when forwarding out an uplink, and the
/// nftables tables we own (one per role, so gateway and client are independent).
#[cfg(target_os = "linux")]
mod names {
    pub(super) const V4_OVERLAY: &str = "100.64.0.0/10";
    pub(super) const V6_OVERLAY: &str = "200::/7";
    pub(super) const SERVER_TABLE: &str = "rayfish_exit";
    pub(super) const CLIENT_TABLE: &str = "rayfish_exit_client";
    pub(super) const V4_FORWARD: &str = "net/ipv4/ip_forward";
    pub(super) const V6_FORWARD: &str = "net/ipv6/conf/all/forwarding";
    /// Policy-routing table holding the client's full-tunnel default route
    /// (`default dev <tun>`), separate from `main` so marked traffic can bypass it.
    pub(super) const EXIT_TABLE: &str = "29793";
    /// `ip rule` preferences (lower = higher priority). Named so install and
    /// teardown stay in sync.
    pub(super) const PREF_BYPASS: &str = "100"; // marked traffic -> main table
    pub(super) const PREF_MAIN: &str = "101"; // main table minus its default route
    pub(super) const PREF_TUNNEL: &str = "102"; // everything else -> the tunnel
}
#[cfg(target_os = "linux")]
use names::*;

/// Turn this host into an exit node: enable IPv4/IPv6 forwarding and install an
/// nftables table that masquerades overlay-sourced traffic leaving any non-TUN
/// interface, so replies come back to us and we can un-NAT them to the client.
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
/// crash can never leave the host acting as an open router. Linux only.
#[cfg(target_os = "linux")]
fn enable(tun_name: &str) -> Result<()> {
    if let Some(path) = snapshot_path() {
        if !path.exists() {
            let body = format!(
                "v4={}\nv6={}\n",
                read_sysctl(V4_FORWARD),
                read_sysctl(V6_FORWARD)
            );
            crate::config::write_file(&path, body.as_bytes(), false)?;
        }
    }
    write_sysctl(V4_FORWARD, "1")?;
    write_sysctl(V6_FORWARD, "1")?;
    nft_load(&format!(
        "{reset}\
         table inet {t} {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tip saddr {v4} oifname != \"{tun}\" masquerade\n\
         \t\tip6 saddr {v6} oifname != \"{tun}\" masquerade\n\
         \t}}\n\
         }}\n",
        reset = drop_table(SERVER_TABLE),
        t = SERVER_TABLE,
        v4 = V4_OVERLAY,
        v6 = V6_OVERLAY,
        tun = tun_name,
    ))?;
    tracing::info!(tun = tun_name, "exit node forwarding + NAT enabled");
    Ok(())
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
    if let Ok(body) = fs::read_to_string(&path) {
        for line in body.lines() {
            match line.split_once('=') {
                Some(("v4", v)) if !v.is_empty() => drop(write_sysctl(V4_FORWARD, v)),
                Some(("v6", v)) if !v.is_empty() => drop(write_sysctl(V6_FORWARD, v)),
                _ => {}
            }
        }
    }
    let _ = fs::remove_file(&path);
    tracing::info!("exit node forwarding + NAT disabled");
}

/// No-op off Linux: exit-node kernel state only exists there.
#[cfg(not(target_os = "linux"))]
pub fn disable() {}

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
#[cfg(target_os = "linux")]
pub fn install_client_routing(tun_name: &str) -> Result<()> {
    let mark = format!("{SOCKET_MARK:#x}");
    for family in ["-4", "-6"] {
        run_ip(&[
            family, "route", "replace", "default", "dev", tun_name, "table", EXIT_TABLE,
        ])?;
        remove_client_rules(family);
        run_ip(&[
            family, "rule", "add", "fwmark", &mark, "table", "main", "pref", PREF_BYPASS,
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
        run_ip(&[
            family, "rule", "add", "table", EXIT_TABLE, "pref", PREF_TUNNEL,
        ])?;
    }
    // Connections opened from outside the tunnel keep answering out the interface
    // they arrived on. `prerouting` tags the conntrack entry (and marks the packet
    // itself, so the reverse-path check resolves against `main`); `output` restores
    // that mark on the locally-generated replies. It matches only on our own ctmark,
    // so traffic this node originates (including iroh's already-marked sockets) is
    // untouched. `type route` forces a re-route once the mark is set.
    nft_load(&format!(
        "{reset}\
         table inet {t} {{\n\
         \tchain prerouting {{\n\
         \t\ttype filter hook prerouting priority mangle; policy accept;\n\
         \t\tiifname \"{tun}\" return\n\
         \t\tct state new ct mark set {mark}\n\
         \t\tct mark {mark} meta mark set {mark}\n\
         \t}}\n\
         \tchain output {{\n\
         \t\ttype route hook output priority mangle; policy accept;\n\
         \t\tct mark {mark} meta mark set {mark}\n\
         \t}}\n\
         }}\n",
        reset = drop_table(CLIENT_TABLE),
        t = CLIENT_TABLE,
        tun = tun_name,
    ))?;
    tracing::info!(tun = tun_name, "exit-node client full-tunnel routing installed");
    Ok(())
}

/// Remove the client full-tunnel policy routing installed by
/// [`install_client_routing`]: drop the rules, flush the tunnel table, remove the
/// conntrack-mark table. Best-effort and idempotent (the TUN going down also drops
/// its routes). Linux only.
#[cfg(target_os = "linux")]
pub fn teardown_client_routing() {
    for family in ["-4", "-6"] {
        remove_client_rules(family);
        let _ = run_ip(&[family, "route", "flush", "table", EXIT_TABLE]);
    }
    let _ = nft_load(&drop_table(CLIENT_TABLE));
    tracing::info!("exit-node client full-tunnel routing removed");
}

/// Delete our three policy rules for one address family, ignoring "not found".
#[cfg(target_os = "linux")]
fn remove_client_rules(family: &str) {
    for pref in [PREF_BYPASS, PREF_MAIN, PREF_TUNNEL] {
        let _ = run_ip(&[family, "rule", "del", "pref", pref]);
    }
}

/// nft script fragment that removes `table`, whether or not it exists: `delete
/// table` alone fails when absent, so create it first. Prefixed to an install to
/// make it a wholesale replace.
#[cfg(target_os = "linux")]
fn drop_table(table: &str) -> String {
    format!("table inet {table}\ndelete table inet {table}\n")
}

#[cfg(target_os = "linux")]
fn nft_load(script: &str) -> Result<()> {
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
fn run_ip(args: &[&str]) -> Result<()> {
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

/// Where the pre-`enable` forwarding sysctls are stashed so [`disable`] (and the
/// panic hook) can put them back.
#[cfg(target_os = "linux")]
fn snapshot_path() -> Option<PathBuf> {
    crate::config::config_dir()
        .ok()
        .map(|d| d.join("exit-forward.snapshot"))
}

/// The sysctl's current value, or `""` if it can't be read (then it is not
/// restored on teardown).
#[cfg(target_os = "linux")]
fn read_sysctl(path: &str) -> String {
    fs::read_to_string(format!("/proc/sys/{path}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn write_sysctl(path: &str, value: &str) -> Result<()> {
    fs::write(format!("/proc/sys/{path}"), value)
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
        s.reload([("n", strs(&["*"]).as_slice())]);
        assert!(s.allows("n", &iroh::SecretKey::generate().public()));
        assert!(s.is_active());
    }

    #[test]
    fn specific_user_gated() {
        let allowed = iroh::SecretKey::generate().public();
        let other = iroh::SecretKey::generate().public();
        let s = ExitServer::new();
        s.reload([("n", strs(&[&allowed.to_string()]).as_slice())]);
        assert!(s.allows("n", &allowed));
        assert!(!s.allows("n", &other));
        // Unknown network is never an exit.
        assert!(!s.allows("other", &allowed));
    }

    #[test]
    fn empty_allow_is_not_active() {
        let s = ExitServer::new();
        s.reload([("n", [].as_slice())]);
        assert!(!s.is_active());
        assert!(!s.allows("n", &iroh::SecretKey::generate().public()));
    }

    #[test]
    fn clear_drops_all_offers() {
        let s = ExitServer::new();
        s.reload([("n", strs(&["*"]).as_slice())]);
        s.clear();
        assert!(!s.is_active());
    }
}
