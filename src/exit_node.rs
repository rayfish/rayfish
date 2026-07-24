//! Exit nodes: the runtime policy consulted on the data path, and the kernel state
//! (forwarding, NAT, policy routing) that a gateway and its clients need.
//!
//! Rayfish's own firewall is entirely userspace (peer -> daemon -> TUN), but an
//! exit node is a kernel job on both ends. On the **gateway**, once the daemon
//! writes a client's packet to the TUN with a public destination the kernel has to
//! route it out the uplink, which needs IP forwarding plus a NAT masquerade so
//! replies come back ([`ExitServer::apply_os`] -> [`enable`] / [`disable`]). On the
//! **client**, a full tunnel means every route decision changes, including for the
//! node's own iroh transport ([`install_client_routing`]).
//!
//! **Offering** an exit node works on Linux (nftables), macOS and FreeBSD (pf).
//! **Using** one works on Linux and macOS. Both rest on keeping iroh's own sockets
//! out of the tunnel they are carrying ([`configure_socket`]): Linux marks them
//! (`SO_MARK`) and policy-routes the mark around the tunnel; macOS pins them to the
//! physical default-route interface (`IP_BOUND_IF`), which bypasses the routing
//! table altogether. FreeBSD has no equivalent we can reach through iroh yet.
//!
//! The per-network allow decision ([`ExitServer`]) and the client's selection
//! ([`ExitClient`]) are plain userspace state, live on every platform, and are
//! bundled for the data path as [`ExitContext`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use std::num::NonZeroU32;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use anyhow::{Context as _, Result};
use arc_swap::{ArcSwap, ArcSwapOption};
use iroh::EndpointId;
use iroh::endpoint::SocketConfigurator;
use socket2::{Domain, SockRef};
use smol_str::SmolStr;

use crate::membership::is_overlay_ip;

/// Linux fwmark set on iroh's own sockets (via the forked
/// `Endpoint::builder().configure_socket`) and on the replies of any connection that
/// arrived from outside the tunnel. A matching `ip rule` sends marked packets to
/// the main routing table, so both bypass the client's full-tunnel default route
/// (the standard WireGuard/Tailscale loop prevention). Arbitrary non-zero value.
pub const SOCKET_MARK: u32 = 0x7261; // "ra"

/// Whether this host's default route currently points into the TUN, i.e. we are
/// using an exit node.
///
/// Read by the socket hook below on every (re)bind of an iroh socket. Linux does not
/// need it (the fwmark is set unconditionally and simply has no matching `ip rule`
/// when no exit is in use), but macOS does: there the hook pins the socket to the
/// default-route interface, which would otherwise make peers reachable only over a
/// *non-default* interface (a second NIC) unreachable. So we pin only while a full
/// tunnel is actually up, and force a rebind when this flips.
static FULL_TUNNEL: AtomicBool = AtomicBool::new(false);

/// Records whether a full tunnel is up, returning the previous value. Whenever this
/// flips, the caller must trigger an endpoint rebind (`Endpoint::network_change`)
/// so already-bound sockets pick it up; when it did not flip, the rebind can be
/// skipped.
pub fn set_full_tunnel(on: bool) -> bool {
    FULL_TUNNEL.swap(on, Ordering::AcqRel)
}

/// Whether a full tunnel (an exit-node selection) is currently active. Read by
/// the macOS DNS configurator to decide whether to route *all* DNS through Magic
/// DNS (so name resolution goes out via the exit) or only `.ray` (split DNS).
pub fn full_tunnel_active() -> bool {
    FULL_TUNNEL.load(Ordering::Acquire)
}

/// The configurator iroh runs on every socket it opens (both underlay UDP sockets
/// and the relay's TCP connection), before bind/connect and again on every rebind.
///
/// It keeps iroh's own traffic off the full-tunnel default route. Without it the
/// transport is routed into the tunnel it is carrying, and the mesh connection that
/// the exit node is reached over dies the moment the exit node is selected.
///
/// The two platforms get there differently. Linux marks the socket and policy-routes
/// the mark around the tunnel. macOS has no fwmark, so we pin the socket to the
/// default-route interface instead (`IP_BOUND_IF`), which makes it ignore the routing
/// table altogether. That is what Tailscale does on darwin, and it is also why the
/// configurator must re-run on rebind: the right interface changes when the default
/// route does (wifi to ethernet), and a stale pin would strand the transport on a
/// dead interface.
pub struct LoopPrevention;

impl SocketConfigurator for LoopPrevention {
    fn configure(&self, sock: SockRef<'_>, domain: Domain) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _ = domain;
            // SO_MARK needs CAP_NET_ADMIN, which an unprivileged process (tests,
            // embedders) does not have. That is fine to skip rather than fail the
            // bind: such a process cannot install the policy routing that consumes
            // the mark either, so there is no tunnel its transport could leak into.
            if let Err(e) = sock.set_mark(SOCKET_MARK)
                && e.raw_os_error() != Some(libc::EPERM)
            {
                return Err(e);
            }
        }
        #[cfg(target_os = "macos")]
        bind_outside_tunnel(&sock, domain)?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = (&sock, domain);
        Ok(())
    }
}

/// The physical default-route interface per family, snapshotted by
/// [`capture_physical_defaults`] before the tunnel routes go in.
#[cfg(target_os = "macos")]
static PHYSICAL_DEFAULTS: std::sync::Mutex<Option<(Option<String>, Option<String>)>> =
    std::sync::Mutex::new(None);

/// Record which interface each family's default route leaves by, to pin iroh's
/// sockets to for as long as the full tunnel is up.
///
/// Must run **before** the tunnel's split defaults are installed, because once they
/// are, the answer is the tunnel: a host with no IPv6 default route (common) has
/// `route get -inet6 default` resolve to the TUN as soon as `::/1` points there, and
/// pinning iroh to that puts its transport inside the tunnel it is carrying. A
/// family with no physical default of its own falls back to the other family's
/// interface, which is the physical NIC either way; that leaves such a socket
/// exactly as (un)usable as it was before the tunnel, instead of looping.
#[cfg(target_os = "macos")]
pub fn capture_physical_defaults() {
    let v4 = default_interface("-inet").and_then(usable_pin_iface);
    let v6 = default_interface("-inet6").and_then(usable_pin_iface);
    let (v4, v6) = (v4.clone().or_else(|| v6.clone()), v6.or(v4));
    tracing::debug!(?v4, ?v6, "captured physical default interfaces for the socket pin");
    *PHYSICAL_DEFAULTS.lock().unwrap() = Some((v4, v6));
}

/// Drop the snapshot when the full tunnel comes down.
#[cfg(target_os = "macos")]
pub fn clear_physical_defaults() {
    *PHYSICAL_DEFAULTS.lock().unwrap() = None;
}

/// Rejects a tunnel interface as a pin target: pinning iroh's socket to the TUN
/// routes its transport into the tunnel it is carrying, which blackholes the very
/// connection the exit node is reached over. Unpinned is strictly better.
#[cfg(target_os = "macos")]
fn usable_pin_iface(name: String) -> Option<String> {
    (!name.starts_with("utun")).then_some(name)
}

/// Pins a socket to the physical default-route interface, so its egress ignores the
/// routing table (and therefore the tunnel's default route).
///
/// Only while a full tunnel is up: see [`FULL_TUNNEL`]. Uses the snapshot taken
/// before the tunnel routes went in, never a live lookup, which by then resolves to
/// the tunnel. A family with no interface to pin to is left unpinned.
#[cfg(target_os = "macos")]
fn bind_outside_tunnel(sock: &SockRef<'_>, domain: Domain) -> std::io::Result<()> {
    if !FULL_TUNNEL.load(Ordering::Acquire) {
        return Ok(());
    }
    let v6 = domain == Domain::IPV6;
    let snapshot = PHYSICAL_DEFAULTS.lock().unwrap().clone();
    let name = match snapshot {
        Some((v4_if, v6_if)) => {
            if v6 {
                v6_if
            } else {
                v4_if
            }
        }
        // No snapshot (the tunnel flag flipped without one): fall back to a live
        // lookup, still refusing to pin to a tunnel.
        None => default_interface(if v6 { "-inet6" } else { "-inet" }).and_then(usable_pin_iface),
    };
    let Some(index) = name.and_then(|name| if_index(&name)) else {
        return Ok(());
    };
    if v6 {
        sock.bind_device_by_index_v6(Some(index))
    } else {
        sock.bind_device_by_index_v4(Some(index))
    }
}

/// Resolves an interface name to its kernel index.
#[cfg(target_os = "macos")]
fn if_index(name: &str) -> Option<NonZeroU32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `cname` is a valid NUL-terminated C string for the duration of the call.
    NonZeroU32::new(unsafe { libc::if_nametoindex(cname.as_ptr()) })
}

/// The physical default-route gateway, for host routes that must bypass the full
/// tunnel.
#[cfg(target_os = "macos")]
fn default_gateway() -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", "-inet", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
}

/// Host routes installed to keep iroh's own underlay traffic off the full tunnel,
/// tracked so teardown can remove exactly what it added.
#[cfg(target_os = "macos")]
static EXCLUDED_IPS: std::sync::Mutex<Vec<Ipv4Addr>> = std::sync::Mutex::new(Vec::new());

/// Route each underlay IP straight out the physical gateway so iroh's own traffic
/// is not swallowed by the full tunnel it is carrying. A `/32` host route beats the
/// `0/1`+`128/1` split default, so it bypasses the TUN. Idempotent.
///
/// This, not the socket pin, is what actually keeps the transport alive. The pin
/// only takes effect when iroh rebinds its sockets, and `Endpoint::network_change`
/// merely asks the network monitor to re-evaluate: it rebinds only if the monitor
/// decides the change was *major*, which a route-only change is not. So a live
/// socket keeps using the routing table, and anything without a host route here
/// goes into the tunnel and disappears.
///
/// Applies to the relay servers (resolved while DNS is still split) and to the exit
/// peer's own direct addresses. IPv6 underlay addresses are not excluded yet, so a
/// peer reachable only over IPv6 still falls back to the relay.
#[cfg(target_os = "macos")]
pub fn exclude_from_tunnel(ips: &[Ipv4Addr]) {
    let Some(gw) = default_gateway() else {
        tracing::warn!("no default gateway; cannot keep iroh's traffic off the exit tunnel");
        return;
    };
    let mut excluded = EXCLUDED_IPS.lock().unwrap();
    let mut added = 0;
    for ip in ips {
        if excluded.contains(ip) {
            continue;
        }
        let s = ip.to_string();
        let _ = Command::new("route")
            .args(["-n", "delete", "-host", &s])
            .status();
        let ok = Command::new("route")
            .args(["-n", "add", "-host", &s, &gw])
            .status()
            .map(|st| st.success())
            .unwrap_or(false);
        if ok {
            excluded.push(*ip);
            added += 1;
        }
    }
    if added > 0 {
        tracing::debug!(added, total = excluded.len(), %gw, "excluded IPs from the exit tunnel");
    }
}

/// Remove the host routes installed by [`exclude_from_tunnel`].
#[cfg(target_os = "macos")]
pub fn remove_tunnel_exclusions() {
    let mut excluded = EXCLUDED_IPS.lock().unwrap();
    for ip in excluded.drain(..) {
        let _ = Command::new("route")
            .args(["-n", "delete", "-host", &ip.to_string()])
            .status();
    }
}

/// Per-network allow policy for peers using this node as an exit node, consulted
/// on the gateway's inbound data path (`forward::evaluate_inbound`). Cheap to clone
/// (Arc-backed) and swapped wholesale whenever the allow-lists change. Empty until
/// the data plane activates and populates it from config, so a node that offers no
/// exit (or is on standby) transits nothing.
#[derive(Clone, Default)]
pub struct ExitServer {
    nets: Arc<ArcSwap<HashMap<SmolStr, Allow>>>,
    /// The gateway's own addresses, refused as transit destinations: a packet to
    /// one of them would be local-delivered by the kernel, reaching this host's
    /// services without ever passing its rayfish inbound firewall.
    self_addrs: Arc<ArcSwap<HashSet<IpAddr>>>,
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

    /// Whether `dst` is one of the gateway's own addresses (so transit to it must
    /// be refused; see `self_addrs`).
    pub fn is_self_addr(&self, dst: IpAddr) -> bool {
        self.self_addrs.load().contains(&dst)
    }

    /// Replace the set of the gateway's own addresses. Refreshed on every
    /// reconcile ([`apply_os`](Self::apply_os)) from the host's interfaces.
    pub fn set_self_addrs(&self, addrs: HashSet<IpAddr>) {
        self.self_addrs.store(Arc::new(addrs));
    }

    /// Whether we currently offer an exit node on any network (drives whether the
    /// kernel forwarding/NAT should be installed).
    pub fn is_active(&self) -> bool {
        !self.nets.load().is_empty()
    }

    /// Whether we currently offer an exit node on `network`. This is the loaded
    /// runtime policy, not the config: false on standby or after a failed enable,
    /// which is exactly what the roster advertisement has to reflect.
    pub fn is_offering(&self, network: &str) -> bool {
        self.nets.load().contains_key(network)
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
    /// directions are idempotent, so this is safe to call on every change.
    ///
    /// [`enable`] is not atomic (forwarding is on before the NAT rules load), so a
    /// failure rolls the whole thing back *and* drops the offers: a gateway that
    /// forwards but cannot masquerade would push overlay-sourced packets out its
    /// uplink un-NAT'd, which never gets a reply and looks like source spoofing to
    /// everyone upstream. Returns a user-facing message when that happens.
    #[must_use]
    pub fn apply_os(&self, tun_name: &str) -> Option<String> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        if self.is_active() {
            self.set_self_addrs(host_addresses());
            if let Err(e) = enable(tun_name) {
                disable();
                self.clear();
                tracing::warn!(error = %e, "failed to enable exit-node forwarding/NAT");
                return Some(format!("failed to enable exit node: {e}"));
            }
        } else {
            disable();
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
        let _ = tun_name;
        None
    }
}

/// Whether an exit node will transit a packet to `dst`. An exit node is an
/// *internet* gateway, so it forwards to globally-routable addresses only.
///
/// Everything the gateway can reach but the internet cannot is refused: its own
/// loopback, its private LAN (RFC 1918 / unique-local), link-local (which on a
/// cloud host includes `169.254.169.254`, the instance metadata service handing
/// out credentials), multicast, and the unspecified/broadcast addresses. Without
/// this, permitting a peer to route out through us would silently also hand it the
/// inside of our network and our cloud identity. Reaching a gateway's LAN is a
/// separate capability (a subnet router), not something an exit-node offer should
/// imply.
///
/// The overlay's own ranges are refused too. The data path never asks about them
/// (it routes an overlay destination to its peer long before considering transit),
/// but this is the whole answer to "may we forward this?", so it should not depend
/// on its caller having already checked.
/// Every address configured on this host's interfaces, asked of the OS
/// (`ip -o addr` on Linux, `ifconfig -a` on the BSDs). Best-effort: an empty set
/// on failure, which only costs the self-address transit refusal its input (the
/// LAN/loopback refusals in [`is_transitable`] do not depend on it).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn host_addresses() -> HashSet<IpAddr> {
    #[cfg(target_os = "linux")]
    let out = Command::new("ip").args(["-o", "addr", "show"]).output();
    #[cfg(not(target_os = "linux"))]
    let out = Command::new("ifconfig").arg("-a").output();
    match out {
        Ok(out) if out.status.success() => {
            parse_host_addresses(&String::from_utf8_lossy(&out.stdout))
        }
        _ => HashSet::new(),
    }
}

/// Pull the addresses out of `ip -o addr show` or `ifconfig -a` output: any token
/// following an `inet`/`inet6` keyword, with the Linux `/prefix` and BSD `%zone`
/// suffixes stripped.
fn parse_host_addresses(out: &str) -> HashSet<IpAddr> {
    let mut addrs = HashSet::new();
    let mut tokens = out.split_whitespace().peekable();
    while let Some(tok) = tokens.next() {
        if tok != "inet" && tok != "inet6" {
            continue;
        }
        let Some(raw) = tokens.peek() else { break };
        let addr = raw.split(['/', '%']).next().unwrap_or(raw);
        if let Ok(ip) = addr.parse::<IpAddr>() {
            addrs.insert(ip);
        }
    }
    addrs
}

pub fn is_transitable(dst: IpAddr) -> bool {
    if is_overlay_ip(dst) {
        return false;
    }
    match dst {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_documentation()
                // 0.0.0.0/8 and 240.0.0.0/4 are not routable either.
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240)
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                // fe80::/10 link-local and fc00::/7 unique-local.
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.segments()[0] & 0xfe00) == 0xfc00)
        }
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

    /// Whether a datagram from sender `peer_user` is our own exit-node return
    /// traffic (the sender is our chosen exit peer). Deliberately not scoped to
    /// the arrival network: the gateway tags replies with whatever shared network
    /// its generic route picks, which need not be the network we selected the
    /// exit on. The sender identity is what the exemption trusts.
    pub fn is_return_traffic(&self, peer_user: &EndpointId) -> bool {
        self.inner
            .load()
            .as_ref()
            .is_some_and(|s| &s.peer_user == peer_user)
    }

    /// Whether return traffic arriving from a peer whose verified mesh IPv4 is
    /// `peer_v4` is our own exit-node return traffic. The sender's mesh IPv4 is
    /// resolved by the reader from our own roster (so it cannot be forged) and is
    /// the same whatever family the reply packet is, which makes it a more robust
    /// match than the resolved user identity (a device-vs-user-key mismatch would
    /// wrongly reject every reply). Matches by identity *or* IPv4.
    pub fn is_return_from(&self, peer_user: &EndpointId, peer_v4: Ipv4Addr) -> bool {
        self.inner
            .load()
            .as_ref()
            .is_some_and(|s| &s.peer_user == peer_user || s.ipv4 == peer_v4)
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
// Kernel state, shared across the platforms that implement a gateway
// ---------------------------------------------------------------------------

/// The overlay source ranges a gateway masquerades when forwarding out its uplink.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const V4_OVERLAY: &str = "100.64.0.0/10";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const V6_OVERLAY: &str = "200::/7";

/// The forwarding sysctls a gateway turns on: paths under `/proc/sys` on Linux,
/// dotted names for `sysctl(8)` on the BSDs.
#[cfg(target_os = "linux")]
const V4_FORWARD: &str = "net/ipv4/ip_forward";
#[cfg(target_os = "linux")]
const V6_FORWARD: &str = "net/ipv6/conf/all/forwarding";
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const V4_FORWARD: &str = "net.inet.ip.forwarding";
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const V6_FORWARD: &str = "net.inet6.ip6.forwarding";

/// What [`enable`] changed, so [`disable`] can put it back. Written to disk rather
/// than kept in memory because the panic hook (which `abort()`s) has to be able to
/// tear the gateway down, and because a crashed daemon must never leave the host
/// forwarding: the next start, or a hand-run `ray down`, restores from this file.
///
/// Present-but-empty fields mean "we could not read the original, so do not touch
/// it on the way out". `pf_token` is BSD-only (see [`pf_enable`]).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
#[derive(Default)]
struct Snapshot {
    v4: String,
    v6: String,
    pf_token: Option<String>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
impl Snapshot {
    /// Read the snapshot, or a default one if it does not exist / cannot be parsed.
    fn load(path: &Path) -> Self {
        let mut snap = Self::default();
        let Ok(body) = fs::read_to_string(path) else {
            return snap;
        };
        for line in body.lines() {
            match line.split_once('=') {
                Some(("v4", v)) => snap.v4 = v.to_string(),
                Some(("v6", v)) => snap.v6 = v.to_string(),
                Some(("pf_token", v)) if !v.is_empty() => snap.pf_token = Some(v.to_string()),
                _ => {}
            }
        }
        snap
    }

    fn save(&self, path: &Path) -> Result<()> {
        let mut body = format!("v4={}\nv6={}\n", self.v4, self.v6);
        if let Some(token) = &self.pf_token {
            body.push_str(&format!("pf_token={token}\n"));
        }
        crate::config::write_file(path, body.as_bytes(), false)
    }

    /// Put the forwarding sysctls back, skipping any we never managed to read.
    fn restore_sysctls(&self) {
        for (name, value) in [(V4_FORWARD, &self.v4), (V6_FORWARD, &self.v6)] {
            if !value.is_empty() {
                let _ = write_sysctl(name, value);
            }
        }
    }
}

/// Where the pre-`enable` state is stashed so [`disable`] (and the panic hook) can
/// put it back.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn snapshot_path() -> Option<PathBuf> {
    crate::config::config_dir()
        .ok()
        .map(|d| d.join("exit-forward.snapshot"))
}

// ---------------------------------------------------------------------------
// Linux kernel state (nftables + policy routing)
// ---------------------------------------------------------------------------

/// The nftables tables we own (one per role, so gateway and client are
/// independent) and the sysctls and routing state the two roles need.
#[cfg(target_os = "linux")]
mod names {
    pub(super) const SERVER_TABLE: &str = "rayfish_exit";
    pub(super) const CLIENT_TABLE: &str = "rayfish_exit_client";
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
/// crash can never leave the host acting as an open router. Writing it is therefore
/// a precondition, not a nicety: without it we could turn forwarding on and never
/// be able to put it back, so we refuse instead. Linux only.
#[cfg(target_os = "linux")]
fn enable(tun_name: &str) -> Result<()> {
    let path = snapshot_path().context("no config dir to snapshot the forwarding sysctls into")?;
    if !path.exists() {
        Snapshot {
            v4: read_sysctl(V4_FORWARD),
            v6: read_sysctl(V6_FORWARD),
            pf_token: None,
        }
        .save(&path)?;
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
    Snapshot::load(&path).restore_sysctls();
    let _ = fs::remove_file(&path);
    tracing::info!("exit node forwarding + NAT disabled");
}

/// No-op where we have no gateway implementation: there is no kernel state to undo.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub fn disable() {}

/// No-op off Linux. Only there does the client full tunnel leave state that can
/// outlive the process (policy rules and an nft table). The macOS client's state
/// dies with the daemon on its own: the split-default routes sit on the utun, which
/// the kernel destroys (routes included) when the owning fd closes, and the socket
/// pinning lives inside the process. So the panic hook, which calls this on every
/// platform, has nothing to do here.
#[cfg(not(target_os = "linux"))]
pub fn teardown_client_routing() {}

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
    // The conntrack-mark table loads first: nothing routes into the tunnel until
    // the `ip rule`s below go in, but the moment they do, an inbound connection's
    // replies depend on this table already restoring the mark. Loading it after
    // the rules would open a window (or, on a mid-way failure, a permanent state)
    // where an SSH session to this host's public IP is routed into the tunnel and
    // cut.
    //
    // Connections opened from outside the tunnel keep answering out the interface
    // they arrived on. `prerouting` tags the conntrack entry of anything arriving on
    // a non-TUN interface (and marks the packet itself, so the reverse-path check
    // resolves against `main`); `output` restores that mark on the locally-generated
    // replies, and `type route` forces a re-route once it is set.
    //
    // The tag is deliberately unconditional rather than `ct state new`: a connection
    // that was already established when the tunnel came up would otherwise keep a
    // ctmark of 0, its replies would go out the tunnel, and it would be cut. Marking
    // every inbound packet picks those up on their next packet instead. Re-marking a
    // connection is idempotent, and traffic this node originates never reaches this
    // chain (iroh's underlay sockets already carry the same mark via `SO_MARK`).
    let mark = format!("{SOCKET_MARK:#x}");
    nft_load(&format!(
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
    ))?;
    for family in ["-4", "-6"] {
        run_ip(&[
            family, "route", "replace", "default", "dev", tun_name, "table", EXIT_TABLE,
        ])?;
        remove_client_rules(family);
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
        run_ip(&[
            family,
            "rule",
            "add",
            "table",
            EXIT_TABLE,
            "pref",
            PREF_TUNNEL,
        ])?;
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
        remove_client_rules(family);
        let _ = run_ip(&[family, "route", "flush", "table", EXIT_TABLE]);
    }
    let _ = nft_load(&drop_table(CLIENT_TABLE));
    tracing::info!("exit-node client full-tunnel routing removed");
}

/// Delete our three policy rules for one address family, ignoring "not found".
/// Each del names the full rule spec, mirroring the adds in
/// [`install_client_routing`], never the pref alone: `ip rule del` removes the
/// first rule matching only the keys given, so a bare `del pref 100` would
/// destroy a foreign rule (another VPN's, systemd-networkd's) that happens to
/// sit at one of our preference numbers.
#[cfg(target_os = "linux")]
fn remove_client_rules(family: &str) {
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
    let _ = run_ip(&[family, "rule", "del", "table", EXIT_TABLE, "pref", PREF_TUNNEL]);
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
const ANCHOR: &str = if cfg!(target_os = "macos") {
    "com.apple/rayfish_exit"
} else {
    "rayfish_exit"
};

/// What the main ruleset has to name for [`ANCHOR`] to be reached. On macOS that is
/// Apple's wildcard, which our anchor sits under; on FreeBSD it is our anchor itself.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const ANCHOR_REF: &str = if cfg!(target_os = "macos") {
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
fn enable(_tun_name: &str) -> Result<()> {
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
    write_sysctl(V4_FORWARD, "1")?;
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

    let v4 = default_interface("-inet");
    let v6 = default_interface("-inet6");
    let rules = nat_rules(v4.as_deref(), v6.as_deref())
        .context("no default route, so there is no uplink to send an exit node's traffic out")?;
    pf_load_anchor(&rules)?;
    tracing::info!(v4 = ?v4, v6 = ?v6, "exit node forwarding + NAT enabled");
    Ok(())
}

/// The pf ruleset masquerading overlay traffic out the given uplinks, or `None` if
/// there is no uplink at all.
///
/// NAT is scoped to the interface each family's default route leaves by, and
/// rewrites to that interface's *current* address: the parentheses tell pf to
/// re-resolve it, so a DHCP renewal doesn't strand the rule on a stale IP. The two
/// families are independent, because a host with no IPv6 default route is still a
/// perfectly good IPv4 exit node.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn nat_rules(v4: Option<&str>, v6: Option<&str>) -> Option<String> {
    let mut rules = String::new();
    if let Some(iface) = v4 {
        rules.push_str(&format!(
            "nat on {iface} inet from {V4_OVERLAY} to any -> ({iface})\n"
        ));
    }
    if let Some(iface) = v6 {
        rules.push_str(&format!(
            "nat on {iface} inet6 from {V6_OVERLAY} to any -> ({iface})\n"
        ));
    }
    (!rules.is_empty()).then_some(rules)
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
fn pf_enable() -> Result<Option<String>> {
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
fn pf_release(token: &str) {
    if cfg!(target_os = "macos") {
        let _ = pfctl(&["-X", token]);
    } else {
        let _ = pfctl(&["-d"]);
    }
}

/// The marker stored in the snapshot's token slot on FreeBSD when [`pf_enable`]
/// was the one to turn pf on.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const PF_ENABLED_BY_US: &str = "pf-enabled-by-rayfish";

/// Whether pf is currently enabled (`pfctl -s info` reports `Status: Enabled`).
/// Errs on the side of "running": claiming a running pf is down would make
/// [`pf_enable`] flip it on and hand [`pf_release`] the right to turn it off.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn pf_running() -> bool {
    pfctl(&["-s", "info"])
        .map(|out| {
            out.lines()
                .any(|l| l.trim_start().strip_prefix("Status:").is_some_and(|s| s.trim_start().starts_with("Enabled")))
        })
        .unwrap_or(true)
}

/// Replace our anchor's ruleset with `rules`.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn pf_load_anchor(rules: &str) -> Result<()> {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = Command::new("pfctl")
        .args(["-a", ANCHOR, "-f", "-"])
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
fn ensure_anchor_referenced() -> Result<()> {
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
const PF_CONF: &str = "/etc/pf.conf";

/// The interface the default route for one family (`-inet` / `-inet6`) leaves by,
/// or `None` if there is no default route for it.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn default_interface(family: &str) -> Option<String> {
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
fn pfctl(args: &[&str]) -> Result<String> {
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
fn read_sysctl(name: &str) -> String {
    Command::new("sysctl")
        .args(["-n", name])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn write_sysctl(name: &str, value: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Pinning iroh to a tunnel interface puts its transport inside the tunnel it
    /// is carrying, which is worse than not pinning at all.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_tunnel_is_never_a_pin_target() {
        assert_eq!(usable_pin_iface("en0".into()), Some("en0".into()));
        assert_eq!(usable_pin_iface("en12".into()), Some("en12".into()));
        assert_eq!(usable_pin_iface("utun7".into()), None);
        assert_eq!(usable_pin_iface("utun0".into()), None);
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
    fn only_globally_routable_destinations_transit() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert!(
                is_transitable(ip.parse().unwrap()),
                "{ip} is on the internet and should transit"
            );
        }
        for ip in [
            "169.254.169.254", // cloud instance metadata
            "192.168.1.1",     // LAN
            "10.0.0.1",        // LAN
            "172.16.0.1",      // LAN
            "127.0.0.1",       // loopback
            "0.0.0.0",         // unspecified
            "255.255.255.255", // broadcast
            "224.0.0.1",       // multicast
            "::1",             // v6 loopback
            "fe80::1",         // v6 link-local
            "fd00::1",         // v6 unique-local
            "ff02::1",         // v6 multicast
            "100.64.0.1",      // the overlay itself: routed to its peer, never transited
            "200::1",
        ] {
            assert!(
                !is_transitable(ip.parse().unwrap()),
                "{ip} is reachable only from inside the gateway and must not transit"
            );
        }
    }

    /// The pf rule text is the whole of the BSD gateway, and nothing in CI ever runs
    /// it: pin the syntax here so a typo shows up as a failing test rather than as a
    /// gateway that comes up and quietly NATs nothing.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn nat_rules_masquerade_each_family_out_its_own_uplink() {
        let both = nat_rules(Some("en0"), Some("en1")).unwrap();
        assert_eq!(
            both,
            "nat on en0 inet from 100.64.0.0/10 to any -> (en0)\n\
             nat on en1 inet6 from 200::/7 to any -> (en1)\n"
        );
        // A host with no IPv6 default route is still an IPv4 exit node.
        let v4_only = nat_rules(Some("en0"), None).unwrap();
        assert!(v4_only.contains("inet from 100.64.0.0/10"));
        assert!(!v4_only.contains("inet6"));
        // With no uplink at all there is nothing to be a gateway for.
        assert!(nat_rules(None, None).is_none());
    }

    #[test]
    fn host_address_parser_reads_ip_and_ifconfig_output() {
        // `ip -o addr show` (Linux)
        let linux = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 51.15.20.7/24 brd 51.15.20.255 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:bc8:710:d1::1/64 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::1c:2ff:fe33:4455/64 scope link \\       valid_lft forever preferred_lft forever";
        let addrs = parse_host_addresses(linux);
        assert!(addrs.contains(&"51.15.20.7".parse().unwrap()));
        assert!(addrs.contains(&"2001:bc8:710:d1::1".parse().unwrap()));
        assert!(addrs.contains(&"127.0.0.1".parse().unwrap()));

        // `ifconfig -a` (macOS/FreeBSD), including a zone-suffixed link-local.
        let mac = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 fe80::8aa:bbcc:ddee:ff00%en0 prefixlen 64 secured scopeid 0xb
\tinet6 2a01:cb00:11:2200:1:2:3:4 prefixlen 64 autoconf secured";
        let addrs = parse_host_addresses(mac);
        assert!(addrs.contains(&"192.168.1.5".parse().unwrap()));
        assert!(addrs.contains(&"2a01:cb00:11:2200:1:2:3:4".parse().unwrap()));
        assert!(addrs.contains(&"fe80::8aa:bbcc:ddee:ff00".parse().unwrap()));
    }

    #[test]
    fn clear_drops_all_offers() {
        let s = ExitServer::new();
        s.reload([("n", strs(&["*"]).as_slice())]);
        s.clear();
        assert!(!s.is_active());
    }
}
