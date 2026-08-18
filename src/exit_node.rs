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

use crate::membership::ExitFamilies;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "macos")]
use std::num::NonZeroU32;
use std::sync::Arc;
// Only the macOS statics below hold one.
#[cfg(target_os = "macos")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
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
use smol_str::SmolStr;
use socket2::{Domain, SockRef};

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

/// Whether the live tunnel claims IPv4, i.e. it is not an IPv6-only one. Only the
/// macOS pin reads it, and only to stay off the family it did not claim.
///
/// Pinning is per-socket and per-family, so a mode that tunnels IPv6 alone must
/// not pin the IPv4 sockets: that would bind the whole IPv4 underlay to the
/// physical interface and carve it out of whichever co-resident VPN owns IPv4 on
/// that Mac, which is the configuration IPv6-only mode exists to share with.
/// `tunnel_relevant` already applies exactly this filter to the host-route
/// exclusions one layer up; this is the same rule for the coarser knob.
static FULL_TUNNEL_V4: AtomicBool = AtomicBool::new(false);

/// Records whether a full tunnel is up and whether it carries IPv4, returning
/// whether either of those *changed*. The caller must trigger an endpoint rebind
/// (`Endpoint::network_change`) when it did, so already-bound sockets pick the new
/// state up; when nothing changed the rebind can be skipped.
///
/// `claims_v4` used to be a restatement of the node's own mode, fixed for the
/// daemon's lifetime, and the answer only reported the on/off flip. It is now
/// `ExitFamilies::tunnelled`, which follows the gateway's claim and changes under
/// a live tunnel: a gateway that gains or loses an IPv6 uplink republishes, and
/// the re-apply arrives with a different value. Reporting only the on/off flip
/// there returns "nothing changed" for a re-apply of a live tunnel, so the pin is
/// never re-evaluated: IPv4 sockets bound while the tunnel did not claim IPv4 stay
/// unpinned once it does (iroh's own IPv4 underlay then routes into the tunnel it
/// is carrying), and sockets pinned while it did stay pinned once it stops (the
/// host's whole IPv4 underlay stays carved out of the co-resident VPN).
pub fn set_full_tunnel(on: bool, claims_v4: bool) -> bool {
    let wants_v4 = on && claims_v4;
    // `FULL_TUNNEL_V4` first, and not for tidiness: a socket binding between the
    // two stores reads both. Publishing `FULL_TUNNEL` first opens a window where
    // an install looks like a tunnel that carries no IPv4, so a v4 socket binding
    // in it skips the pin. The rebind that follows a change heals it, but the
    // window is free to close.
    let was_v4 = FULL_TUNNEL_V4.swap(wants_v4, Ordering::AcqRel);
    let was_on = FULL_TUNNEL.swap(on, Ordering::AcqRel);
    was_on != on || was_v4 != wants_v4
}

/// Whether a full tunnel (an exit-node selection) is currently active. Read by
/// the macOS DNS configurator to decide whether to route *all* DNS through Magic
/// DNS (so name resolution goes out via the exit) or only `.ray` (split DNS).
pub fn full_tunnel_active() -> bool {
    FULL_TUNNEL.load(Ordering::Acquire)
}

/// Whether the live tunnel claims IPv4. See [`FULL_TUNNEL_V4`].
pub fn full_tunnel_claims_v4() -> bool {
    FULL_TUNNEL_V4.load(Ordering::Acquire)
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
static PHYSICAL_DEFAULTS: Mutex<Option<(Option<String>, Option<String>)>> = Mutex::new(None);

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
    tracing::debug!(
        ?v4,
        ?v6,
        "captured physical default interfaces for the socket pin"
    );
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
    // Nothing to keep this socket out of if its family was never claimed. See
    // [`FULL_TUNNEL_V4`].
    if !v6 && !full_tunnel_claims_v4() {
        return Ok(());
    }
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

/// The physical default-route gateway for one family, for host routes that must
/// bypass the full tunnel. `None` when that family has no default route, which is
/// the ordinary state of a Mac with no native IPv6.
#[cfg(target_os = "macos")]
fn default_gateway(family: &str) -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", family, "default"])
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
static EXCLUDED_IPS: Mutex<Vec<IpAddr>> = Mutex::new(Vec::new());

/// Route each underlay IP straight out the physical gateway so iroh's own traffic
/// is not swallowed by the full tunnel it is carrying. A `/32` or `/128` host route
/// beats the `0/1`+`128/1` (or `::/1`+`8000::/1`) split default, so it bypasses the
/// TUN. Idempotent.
///
/// This, not the socket pin, is what actually keeps the transport alive. The pin
/// only takes effect when iroh rebinds its sockets, and `Endpoint::network_change`
/// merely asks the network monitor to re-evaluate: it rebinds only if the monitor
/// decides the change was *major*, which a route-only change is not. So a live
/// socket keeps using the routing table, and anything without a host route here
/// goes into the tunnel and disappears.
///
/// Applies to the relay servers (resolved while DNS is still split) and to the exit
/// peer's own direct addresses. Both families: an IPv6-only node's tunnel is IPv6,
/// so IPv6 underlay paths are exactly the ones it would otherwise swallow, and the
/// address a peer is reachable at is not something we get to choose.
///
/// Per family, and best-effort per address: a host with no default route in one
/// family simply has nothing to route around, and the addresses in the other
/// family still get their exclusion.
#[cfg(target_os = "macos")]
pub fn exclude_from_tunnel(ips: &[IpAddr]) {
    let mut excluded = EXCLUDED_IPS.lock().unwrap();
    let mut added = 0;
    let mut gateways: HashMap<&str, Option<String>> = HashMap::new();
    let mut ungatewayed: HashSet<&str> = HashSet::new();
    for ip in ips {
        if excluded.contains(ip) {
            continue;
        }
        let family = if ip.is_ipv6() { "-inet6" } else { "-inet" };
        let gw = gateways
            .entry(family)
            .or_insert_with(|| default_gateway(family));
        let Some(gw) = gw.as_deref() else {
            // Worth saying: an address in a family with no default route is one
            // this host cannot reach at all, so it is not merely un-excluded.
            ungatewayed.insert(family);
            continue;
        };
        let s = ip.to_string();
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-host", &s])
            .status();
        let ok = Command::new("route")
            .args(["-n", "add", family, "-host", &s, gw])
            .status()
            .map(|st| st.success())
            .unwrap_or(false);
        if ok {
            excluded.push(*ip);
            added += 1;
        }
    }
    for family in ungatewayed {
        tracing::warn!(
            family,
            "no default gateway for this family; cannot keep iroh's traffic there \
             off the exit tunnel"
        );
    }
    if added > 0 {
        tracing::debug!(
            added,
            total = excluded.len(),
            "excluded IPs from the exit tunnel"
        );
    }
}

/// Remove the host routes installed by [`exclude_from_tunnel`].
#[cfg(target_os = "macos")]
pub fn remove_tunnel_exclusions() {
    let mut excluded = EXCLUDED_IPS.lock().unwrap();
    for ip in excluded.drain(..) {
        let family = if ip.is_ipv6() { "-inet6" } else { "-inet" };
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-host", &ip.to_string()])
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
    /// Whether this host can actually egress IPv6. Sampled by `apply_os`
    /// alongside `self_addrs`, and re-probed on the reconverge that publishes it
    /// ([`refresh_v6_uplink`](Self::refresh_v6_uplink)), since on a gateway
    /// `apply_os` only runs on `ray up` and on a local `ray exit-node` command.
    /// Advertised as `Member.exit_families` so an IPv6-only client can tell a
    /// gateway it can use from one that would take its traffic and have nowhere
    /// to send it.
    v6_uplink: Arc<AtomicBool>,
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

    /// Whether an exit node we offer can carry IPv6. Read at the same moment as
    /// [`is_offering`](Self::is_offering) when publishing the roster claim, so the
    /// two never disagree about what this host does.
    pub fn offers_v6(&self) -> bool {
        self.v6_uplink.load(Ordering::Relaxed)
    }

    /// Re-probe the IPv6 uplink, for the reconverge that publishes the claim.
    ///
    /// `apply_os` samples it too, but on a gateway that path only runs on `ray up`
    /// and on a local `ray exit-node` command, so a box that gains IPv6 an hour
    /// later would keep advertising IPv4-only until the next `ray up`. This runs
    /// on the roster's own cadence instead. Spawns a process, so callers put it on
    /// the blocking pool; a no-op unless we actually offer an exit node.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub fn refresh_v6_uplink(&self) {
        if self.is_active() {
            self.v6_uplink.store(has_v6_uplink(), Ordering::Relaxed);
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    pub fn refresh_v6_uplink(&self) {}

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
            // Re-read rather than cache: an uplink gains or loses IPv6 with a
            // lease or a link change, and the claim we publish has to follow.
            self.v6_uplink.store(has_v6_uplink(), Ordering::Relaxed);
            if let Err(e) = enable(tun_name) {
                disable();
                self.clear();
                tracing::warn!(error = %e, "failed to enable exit-node forwarding/NAT");
                return Some(format!("failed to enable exit node: {e}"));
            }
        } else {
            disable();
            self.v6_uplink.store(false, Ordering::Relaxed);
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
// Same platforms as its only caller: Android has neither `ip` nor `ifconfig`,
// so nothing there produces output for it to parse.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
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

/// Whether this host has an IPv6 default route, i.e. an exit node it offers can
/// masquerade IPv6 onto something. A gateway without one is still a perfectly good
/// IPv4 exit node, which is why this is advertised rather than refused.
#[cfg(target_os = "linux")]
fn has_v6_uplink() -> bool {
    ip_output(&["-6", "route", "show", "default"]).is_some_and(|out| !out.trim().is_empty())
}

/// The BSD counterpart, over the same `route -n get` the NAT rules already use to
/// find the interface to masquerade onto.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn has_v6_uplink() -> bool {
    default_interface("-inet6").is_some()
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
    /// Which families this tunnel carries: [`ExitFamilies::tunnelled`] of the
    /// gateway's claim and our own data plane. Never `Unknown` or `Neither`, since
    /// a selection that carries nothing is refused rather than installed.
    ///
    /// Held on the selection rather than re-derived at install time because the
    /// two must not be able to disagree: the routing rules, the socket pin and the
    /// DNS override are three separate decisions that all have to be made about
    /// the same tunnel.
    pub carries: ExitFamilies,
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

/// The IPv6 resolvers a full tunnel forwards DNS to when the operator has named
/// none of their own: the v6 addresses of the same pair the control plane falls
/// back to (`transport::PUBLIC_FALLBACK_DNS`).
const PUBLIC_FALLBACK_DNS_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
];

/// The upstreams a client full tunnel should forward DNS to, or `None` when it
/// needs no override.
///
/// Only a tunnel that carries IPv6 and not IPv4 needs one, which is IPv6-only
/// mode and, since the gateway's claim narrows the tunnel too, a dual-stack node
/// routing through a gateway that can only return IPv6. Every upstream the
/// desktop capture can produce is IPv4 (`DnsConfigurator::captured_upstreams`),
/// so left alone the daemon would forward each lookup out the physical link: the
/// exit node would carry the traffic and see none of the names that chose it. A
/// tunnel that carries IPv4 has no such gap, since it carries the captured
/// upstreams' own family.
///
/// The operator's `dns_upstreams` come first when any of them are IPv6 (the same
/// list [`crate::config::resolve_upstreams`] reads for IPv4, from the other end),
/// and `replace` suppresses the public fallback exactly as it does there.
///
/// A `replace` list with no IPv6 server in it is the case worth stating: we take
/// their IPv4 servers rather than override them. The override exists to stop
/// lookups leaving around the exit, so the reflex is to swap in a public IPv6
/// resolver, but `replace` is an operator saying *these servers and no others*,
/// usually an internal resolver holding names nothing else can answer. Silently
/// sending those queries to Cloudflare and Google instead breaks resolution and
/// hands a third party the names, to fix a leak that is not even total: IPv4
/// egress deliberately still leaves directly in this mode, so their resolver is
/// genuinely reachable. Privacy caveat is the caller's to warn about; a wrong
/// answer is not recoverable at all.
pub fn tunnel_upstreams(
    carries: ExitFamilies,
    configured: &crate::config::ServerOverride,
) -> Option<Vec<SocketAddr>> {
    if carries.carries_v4() || !carries.carries_v6() {
        return None;
    }
    let v6: Vec<Ipv6Addr> = configured
        .servers
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if configured.replace {
        if !v6.is_empty() {
            return Some(with_port(v6));
        }
        // Their list, as given, including the IPv4 entries this mode leaves
        // untunnelled. Empty only if `replace` was set with nothing usable in it,
        // where the public fallback is all that is left.
        let theirs: Vec<SocketAddr> = configured
            .servers
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::from((ip, 53u16)))
            .collect();
        if !theirs.is_empty() {
            return Some(theirs);
        }
    }
    let mut servers = v6;
    servers.extend(PUBLIC_FALLBACK_DNS_V6);
    Some(with_port(servers))
}

/// Port 53 on each, the only port a resolver override ever uses here.
fn with_port(servers: Vec<Ipv6Addr>) -> Vec<SocketAddr> {
    servers
        .into_iter()
        .map(|ip| SocketAddr::from((ip, 53u16)))
        .collect()
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
    /// Destinations another VPN's own table owns -> our table, where
    /// `mirror_foreign_routes` put a copy of its route. Above `PREF_SRC` because
    /// the two rules below it both look up `main`, which is exactly the table a
    /// policy-routing VPN does *not* keep its prefixes in: without this, that
    /// VPN's traffic reaches `main`, misses, and takes main's default out the
    /// physical uplink. The mirror alone only rescues the `PREF_TUNNEL` path.
    pub(super) const PREF_FOREIGN: &str = "98";
    pub(super) const PREF_SRC: &str = "99"; // physical-sourced traffic -> main table
    pub(super) const PREF_BYPASS: &str = "100"; // marked traffic -> main table
    pub(super) const PREF_MAIN: &str = "101"; // main table minus its default route
    pub(super) const PREF_TUNNEL: &str = "102"; // everything else -> the tunnel
}
#[cfg(target_os = "linux")]
use names::*;

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
         \t\tiifname \"{tun}\" ip saddr {v4} oifname != \"{tun}\" masquerade\n\
         \t\tiifname \"{tun}\" ip6 saddr {v6} oifname != \"{tun}\" masquerade\n\
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
/// Whether a local address should get a "leave via the physical uplink" rule at
/// [`PREF_SRC`]. True for the host's own globally-routable addresses; false for the
/// overlay (traffic entering the TUN is sourced from there, and bypassing the tunnel
/// for it would leak exactly what the tunnel is meant to carry) and for addresses
/// that never leave the host.
#[cfg(target_os = "linux")]
fn is_bypass_source(addr: IpAddr) -> bool {
    if crate::membership::is_overlay_ip(addr) {
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
fn bypass_source_addrs(family: &str) -> Vec<IpAddr> {
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
fn client_nft_script(tun_name: &str) -> String {
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
/// `carries` is [`ExitFamilies::tunnelled`], the intersection of what this node's
/// data plane routes and what the chosen gateway says it can return. Both have to
/// hold: an IPv6-only data plane carries no mesh IPv4 at all, so claiming the
/// host's IPv4 egress would source transit from a `/32` it deliberately leaves
/// unrouted and pull IPv4 out from under the very VPN the mode exists to share a
/// host with; and a gateway that cannot return a family drops it just as
/// completely at the other end.
///
/// Teardown is not symmetric with this: it always sweeps both families, so a
/// daemon restarted with a different selection still cleans up what the last one
/// left.
///
/// [`ExitFamilies::Unknown`] is not a `tunnelled()` output, and is read here as
/// both families, since that is what an absent claim meant before the field
/// existed.
#[cfg(target_os = "linux")]
fn tunnel_families(carries: ExitFamilies) -> &'static [&'static str] {
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
    // Kernel rules outlive the process, so install has to be as mode-symmetric as
    // teardown already is. A daemon killed (or aborted by the panic hook) while a
    // dual-stack tunnel was up, restarted in IPv6-only mode with the selection
    // still in config, would otherwise install `-6` and leave the previous run's
    // `-4` rules and default in place: IPv4 policy-routed into a tunnel this mode
    // promises not to claim, sourced from the /32 it deliberately leaves
    // unrouted, taking the co-resident VPN's IPv4 down with it.
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
enum RuleSweep {
    All,
    KeepCatchAll,
}

/// Whether our catch-all rule is already installed for one family, read back from
/// `ip rule show` the same way the other rule readbacks work.
#[cfg(target_os = "linux")]
fn catch_all_installed(family: &str) -> bool {
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
fn parse_catch_all(show: &str) -> bool {
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
fn installed_source_rules(family: &str) -> Vec<String> {
    let out = match Command::new("ip").args([family, "rule", "show"]).output() {
        Ok(out) if out.status.success() => out.stdout,
        _ => return Vec::new(),
    };
    parse_source_rules(&String::from_utf8_lossy(&out))
}

/// Pull the addresses out of `ip rule show` output for rules that are ours: at
/// [`PREF_SRC`], `from <addr>`, looking up `main`.
#[cfg(target_os = "linux")]
fn parse_source_rules(show: &str) -> Vec<String> {
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
fn foreign_rule_args<'a>(family: &'a str, verb: &'a str) -> [&'a str; 9] {
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
fn strays_at_our_pref(family: &str) -> Vec<String> {
    match ip_output(&[family, "rule", "show"]) {
        Some(out) => parse_strays(&out),
        None => Vec::new(),
    }
}

/// The text half of [`strays_at_our_pref`], split out to be testable.
#[cfg(target_os = "linux")]
fn parse_strays(show: &str) -> Vec<String> {
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
fn remove_client_rules(family: &str, sweep: RuleSweep) {
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
struct MirroredRoute {
    dest: String,
    spec: Vec<String>,
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
/// route anything, which is precisely what IPv6-only mode exists to avoid.
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
fn mirror_args(family: &str, route: &MirroredRoute) -> Vec<String> {
    let mut args: Vec<String> = ["route", "replace"].iter().map(|s| s.to_string()).collect();
    args.insert(0, family.to_string());
    args.push(route.dest.clone());
    args.extend(["table".to_string(), EXIT_TABLE.to_string()]);
    args.extend(route.spec.iter().cloned());
    args
}

#[cfg(target_os = "linux")]
fn mirror_foreign_routes(family: &str, tun_name: &str) -> usize {
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
fn parse_foreign_routes(show: &str, tun_name: &str) -> Vec<MirroredRoute> {
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
fn parse_table_routes(show: &str) -> Vec<MirroredRoute> {
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
fn ip_output(args: &[&str]) -> Option<String> {
    let out = Command::new("ip").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
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

/// Whether a [`run_ip`] failure is the kernel saying the object is already there.
///
/// `ip` reports it as `RTNETLINK answers: File exists` on stderr, which `run_ip`
/// folds into its message. Matched on the errno text rather than the prefix,
/// which differs between the `rule` and `route` subcommands.
#[cfg(target_os = "linux")]
fn is_already_exists(e: &anyhow::Error) -> bool {
    e.to_string().contains("File exists")
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
            out.lines().any(|l| {
                l.trim_start()
                    .strip_prefix("Status:")
                    .is_some_and(|s| s.trim_start().starts_with("Enabled"))
            })
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

    /// Which local addresses get a "leave via the physical uplink" source rule.
    ///
    /// A connection that predates the tunnel is bound to a physical address, and its
    /// packets must keep leaving that way or it stalls (see [`super::PREF_SRC`]). The
    /// overlay addresses are the opposite case: traffic entering the TUN is sourced
    /// from them, and a bypass rule for those would route the tunnel's own payload
    /// straight back out the uplink, which is the leak the whole feature exists to
    /// prevent. Loopback and link-local never leave the host.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_physical_addresses_get_a_source_bypass() {
        let phys4: IpAddr = "212.47.229.78".parse().unwrap();
        let phys6: IpAddr = "2001:bc8:1234::1".parse().unwrap();
        assert!(is_bypass_source(phys4));
        assert!(is_bypass_source(phys6));

        // Overlay: routing these around the tunnel would defeat the tunnel.
        assert!(!is_bypass_source("100.64.0.1".parse().unwrap()));
        assert!(!is_bypass_source("100.127.255.254".parse().unwrap()));
        assert!(!is_bypass_source("200::1".parse().unwrap()));

        assert!(!is_bypass_source("127.0.0.1".parse().unwrap()));
        assert!(!is_bypass_source("::1".parse().unwrap()));
        assert!(!is_bypass_source("169.254.1.1".parse().unwrap()));
        assert!(!is_bypass_source("fe80::1".parse().unwrap()));
    }

    /// Teardown reads back what it installed. It must recognise its own rules and
    /// leave anything else at that pref alone: `ip rule del` matches on the keys
    /// given, so deleting somebody else's rule is a real possibility.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_our_own_source_rules_are_reclaimed() {
        let show = "\
0:\tfrom all lookup local
99:\tfrom 212.47.229.78 lookup main
99:\tfrom 2001:bc8:1234::1 lookup main
99:\tfrom 10.0.0.5 lookup 42
100:\tfrom all fwmark 0x7261 lookup main
102:\tfrom all lookup 29793
32766:\tfrom all lookup main
";
        assert_eq!(
            parse_source_rules(show),
            vec!["212.47.229.78".to_string(), "2001:bc8:1234::1".to_string()],
            "only `from <addr> lookup main` rules at pref 99 are ours"
        );
    }

    /// The rule that hands a co-resident VPN's destinations back to it, spelled
    /// out, and the sweep that reclaims the shape it replaced.
    ///
    /// `suppress_prefixlength 0` is what makes one rule cover every mirrored
    /// prefix: the lookup itself is the selector, matching the copies and
    /// suppressing our own default. Verified against a live kernel (iproute2
    /// 6.1.0) with a mirrored `172.20.0.0/16` and our default in the table: a
    /// packet to that prefix resolves to the foreign interface whether it is
    /// sourced from the physical address or carries our mark, an ordinary
    /// destination still takes the tunnel, and a marked one still bypasses it.
    /// What is pinned here is the spelling, because a `del` that omits any of it
    /// matches nothing and leaves the rule to stack on the next add.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_foreign_rule_is_spelled_the_same_way_twice() {
        assert_eq!(
            foreign_rule_args("-6", "add"),
            [
                "-6",
                "rule",
                "add",
                "table",
                EXIT_TABLE,
                "suppress_prefixlength",
                "0",
                "pref",
                PREF_FOREIGN,
            ]
        );
        // The del names the identical rule, differing in the verb alone.
        let add = foreign_rule_args("-4", "add");
        let del = foreign_rule_args("-4", "del");
        assert_eq!(add[2], "add");
        assert_eq!(del[2], "del");
        assert_eq!(add[3..], del[3..], "a del that names less matches nothing");

        // `suppress_prefixlength 0` is the whole mechanism, not decoration: it is
        // what excludes our own default from the lookup. Without it the rule sends
        // *everything* to the tunnel table at a preference above the bypasses.
        let spec = add.join(" ");
        assert!(spec.contains("suppress_prefixlength 0"), "{spec}");
        assert!(spec.contains(&format!("table {EXIT_TABLE}")), "{spec}");
    }

    /// A host that ran the per-prefix build keeps those rules across a binary
    /// swap, and nothing else looks at pref 98 any more.
    ///
    /// Kernel rules outlive the process and the panic hook `abort()`s, so this is
    /// a supported path rather than a corner. A stranded `to <prefix>` rule
    /// outlives the mirrored route it depends on; once the co-resident VPN drops
    /// that prefix, the rule sends those destinations to the tunnel default in the
    /// same table, which is the failure the single-rule form exists to prevent.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_old_per_prefix_rules_are_reclaimed_and_a_foreign_one_is_not() {
        let show = "\
0:\tfrom all lookup local
98:\tfrom all to fd7a:115c:a1e0::/48 lookup 29793
98:\tfrom all to 100.64.0.0/10 lookup corpvpn
98:\tfrom all lookup 29793 suppress_prefixlength 0
99:\tfrom 2a01:4f8:121:33c3::2 lookup main
5270:\tfrom all to 10.9.0.0/24 lookup 52
";
        assert_eq!(
            parse_strays(show),
            vec![
                "fd7a:115c:a1e0::/48".to_string(),
                // Matched by shape, not by table text: `ip rule show` prints the
                // name when /etc/iproute2/rt_tables maps our id, and reading that
                // as somebody else's rule is what left these behind before.
                "100.64.0.0/10".to_string(),
            ],
        );
        // The current rule has no `to`, so the sweep never touches it, and a rule
        // at another pref is not ours whatever its shape.
        assert!(!parse_strays(show).iter().any(|d| d == "10.9.0.0/24"));
    }

    /// The rule that hands a co-resident VPN's destinations back to it.
    ///
    /// `mirror_foreign_routes` alone only rescues the `PREF_TUNNEL` path. The two
    /// rules above it look up `main`, and a policy-routing VPN keeps its prefixes
    /// in its own table, so traffic *sourced from* that VPN's address (an inbound
    /// SSH session's replies, say) reached `main`, missed, and left out the
    /// physical uplink.
    ///
    /// One rule covers every mirrored prefix, because `suppress_prefixlength 0`
    /// makes the lookup itself the selector. Verified against a live kernel
    /// (iproute2 6.1.0) with a mirrored `172.20.0.0/16` and our default in the
    /// table: a packet to that prefix resolves to the foreign interface whether
    /// it is sourced from the physical address or carries our mark, while an
    /// ordinary destination still takes the tunnel and a marked one still
    /// bypasses it. What is pinned here is the ordering that makes any of it
    /// reachable.
    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_destinations_are_routed_back_to_their_own_table() {
        // Ordered above the rules that look up `main`, or it would never be
        // consulted for the traffic it exists to rescue.
        for lower in [PREF_SRC, PREF_BYPASS, PREF_MAIN, PREF_TUNNEL] {
            assert!(
                PREF_FOREIGN.parse::<u32>().unwrap() < lower.parse::<u32>().unwrap(),
                "PREF_FOREIGN must outrank {lower}"
            );
        }
        // And below the kernel's `local` table, which must keep winning.
        assert!(PREF_FOREIGN.parse::<u32>().unwrap() > 0);
    }

    /// A re-install must recognize its own catch-all and leave it standing.
    ///
    /// It is the only rule between tunnel-bound traffic and `main`, and the
    /// rebuild around it re-mirrors one route per foreign prefix, a separate `ip`
    /// process each, so tearing it down first leaks every packet out the physical
    /// uplink for as long as that takes. Recognizing it also has to be exact: a co-resident VPN's own
    /// catch-all has the identical shape and differs only in the preference, so a
    /// looser match would read someone else's rule as ours and skip installing
    /// one at all.
    #[cfg(target_os = "linux")]
    #[test]
    fn our_catch_all_is_recognized_and_a_foreign_one_is_not() {
        assert!(parse_catch_all("102:\tfrom all lookup 29793\n"));
        assert!(parse_catch_all(
            "0:\tfrom all lookup local\n102:\tfrom all lookup 29793\n5270:\tfrom all lookup 52\n"
        ));
        // Tailscale's catch-all: same shape, different pref.
        assert!(!parse_catch_all("5270:\tfrom all lookup 52\n"));
        // Our own table under a name, which is what `ip rule show` prints when
        // /etc/iproute2/rt_tables maps our id. Still ours: a false negative here
        // used to fail the install, and a failed install tears the tunnel down.
        assert!(parse_catch_all("102:\tfrom all lookup corpvpn\n"));
        // A selector makes it a different rule (this is the PREF_FOREIGN shape).
        assert!(!parse_catch_all(
            "102:\tfrom all to 10.0.0.0/8 lookup 29793\n"
        ));
        // Nothing installed at all, which is what a first install sees.
        assert!(!parse_catch_all(
            "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n"
        ));
    }

    /// A tunnel pins only the families it carries, and says so whenever that
    /// changes.
    ///
    /// The pin is what keeps iroh's underlay out of the tunnel, so it is only
    /// wanted for a family the tunnel actually claimed. Pinning IPv4 in IPv6-only
    /// mode binds the whole IPv4 underlay to the physical interface and carves it
    /// out of the co-resident VPN that owns IPv4 on that host, which is the setup
    /// the mode exists to share with.
    ///
    /// The second half is the part that changed. `claims_v4` used to restate this
    /// node's mode, fixed for the daemon's lifetime, so reporting only the on/off
    /// flip was enough. It now follows the gateway's claim and moves under a live
    /// tunnel: a gateway that gains or loses an IPv6 uplink republishes and the
    /// re-apply arrives with a different value. Answering "nothing changed" there
    /// skips the rebind that applies `IP_BOUND_IF`, leaving IPv4 sockets unpinned
    /// for a tunnel that now carries IPv4 (iroh's own underlay then routes into
    /// the tunnel it is carrying), or pinned for one that no longer does.
    ///
    /// Sole owner of these process-wide statics, deliberately: a second test
    /// touching them races this one under cargo's thread pool, so new cases go
    /// here rather than in a test of their own.
    #[test]
    fn a_tunnel_pins_the_families_it_carries_and_reports_every_change() {
        set_full_tunnel(true, false);
        assert!(full_tunnel_active(), "the tunnel itself is up");
        assert!(
            !full_tunnel_claims_v4(),
            "IPv6-only mode leaves IPv4 to the other VPN, so its sockets stay unpinned"
        );

        set_full_tunnel(true, true);
        assert!(full_tunnel_claims_v4(), "a dual-stack tunnel pins both");

        // Coming down clears it, or the next dual-stack-looking read is stale.
        set_full_tunnel(false, false);
        assert!(!full_tunnel_active());
        assert!(!full_tunnel_claims_v4());

        // And the answer itself: every change has to be reported, not just the
        // on/off flip, or a narrowing tunnel never re-evaluates the pin.

        // From nothing to a v6-only tunnel: a flip either way round.
        set_full_tunnel(false, false);
        assert!(set_full_tunnel(true, false), "coming up is a change");
        assert!(!set_full_tunnel(true, false), "a plain re-apply is not");

        // Widening while up: `FULL_TUNNEL` does not move, and this is exactly the
        // case that used to answer "no change" and leave the v4 sockets unpinned.
        assert!(
            set_full_tunnel(true, true),
            "gaining IPv4 under a live tunnel is a change"
        );
        assert!(full_tunnel_claims_v4());
        assert!(!set_full_tunnel(true, true), "and then it settles");

        // Narrowing while up, the other direction of the same bug: the pin stays
        // on IPv4 sockets for a family the tunnel no longer carries.
        assert!(
            set_full_tunnel(true, false),
            "losing IPv4 under a live tunnel is a change"
        );
        assert!(!full_tunnel_claims_v4());

        set_full_tunnel(false, false);
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

    /// The tunnel installs exactly the families it carries, and cleans up the rest.
    ///
    /// `carries` is already the intersection of this node's data plane and the
    /// gateway's claim, so all three shapes are reachable: an IPv6-only node (or
    /// any node through a v6-only gateway) takes `-6`, a node through a gateway
    /// that can only return IPv4 takes `-4`, and the ordinary pair takes both.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_tunnel_installs_only_the_families_it_carries() {
        use ExitFamilies::{Dual, V4, V6};
        assert_eq!(tunnel_families(V6), ["-6"]);
        assert_eq!(tunnel_families(V4), ["-4"]);
        assert_eq!(tunnel_families(Dual), ["-4", "-6"]);
        // Not a `tunnelled()` output, and read as the pre-claim behaviour rather
        // than as "install nothing", which would silently drop the tunnel on
        // every network whose coordinator predates the field.
        assert_eq!(tunnel_families(ExitFamilies::Unknown), ["-4", "-6"]);

        // Install cleans up whatever it stopped claiming, so a restart under a
        // different selection cannot leave the previous run's rules routing a
        // family this one promises not to touch. Kernel state outlives the
        // process, and the panic hook `abort()`s, so "the last teardown ran" is
        // not an assumption install gets to make.
        for (carries, expected) in [(V6, vec!["-4"]), (V4, vec!["-6"]), (Dual, vec![])] {
            let claimed = tunnel_families(carries);
            let dropped: Vec<&str> = ["-4", "-6"]
                .into_iter()
                .filter(|f| !claimed.contains(f))
                .collect();
            assert_eq!(dropped, expected, "{carries:?}");
        }
    }

    /// What gets copied into the tunnel table so a co-resident VPN survives our
    /// catch-all rule, and what deliberately does not.
    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_routes_are_mirrored_but_defaults_and_our_own_are_not() {
        let show = "\
fd7a:115c:a1e0::/48 dev tailscale0 table 52 metric 1024 pref medium
2001:db8:1::/64 via fe80::1 dev eth0 table 52 metric 100 pref medium
default via fe80::ff dev tailscale0 table 52 metric 1024 pref medium
200::/7 dev ray0 table 52 metric 1024 pref medium
2001:db8:9::/64 dev eth0 proto kernel metric 256 pref medium
::1 dev lo table local proto kernel metric 0 pref medium
local 2001:db8:9::5 dev eth0 table local proto kernel metric 0 pref medium
unreachable fd00::/8 dev lo table 52 metric 1024 pref medium
";
        let got = parse_foreign_routes(show, "ray0");

        // A foreign table's real prefixes, carried over with just what decides
        // where a packet goes.
        assert_eq!(
            got,
            vec![
                MirroredRoute {
                    dest: "fd7a:115c:a1e0::/48".into(),
                    spec: strs(&["dev", "tailscale0", "metric", "1024"]),
                },
                MirroredRoute {
                    dest: "2001:db8:1::/64".into(),
                    spec: strs(&["via", "fe80::1", "dev", "eth0", "metric", "100"]),
                },
            ]
        );
        // And what is left out: a foreign `default` (mirroring another full
        // tunnel would hand our egress straight back), our own TUN's route, a
        // route with no `table` of its own (that is `main`, already rescued by
        // PREF_MAIN), the kernel's `local` table, and non-unicast route types
        // that lead with a type instead of a destination.
        for absent in [
            "default",
            "200::/7",
            "2001:db8:9::/64",
            "::1",
            "fd00::/8",
            "2001:db8:9::5",
        ] {
            assert!(
                !got.iter().any(|r| r.dest == absent),
                "{absent} should not be mirrored"
            );
        }
    }

    /// A multipath route is printed across several lines, and the route line
    /// carries no `dev` at all.
    ///
    /// Reading only the first line drops it, and a dropped foreign route is not a
    /// no-op: the prefix falls through to our catch-all and that VPN's
    /// destinations go into our tunnel and nowhere. Format below is real
    /// `ip route show table all` output.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_multipath_foreign_route_is_mirrored_with_all_its_nexthops() {
        let show = "\
172.20.0.0/16 table 52
\tnexthop via 10.0.0.1 dev eth0 weight 1
\tnexthop via 10.0.1.1 dev eth1 weight 1
10.7.0.0/16 table 52
\tnexthop via 10.0.0.1 dev ray0 weight 1
\tnexthop via 10.0.1.1 dev eth1 weight 1
192.168.5.0/24 dev eth0 table 52
";
        let got = parse_foreign_routes(show, "ray0");
        assert_eq!(
            got,
            vec![
                MirroredRoute {
                    dest: "172.20.0.0/16".into(),
                    spec: strs(&[
                        "nexthop", "via", "10.0.0.1", "dev", "eth0", "weight", "1", "nexthop",
                        "via", "10.0.1.1", "dev", "eth1", "weight", "1",
                    ]),
                },
                // The single-path route after a multipath one still parses: the
                // grouping must end at the next unindented line.
                MirroredRoute {
                    dest: "192.168.5.0/24".into(),
                    spec: strs(&["dev", "eth0"]),
                },
            ]
        );
        // Our own TUN among the nexthops means the copy would partly duplicate the
        // route we are installing, so the whole entry is left alone.
        assert!(!got.iter().any(|r| r.dest == "10.7.0.0/16"));

        // And the command it becomes. Parsing the route correctly is only half of
        // it: `table` after a nexthop list is rejected by iproute2, so the
        // original spelling failed every multipath mirror while this same parser
        // test passed. Verified against iproute2 6.1.0.
        let args = mirror_args("-4", &got[0]);
        assert_eq!(
            args,
            strs(&[
                "-4",
                "route",
                "replace",
                "172.20.0.0/16",
                "table",
                EXIT_TABLE,
                "nexthop",
                "via",
                "10.0.0.1",
                "dev",
                "eth0",
                "weight",
                "1",
                "nexthop",
                "via",
                "10.0.1.1",
                "dev",
                "eth1",
                "weight",
                "1",
            ])
        );
        let table_at = args.iter().position(|a| a == "table").unwrap();
        let first_hop = args.iter().position(|a| a == "nexthop").unwrap();
        assert!(
            table_at < first_hop,
            "`table` after a nexthop list is a parse error, not a wrong table"
        );
        // Single-path takes the same order, so there is only one to get right.
        assert_eq!(
            mirror_args("-4", &got[1]),
            strs(&[
                "-4",
                "route",
                "replace",
                "192.168.5.0/24",
                "table",
                EXIT_TABLE,
                "dev",
                "eth0",
            ])
        );
    }

    /// The sweep reads our own table with the same shape, so it has the same
    /// multipath problem, and a `nexthop` line read as a destination is swept
    /// forever: it is in no wanted set, so every re-apply runs a `route del
    /// nexthop` that fails.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_stale_sweep_does_not_read_a_nexthop_line_as_a_destination() {
        let show = "\
default dev ray0 table 29793
172.20.0.0/16 table 29793
\tnexthop via 10.0.0.1 dev eth0 weight 1
\tnexthop via 10.0.1.1 dev eth1 weight 1
192.168.5.0/24 dev eth0 table 29793
";
        let dests: Vec<String> = parse_table_routes(show)
            .into_iter()
            .map(|r| r.dest)
            .collect();
        assert_eq!(
            dests,
            strs(&["default", "172.20.0.0/16", "192.168.5.0/24"]),
            "continuation lines are part of the route above them, not routes"
        );
    }

    /// The IPv4 side, where the range that matters is the one IPv6-only mode
    /// hands over in the first place.
    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_cgnat_route_is_mirrored() {
        let show = "100.64.0.0/10 dev tailscale0 table 52 \n";
        assert_eq!(
            parse_foreign_routes(show, "ray0"),
            vec![MirroredRoute {
                dest: "100.64.0.0/10".into(),
                spec: strs(&["dev", "tailscale0"]),
            }]
        );
    }

    /// Only a tunnel carrying IPv6 and not IPv4 needs its own DNS upstreams: any
    /// tunnel that carries IPv4 already carries the family the captured upstreams
    /// live in. That is IPv6-only mode, and now also a dual-stack node routing
    /// through a gateway that can only return IPv6.
    #[test]
    fn only_a_v6_carrying_tunnel_overrides_dns_upstreams() {
        use crate::config::ServerOverride;
        use ExitFamilies::{Dual, V4, V6};

        // Both families, or IPv4 alone: the captured upstreams already ride it.
        assert!(tunnel_upstreams(Dual, &ServerOverride::default()).is_none());
        assert!(tunnel_upstreams(V4, &ServerOverride::default()).is_none());

        // Nothing configured: the public fallback pair, on port 53.
        let got = tunnel_upstreams(V6, &ServerOverride::default()).unwrap();
        assert_eq!(
            got,
            PUBLIC_FALLBACK_DNS_V6
                .map(|ip| SocketAddr::from((ip, 53)))
                .to_vec()
        );

        // The operator's own IPv6 entries come first; their IPv4 ones are not
        // reachable through this tunnel and are left to `resolve_upstreams`.
        let augment = ServerOverride {
            servers: strs(&["2001:4860:4860::8844", "192.168.1.1"]),
            replace: false,
        };
        let got = tunnel_upstreams(V6, &augment).unwrap();
        assert_eq!(got[0], "[2001:4860:4860::8844]:53".parse().unwrap());
        assert_eq!(got.len(), 1 + PUBLIC_FALLBACK_DNS_V6.len());

        // `replace` suppresses the fallback, exactly as it does for IPv4.
        let replace = ServerOverride {
            servers: strs(&["2001:4860:4860::8844"]),
            replace: true,
        };
        assert_eq!(
            tunnel_upstreams(V6, &replace).unwrap(),
            vec!["[2001:4860:4860::8844]:53".parse::<SocketAddr>().unwrap()]
        );

        // `replace` with no IPv6 entry keeps the operator's own IPv4 servers
        // rather than substituting public ones. `replace` means "these and no
        // others", and it usually names an internal resolver holding names
        // nothing else can answer, so swapping in Cloudflare breaks resolution
        // and leaks the names. IPv4 egress still leaves directly in this mode, so
        // that server is genuinely reachable; the cost is a lookup that goes
        // around the exit, which is the lesser of the two.
        let v4_only = ServerOverride {
            servers: strs(&["192.168.1.1"]),
            replace: true,
        };
        assert_eq!(
            tunnel_upstreams(V6, &v4_only).unwrap(),
            vec!["192.168.1.1:53".parse::<SocketAddr>().unwrap()],
            "an explicit --replace list is not silently swapped for public resolvers"
        );

        // Mixed: the IPv6 half is enough to keep everything inside the tunnel, so
        // the IPv4 entries are not needed and not used.
        let mixed = ServerOverride {
            servers: strs(&["192.168.1.1", "2001:4860:4860::8844"]),
            replace: true,
        };
        assert_eq!(
            tunnel_upstreams(V6, &mixed).unwrap(),
            vec!["[2001:4860:4860::8844]:53".parse::<SocketAddr>().unwrap()]
        );

        // `replace` with nothing parseable in it: the fallback is all that is
        // left, and an empty override would forward nowhere at all.
        let junk = ServerOverride {
            servers: strs(&["not-an-address"]),
            replace: true,
        };
        assert_eq!(
            tunnel_upstreams(V6, &junk).unwrap().len(),
            PUBLIC_FALLBACK_DNS_V6.len()
        );
    }
}
