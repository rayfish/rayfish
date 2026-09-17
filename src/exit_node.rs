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
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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
/// Pinning is per-socket and per-family, and the tunnel carries IPv6 alone, so the
/// IPv4 sockets must not be pinned: that would bind the whole IPv4 underlay to the
/// physical interface and carve it out of whichever co-resident VPN owns IPv4 on
/// that Mac.
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
    (!is_tunnel_iface(&name)).then_some(name)
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
    /// The IPv6 prefixes this host is directly attached to, refused as transit
    /// destinations for the same reason `self_addrs` is: they are reachable from
    /// the gateway but are not "the internet", so forwarding into them turns an
    /// exit offer into a way onto the gateway's LAN.
    ///
    /// The IPv4 side of this was free: `is_transitable` refuses `is_private()`,
    /// which is where a v4 LAN lives by definition. IPv6 has no such rule -- a
    /// home or office LAN is normally a *global* /64 delegated by the ISP, which
    /// `is_transitable` cannot tell from any other global address. So the answer
    /// has to be read from the host rather than derived, which is what this is.
    on_link: Arc<ArcSwap<Vec<Ipv6Prefix>>>,
}

/// An IPv6 prefix the gateway is directly attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Prefix {
    addr: Ipv6Addr,
    len: u8,
}

impl Ipv6Prefix {
    /// Whether `ip` falls inside this prefix.
    fn contains(&self, ip: Ipv6Addr) -> bool {
        if self.len == 0 || self.len > 128 {
            return false;
        }
        let shift = 128 - u32::from(self.len);
        (u128::from(self.addr) >> shift) == (u128::from(ip) >> shift)
    }
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

    /// Whether `dst` is on a network this gateway is directly attached to (so
    /// transit to it must be refused; see `on_link`).
    pub fn is_on_link(&self, dst: IpAddr) -> bool {
        let IpAddr::V6(v6) = dst else {
            // IPv4 is not transited at all, and `is_transitable` already refuses
            // every private v4 range, which is the same question for that family.
            return false;
        };
        self.on_link.load().iter().any(|p| p.contains(v6))
    }

    /// Replace the set of directly-attached IPv6 prefixes. Refreshed alongside
    /// [`set_self_addrs`](Self::set_self_addrs).
    pub fn set_on_link(&self, prefixes: Vec<Ipv6Prefix>) {
        self.on_link.store(Arc::new(prefixes));
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
            let host = host_interfaces();
            self.set_self_addrs(host.addrs);
            self.set_on_link(host.on_link);
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
fn host_interfaces() -> HostInterfaces {
    #[cfg(target_os = "linux")]
    let out = Command::new("ip").args(["-o", "addr", "show"]).output();
    #[cfg(not(target_os = "linux"))]
    let out = Command::new("ifconfig").arg("-a").output();
    match out {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            HostInterfaces {
                addrs: parse_host_addresses(&text),
                on_link: parse_on_link_prefixes(&text),
            }
        }
        _ => HostInterfaces::default(),
    }
}

/// One read of the host's interface list: what the gateway must refuse as a
/// transit destination, in both of the forms it takes.
#[derive(Default)]
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub struct HostInterfaces {
    pub addrs: HashSet<IpAddr>,
    pub on_link: Vec<Ipv6Prefix>,
}

/// Pull the directly-attached IPv6 prefixes out of the same output
/// [`parse_host_addresses`] reads, in either platform's spelling: Linux's
/// `inet6 2001:db8::1/64` and the BSDs' `inet6 2001:db8::1 prefixlen 64`.
///
/// Only global unicast (`2000::/3`) is kept, and only `32 <= len < 128`. Everything
/// narrower than /128 is already covered by `self_addrs`, and everything the other
/// bounds exclude is either refused by [`is_transitable`] anyway (link-local, ULA,
/// loopback, the overlay) or is not a prefix a host is plausibly attached to. The
/// lower bound matters most: a misparse that yielded a short prefix would refuse
/// transit to most of the internet and break the exit node outright, so the
/// failure mode of this parser is bounded on the side that keeps traffic flowing.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", test))]
pub(crate) fn parse_on_link_prefixes(out: &str) -> Vec<Ipv6Prefix> {
    let mut found: Vec<Ipv6Prefix> = Vec::new();
    let toks: Vec<&str> = out.split_whitespace().collect();
    for (i, tok) in toks.iter().enumerate() {
        if *tok != "inet6" {
            continue;
        }
        let Some(raw) = toks.get(i + 1) else { break };
        let addr_part = raw.split('%').next().unwrap_or(raw);
        let (addr_str, inline_len) = match addr_part.split_once('/') {
            Some((a, l)) => (a, l.parse::<u8>().ok()),
            None => (addr_part, None),
        };
        let Ok(addr) = addr_str.parse::<Ipv6Addr>() else {
            continue;
        };
        let len = inline_len.or_else(|| {
            (toks.get(i + 2) == Some(&"prefixlen")).then(|| toks.get(i + 3)?.parse().ok())?
        });
        let Some(len) = len else { continue };
        // Global unicast only, and wide enough to be a network rather than a host
        // yet narrow enough not to swallow the internet. See the doc above.
        if !(32..128).contains(&len) || (addr.segments()[0] & 0xe000) != 0x2000 {
            continue;
        }
        let prefix = Ipv6Prefix { addr, len };
        if !found.contains(&prefix) {
            found.push(prefix);
        }
    }
    found
}

/// Pull the addresses out of `ip -o addr show` or `ifconfig -a` output: any token
/// following an `inet`/`inet6` keyword, with the Linux `/prefix` and BSD `%zone`
/// suffixes stripped.
// Same platforms as its only caller: Android has neither `ip` nor `ifconfig`,
// and Windows reads its addresses through PowerShell, so nothing else produces
// output for it to parse. `test` joins them because the parser is pure string
// handling and its test is worth running everywhere, the same way
// [`parse_on_link_prefixes`] is gated.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", test))]
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
/// masquerade IPv6 onto something. A gateway without one can carry nothing at all,
/// since the overlay routes no IPv4: it publishes [`ExitFamilies::Neither`] and
/// every client refuses it by name. Advertised rather than refused locally so the
/// refusal names the reason, which "does not advertise an exit node" would not.
#[cfg(target_os = "linux")]
fn has_v6_uplink() -> bool {
    ip_output(&["-6", "route", "show", "default"]).is_some_and(|out| !out.trim().is_empty())
}

/// The BSD counterpart, over the same `route -n get` the NAT rules already use to
/// find the interface to masquerade onto.
///
/// A tunnel interface is not an uplink. On a host that both offers an exit node
/// and uses one, the client tunnel's `::/1` + `8000::/1` are more specific than
/// `::/0`, so `route -n get -inet6 default` answers with our own utun the moment
/// they go in (the same trap [`capture_physical_defaults`] documents and filters
/// with [`usable_pin_iface`]). Unfiltered, `refresh_v6_uplink` re-probes after
/// the client install and publishes `ExitFamilies::V6` for an uplink that does
/// not exist, and `enable()` then masquerades transit onto the tunnel we are
/// ourselves carrying. A false claim is the one outcome the type exists to
/// prevent, since `ipv6_gateway_refusal` never fires on it.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn has_v6_uplink() -> bool {
    default_interface("-inet6").is_some_and(|n| !is_tunnel_iface(&n))
}

/// Whether `name` is a tunnel interface rather than a physical uplink: `utun*` on
/// macOS, `tun*` on FreeBSD.
#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
fn is_tunnel_iface(name: &str) -> bool {
    name.starts_with("utun") || name.starts_with("tun")
}

pub fn is_transitable(dst: IpAddr) -> bool {
    if is_overlay_ip(dst) || matches!(dst, IpAddr::V4(v4) if crate::membership::is_cgnat_range(v4))
    {
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
    /// The exit peer's mesh IPv6, used to look up its live route and to dial it.
    pub ipv6: Ipv6Addr,
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

    /// Whether return traffic arriving from a peer whose verified mesh address is
    /// `peer_v6` is our own exit-node return traffic. The sender's address is
    /// derived by the reader from our own roster (so it cannot be forged), which
    /// makes it a more robust match than the resolved user identity (a
    /// device-vs-user-key mismatch would wrongly reject every reply). Matches by
    /// identity *or* address.
    pub fn is_return_from(&self, peer_user: &EndpointId, peer_v6: Ipv6Addr) -> bool {
        self.inner
            .load()
            .as_ref()
            .is_some_and(|s| &s.peer_user == peer_user || s.ipv6 == peer_v6)
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
    pub my_v6: Ipv6Addr,
}

impl Default for ExitContext {
    fn default() -> Self {
        Self {
            server: ExitServer::new(),
            client: ExitClient::new(),
            my_v6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel state, shared across the platforms that implement a gateway
// ---------------------------------------------------------------------------

/// The overlay source range a gateway masquerades when forwarding out its uplink.
/// One family, because the overlay only ever carries one.
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

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::*;
#[cfg(target_os = "linux")]
pub use linux::{disable, install_client_routing, teardown_client_routing};

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod pf;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub use pf::disable;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use pf::*;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use pf::{pf_load_anchor, pfctl};

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
    fn nat_rules_masquerade_the_overlay_out_the_v6_uplink_and_claim_no_ipv4() {
        assert_eq!(
            nat_rules(Some("en1")),
            "nat on en1 inet6 from 200::/7 to any -> (en1)\n"
        );
        // `nat on <uplink> inet` matches on the uplink, not our TUN, so an IPv4 half
        // could only ever catch a co-resident VPN's traffic. There must not be one.
        assert!(!nat_rules(Some("en1")).contains("100.64.0.0/10"));
        assert!(!nat_rules(Some("en1")).contains(" inet from"));
        // No IPv6 uplink is nothing to masquerade, not an error: the offer stands
        // and the client refuses it by name.
        assert_eq!(nat_rules(None), "");
    }

    /// A gateway's own IPv6 LAN is a *global* prefix, which is exactly why
    /// `is_transitable` cannot catch it: the v4 arm has `is_private()` and the v6
    /// arm has nothing equivalent. Both platforms' spellings are parsed here
    /// because neither command runs in CI.
    #[test]
    fn on_link_prefixes_are_read_from_either_platforms_interface_listing() {
        // Linux: `ip -o addr show`
        let linux = "2: eth0    inet6 2001:db8:1:2::5/64 scope global \\       valid_lft forever\n\
                     1: lo      inet6 ::1/128 scope host \\       valid_lft forever\n\
                     2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever\n\
                     3: tun0    inet6 200::5/7 scope global \\       valid_lft forever\n";
        assert_eq!(
            parse_on_link_prefixes(linux),
            vec![Ipv6Prefix {
                addr: "2001:db8:1:2::5".parse().unwrap(),
                len: 64
            }],
            "only the global LAN prefix: loopback, link-local and the overlay are \
             refused by is_transitable already, and /128 is a self address"
        );

        // BSD: `ifconfig -a`
        let bsd = "en0: flags=8863 mtu 1500\n\
                   \tinet6 fe80::aede:48ff:fe00:1122%en0 prefixlen 64 scopeid 0x4\n\
                   \tinet6 2001:db8:99::7 prefixlen 64 autoconf secured\n\
                   lo0: flags=8049 mtu 16384\n\
                   \tinet6 ::1 prefixlen 128\n";
        assert_eq!(
            parse_on_link_prefixes(bsd),
            vec![Ipv6Prefix {
                addr: "2001:db8:99::7".parse().unwrap(),
                len: 64
            }]
        );
    }

    /// The bound that matters: a misparse yielding a short prefix would refuse
    /// transit to most of the internet, which breaks the exit node outright. The
    /// parser fails toward keeping traffic flowing.
    #[test]
    fn an_implausibly_short_prefix_is_not_treated_as_on_link() {
        let absurd = "eth0 inet6 2000::1/3 scope global\n\
                      eth0 inet6 2001:db8::1/31 scope global\n";
        assert!(parse_on_link_prefixes(absurd).is_empty());
        // /32 is the documented lower bound and is kept.
        assert_eq!(
            parse_on_link_prefixes("eth0 inet6 2001:db8::1/32 x").len(),
            1
        );
    }

    /// Containment, including the boundary a `/64` draws.
    #[test]
    fn an_on_link_prefix_contains_its_neighbours_and_nothing_else() {
        let server = ExitServer::new();
        server.set_on_link(parse_on_link_prefixes(
            "eth0 inet6 2001:db8:1:2::5/64 scope global",
        ));
        // The gateway's neighbours: reachable from the gateway, not "the internet".
        for neighbour in ["2001:db8:1:2::1", "2001:db8:1:2::dead:beef"] {
            assert!(
                server.is_on_link(neighbour.parse::<IpAddr>().unwrap()),
                "{neighbour} shares the gateway's /64"
            );
        }
        // One bit outside the /64, and ordinary internet destinations.
        for outside in [
            "2001:db8:1:3::1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(
                !server.is_on_link(outside.parse::<IpAddr>().unwrap()),
                "{outside} is not on the gateway's link and must still transit"
            );
        }
        // IPv4 is never asked: `is_transitable` already refuses every private range.
        assert!(!server.is_on_link("192.168.1.1".parse().unwrap()));
        // A gateway that read nothing refuses nothing extra.
        assert!(!ExitServer::new().is_on_link("2001:db8:1:2::1".parse().unwrap()));
    }

    /// Both `has_v6_uplink` and the socket pin ask "is this a real uplink", and
    /// neither runs on Linux, so the shared predicate is pinned here. A gateway
    /// that answers `utun` to `route -n get -inet6 default` is reading its own
    /// client tunnel's `::/1` back, not an uplink it could masquerade onto.
    #[test]
    fn a_tunnel_interface_is_not_an_uplink() {
        for tun in ["utun0", "utun9", "tun0", "tun42"] {
            assert!(is_tunnel_iface(tun), "{tun} is a tunnel");
        }
        for phys in ["en0", "eth0", "bridge100", "wlan0", "lo0"] {
            assert!(!is_tunnel_iface(phys), "{phys} is a real interface");
        }
    }

    /// The Linux twin of the above, and the same argument: `nft_load` never runs in
    /// CI either, so the ruleset text is pinned rather than exercised.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_server_nft_ruleset_masquerades_the_overlay_and_claims_no_ipv4() {
        let rules = server_nft_ruleset("tun-rayfish");
        assert!(
            rules.contains(
                "iifname \"tun-rayfish\" ip6 saddr 200::/7 oifname != \"tun-rayfish\" masquerade"
            ),
            "the overlay's own range is what a gateway masquerades: {rules}"
        );
        // The overlay routes no IPv4, so there is no `ip saddr` rule to write.
        assert!(!rules.contains("100.64.0.0/10"), "{rules}");
        assert!(!rules.contains("ip saddr"), "{rules}");
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
