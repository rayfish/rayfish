//! TUN device creation and I/O.
//!
//! The device is a single `tun-rs` [`AsyncDevice`] shared (via `Arc`) between a
//! [`TunReader`] and a [`TunWriter`]; its `recv`/`send` take `&self`, so reads
//! and writes run concurrently without a split or a lock.

// These support the desktop TUN setup (address/route/link configuration via
// `ifconfig`/`ip`/netlink) and the CGNAT preflight, none of which compile on
// Android where the packet interface is a `VpnService` fd.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use crate::membership::ExitFamilies;
#[cfg(target_os = "linux")]
use std::future::Future;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::net::Ipv4Addr;
#[cfg(not(target_os = "android"))]
use std::net::Ipv6Addr;
#[cfg(not(target_os = "android"))]
use std::process::Command;
#[cfg(not(target_os = "android"))]
use std::sync::Arc;

// `Result` is the CGNAT preflight's too, which Android has its own version of;
// `Context` is only used by the desktop setup below.
#[cfg(not(target_os = "android"))]
use anyhow::Context;
use anyhow::Result;
// The desktop TUN device (the `tun-rs` crate) only exists off Android, where the
// packet interface is a `VpnService` fd instead.
#[cfg(not(target_os = "android"))]
use tun_rs::{AsyncDevice, DeviceBuilder};

/// Read side of a packet interface. Fills the spare capacity of `buf` with one
/// IP packet and returns the number of bytes read. Abstracts the concrete TUN
/// device so the forwarding loop can run over any packet source: the desktop
/// TUN, an Android `VpnService` fd, an iOS `NEPacketTunnelFlow`, or an in-memory
/// fake in tests. Reading into caller-owned spare capacity keeps the forward
/// loop's zero-copy `split_to(n).freeze()` hand-off.
///
/// Contract: `Ok(0)` means "no packet this time, retry", the forwarding loop
/// treats it as a spurious wakeup and loops again. End-of-stream (e.g. an
/// Android `VpnService` fd whose descriptor is revoked/closed) MUST surface as
/// `Err`, never as a perpetual `Ok(0)`, or `run_mesh` would busy-spin at 100%
/// CPU. The desktop TUN never returns 0, so this only binds future impls.
///
/// **`read_into` MUST be cancel-safe.** `run_mesh` races it in a `select!` against
/// dial-completion and shutdown, so the future can be dropped before it resolves.
/// A dropped read MUST leave `buf` byte-for-byte as it was on entry: never append
/// (or grow-then-not-truncate) before the `.await`, or a cancelled read leaves
/// stray bytes in the pool that offset every later `split_to`, silently corrupting
/// every subsequent packet. Read into owned scratch (or uninitialised spare
/// capacity via `advance_mut`) and commit to `buf` only after the read returns.
pub trait TunRead: Send + 'static {
    fn read_into(
        &mut self,
        buf: &mut bytes::BytesMut,
    ) -> impl core::future::Future<Output = anyhow::Result<usize>> + Send;
}

/// Write side of a packet interface. Writes one IP packet to the device.
pub trait TunWrite: Send + 'static {
    fn write_packet(
        &mut self,
        packet: &[u8],
    ) -> impl core::future::Future<Output = anyhow::Result<()>> + Send;
}

/// MTU for the TUN device. IPv6 mandates a minimum link MTU of 1280 bytes
/// (RFC 8200 §5); Linux refuses to enable IPv6 on a device with a smaller MTU,
/// which silently breaks IPv6 address/route installation (the builder's IPv6
/// assignment / `route_peer_range` fail with `EINVAL`). 1280 is also the value
/// WireGuard and
/// Tailscale use for their TUN interfaces for the same reason, and it still
/// fits within QUIC datagram limits.
#[cfg(not(target_os = "android"))]
const TUN_MTU: u16 = 1280;

/// Bytes exposed for a single `recv`. A TUN read yields at most one MTU-bounded
/// packet (offload is off), plus a few bytes of slack for any platform
/// packet-info header. `recv` needs an initialised `&mut [u8]`, so we zero-fill
/// this many bytes at the tail of the caller's pool before each read; a hand-set
/// jumbo MTU beyond this would be truncated, but such a packet exceeds the path
/// MTU and could not traverse a QUIC datagram anyway.
#[cfg(not(target_os = "android"))]
const READ_RESERVE: usize = TUN_MTU as usize + 4;

/// Read half of the TUN device. Owned by [`forward::run_mesh`]. Holds a clone of
/// the shared [`AsyncDevice`]; `recv` takes `&self`, so the reader and writer
/// share one device without a lock.
#[cfg(not(target_os = "android"))]
pub struct TunReader {
    dev: Arc<AsyncDevice>,
    /// Owned landing buffer for one packet. `read_into` reads here first, then
    /// copies into the caller's pool, which keeps it cancel-safe (see `read_into`).
    scratch: Box<[u8]>,
}

/// Write half of the TUN device. Owned by [`forward::spawn_tun_writer`].
#[cfg(not(target_os = "android"))]
pub struct TunWriter {
    dev: Arc<AsyncDevice>,
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// Error for a host that already has another VPN sitting on the CGNAT range.
///
/// States the finding and nothing else: the caller decides what it means (start
/// IPv6-only, or refuse) and appends the advice that goes with that outcome.
fn cgnat_conflict(iface: &str, ip: Ipv4Addr) -> anyhow::Error {
    anyhow::anyhow!(
        "interface {iface} already has CGNAT address {ip}: another VPN \
         (e.g. Tailscale) is using the 100.64.0.0/10 range."
    )
}

/// Refuses to start when another VPN already holds an address in
/// `100.64.0.0/10`, since both overlays would fight over the same range.
///
/// Skipped in IPv6-only mode, which exists precisely to share a host with such
/// a VPN (see `AppConfig::ipv6_only`).
///
/// Linux reads the address list over netlink. It used to parse `ifconfig` here
/// too and treat a missing binary as "no conflict", so on a server without
/// net-tools (most of them) the clash went undetected and the overlay silently
/// lost its IPv4 half instead of refusing to start.
#[cfg(target_os = "linux")]
pub async fn check_cgnat_conflict() -> Result<()> {
    use futures::TryStreamExt;
    use rtnetlink::packet_route::address::AddressAttribute;

    let (connection, handle, _) = rtnetlink::new_connection().context("open netlink socket")?;
    let conn = tokio::spawn(connection);

    let result = async {
        let mut addrs = handle.address().get().execute();
        while let Some(msg) = addrs
            .try_next()
            .await
            .context("dump interface addresses via netlink")?
        {
            // IFA_LOCAL is the interface's own address and IFA_ADDRESS the peer's
            // on a point-to-point link (they are equal elsewhere); either one in
            // the range means someone else is already routing it.
            let mut label = None;
            let mut found = None;
            for attr in &msg.attributes {
                match attr {
                    AddressAttribute::Label(l) => label = Some(l.clone()),
                    AddressAttribute::Address(IpAddr::V4(ip))
                    | AddressAttribute::Local(IpAddr::V4(ip))
                        if is_cgnat(*ip) =>
                    {
                        found = Some(*ip)
                    }
                    _ => {}
                }
            }
            if let Some(ip) = found {
                let iface = label.unwrap_or_else(|| format!("index {}", msg.header.index));
                return Err(cgnat_conflict(&iface, ip));
            }
        }
        Ok(())
    }
    .await;

    conn.abort();
    result
}

#[cfg(all(not(target_os = "android"), not(target_os = "linux")))]
pub async fn check_cgnat_conflict() -> Result<()> {
    let output = Command::new("ifconfig").output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return Ok(()),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_iface = String::new();

    for line in stdout.lines() {
        if !line.starts_with('\t')
            && !line.starts_with(' ')
            && let Some(name) = line.split(':').next()
        {
            current_iface = name.to_string();
        }
        if line.contains("inet ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&p| p == "inet")
                && let Some(ip_str) = parts.get(pos + 1)
                && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
                && is_cgnat(ip)
            {
                return Err(cgnat_conflict(&current_iface, ip));
            }
        }
    }

    Ok(())
}

/// Android counterpart of the desktop scan, over `getifaddrs` (bionic, API 24+):
/// netlink dumps and `/proc/net` are not something an app can rely on there,
/// and there is no `ifconfig` to shell out to.
///
/// `own` is this node's own mesh IPv4, skipped if present. The desktop scan runs
/// before the TUN exists so it cannot meet its own address; here the packet
/// interface is a `VpnService` fd that may well be up already when the node is
/// rebuilt, and mistaking our own address for another VPN's would latch the mode
/// on permanently.
///
/// The case this catches is not a peer VPN (Android runs one at a time) but a
/// carrier handing the phone a `100.64.x.x` address of its own, which the tunnel
/// would otherwise swallow whole.
#[cfg(target_os = "android")]
pub async fn check_cgnat_conflict(own: Option<Ipv4Addr>) -> Result<()> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes a list head into `ifap` and returns 0 on
    // success; the list is freed below on every path out.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        // No list means nothing to compare against. Treating this as "no
        // conflict" keeps a restricted device starting in the normal mode
        // rather than failing, which is the same call the desktop scan makes
        // when it cannot read the addresses.
        tracing::debug!("getifaddrs failed; assuming no CGNAT conflict");
        return Ok(());
    }
    let addrs = collect_ipv4_addrs(ifap);
    // SAFETY: `ifap` came from a successful `getifaddrs` and is freed once.
    unsafe { libc::freeifaddrs(ifap) };

    match find_cgnat_conflict(&addrs, own) {
        Some((iface, ip)) => Err(cgnat_conflict(&iface, ip)),
        None => Ok(()),
    }
}

/// Walk the `getifaddrs` list into owned `(interface, address)` pairs, so the
/// filtering below is ordinary safe code that can be tested on a made-up list.
#[cfg(target_os = "android")]
fn collect_ipv4_addrs(ifap: *mut libc::ifaddrs) -> Vec<(String, Ipv4Addr)> {
    let mut out = Vec::new();
    let mut cur = ifap;
    // SAFETY: walking a `getifaddrs` list; every pointer is checked for null
    // before it is read, and the list outlives this walk (freed by the caller).
    unsafe {
        while !cur.is_null() {
            let entry = &*cur;
            cur = entry.ifa_next;
            if entry.ifa_addr.is_null() {
                continue;
            }
            let sa = &*entry.ifa_addr;
            if i32::from(sa.sa_family) != libc::AF_INET {
                continue;
            }
            let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let name = if entry.ifa_name.is_null() {
                String::from("unknown")
            } else {
                std::ffi::CStr::from_ptr(entry.ifa_name)
                    .to_string_lossy()
                    .into_owned()
            };
            out.push((name, ip));
        }
    }
    out
}

/// The first address in `100.64.0.0/10` that is not ours, if any. Split from
/// the `getifaddrs` walk so the rule that decides a conflict is testable off
/// Android, which is the only place it runs.
#[cfg(any(target_os = "android", test))]
fn find_cgnat_conflict(
    addrs: &[(String, Ipv4Addr)],
    own: Option<Ipv4Addr>,
) -> Option<(String, Ipv4Addr)> {
    addrs
        .iter()
        .find(|(_, ip)| is_cgnat(*ip) && Some(*ip) != own)
        .cloned()
}

/// Creates a TUN device with the given virtual IPs and shares it between
/// independent read/write halves. IPv4 gets a /10 (100.64.0.0/10); IPv6 gets our
/// own /128 address. The `200::/7` peer range is routed in separately by
/// [`route_peer_range`] after link-up (the kernel does not reliably install an
/// IPv6 connected route while the link is down), mirroring how the IPv4 /10 works.
///
/// In `ipv6_only` mode the IPv4 address is assigned as a `/32` instead, so no
/// connected route for the `/10` is installed and another VPN keeps the range.
/// The `/10` is the part that collides; a single address does not.
///
/// The address itself stays because it is still this node's identity-derived
/// handle: the peer table is keyed on it (`conn_for_ip`), `ray status` reports
/// it, and the roster carries it for every member. Dropping it would mean
/// reworking all of that to buy nothing, since an unrouted `/32` carries no
/// traffic either way. Magic DNS does not depend on it in this mode: it is
/// reached at [`crate::dns::MAGIC_DNS_V6`] instead.
#[cfg(not(target_os = "android"))]
pub async fn create(
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    ipv6_only: bool,
) -> Result<(TunReader, TunWriter, String)> {
    let gateway = Ipv4Addr::new(100, 64, 0, 1);
    // `10` is the /10 prefix (was the (255,192,0,0) netmask); `Some(gateway)` is
    // the point-to-point destination. `ipv6(v6, 128)` assigns just our own
    // address (a /128, no connected route) cross-platform, replacing the old
    // netlink/`ifconfig` `configure_ipv6` shell-out. `enable(true)` brings the
    // link up at creation (as the old `.up()` did); `set_link_up` and the
    // peer-range route helpers still run later on activate.
    let (prefix, gateway) = if ipv6_only {
        (32, None)
    } else {
        (10, Some(gateway))
    };
    let device = DeviceBuilder::new()
        .ipv4(v4, prefix, gateway)
        .ipv6(v6, 128)
        .mtu(TUN_MTU)
        .enable(true)
        .build_async()
        .context("create tun-rs device")?;

    let tun_name = device.name().unwrap_or_else(|_| "unknown".to_string());
    tracing::info!(addr = %v4, ipv6 = %v6, tun = %tun_name, ipv6_only, "TUN device created");

    // `recv`/`send` take `&self`, so both halves share one device via `Arc`
    // instead of splitting into independent read/write objects.
    let dev = Arc::new(device);
    Ok((
        TunReader {
            dev: dev.clone(),
            scratch: vec![0u8; READ_RESERVE].into_boxed_slice(),
        },
        TunWriter { dev },
        tun_name,
    ))
}

/// Run `f` with a netlink handle and the interface index of `tun_name`.
///
/// Every netlink call below needs the same preamble (open a socket, spawn the
/// connection driver, resolve the link index) and must abort that driver task on
/// every path out, success or error. Doing it here keeps each caller down to the
/// one call it actually makes.
#[cfg(target_os = "linux")]
async fn with_tun_link<F, Fut>(tun_name: &str, f: F) -> Result<()>
where
    F: FnOnce(rtnetlink::Handle, u32) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    use futures::TryStreamExt;

    let (connection, handle, _) = rtnetlink::new_connection().context("open netlink socket")?;
    let conn = tokio::spawn(connection);

    let result = async {
        let index = handle
            .link()
            .get()
            .match_name(tun_name.to_owned())
            .execute()
            .try_next()
            .await
            .context("query TUN link")?
            .with_context(|| format!("TUN link {tun_name} not found"))?
            .header
            .index;
        f(handle.clone(), index).await
    }
    .await;

    conn.abort();
    result
}

/// Re-assigns our own IPv6 `/128` to the TUN. The address is set once at device
/// creation, but Linux flushes an interface's global IPv6 addresses when the link
/// goes down (`keep_addr_on_down` defaults to 0) and never restores them, while
/// IPv4 addresses survive. Without this, a `down`/`up` cycle leaves the node with
/// a working IPv4 overlay and a silently dead IPv6 one: it still routes `200::/7`
/// into the TUN, but owns no address in it, so peers get no answer. Must run after
/// [`set_link_up`]; idempotent (netlink `replace`), safe on every `up` cycle.
#[cfg(target_os = "linux")]
pub async fn ensure_ipv6_addr(tun_name: &str, v6: Ipv6Addr) -> Result<()> {
    with_tun_link(tun_name, async |handle, index| {
        handle
            .address()
            .add(index, IpAddr::V6(v6), 128)
            .replace()
            .execute()
            .await
            .context("add TUN IPv6 address via netlink")
    })
    .await
}

/// Routes the peer ranges into the TUN. Must be called *after* the interface is
/// up (see [`set_link_up`]). On Linux only the IPv6 `200::/7` route needs adding:
/// the kernel does not reliably install an IPv6 connected route while the link is
/// down (peer traffic would otherwise leak out the host's default IPv6 route),
/// whereas it re-installs the IPv4 `100.64.0.0/10` connected route from the /10
/// netmask automatically on link-up. On macOS the point-to-point utun installs
/// neither range reliably, so *both* `100.64.0.0/10` and `200::/7` are added
/// explicitly. Idempotent, safe to call on every `up` cycle.
#[cfg(target_os = "linux")]
pub async fn route_peer_range(tun_name: &str, _ipv6_only: bool) -> Result<()> {
    use rtnetlink::RouteMessageBuilder;

    with_tun_link(tun_name, async |handle, index| {
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0), 7)
            .output_interface(index)
            .build();
        handle
            .route()
            .add(route)
            .replace()
            .execute()
            .await
            .context("add 200::/7 route via netlink")
    })
    .await
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_peer_range(tun_name: &str, ipv6_only: bool) -> Result<()> {
    // utun is point-to-point, so the address prefix alone does not reliably
    // create the range route, we add both families explicitly. The IPv4 `/10`
    // is only installed implicitly by the `tun` crate at device creation and
    // macOS drops it across an `up`/`down` cycle, so (like the IPv6 `/7`) we
    // re-add it on every activate or peers become unreachable over IPv4 while
    // IPv6 still works. `route add` fails if the route already exists (e.g. an
    // earlier `up`), so delete any stale entry first and ignore its result.
    //
    // In IPv6-only mode the `/10` is left to the other VPN; only `200::/7` is
    // ours, and it already covers `dns::MAGIC_DNS_V6`, so that mode installs no
    // magic-DNS host route at all.
    let ranges: &[(&str, &str)] = if ipv6_only {
        &[("-inet6", "200::/7")]
    } else {
        &[("-inet", "100.64.0.0/10"), ("-inet6", "200::/7")]
    };
    for (family, net) in ranges.iter().copied() {
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-net", net, "-interface", tun_name])
            .status();
        let status = Command::new("route")
            .args(["-n", "add", family, "-net", net, "-interface", tun_name])
            .status()
            .with_context(|| format!("run route add {family} {net}"))?;
        anyhow::ensure!(
            status.success(),
            "route add {family} {net} failed with {status}"
        );
    }
    Ok(())
}

/// The full-tunnel default as two half-space routes per family: `0.0.0.0/1` +
/// `128.0.0.0/1` and `::/1` + `8000::/1`. Each is more specific than a real
/// default route, so together they capture everything by longest-prefix match
/// without touching (or having to restore) the system default. The wg-quick
/// approach; Linux does not use it (its full tunnel is a policy-routing table,
/// see `exit_node::install_client_routing`).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const SPLIT_DEFAULT: [(&str, &str); 4] = [
    ("-inet", "0.0.0.0/1"),
    ("-inet", "128.0.0.0/1"),
    ("-inet6", "::/1"),
    ("-inet6", "8000::/1"),
];

/// Routes all traffic into the TUN via the [`SPLIT_DEFAULT`] half-space routes
/// (the exit-node client full tunnel). Delete-then-add, so it is idempotent
/// across re-applies. The caller is responsible for loop prevention *before*
/// this goes in: from here on, everything the routing table decides, including
/// the daemon's own transport unless it is pinned elsewhere, goes to the TUN.
///
/// Only the halves of the families the tunnel actually carries go in
/// (`ExitFamilies::tunnelled`: what this node's data plane routes, intersected
/// with what the gateway says it can return). In IPv6-only mode that is `::/1` +
/// `8000::/1`, since mesh IPv4 carries no traffic on such a host and its egress
/// stays with whoever owns `100.64.0.0/10` there. Unlike Linux, no hole has to be
/// punched for that VPN's own prefixes: the split default lives in the one routing
/// table, where its more specific routes already win.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_default_via_tun(tun_name: &str, carries: ExitFamilies) -> Result<()> {
    for step in split_default_plan(carries, tun_name) {
        let _ = Command::new("route").args(&step.delete).status();
        let Some(add) = &step.add else { continue };
        let status = Command::new("route")
            .args(add)
            .status()
            .with_context(|| format!("run route {}", add.join(" ")))?;
        anyhow::ensure!(
            status.success(),
            "route {} failed with {status}",
            add.join(" ")
        );
    }
    Ok(())
}

/// What one [`SPLIT_DEFAULT`] entry costs: always a delete, and an add only if
/// this tunnel carries that family.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
struct SplitDefaultStep {
    delete: Vec<String>,
    add: Option<Vec<String>>,
}

/// The `route` invocations an install makes, as data, so the shape is pinned by a
/// test instead of by reading the loop.
///
/// Every entry is deleted whatever the answer, and only the carried ones are added
/// back. That asymmetry is the point: this is an install, and an install has to be
/// as family-symmetric as a teardown. `carries` follows the gateway's claim, so a
/// live tunnel can narrow (its gateway loses an uplink, or `ipv6_only = auto`
/// turns on here) and the re-apply arrives with one family fewer. Skipping the
/// dropped family entirely would leave its half-space routes pointing at a utun
/// that is still up, so that family keeps entering a tunnel whose far end cannot
/// return it while the daemon tells the user it is leaving directly.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn split_default_plan(carries: ExitFamilies, tun_name: &str) -> [SplitDefaultStep; 4] {
    SPLIT_DEFAULT.map(|(family, net)| {
        let args = |verb: &str| {
            ["-n", verb, family, "-net", net, "-interface", tun_name]
                .map(str::to_string)
                .to_vec()
        };
        // `Unknown` is not a `tunnelled()` output; read as both families, which is
        // what an absent claim meant before the field existed.
        let wanted = match family {
            "-inet" => carries.carries_v4() || carries.is_unknown(),
            _ => carries.carries_v6() || carries.is_unknown(),
        };
        SplitDefaultStep {
            delete: args("delete"),
            add: wanted.then(|| args("add")),
        }
    })
}

/// Removes the full-tunnel half-space routes. Best-effort and idempotent: routes
/// that are already gone (never installed, or dropped with the utun) are fine.
///
/// Always both families, whatever mode installed them, so a daemon restarted into
/// the other one still clears what the last left behind.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn unroute_default_via_tun(tun_name: &str) {
    for (family, net) in SPLIT_DEFAULT {
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-net", net, "-interface", tun_name])
            .status();
    }
}

/// Routes the magic-DNS virtual IP (`dns::MAGIC_DNS_V4`) into the TUN as a `/32`
/// host route so that packets from the kernel addressed to that IP are delivered
/// to the TUN device (and thus intercepted by our DNS server) rather than going
/// out the host's default gateway. The IP is **never** assigned as a local
/// interface address, it is a route-only entry. Idempotent across `up`/`down`.
#[cfg(target_os = "linux")]
pub async fn route_magic_dns(tun_name: &str) -> Result<()> {
    use rtnetlink::RouteMessageBuilder;

    with_tun_link(tun_name, async |handle, index| {
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(crate::dns::MAGIC_DNS_V4, 32)
            .output_interface(index)
            .build();
        handle
            .route()
            .add(route)
            .replace()
            .execute()
            .await
            .context("add magic-DNS /32 route via netlink")
    })
    .await
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_magic_dns(tun_name: &str) -> Result<()> {
    let ip = crate::dns::MAGIC_DNS_V4.to_string();
    let _ = Command::new("route")
        .args([
            "-n",
            "delete",
            "-inet",
            "-host",
            &ip,
            "-interface",
            tun_name,
        ])
        .status();
    let status = Command::new("route")
        .args(["-n", "add", "-inet", "-host", &ip, "-interface", tun_name])
        .status()
        .context("run route add magic dns")?;
    anyhow::ensure!(status.success(), "route add magic dns failed with {status}");
    Ok(())
}

#[cfg(all(
    not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")),
    not(target_os = "android")
))]
pub async fn route_magic_dns(_tun_name: &str) -> Result<()> {
    Ok(())
}

/// Install host routes for our *own* dual-stack addresses via the loopback
/// interface so traffic to ourselves (e.g. `ping dario.field.ray` resolving to
/// our own IP) is short-circuited locally instead of being sent out the TUN,
/// where the forwarding loop would drop it as "no peer for dst".
///
/// On a normal broadcast interface macOS auto-installs a `<own-ip> -> lo0` route
/// for exactly this. A point-to-point `utun` does not get one (the local address
/// only exists as the source end of the `addr --> gateway` pair), so we add it
/// explicitly, mirroring what Tailscale does. Delete-then-add keeps it
/// idempotent across `up`/`down` cycles. Must run after the address is assigned.
///
/// On Linux this is a no-op: assigning an address makes the kernel add a
/// `local` route in the `local` table that already delivers self-traffic via
/// loopback, so pinging your own TUN address works out of the box.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_self_loopback(v4: Ipv4Addr, v6: Ipv6Addr, ipv6_only: bool) -> Result<()> {
    // IPv6-only mode carries no IPv4 mesh traffic, so only the v6 self-route is
    // wanted; a `/32` for our own IPv4 sitting on lo0 would just shadow that one
    // address for the VPN that owns the range.
    let mut families = vec![("-inet6", v6.to_string())];
    if !ipv6_only {
        families.insert(0, ("-inet", v4.to_string()));
    }
    for (family, addr) in families {
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-host", &addr, "-interface", "lo0"])
            .status();
        let status = Command::new("route")
            .args(["-n", "add", family, "-host", &addr, "-interface", "lo0"])
            .status()
            .context("run route add (loopback self-route)")?;
        anyhow::ensure!(
            status.success(),
            "route add {family} -host {addr} via lo0 failed with {status}"
        );
    }
    Ok(())
}

#[cfg(all(
    not(target_os = "macos"),
    not(target_os = "android"),
    not(target_os = "freebsd")
))]
pub async fn route_self_loopback(_v4: Ipv4Addr, _v6: Ipv6Addr, _ipv6_only: bool) -> Result<()> {
    // Linux installs the loopback `local` route automatically on address
    // assignment; self-traffic already works without an explicit route.
    Ok(())
}

/// Bring the TUN interface administratively up (used when activating the VPN).
#[cfg(not(target_os = "android"))]
pub fn set_link_up(tun_name: &str) -> Result<()> {
    set_link_state(tun_name, true)
}

/// Bring the TUN interface administratively down (standby). The underlying file
/// descriptor stays open, so the device can be brought back up without
/// recreating it.
#[cfg(not(target_os = "android"))]
pub fn set_link_down(tun_name: &str) -> Result<()> {
    set_link_state(tun_name, false)
}

#[cfg(not(target_os = "android"))]
fn set_link_state(tun_name: &str, up: bool) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let state = if up { "up" } else { "down" };
        let status = Command::new("ifconfig")
            .args([tun_name, state])
            .status()
            .context("run ifconfig")?;
        anyhow::ensure!(status.success(), "ifconfig {state} failed with {status}");
    }
    #[cfg(target_os = "linux")]
    {
        let state = if up { "up" } else { "down" };
        let status = Command::new("ip")
            .args(["link", "set", tun_name, state])
            .status()
            .context("run ip link set")?;
        anyhow::ensure!(status.success(), "ip link set {state} failed with {status}");
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
impl TunRead for TunReader {
    /// Reads one packet from the TUN device, appending it to `buf`.
    ///
    /// **Cancel-safety matters here:** `run_mesh` races this future in a `select!`
    /// against dial-completion and shutdown, so it can be dropped mid-`recv`. We
    /// therefore read into an owned `scratch` buffer and only append to the caller's
    /// pool *after* `recv` returns. Growing `buf` before the await (and truncating
    /// after) would leave stray bytes in the pool whenever a read is cancelled,
    /// permanently offsetting every subsequent `split_to`, so every packet parses as
    /// garbage and the whole data plane wedges. The one extra copy is a single
    /// sub-MTU `memcpy`; correctness beats the zero-copy read.
    async fn read_into(&mut self, buf: &mut bytes::BytesMut) -> anyhow::Result<usize> {
        let n = self.dev.recv(&mut self.scratch[..]).await?;
        buf.extend_from_slice(&self.scratch[..n]);
        Ok(n)
    }
}

#[cfg(not(target_os = "android"))]
impl TunWrite for TunWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        self.dev.send(packet).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{find_cgnat_conflict, is_cgnat};
    use std::net::Ipv4Addr;

    fn addrs() -> Vec<(String, Ipv4Addr)> {
        vec![
            ("lo".into(), Ipv4Addr::new(127, 0, 0, 1)),
            ("wlan0".into(), Ipv4Addr::new(192, 168, 1, 20)),
            // What a carrier hands a phone on mobile data.
            ("rmnet_data0".into(), Ipv4Addr::new(100, 79, 3, 4)),
        ]
    }

    /// A narrowing tunnel must delete the family it stopped carrying.
    ///
    /// `carries` follows the gateway's claim, so it changes under a live tunnel:
    /// the gateway loses an IPv6 uplink, or `ipv6_only = auto` turns on here, and
    /// the re-apply arrives with one family fewer. The utun is still up, so
    /// nothing reaps the dropped family's half-space routes on their own, and that
    /// family keeps entering a tunnel whose far end cannot return it while
    /// `ray exit-node status` says it is leaving directly.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn the_split_default_plan_visits_every_family_and_adds_only_what_it_carries() {
        use crate::membership::ExitFamilies::{Dual, Neither, V4, V6};

        let deletes = |carries| -> Vec<String> {
            super::split_default_plan(carries, "utun9")
                .into_iter()
                .map(|s| s.delete.join(" "))
                .collect()
        };
        let adds = |carries| -> Vec<String> {
            super::split_default_plan(carries, "utun9")
                .into_iter()
                .filter_map(|s| s.add.map(|a| a.join(" ")))
                .collect()
        };

        // Every family is deleted whatever the tunnel carries. This is the half
        // that a narrowing tunnel depends on, and the half that reads as dead code
        // if you only look at the family it is installing.
        let all_four = [
            "-n delete -inet -net 0.0.0.0/1 -interface utun9",
            "-n delete -inet -net 128.0.0.0/1 -interface utun9",
            "-n delete -inet6 -net ::/1 -interface utun9",
            "-n delete -inet6 -net 8000::/1 -interface utun9",
        ];
        for carries in [Dual, V6, V4, Neither] {
            assert_eq!(deletes(carries), all_four, "{carries:?}");
        }

        // And only the carried family is added back.
        assert_eq!(
            adds(V6),
            [
                "-n add -inet6 -net ::/1 -interface utun9",
                "-n add -inet6 -net 8000::/1 -interface utun9",
            ]
        );
        assert_eq!(
            adds(V4),
            [
                "-n add -inet -net 0.0.0.0/1 -interface utun9",
                "-n add -inet -net 128.0.0.0/1 -interface utun9",
            ]
        );
        assert_eq!(adds(Dual).len(), 4);
        assert!(adds(Neither).is_empty(), "nothing to carry, nothing to add");
    }

    #[test]
    fn cgnat_range_is_the_whole_slash_ten() {
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 255)));
        // Either side of it: 100.63.x and 100.128.x are ordinary public space.
        assert!(!is_cgnat(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 0)));
    }

    #[test]
    fn a_carrier_cgnat_address_is_a_conflict() {
        let found = find_cgnat_conflict(&addrs(), None).expect("carrier address should be found");
        assert_eq!(found.0, "rmnet_data0");
        assert_eq!(found.1, Ipv4Addr::new(100, 79, 3, 4));
    }

    /// The Android-only case: our own `VpnService` interface is up when the node
    /// is rebuilt, and finding our own mesh IPv4 must not read as another VPN,
    /// or the mode would latch on and never come back off.
    #[test]
    fn our_own_mesh_address_is_not_a_conflict() {
        let mut list = addrs();
        list.pop();
        let own = Ipv4Addr::new(100, 119, 146, 219);
        list.push(("tun0".into(), own));

        assert_eq!(find_cgnat_conflict(&list, Some(own)), None);
        // Someone else's, on the same interface list, still is.
        assert!(find_cgnat_conflict(&list, Some(Ipv4Addr::new(100, 64, 9, 9))).is_some());
    }

    #[test]
    fn a_host_with_no_cgnat_address_is_clean() {
        let list = vec![("wlan0".to_string(), Ipv4Addr::new(192, 168, 1, 20))];
        assert_eq!(find_cgnat_conflict(&list, None), None);
    }
}
