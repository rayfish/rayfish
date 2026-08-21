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

/// Creates a TUN device with this node's mesh address and shares it between
/// independent read/write halves. The device gets our own `/128` and nothing
/// else; the `200::/7` peer range is routed in separately by [`route_peer_range`]
/// after link-up, because the kernel does not reliably install an IPv6 connected
/// route while the link is down.
///
/// No IPv4 is assigned at all. `100.64.0.0/10` belongs to whatever other VPN
/// shares the host, and the overlay carries no IPv4 to put there.
#[cfg(not(target_os = "android"))]
pub async fn create(v6: Ipv6Addr) -> Result<(TunReader, TunWriter, String)> {
    // `ipv6(v6, 128)` assigns just our own address (a /128, no connected route)
    // cross-platform. `enable(true)` brings the link up at creation (as the old
    // `.up()` did); `set_link_up` and the peer-range route helpers still run
    // later on activate. No IPv4 is assigned at all: the overlay is IPv6-only,
    // and `100.64.0.0/10` belongs to whatever else may be sharing the host.
    let device = DeviceBuilder::new()
        .ipv6(v6, 128)
        .mtu(TUN_MTU)
        .enable(true)
        .build_async()
        .context("create tun-rs device")?;

    let tun_name = device.name().unwrap_or_else(|_| "unknown".to_string());
    tracing::info!(ipv6 = %v6, tun = %tun_name, "TUN device created");

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

/// Routes the peer range into the TUN. Must be called *after* the interface is
/// up (see [`set_link_up`]): the kernel does not reliably install an IPv6
/// connected route while the link is down, and peer traffic would otherwise leak
/// out the host's default IPv6 route. `200::/7` is the whole range, magic DNS
/// (`dns::MAGIC_DNS_V6`) included, so nothing else needs a host route.
/// Idempotent, safe to call on every `up` cycle.
#[cfg(target_os = "linux")]
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
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
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
    // utun is point-to-point, so the address prefix alone does not reliably
    // create the range route; macOS also drops it across an `up`/`down` cycle,
    // so it is re-added on every activate. `route add` fails if the route
    // already exists (e.g. an earlier `up`), so delete any stale entry first and
    // ignore its result. `200::/7` covers `dns::MAGIC_DNS_V6` too.
    let ranges: &[(&str, &str)] = &[("-inet6", "200::/7")];
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
/// with what the gateway says it can return). That is `::/1` + `8000::/1`, or
/// nothing at all: the overlay carries no IPv4, so IPv4 egress stays with
/// whoever owns `100.64.0.0/10` here. Unlike Linux, no hole has to be
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
/// live tunnel can narrow (the gateway loses its IPv6 uplink and republishes a
/// narrower claim) and the re-apply arrives with one family fewer. Skipping the
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
pub async fn route_self_loopback(v6: Ipv6Addr) -> Result<()> {
    let families = [("-inet6", v6.to_string())];
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
pub async fn route_self_loopback(_v6: Ipv6Addr) -> Result<()> {
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
    /// A narrowing tunnel must delete the family it stopped carrying.
    ///
    /// `carries` follows the gateway's claim, so it changes under a live tunnel:
    /// the gateway republishes a claim with no IPv6 in it, and the re-apply
    /// arrives with one family fewer. The utun is still up, so nothing reaps the
    /// dropped family's half-space routes on their own, and that family keeps
    /// entering a tunnel whose far end cannot return it while
    /// `ray exit-node status` says it is leaving directly.
    ///
    /// `tunnelled` narrows to `V6` or `Neither`, but the plan is written against
    /// the whole enum because the claim rides the signed roster and is decoded
    /// as well as written.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn the_split_default_plan_visits_every_family_and_adds_only_what_it_carries() {
        use crate::membership::ExitFamilies::{Dual, Neither, Unknown, V4, V6};

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
        for carries in [Dual, V6, V4, Neither, Unknown] {
            assert_eq!(deletes(carries), all_four, "{carries:?}");
        }

        // And only the carried family is added back. `V6` and `Neither` are the
        // two a real selection produces.
        assert_eq!(
            adds(V6),
            [
                "-n add -inet6 -net ::/1 -interface utun9",
                "-n add -inet6 -net 8000::/1 -interface utun9",
            ]
        );
        assert!(adds(Neither).is_empty(), "nothing to carry, nothing to add");
        assert_eq!(
            adds(V4),
            [
                "-n add -inet -net 0.0.0.0/1 -interface utun9",
                "-n add -inet -net 128.0.0.0/1 -interface utun9",
            ]
        );
        assert_eq!(adds(Dual).len(), 4);
        // An absent claim predates the field, so it is read as both families.
        assert_eq!(adds(Unknown).len(), 4);
    }
}
