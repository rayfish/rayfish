//! TUN device creation and I/O.
//!
//! The device is a single `tun-rs` [`AsyncDevice`] shared (via `Arc`) between a
//! [`TunReader`] and a [`TunWriter`]; its `recv`/`send` take `&self`, so reads
//! and writes run concurrently without a split or a lock.

// These support the desktop TUN setup (address/route/link configuration via
// `ifconfig`/`ip`/netlink) and the CGNAT preflight, none of which compile on
// Android where the packet interface is a `VpnService` fd.
#[cfg(not(target_os = "android"))]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(not(target_os = "android"))]
use std::process::Command;
#[cfg(not(target_os = "android"))]
use std::sync::Arc;

#[cfg(not(target_os = "android"))]
use anyhow::{Context, Result, bail};
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

#[cfg(not(target_os = "android"))]
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

#[cfg(not(target_os = "android"))]
pub fn check_cgnat_conflict() -> Result<()> {
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
                bail!(
                    "interface {} already has CGNAT address {} — another VPN \
                     (e.g. Tailscale) is using the 100.64.0.0/10 range. \
                     Disable it before starting rayfish.",
                    current_iface,
                    ip
                );
            }
        }
    }

    Ok(())
}

/// Creates a TUN device with the given virtual IPs and shares it between
/// independent read/write halves. IPv4 gets a /10 (100.64.0.0/10); IPv6 gets our
/// own /128 address. The `200::/7` peer range is routed in separately by
/// [`route_peer_range`] after link-up (the kernel does not reliably install an
/// IPv6 connected route while the link is down), mirroring how the IPv4 /10 works.
#[cfg(not(target_os = "android"))]
pub async fn create(v4: Ipv4Addr, v6: Ipv6Addr) -> Result<(TunReader, TunWriter, String)> {
    let gateway = Ipv4Addr::new(100, 64, 0, 1);
    // `10` is the /10 prefix (was the (255,192,0,0) netmask); `Some(gateway)` is
    // the point-to-point destination. `ipv6(v6, 128)` assigns just our own
    // address (a /128, no connected route) cross-platform, replacing the old
    // netlink/`ifconfig` `configure_ipv6` shell-out. `enable(true)` brings the
    // link up at creation (as the old `.up()` did); `set_link_up` and the
    // peer-range route helpers still run later on activate.
    let device = DeviceBuilder::new()
        .ipv4(v4, 10, Some(gateway))
        .ipv6(v6, 128)
        .mtu(TUN_MTU)
        .enable(true)
        .build_async()
        .context("create tun-rs device")?;

    let tun_name = device.name().unwrap_or_else(|_| "unknown".to_string());
    tracing::info!(addr = %v4, ipv6 = %v6, tun = %tun_name, "TUN device created");

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

/// Re-assigns our own IPv6 `/128` to the TUN. The address is set once at device
/// creation, but Linux flushes an interface's global IPv6 addresses when the link
/// goes down (`keep_addr_on_down` defaults to 0) and never restores them, while
/// IPv4 addresses survive. Without this, a `down`/`up` cycle leaves the node with
/// a working IPv4 overlay and a silently dead IPv6 one: it still routes `200::/7`
/// into the TUN, but owns no address in it, so peers get no answer. Must run after
/// [`set_link_up`]; idempotent (netlink `replace`), safe on every `up` cycle.
#[cfg(target_os = "linux")]
pub async fn ensure_ipv6_addr(tun_name: &str, v6: Ipv6Addr) -> Result<()> {
    use futures::TryStreamExt;
    use std::net::IpAddr;

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

        handle
            .address()
            .add(index, IpAddr::V6(v6), 128)
            .replace()
            .execute()
            .await
            .context("add TUN IPv6 address via netlink")?;

        Ok(())
    }
    .await;

    conn.abort();
    result
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
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
    use futures::TryStreamExt;
    use rtnetlink::RouteMessageBuilder;

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
            .context("add 200::/7 route via netlink")?;

        Ok(())
    }
    .await;

    conn.abort();
    result
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
    // utun is point-to-point, so the address prefix alone does not reliably
    // create the range route, we add both families explicitly. The IPv4 `/10`
    // is only installed implicitly by the `tun` crate at device creation and
    // macOS drops it across an `up`/`down` cycle, so (like the IPv6 `/7`) we
    // re-add it on every activate or peers become unreachable over IPv4 while
    // IPv6 still works. `route add` fails if the route already exists (e.g. an
    // earlier `up`), so delete any stale entry first and ignore its result.
    for (family, net) in [("-inet", "100.64.0.0/10"), ("-inet6", "200::/7")] {
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

/// Routes the magic-DNS virtual IP (`dns::MAGIC_DNS_V4`) into the TUN as a `/32`
/// host route so that packets from the kernel addressed to that IP are delivered
/// to the TUN device (and thus intercepted by our DNS server) rather than going
/// out the host's default gateway. The IP is **never** assigned as a local
/// interface address, it is a route-only entry. Idempotent across `up`/`down`.
#[cfg(target_os = "linux")]
pub async fn route_magic_dns(tun_name: &str) -> Result<()> {
    use futures::TryStreamExt;
    use rtnetlink::RouteMessageBuilder;

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
            .context("add magic-DNS /32 route via netlink")?;

        Ok(())
    }
    .await;

    conn.abort();
    result
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
pub async fn route_self_loopback(v4: Ipv4Addr, v6: Ipv6Addr) -> Result<()> {
    for (family, addr) in [("-inet", v4.to_string()), ("-inet6", v6.to_string())] {
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
pub async fn route_self_loopback(_v4: Ipv4Addr, _v6: Ipv6Addr) -> Result<()> {
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
