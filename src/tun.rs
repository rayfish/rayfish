//! TUN device creation and I/O.
//!
//! The device is immediately split into [`TunReader`] and [`TunWriter`] halves
//! so that reads and writes can happen concurrently without locking.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::{Configuration, DeviceReader, DeviceWriter};

/// MTU for the TUN device. IPv6 mandates a minimum link MTU of 1280 bytes
/// (RFC 8200 §5); Linux refuses to enable IPv6 on a device with a smaller MTU,
/// which silently breaks IPv6 address/route installation (`configure_ipv6` /
/// `route_peer_range` fail with `EINVAL`). 1280 is also the value WireGuard and
/// Tailscale use for their TUN interfaces for the same reason, and it still
/// fits within QUIC datagram limits.
const TUN_MTU: u16 = 1280;

/// Read half of the TUN device. Owned by [`forward::run_mesh`].
pub struct TunReader {
    reader: DeviceReader,
}

/// Write half of the TUN device. Owned by [`forward::spawn_tun_writer`].
pub struct TunWriter {
    writer: DeviceWriter,
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

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

/// Creates a TUN device with the given virtual IPs and splits it into
/// independent read/write halves. IPv4 gets a /10 netmask (100.64.0.0/10);
/// IPv6 gets a /7 prefix (`200::/7`) so the kernel installs the connected
/// route for the whole peer range, mirroring how the IPv4 /10 netmask works.
pub async fn create(v4: Ipv4Addr, v6: Ipv6Addr) -> Result<(TunReader, TunWriter, String)> {
    let gateway = Ipv4Addr::new(100, 64, 0, 1);
    let mut config = Configuration::default();
    config
        .address(v4)
        .destination(gateway)
        .netmask((255, 192, 0, 0)) // /10
        .mtu(TUN_MTU)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let device = tun::create_as_async(&config)?;
    let tun_name = device
        .as_ref()
        .tun_name()
        .unwrap_or_else(|_| "unknown".to_string());
    tracing::info!(addr = %v4, ipv6 = %v6, tun = %tun_name, "TUN device created");

    if let Err(e) = configure_ipv6(&tun_name, v6).await {
        tracing::warn!(error = %e, "failed to configure IPv6 on TUN (IPv6 routing will not work)");
    }

    let (writer, reader) = device.split()?;
    Ok((TunReader { reader }, TunWriter { writer }, tun_name))
}

/// Assigns the TUN's own IPv6 address. The `200::/7` peer range is routed into
/// the TUN separately by [`route_peer_range`], which must run *after* the link
/// is up — assigning the address here at creation time (link still down) is not
/// enough on Linux, where the kernel does not reliably install the connected
/// route until the interface comes up.
#[cfg(target_os = "linux")]
async fn configure_ipv6(tun_name: &str, addr: Ipv6Addr) -> Result<()> {
    use futures::TryStreamExt;
    use std::net::IpAddr;

    let (connection, handle, _) = rtnetlink::new_connection().context("open netlink socket")?;
    // The connection future must be polled while we use the handle; abort it
    // once configuration is done.
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

        // /128: just our own address. The peer-range route is added explicitly
        // after link-up in `route_peer_range`. `replace()` keeps it idempotent
        // across daemon restarts.
        handle
            .address()
            .add(index, IpAddr::V6(addr), 128)
            .replace()
            .execute()
            .await
            .context("add IPv6 address via netlink")?;

        Ok(())
    }
    .await;

    conn.abort();
    result
}

#[cfg(target_os = "macos")]
async fn configure_ipv6(tun_name: &str, addr: Ipv6Addr) -> Result<()> {
    // macOS has no netlink; assign the address via the BSD tools. The peer-range
    // route is added separately by `route_peer_range` after link-up.
    let status = Command::new("ifconfig")
        .args([tun_name, "inet6", &addr.to_string(), "prefixlen", "128"])
        .status()
        .context("run ifconfig")?;
    anyhow::ensure!(status.success(), "ifconfig inet6 failed with {status}");
    Ok(())
}

/// Routes the peer ranges into the TUN. Must be called *after* the interface is
/// up (see [`set_link_up`]). On Linux only the IPv6 `200::/7` route needs adding:
/// the kernel does not reliably install an IPv6 connected route while the link is
/// down (peer traffic would otherwise leak out the host's default IPv6 route),
/// whereas it re-installs the IPv4 `100.64.0.0/10` connected route from the /10
/// netmask automatically on link-up. On macOS the point-to-point utun installs
/// neither range reliably, so *both* `100.64.0.0/10` and `200::/7` are added
/// explicitly. Idempotent — safe to call on every `up` cycle.
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

#[cfg(target_os = "macos")]
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
    // utun is point-to-point, so the address prefix alone does not reliably
    // create the range route — we add both families explicitly. The IPv4 `/10`
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
        anyhow::ensure!(status.success(), "route add {family} {net} failed with {status}");
    }
    Ok(())
}

/// Routes the magic-DNS virtual IP (`dns::MAGIC_DNS_V4`) into the TUN as a `/32`
/// host route so that packets from the kernel addressed to that IP are delivered
/// to the TUN device (and thus intercepted by our DNS server) rather than going
/// out the host's default gateway. The IP is **never** assigned as a local
/// interface address — it is a route-only entry. Idempotent across `up`/`down`.
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

#[cfg(target_os = "macos")]
pub async fn route_magic_dns(tun_name: &str) -> Result<()> {
    let ip = crate::dns::MAGIC_DNS_V4.to_string();
    let _ = Command::new("route")
        .args(["-n", "delete", "-inet", "-host", &ip, "-interface", tun_name])
        .status();
    let status = Command::new("route")
        .args(["-n", "add", "-inet", "-host", &ip, "-interface", tun_name])
        .status()
        .context("run route add magic dns")?;
    anyhow::ensure!(status.success(), "route add magic dns failed with {status}");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn route_magic_dns(_tun_name: &str) -> Result<()> {
    Ok(())
}

/// Install host routes for our *own* dual-stack addresses via the loopback
/// interface so traffic to ourselves (e.g. `ping dario.field.ray` resolving to
/// our own IP) is short-circuited locally instead of being sent out the TUN —
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
#[cfg(target_os = "macos")]
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

#[cfg(not(target_os = "macos"))]
pub async fn route_self_loopback(_v4: Ipv4Addr, _v6: Ipv6Addr) -> Result<()> {
    // Linux installs the loopback `local` route automatically on address
    // assignment; self-traffic already works without an explicit route.
    Ok(())
}

/// Bring the TUN interface administratively up (used when activating the VPN).
pub fn set_link_up(tun_name: &str) -> Result<()> {
    set_link_state(tun_name, true)
}

/// Bring the TUN interface administratively down (standby). The underlying file
/// descriptor stays open, so the device can be brought back up without
/// recreating it.
pub fn set_link_down(tun_name: &str) -> Result<()> {
    set_link_state(tun_name, false)
}

fn set_link_state(tun_name: &str, up: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
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

impl TunReader {
    /// Reads one packet from the TUN device, appending it into the spare
    /// capacity of `buf` without zeroing or reallocating. The caller MUST ensure
    /// `buf` has at least one MTU of spare capacity before calling — a short
    /// buffer truncates the packet. Returns the number of bytes read.
    ///
    /// Reading straight into a [`BytesMut`] lets the forward loop hand the
    /// packet to quinn as a zero-copy `split_to(n).freeze()`, avoiding the
    /// per-packet allocate-and-copy a `Bytes::copy_from_slice` would cost.
    pub async fn read_into(&mut self, buf: &mut bytes::BytesMut) -> Result<usize> {
        let n = self.reader.read_buf(buf).await?;
        Ok(n)
    }
}

impl TunWriter {
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.writer.write_all(packet).await?;
        Ok(())
    }
}
