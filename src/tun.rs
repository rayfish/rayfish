//! TUN device creation and I/O.
//!
//! The device is immediately split into [`TunReader`] and [`TunWriter`] halves
//! so that reads and writes can happen concurrently without locking.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::{Configuration, DeviceReader, DeviceWriter};

/// MTU sized to fit within QUIC datagram limits.
const TUN_MTU: u16 = 1200;

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
    let output = std::process::Command::new("ifconfig").output();

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

/// Assigns the IPv6 address to the TUN and ensures the `200::/7` peer range
/// routes into it. The address is added with a `/7` prefix so the kernel
/// installs the connected route automatically — no separate route entry needed.
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

        // `/7` prefix → kernel adds the 200::/7 connected route into the TUN,
        // exactly as the IPv4 /10 netmask does. `replace()` keeps it idempotent
        // across daemon restarts.
        handle
            .address()
            .add(index, IpAddr::V6(addr), 7)
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
    // macOS has no netlink; assign the address and add the range route via the
    // BSD tools. utun is point-to-point, so the /7 prefix alone does not create
    // the connected route — we add it explicitly.
    let status = std::process::Command::new("ifconfig")
        .args([tun_name, "inet6", &addr.to_string(), "prefixlen", "128"])
        .status()
        .context("run ifconfig")?;
    anyhow::ensure!(status.success(), "ifconfig inet6 failed with {status}");

    // `route add` fails if the route already exists (e.g. daemon restart), so
    // delete any stale entry first and ignore its result.
    let _ = std::process::Command::new("route")
        .args([
            "-n",
            "delete",
            "-inet6",
            "-net",
            "200::/7",
            "-interface",
            tun_name,
        ])
        .status();
    let status = std::process::Command::new("route")
        .args([
            "-n",
            "add",
            "-inet6",
            "-net",
            "200::/7",
            "-interface",
            tun_name,
        ])
        .status()
        .context("run route add -inet6")?;
    anyhow::ensure!(status.success(), "route add -inet6 failed with {status}");
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
        let status = std::process::Command::new("ifconfig")
            .args([tun_name, state])
            .status()
            .context("run ifconfig")?;
        anyhow::ensure!(status.success(), "ifconfig {state} failed with {status}");
    }
    #[cfg(target_os = "linux")]
    {
        let state = if up { "up" } else { "down" };
        let status = std::process::Command::new("ip")
            .args(["link", "set", tun_name, state])
            .status()
            .context("run ip link set")?;
        anyhow::ensure!(status.success(), "ip link set {state} failed with {status}");
    }
    Ok(())
}

impl TunReader {
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.reader.read(buf).await?;
        Ok(n)
    }
}

impl TunWriter {
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.writer.write_all(packet).await?;
        Ok(())
    }
}
