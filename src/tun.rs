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
    let output = std::process::Command::new("ifconfig")
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return Ok(()),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_iface = String::new();

    for line in stdout.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ')
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
                     Disable it before starting pitopi.",
                    current_iface, ip
                );
            }
        }
    }

    Ok(())
}

/// Creates a TUN device with the given virtual IPs and splits it into
/// independent read/write halves. IPv4 gets a /10 netmask (100.64.0.0/10),
/// IPv6 gets a /128 host address in the `200::/7` range.
pub fn create(v4: Ipv4Addr, v6: Ipv6Addr) -> Result<(TunReader, TunWriter, String)> {
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
    let tun_name = device.as_ref().tun_name()
        .unwrap_or_else(|_| "unknown".to_string());
    tracing::info!(addr = %v4, ipv6 = %v6, tun = %tun_name, "TUN device created");

    if let Err(e) = add_ipv6_address(&tun_name, v6) {
        tracing::warn!(error = %e, "failed to add IPv6 address to TUN (IPv6 routing will not work)");
    }

    let (writer, reader) = device.split()?;
    Ok((TunReader { reader }, TunWriter { writer }, tun_name))
}

fn add_ipv6_address(tun_name: &str, addr: Ipv6Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("ifconfig")
            .args([tun_name, "inet6", &addr.to_string(), "prefixlen", "128"])
            .status()
            .context("run ifconfig")?;
        anyhow::ensure!(status.success(), "ifconfig inet6 failed with {status}");
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("ip")
            .args(["-6", "addr", "add", &format!("{addr}/128"), "dev", tun_name])
            .status()
            .context("run ip -6 addr add")?;
        anyhow::ensure!(status.success(), "ip -6 addr add failed with {status}");
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
