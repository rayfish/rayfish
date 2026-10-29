//! Rootless Linux networking. The mesh carries ordinary IPv6 packets; smoltcp
//! replaces the kernel stack, and only configured proxies and forwards use it.

mod http;
pub(crate) mod proxy;
pub(crate) mod stack;

use std::fmt;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroU16;
use std::str::FromStr;

use anyhow::{Context, Result};
use url::Host;

use crate::daemon::Daemon;

#[derive(Clone, Debug)]
pub struct Target {
    host: Host<String>,
    port: NonZeroU16,
}

impl FromStr for Target {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let (host, port) = value
            .rsplit_once(':')
            .context("expected PEER:PORT (bracket IPv6 addresses)")?;
        let host = Host::parse(host)?;
        let port = port
            .parse::<NonZeroU16>()
            .context("port must be between 1 and 65535")?;
        Ok(Self { host, port })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl Target {
    pub(super) async fn resolve(&self, daemon: &Daemon) -> Result<SocketAddrV6> {
        let ip = match &self.host {
            Host::Ipv6(ip) => *ip,
            Host::Domain(host) => daemon
                .rootless_resolve(host)
                .await
                .context("unknown mesh hostname")?,
            Host::Ipv4(_) => {
                anyhow::bail!("rootless mode currently supports mesh IPv6 destinations only")
            }
        };
        anyhow::ensure!(
            crate::membership::is_overlay_ip(ip.into()),
            "destination must be a mesh IPv6 address"
        );
        Ok(SocketAddrV6::new(ip, self.port.get(), 0, 0))
    }

    pub(super) fn ipv6(ip: Ipv6Addr, port: u16) -> Result<Self> {
        Ok(Self {
            host: Host::Ipv6(ip),
            port: NonZeroU16::new(port).context("port cannot be zero")?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct LocalForward {
    listen: SocketAddr,
    target: Target,
}
impl FromStr for LocalForward {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let (listen, target) = value
            .split_once('=')
            .context("expected LOCAL_PORT=PEER:PORT")?;
        let listen = loopback_listener(listen)?;
        // TCP loopback has no Unix peer credentials. It cannot be private on a shared host.
        Ok(Self {
            listen,
            target: target.parse()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Expose {
    port: NonZeroU16,
    target: SocketAddr,
}
impl FromStr for Expose {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let (port, target) = value
            .split_once('=')
            .context("expected MESH_PORT=LOOPBACK_ADDRESS:PORT")?;
        let port = port.parse::<NonZeroU16>()?;
        let target: SocketAddr = target.parse()?;
        anyhow::ensure!(
            target.ip().is_loopback() && target.port() != 0,
            "exposed target must be a loopback address with a nonzero port"
        );
        Ok(Self { port, target })
    }
}

pub fn loopback_listener(value: &str) -> Result<SocketAddr> {
    let address = match value.parse::<u16>() {
        Ok(port) => SocketAddr::from(([127, 0, 0, 1], port)),
        Err(_) => value.parse()?,
    };
    anyhow::ensure!(
        address.ip().is_loopback(),
        "proxy listeners must use a loopback address"
    );
    Ok(address)
}

pub struct Options {
    pub socks5: SocketAddr,
    pub http: Option<SocketAddr>,
    pub forwards: Vec<LocalForward>,
    pub expose: Vec<Expose>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_forward_destinations_and_local_exposure() {
        assert!("[200::1]:22".parse::<Target>().is_ok());
        assert!("host.network.ray:22".parse::<Target>().is_ok());
        assert!("host:0".parse::<Target>().is_err());
        assert!("22=127.0.0.1:8022".parse::<Expose>().is_ok());
        assert!("22=0.0.0.0:8022".parse::<Expose>().is_err());
        assert!("0.0.0.0:8080=host:80".parse::<LocalForward>().is_err());
    }
}
