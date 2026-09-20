//! DNS upstream selection for an active exit tunnel.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::membership::ExitFamilies;

/// The IPv6 resolvers used when an IPv6-only tunnel has no configured IPv6
/// resolver of its own.
pub(super) const PUBLIC_FALLBACK_DNS_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
];

/// Returns DNS upstreams for an IPv6-only exit tunnel. Other tunnel modes keep
/// the normal resolver configuration.
pub(super) fn tunnel_upstreams(
    carries: ExitFamilies,
    configured: &crate::config::ServerOverride,
) -> Option<Vec<SocketAddr>> {
    if carries.carries_v4() || !carries.carries_v6() {
        return None;
    }

    let ipv6_servers: Vec<Ipv6Addr> = configured
        .servers
        .iter()
        .filter_map(|server| server.parse().ok())
        .collect();
    if configured.replace {
        if !ipv6_servers.is_empty() {
            return Some(with_dns_port(ipv6_servers));
        }
        let configured_servers: Vec<SocketAddr> = configured
            .servers
            .iter()
            .filter_map(|server| server.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::from((ip, 53)))
            .collect();
        if !configured_servers.is_empty() {
            return Some(configured_servers);
        }
    }

    let mut servers = ipv6_servers;
    servers.extend(PUBLIC_FALLBACK_DNS_V6);
    Some(with_dns_port(servers))
}

fn with_dns_port(servers: Vec<Ipv6Addr>) -> Vec<SocketAddr> {
    servers
        .into_iter()
        .map(|ip| SocketAddr::from((ip, 53)))
        .collect()
}
