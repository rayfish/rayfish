//! DNS upstream selection for an active exit tunnel.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::membership::ExitFamilies;

/// The IPv6 resolvers used when an IPv6-only tunnel has no configured IPv6
/// resolver of its own.
pub(super) const PUBLIC_FALLBACK_DNS_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
];

/// Use reachable public resolvers by default. Captured LAN resolvers must not
/// send exit traffic outside the tunnel. Explicit replacement remains authoritative.
pub(super) fn tunnel_upstreams(
    carries: ExitFamilies,
    configured: &crate::config::ServerOverride,
) -> Option<Vec<SocketAddr>> {
    let configured_servers: Vec<IpAddr> = configured
        .servers
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let mut servers: Vec<IpAddr> = configured_servers
        .iter()
        .copied()
        .filter(|ip| match ip {
            IpAddr::V4(_) => carries.carries_v4(),
            IpAddr::V6(_) => carries.carries_v6(),
        })
        .collect();
    if configured.replace && !configured_servers.is_empty() {
        if servers.is_empty() {
            servers = configured_servers;
        }
    } else if carries.carries_v4() {
        servers.extend([
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ]);
    } else {
        servers.extend(PUBLIC_FALLBACK_DNS_V6.into_iter().map(IpAddr::V6));
    }
    Some(
        servers
            .into_iter()
            .map(|ip| SocketAddr::from((ip, 53)))
            .collect(),
    )
}
