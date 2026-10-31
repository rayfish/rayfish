//! DNS upstream selection for an active exit tunnel.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use super::policy::is_transitable;
use crate::dns::resolver::is_own_resolver;
use crate::membership::{ExitFamilies, is_overlay_ip};
use crate::transport::PUBLIC_FALLBACK_DNS;

/// The IPv6 resolvers used when an IPv6-only tunnel has no configured IPv6
/// resolver of its own.
pub(super) const PUBLIC_FALLBACK_DNS_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
];

/// Use reachable public resolvers by default. Captured LAN resolvers must not
/// send exit traffic outside the tunnel. Explicit replacement remains authoritative:
/// when none of its servers is reachable, lookups fail rather than go elsewhere.
pub(super) fn tunnel_upstreams(
    carries: ExitFamilies,
    configured: &crate::config::ServerOverride,
) -> Vec<SocketAddr> {
    // Our own resolver address is no upstream: the resolver drops it, and a
    // replacement made only of it would leave no override, so lookups would go
    // to the captured system resolvers around the exit.
    let configured_servers: Vec<IpAddr> = configured
        .servers
        .iter()
        .filter_map(|s| s.parse().ok())
        .filter(|ip| !is_own_resolver(*ip))
        .collect();
    // The gateway refuses private destinations, so a LAN resolver would only
    // time out ahead of the ones that work. Mesh resolvers do not use the exit.
    let mut servers: Vec<IpAddr> = configured_servers
        .iter()
        .copied()
        .filter(|ip| is_overlay_ip(*ip) || is_transitable(*ip))
        .filter(|ip| carries.carries(*ip))
        .collect();
    if configured.replace && !configured_servers.is_empty() {
        if servers.is_empty() {
            servers = configured_servers;
        }
    } else if carries.carries_v4() {
        servers.extend(PUBLIC_FALLBACK_DNS.into_iter().filter(|ip| ip.is_ipv4()));
    } else {
        servers.extend(PUBLIC_FALLBACK_DNS_V6.into_iter().map(IpAddr::V6));
    }
    servers
        .into_iter()
        .map(|ip| SocketAddr::from((ip, 53)))
        .collect()
}
