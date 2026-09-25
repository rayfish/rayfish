//! Platform-neutral destination policy for exit-node transit.

use std::net::IpAddr;

use crate::membership::{is_cgnat_range, is_overlay_ip};

/// Whether an exit node may forward to `destination`.
pub fn is_transitable(destination: IpAddr) -> bool {
    if is_overlay_ip(destination) || matches!(destination, IpAddr::V4(ip) if is_cgnat_range(ip)) {
        return false;
    }

    match destination {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_documentation()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240)
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}
