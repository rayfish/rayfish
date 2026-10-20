//! Reading and writing Linux sysctls through `/proc/sys`. Blocking: async
//! callers run these on a blocking thread.

use std::fs;

use anyhow::{Context, Result};

/// The sysctl's current value, or `""` if it can't be read (then it is not
/// restored on teardown).
pub(crate) fn read_sysctl(path: &str) -> String {
    fs::read_to_string(format!("/proc/sys/{path}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub(crate) fn write_sysctl(path: &str, value: &str) -> Result<()> {
    fs::write(format!("/proc/sys/{path}"), value)
        .with_context(|| format!("writing sysctl {path}={value}"))
}

/// The path of a per-interface IPv6 setting, as [`read_sysctl`] takes it.
pub(crate) fn ipv6_conf(interface: &str, key: &str) -> String {
    format!("net/ipv6/conf/{interface}/{key}")
}
