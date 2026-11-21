//! DNS upstreams in network policy and deployment files.

use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ipc::MachineHostname;

/// A literal resolver address or a hostname resolved from the network roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsUpstream {
    Ip(IpAddr),
    Peer(MachineHostname),
}

impl fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Peer(host) => host.fmt(f),
        }
    }
}

impl FromStr for DnsUpstream {
    type Err = InvalidDnsUpstream;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = value.parse() {
            return Ok(Self::Ip(ip));
        }
        value
            .parse()
            .map(Self::Peer)
            .map_err(|_| InvalidDnsUpstream)
    }
}

impl Serialize for DnsUpstream {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DnsUpstream {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidDnsUpstream;

impl fmt::Display for InvalidDnsUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS upstream must be an IP address or a lowercase mesh hostname")
    }
}

impl Error for InvalidDnsUpstream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams_use_strings_on_the_wire_and_validate_input() {
        for text in ["1.1.1.1", "2606:4700:4700::1111", "dns-server"] {
            let upstream: DnsUpstream = text.parse().unwrap();
            let encoded = rmp_serde::to_vec(&upstream).unwrap();
            assert_eq!(rmp_serde::from_slice::<String>(&encoded).unwrap(), text);
            assert_eq!(
                rmp_serde::from_slice::<DnsUpstream>(&encoded).unwrap(),
                upstream
            );
        }
        assert!("bad.name".parse::<DnsUpstream>().is_err());
        assert!("1.1.1.1:53".parse::<DnsUpstream>().is_err());
    }
}
