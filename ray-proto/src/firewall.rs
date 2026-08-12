//! Firewall enums shared across the IPC boundary.
//!
//! These live here (rather than in `ray`'s `firewall` module) so the protocol
//! crate can carry them typed — `FirewallState`, `FirewallRuleView` and
//! `FirewallAdd` use these enums directly instead of stringly-typed fields.
//! (The single-value toggles do not: `ray firewall default allow|deny` rides
//! `ConfigSet` as a raw word, parsed by the settings registry daemon-side.)
//! `ray`'s `firewall` module re-exports them so the
//! daemon's logic keeps its original `firewall::Action` paths.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Traffic direction a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, derive_more::Display)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[display("in")]
    In,
    #[display("out")]
    Out,
}

impl FromStr for Direction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "in" => Ok(Direction::In),
            "out" => Ok(Direction::Out),
            _ => Err(format!("invalid direction '{s}' (expected 'in' or 'out')")),
        }
    }
}

/// Transport protocol a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, derive_more::Display)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[display("tcp")]
    Tcp,
    #[display("udp")]
    Udp,
    #[display("icmp")]
    Icmp,
    #[display("any")]
    Any,
}

impl FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "any" => Ok(Protocol::Any),
            _ => Err(format!(
                "invalid protocol '{s}' (expected 'tcp', 'udp', 'icmp', or 'any')"
            )),
        }
    }
}

/// Whether a matching rule (or the default) allows or denies traffic.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    derive_more::IsVariant,
    derive_more::Display,
)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[display("allow")]
    Allow,
    #[display("deny")]
    Deny,
}

impl FromStr for Action {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            _ => Err(format!("invalid action '{s}' (expected 'allow' or 'deny')")),
        }
    }
}
