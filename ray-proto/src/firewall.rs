//! Firewall enums shared across the IPC boundary.
//!
//! These live here (rather than in `ray`'s `firewall` module) so the protocol
//! crate can carry them typed: `FirewallState`, `FirewallRuleView` and
//! `FirewallAdd` use these enums directly instead of stringly-typed fields.
//! (The single-value toggles do not: `ray firewall default allow|deny` rides
//! `ConfigSet` as a raw word, parsed by the settings registry daemon-side.)
//! `ray`'s `firewall` module re-exports them so the
//! daemon's logic keeps its original `firewall::Action` paths.

use serde::{Deserialize, Serialize};

/// Traffic direction a rule applies to.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(
    serialize_all = "lowercase",
    parse_err_ty = String,
    parse_err_fn = invalid_direction
)]
pub enum Direction {
    In,
    Out,
}

fn invalid_direction(s: &str) -> String {
    format!("invalid direction '{s}' (expected 'in' or 'out')")
}

/// Transport protocol a rule matches.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(
    serialize_all = "lowercase",
    parse_err_ty = String,
    parse_err_fn = invalid_protocol
)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

fn invalid_protocol(s: &str) -> String {
    format!("invalid protocol '{s}' (expected 'tcp', 'udp', 'icmp', or 'any')")
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
    strum::Display,
    strum::EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(
    serialize_all = "lowercase",
    parse_err_ty = String,
    parse_err_fn = invalid_action
)]
pub enum Action {
    Allow,
    Deny,
}

fn invalid_action(s: &str) -> String {
    format!("invalid action '{s}' (expected 'allow' or 'deny')")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_bad_names_say_what_was_expected() {
        for direction in [Direction::In, Direction::Out] {
            assert_eq!(direction.to_string().parse(), Ok(direction));
        }
        for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::Any] {
            assert_eq!(protocol.to_string().parse(), Ok(protocol));
        }
        for action in [Action::Allow, Action::Deny] {
            assert_eq!(action.to_string().parse(), Ok(action));
        }
        assert_eq!(
            "up".parse::<Direction>(),
            Err("invalid direction 'up' (expected 'in' or 'out')".to_string())
        );
        assert_eq!(
            "sctp".parse::<Protocol>(),
            Err("invalid protocol 'sctp' (expected 'tcp', 'udp', 'icmp', or 'any')".to_string())
        );
        assert_eq!(Protocol::Icmp.to_string(), "icmp");
    }
}
