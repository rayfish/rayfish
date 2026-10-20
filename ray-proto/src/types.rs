//! Small enums referenced by [`crate::ipc::IpcMessage`].
//!
//! These live here (rather than in `ray`'s `membership`/`config` modules) so the
//! protocol crate is self-contained. `ray` re-exports them at their original paths,
//! so the daemon's logic is untouched.

use serde::{Deserialize, Serialize};

/// Controls who can approve new members joining the network.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(
    serialize_all = "lowercase",
    parse_err_ty = String,
    parse_err_fn = unknown_group_mode
)]
pub enum GroupMode {
    Open,
    #[default]
    Restricted,
}

fn unknown_group_mode(s: &str) -> String {
    format!("unknown group mode: {s}")
}

/// Per-network transport preference (relay/direct vs. Tor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, derive_more::IsVariant)]
pub enum TransportMode {
    #[default]
    Default,
    Tor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_mode_names_round_trip() {
        assert_eq!(GroupMode::Open.to_string(), "open");
        assert_eq!("restricted".parse(), Ok(GroupMode::Restricted));
        assert_eq!(
            "closed".parse::<GroupMode>(),
            Err("unknown group mode: closed".to_string())
        );
    }
}
