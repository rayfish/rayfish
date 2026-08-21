//! Small enums referenced by [`crate::ipc::IpcMessage`].
//!
//! These live here (rather than in `ray`'s `membership`/`config` modules) so the
//! protocol crate is self-contained. `ray` re-exports them at their original paths,
//! so the daemon's logic is untouched.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Controls who can approve new members joining the network.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupMode {
    Open,
    #[default]
    Restricted,
}

impl fmt::Display for GroupMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupMode::Open => write!(f, "open"),
            GroupMode::Restricted => write!(f, "restricted"),
        }
    }
}

impl std::str::FromStr for GroupMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(GroupMode::Open),
            "restricted" => Ok(GroupMode::Restricted),
            other => Err(format!("unknown group mode: {other}")),
        }
    }
}

/// Per-network transport preference (relay/direct vs. Tor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, derive_more::IsVariant)]
pub enum TransportMode {
    #[default]
    Default,
    Tor,
}
