//! Small enums referenced by [`crate::ipc::IpcMessage`].
//!
//! These live here (rather than in `ray`'s `membership`/`config` modules) so the
//! protocol crate is self-contained. `ray` re-exports them at their original paths,
//! so the daemon's logic is untouched.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

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

/// The IPv6-only data plane, as a setting and as the state it resolves to.
///
/// Three values because "off" has to be sayable: without it a host could not
/// opt out of being moved onto the mode by the startup scan.
///
/// As a **setting** (`ray config set ipv6-only`, the app's own store on
/// Android): `Auto` leaves the decision to the scan, `On` and `Off` pin it.
///
/// As the **state** a daemon reports (`IpcMessage::StatusResponse`): `Auto`
/// means the mode is on because the scan found another VPN on
/// `100.64.0.0/10`, `On` means it was asked for, `Off` means the data plane is
/// dual-stack. One type for both because the values are the same three, and
/// because the state is what an auto setting resolved *to*.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Only {
    #[default]
    Auto,
    On,
    Off,
}

impl Ipv6Only {
    /// The state reading: is the data plane IPv6-only? True for `On` and for
    /// `Auto`, which is only ever reported when the scan turned the mode on.
    pub fn enabled(self) -> bool {
        !matches!(self, Ipv6Only::Off)
    }

    /// Nothing was decided or configured. Used to keep `auto` out of the config
    /// file: the mode has to follow the host, so it is never written back.
    pub fn is_auto(&self) -> bool {
        matches!(self, Ipv6Only::Auto)
    }

    /// `Off`, for the status field's serde default: an older daemon that does
    /// not send it is not in the mode, whereas the *setting*'s default is
    /// `Auto`.
    pub fn off() -> Self {
        Ipv6Only::Off
    }
}

impl fmt::Display for Ipv6Only {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Ipv6Only::Auto => "auto",
            Ipv6Only::On => "on",
            Ipv6Only::Off => "off",
        })
    }
}

impl std::str::FromStr for Ipv6Only {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            // Empty is `ray config set ipv6-only unset`, which is the default.
            "auto" | "" => Ok(Ipv6Only::Auto),
            "on" | "true" | "yes" | "1" => Ok(Ipv6Only::On),
            "off" | "false" | "no" | "0" => Ok(Ipv6Only::Off),
            other => Err(format!("expected on, off or auto, got `{other}`")),
        }
    }
}

/// Reads the string form, and the `ipv6_only = true` bool that settings.toml
/// carried before this was three-valued. Config files outlive the shape of the
/// code that writes them; an unreadable one would stop the daemon.
impl<'de> Deserialize<'de> for Ipv6Only {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = Ipv6Only;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("on, off, auto, or a boolean")
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Ipv6Only, E> {
                Ok(if v { Ipv6Only::On } else { Ipv6Only::Off })
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Ipv6Only, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(V)
    }
}

/// Per-network transport preference (relay/direct vs. Tor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, derive_more::IsVariant)]
pub enum TransportMode {
    #[default]
    Default,
    Tor,
}
