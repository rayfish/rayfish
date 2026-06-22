//! Shared wire protocol for rayfish.
//!
//! Both the `ray` daemon/CLI and GUI frontends speak the same [`ipc::IpcMessage`]
//! enum over a length-prefixed msgpack Unix socket. This crate is the single source
//! of truth for that protocol so frontends never hand-mirror it.

pub mod ipc;
mod types;

pub use types::{GroupMode, TransportMode};
