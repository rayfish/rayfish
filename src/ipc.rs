//! IPC protocol — re-exported from the shared `ray-proto` crate.
//!
//! The message enum, codec, and socket helpers live in `ray-proto` so GUI
//! frontends can speak the exact same wire protocol. Kept as `crate::ipc::*` here
//! so the daemon/CLI continue to use their original paths unchanged.

pub use ray_proto::ipc::*;
