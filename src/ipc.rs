//! IPC protocol, re-exported from the shared `ray-proto` crate.
//!
//! The message enum, codec, and socket helpers live in `ray-proto` so GUI
//! frontends can speak the exact same wire protocol. Kept as `crate::ipc::*` here
//! so the daemon/CLI continue to use their original paths unchanged.

pub use ray_proto::ipc::*;

/// Shorthand for the ubiquitous `IpcMessage::Error { message }` reply. Lets a
/// handler write `return ipc_err(format!("..."))` (or `... ?` via the
/// `Result<IpcMessage, IpcMessage>` handler alias) instead of the three-line
/// struct literal.
pub fn ipc_err(msg: impl Into<String>) -> IpcMessage {
    IpcMessage::Error {
        message: msg.into(),
    }
}
