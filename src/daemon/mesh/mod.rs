//! [`MeshManager`]'s IPC operations, split by domain. Each submodule holds an
//! additional `impl MeshManager` block and opens with `use super::super::*;` to
//! inherit the imports and private types declared in `daemon/mod.rs`.
//!
//! These live under `mesh/` (rather than as siblings of `daemon/mod.rs`) so the
//! module names can be the clean domain names — `firewall`, `connect`, …  —
//! without colliding with the `use crate::{firewall, dns, …}` aliases that
//! `daemon/mod.rs` brings into its own namespace. The modules export no names of
//! their own (only `impl MeshManager` blocks), so no re-export is needed; the
//! methods attach to `MeshManager` and are called as `self.method()`.

mod accept;
mod admin;
mod alias;
mod bootstrap;
mod connect;
mod coordinator;
mod create_join;
mod diagnostics;
mod files;
mod firewall;
mod invite;
mod join;
mod publish;
mod reconverge;
mod rename;
mod runtime;
mod select;

// The join handshake (`join`) and the background-task / reconvergence modules
// (split out of the former `background.rs`: `publish`, `reconverge`,
// `coordinator`, `select`, `rename`) moved here from `daemon/mod.rs`; re-export
// their names so the rest of the daemon reaches them (via the daemon-level
// `pub(crate) use mesh::*`).
pub(crate) use accept::*;
pub(crate) use coordinator::*;
pub(crate) use join::*;
pub(crate) use publish::*;
pub(crate) use reconverge::*;
pub(crate) use rename::*;
pub(crate) use select::*;
// `run_daemon` is the public process entry point (called by `ray daemon`).
pub use bootstrap::run_daemon;
// `build_headless` is the embedder (mobile) construction entry point.
pub use bootstrap::build_headless;
