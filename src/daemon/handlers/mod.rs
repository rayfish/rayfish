//! `DaemonState`'s IPC handlers, split by domain. Each submodule holds an
//! additional `impl DaemonState` block and opens with `use super::super::*;` to
//! inherit the imports and private types declared in `daemon/mod.rs`.
//!
//! These live under `handlers/` (rather than as siblings of `daemon/mod.rs`) so
//! the module names can be the clean domain names — `firewall`, `connect`, …  —
//! without colliding with the `use crate::{firewall, dns, …}` aliases that
//! `daemon/mod.rs` brings into its own namespace. The modules export no names of
//! their own (only `impl DaemonState` blocks), so no re-export is needed; the
//! methods attach to `DaemonState` and are called as `self.method()`.

mod admin;
mod alias;
mod connect;
mod create_join;
mod diagnostics;
mod files;
mod firewall;
mod invite;
mod runtime;
