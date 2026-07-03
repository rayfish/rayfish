//! CLI command handlers, split by domain. `main.rs` (the binary crate root)
//! holds the clap definitions, `main` dispatch, tracing/panic plumbing, and the
//! shared presentation helpers; the per-command handlers live here.
//!
//! Each submodule opens with `use crate::*;` to inherit the crate-root imports
//! and helpers, and this module flattens them back out with `pub use <m>::*;`.
//! `main.rs` then does `use cli::*;`, so every handler — in root or any
//! submodule — resolves the others through the crate-root namespace. Submodules
//! are kept private (`mod`, not `pub mod`) so only their *contents* are
//! re-exported, avoiding a name clash with the `use rayfish::{firewall, …}`
//! aliases in the crate root.

mod alias;
mod connect;
mod files;
mod firewall;
mod invite;
mod network;
mod open;
mod pair;
mod service;
mod status;
mod update;

pub(crate) use alias::*;
pub(crate) use connect::*;
pub(crate) use files::*;
pub(crate) use firewall::*;
pub(crate) use invite::*;
pub(crate) use network::*;
pub(crate) use open::*;
pub(crate) use pair::*;
pub(crate) use service::*;
pub(crate) use status::*;
pub(crate) use update::*;
