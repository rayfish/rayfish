//! CLI command handlers, split by domain. `main.rs` (the binary crate root)
//! holds the clap definitions, `main` dispatch, tracing/panic plumbing, and the
//! shared presentation helpers; the per-command handlers live here.
//!
//! Each submodule opens with `use crate::*;` to inherit the crate-root imports
//! and helpers, and this module flattens them back out with `pub use <m>::*;`.
//! `main.rs` then does `use cli::*;`, so every handler (in root or any
//! submodule) resolves the others through the crate-root namespace. Submodules
//! are kept private (`mod`, not `pub mod`) so only their *contents* are
//! re-exported, avoiding a name clash with the `use rayfish::{firewall, …}`
//! aliases in the crate root.

mod alias;
mod connect;
mod exit_node;
mod files;
mod firewall;
mod gui;
mod invite;
mod network;
mod open;
mod pair;
mod service;
mod status;
mod update;

pub(crate) use alias::*;
pub(crate) use connect::*;
pub(crate) use exit_node::*;
pub(crate) use files::*;
pub(crate) use firewall::*;
pub(crate) use gui::*;
pub(crate) use invite::*;
pub(crate) use network::*;
pub(crate) use open::*;
pub(crate) use pair::*;
pub(crate) use service::*;
pub(crate) use status::*;
pub(crate) use update::*;

/// Validate an `on|off` argument client-side, before the daemon is dialled.
///
/// The daemon parses the word again through the settings registry, which is the
/// authority; this pre-check exists for two reasons the registry cannot serve.
/// The `ray firewall` / `ray files` handlers print a daemon error and still
/// return `Ok(())`, so a typo caught only server-side would exit 0 instead of 1.
/// And the wording here is the one those commands have always printed, which
/// differs from the registry's.
///
/// Deliberately stricter than `settings::parse_bool` (no `1`/`0`/`true`-only
/// spellings beyond the originals): matching the old behaviour exactly means
/// rejecting exactly what it rejected.
pub(crate) fn parse_on_off(state: &str) -> anyhow::Result<bool> {
    match state.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" => Ok(true),
        "off" | "false" | "no" => Ok(false),
        other => anyhow::bail!("expected `on` or `off`, got '{other}'"),
    }
}
