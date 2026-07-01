//! Local alias handlers for `DaemonState`: `set_alias` / `remove_alias` /
//! `list_aliases`. Aliases are a node-local, per-network convenience (`alias
//! name -> identity string`) that show inline in `ray status` and seed `ray
//! apply`'s `aliases:` map. They are never published in the signed GroupBlob.

use super::super::*;

impl DaemonState {
    /// Bind a local alias to an identity for a network. The identity is already
    /// canonicalized CLI-side (the string `ray identityof` prints); this just
    /// persists the mapping. Overwrites any existing alias of the same name.
    pub(crate) fn set_alias(&self, network: &str, identity: &str, alias: &str) -> IpcMessage {
        let mut net = match config::load_network(network) {
            Ok(Some(n)) => n,
            Ok(None) => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load network config: {e}"),
                };
            }
        };
        net.aliases.insert(alias.to_string(), identity.to_string());
        if let Err(e) = config::save_network(&net) {
            return IpcMessage::Error {
                message: format!("failed to save config: {e}"),
            };
        }
        IpcMessage::Ok {
            message: format!("alias '{alias}' -> {identity} on '{network}'"),
        }
    }

    /// Remove a local alias by name. Reports an error if no such alias exists so
    /// a typo is visible rather than silently succeeding.
    pub(crate) fn remove_alias(&self, network: &str, alias: &str) -> IpcMessage {
        let mut net = match config::load_network(network) {
            Ok(Some(n)) => n,
            Ok(None) => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load network config: {e}"),
                };
            }
        };
        if net.aliases.remove(alias).is_none() {
            return IpcMessage::Error {
                message: format!("no alias '{alias}' on '{network}'"),
            };
        }
        if let Err(e) = config::save_network(&net) {
            return IpcMessage::Error {
                message: format!("failed to save config: {e}"),
            };
        }
        IpcMessage::Ok {
            message: format!("removed alias '{alias}' from '{network}'"),
        }
    }

    /// List a network's local aliases (`alias name -> identity`). Open read.
    pub(crate) fn list_aliases(&self, network: &str) -> IpcMessage {
        match config::load_network(network) {
            Ok(Some(n)) => IpcMessage::AliasListResponse { aliases: n.aliases },
            Ok(None) => IpcMessage::Error {
                message: format!("network '{network}' not found"),
            },
            Err(e) => IpcMessage::Error {
                message: format!("failed to load network config: {e}"),
            },
        }
    }
}
