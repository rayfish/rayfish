//! Local alias handlers for `Daemon`: `set_alias` / `remove_alias` /
//! `list_aliases`. Aliases are a node-local, per-network convenience (`alias
//! name -> identity string`) that show inline in `ray status` and seed `ray
//! apply`'s `aliases:` map. They are never published in the signed GroupBlob.

use super::super::*;

impl NetworkRegistry {
    /// Bind a local alias to an identity for a network. The identity is already
    /// canonicalized CLI-side (the string `ray identityof` prints); this just
    /// persists the mapping. Overwrites any existing alias of the same name.
    pub(crate) fn set_alias(&self, network: &str, identity: &str, alias: &str) -> IpcMessage {
        match config::update_network(network, |net| {
            net.aliases.insert(alias.to_string(), identity.to_string());
            Ok(())
        }) {
            Ok(Some(_)) => {}
            Ok(None) => return ipc_err(format!("network '{network}' not found")),
            Err(e) => return ipc_err(format!("failed to save config: {e}")),
        }
        IpcMessage::Ok {
            message: format!("alias '{alias}' -> {identity} on '{network}'"),
        }
    }

    /// Remove a local alias by name. Reports an error if no such alias exists so
    /// a typo is visible rather than silently succeeding.
    pub(crate) fn remove_alias(&self, network: &str, alias: &str) -> IpcMessage {
        let mut removed = false;
        match config::update_network(network, |net| {
            removed = net.aliases.remove(alias).is_some();
            Ok(())
        }) {
            Ok(Some(_)) if removed => {}
            Ok(Some(_)) => return ipc_err(format!("no alias '{alias}' on '{network}'")),
            Ok(None) => return ipc_err(format!("network '{network}' not found")),
            Err(e) => return ipc_err(format!("failed to save config: {e}")),
        }
        IpcMessage::Ok {
            message: format!("removed alias '{alias}' from '{network}'"),
        }
    }

    /// List a network's local aliases (`alias name -> identity`). Open read.
    pub(crate) fn list_aliases(&self, network: &str) -> IpcMessage {
        match config::load_network(network) {
            Ok(Some(n)) => IpcMessage::AliasListResponse { aliases: n.aliases },
            Ok(None) => ipc_err(format!("network '{network}' not found")),
            Err(e) => ipc_err(format!("failed to load network config: {e}")),
        }
    }
}
