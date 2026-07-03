//! Admin (co-coordinator) handlers for `DaemonState`: `admin_add` / `admin_list`.
//! Split out of `daemon/mod.rs`.

use super::super::*;

impl DaemonState {
    /// Coordinator-only: grant the per-network secret key to a member over an
    /// authenticated mesh stream, making it a co-coordinator (can publish /
    /// suggest firewall rules). The key is shared (shared-key model), so this is
    /// a transfer of publish capability, not an attributable delegation. The
    /// grant is recorded locally for `ray admin list`.
    pub(crate) async fn admin_add(&self, network: &str, identity_str: &str) -> IpcMessage {
        let Some(identity) = self.resolve_short_id_any_network(identity_str) else {
            return IpcMessage::Error {
                message: format!(
                    "could not resolve identity '{identity_str}' (use a short id of a joined member)"
                ),
            };
        };
        let (net_pubkey, net_secret_key) = match self.networks.get(network) {
            Some(h) => {
                let key = {
                    let s = h.state.read().unwrap();
                    s.network_secret_key.clone()
                };
                if key.is_none() {
                    return IpcMessage::Error {
                        message: "only a coordinator (network key holder) can grant admin"
                            .to_string(),
                    };
                }
                (h.network_key, key)
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            }
        };
        let Some(net_secret_key) = net_secret_key else {
            return IpcMessage::Error {
                message: "network key not available".to_string(),
            };
        };

        // The target must be a member of this network. Send the grant over the
        // *existing* mesh connection to that member (the one its control reader
        // is accept_bi-ing on from join time). Opening a fresh connection would
        // land the AdminGrant on the member's new-connection handler, which
        // expects a MeshHello first and silently drops anything else.
        let conn = self
            .peers
            .peers_for_network_with_conn(network)
            .into_iter()
            .find(|(id, _, _)| *id == identity)
            .map(|(_, _, c)| c)
            .ok_or_else(|| IpcMessage::Error {
                message: format!(
                    "could not find an active connection to {identity} on '{network}'"
                ),
            });
        let conn = match conn {
            Ok(c) => c,
            Err(e) => return e,
        };
        let grant = ControlMsg::AdminGrant {
            network_pubkey: net_pubkey,
            secret_key: net_secret_key.to_bytes(),
        };
        match conn.open_bi().await {
            Ok((mut send, _)) => match control::send_msg(&mut send, &grant).await {
                Ok(()) => {
                    // The grant connection is dropped when this handler returns;
                    // wait for the grantee to read it so it flushes first.
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                }
                Err(e) => {
                    return IpcMessage::Error {
                        message: format!("failed to send admin grant: {e}"),
                    };
                }
            },
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to open stream to {identity}: {e}"),
                };
            }
        }

        // Publish the grantee as a coordinator in the signed group blob so
        // joiners can discover co-coordinators to dial.
        {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut s = handle.state.write().unwrap();
            crate::membership::mark_coordinator(&mut s.members, &identity);
            s.refresh_snapshot();
        }
        self.store_and_publish_group(network).await;

        // Record the grant locally (coordinator's record; not verifiable).
        if let Ok(Some(mut net)) = config::load_network(network)
            && !net.admins.contains(&identity)
        {
            net.admins.push(identity);
            let _ = config::save_network(&net);
        }
        IpcMessage::Ok {
            message: format!("granted network key to {}", identity.fmt_short()),
        }
    }

    /// List this network's key-holders: the local node (if it holds the key) plus
    /// every identity it has granted the key to (`ray admin add`).
    pub(crate) fn admin_list(&self, network: &str) -> IpcMessage {
        let self_id = self.endpoint.id();
        let mut admins = Vec::new();
        let self_holds_key = match self.networks.get(network) {
            Some(h) => h.state.read().unwrap().network_secret_key.is_some(),
            None => false,
        };
        if self_holds_key {
            admins.push(ipc::AdminInfo {
                short_id: self_id.fmt_short().to_string(),
                self_node: true,
            });
        }
        if let Ok(cfg) = config::load()
            && let Some(net) = cfg.networks.iter().find(|n| n.name == network)
        {
            for id in &net.admins {
                admins.push(ipc::AdminInfo {
                    short_id: id.fmt_short().to_string(),
                    self_node: false,
                });
            }
        }
        if !self_holds_key && admins.is_empty() {
            return IpcMessage::Error {
                message: format!("network '{network}' not found or not a coordinator"),
            };
        }
        IpcMessage::AdminListResponse { admins }
    }

    // -----------------------------------------------------------------------
    // Direct connections (ray connect)
    // -----------------------------------------------------------------------
}
