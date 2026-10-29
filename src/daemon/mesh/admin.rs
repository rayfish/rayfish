//! Admin (co-coordinator) handlers for `Daemon`: `admin_add` / `admin_list`.
//! Split out of `daemon/mod.rs`.

use super::super::*;

impl NetworkRegistry {
    /// Coordinator-only: grant the per-network secret key to a member over an
    /// authenticated mesh stream, making it a co-coordinator (can publish /
    /// suggest firewall rules). The key is shared (shared-key model), so this is
    /// a transfer of publish capability, not an attributable delegation. The
    /// grant is recorded locally for `ray admin list`.
    pub(crate) async fn admin_add(&self, network: &str, peer: &str) -> IpcMessage {
        let Some(identity) = self.resolve_peer_in_network(network, peer) else {
            return ipc_err(format!("could not resolve member '{peer}' on '{network}'"));
        };
        let (net_pubkey, net_secret_key) = match self.networks.get(network) {
            Some(h) => {
                let Some(key) = h.state.read().unwrap().network_secret_key.clone() else {
                    return ipc_err(
                        "only a coordinator (network key holder) can grant admin".to_string(),
                    );
                };
                (h.network_key, key)
            }
            None => {
                return ipc_err(format!("network '{network}' not active"));
            }
        };

        // A live connection proves the target participates in this network.
        let conn = self
            .peers
            .peers_for_network_with_conn(network)
            .into_iter()
            .find(|(id, _, _)| *id == identity)
            .map(|(_, _, c)| c)
            .ok_or_else(|| {
                ipc_err(format!(
                    "could not find an active connection to {identity} on '{network}'"
                ))
            });
        let conn = match conn {
            Ok(c) => c,
            Err(e) => return e,
        };
        if let Err(error) = send_admin_grant(&conn, net_pubkey, net_secret_key.to_bytes()).await {
            return ipc_err(format!(
                "admin grant to {} failed: {error:#}",
                identity.fmt_short()
            ));
        }

        // Publish the grantee as a coordinator in the signed group blob so
        // joiners can discover co-coordinators to dial.
        {
            let Some(handle) = self.networks.get(network) else {
                return ipc_err(format!("network '{network}' not active"));
            };
            let mut s = handle.state.write().unwrap();
            crate::membership::mark_coordinator(&mut s.members, &identity);
            s.refresh_snapshot();
        }
        self.store_and_publish_group(network).await;

        // Record the grant locally (coordinator's record; not verifiable).
        let saved = config::update_network(network, |net| {
            if !net.admins.contains(&identity) {
                net.admins.push(identity);
            }
            Ok(())
        });
        match saved {
            Ok(Some(_)) => {}
            Ok(None) => {
                return ipc_err(
                    "peer saved the network key, but the local network config was deleted"
                        .to_string(),
                );
            }
            Err(error) => {
                return ipc_err(format!(
                    "peer saved the network key, but recording the grant failed: {error}"
                ));
            }
        }
        IpcMessage::Ok {
            message: format!("granted network key to {}", identity.fmt_short()),
        }
    }

    /// List this network's key-holders: the local node (if it holds the key) plus
    /// every identity it has granted the key to (`ray admin add`).
    pub(crate) fn admin_list(&self, network: &str) -> IpcMessage {
        let self_id = self.transport.endpoint.id();
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
            return ipc_err(format!(
                "network '{network}' not found or not a coordinator"
            ));
        }
        IpcMessage::AdminListResponse { admins }
    }

    // -----------------------------------------------------------------------
    // Direct connections (ray connect)
    // -----------------------------------------------------------------------
}

/// A grant succeeds only after its recipient durably saves the key.
async fn send_admin_grant(
    conn: &Connection,
    network_pubkey: EndpointId,
    secret_key: [u8; 32],
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (mut send, mut recv) = conn.open_bi().await.context("open admin grant stream")?;
        control::send_msg(&mut send, Some(network_pubkey), &ControlMsg::AdminGrant {
            network_pubkey,
            secret_key,
        }).await.context("send admin grant")?;
        let response = control::recv_msg(&mut recv).await
            .context("peer did not acknowledge saving the admin grant (update the peer if it runs an older build)")?;
        match response {
            ControlMsg::AdminGrantResult { network_pubkey: received, error } => {
                anyhow::ensure!(received == network_pubkey, "admin grant reply names a different network");
                if let Some(error) = error {
                    anyhow::bail!("peer refused admin grant: {error}");
                }
                Ok(())
            }
            _ => anyhow::bail!("peer did not acknowledge the admin grant"),
        }
    }).await.context("timed out waiting for the peer to save the admin grant")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayMode;
    use iroh::endpoint::presets;

    async fn grant_reply(reply: Option<ControlMsg>) -> Result<()> {
        let alpn = transport::mesh_alpn();
        let recipient = Endpoint::builder(presets::N0)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let sender = Endpoint::builder(presets::N0)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let network_key = SecretKey::from([7; 32]);
        let expected_network = network_key.public();
        let accepting = {
            let recipient = recipient.clone();
            tokio::spawn(async move {
                let incoming = recipient.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = incoming.accept_bi().await.unwrap();
                assert!(matches!(
                    control::recv_msg(&mut recv).await.unwrap(),
                    ControlMsg::AdminGrant { .. }
                ));
                if let Some(reply) = reply {
                    control::send_msg(&mut send, Some(expected_network), &reply)
                        .await
                        .unwrap();
                }
                incoming
            })
        };
        let connection = sender.connect(recipient.addr(), &alpn).await.unwrap();
        let result =
            send_admin_grant(&connection, network_key.public(), network_key.to_bytes()).await;
        let _incoming = accepting.await.unwrap();
        sender.close().await;
        recipient.close().await;
        result
    }

    #[tokio::test]
    async fn admin_grant_requires_successful_persistence_reply() {
        let network_pubkey = SecretKey::from([7; 32]).public();
        grant_reply(Some(ControlMsg::AdminGrantResult {
            network_pubkey,
            error: None,
        }))
        .await
        .unwrap();
        let error = grant_reply(Some(ControlMsg::AdminGrantResult {
            network_pubkey,
            error: Some("could not save network key".into()),
        }))
        .await
        .unwrap_err();
        assert!(error.to_string().contains("could not save network key"));
    }

    #[tokio::test]
    async fn admin_grant_rejects_a_reply_for_another_network() {
        let error = grant_reply(Some(ControlMsg::AdminGrantResult {
            network_pubkey: SecretKey::from([8; 32]).public(),
            error: None,
        }))
        .await
        .unwrap_err();
        assert!(error.to_string().contains("different network"));
    }

    #[tokio::test]
    async fn admin_grant_without_an_acknowledgement_reports_failure() {
        let error = grant_reply(None).await.unwrap_err();
        assert!(error.to_string().contains("did not acknowledge"));
    }
}
