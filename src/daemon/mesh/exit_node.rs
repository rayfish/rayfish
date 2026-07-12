//! Exit-node control plane: `ray exit-node {allow,disallow,use,none,status}`.
//!
//! Two roles, both per-network and both stored in `NetworkConfig` (never on the
//! signed blob):
//!
//! - **Server** (`exit_allow`): the local allow-list of peers permitted to route
//!   internet-bound traffic out through this node. Non-empty means "I offer exit";
//!   the daemon advertises that offer to the coordinator set via
//!   [`ControlMsg::ExitNodeOffer`], which records `Member.exit_node` on the signed
//!   roster so peers can discover it. The allow-list itself stays local and is the
//!   real gate on forwarding (a false blob claim only wastes a dial).
//! - **Client** (`exit_node_use`): the exit peer this node routes all non-mesh
//!   traffic through. Set here; the data plane wiring happens on `ray up`.

use smol_str::SmolStr;

use super::super::*;
use crate::exit_node::ExitSelection;

impl NetworkRegistry {
    /// Add or remove a peer from a network's exit-node allow list, then advertise
    /// the resulting offer state (offering iff the list is non-empty). `peer` is
    /// `*` (any member) or a name/ip/id resolved to the peer's user identity.
    pub(crate) async fn exit_node_allow(
        &self,
        network: &str,
        peer: &str,
        allow: bool,
    ) -> IpcMessage {
        let mut app_config = match config::load() {
            Ok(c) => c,
            Err(e) => return ipc_err(format!("failed to load config: {e}")),
        };
        // Resolve to a stored allow-entry: `*` stays literal, otherwise the peer's
        // **user identity** hex, so a paired multi-device peer matches on any of
        // its devices (same normalization the SSH allow-list uses).
        let entry = if peer == "*" {
            "*".to_string()
        } else {
            match self.resolve_peer_flexible(peer).await {
                Some(id) => self.device_user_map.resolve(&id).to_string(),
                None => return ipc_err(format!("could not resolve peer: {peer}")),
            }
        };
        let Some(net) = app_config.networks.iter_mut().find(|n| n.name == network) else {
            return ipc_err(format!("no such network: {network}"));
        };
        if allow {
            if !net.exit_allow.iter().any(|p| p == &entry) {
                net.exit_allow.push(entry.clone());
            }
        } else {
            net.exit_allow.retain(|p| p != &entry);
        }
        let offering = !net.exit_allow.is_empty();
        let net = net.clone();
        if let Err(e) = config::save_network(&net) {
            return ipc_err(format!("failed to persist network config: {e}"));
        }
        self.publish_exit_offer(network, offering).await;
        let detail = if allow {
            format!(
                "exit-node allow {peer} on {network} (this node now offers exit; \
                 activate with `ray up`)"
            )
        } else if offering {
            format!("exit-node disallow {peer} on {network}")
        } else {
            format!("exit-node disallow {peer} on {network} (no peers left; offer withdrawn)")
        };
        IpcMessage::Ok { message: detail }
    }

    /// Select or clear the exit peer this node routes non-mesh traffic through.
    /// On select, the peer must be in the roster and advertise `exit_node`.
    pub(crate) async fn exit_node_use(&self, network: &str, peer: Option<String>) -> IpcMessage {
        let mut app_config = match config::load() {
            Ok(c) => c,
            Err(e) => return ipc_err(format!("failed to load config: {e}")),
        };
        // Validate the selection against the live roster before persisting.
        let selection = match &peer {
            Some(name) => {
                let Some(id) = self.resolve_peer_flexible(name).await else {
                    return ipc_err(format!("could not resolve peer: {name}"));
                };
                let advertises = self.networks.get(network).is_some_and(|h| {
                    let s = h.state.read().unwrap();
                    s.members
                        .all()
                        .iter()
                        .any(|m| m.identity == id && m.exit_node)
                });
                if !advertises {
                    return ipc_err(format!(
                        "{name} does not advertise an exit node on '{network}' \
                         (see `ray exit-node status`)"
                    ));
                }
                Some(id.to_string())
            }
            None => None,
        };
        let Some(net) = app_config.networks.iter_mut().find(|n| n.name == network) else {
            return ipc_err(format!("no such network: {network}"));
        };
        net.exit_node_use = selection;
        let net = net.clone();
        if let Err(e) = config::save_network(&net) {
            return ipc_err(format!("failed to persist network config: {e}"));
        }
        let message = match &peer {
            Some(name) => {
                format!("routing all traffic through {name} on {network} (activate with `ray up`)")
            }
            None => format!("direct egress restored on {network} (activate with `ray up`)"),
        };
        IpcMessage::Ok { message }
    }

    /// Rebuild both halves of the runtime exit-node state from the on-disk config:
    /// the gateway allow policy the inbound data path enforces
    /// (`forward::evaluate_inbound`), and this node's own exit selection.
    ///
    /// The selection is the first network with `exit_node_use` set whose peer is a
    /// resolvable roster member, resolved to its mesh IPv4 (to route to) and user
    /// identity (to match its return traffic); it clears when none applies. Cheap;
    /// called on `activate()` and after any `ray exit-node` change while up.
    pub(crate) fn reload_exit_state(&self) {
        let networks = config::load().map(|c| c.networks).unwrap_or_default();
        self.exit_server.reload(
            networks
                .iter()
                .map(|n| (n.name.as_str(), n.exit_allow.as_slice())),
        );
        let selection = networks.iter().find_map(|nc| {
            let id = nc.exit_node_use.as_ref()?.parse::<EndpointId>().ok()?;
            let handle = self.networks.get(&nc.name)?;
            let s = handle.state.read().unwrap();
            let member = s
                .members
                .all()
                .into_iter()
                .find(|m| m.identity == id || m.user_identity == Some(id))?;
            Some(ExitSelection {
                peer_user: self.device_user_map.resolve(&member.identity),
                ipv4: member.ip,
                network: SmolStr::new(&nc.name),
            })
        });
        self.exit_client.set(selection);
    }

    /// Report exit-node state per network: this node's own allow list + selection,
    /// and which roster peers advertise an exit node.
    pub(crate) fn exit_node_status(&self, network: Option<String>) -> IpcMessage {
        let cfg = match config::load() {
            Ok(c) => c,
            Err(e) => return ipc_err(format!("failed to load config: {e}")),
        };
        let networks = cfg
            .networks
            .into_iter()
            .filter(|n| network.as_ref().is_none_or(|want| &n.name == want))
            .map(|n| {
                let available = self
                    .networks
                    .get(&n.name)
                    .map(|h| {
                        let s = h.state.read().unwrap();
                        s.members
                            .all()
                            .iter()
                            .filter(|m| m.exit_node)
                            .map(|m| {
                                m.hostname
                                    .clone()
                                    .unwrap_or_else(|| m.identity.fmt_short().to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                ipc::ExitNodeStatusView {
                    network: n.name,
                    allow: n.exit_allow,
                    using: n.exit_node_use,
                    available,
                }
            })
            .collect();
        IpcMessage::ExitNodeState { networks }
    }

    /// Advertise this node's exit-node offer to the network. If we hold the
    /// network key we record it on our own roster entry and republish the signed
    /// blob directly; either way we broadcast [`ControlMsg::ExitNodeOffer`] so any
    /// online coordinator records it. If no coordinator is reachable the offer is
    /// simply not yet visible to peers, and re-advertises on the next change.
    async fn publish_exit_offer(&self, network: &str, enabled: bool) {
        let self_id = self.transport.endpoint.id();
        let (net_pubkey, is_coordinator) = match self.networks.get(network) {
            Some(h) => {
                let s = h.state.read().unwrap();
                (s.network_public_key, s.network_secret_key.is_some())
            }
            None => return,
        };
        if is_coordinator {
            self.record_exit_offer(network, self_id, enabled).await;
        }
        broadcast_control_msg(
            &self.peers,
            net_pubkey,
            network,
            &ControlMsg::ExitNodeOffer { enabled },
        )
        .await;
    }

    /// Coordinator side: record a member's exit-node offer on its signed roster
    /// entry and republish. `sender` is the offering peer's transport id; it is
    /// normalized to the roster identity (device or paired user) before matching.
    /// No-op if we do not hold the network key or the sender is not a member.
    pub(crate) async fn record_exit_offer(&self, network: &str, sender: EndpointId, enabled: bool) {
        let user_id = self.device_user_map.resolve(&sender);
        let changed = match self.networks.get(network) {
            Some(h) => {
                let mut s = h.state.write().unwrap();
                if s.network_secret_key.is_none() {
                    return;
                }
                // The roster keys a member by its own identity, which for a paired
                // multi-device peer is the user identity rather than the device id
                // the datagram arrived under. Try both.
                let Some(id) = [sender, user_id]
                    .into_iter()
                    .find(|id| s.members.get(id).is_some())
                else {
                    return;
                };
                match s.members.get_mut(&id) {
                    Some(member) if member.exit_node != enabled => {
                        member.exit_node = enabled;
                        s.refresh_snapshot();
                        true
                    }
                    _ => false,
                }
            }
            None => return,
        };
        if changed {
            self.store_and_publish_group(network).await;
        }
    }
}
