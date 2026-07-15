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

/// How a member is named in `ray exit-node status`: its hostname, else a short id.
fn display_name(m: &Member) -> String {
    m.hostname
        .clone()
        .unwrap_or_else(|| m.identity.fmt_short().to_string())
}

impl NetworkRegistry {
    /// A network's roster, or empty if we don't have that network. Keeps the
    /// lookup-then-lock-then-clone dance (and the lock guard) out of the callers.
    fn roster(&self, network: &str) -> Vec<Member> {
        match self.networks.get(network) {
            // Cloned out (`NetworkState::roster`): callers must be free to work
            // (and to await) without holding the state lock.
            Some(handle) => handle.state.read().unwrap().roster(),
            None => Vec::new(),
        }
    }

    /// The roster member `id` names (see [`Member::matches_identity`]).
    fn roster_member(&self, network: &str, id: EndpointId) -> Option<Member> {
        self.roster(network)
            .into_iter()
            .find(|m| m.matches_identity(id))
    }

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
        // Not advertised from here: the roster flag must reflect a gateway that
        // actually forwards, so [`Self::sync_exit_offers`] publishes it only once
        // the reconcile has the kernel state in place (now if the daemon is up,
        // else on `ray up`). Advertising on config alone would let peers select a
        // gateway that blackholes them.
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
                let advertises = self
                    .roster_member(network, id)
                    .is_some_and(|m| m.exit_node);
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
    /// identity (to match its return traffic); it clears when the config selects
    /// nothing. There is one default route, so only one selection can win: a
    /// second one is reported rather than silently ignored. Cheap; called on
    /// `activate()` and after any `ray exit-node` change while up. Returns a
    /// user-facing warning when the state could not (yet) be made to match.
    pub(crate) fn reload_exit_state(&self) -> Option<String> {
        let networks = match config::load() {
            Ok(c) => c.networks,
            Err(e) => {
                // A transient read failure must not be taken for an empty config:
                // that would clear a live gateway's allow policy and tear down a
                // live full tunnel, leaking the traffic the user chose to route.
                tracing::warn!(error = %e, "config unreadable; exit-node state left as it was");
                return Some(format!("config unreadable, exit-node state left as it was: {e}"));
            }
        };
        self.exit_server.reload(
            networks
                .iter()
                .map(|n| (n.name.as_str(), n.exit_allow.as_slice())),
        );
        let selected: Vec<_> = networks
            .iter()
            .filter(|nc| nc.exit_node_use.is_some())
            .collect();
        if selected.len() > 1 {
            let names: Vec<&str> = selected.iter().map(|nc| nc.name.as_str()).collect();
            tracing::warn!(
                networks = ?names,
                "an exit node is selected on more than one network; only one is used \
                 (all traffic leaves through one default route). Clear the others with \
                 `ray exit-node none`.",
            );
        }
        // Note this does not require the peer to still advertise `exit_node`: a
        // roster that briefly loses the flag must not silently drop us back to
        // direct egress, leaking out our own uplink the traffic we chose to tunnel.
        let wanted = !selected.is_empty();
        let selection = selected.into_iter().find_map(|nc| {
            let id = nc.exit_node_use.as_ref()?.parse::<EndpointId>().ok()?;
            let member = self.roster_member(&nc.name, id)?;
            Some(ExitSelection {
                peer_user: self.device_user_map.resolve(&member.identity),
                ipv4: member.ip,
                network: SmolStr::new(&nc.name),
            })
        });
        // The same no-silent-fallback rule when the roster cannot resolve the
        // selected peer at all (boot before the first reconverge, or the peer
        // temporarily absent): keep whatever tunnel is in place rather than
        // dropping to direct egress, mark the selection pending, and let the
        // reconverge that lands the roster nudge a re-apply.
        if wanted && selection.is_none() {
            self.exit_selection_pending.store(true, Ordering::Relaxed);
            return Some(if self.exit_client.is_active() {
                "the selected exit peer is missing from the roster; keeping the \
                 existing tunnel until it reappears"
                    .to_string()
            } else {
                "the selected exit peer is not in the roster yet; the full tunnel \
                 will be installed when it appears"
                    .to_string()
            });
        }
        self.exit_selection_pending.store(false, Ordering::Relaxed);
        self.exit_client.set(selection);
        None
    }

    /// Reconcile the advertised `Member.exit_node` flag with what this node
    /// actually offers right now ([`ExitServer::is_offering`]: non-empty only
    /// while the data plane is up and the kernel state went in). Runs after every
    /// exit reconcile and after every reconverge, so each way the two can drift
    /// heals on the next pass: a coordinator rebuild that wiped the flag, an
    /// offer made while every coordinator was offline, a standby or failed
    /// gateway still advertising. Publishing only on mismatch keeps the steady
    /// state quiet. Gated on `exit_sync_enabled` so a reconverge that fires while
    /// the data plane is down does not withdraw an offer `activate()` is about to
    /// re-advertise.
    pub(crate) async fn sync_exit_offers(&self) {
        if !self.exit_sync_enabled.load(Ordering::Relaxed) {
            return;
        }
        let self_id = self.transport.endpoint.id();
        let user_id = self.device_user_map.resolve(&self_id);
        let names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        for name in names {
            let advertised = [self_id, user_id]
                .into_iter()
                .find_map(|id| self.roster_member(&name, id))
                .is_some_and(|m| m.exit_node);
            let offering = self.exit_server.is_offering(&name);
            if advertised != offering {
                self.publish_exit_offer(&name, offering).await;
            }
        }
    }

    /// Report exit-node state per network: this node's own allow list + selection,
    /// and which roster peers advertise an exit node.
    pub(crate) fn exit_node_status(&self, network: Option<String>) -> IpcMessage {
        let cfg = match config::load() {
            Ok(c) => c,
            Err(e) => return ipc_err(format!("failed to load config: {e}")),
        };
        let mut networks = Vec::new();
        for n in cfg.networks {
            if network.as_ref().is_some_and(|want| want != &n.name) {
                continue;
            }
            let available = self
                .roster(&n.name)
                .iter()
                .filter(|m| m.exit_node)
                .map(display_name)
                .collect();
            networks.push(ipc::ExitNodeStatusView {
                network: n.name,
                allow: n.exit_allow,
                using: n.exit_node_use,
                available,
            });
        }
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
