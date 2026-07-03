//! Firewall IPC handlers for [`DaemonState`]: per-device firewall rules and
//! coordinator-suggested rules. Split out of `daemon/mod.rs`.

use super::super::*;

impl DaemonState {
    // -----------------------------------------------------------------------
    // Firewall handlers
    // -----------------------------------------------------------------------

    pub(crate) async fn firewall_add(
        &self,
        direction: firewall::Direction,
        action: firewall::Action,
        protocol: firewall::Protocol,
        port: Option<&str>,
        peer: Option<&str>,
        network: Option<&str>,
    ) -> IpcMessage {
        // A port spec may be a comma-separated list (e.g. `80,443` or
        // `22,8000-9000`): each item is its own range and becomes its own rule,
        // since a FirewallRule carries a single contiguous PortRange. `None` (no
        // --port) yields a single port-agnostic rule.
        let ports: Vec<Option<firewall::PortRange>> = match port {
            Some(s) => match firewall::parse_port_list(s) {
                Ok(ranges) => ranges.into_iter().map(Some).collect(),
                Err(e) => {
                    return IpcMessage::Error {
                        message: e.to_string(),
                    };
                }
            },
            None => vec![None],
        };
        // Resolve the peer to its **device** endpoint id (accepts hostname, mesh
        // IPv4/IPv6, short id, full endpoint id, or a paired user identity), then
        // normalize to the value the data plane actually compares against, which
        // differs by direction: inbound matches `device_user_map.resolve(...)`
        // (the peer's user identity for a paired/multi-device peer, else its
        // device id — so an `in` rule keyed on the user id matches every one of
        // that user's devices), while outbound matches the raw device id. Same
        // reasoning as the SSH-allow handler below.
        let peer = match peer {
            Some(s) => match self.resolve_peer_flexible(s).await {
                Some(device_id) => {
                    let id = match direction {
                        firewall::Direction::In => self.device_user_map.resolve(&device_id),
                        firewall::Direction::Out => device_id,
                    };
                    firewall::PeerFilter::Identity(id)
                }
                None => {
                    return IpcMessage::Error {
                        message: format!(
                            "unknown peer '{s}' (try a hostname, mesh IP, short id, or identity)"
                        ),
                    };
                }
            },
            None => firewall::PeerFilter::Any,
        };

        // The `network` field is a match filter, not a reference that must
        // resolve now: a rule scoped to a network this node hasn't joined yet
        // (or has temporarily left) is kept and simply never matches until the
        // node is on that network. We only warn on an unknown name so typos
        // are still surfaced without rejecting the rule.
        let unknown_network = network.filter(|net| !self.networks.contains_key(*net));
        if let Some(net) = unknown_network {
            tracing::warn!(network = %net, "firewall rule scoped to a network this node is not on");
        }
        let mut config = (*self.firewall.get_config()).clone();
        for port in ports.iter().cloned() {
            let rule = firewall::FirewallRule {
                direction,
                action,
                protocol,
                port,
                peer: peer.clone(),
                network: network.map(str::to_string),
                origin: firewall::RuleOrigin::Local,
            };
            // A new rule supersedes a contradicting one with the *same selector*
            // (direction/proto/port/peer/network, ignoring action): drop the old
            // entry, then insert at the front so it wins under first-match. So
            // `deny in icmp` after the seeded `allow in icmp` makes deny prevail
            // (and re-adding `allow` flips it back) without leaving dead rules. A
            // narrower selector (e.g. `deny in icmp --peer X`) keeps the broader
            // rule and just layers ahead of it. With a comma list each range
            // inserts at the front, so they end up in reverse spec order; order
            // doesn't matter between same-action rules that differ only by port.
            config.rules.retain(|r| !firewall::same_selector(r, &rule));
            config.rules.insert(0, rule);
        }
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        let count = ports.len();
        let plural = if count == 1 { "rule" } else { "rules" };
        let message = match unknown_network {
            Some(net) => {
                format!("{count} {plural} added (note: not currently on network '{net}')")
            }
            None => format!("{count} {plural} added"),
        };
        IpcMessage::Ok { message }
    }

    pub(crate) fn firewall_remove(&self, index: usize) -> IpcMessage {
        let current = self.firewall.get_config();
        if index >= current.rules.len() {
            return IpcMessage::Error {
                message: format!(
                    "index {index} out of range (have {} rules)",
                    current.rules.len()
                ),
            };
        }
        let mut config = (*current).clone();
        config.rules.remove(index);
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: "rule removed".to_string(),
        }
    }

    pub(crate) fn firewall_show(&self) -> IpcMessage {
        let config = self.firewall.get_config();
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        IpcMessage::FirewallState {
            default_inbound: config.default_inbound,
            default_outbound: config.default_outbound,
            reject: config.reject,
            disabled: config.disabled,
            rules: firewall::rule_views(&config.rules, &short_id),
        }
    }

    /// Coordinator-only: replace a network's suggested firewall rules and
    /// republish the signed blob. Authority comes from holding the per-network
    /// secret key (so any admin granted the key can suggest). Suggestions are
    /// advisory on every network; each node queues or auto-accepts them.
    pub(crate) async fn firewall_suggest(
        &self,
        network: &str,
        suggestions: SuggestedFirewall,
    ) -> IpcMessage {
        let (state, dht_notify, has_key) = match self.networks.get(network) {
            Some(h) => {
                let has_key = h.state.read().unwrap().network_secret_key.is_some();
                (h.state.clone(), h.dht_notify.clone(), has_key)
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
        };
        if !has_key {
            return IpcMessage::Error {
                message: "only a coordinator (network key holder) can suggest firewall rules"
                    .to_string(),
            };
        }
        let count: usize = suggestions.len();
        {
            let mut s = state.write().unwrap();
            s.suggested_firewall = suggestions;
        }
        update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
        // Nudge connected members to reconverge from the freshly-published signed
        // record now, instead of waiting up to 60s for the group poller. Like the
        // rename flow, this is a payload-free trigger — the suggestions still come
        // exclusively from the network-key-signed blob, never from this message.
        broadcast_member_sync(&self.peers, None).await;
        // The coordinator is the blob's source, so the group poller's hash
        // check (local == published) short-circuits and it never re-applies its
        // own authored suggestions. Materialize them here so the coordinator is
        // subject to its own rules like any other member (auto-take or queue).
        apply_suggested_firewall(&self.firewall, self.endpoint.id(), network, &state);
        IpcMessage::Ok {
            message: format!("published firewall suggestions for '{network}' ({count} subjects)"),
        }
    }

    pub(crate) fn firewall_suggestions(&self, network: &str) -> IpcMessage {
        match self.networks.get(network) {
            Some(h) => {
                let suggestions = h.state.read().unwrap().suggested_firewall.clone();
                IpcMessage::FirewallSuggestionsResponse { suggestions }
            }
            None => IpcMessage::Error {
                message: format!("network '{network}' not found"),
            },
        }
    }

    /// Materialized suggested rules awaiting manual review (`ray firewall
    /// pending`). Returns the rules as structured views; the CLI renders them as
    /// an interactive picker on a TTY or a static table otherwise.
    pub(crate) fn firewall_pending(&self, network: &str) -> IpcMessage {
        match self.networks.get(network) {
            Some(h) => {
                let pending = h.state.read().unwrap().pending_suggestions.clone();
                let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
                IpcMessage::FirewallPendingResponse {
                    network: network.to_string(),
                    rules: firewall::rule_views(&pending, &short_id),
                }
            }
            None => IpcMessage::Error {
                message: format!("network '{network}' not found"),
            },
        }
    }

    /// Resolve individual queued suggestions from the interactive picker: install
    /// the rules whose view is in `accept`, drop both `accept`+`deny` from the
    /// queue, and persist. Matching is by view value so it's robust to queue
    /// reordering between fetch and resolve.
    pub(crate) fn firewall_resolve_suggestions(
        &self,
        network: &str,
        accept: &[FirewallRuleView],
        deny: &[FirewallRuleView],
    ) -> IpcMessage {
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let h = match self.networks.get(network) {
            Some(h) => h,
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
        };
        let accept_set: HashSet<&FirewallRuleView> = accept.iter().collect();
        let deny_set: HashSet<&FirewallRuleView> = deny.iter().collect();

        // Partition the queue: keep the still-undecided rules; collect accepted.
        let mut accepted_rules = Vec::new();
        {
            let mut s = h.state.write().unwrap();
            let mut remaining = Vec::new();
            for rule in std::mem::take(&mut s.pending_suggestions) {
                let view = firewall::rule_view(&rule, &short_id);
                if accept_set.contains(&view) {
                    accepted_rules.push(rule);
                } else if deny_set.contains(&view) {
                    // dropped
                } else {
                    remaining.push(rule);
                }
            }
            s.pending_suggestions = remaining;
        }

        let n_accept = accepted_rules.len();
        let n_deny = deny.len();
        if !accepted_rules.is_empty() {
            // Merge accepted rules into the network's existing installed set,
            // rather than replacing it, so earlier per-rule accepts survive.
            let mut existing: Vec<firewall::FirewallRule> = self
                .firewall
                .get_config()
                .rules
                .iter()
                .filter(|r| matches!(&r.origin, firewall::RuleOrigin::Network(n) if n == network))
                .cloned()
                .collect();
            existing.extend(accepted_rules);
            // Dedup by selector, newest (accepted) wins, so accepting a rule
            // whose selector is already installed replaces it instead of stacking
            // a duplicate (and a re-suggested action flip supersedes the old one).
            let deduped = firewall::dedup_by_selector(existing);
            let config = self.firewall.replace_network_rules(network, deduped);
            if let Err(e) = firewall::save_firewall(&config) {
                tracing::warn!(error = %e, "failed to persist firewall config");
            }
        }
        IpcMessage::Ok {
            message: format!(
                "accepted {n_accept}, denied {n_deny} suggested rules for '{network}'"
            ),
        }
    }

    /// Accept the queued suggested rules for a network: install them (replacing
    /// the prior `Network(net)` set), persist, and clear the queue.
    pub(crate) fn firewall_accept(&self, network: &str) -> IpcMessage {
        let rules = match self.networks.get(network) {
            Some(h) => {
                let mut s = h.state.write().unwrap();
                std::mem::take(&mut s.pending_suggestions)
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found"),
                };
            }
        };
        if rules.is_empty() {
            return IpcMessage::Error {
                message: format!("no pending suggested rules for '{network}'"),
            };
        }
        let count = rules.len();
        let config = self.firewall.replace_network_rules(network, rules);
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: format!("accepted {count} suggested rules from '{network}'"),
        }
    }

    /// Discard the queued suggested rules for a network without installing them.
    pub(crate) fn firewall_deny(&self, network: &str) -> IpcMessage {
        match self.networks.get(network) {
            Some(h) => {
                let mut s = h.state.write().unwrap();
                let count = s.pending_suggestions.len();
                s.pending_suggestions.clear();
                IpcMessage::Ok {
                    message: format!("discarded {count} pending suggested rules for '{network}'"),
                }
            }
            None => IpcMessage::Error {
                message: format!("network '{network}' not found"),
            },
        }
    }

    /// Toggle this node's per-network auto-accept of coordinator-suggested
    /// firewall rules (persisted in config). Turning it on immediately
    /// re-materializes and installs the current suggestions; turning it off
    /// leaves already-installed rules in place but stops future auto-install.
    pub(crate) fn firewall_auto_accept(&self, network: &str, enabled: bool) -> IpcMessage {
        if !self.networks.contains_key(network) {
            return IpcMessage::Error {
                message: format!("network '{network}' not found"),
            };
        }
        // Persist the per-network flag.
        match config::load_network(network) {
            Ok(Some(mut nc)) => {
                nc.auto_accept_firewall = enabled;
                if let Err(e) = config::save_network(&nc) {
                    return IpcMessage::Error {
                        message: format!("failed to persist auto-accept setting: {e}"),
                    };
                }
            }
            Ok(None) => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found in config"),
                };
            }
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        }
        // Re-apply suggestions with the new consent setting. With auto-accept on
        // this installs the queued set; with it off it just (re)queues.
        if let Some(h) = self.networks.get(network) {
            apply_suggested_firewall(&self.firewall, self.endpoint.id(), network, &h.state);
        }
        IpcMessage::Ok {
            message: format!(
                "auto-accept firewall suggestions {} for '{network}'",
                if enabled { "enabled" } else { "disabled" }
            ),
        }
    }

    /// `ray firewall default allow|deny` flips the **inbound** default (the
    /// outbound default stays `Allow` — you always initiate freely). `allow`
    /// restores the old permissive inbound posture; `deny` is the secure default.
    /// Inbound ICMP-allow is a separate built-in default and is unaffected.
    pub(crate) fn firewall_default(&self, action: firewall::Action) -> IpcMessage {
        let mut config = (*self.firewall.get_config()).clone();
        config.default_inbound = action;
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: format!("inbound default set to {action}"),
        }
    }

    pub(crate) fn firewall_reject(&self, enabled: bool) -> IpcMessage {
        let mut config = (*self.firewall.get_config()).clone();
        config.reject = enabled;
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: format!("fail-fast reject {}", if enabled { "on" } else { "off" }),
        }
    }

    /// `ray firewall on|off`: the global kill switch. `off` sets
    /// `config.disabled = true` so `evaluate_packet` allows every packet
    /// (rules and defaults are bypassed; the anti-spoof check upstream still
    /// runs). Hot-swaps the live `ArcSwap`, so the effect is immediate.
    pub(crate) fn firewall_set_enabled(&self, enabled: bool) -> IpcMessage {
        let mut config = (*self.firewall.get_config()).clone();
        config.disabled = !enabled;
        self.firewall.update(config.clone());
        if let Err(e) = firewall::save_firewall(&config) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        IpcMessage::Ok {
            message: if enabled {
                "firewall on (enforcing rules and defaults)".to_string()
            } else {
                "firewall off (all packets allowed on this device)".to_string()
            },
        }
    }

    // -----------------------------------------------------------------------
    // Mesh SSH (`ray firewall ssh ...`)
    // -----------------------------------------------------------------------

    /// Toggle the embedded mesh SSH server. Persists `ssh_enabled`, seeds/removes
    /// the `allow in tcp:22` passthrough so SSH packets reach the listener under
    /// the deny-inbound default, and starts/stops the listeners if the data plane
    /// is active.
    pub(crate) fn firewall_ssh_set(self: &Arc<Self>, enabled: bool) -> IpcMessage {
        let mut app_config = match config::load() {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        };
        app_config.ssh_enabled = enabled;
        if let Err(e) = config::save_settings(&app_config) {
            return IpcMessage::Error {
                message: format!("failed to persist ssh setting: {e}"),
            };
        }
        // Open/close port 22 at the packet layer; SSH-layer authz is the real gate.
        let fw = self.firewall.set_ssh_passthrough(enabled);
        if let Err(e) = firewall::save_firewall(&fw) {
            tracing::warn!(error = %e, "failed to persist firewall config");
        }
        // Reflect immediately if the data plane is up (else activate() starts it).
        #[cfg(feature = "desktop")]
        if self.active.load(Ordering::SeqCst) {
            if enabled {
                self.start_ssh();
            } else {
                self.stop_ssh();
            }
        }
        // Nudge: enabling the server does nothing until a peer is authorized. If
        // no network has any `ssh_allow` entry yet, tell the user the next step.
        let has_allow = app_config.networks.iter().any(|n| !n.ssh_allow.is_empty());
        let message = if enabled && !has_allow {
            "mesh SSH on. No peer is authorized yet. Grant access with \
             `ray firewall ssh allow <network> <peer>` (peer = hostname / mesh IP / \
             short id, or `*` for any peer on the network)."
                .to_string()
        } else {
            format!("mesh SSH {}", if enabled { "on" } else { "off" })
        };
        IpcMessage::Ok { message }
    }

    /// Add or remove a peer from a network's SSH allow list. `peer` is `*` (any
    /// peer on the network) or a name/ip/short-id resolved to a user identity.
    /// On allow, `users` is the set of local accounts the peer may log in as
    /// (empty = any non-root user; `"*"` = any incl. root) and **replaces** the
    /// peer's prior users. On deny, the peer's rule is dropped (`users` ignored).
    pub(crate) async fn firewall_ssh_allow(
        &self,
        network: &str,
        peer: &str,
        users: Vec<String>,
        allow: bool,
    ) -> IpcMessage {
        let mut app_config = match config::load() {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        };
        if !app_config.networks.iter().any(|n| n.name == network) {
            return IpcMessage::Error {
                message: format!("no such network: {network}"),
            };
        }
        // Resolve the peer to a stored allow-entry: `*` stays literal, otherwise
        // resolve to the peer's **user identity** hex. `resolve_peer_name` may
        // return a transport endpoint id (for a connected peer) which differs
        // from the user identity for a paired/multi-device peer; the SSH server
        // authorizes by user identity (`device_user_map.resolve`), so normalize
        // through the same map here. For an unmapped id this is a no-op.
        let entry = if peer == "*" {
            "*".to_string()
        } else {
            match self.resolve_peer_name(peer).await {
                Some(id) => self.device_user_map.resolve(&id).to_string(),
                None => {
                    return IpcMessage::Error {
                        message: format!("could not resolve peer: {peer}"),
                    };
                }
            }
        };
        let net = app_config
            .networks
            .iter_mut()
            .find(|n| n.name == network)
            .expect("network presence checked above");
        if allow {
            // Normalize: a `*` collapses the list to just `*` (any incl. root);
            // otherwise dedupe. Empty = the non-root default.
            let users = normalize_ssh_users(users);
            match net.ssh_allow.iter_mut().find(|r| r.peer == entry) {
                Some(r) => r.users = users,
                None => net.ssh_allow.push(config::SshRule {
                    peer: entry.clone(),
                    users,
                }),
            }
        } else {
            net.ssh_allow.retain(|r| r.peer != entry);
        }
        let net = net.clone();
        if let Err(e) = config::save_network(&net) {
            return IpcMessage::Error {
                message: format!("failed to persist network config: {e}"),
            };
        }
        // Push the change to any live listener.
        #[cfg(feature = "desktop")]
        self.rebuild_ssh_authz();
        let detail = if allow {
            let r = net.ssh_allow.iter().find(|r| r.peer == entry);
            let as_users = match r.map(|r| r.users.as_slice()) {
                Some([]) | None => " as any non-root user".to_string(),
                Some(u) if u.iter().any(|x| x == "*") => " as any user".to_string(),
                Some(u) => format!(" as {}", u.join(",")),
            };
            format!("ssh allow {peer} on {network}{as_users}")
        } else {
            format!("ssh deny {peer} on {network}")
        };
        IpcMessage::Ok { message: detail }
    }

    /// Report the SSH server state + per-network allow lists.
    pub(crate) fn firewall_ssh_show(&self) -> IpcMessage {
        let (enabled, networks) = match config::load() {
            Ok(c) => (
                c.ssh_enabled,
                c.networks
                    .into_iter()
                    .filter(|n| !n.ssh_allow.is_empty())
                    .map(|n| {
                        let allow = n
                            .ssh_allow
                            .into_iter()
                            .map(|r| ray_proto::ipc::SshAllowView {
                                peer: r.peer,
                                users: r.users,
                            })
                            .collect();
                        (n.name, allow)
                    })
                    .collect(),
            ),
            Err(_) => (false, Vec::new()),
        };
        IpcMessage::FirewallSshState { enabled, networks }
    }
}

/// Normalize an SSH allow rule's user list: a `*` (any user incl. root) collapses
/// the whole list to just `*`; otherwise sort + dedupe. An empty list is left
/// empty, meaning "any non-root user" (the secure default).
fn normalize_ssh_users(mut users: Vec<String>) -> Vec<String> {
    if users.iter().any(|u| u == "*") {
        return vec!["*".to_string()];
    }
    users.sort();
    users.dedup();
    users
}
