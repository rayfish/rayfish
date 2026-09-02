//! Firewall IPC handlers for [`Daemon`]: per-device firewall rules and
//! coordinator-suggested rules. Split out of `daemon/mod.rs`.

use super::super::*;

/// Persist firewall config to disk, logging (not failing) on a write error. The
/// in-memory `ArcSwap` already holds the new rules; a failed write only means
/// they won't survive a daemon restart.
fn save_firewall_warn(config: &firewall::FirewallConfig) {
    if let Err(e) = firewall::save_firewall(config) {
        tracing::warn!(error = %e, "failed to persist firewall config");
    }
}

impl NetworkRegistry {
    // -----------------------------------------------------------------------
    // Firewall handlers
    // -----------------------------------------------------------------------

    pub async fn firewall_add(
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
                    return ipc_err(e.to_string());
                }
            },
            None => vec![None],
        };
        // Resolve the peer to its **device** endpoint id (accepts hostname, mesh
        // IPv4/IPv6, short id, full endpoint id, or a paired user identity), then
        // normalize to the value the data plane actually compares against, which
        // differs by direction: inbound matches `device_user_map.resolve(...)`
        // (the peer's user identity for a paired/multi-device peer, else its
        // device id, so an `in` rule keyed on the user id matches every one of
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
                    return ipc_err(format!(
                        "unknown peer '{s}' (try a hostname, mesh IP, short id, or identity)"
                    ));
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
        save_firewall_warn(&config);
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

    pub fn firewall_remove(&self, index: usize) -> IpcMessage {
        let len = self.firewall.get_config().rules.len();
        if index >= len {
            return ipc_err(format!("index {index} out of range (have {len} rules)"));
        }
        self.edit_firewall(|c| {
            c.rules.remove(index);
        });
        IpcMessage::Ok {
            message: "rule removed".to_string(),
        }
    }

    pub fn firewall_show(&self) -> IpcMessage {
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
        self: &Arc<Self>,
        network: &str,
        suggestions: SuggestedFirewall,
    ) -> IpcMessage {
        let (state, dht_notify, has_key) = match self.networks.get(network) {
            Some(h) => {
                let has_key = h.state.read().unwrap().network_secret_key.is_some();
                (h.state.clone(), h.dht_notify.clone(), has_key)
            }
            None => {
                return ipc_err(format!("network '{network}' not found"));
            }
        };
        if !has_key {
            return ipc_err(
                "only a coordinator (network key holder) can suggest firewall rules".to_string(),
            );
        }
        let count: usize = suggestions.len();
        {
            let mut s = state.write().unwrap();
            s.suggested_firewall = suggestions;
        }
        update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await;
        // Nudge connected members to reconverge from the freshly-published signed
        // record now, instead of waiting for the group poller. Like the
        // rename flow, this is a payload-free trigger, the suggestions still come
        // exclusively from the network-key-signed blob, never from this message.
        let net_pubkey = state.read().unwrap().network_public_key;
        broadcast_member_sync(self, net_pubkey, network, None).await;
        // The coordinator is the blob's source, so the group poller's hash
        // check (local == published) short-circuits and it never re-applies its
        // own authored suggestions. Materialize them here so the coordinator is
        // subject to its own rules like any other member (auto-take or queue).
        apply_suggested_firewall(
            &self.firewall,
            self.transport.endpoint.id(),
            network,
            &state,
        );
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
            None => ipc_err(format!("network '{network}' not found")),
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
            None => ipc_err(format!("network '{network}' not found")),
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
                return ipc_err(format!("network '{network}' not found"));
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
            save_firewall_warn(&config);
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
                return ipc_err(format!("network '{network}' not found"));
            }
        };
        if rules.is_empty() {
            return ipc_err(format!("no pending suggested rules for '{network}'"));
        }
        let count = rules.len();
        let config = self.firewall.replace_network_rules(network, rules);
        save_firewall_warn(&config);
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
            None => ipc_err(format!("network '{network}' not found")),
        }
    }

    /// Re-materialize a network's coordinator-suggested rules under this node's
    /// current consent setting: with `net.auto-accept-firewall` on it installs
    /// the queued set, with it off it just (re)queues. Called after the setting
    /// is persisted so turning it on takes effect immediately rather than at the
    /// next suggestion.
    pub(crate) fn reapply_suggested_firewall(&self, network: &str) {
        if let Some(h) = self.networks.get(network) {
            apply_suggested_firewall(
                &self.firewall,
                self.transport.endpoint.id(),
                network,
                &h.state,
            );
        }
    }

    /// `ray firewall default allow|deny` flips the **inbound** default (the
    /// outbound default stays `Allow`, you always initiate freely). `allow`
    /// restores the old permissive inbound posture; `deny` is the secure default.
    /// Inbound ICMP-allow is a separate built-in default and is unaffected.
    pub fn firewall_default(&self, action: firewall::Action) -> IpcMessage {
        self.firewall_config_set(FirewallKey::DefaultIn, &action.to_string())
    }

    /// Read-modify-write the live firewall config: clone the current snapshot,
    /// apply `edit`, swap it into the lock-free `ArcSwap`, and persist (logging on
    /// write error). For infallible edits; [`Self::firewall_config_set`] spells
    /// the same sequence out because its edit can fail.
    fn edit_firewall(&self, edit: impl FnOnce(&mut firewall::FirewallConfig)) {
        let mut config = (*self.firewall.get_config()).clone();
        edit(&mut config);
        self.firewall.update(config.clone());
        save_firewall_warn(&config);
    }

    /// Apply one firewall settings key (`ray firewall on|off|reject|default`,
    /// or `ray config set firewall.*`).
    ///
    /// Hot-swaps rather than doing a load/mutate/save: the packet path reads the
    /// config from a lock-free `ArcSwap`, so the edit has to be swapped into it
    /// for `ray firewall off` to take effect now instead of at the next daemon
    /// restart. It repeats [`Self::edit_firewall`]'s sequence instead of calling
    /// it because `apply_firewall` can fail and that helper takes an infallible
    /// closure, so a rejected value must not reach the swap. Parsing and validation belong to
    /// the registry (`settings::apply_firewall`); this method owns the live swap,
    /// the persist, and the per-key confirmation message.
    pub(crate) fn firewall_config_set(&self, key: FirewallKey, value: &str) -> IpcMessage {
        let mut config = (*self.firewall.get_config()).clone();
        if let Err(e) = settings::apply_firewall(&mut config, key, value) {
            return ipc_err(e.to_string());
        }
        self.firewall.update(config.clone());
        save_firewall_warn(&config);
        IpcMessage::Ok {
            message: firewall_set_message(&config, key),
        }
    }

    /// Render one firewall settings key from the live config.
    pub(crate) fn firewall_config_get(&self, key: FirewallKey) -> IpcMessage {
        IpcMessage::ConfigValues {
            rows: self.firewall_config_rows(Some(key)),
        }
    }

    /// Firewall settings as `(key, value)` rows, read from the live config so a
    /// get agrees with what the packet path is enforcing. `None` renders every
    /// key, which is how the bare `ray config get` picks them up alongside the
    /// globals.
    pub(crate) fn firewall_config_rows(&self, key: Option<FirewallKey>) -> Vec<(String, String)> {
        let config = self.firewall.get_config();
        let keys: Vec<FirewallKey> = match key {
            Some(k) => vec![k],
            None => FirewallKey::ALL.to_vec(),
        };
        keys.into_iter()
            .map(|k| (k.name().to_string(), settings::render_firewall(&config, k)))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Mesh SSH (`ray firewall ssh ...`)
    // -----------------------------------------------------------------------
}

impl Daemon {
    // Thin delegates so the `ray-mobile` FFI (which can only reach public
    // Daemon methods, not the pub(crate) registry) keeps its firewall
    // surface. The logic lives on NetworkRegistry.
    pub async fn firewall_add(
        &self,
        direction: firewall::Direction,
        action: firewall::Action,
        protocol: firewall::Protocol,
        port: Option<&str>,
        peer: Option<&str>,
        network: Option<&str>,
    ) -> IpcMessage {
        self.registry
            .firewall_add(direction, action, protocol, port, peer, network)
            .await
    }

    pub fn firewall_remove(&self, index: usize) -> IpcMessage {
        self.registry.firewall_remove(index)
    }

    pub fn firewall_show(&self) -> IpcMessage {
        self.registry.firewall_show()
    }

    pub fn firewall_default(&self, action: firewall::Action) -> IpcMessage {
        self.registry.firewall_default(action)
    }

    /// Apply the `ssh` settings key (`ray firewall ssh on|off`, `ray config set
    /// ssh <on|off>`), which is more than a config write: it also seeds/removes
    /// the `allow in tcp:22` passthrough so SSH packets reach the listener under
    /// the deny-inbound default, and starts/stops the listeners if the data plane
    /// is active. The key is served here, not by the generic `config_apply` path,
    /// precisely so those side effects cannot be bypassed: `ssh_enabled` written
    /// on its own leaves the node advertising SSH with nothing listening.
    pub(crate) fn ssh_config_set(self: &Arc<Self>, value: &str) -> IpcMessage {
        // There is no Windows SSH server to start, so turning it on would write
        // `ssh_enabled = true` and open port 22 for a listener that never
        // arrives. Rejected before anything is persisted, so the config and the
        // firewall stay consistent with what the daemon can actually do.
        // `off` still goes through, so a config carried over from another
        // platform can be turned back off here.
        #[cfg(windows)]
        if settings::parse_bool(value, false).unwrap_or(false) {
            return ipc_err(
                "the embedded SSH server is not available on Windows; nothing was changed",
            );
        }
        // The registry parses and writes the field; everything below is the side
        // effects it deliberately does not do.
        let mut parse_err = None;
        let saved = config::update_settings(|cfg| {
            if let Err(e) = settings::apply_global(cfg, GlobalKey::Ssh, value, false) {
                parse_err = Some(e.to_string());
                anyhow::bail!("rejected");
            }
            Ok(())
        });
        if let Some(e) = parse_err {
            return ipc_err(e);
        }
        let app_config = match saved {
            Ok(cfg) => cfg,
            Err(e) => return ipc_err(format!("failed to persist ssh setting: {e}")),
        };
        let enabled = app_config.ssh_enabled;
        // Open/close port 22 at the packet layer; SSH-layer authz is the real gate.
        let fw = self.registry.firewall.set_ssh_passthrough(enabled);
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
        // Only the desktop build appends the host-firewall warning below.
        #[cfg_attr(not(feature = "desktop"), allow(unused_mut))]
        let mut message = if enabled && !has_allow {
            "mesh SSH on. No peer is authorized yet. Grant access with \
             `ray firewall ssh allow <network> <peer>` (peer = hostname / mesh IP / \
             short id, or `*` for any peer on the network)."
                .to_string()
        } else {
            format!("mesh SSH {}", if enabled { "on" } else { "off" })
        };
        // A host firewall that allows "22/tcp" does not allow the port mesh SSH
        // actually listens on, and the resulting failure looks like a network
        // problem rather than a firewall one. Say so here, where the operator is
        // already thinking about SSH access. The check only reads the ruleset.
        // Desktop-only: the embedded SSH server (and the port NAT it needs) is
        // not part of the Android library, so there is nothing to warn about.
        #[cfg(feature = "desktop")]
        if enabled
            && let Some(warning) = crate::hostfw::check_inbound_tcp(
                self.tun_name.load().as_str(),
                crate::forward::SSH_LISTEN_PORT,
            )
            .warning(crate::forward::SSH_LISTEN_PORT)
        {
            tracing::warn!("{warning}");
            message.push_str("\n\n");
            message.push_str(&warning);
        }
        IpcMessage::Ok { message }
    }

    /// Write the `pf-passthrough` setting and make the live pf anchor follow it.
    ///
    /// Its own setter for the same reason `v4-bridge` has one, with more at
    /// stake: a write that waited for the next restart would leave the mesh dead
    /// for the rest of the session on a host whose other VPN is already
    /// default-denying.
    pub(crate) fn pf_passthrough_config_set(self: &Arc<Self>, value: &str) -> IpcMessage {
        let mut parse_err = None;
        let saved = config::update_settings(|cfg| {
            if let Err(e) = settings::apply_global(cfg, GlobalKey::PfPassthrough, value, false) {
                parse_err = Some(e.to_string());
                anyhow::bail!("rejected");
            }
            Ok(())
        });
        if let Some(e) = parse_err {
            return ipc_err(e);
        }
        let enabled = match saved {
            Ok(cfg) => cfg.pf_passthrough,
            Err(e) => return ipc_err(format!("failed to persist pf-passthrough setting: {e}")),
        };
        // Reflect immediately if the data plane is up (else activate() loads it).
        #[cfg(all(target_os = "macos", feature = "desktop"))]
        if self.active.load(Ordering::SeqCst) {
            if enabled {
                let tun = self.tun_name.load().as_str().to_owned();
                if let Err(e) = crate::hostfw::install_tun_passthrough(&tun) {
                    return ipc_err(format!("failed to load the pf passthrough anchor: {e:#}"));
                }
            } else {
                crate::hostfw::remove_tun_passthrough();
            }
        }
        IpcMessage::Ok {
            message: format!(
                "pf passthrough {}. {}",
                if enabled { "on" } else { "off" },
                if enabled {
                    "Mesh traffic is passed ahead of any other VPN's pf ruleset, so the \
                     mesh keeps working while that VPN is connected. Nothing leaves this \
                     host in the clear: the rule matches the mesh interface only, and what \
                     the daemon sends on is still routed by the table that VPN owns."
                } else {
                    "Another VPN whose ruleset ends in a catch-all block will drop mesh \
                     traffic on this host while it is connected."
                }
            ),
        }
    }

    /// Write the `v4-bridge` setting and make the running bridge follow it.
    ///
    /// A plain config write would leave the listeners up until the next restart,
    /// which is the `ssh` bug in a second place, so this key gets its own setter
    /// for the same reason that one does.
    pub(crate) fn v4_bridge_config_set(self: &Arc<Self>, value: &str) -> IpcMessage {
        let mut parse_err = None;
        let saved = config::update_settings(|cfg| {
            if let Err(e) = settings::apply_global(cfg, GlobalKey::V4Bridge, value, false) {
                parse_err = Some(e.to_string());
                anyhow::bail!("rejected");
            }
            Ok(())
        });
        if let Some(e) = parse_err {
            return ipc_err(e);
        }
        let enabled = match saved {
            Ok(cfg) => cfg.v4_bridge,
            Err(e) => return ipc_err(format!("failed to persist v4-bridge setting: {e}")),
        };
        // Reflect immediately if the data plane is up (else activate() starts it).
        #[cfg(feature = "desktop")]
        if self.active.load(Ordering::SeqCst) {
            if enabled {
                self.start_v4_bridge();
            } else {
                self.stop_v4_bridge();
            }
        }
        IpcMessage::Ok {
            message: format!(
                "IPv4 listener bridge {}. {}",
                if enabled { "on" } else { "off" },
                if enabled {
                    "A service listening on 0.0.0.0 now answers at this node's mesh \
                     address, for the peers the firewall allows. Services bound to \
                     127.0.0.1 are not bridged."
                } else {
                    "Services that listen on IPv4 only are no longer reachable over \
                     the mesh."
                }
            ),
        }
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
        let ssh_enabled = match config::load() {
            Ok(c) => c.ssh_enabled,
            Err(e) => {
                return ipc_err(format!("failed to load config: {e}"));
            }
        };
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
                Some(id) => self.registry.device_user_map.resolve(&id).to_string(),
                None => {
                    return ipc_err(format!("could not resolve peer: {peer}"));
                }
            }
        };
        let net = match config::update_network(network, |net| {
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
            Ok(())
        }) {
            Ok(Some(net)) => net,
            Ok(None) => return ipc_err(format!("no such network: {network}")),
            Err(e) => return ipc_err(format!("failed to persist network config: {e}")),
        };
        // Push the change to any live listener.
        #[cfg(feature = "desktop")]
        self.rebuild_ssh_authz();
        let mut detail = if allow {
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
        // Mirror of the `ssh on` nudge: a rule with the server off looks like it
        // took effect, but `:22` still falls through to the host sshd (which
        // asks for a password), so the failure doesn't point back here.
        if allow && !ssh_enabled {
            detail.push_str(
                "\n\nmesh SSH is off, so this rule is not in effect yet. \
                 Start the server with `ray firewall ssh on`.",
            );
        }
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

/// The confirmation line for a firewall key, rendered from the config
/// as it stands after the write. Each key keeps the exact string its old handler
/// produced. Note the absence of the global keys' "Restart the daemon" clause:
/// these edits are live the moment the `ArcSwap` swap lands, so claiming
/// otherwise would be false.
fn firewall_set_message(config: &firewall::FirewallConfig, key: FirewallKey) -> String {
    match key {
        FirewallKey::Enabled if config.disabled => {
            "firewall off (all packets allowed on this device)".to_string()
        }
        FirewallKey::Enabled => "firewall on (enforcing rules and defaults)".to_string(),
        FirewallKey::Reject => format!(
            "fail-fast reject {}",
            if config.reject { "on" } else { "off" }
        ),
        FirewallKey::DefaultIn => format!("inbound default set to {}", config.default_inbound),
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

#[cfg(test)]
mod firewall_message_tests {
    use super::*;

    /// Pinned byte-for-byte: these strings used to live in `firewall_reject`,
    /// `firewall_set_enabled` and `firewall_default`, and the settings-registry
    /// migration was not allowed to change what the user reads. See the matching
    /// test in `daemon::confirmation_message_tests` for the global keys.
    fn disabled(v: bool) -> firewall::FirewallConfig {
        firewall::FirewallConfig {
            disabled: v,
            ..Default::default()
        }
    }

    fn reject(v: bool) -> firewall::FirewallConfig {
        firewall::FirewallConfig {
            reject: v,
            ..Default::default()
        }
    }

    fn default_in(v: firewall::Action) -> firewall::FirewallConfig {
        firewall::FirewallConfig {
            default_inbound: v,
            ..Default::default()
        }
    }

    #[test]
    fn firewall_keys_keep_the_exact_wording_their_handlers_printed() {
        assert_eq!(
            firewall_set_message(&disabled(false), FirewallKey::Enabled),
            "firewall on (enforcing rules and defaults)"
        );
        assert_eq!(
            firewall_set_message(&disabled(true), FirewallKey::Enabled),
            "firewall off (all packets allowed on this device)"
        );

        assert_eq!(
            firewall_set_message(&reject(true), FirewallKey::Reject),
            "fail-fast reject on"
        );
        assert_eq!(
            firewall_set_message(&reject(false), FirewallKey::Reject),
            "fail-fast reject off"
        );

        assert_eq!(
            firewall_set_message(&default_in(firewall::Action::Deny), FirewallKey::DefaultIn),
            "inbound default set to deny"
        );
        assert_eq!(
            firewall_set_message(&default_in(firewall::Action::Allow), FirewallKey::DefaultIn),
            "inbound default set to allow"
        );
    }

    /// A firewall edit hot-swaps the `ArcSwap` the packet path reads, so it is
    /// in force before the reply is written. Telling the user to restart would
    /// be false, and would also mask a regression back to load/mutate/save.
    #[test]
    fn firewall_messages_never_claim_a_restart_is_needed() {
        let fw = firewall::FirewallConfig::default();
        for &key in FirewallKey::ALL {
            let msg = firewall_set_message(&fw, key);
            assert!(!msg.contains("Restart"), "{key}: {msg}");
        }
    }
}

#[cfg(test)]
mod ssh_user_tests {
    use super::*;

    fn v(users: &[&str]) -> Vec<String> {
        users.iter().map(|s| s.to_string()).collect()
    }

    /// `*` means "any user, root included", so it must collapse the list
    /// rather than sit alongside named users: leaving both would let a later
    /// reader match on a name and miss that everything is already allowed.
    #[test]
    fn wildcard_collapses_the_list() {
        assert_eq!(normalize_ssh_users(v(&["alice", "*", "bob"])), v(&["*"]));
        assert_eq!(normalize_ssh_users(v(&["*"])), v(&["*"]));
        assert_eq!(normalize_ssh_users(v(&["*", "*"])), v(&["*"]));
    }

    /// An empty list is the secure default (any non-root user) and must not
    /// silently become a wildcard.
    #[test]
    fn empty_list_stays_empty() {
        assert!(normalize_ssh_users(Vec::new()).is_empty());
    }

    /// Sorted and deduped, so the same allow-list written in any order
    /// produces the same stored rule.
    #[test]
    fn named_users_are_sorted_and_deduped() {
        assert_eq!(
            normalize_ssh_users(v(&["carol", "alice", "bob", "alice"])),
            v(&["alice", "bob", "carol"]),
        );
    }

    /// A name that merely contains an asterisk is not the wildcard.
    #[test]
    fn only_a_bare_asterisk_is_the_wildcard() {
        let got = normalize_ssh_users(v(&["ro*t", "alice"]));
        assert_eq!(got, v(&["alice", "ro*t"]));
    }
}
