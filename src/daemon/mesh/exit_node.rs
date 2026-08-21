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

/// Why this node cannot route through `member`, or `None` when it can. `member`
/// is `None` when the roster does not list the peer at all.
///
/// Two refusals, both about a gateway that would take our traffic and drop it.
/// The first is the long-standing one: a peer that does not advertise an exit
/// node has no allow-list entry for us and would refuse every packet. The second
/// is the family gate: the tunnel carries IPv6 alone, so a gateway with no IPv6
/// uplink has nothing to masquerade onto and would black-hole us in silence. Both
/// are cheaper to say here than to diagnose from a dead tunnel.
fn gateway_refusal(member: Option<&Member>, name: &str, network: &str) -> Option<String> {
    match member {
        None
        | Some(Member {
            exit_node: false, ..
        }) => Some(format!(
            "{name} does not advertise an exit node on '{network}' \
             (see `ray exit-node status`)"
        )),
        Some(m) => ipv6_gateway_refusal(m, name),
    }
}

/// The family half of [`gateway_refusal`], on its own because the two halves have
/// different lifetimes. "Does not advertise an exit node" is a roster fact that
/// flickers (a coordinator rebuild, a gateway mid-restart) and must not drop a
/// live tunnel, so it is only ever checked when the user picks. This one is a
/// standing property of the pair: while it holds, the tunnel carries nothing, so
/// it is re-checked on every re-apply as well.
///
/// Refuses only when the tunnel would carry *nothing*
/// ([`ExitFamilies::tunnelled`] is [`ExitFamilies::Neither`]). A gateway claiming
/// IPv4 as well is not refused: the tunnel narrows to IPv6 and the host's IPv4
/// leaves directly, which is what it did before the tunnel existed.
///
/// [`ExitFamilies::Unknown`] never refuses, because `tunnelled` reads it as "can
/// carry": it is what a coordinator on a release that predates the field leaves
/// behind, and treating silence as denial would make exit nodes unusable on every
/// such network. Allowing it can be wrong, but wrongly is the direction that
/// fails loudly (the user chose this gateway, sees no internet, and clears it),
/// while the silent black hole this exists to prevent is a gateway confidently
/// marked usable. The caller warns instead, so the reason is in the log before the
/// traffic stops.
fn ipv6_gateway_refusal(m: &Member, name: &str) -> Option<String> {
    if m.exit_families.tunnelled() != ExitFamilies::Neither {
        return None;
    }
    Some(format!(
        "{name} offers an exit node but cannot carry IPv6, which is the only family \
         the mesh routes, so nothing would reach the internet through it. Pick a \
         gateway shown as (IPv6) in `ray exit-node status`, or give that host an \
         IPv6 uplink."
    ))
}

/// Whether selecting `m` as a gateway is a guess: it offers an exit node, we need
/// IPv6 out of it, and nothing on the roster says whether it has any. Distinct
/// from [`ipv6_gateway_refusal`], which answers a claim that was actually made.
///
/// Fires on any unclaimed gateway: every tunnel needs IPv6 out of it now, so a
/// roster that says nothing about a gateway's uplink is a roster we are guessing
/// against. That includes every network whose coordinator predates the field.
fn ipv6_gateway_unverified(m: &Member) -> bool {
    m.exit_node && m.exit_families.is_unknown()
}

/// The reason half of [`NetworkRegistry::exit_selection_problem`], pure so the
/// wording of each case is pinned by a test rather than by a running daemon.
///
/// Ordered by what the user can act on, with the kernel's answer ahead of the
/// config's. The refusal is last of the specific ones
/// because it is the only one that is not a wait: down and not-yet-in-the-roster
/// both heal on their own, while a gateway that cannot carry our family stays
/// that way until something changes on one of the two hosts.
fn selection_problem(
    install_error: Option<&str>,
    selection_resolved: bool,
    data_plane_up: bool,
    member: Option<&Member>,
) -> Option<String> {
    // First, because a failed install leaves the selection resolved: it rolled
    // its own rules back and the next re-apply will retry, so the config is
    // still what the user wants and nothing is carrying traffic meanwhile.
    if let Some(e) = install_error {
        return Some(format!("the tunnel could not be installed: {e}"));
    }
    if selection_resolved {
        return None;
    }
    if !data_plane_up {
        return Some("the data plane is down (`ray up`)".to_string());
    }
    let Some(member) = member else {
        return Some("the peer is not in this network's roster".to_string());
    };
    ipv6_gateway_refusal(member, &display_name(member)).or(Some(
        "the full tunnel is not installed; see the daemon log".to_string(),
    ))
}

/// Whether the roster's record of our own exit offer disagrees with what we
/// would publish right now. Split out from
/// [`NetworkRegistry::exit_offer_out_of_sync`] because it is the whole decision,
/// and reaching that method needs a live registry.
///
/// `advertised` is `(exit_node, exit_families)` as the signed roster holds it;
/// `claimed` is what we would send. The families are compared only while the
/// offer stands, and an [`ExitFamilies::Unknown`] on the roster compares equal to
/// anything; both exemptions exist because this gates a 30-second backstop tick
/// that reconverges (a pkarr resolve, plus a re-delivery to every coordinator)
/// each time it says yes, so a comparison that cannot balance is not a missing
/// feature but a permanent loop.
fn offer_disagrees(
    advertised: (bool, ExitFamilies),
    offering: bool,
    claimed: ExitFamilies,
) -> bool {
    let (advertised_offer, advertised_families) = advertised;
    if advertised_offer != offering {
        return true;
    }
    // Not offering means there is no capability to state, so the roster's copy
    // is not something to compare against. It is also not `Unknown` in general:
    // withdrawing an offer publishes `Unknown`, which `record_exit_offer` maps
    // back onto the claim already held (silence never erases a statement), so a
    // node that stops offering leaves a `Dual` behind that it would then
    // disagree with forever. The families only mean anything while the offer
    // stands, and selection already gates on `exit_node`.
    if !offering {
        return false;
    }
    // An `Unknown` on the roster compares equal to anything: only a coordinator
    // that knows the field can write it, so demanding it from one that cannot is
    // demanding something that will never arrive, and this gates a 30-second
    // backstop tick that reconverges (a pkarr resolve, plus a re-delivery to
    // every coordinator) each time it says yes.
    !advertised_families.is_unknown() && advertised_families != claimed
}

/// Whether a reconverge should ask the daemon to re-run the exit reconcile.
/// Split out from [`NetworkRegistry::nudge_exit_reapply`] for the same reason as
/// [`offer_disagrees`]: it is the whole decision, and reaching the method needs a
/// live registry.
///
/// Two states need it, and only one of them is a pending selection. An
/// *installed* tunnel is the other: [`ipv6_gateway_refusal`] is a standing
/// property re-checked on every apply, and the roster is exactly where it
/// changes, so a gateway that loses its IPv6 uplink (or a coordinator that
/// upgrades and fills in a claim we had to guess at) has to reach a re-apply.
/// Keying the nudge on `exit_selection_pending` alone gets this backwards: the
/// flag is cleared the moment the tunnel installs, so the case the re-check
/// exists for is the one case it never sees, and the client keeps a full IPv6
/// tunnel into a gateway with nowhere to send it.
///
/// Cheap when nothing changed: the listener re-runs `apply_exit_node`, which is
/// idempotent, and this only fires on a reconverge that actually applied.
fn wants_exit_reapply(selection_pending: bool, tunnel_installed: bool) -> bool {
    selection_pending || tunnel_installed
}

impl NetworkRegistry {
    /// Ask the daemon to re-run the exit reconcile, if a reconverge could have
    /// changed its answer. See [`wants_exit_reapply`].
    pub(crate) fn nudge_exit_reapply(&self) {
        if wants_exit_reapply(
            self.exit_selection_pending.load(Ordering::Relaxed),
            self.exit_client.is_active(),
        ) {
            self.exit_reapply.notify_one();
        }
    }

    /// A network's roster, or empty if we don't have that network. Keeps the
    /// lookup-then-lock-then-clone dance (and the lock guard) out of the callers.
    pub(crate) fn roster(&self, network: &str) -> Vec<Member> {
        match self.networks.get(network) {
            // Cloned out (`NetworkState::roster`): callers must be free to work
            // (and to await) without holding the state lock.
            Some(handle) => handle.state.read().unwrap().roster(),
            None => Vec::new(),
        }
    }

    /// The roster member `id` names (see [`Member::matches_identity`]).
    pub(crate) fn roster_member(&self, network: &str, id: EndpointId) -> Option<Member> {
        self.roster(network)
            .into_iter()
            .find(|m| m.matches_identity(id))
    }

    /// Whether `device_key` is nullified on *any* network this node runs
    /// (`ray unpair`).
    ///
    /// Nullifier sets are per-network, but the thing they gate here is not: a
    /// verified cert writes into `device_user_map`, which is one map for the whole
    /// daemon and is what the inbound firewall, mesh SSH and own-device
    /// auto-accept resolve through. Checking only the network a `MeshHello`
    /// happened to arrive on let a device revoked on network A re-establish that
    /// daemon-wide binding by saying hello on network B. The check has to be as
    /// wide as the map it protects.
    pub(crate) fn is_nullified_anywhere(&self, device_key: &EndpointId) -> bool {
        self.networks
            .iter()
            .any(|h| h.state.read().unwrap().nullifiers.contains(device_key))
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
            format!("exit-node allow {peer} on {network} (this node now offers exit)")
        } else if offering {
            format!("exit-node disallow {peer} on {network}")
        } else {
            format!("exit-node disallow {peer} on {network} (no peers left; offer withdrawn)")
        };
        IpcMessage::Ok { message: detail }
    }

    /// Select or clear the exit peer this node routes non-mesh traffic through.
    /// On select, the peer must be in the roster and advertise `exit_node`, and on
    /// an IPv6-only node the roster must not say it is IPv4-only (an absent claim is allowed, and warned about).
    ///
    /// That extra condition is the whole reason the flag exists. An IPv6-only data
    /// plane tunnels IPv6 and nothing else, so a gateway that reaches the internet
    /// over IPv4 alone would receive this node's traffic and have no uplink to
    /// masquerade it onto. Refusing here turns a silent black hole into a sentence.
    pub(crate) async fn exit_node_use(&self, network: &str, peer: Option<String>) -> IpcMessage {
        let mut app_config = match config::load() {
            Ok(c) => c,
            Err(e) => return ipc_err(format!("failed to load config: {e}")),
        };
        // Validate the selection against the live roster before persisting.
        // Set when the gateway is allowed on an absent IPv6 claim rather than a
        // positive one, so the reply can say so: a log line is not where someone
        // running `ray exit-node use` looks.
        let mut unverified = false;
        let selection = match &peer {
            Some(name) => {
                let Some(id) = self.resolve_peer_flexible(name).await else {
                    return ipc_err(format!("could not resolve peer: {name}"));
                };
                let member = self.roster_member(network, id);
                if let Some(why) = gateway_refusal(member.as_ref(), name, network) {
                    return ipc_err(why);
                }
                // Allowed, but on no evidence: the roster says nothing about this
                // gateway's IPv6, which is what a coordinator too old to carry the
                // claim leaves behind. Say so once, here, rather than let a dead
                // tunnel be the first news of it.
                unverified = member.as_ref().is_some_and(ipv6_gateway_unverified);
                if unverified {
                    tracing::warn!(
                        gateway = %name,
                        network = %network,
                        "selected gateway does not say whether it can carry IPv6, the only \
                         family the mesh routes; allowing it because the claim is absent \
                         rather than negative (a coordinator on an older release drops it). \
                         If nothing reaches the internet, that is why"
                    );
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
        // "All traffic" would be a lie: the mesh carries no IPv4, so the tunnel
        // takes IPv6 and leaves the host's IPv4 egress where it already was. Say
        // so rather than let the user find out from a leak test.
        let message = match &peer {
            Some(name) => format!(
                "routing IPv6 traffic through {name} on {network}. IPv4 is not tunnelled \
                 and still leaves this host directly{}",
                if unverified {
                    ". Note: this network's coordinator does not report whether that \
                     gateway has an IPv6 uplink, so this is unverified. If nothing \
                     reaches the internet, that is the first thing to check"
                } else {
                    ""
                }
            ),
            None => format!("direct egress restored on {network}"),
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
                return Some(format!(
                    "config unreadable, exit-node state left as it was: {e}"
                ));
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
        // A refusal found while resolving the selection, kept out of the closure
        // so the no-silent-fallback rule below can tell it apart from a peer the
        // roster simply hasn't landed yet.
        let mut refused: Option<String> = None;
        let selection = selected.into_iter().find_map(|nc| {
            let id = nc.exit_node_use.as_ref()?.parse::<EndpointId>().ok()?;
            let member = self.roster_member(&nc.name, id)?;
            // The IPv6 gate cannot live only in `exit_node_use`: a gateway can
            // republish a narrower claim with nobody touching the selection, and
            // the selection outlives a restart. Re-checking here is what keeps the
            // claim's promise true after boot. Only the IPv6 half, though: a peer
            // that momentarily stops advertising `exit_node` keeps its tunnel, per
            // the note above.
            if let Some(why) = ipv6_gateway_refusal(
                &member,
                member
                    .hostname
                    .as_deref()
                    .unwrap_or("the selected exit node"),
            ) {
                refused = Some(why);
                return None;
            }
            Some(ExitSelection {
                peer_user: self.device_user_map.resolve(&member.identity),
                ipv6: derive_ipv6(&member.identity),
                network: SmolStr::new(&nc.name),
                carries: member.exit_families.tunnelled(),
            })
        });
        // Unlike the missing-peer case below, this is not a roster gap a
        // reconverge will heal: the gateway is present and simply cannot carry
        // the only family this tunnel would route. Keeping or installing it would
        // black-hole every flow, so direct egress is the better side to fail on
        // (the opposite of the leak that rule guards against). The config entry is
        // left alone so `ray exit-node status` still shows what to clear.
        //
        // Gated on there being no selection at all: `find_map` keeps looking after
        // a refusal, so with an exit selected on more than one network (warned
        // about above) a later usable gateway still wins over an earlier bad one.
        if let Some(why) = refused.filter(|_| selection.is_none()) {
            // Stays *pending*, unlike every other terminal branch here. The
            // refusal rests on a roster fact that the gateway itself can change:
            // it gains an IPv6 uplink, `refresh_v6_uplink` re-probes on the
            // reconverge that republishes the offer, and the claim reaches us. The
            // reconverge only nudges `exit_reapply` while this flag is set, so
            // clearing it here would leave the client on direct egress until
            // someone reran `ray up`, having built the gateway half of exactly
            // that loop. Re-applying is idempotent and costs a roster read.
            self.exit_selection_pending.store(true, Ordering::Relaxed);
            self.exit_client.set(None);
            tracing::warn!(reason = %why, "exit selection unusable; using direct egress");
            return Some(why);
        }
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
        match &selection {
            Some(s) => tracing::info!(
                network = %s.network,
                peer_user = %s.peer_user.fmt_short(),
                peer_ip = %s.ipv6,
                "exit selection active (return traffic from this peer will be admitted)"
            ),
            None => tracing::debug!("exit selection cleared (direct egress)"),
        }
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
            tracing::debug!("exit offer sync disabled (data plane down); skipping");
            return;
        }
        // Re-probe before comparing, so a gateway that gained (or lost) IPv6 since
        // the last `ray up` republishes on this pass rather than advertising a
        // stale capability until someone restarts the data plane. Blocking pool:
        // it shells out, and this runs from the reconverge worker.
        {
            let server = self.exit_server.clone();
            let _ = tokio::task::spawn_blocking(move || server.refresh_v6_uplink()).await;
        }
        let names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        for name in names {
            if self.exit_offer_out_of_sync(&name) {
                let offering = self.exit_server.is_offering(&name);
                let families = self.claimed_exit_families(offering);
                tracing::debug!(network = %name, offering, ?families, "exit offer out of sync; publishing");
                self.publish_exit_offer(&name, offering, families).await;
            }
        }
    }

    /// Whether `network`'s signed roster disagrees with what this node actually
    /// offers right now: the condition [`Self::sync_exit_offers`] publishes on.
    /// Cheap (two map reads), so it also gates the reconverge worker's backstop
    /// tick, which is the retry that heals a delivery that missed every
    /// coordinator. Always false while the data plane is down.
    ///
    /// The IPv6 claim counts as part of the offer: a gateway that gains or loses
    /// its IPv6 uplink has to republish, or an IPv6-only client keeps selecting it
    /// (or keeps refusing to) on a fact that stopped being true.
    ///
    /// But only when the roster carries a claim at all. A coordinator on a release
    /// that predates `Member.exit_families` drops the key when it republishes, so
    /// demanding it there is demanding something that side cannot supply: the
    /// comparison would never balance, and since it gates the 30-second backstop
    /// tick in the reconverge worker, "never balances" means a pkarr resolve and a
    /// re-delivery to every coordinator every 30 seconds, per network, for as long
    /// as the two builds coexist. [`ExitFamilies::Unknown`] therefore compares
    /// equal to whatever we would have claimed: the offer itself is still synced
    /// on `exit_node`, which that coordinator does understand, and the capability
    /// lands on its own once the coordinator upgrades.
    pub(crate) fn exit_offer_out_of_sync(&self, network: &str) -> bool {
        if !self.exit_sync_enabled.load(Ordering::Relaxed) {
            return false;
        }
        let self_id = self.transport.endpoint.id();
        let user_id = self.device_user_map.resolve(&self_id);
        let advertised = [self_id, user_id]
            .into_iter()
            .find_map(|id| self.roster_member(network, id))
            .map(|m| (m.exit_node, m.exit_families))
            .unwrap_or((false, ExitFamilies::Unknown));
        let offering = self.exit_server.is_offering(network);
        offer_disagrees(advertised, offering, self.claimed_exit_families(offering))
    }

    /// The `exit_families` value this node would publish right now.
    ///
    /// Both halves are our own state, not the peer's: the uplink probe says what
    /// we can reach. A gateway with no IPv6 uplink cannot return a client's
    /// reply, and claiming otherwise is the black hole this exists to prevent.
    fn claimed_exit_families(&self, offering: bool) -> ExitFamilies {
        if offering {
            ExitFamilies::from_uplink(self.exit_server.offers_v6())
        } else {
            ExitFamilies::Unknown
        }
    }

    /// Why the selection configured on `network` is not the tunnel that is
    /// actually installed, or `None` when it is.
    ///
    /// The two are allowed to disagree, and both directions of that are
    /// deliberate: [`Self::reload_exit_state`] keeps a live tunnel through a
    /// roster that briefly loses the peer, and drops one whose gateway now says
    /// it cannot carry our family. Neither touches the config, so `ray exit-node
    /// status` keeps showing what to change. What it must not do is keep printing
    /// `using: <peer>` while the traffic leaves directly: the second case needs no
    /// user action to arrive (the gateway republishes a claim), so the user has no
    /// reason to suspect it.
    fn exit_selection_problem(&self, network: &str, selected: &str) -> Option<String> {
        let resolved = self
            .exit_client
            .selection()
            .is_some_and(|s| s.network == network);
        let member = selected
            .parse::<EndpointId>()
            .ok()
            .and_then(|id| self.roster_member(network, id));
        // The install error belongs to the network whose selection was installed,
        // and there is only ever one: a single default route means a single
        // tunnel. Reporting it against every configured network would blame this
        // one's gateway for a failure that happened on another's, which is worse
        // than saying nothing, since the reason string is the whole point.
        let install_error = resolved
            .then(|| self.exit_install_error.load().as_deref().cloned())
            .flatten();
        selection_problem(
            install_error.as_deref(),
            resolved,
            self.exit_sync_enabled.load(Ordering::Relaxed),
            member.as_ref(),
        )
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
            let offers: Vec<Member> = self
                .roster(&n.name)
                .into_iter()
                .filter(|m| m.exit_node)
                .collect();
            let available_v6 = offers
                .iter()
                .filter(|m| m.exit_families.carries_v6())
                .map(display_name)
                .collect();
            // From the same predicate `ray exit-node use` will run, so the list
            // cannot disagree with what the command does.
            let refused = offers
                .iter()
                .filter(|m| ipv6_gateway_refusal(m, "gw").is_some())
                .map(display_name)
                .collect();
            let not_in_effect = n
                .exit_node_use
                .as_deref()
                .and_then(|sel| self.exit_selection_problem(&n.name, sel));
            // What the installed tunnel carries, which is the selection's own copy
            // and not a fresh read of the roster: between a gateway republishing a
            // narrower claim and the re-apply that acts on it, the roster answer
            // describes a tunnel that is not installed, and `not_in_effect` says
            // nothing because the selection did resolve. Fall back to the roster
            // only when nothing is installed, so a selection waiting on a re-apply
            // still reports what it would carry.
            let carries = self
                .exit_client
                .selection()
                .filter(|s| s.network == n.name)
                .map(|s| s.carries)
                .unwrap_or_else(|| {
                    n.exit_node_use
                        .as_deref()
                        .and_then(|sel| sel.parse::<EndpointId>().ok())
                        .and_then(|id| self.roster_member(&n.name, id))
                        .map(|m| m.exit_families)
                        .unwrap_or_default()
                        .tunnelled()
                });
            networks.push(ipc::ExitNodeStatusView {
                network: n.name,
                allow: n.exit_allow,
                using: n.exit_node_use,
                available: offers.iter().map(display_name).collect(),
                available_v6,
                refused,
                not_in_effect,
                tunnel_v4: carries.carries_v4(),
                tunnel_v6: carries.carries_v6(),
            });
        }
        IpcMessage::ExitNodeState { networks }
    }

    /// Advertise this node's exit-node offer to the network. If we hold the
    /// network key we record it on our own roster entry and republish the signed
    /// blob directly. Otherwise we deliver [`ControlMsg::ExitNodeOffer`] to the
    /// coordinator set over each coordinator's **retained** mesh connection (the
    /// daemon keeps a connection to every saved network for its lifetime).
    ///
    /// The connection has to be one the [`ConnectionManager`] owns, not a
    /// locally-held dial: a control frame is written on a fresh bidirectional
    /// stream and only flushes while its connection stays open, so sending over a
    /// connection this function owns and then drops cuts the stream off before
    /// the bytes reach the coordinator (the sender sees a clean `Ok` while the
    /// coordinator never receives the frame, the bug this replaced). A coordinator
    /// with no live connection right now (an idle-closed on-demand link) is
    /// skipped; [`Self::sync_exit_offers`] retries on the backstop / group-poll
    /// cadence, and the reconnect loop re-establishes the link, so a later pass
    /// delivers.
    async fn publish_exit_offer(&self, network: &str, enabled: bool, families: ExitFamilies) {
        if self
            .deliver_self_flag(
                network,
                &ControlMsg::ExitNodeOffer {
                    enabled,
                    exit_families: families,
                },
                "exit offer",
            )
            .await
        {
            self.record_exit_offer(network, self.transport.endpoint.id(), enabled, families)
                .await;
        }
    }

    /// Deliver a self-claimed roster flag to the network's coordinator set, over
    /// each coordinator's **retained** mesh connection. Returns `true` when this
    /// node holds the network key, meaning the caller should record the flag on
    /// its own roster entry and republish instead of sending anything.
    ///
    /// The connection has to be one the [`ConnectionManager`] owns, not a
    /// locally-held dial: a control frame is written on a fresh bidirectional
    /// stream and only flushes while its connection stays open, so sending over a
    /// connection this function owns and then drops cuts the stream off before
    /// the bytes reach the coordinator (the sender sees a clean `Ok` while the
    /// coordinator never receives the frame, the bug this replaced). A coordinator
    /// with no live connection right now (an idle-closed on-demand link) is
    /// skipped; the caller's sync pass retries on the backstop / group-poll
    /// cadence, and the reconnect loop re-establishes the link, so a later pass
    /// delivers.
    pub(crate) async fn deliver_self_flag(
        &self,
        network: &str,
        msg: &ControlMsg,
        what: &str,
    ) -> bool {
        let self_id = self.transport.endpoint.id();
        let user_id = self.device_user_map.resolve(&self_id);
        let (net_pubkey, is_coordinator) = match self.networks.get(network) {
            Some(h) => {
                let s = h.state.read().unwrap();
                (s.network_public_key, s.network_secret_key.is_some())
            }
            None => return false,
        };
        tracing::debug!(network = %network, is_coordinator, "advertising {what}");
        if is_coordinator {
            return true;
        }
        let coordinators: Vec<Member> = self
            .roster(network)
            .into_iter()
            .filter(|m| m.is_coordinator && m.identity != self_id && m.identity != user_id)
            .collect();
        if coordinators.is_empty() {
            tracing::debug!(network = %network, "no coordinator in roster to deliver {what} to; will retry");
            return false;
        }
        for m in coordinators {
            // Reuse the live, ConnectionManager-owned link. Never a connection we
            // dial and own here: it would be dropped before the frame flushes.
            let Some(conn) = self.peers.conn_for_ip(&derive_ipv6(&m.identity)) else {
                tracing::debug!(
                    network = %network,
                    coordinator = %m.identity.fmt_short(),
                    "no live connection to coordinator to deliver {what}; will retry"
                );
                continue;
            };
            if let Err(e) = open_and_send(&conn, Some(net_pubkey), msg).await {
                tracing::warn!(
                    network = %network,
                    coordinator = %m.identity.fmt_short(),
                    error = %e,
                    "failed to deliver {what} to coordinator; will retry"
                );
            } else {
                tracing::debug!(
                    network = %network,
                    coordinator = %m.identity.fmt_short(),
                    "delivered {what} to coordinator"
                );
            }
        }
        false
    }

    /// Coordinator side: record a member's exit-node offer on its signed roster
    /// entry and republish. `sender` is the offering peer's transport id; it is
    /// normalized to the roster identity (device or paired user) before matching.
    /// No-op if we do not hold the network key or the sender is not a member.
    pub(crate) async fn record_exit_offer(
        &self,
        network: &str,
        sender: EndpointId,
        enabled: bool,
        families: ExitFamilies,
    ) {
        self.record_self_flag(network, sender, "exit offer", |m| {
            // An offer from a build that predates `exit_families` arrives as
            // `Unknown`. Recording that over a claim we already hold would erase
            // what a newer run of the same peer told us, so silence never
            // overwrites a statement: it only ever fills a gap.
            let families = if families.is_unknown() {
                m.exit_families
            } else {
                families
            };
            let changed = m.exit_node != enabled || m.exit_families != families;
            m.exit_node = enabled;
            m.exit_families = families;
            changed
        })
        .await;
    }

    /// Coordinator side: apply a member's self-claimed flag to its signed roster
    /// entry and republish if `set` actually changed it. `sender` is the claiming
    /// peer's transport id; it is normalized to the roster identity (device or
    /// paired user) before matching. No-op if we do not hold the network key or
    /// the sender is not a member.
    pub(crate) async fn record_self_flag(
        &self,
        network: &str,
        sender: EndpointId,
        what: &str,
        set: impl Fn(&mut Member) -> bool,
    ) {
        let user_id = self.device_user_map.resolve(&sender);
        let changed = match self.networks.get(network) {
            Some(h) => {
                let mut s = h.state.write().unwrap();
                if s.network_secret_key.is_none() {
                    tracing::debug!(network = %network, "{what} received but we hold no network key; ignoring");
                    return;
                }
                // The roster keys a member by its own identity, which for a paired
                // multi-device peer is the user identity rather than the device id
                // the datagram arrived under. Try both.
                let Some(id) = [sender, user_id]
                    .into_iter()
                    .find(|id| s.members.get(id).is_some())
                else {
                    tracing::warn!(
                        network = %network,
                        sender = %sender.fmt_short(),
                        "{what} from a peer the roster does not list; ignoring"
                    );
                    return;
                };
                let changed = match s.members.get_mut(&id) {
                    Some(member) => set(member),
                    None => false,
                };
                if changed {
                    s.refresh_snapshot();
                }
                changed
            }
            None => return,
        };
        tracing::debug!(
            network = %network,
            sender = %sender.fmt_short(),
            changed,
            "{what} recorded"
        );
        if changed {
            self.store_and_publish_group(network).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Member, gateway_refusal};
    use crate::membership::ExitFamilies;

    fn gateway(exit_node: bool, exit_families: ExitFamilies) -> Member {
        let identity = iroh::SecretKey::from_bytes(&[3u8; 32]).public();
        Member {
            identity,
            is_coordinator: false,
            hostname: Some("gw".to_string()),
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node,
            exit_families,
        }
    }

    /// Which gateways `ray exit-node use` will accept, and why it turns the
    /// unusable cases into a sentence instead of a dead tunnel.
    #[test]
    fn a_gateway_must_carry_ipv6() {
        use ExitFamilies::{Dual, Unknown, V4};

        // IPv6 is the only family the mesh routes, so a gateway that says it has
        // no IPv6 uplink would receive the traffic and have nowhere to send it.
        let refusal = gateway_refusal(Some(&gateway(true, V4)), "gw", "net")
            .expect("a v4-only gateway carries nothing we can send it");
        assert!(refusal.contains("cannot carry IPv6"), "{refusal}");
        // A claim that includes IPv6 is fine however it is spelled.
        assert!(gateway_refusal(Some(&gateway(true, Dual)), "gw", "net").is_none());

        // No claim on the roster is not a denial. It is what a coordinator on a
        // release without the field leaves behind, and refusing on it would make
        // exit nodes unusable on that whole network. Allowed, and flagged as a
        // guess so the caller can warn.
        assert!(gateway_refusal(Some(&gateway(true, Unknown)), "gw", "net").is_none());
        assert!(super::ipv6_gateway_unverified(&gateway(true, Unknown)));
        assert!(!super::ipv6_gateway_unverified(&gateway(true, Dual)));
        assert!(!super::ipv6_gateway_unverified(&gateway(true, V4)));
        // Nor is a peer that offers no exit node at all a guess: that is the
        // other refusal's business, and reporting it twice would be noise.
        assert!(!super::ipv6_gateway_unverified(&gateway(false, Unknown)));

        // No offer at all, and not on the roster, are the same answer: there is
        // nothing there to route through.
        for member in [Some(gateway(false, Dual)), None] {
            let refusal = gateway_refusal(member.as_ref(), "gw", "net")
                .expect("a peer with no offer is unusable");
            assert!(
                refusal.contains("does not advertise an exit node"),
                "{refusal}"
            );
        }
    }

    /// An installed tunnel has to be re-nudged on a reconverge, not just a
    /// pending selection.
    ///
    /// `reload_exit_state` clears `exit_selection_pending` as soon as the tunnel
    /// installs, so keying the nudge on that flag alone means the standing IPv6
    /// re-check never runs against a live tunnel: the roster is where a gateway's
    /// claim changes, and a gateway that loses its IPv6 uplink would keep the
    /// client's whole tunnel pointed into a black hole until the next `ray up`.
    #[test]
    fn a_live_tunnel_is_re_nudged_even_with_no_pending_selection() {
        assert!(super::wants_exit_reapply(false, true));
        assert!(super::wants_exit_reapply(true, false));
        assert!(super::wants_exit_reapply(true, true));
        // Nothing selected and nothing installed: the reconverge has no exit
        // state to re-derive, so it stays quiet.
        assert!(!super::wants_exit_reapply(false, false));
    }

    /// The offer-sync comparison must converge against a coordinator that cannot
    /// write `exit_families`, which is every coordinator on 0.3.0.
    ///
    /// This gates the reconverge worker's 30-second backstop tick, so a
    /// comparison that can never balance is not a missing feature: it is a pkarr
    /// resolve and a re-delivery to every coordinator, every 30 seconds, per
    /// network, for as long as the two builds coexist.
    #[test]
    fn an_unwritable_claim_still_converges() {
        use ExitFamilies::{Dual, Unknown, V4};

        // The case that spun: we offer and have IPv6, the coordinator recorded the
        // offer but dropped the capability. `exit_node` agrees, so we are done.
        assert!(!super::offer_disagrees((true, Unknown), true, Dual));
        assert!(!super::offer_disagrees((true, Unknown), true, V4));

        // A coordinator that *did* record a claim is held to it, so a gateway that
        // gains or loses its uplink still republishes.
        assert!(super::offer_disagrees((true, V4), true, Dual));
        assert!(super::offer_disagrees((true, Dual), true, V4));
        assert!(!super::offer_disagrees((true, Dual), true, Dual));
        assert!(!super::offer_disagrees((true, V4), true, V4));

        // The offer itself is compared as it always was, in both directions, and
        // is what actually reaches an old coordinator.
        assert!(super::offer_disagrees((false, Unknown), true, Dual));
        assert!(super::offer_disagrees((true, Dual), false, Unknown));

        // Not offering: nothing to state, so no gap either way.
        assert!(!super::offer_disagrees((false, Unknown), false, Unknown));

        // Withdrawing an offer settles, which needs the families ignored rather
        // than compared. Withdrawal publishes `Unknown`, and `record_exit_offer`
        // maps that back onto the claim already held, so the roster keeps the
        // `Dual` it was told while `exit_node` goes false. Comparing the two
        // there is a disagreement nothing can ever resolve: the withdrawal is
        // already delivered, and republishing it changes nothing.
        assert!(!super::offer_disagrees((false, Dual), false, Unknown));
        assert!(!super::offer_disagrees((false, V4), false, Unknown));

        // Not on the roster at all while offering is a real disagreement: the
        // delivery missed every coordinator and the backstop is what retries it.
        assert!(super::offer_disagrees((false, Unknown), true, V4));
    }

    /// The two halves of the refusal have different lifetimes, and `reload_exit_state`
    /// re-checks only one of them on every apply.
    ///
    /// "Does not advertise an exit node" is a roster fact that flickers, and
    /// dropping a live tunnel on it would leak the traffic the user chose to
    /// tunnel, so it stays a selection-time check. The IPv6 one is a standing
    /// property: while it holds the tunnel carries nothing, and the gateway can
    /// republish a narrower claim with no user action at all, so a selection made
    /// against a gateway that had IPv6 has to be caught later.
    #[test]
    fn only_the_ipv6_half_of_the_refusal_is_re_checked_after_selection() {
        use ExitFamilies::{Dual, Unknown, V4};

        // A gateway that stopped advertising keeps its tunnel: no refusal from the
        // half `reload_exit_state` consults.
        assert!(super::ipv6_gateway_refusal(&gateway(false, Dual), "gw").is_none());
        // A gateway that says it has no IPv6 uplink is refused on every re-apply,
        // not just at selection time.
        let refusal = super::ipv6_gateway_refusal(&gateway(true, V4), "gw")
            .expect("a gateway that cannot carry IPv6 stays unusable");
        assert!(refusal.contains("cannot carry IPv6"), "{refusal}");
        // An unknown claim never tears down a live tunnel. A roster that lost the
        // key (a coordinator on an older build republished it) must not read as a
        // gateway that lost its uplink.
        assert!(super::ipv6_gateway_refusal(&gateway(true, Unknown), "gw").is_none());
    }

    /// A configured selection that is not the installed tunnel says so.
    ///
    /// `reload_exit_state` deliberately leaves the config alone when it refuses a
    /// gateway or cannot resolve one, so the status line is the only place the
    /// gap can show. Printing `using: gw` for a node whose packets all leave
    /// directly is the failure this pins, and it needs no user action to arrive:
    /// the gateway republishes a family claim it worked out for itself.
    #[test]
    fn a_selection_that_is_not_installed_is_reported_as_not_installed() {
        use super::selection_problem;
        use ExitFamilies::{Dual, V4};

        // Resolved and installed: nothing to say, whatever the roster now claims.
        assert!(selection_problem(None, true, true, Some(&gateway(true, V4))).is_none());

        // A failed install rolls back its rules and leaves the selection
        // resolved, so it has to be answered ahead of it or the status line
        // reports a tunnel the kernel refused.
        let why = selection_problem(
            Some("RTNETLINK answers: operation not permitted"),
            true,
            true,
            Some(&gateway(true, Dual)),
        )
        .expect("a rolled-back install is not a tunnel");
        assert!(why.contains("operation not permitted"), "{why}");

        // Down is a wait, and says which command ends it.
        let why = selection_problem(None, false, false, Some(&gateway(true, Dual)))
            .expect("a selection cannot be in effect while the data plane is down");
        assert!(why.contains("ray up"), "{why}");

        // Not on the roster yet is the other wait.
        let why = selection_problem(None, false, true, None).expect("no peer, no tunnel");
        assert!(why.contains("roster"), "{why}");

        // The one that is not a wait: the reason the tunnel came down is the same
        // string `ray exit-node use` would have refused with.
        let why = selection_problem(None, false, true, Some(&gateway(true, V4)))
            .expect("a gateway that cannot carry IPv6 is unusable");
        assert!(why.contains("cannot carry IPv6"), "{why}");
    }

    /// A gateway that can carry nothing is refused by everyone.
    ///
    /// A host on an ordinary IPv4-only uplink is the common shape of this, not a
    /// corner: the overlay gives it no IPv4 to return traffic over and it has no
    /// IPv6 to offer instead. Reporting that as `V4`
    /// makes it a positive claim to carry IPv4, which a dual-stack client
    /// accepts, and the tunnel then carries nothing in silence.
    #[test]
    fn a_gateway_that_can_carry_nothing_is_refused_in_both_modes() {
        use ExitFamilies::Neither;

        assert!(
            !Neither.carries_v4(),
            "a claim of nothing is not a claim of v4"
        );
        assert!(!Neither.carries_v6());
        assert!(
            !Neither.is_unknown(),
            "it is a claim, not the absence of one, so it must not read as unverified"
        );
        {
            let refusal = super::ipv6_gateway_refusal(&gateway(true, Neither), "gw")
                .expect("a gateway that carries nothing must be refused");
            assert!(refusal.contains("cannot carry IPv6"), "{refusal}");
        }
    }
}
