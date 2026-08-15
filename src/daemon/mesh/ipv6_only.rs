//! Deciding this node's IPv6-only data plane, and advertising it on the signed
//! roster.
//!
//! `AppConfig::ipv6_only` is a local decision (another VPN owns
//! `100.64.0.0/10` on this host), but peers have to know about it: they hold our
//! mesh IPv4 in their DNS tables and would hand it to apps, which then send
//! packets that arrive here and get answered out the wrong interface. So the
//! flag rides the roster like any other self-claimed capability, using the same
//! coordinator delivery and record helpers as the exit-node offer
//! (`deliver_self_flag` / `record_self_flag` in `exit_node.rs`).
//!
//! The decision itself lives here rather than in `bootstrap.rs` because both
//! entry points need it and they are on different platforms: `run_daemon` on
//! desktop, and `ray-mobile`'s `Node::start` on Android, where the app's own
//! settings store is the authority instead of `settings.toml`.

use super::super::*;

/// What to do about the data plane's address families, given the `ipv6-only`
/// setting and whether another VPN was found on `100.64.0.0/10`.
#[derive(Debug, PartialEq, Eq)]
pub enum Ipv6OnlyDecision {
    /// Both families, the normal case.
    DualStack,
    /// IPv6-only. `auto` when the scan decided it rather than the operator.
    Ipv6Only { auto: bool },
    /// Refuse to start: the operator asked for both families on a host where
    /// mesh IPv4 cannot work.
    Refuse,
}

/// The `ipv6-only` decision table. Pure, so the six cases are testable without
/// a network interface in sight.
///
/// `Some(true)` needs no scan at all (the caller skips it and passes
/// `conflict = false`), because the mode it asks for is exactly the one a
/// conflict would force.
pub fn decide_ipv6_only(setting: Option<bool>, conflict: bool) -> Ipv6OnlyDecision {
    match (setting, conflict) {
        (Some(true), _) => Ipv6OnlyDecision::Ipv6Only { auto: false },
        (Some(false), false) | (None, false) => Ipv6OnlyDecision::DualStack,
        (Some(false), true) => Ipv6OnlyDecision::Refuse,
        (None, true) => Ipv6OnlyDecision::Ipv6Only { auto: true },
    }
}

/// Resolve the `ipv6-only` setting against what is actually on this host,
/// returning `(ipv6_only, auto)`. `None` is "auto": scan, and take the mode if
/// something else already holds the CGNAT range.
///
/// Errors only in the [`Ipv6OnlyDecision::Refuse`] case, carrying the scan's own
/// description of the conflicting interface and address.
///
/// Part of the embedding API: Android calls this with the app's tri-state
/// setting, exactly as `run_daemon` calls it with the config's.
#[cfg(not(target_os = "android"))]
pub async fn resolve_ipv6_only(setting: Option<bool>) -> Result<(bool, bool)> {
    resolve_with(setting, crate::tun::check_cgnat_conflict().await.err())
}

/// Android counterpart. The scan has to skip our own tunnel: unlike desktop,
/// where this runs before the TUN exists, `Node::start` can run with a
/// `VpnService` interface already up, and seeing our own mesh IPv4 there would
/// latch the mode on for good.
#[cfg(target_os = "android")]
pub async fn resolve_ipv6_only(setting: Option<bool>) -> Result<(bool, bool)> {
    let own = own_mesh_ipv4();
    resolve_with(setting, crate::tun::check_cgnat_conflict(own).await.err())
}

/// Our own identity-derived mesh IPv4, for the scan to ignore. Best-effort: a
/// missing identity means we have no address on any interface yet, so there is
/// nothing of ours to mistake for another VPN.
#[cfg(target_os = "android")]
fn own_mesh_ipv4() -> Option<std::net::Ipv4Addr> {
    let key = crate::identity::load_or_create().ok()?;
    let index = crate::identity::load_collision_index().unwrap_or(0);
    Some(crate::membership::derive_ip_with_index(
        &key.public(),
        index,
    ))
}

/// Shared tail of both `resolve_ipv6_only`s: apply the table to a scan result.
fn resolve_with(setting: Option<bool>, conflict: Option<anyhow::Error>) -> Result<(bool, bool)> {
    // Asking for the mode outright means the scan cannot change the answer.
    if setting == Some(true) {
        return Ok((true, false));
    }
    match decide_ipv6_only(setting, conflict.is_some()) {
        Ipv6OnlyDecision::DualStack => Ok((false, false)),
        Ipv6OnlyDecision::Ipv6Only { auto } => {
            if let Some(e) = conflict {
                tracing::warn!(
                    "{e} Starting the IPv6-only data plane instead, so the two can share this \
                     host; mesh IPv4 carries no traffic and `.ray` names answer AAAA only. \
                     Set ipv6-only to off to refuse to start in this situation instead, or \
                     to on to make the mode permanent."
                );
            }
            Ok((true, auto))
        }
        // Only reachable with a conflict in hand (see the table above).
        Ipv6OnlyDecision::Refuse => Err(conflict
            .unwrap_or_else(|| anyhow::anyhow!("another VPN is using the 100.64.0.0/10 range"))
            .context("ipv6-only is set to off, so rayfish will not start on this host")),
    }
}

impl NetworkRegistry {
    /// Publish this node's IPv6-only claim to every network whose signed roster
    /// disagrees with it. Called wherever `sync_exit_offers` is, so a delivery
    /// that missed every coordinator (all idle-closed, all offline) heals on the
    /// next reconverge or group poll.
    ///
    /// Unlike the exit offer there is no data-plane gate: the mode is fixed for
    /// the daemon's lifetime and true whether the TUN is up or not, so a `ray
    /// down` must not withdraw the claim.
    pub(crate) async fn sync_ipv6_only(&self) {
        let names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        for name in names {
            if self.ipv6_only_out_of_sync(&name) {
                tracing::debug!(
                    network = %name,
                    ipv6_only = self.ipv6_only,
                    "ipv6-only claim out of sync; publishing"
                );
                self.publish_ipv6_only(&name).await;
            }
        }
    }

    /// Whether `network`'s signed roster disagrees with this node's actual mode.
    pub(crate) fn ipv6_only_out_of_sync(&self, network: &str) -> bool {
        let self_id = self.transport.endpoint.id();
        let user_id = self.device_user_map.resolve(&self_id);
        let advertised = [self_id, user_id]
            .into_iter()
            .find_map(|id| self.roster_member(network, id))
            .is_some_and(|m| m.ipv6_only);
        advertised != self.ipv6_only
    }

    /// Advertise this node's mode on one network: recorded directly when we hold
    /// the network key, otherwise delivered to the coordinator set.
    pub(crate) async fn publish_ipv6_only(&self, network: &str) {
        let enabled = self.ipv6_only;
        if self
            .deliver_self_flag(
                network,
                &ControlMsg::Ipv6Only { enabled },
                "ipv6-only claim",
            )
            .await
        {
            self.record_ipv6_only(network, self.transport.endpoint.id(), enabled)
                .await;
        }
    }

    /// Coordinator side: record a member's IPv6-only claim and republish.
    pub(crate) async fn record_ipv6_only(&self, network: &str, sender: EndpointId, enabled: bool) {
        self.record_self_flag(network, sender, "ipv6-only claim", |m| {
            let changed = m.ipv6_only != enabled;
            m.ipv6_only = enabled;
            changed
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::{Ipv6OnlyDecision, decide_ipv6_only};

    /// The whole point of the tri-state: `off` is a standing refusal, absent is
    /// consent to be moved, and `on` never depends on what is on the host.
    #[test]
    fn ipv6_only_decision_table() {
        use Ipv6OnlyDecision::*;

        // Configured on: the mode is the mode, scan or no scan.
        assert_eq!(
            decide_ipv6_only(Some(true), false),
            Ipv6Only { auto: false }
        );
        assert_eq!(decide_ipv6_only(Some(true), true), Ipv6Only { auto: false });

        // Configured off: dual-stack, and a conflict is fatal rather than
        // quietly overridden.
        assert_eq!(decide_ipv6_only(Some(false), false), DualStack);
        assert_eq!(decide_ipv6_only(Some(false), true), Refuse);

        // Auto: dual-stack on a clean host, IPv6-only on a shared one, and the
        // switch is marked so the UI can say the daemon chose it.
        assert_eq!(decide_ipv6_only(None, false), DualStack);
        assert_eq!(decide_ipv6_only(None, true), Ipv6Only { auto: true });
    }
}
