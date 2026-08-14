//! Advertising this node's IPv6-only data plane on the signed roster.
//!
//! `AppConfig::ipv6_only` is a local decision (another VPN owns
//! `100.64.0.0/10` on this host), but peers have to know about it: they hold our
//! mesh IPv4 in their DNS tables and would hand it to apps, which then send
//! packets that arrive here and get answered out the wrong interface. So the
//! flag rides the roster like any other self-claimed capability, using the same
//! coordinator delivery and record helpers as the exit-node offer
//! (`deliver_self_flag` / `record_self_flag` in `exit_node.rs`).

use super::super::*;

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
