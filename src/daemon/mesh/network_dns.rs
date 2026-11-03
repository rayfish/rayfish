//! Signed network DNS policy and the local choice to use it.

use super::super::*;
use std::net::{IpAddr, SocketAddr};

impl NetworkRegistry {
    pub(crate) fn dns_policy_authorized(&self, network: &str) -> bool {
        self.networks
            .get(network)
            .is_some_and(|h| h.state.read().unwrap().network_secret_key.is_some())
    }

    pub(crate) async fn publish_dns_policy(
        self: &Arc<Self>,
        network: &str,
        servers: Vec<ipc::MachineHostname>,
    ) -> OpResult<Done> {
        let Some(handle) = self.networks.get(network) else {
            return op_err(format!("network '{network}' not found"));
        };
        let state = Arc::clone(&handle.state);
        let notify = handle.dht_notify.clone();
        drop(handle);
        {
            let mut live = state.write().unwrap();
            if live.network_secret_key.is_none() {
                return op_err("only a coordinator can publish DNS policy".to_string());
            }
            live.group.dns_upstreams = servers;
        }
        let saved = update_snapshot_and_publish(&state, &self.transport.blob_store, &notify).await;
        let key = state.read().unwrap().network_public_key;
        broadcast_member_sync(self, key, network, None).await;
        self.refresh_network_dns().await;
        if !saved {
            return op_err(unsaved_snapshot_warning(network));
        }
        Ok(Done(format!("published DNS policy for '{network}'")))
    }

    /// The first opted-in network by name wins. An unresolved policy stays
    /// selected with no upstreams, so a missing resolver cannot leak queries.
    pub(crate) async fn refresh_network_dns(&self) {
        let Ok(cfg) = config::load() else {
            return;
        };
        let mut accepted: Vec<_> = cfg.networks.iter().filter(|n| n.accept_dns).collect();
        accepted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut selected = None;
        for net in accepted {
            let Some(handle) = self.networks.get(&net.name) else {
                continue;
            };
            let state = handle.state.read().unwrap();
            if state.group.dns_upstreams.is_empty() {
                continue;
            }
            let roster = state.roster();
            // A resolver host keeps its own upstreams rather than forwarding
            // its OS lookups back through the service it provides to the mesh.
            if roster.iter().any(|m| {
                m.identity == self.transport.endpoint.id()
                    && m.hostname
                        .as_ref()
                        .is_some_and(|h| state.group.dns_upstreams.iter().any(|s| s.as_ref() == h))
            }) {
                continue;
            }
            let addresses = state
                .group
                .dns_upstreams
                .iter()
                .filter_map(|host| {
                    roster
                        .iter()
                        .find(|m| m.hostname.as_deref() == Some(host.as_ref()))
                        .map(|m| {
                            SocketAddr::new(
                                IpAddr::V6(crate::membership::derive_ipv6(&m.identity)),
                                53,
                            )
                        })
                })
                .collect();
            selected = Some(addresses);
            break;
        }
        let changed = crate::dns::resolver::set_network_dns_active(selected.is_some());
        self.dns.resolver.set_network_upstreams(selected);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if changed {
            let tun_name = self.tun_name.load().as_str().to_owned();
            self.dns.reassert_os_config(&tun_name).await;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = changed;
    }
}
