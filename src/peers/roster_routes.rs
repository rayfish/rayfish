use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;

use iroh::EndpointId;
use smol_str::SmolStr;

use super::FastDashMap;

/// A known roster member that can be dialed even without a live connection.
#[derive(Clone, Debug)]
pub struct RouteTarget {
    pub endpoint_id: EndpointId,
    pub ipv6: Ipv6Addr,
    pub networks: Vec<SmolStr>,
}

/// The routing fields copied from one roster member.
#[derive(Clone, Copy, Debug)]
pub struct RouteMember {
    pub endpoint_id: EndpointId,
    pub ipv6: Ipv6Addr,
}

struct RouteEntry {
    endpoint_id: EndpointId,
    ipv6: Ipv6Addr,
    networks: HashSet<SmolStr>,
}

impl RouteEntry {
    fn to_target(&self) -> RouteTarget {
        RouteTarget {
            endpoint_id: self.endpoint_id,
            ipv6: self.ipv6,
            networks: self.networks.iter().cloned().collect(),
        }
    }
}

/// Roster routes used to find and lazily dial peers that are not connected.
#[derive(Clone, Default)]
pub struct RosterRouteMap {
    peers: Arc<FastDashMap<Ipv6Addr, RouteEntry>>,
}

impl RosterRouteMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sync_network(&self, network: &str, members: &[RouteMember]) {
        let net = SmolStr::new(network);
        let fresh: HashSet<Ipv6Addr> = members.iter().map(|m| m.ipv6).collect();
        let stale: Vec<Ipv6Addr> = self
            .peers
            .iter()
            .filter(|e| e.networks.contains(&net) && !fresh.contains(e.key()))
            .map(|e| *e.key())
            .collect();
        for ipv6 in stale {
            self.drop_network(&ipv6, &net);
        }
        for member in members {
            self.upsert(member.ipv6, member.endpoint_id, net.clone());
        }
    }

    fn upsert(&self, ipv6: Ipv6Addr, endpoint_id: EndpointId, network: SmolStr) {
        let mut entry = self.peers.entry(ipv6).or_insert_with(|| RouteEntry {
            endpoint_id,
            ipv6,
            networks: HashSet::new(),
        });
        entry.endpoint_id = endpoint_id;
        entry.networks.insert(network);
    }

    fn drop_network(&self, ipv6: &Ipv6Addr, network: &SmolStr) {
        if let Some(mut entry) = self.peers.get_mut(ipv6) {
            entry.networks.remove(network);
        }
        self.peers
            .remove_if(ipv6, |_, entry| entry.networks.is_empty());
    }

    pub fn remove_network(&self, network: &str) {
        let network = SmolStr::new(network);
        let affected: Vec<Ipv6Addr> = self
            .peers
            .iter()
            .filter(|entry| entry.networks.contains(&network))
            .map(|entry| *entry.key())
            .collect();
        for ipv6 in affected {
            self.drop_network(&ipv6, &network);
        }
    }

    pub fn sync_add(&self, network: &str, ipv6: Ipv6Addr, endpoint_id: EndpointId) {
        self.upsert(ipv6, endpoint_id, SmolStr::new(network));
    }

    pub fn resolve_v6(&self, ipv6: &Ipv6Addr) -> Option<RouteTarget> {
        self.peers.get(ipv6).map(|entry| entry.to_target())
    }
}
