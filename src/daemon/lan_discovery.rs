//! The set of rayfish nodes seen on the local network over mDNS.
//!
//! The mDNS browse loop in `mesh::bootstrap` feeds this map; it is the only
//! place LAN sightings are kept. Two consumers read it: `ray mdns scan` (which
//! lists it) and `ConnectService::connect` (which uses it to dial a neighbour by
//! endpoint id, skipping the pkarr contact lookup).
//!
//! A sighting is not a relationship. Being in this map grants a peer nothing:
//! it only means the LAN told us the peer exists and where to reach it.

use super::*;

/// One node seen on the LAN, as last advertised over mDNS.
#[derive(Clone)]
pub(crate) struct LanPeer {
    /// Socket addresses the peer advertised. Empty is possible (relay-only).
    pub(crate) addrs: Vec<SocketAddr>,
    /// When the peer was last (re-)advertised, for the "seen" column.
    pub(crate) last_seen: Instant,
}

/// LAN sightings keyed by transport endpoint id.
#[derive(Default)]
pub(crate) struct LanPeers {
    peers: DashMap<EndpointId, LanPeer>,
}

impl LanPeers {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record (or refresh) a sighting. A re-advertisement replaces the addresses
    /// wholesale, since mDNS records are a full statement of where a peer is.
    pub(crate) fn discovered(&self, id: EndpointId, addrs: Vec<SocketAddr>) {
        self.peers.insert(
            id,
            LanPeer {
                addrs,
                last_seen: Instant::now(),
            },
        );
    }

    /// Drop a peer whose mDNS record expired or was withdrawn.
    pub(crate) fn expired(&self, id: &EndpointId) {
        self.peers.remove(id);
    }

    pub(crate) fn contains(&self, id: &EndpointId) -> bool {
        self.peers.contains_key(id)
    }

    /// Every current sighting, ordered by endpoint id so repeated `ray mdns
    /// scan` runs print rows in a stable order.
    pub(crate) fn snapshot(&self) -> Vec<(EndpointId, LanPeer)> {
        let mut out: Vec<_> = self
            .peers
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        out.sort_by_key(|(id, _)| id.to_string());
        out
    }

    /// Resolve a user-typed id to a LAN peer, never to `me`. Accepts a full
    /// endpoint id or any unique prefix of one (in full or short form), which is
    /// what `ray mdns scan` prints. An ambiguous prefix resolves to nothing
    /// rather than to an arbitrary peer: dialling the wrong neighbour is worse
    /// than an error.
    pub(crate) fn resolve(&self, id_prefix: &str, me: EndpointId) -> Option<EndpointId> {
        if let Ok(id) = id_prefix.parse::<EndpointId>() {
            return (id != me && self.contains(&id)).then_some(id);
        }
        let mut matches = self
            .peers
            .iter()
            .map(|e| *e.key())
            .filter(|id| *id != me)
            .filter(|id| {
                id.to_string().starts_with(id_prefix)
                    || id.fmt_short().to_string().starts_with(id_prefix)
            });
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, 24], port))
    }

    #[test]
    fn records_and_lists_a_sighting() {
        let peers = LanPeers::new();
        peers.discovered(id(1), vec![addr(41641)]);

        let snap = peers.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, id(1));
        assert_eq!(snap[0].1.addrs, vec![addr(41641)]);
        assert!(peers.contains(&id(1)));
    }

    #[test]
    fn readvertisement_replaces_addresses() {
        let peers = LanPeers::new();
        peers.discovered(id(1), vec![addr(41641)]);
        peers.discovered(id(1), vec![addr(57012)]);

        let snap = peers.snapshot();
        assert_eq!(snap.len(), 1, "same peer must not appear twice");
        assert_eq!(snap[0].1.addrs, vec![addr(57012)]);
    }

    #[test]
    fn expiry_removes_the_peer() {
        let peers = LanPeers::new();
        peers.discovered(id(1), vec![addr(41641)]);
        peers.expired(&id(1));

        assert!(peers.snapshot().is_empty());
        assert!(!peers.contains(&id(1)));
        assert_eq!(peers.resolve(&id(1).to_string(), id(9)), None);
    }

    #[test]
    fn snapshot_order_is_stable() {
        let peers = LanPeers::new();
        for seed in [3, 1, 2] {
            peers.discovered(id(seed), vec![]);
        }
        let ids: Vec<_> = peers.snapshot().into_iter().map(|(id, _)| id).collect();
        let mut sorted = ids.clone();
        sorted.sort_by_key(|id| id.to_string());
        assert_eq!(ids, sorted);
    }

    #[test]
    fn resolves_full_id_short_id_and_prefix() {
        let peers = LanPeers::new();
        peers.discovered(id(1), vec![addr(41641)]);

        assert_eq!(peers.resolve(&id(1).to_string(), id(9)), Some(id(1)));
        assert_eq!(
            peers.resolve(&id(1).fmt_short().to_string(), id(9)),
            Some(id(1))
        );
        assert_eq!(peers.resolve(&id(1).to_string()[..6], id(9)), Some(id(1)));
    }

    #[test]
    fn never_resolves_to_ourselves() {
        let peers = LanPeers::new();
        // Our own record can land in the map if the LAN echoes it back.
        peers.discovered(id(1), vec![addr(41641)]);

        assert_eq!(peers.resolve(&id(1).to_string(), id(1)), None);
        assert_eq!(peers.resolve(&id(1).fmt_short().to_string(), id(1)), None);
    }

    #[test]
    fn unknown_id_resolves_to_nothing() {
        let peers = LanPeers::new();
        peers.discovered(id(1), vec![addr(41641)]);

        // A well-formed id that is simply not on this LAN must not resolve: the
        // caller falls back to the pkarr contact lookup instead.
        assert_eq!(peers.resolve(&id(2).to_string(), id(9)), None);
        assert_eq!(peers.resolve("zzzz", id(9)), None);
    }

    #[test]
    fn ambiguous_prefix_resolves_to_nothing() {
        let peers = LanPeers::new();
        // Find two ids sharing a first character, then query with just that.
        let (a, b) = (1..64u8)
            .flat_map(|i| (1..64u8).map(move |j| (i, j)))
            .find(|(i, j)| {
                i != j && id(*i).to_string().as_bytes()[0] == id(*j).to_string().as_bytes()[0]
            })
            .expect("two ids sharing a leading character");
        peers.discovered(id(a), vec![]);
        peers.discovered(id(b), vec![]);

        let shared = &id(a).to_string()[..1];
        assert_eq!(peers.resolve(shared, id(9)), None);
    }
}
