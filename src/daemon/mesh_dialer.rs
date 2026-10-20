//! `MeshDialer`: at most one outbound mesh dial per peer, with no lock held
//! across the dial.
//!
//! Several callers often want a connection to the same peer at once. Pairing
//! joins every shared network against the primary together, and restore, the
//! connection supervisor and roster dials overlap with it. Dialing separately
//! opens duplicate connections that the peer table then has to choose between.
//!
//! This used to be a per-peer mutex held from the dial until the caller had
//! registered the connection, which also held every other caller through the
//! first one's join handshake. The dial itself is shared instead: a caller that
//! arrives while it is in flight awaits the same result, then runs its own
//! handshake on the connection next to the others. Until one of them registers
//! it in the peer table, the [`DialClaim`]s they hold keep the connection
//! findable here.

use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use iroh::EndpointId;
use iroh::endpoint::{Connection, Endpoint};
use tokio::sync::OnceCell;

use crate::membership::derive_ipv6;
use crate::peers::PeerTable;
use crate::transport;

/// Bound on one shared dial, so a peer with a stale address cannot hold every
/// caller waiting on it for iroh's full handshake timeout.
pub(crate) const MESH_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// One dial's outcome, shared by every caller that waited on it. The error is
/// behind an `Arc` because each waiter gets its own copy of it.
type DialOutcome = Result<Connection, Arc<anyhow::Error>>;

#[derive(Default)]
struct InflightDial {
    outcome: OnceCell<DialOutcome>,
}

impl InflightDial {
    /// Whether a new caller has to dial again instead of reusing this dial.
    fn is_spent(&self) -> bool {
        match self.outcome.get() {
            None => false,
            Some(Ok(conn)) => conn.close_reason().is_some(),
            Some(Err(_)) => true,
        }
    }
}

/// Keeps a dialed, not yet registered connection findable by later callers.
/// Hold it until the connection is registered in the peer table, or until the
/// caller has given up on it, then drop it.
pub(crate) struct DialClaim {
    _dial: Arc<InflightDial>,
}

/// A live connection to a peer.
pub(crate) struct DialedPeer {
    pub(crate) conn: Connection,
    /// `Some` when the connection came from a dial that is not registered yet.
    pub(crate) claim: Option<DialClaim>,
}

/// Shares outbound mesh dials per peer. See the module docs.
#[derive(Default)]
pub(crate) struct MeshDialer {
    inflight: DashMap<EndpointId, Weak<InflightDial>>,
}

impl MeshDialer {
    /// A live mesh connection to `peer`: the registered one from `peers` if
    /// there is one, else the result of the dial already in flight, else a new
    /// dial on the mesh ALPN. Concurrent callers share one dial and its error.
    pub(crate) async fn connect(
        &self,
        endpoint: &Endpoint,
        peers: &PeerTable,
        peer: EndpointId,
    ) -> Result<DialedPeer> {
        let dial = match self.inflight_dial(peers, peer) {
            Joined::Registered(conn) => return Ok(DialedPeer { conn, claim: None }),
            Joined::Dial(dial) => dial,
        };
        // If the caller running the dial is cancelled, the next waiter runs its
        // own copy of this future, so a dropped join cannot strand the others.
        let outcome = dial
            .outcome
            .get_or_init(|| async {
                let alpn = transport::mesh_alpn();
                match tokio::time::timeout(
                    MESH_DIAL_TIMEOUT,
                    transport::connect_to_peer_with_alpn(endpoint, peer, &alpn),
                )
                .await
                {
                    Ok(dialed) => dialed.map_err(Arc::new),
                    Err(_) => Err(Arc::new(anyhow!(
                        "mesh dial timed out after {}s",
                        MESH_DIAL_TIMEOUT.as_secs()
                    ))),
                }
            })
            .await;
        match outcome {
            Ok(conn) => Ok(DialedPeer {
                conn: conn.clone(),
                claim: Some(DialClaim {
                    _dial: Arc::clone(&dial),
                }),
            }),
            Err(error) => Err(anyhow!("{error:#}")),
        }
    }

    /// What to use for `peer`: its registered connection, else the dial in
    /// flight or still claimed, unless it failed or its connection closed, in
    /// which case a fresh one replaces it. The map guard is released before
    /// anything awaits.
    fn inflight_dial(&self, peers: &PeerTable, peer: EndpointId) -> Joined {
        let registered = || {
            peers
                .conn_for_ip(&derive_ipv6(&peer))
                .filter(|conn| conn.close_reason().is_none())
        };
        if let Some(conn) = registered() {
            return Joined::Registered(conn);
        }
        // Drop the entries nobody holds any more, so the map tracks dials in
        // use rather than every peer this daemon has ever dialed.
        self.inflight.retain(|_, dial| dial.strong_count() > 0);
        let mut slot = self.inflight.entry(peer).or_default();
        if let Some(dial) = slot.upgrade().filter(|dial| !dial.is_spent()) {
            return Joined::Dial(dial);
        }
        // Another caller may have registered the shared connection and
        // dropped its claim since the check above. Its claim kept the
        // connection findable until then, so look in the table once more
        // before dialing again.
        if let Some(conn) = registered() {
            return Joined::Registered(conn);
        }
        let dial = Arc::new(InflightDial::default());
        *slot = Arc::downgrade(&dial);
        Joined::Dial(dial)
    }
}

/// Where [`MeshDialer::inflight_dial`] sends a caller.
enum Joined {
    Registered(Connection),
    Dial(Arc<InflightDial>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::presets;
    use iroh::{RelayMode, SecretKey};

    async fn mesh_endpoint(lookup: MemoryLookup) -> Endpoint {
        Endpoint::builder(presets::N0)
            .alpns(vec![transport::mesh_alpn()])
            .address_lookup(lookup)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint")
    }

    /// A client endpoint that can find the server by id alone, and the server.
    async fn client_and_server() -> (Endpoint, Endpoint) {
        let lookup = MemoryLookup::new();
        let server = mesh_endpoint(MemoryLookup::new()).await;
        let client = mesh_endpoint(lookup.clone()).await;
        lookup.add_endpoint_info(server.addr());
        (client, server)
    }

    /// Every caller that asks while a dial is in flight gets that dial's
    /// connection, so the peer sees one connection and the callers can each run
    /// their own handshake on it at the same time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_share_one_dial() {
        let (client, server) = client_and_server().await;
        let accepted = tokio::spawn({
            let server = server.clone();
            async move {
                let mut conns = Vec::new();
                while let Ok(Some(incoming)) =
                    tokio::time::timeout(Duration::from_secs(2), server.accept()).await
                {
                    if let Ok(conn) = incoming.await {
                        conns.push(conn);
                    }
                }
                conns.len()
            }
        });

        let dialer = MeshDialer::default();
        let peers = PeerTable::new();
        let dialed =
            futures::future::join_all((0..4).map(|_| dialer.connect(&client, &peers, server.id())))
                .await;
        let dialed: Vec<DialedPeer> = dialed
            .into_iter()
            .map(|dialed| dialed.expect("the dial reaches the loopback peer"))
            .collect();
        let first = dialed[0].conn.stable_id();
        assert!(dialed.iter().all(|d| d.conn.stable_id() == first));
        assert!(dialed.iter().all(|d| d.claim.is_some()));

        // While a claim is held, a later caller still reuses the connection.
        let later = dialer
            .connect(&client, &peers, server.id())
            .await
            .expect("reuse the claimed connection");
        assert_eq!(later.conn.stable_id(), first);

        assert_eq!(
            accepted.await.expect("accept task"),
            1,
            "the peer must see a single connection"
        );
        client.close().await;
        server.close().await;
    }

    /// A dial nobody holds is dropped from the map on the next lookup.
    #[test]
    fn released_dials_are_pruned() {
        let id = |seed| SecretKey::from_bytes(&[seed; 32]).public();
        let dialer = MeshDialer::default();
        let peers = PeerTable::new();
        drop(dialer.inflight_dial(&peers, id(1)));
        let _held = dialer.inflight_dial(&peers, id(2));
        assert_eq!(dialer.inflight.len(), 1);
    }

    /// Once a caller has registered the dialed connection and dropped its
    /// claim, the next lookup finds it in the table instead of starting a
    /// second dial.
    #[tokio::test]
    async fn registered_after_claim_dropped_is_not_redialed() {
        let (client, server) = client_and_server().await;
        let accept = tokio::spawn({
            let server = server.clone();
            async move { server.accept().await.expect("incoming").await }
        });
        let dialer = MeshDialer::default();
        let peers = PeerTable::new();
        let dialed = dialer
            .connect(&client, &peers, server.id())
            .await
            .expect("the dial reaches the loopback peer");
        let _accepted = accept.await.expect("accept task").expect("accept");
        peers.add(
            derive_ipv6(&server.id()),
            dialed.conn.clone(),
            server.id(),
            "net",
        );
        drop(dialed.claim);

        match dialer.inflight_dial(&peers, server.id()) {
            Joined::Registered(conn) => assert_eq!(conn.stable_id(), dialed.conn.stable_id()),
            Joined::Dial(_) => panic!("a registered peer must not be dialed again"),
        }
        client.close().await;
        server.close().await;
    }

    /// A registered connection wins over dialing, and carries no claim.
    #[tokio::test]
    async fn registered_connection_is_reused_without_a_dial() {
        let (client, server) = client_and_server().await;
        let alpn = transport::mesh_alpn();
        let (conn, _incoming) = tokio::join!(client.connect(server.addr(), &alpn), async {
            server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("accept")
        });
        let conn = conn.expect("dial");
        let peers = PeerTable::new();
        peers.add(derive_ipv6(&server.id()), conn.clone(), server.id(), "net");

        let dialed = MeshDialer::default()
            .connect(&client, &peers, server.id())
            .await
            .expect("registered connection");
        assert_eq!(dialed.conn.stable_id(), conn.stable_id());
        assert!(dialed.claim.is_none());
        client.close().await;
        server.close().await;
    }
}
