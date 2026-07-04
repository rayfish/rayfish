//! `ray connect` (direct-connection) state and its ALPN accept arm, owned as one
//! unit instead of living loose inside `ProtocolRouter`.
//!
//! Holds the three connect maps (pending/approved/outgoing) and the
//! `CONNECT_ALPN` accept arm. The `ProtocolRouter` accept loop holds an
//! `Arc<ConnectService>` and delegates to it; `MeshManager` holds the same handle
//! for the IPC-side connect commands (`connect`/`connections approve`/…), which
//! mint and join networks over the core registry.

use super::*;

/// A pending incoming `ray connect` request, awaiting `ray connections approve`.
/// Keyed by the requester's transport endpoint id (not contact id) so it
/// survives the requester rotating their contact key.
#[derive(Clone)]
pub(crate) struct PendingConnect {
    pub(crate) from_contact_id: EndpointId,
    pub(crate) from_endpoint: EndpointId,
    pub(crate) hostname: Option<String>,
    pub(crate) requested_at: Instant,
}

pub(crate) struct ConnectService {
    /// `ray connect` requests received on `CONNECT_ALPN`, awaiting approval.
    /// Keyed by the requester's transport endpoint id.
    pub(crate) pending_connects: Arc<DashMap<EndpointId, PendingConnect>>,
    /// Approved connect requests: requester endpoint id → (room id, coordinator).
    /// The `CONNECT_ALPN` handler replies `Approved` from here when the requester
    /// re-dials after `ray connections approve`.
    pub(crate) approved_connects: Arc<DashMap<EndpointId, (EndpointId, EndpointId)>>,
    /// Peer endpoints we have sent an outgoing `ray connect` request to. Used by
    /// the concurrency tie-break: if both peers requested *and* approved each
    /// other, only the higher endpoint id mints, avoiding a duplicate network.
    pub(crate) outgoing_connects: Arc<DashSet<EndpointId>>,
}

impl ConnectService {
    pub(crate) fn new() -> Self {
        Self {
            pending_connects: Arc::new(DashMap::new()),
            approved_connects: Arc::new(DashMap::new()),
            outgoing_connects: Arc::new(DashSet::new()),
        }
    }

    /// `CONNECT_ALPN`: handle a `ray connect` friend request. Binds the request
    /// to the dialing identity, replies `Approved` if already accepted
    /// (idempotent), else queues it as `Pending` for `ray connections approve`.
    pub(crate) async fn accept_connect_request(&self, conn: Connection) {
        let pending = self.pending_connects.clone();
        let approved = self.approved_connects.clone();
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let request: control::ConnectMsg = match control::recv_framed(&mut recv).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read connect request");
                        return;
                    }
                };
                if let control::ConnectMsg::Request {
                    from_contact_id,
                    from_endpoint,
                    hostname,
                } = request
                {
                    // Bind the request to the dialing identity: the
                    // endpoint we pre-approve must be the one that dialed.
                    if from_endpoint != remote_id {
                        tracing::warn!(claimed = %from_endpoint.fmt_short(), actual = %remote_id.fmt_short(), "connect request endpoint mismatch");
                        let _ = control::send_framed(
                            &mut send,
                            &control::ConnectMsg::Denied {
                                reason: "endpoint mismatch".to_string(),
                            },
                        )
                        .await;
                        return;
                    }
                    // Already approved? Reply with the minted room id so
                    // a re-dialing requester joins it (idempotent).
                    let already = approved.get(&from_endpoint).map(|r| *r.value());
                    let reply = if let Some((room_id, coordinator)) = already {
                        control::ConnectMsg::Approved {
                            room_id,
                            coordinator,
                        }
                    } else {
                        pending.insert(
                            from_endpoint,
                            PendingConnect {
                                from_contact_id,
                                from_endpoint,
                                hostname,
                                requested_at: Instant::now(),
                            },
                        );
                        tracing::info!(from = %from_contact_id.fmt_short(), endpoint = %from_endpoint.fmt_short(), "connect request received");
                        control::ConnectMsg::Pending
                    };
                    if let Err(e) = control::send_framed(&mut send, &reply).await {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to send connect reply");
                        return;
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                } else {
                    tracing::warn!(peer = %remote_id.fmt_short(), "unexpected connect message type");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for connect");
            }
        }
    }
}
