//! Hostname-rename delivery: whether the signed blob has caught up to a pending
//! rename, reading the durable pending intent from config, and the post-reconverge
//! drain that re-sends `MeshHello` to coordinators until the rename lands.

use super::super::*;

/// Decide whether a locally-requested rename has been confirmed by the signed
/// blob. Satisfied when the blob's self-name equals the requested name or its
/// coordinator-assigned collision form `{pending}-{digits}` (e.g. a request for
/// `alice` that the coordinator seated as `alice-1`). Used to clear the pending
/// intent so we stop resending.
pub(crate) fn rename_satisfied(pending: &str, blob: Option<&str>) -> bool {
    match blob {
        Some(name) if name == pending => true,
        Some(name) => name
            .strip_prefix(pending)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
}

/// Whether this node has an unconfirmed rename queued for `network_name`.
/// Gates the reconverge worker's periodic backstop so it idles unless there's
/// a rename to keep delivering.
pub(crate) fn has_pending_hostname(network_name: &str) -> bool {
    matches!(
        config::load_network(network_name),
        Ok(Some(net)) if net.pending_hostname.is_some()
    )
}

/// The hostname this node should announce to peers: a not-yet-confirmed rename
/// intent (`pending_hostname`) if one is queued, otherwise the confirmed name.
/// Read fresh from config at every announce so a rename done mid-session is
/// advertised on the next (re)connect — not a value captured at daemon start.
pub(crate) fn outgoing_hostname(network_name: &str) -> Option<String> {
    match config::load_network(network_name) {
        Ok(Some(net)) => net.pending_hostname.or(net.my_hostname),
        _ => None,
    }
}

/// Drive a queued rename to completion. If `pending_hostname` is still set after
/// a reconverge (i.e. the freshly-applied blob doesn't yet reflect it), dial
/// every coordinator in the roster and re-send `MeshHello(pending)`. A dialed
/// connection is one the coordinator *accepts*, so its control reader always
/// reads the hello regardless of which side first established the mesh link.
/// Runs only while a rename is in flight, so steady state does no extra dialing.
pub(crate) async fn drain_pending_rename(
    endpoint: &Endpoint,
    roster: &[Member],
    alpn: &[u8],
    network_name: &str,
    my_identity: EndpointId,
    my_ip: Ipv4Addr,
    device_cert: &Option<control::DeviceCert>,
) {
    // `apply_roster_to_dns` already cleared the intent if the blob confirmed it,
    // so a value here means it's genuinely still outstanding.
    let Some(pending) = (match config::load_network(network_name) {
        Ok(Some(net)) => net.pending_hostname,
        _ => None,
    }) else {
        return;
    };

    let coordinators: Vec<&Member> = roster
        .iter()
        .filter(|m| m.is_coordinator && m.identity != my_identity)
        .collect();
    tracing::info!(
        network = %network_name,
        hostname = %pending,
        coordinators = coordinators.len(),
        "pending rename outstanding; delivering MeshHello to coordinator set"
    );
    if coordinators.is_empty() {
        tracing::warn!(
            network = %network_name,
            hostname = %pending,
            "no other coordinator in roster to deliver pending rename to; will retry on next reconverge/backstop"
        );
    }

    for m in coordinators {
        match transport::connect_to_peer_with_alpn(endpoint, m.identity, alpn).await {
            Ok(conn) => {
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let _ = control::send_msg(
                        &mut send,
                        &ControlMsg::MeshHello {
                            identity: my_identity,
                            ip: my_ip,
                            hostname: Some(pending.clone()),
                            device_cert: device_cert.clone(),
                        },
                    )
                    .await;
                    tracing::info!(
                        network = %network_name,
                        coordinator = %m.identity.fmt_short(),
                        hostname = %pending,
                        "re-sent pending rename to coordinator"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    network = %network_name,
                    coordinator = %m.identity.fmt_short(),
                    error = %e,
                    "could not reach coordinator to deliver pending rename; will retry"
                );
            }
        }
    }
}
