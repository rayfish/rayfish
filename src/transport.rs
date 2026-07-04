//! iroh endpoint setup and peer connection management.
//!
//! Each network gets its own ALPN (`rayfish/net/<version>/<prefix>`) for isolation
//! and mesh-protocol version gating (see `MESH_PROTOCOL_VERSION`).
//! A single shared iroh [`Endpoint`] handles all networks, filtering by ALPN on accept.

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey,
    address_lookup::{PkarrPublisher, PkarrResolver},
    endpoint::Connection,
    endpoint::presets,
    endpoint::{Builder, QuicTransportConfig},
};

use crate::config::ServerOverride;
#[cfg(feature = "tor")]
use std::sync::Arc;

/// ALPN for the file-transfer protocol. The trailing `/1` is its protocol
/// version — **bump it (`/2`, …) on any breaking change to the file wire
/// protocol** (`FileOffer`/blob handshake). iroh negotiates the ALPN at the QUIC
/// handshake, so a peer on a different version shares no common ALPN and the
/// transfer simply can't connect — the version gate needs no in-band check.
pub const FILES_ALPN: &[u8] = b"rayfish/files/1";

/// Identity-level ALPN for the `ray connect` friend-request handshake. Unlike
/// `network_alpn`, this is not per-network — it accepts connection requests
/// addressed to this node's contact key. The trailing `/1` is its protocol
/// version — **bump it on any breaking change to the `ConnectMsg` handshake**;
/// peers on different versions can't negotiate a connection (transport-enforced).
pub const CONNECT_ALPN: &[u8] = b"rayfish/connect/1";

/// Fixed UDP port the endpoint binds so users can port-forward a stable, known
/// port for guaranteed direct reachability (Tailscale-style). Unlike an ephemeral
/// port, this stays the same across daemon restarts, so a manual router forward
/// keeps working and the external NAT mapping doesn't churn. iroh still does
/// automatic NAT traversal (UPnP/NAT-PMP/PCP), discovery, and relay fallback on
/// top of this. If the port is already taken, the endpoint falls back to an
/// ephemeral port (see `create_endpoint_with_alpns`).
pub const RAYFISH_LISTEN_PORT: u16 = 41383;

/// Mesh wire-protocol version, embedded in the per-network ALPN. Bump this on any
/// breaking change to the mesh control/forwarding protocol. Because iroh negotiates
/// the ALPN during the QUIC handshake, two peers on different mesh versions share no
/// common ALPN and simply cannot connect — the version gate is enforced by the
/// transport, with no in-band handshake. Per-network discovery still keys on the
/// pubkey prefix; the version is an independent leading segment.
pub const MESH_PROTOCOL_VERSION: u32 = 1;

pub fn network_alpn(network_pubkey: &EndpointId) -> Vec<u8> {
    let full = network_pubkey.to_string();
    let prefix = &full[..full.len().min(16)];
    format!("rayfish/net/{MESH_PROTOCOL_VERSION}/{prefix}").into_bytes()
}

/// Creates an iroh endpoint with the N0 preset (NAT traversal + relay fallback).
/// When `tor` is true and the `tor` feature is enabled, adds the Tor custom transport
/// alongside the default relay transport.
pub async fn create_endpoint_with_alpns(
    secret_key: SecretKey,
    alpns: Vec<Vec<u8>>,
    tor: bool,
    relay: &ServerOverride,
    discovery: &ServerOverride,
) -> Result<Endpoint> {
    // Bind the fixed port so the daemon is reachable on a known, forwardable UDP
    // port across restarts. The builder is consumed by `.bind()`, so we rebuild
    // it for the ephemeral fallback. Falling back keeps the `0.0.0.0:0` guarantee
    // that the daemon always starts even if the fixed port is already in use.
    let fixed = format!("0.0.0.0:{RAYFISH_LISTEN_PORT}");
    let ep = match bind_endpoint(&secret_key, &alpns, tor, &fixed, relay, discovery).await {
        Ok(ep) => ep,
        Err(e) => {
            tracing::warn!(
                port = RAYFISH_LISTEN_PORT,
                error = %e,
                "fixed UDP port unavailable; falling back to an ephemeral port"
            );
            bind_endpoint(&secret_key, &alpns, tor, "0.0.0.0:0", relay, discovery)
                .await
                .context("failed to bind iroh endpoint")?
        }
    };

    tracing::info!(id = %ep.id().fmt_short(), "iroh endpoint ready");

    Ok(ep)
}

/// Builds and binds an iroh endpoint at `bind` with the N0 preset and (when
/// requested + compiled in) the Tor custom transport. Factored out so the caller
/// can retry with a different bind address after a port collision.
async fn bind_endpoint(
    secret_key: &SecretKey,
    alpns: &[Vec<u8>],
    tor: bool,
    bind: &str,
    relay: &ServerOverride,
    discovery: &ServerOverride,
) -> Result<Endpoint> {
    #[allow(unused_mut)]
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .alpns(alpns.to_vec())
        .clear_ip_transports()
        .bind_addr(bind)
        .context("invalid bind address")?
        // Rayfish's data plane is a single stream of QUIC datagrams per peer
        // (TUN packets → `send_datagram`), with a few reliable control streams per
        // connection. Tune the transport config for that shape:
        //   - `send_fairness(false)`: no competing data streams of equal priority
        //     to round-robin, so fairness scheduling is pure overhead. (Affects
        //     stream scheduling only, not datagrams, but is the correct setting and
        //     removes a small amount of per-packet work.)
        //   - GSO on (default): confirmed explicit so a future change can't silently
        //     regress it. GSO coalesces same-destination segments into one sendmsg,
        //     cutting syscalls under burst.
        //   - Datagrams enabled (iroh/noq default `Some` receive buffer); the send
        //     buffer stays at the 1 MiB default, sized via `datagram_send_buffer_space`
        //     on the hot path (see `forward::run_mesh`).
        // The congestion controller stays at the noq default (Cubic). Switching to
        // BBR3 would help on lossy/shallow-buffer consumer uplinks but requires a
        // `noq-proto` dependency to reach the config type — deferred to a measured
        // follow-up (see iroh-audit BASELINE.md, cross-parameter sweep).
        .transport_config(quic_transport_config());

    // Override the N0 preset's relay / discovery defaults when configured.
    if let Some(mode) = build_relay_mode(relay)? {
        builder = builder.relay_mode(mode);
    }
    builder = apply_discovery(builder, discovery)?;

    #[cfg(feature = "tor")]
    if tor {
        let tor_transport = iroh_tor_transport::TorCustomTransport::builder()
            .build(secret_key.clone())
            .await
            .context("failed to create Tor transport — is Tor running with ControlPort 9051?")?;
        builder = builder
            .add_custom_transport(
                tor_transport.clone() as Arc<dyn iroh::endpoint::transports::CustomTransport>
            )
            .address_lookup(tor_transport.discovery());
        tracing::info!("Tor transport enabled");
    }

    #[cfg(not(feature = "tor"))]
    if tor {
        anyhow::bail!("Tor support requires building with --features tor");
    }

    builder.bind().await.context("failed to bind iroh endpoint")
}

/// Builds the [`QuicTransportConfig`] for rayfish's data-plane shape (one stream
/// of QUIC datagrams per peer, plus a few reliable control streams).
///
/// Starts from iroh's builder defaults (which carry the multipath / NAT-traversal
/// / heartbeat settings required for holepunching) and only overrides the
/// datagram-relevant knobs. See `bind_endpoint` for the rationale.
fn quic_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        // No competing data streams of equal priority → disable round-robin
        // fairness scheduling (removes overhead; correct for a single datagram
        // stream per peer).
        .send_fairness(false)
        // Keep GSO on (default) explicitly so a future change can't silently
        // regress it.
        .enable_segmentation_offload(true)
        .build()
}

/// Build a custom [`RelayMode`] from a relay override, or `None` when unset (in
/// which case the N0 preset's default relays are kept). Replace mode uses only
/// the configured relays; augment mode appends n0's default relay URLs so the
/// node keeps the n0 fallback.
pub fn build_relay_mode(o: &ServerOverride) -> Result<Option<RelayMode>> {
    let urls = crate::config::relay_urls(o)?;
    if urls.is_empty() {
        return Ok(None);
    }
    let mut parsed: Vec<RelayUrl> = urls
        .iter()
        .map(|u| u.parse().with_context(|| format!("invalid relay URL: {u}")))
        .collect::<Result<_>>()?;
    if !o.replace {
        parsed.extend(RelayMode::Default.relay_map().urls::<Vec<RelayUrl>>());
    }
    Ok(Some(RelayMode::custom(parsed)))
}

/// Apply a discovery-DNS override to the endpoint builder. Each configured URL
/// is registered as a pkarr publisher + resolver. Replace mode first clears the
/// preset's address-lookup services (n0 pkarr/DNS); augment mode stacks on top.
fn apply_discovery(mut builder: Builder, o: &ServerOverride) -> Result<Builder> {
    let urls = crate::config::discovery_urls(o)?;
    if urls.is_empty() {
        return Ok(builder);
    }
    if o.replace {
        builder = builder.clear_address_lookup();
    }
    for u in urls {
        let url: url::Url = u
            .parse()
            .with_context(|| format!("invalid discovery URL: {u}"))?;
        builder = builder
            .address_lookup(PkarrPublisher::builder(url.clone()))
            .address_lookup(PkarrResolver::builder(url));
    }
    Ok(builder)
}

#[allow(dead_code)]
pub async fn accept_connection_with_alpn(ep: &Endpoint) -> Result<(Connection, Vec<u8>)> {
    let incoming = ep.accept().await.context("no incoming connection")?;
    let conn = incoming.await.context("failed to accept connection")?;
    let alpn = conn.alpn().to_vec();
    tracing::info!(
        peer = %conn.remote_id().fmt_short(),
        alpn = %String::from_utf8_lossy(&alpn),
        "peer connected"
    );
    Ok((conn, alpn))
}

/// Connects to a peer by EndpointId with a specific ALPN. iroh handles
/// NAT traversal and falls back to relay if direct connection fails.
pub async fn connect_to_peer_with_alpn(
    ep: &Endpoint,
    id: EndpointId,
    alpn: &[u8],
) -> Result<Connection> {
    let addr: EndpointAddr = id.into();
    let conn = match ep.connect(addr, alpn).await {
        Ok(conn) => conn,
        // An ALPN mismatch fails the QUIC/TLS handshake opaquely. Map that one
        // case to an actionable hint (it's a heuristic — a peer that isn't
        // running rayfish at all looks similar — hence "may be").
        Err(e) if is_alpn_mismatch(&e.to_string()) => {
            return Err(e).context(
                "no shared protocol with peer — it may be running an incompatible \
                 rayfish version (run `ray update`)",
            );
        }
        Err(e) => return Err(e).context("failed to connect to peer"),
    };
    tracing::info!(
        peer = %conn.remote_id().fmt_short(),
        alpn = %String::from_utf8_lossy(alpn),
        "connected to peer"
    );
    Ok(conn)
}

/// Heuristic: does a connect error look like an ALPN mismatch (no protocol the
/// two peers share)? iroh/quinn surfaces this as "peer doesn't support any known
/// protocol" / a TLS `no_application_protocol` alert. Matching the message keeps
/// us robust across iroh patch releases without depending on exact error enums.
pub(crate) fn is_alpn_mismatch(err: &str) -> bool {
    let e = err.to_lowercase();
    e.contains("known protocol") || e.contains("application protocol")
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn test_network_alpn() {
        let key = SecretKey::generate().public();
        let alpn = network_alpn(&key);
        let key_str = key.to_string();
        let expected = format!("rayfish/net/{MESH_PROTOCOL_VERSION}/{}", &key_str[..16]);
        assert_eq!(alpn, expected.as_bytes());
    }

    #[test]
    fn relay_mode_augment_vs_replace() {
        // Unset: keep the preset default (None).
        assert!(
            build_relay_mode(&ServerOverride::default())
                .unwrap()
                .is_none()
        );

        // A parseable relay URL (iroh RelayUrl requires a host).
        let custom = "https://relay.example.com".to_string();

        // Replace: only the custom relay.
        let rep = ServerOverride {
            servers: vec![custom.clone()],
            replace: true,
        };
        let mode = build_relay_mode(&rep).unwrap().expect("some mode");
        assert_eq!(mode.relay_map().urls::<Vec<RelayUrl>>().len(), 1);

        // Augment: custom + n0 defaults (more than one).
        let aug = ServerOverride {
            servers: vec![custom],
            replace: false,
        };
        let mode = build_relay_mode(&aug).unwrap().expect("some mode");
        assert!(mode.relay_map().urls::<Vec<RelayUrl>>().len() > 1);
    }

    #[test]
    fn alpn_mismatch_classifier() {
        // iroh/quinn phrasings for "no shared ALPN".
        assert!(is_alpn_mismatch(
            "connection closed: peer doesn't support any known protocol"
        ));
        assert!(is_alpn_mismatch(
            "the cryptographic handshake failed: no application protocol"
        ));
        // Unrelated failures must not be misclassified as version mismatches.
        assert!(!is_alpn_mismatch("connection timed out"));
        assert!(!is_alpn_mismatch("connection refused"));
    }
}
