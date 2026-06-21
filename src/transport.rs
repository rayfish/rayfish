//! iroh endpoint setup and peer connection management.
//!
//! Each network gets its own ALPN (`pitopi/net/<name>`) for isolation.
//! A single shared iroh [`Endpoint`] handles all networks, filtering by ALPN on accept.

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, endpoint::Connection, endpoint::presets,
};
#[cfg(feature = "tor")]
use std::sync::Arc;

pub const FILES_ALPN: &[u8] = b"pitopi/files/1";

pub fn network_alpn(network_pubkey: &EndpointId) -> Vec<u8> {
    let full = network_pubkey.to_string();
    let prefix = &full[..full.len().min(16)];
    format!("pitopi/net/{prefix}").into_bytes()
}

/// Creates an iroh endpoint with the N0 preset (NAT traversal + relay fallback).
/// When `tor` is true and the `tor` feature is enabled, adds the Tor custom transport
/// alongside the default relay transport.
pub async fn create_endpoint_with_alpns(
    secret_key: SecretKey,
    alpns: Vec<Vec<u8>>,
    tor: bool,
) -> Result<Endpoint> {
    #[allow(unused_mut)]
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .alpns(alpns)
        .clear_ip_transports()
        .bind_addr("0.0.0.0:0")
        .context("invalid bind address")?;

    #[cfg(feature = "tor")]
    if tor {
        let tor_transport = iroh_tor_transport::TorCustomTransport::builder()
            .build(secret_key)
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

    let ep = builder
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    tracing::info!(id = %ep.id().fmt_short(), "iroh endpoint ready");

    Ok(ep)
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
    let conn = ep
        .connect(addr, alpn)
        .await
        .context("failed to connect to peer")?;
    tracing::info!(
        peer = %conn.remote_id().fmt_short(),
        alpn = %String::from_utf8_lossy(alpn),
        "connected to peer"
    );
    Ok(conn)
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
        let expected = format!("pitopi/net/{}", &key_str[..16]);
        assert_eq!(alpn, expected.as_bytes());
    }
}
