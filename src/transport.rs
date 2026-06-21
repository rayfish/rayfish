//! iroh endpoint setup and peer connection management.
//!
//! Each network gets its own ALPN (`pitopi/net/<name>`) for isolation.
//! A single shared iroh [`Endpoint`] handles all networks, filtering by ALPN on accept.

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, endpoint::Connection, endpoint::presets,
};

/// Returns the ALPN protocol identifier for a network: `pitopi/net/<pubkey-prefix>`.
/// Uses the first 16 hex chars of the network public key.
pub fn network_alpn(network_pubkey: &str) -> Vec<u8> {
    let prefix = &network_pubkey[..network_pubkey.len().min(16)];
    format!("pitopi/net/{prefix}").into_bytes()
}

/// Creates an iroh endpoint with the N0 preset (NAT traversal + relay fallback).
pub async fn create_endpoint_with_alpns(
    secret_key: SecretKey,
    alpns: Vec<Vec<u8>>,
) -> Result<Endpoint> {
    let ep = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(alpns)
        .clear_ip_transports()
        .bind_addr("0.0.0.0:0")
        .context("invalid bind address")?
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

    #[test]
    fn test_network_alpn() {
        assert_eq!(network_alpn("aa8bc368fec8c227"), b"pitopi/net/aa8bc368fec8c227");
        assert_eq!(
            network_alpn("aa8bc368fec8c2272cbcd07688d3442bac20bc7f60e19a09604a4f9447af5b1d"),
            b"pitopi/net/aa8bc368fec8c227"
        );
    }
}
