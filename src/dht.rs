//! DHT-based network record publishing and resolution.
//!
//! Each network has a single pkarr record containing the group blob hash and
//! seed peer list. Only the coordinator (holder of the per-network secret key)
//! can publish or update the record.

use anyhow::{Context as _, Result, ensure};
use iroh::{
    EndpointId, SecretKey,
    address_lookup::PkarrRelayClient,
    dns::DnsResolver,
    endpoint::Endpoint,
};
use iroh_dns::pkarr::SignedPacket;
use url::Url;

const RECORD_NAME: &str = "_pitopi";
const RECORD_VERSION: &str = "v1";
const RECORD_TTL: u32 = 300;
const PKARR_RELAY_URL: &str = "https://dns.iroh.link/pkarr";

// ---------------------------------------------------------------------------
// Pkarr client
// ---------------------------------------------------------------------------

pub fn create_pkarr_client(ep: &Endpoint) -> Result<PkarrRelayClient> {
    let tls_config = ep.tls_config().clone();
    let dns_resolver: DnsResolver = ep
        .dns_resolver()
        .context("endpoint has no DNS resolver")?
        .clone();
    let relay_url: Url = PKARR_RELAY_URL.parse().expect("relay URL is valid");
    Ok(PkarrRelayClient::new(relay_url, tls_config, dns_resolver))
}

// ---------------------------------------------------------------------------
// Network record encoding / decoding
// ---------------------------------------------------------------------------

/// Encodes a network record into a signed pkarr packet.
///
/// The record contains the group blob hash and a list of seed peers.
pub fn encode_network_record(
    key: &SecretKey,
    blob_hash: &blake3::Hash,
    seed_peers: &[EndpointId],
) -> Result<SignedPacket> {
    let mut values = vec![
        RECORD_VERSION.to_string(),
        format!("h,{blob_hash}"),
    ];
    for peer in seed_peers {
        values.push(format!("p,{peer}"));
    }
    SignedPacket::from_txt_strings(key, RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build network record: {e}"))
}

pub fn decode_network_record(packet: &SignedPacket) -> Result<(blake3::Hash, Vec<EndpointId>)> {
    let records = packet.txt_records(RECORD_NAME);
    ensure!(!records.is_empty(), "no network records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );

    let mut blob_hash = None;
    let mut peers = Vec::new();

    for record in &records[1..] {
        if let Some(hash_str) = record.strip_prefix("h,") {
            blob_hash = Some(hash_str.parse::<blake3::Hash>().context("invalid blob hash")?);
        } else if let Some(id_str) = record.strip_prefix("p,") {
            peers.push(id_str.parse::<EndpointId>().context("invalid peer endpoint ID")?);
        }
    }

    Ok((
        blob_hash.context("missing blob hash (h,)")?,
        peers,
    ))
}

// ---------------------------------------------------------------------------
// Publish / resolve
// ---------------------------------------------------------------------------

pub async fn publish_network(
    client: &PkarrRelayClient,
    key: &SecretKey,
    blob_hash: &blake3::Hash,
    seed_peers: &[EndpointId],
) -> Result<()> {
    let packet = encode_network_record(key, blob_hash, seed_peers)?;
    client
        .publish(&packet)
        .await
        .map_err(|e| anyhow::anyhow!("failed to publish network record: {e}"))
}

pub async fn resolve_network(
    client: &PkarrRelayClient,
    network_pubkey: EndpointId,
) -> Result<(blake3::Hash, Vec<EndpointId>)> {
    let packet = client
        .resolve(network_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve network record: {e}"))?;
    decode_network_record(&packet)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn network_record_roundtrip() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test data");
        let peers = vec![
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        ];
        let packet = encode_network_record(&key, &hash, &peers).unwrap();
        let (decoded_hash, decoded_peers) = decode_network_record(&packet).unwrap();
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded_peers, peers);
    }

    #[test]
    fn network_record_empty_peers() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let packet = encode_network_record(&key, &hash, &[]).unwrap();
        let (decoded_hash, decoded_peers) = decode_network_record(&packet).unwrap();
        assert_eq!(decoded_hash, hash);
        assert!(decoded_peers.is_empty());
    }

    #[test]
    fn record_version_check() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let packet = encode_network_record(&key, &hash, &[]).unwrap();
        let records = packet.txt_records("_pitopi");
        assert_eq!(records[0], "v1");
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let key = SecretKey::generate();
        let values = vec!["v99".to_string()];
        let packet = SignedPacket::from_txt_strings(&key, "_pitopi", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported record version"));
    }

    #[test]
    fn decode_rejects_empty_packet() {
        let key = SecretKey::generate();
        let values = vec!["v1".to_string()];
        let packet = SignedPacket::from_txt_strings(&key, "_other", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_missing_hash() {
        let key = SecretKey::generate();
        let peer = SecretKey::generate().public();
        let values = vec!["v1".to_string(), format!("p,{peer}")];
        let packet = SignedPacket::from_txt_strings(&key, "_pitopi", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing blob hash"));
    }
}
