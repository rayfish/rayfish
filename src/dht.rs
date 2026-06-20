//! DHT-based membership publishing and resolution.
//!
//! Encodes network membership as signed pkarr DNS TXT records and publishes them
//! to the iroh pkarr relay so peers can discover each other without the coordinator
//! being online.
//!
//! # Record format
//!
//! TXT records are stored under the `_pitopi` DNS name:
//!
//! ```text
//! "v1"                             // version sentinel (always first)
//! "c,<hex_identity>"               // coordinator member
//! "m,<hex_identity>"               // regular member
//! "a,<hex_identity>"               // approved (not yet connected)
//! ```
//!
//! IPs are not stored — they are reconstructed on decode via [`derive_ip`].

use anyhow::{Context as _, Result, bail, ensure};
use iroh::{
    EndpointId, SecretKey,
    address_lookup::PkarrRelayClient,
    dns::DnsResolver,
    endpoint::Endpoint,
};
use iroh_dns::pkarr::SignedPacket;
use url::Url;


// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RECORD_NAME: &str = "_pitopi";
const RECORD_VERSION: &str = "v1";
const RECORD_TTL: u32 = 300;
/// The production pkarr relay run by number 0.
const PKARR_RELAY_URL: &str = "https://dns.iroh.link/pkarr";

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derives a deterministic `SecretKey` for this network's DHT membership record.
///
/// The coordinator publishes membership under this key so that peers can find it
/// using only the coordinator's public key and the network name.
pub fn derive_membership_key(coordinator_key: &SecretKey, network_name: &str) -> SecretKey {
    let context = format!("pitopi/membership/{network_name}");
    let derived = blake3::derive_key(&context, &coordinator_key.to_bytes());
    SecretKey::from_bytes(&derived)
}

/// Returns the `EndpointId` (public key) under which membership is published on the DHT.
pub fn membership_dht_id(coordinator_key: &SecretKey, network_name: &str) -> EndpointId {
    derive_membership_key(coordinator_key, network_name).public()
}

// ---------------------------------------------------------------------------
// Record encoding / decoding
// ---------------------------------------------------------------------------

/// Encodes a membership hash into a signed pkarr packet.
///
/// The record contains only the version tag and a blake3 hash pointer.
/// Peers request the full membership data from any online peer using
/// this hash.
pub fn encode_membership_record(
    key: &SecretKey,
    hash: &str,
) -> Result<SignedPacket> {
    let values = vec![RECORD_VERSION.to_string(), format!("h,{hash}")];
    SignedPacket::from_txt_strings(key, RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build signed packet: {e}"))
}

/// Decodes a signed pkarr packet, extracting the membership hash.
///
/// Accepts both hash-only records (`h,<blake3>`) and legacy member records
/// (`c,`/`m,`/`a,` entries), skipping the latter for forward compatibility.
pub fn decode_membership_record(
    packet: &SignedPacket,
) -> Result<String> {
    let records = packet.txt_records(RECORD_NAME);
    ensure!(!records.is_empty(), "no membership records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );

    for record in &records[1..] {
        if let Some(hash) = record.strip_prefix("h,") {
            return Ok(hash.to_string());
        }
    }

    bail!("no membership hash found in record")
}

// ---------------------------------------------------------------------------
// Pkarr client
// ---------------------------------------------------------------------------

/// Creates a [`PkarrRelayClient`] using the endpoint's TLS and DNS configuration.
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
// Publish / resolve
// ---------------------------------------------------------------------------

/// Publishes a membership hash to the pkarr relay.
pub async fn publish_membership(
    client: &PkarrRelayClient,
    key: &SecretKey,
    hash: &str,
) -> Result<()> {
    let packet = encode_membership_record(key, hash)?;
    client
        .publish(&packet)
        .await
        .map_err(|e| anyhow::anyhow!("failed to publish membership: {e}"))
}

/// Resolves the membership hash from the pkarr relay.
pub async fn resolve_membership_hash(
    client: &PkarrRelayClient,
    dht_id: EndpointId,
) -> Result<String> {
    let packet = client
        .resolve(dht_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve membership: {e}"))?;
    decode_membership_record(&packet)
}

// ---------------------------------------------------------------------------
// Directory record
// ---------------------------------------------------------------------------

/// Derives a deterministic `SecretKey` for this network's DHT directory record.
///
/// The directory record maps a human-readable network name to the network's
/// pkarr pubkey and membership DHT pubkey, allowing peers to discover a network
/// by name without knowing the coordinator's identity in advance.
#[allow(dead_code)]
pub fn derive_directory_key(name: &str) -> SecretKey {
    let derived = blake3::derive_key("pitopi/directory", name.as_bytes());
    SecretKey::from_bytes(&derived)
}

/// Returns the `EndpointId` (public key) under which the directory record is published.
#[allow(dead_code)]
pub fn directory_dht_id(name: &str) -> EndpointId {
    derive_directory_key(name).public()
}

/// Encodes a directory record into a signed pkarr packet.
///
/// The record maps a network name to its coordinator's pkarr pubkey (`n,`) and
/// its membership DHT pubkey (`m,`), enabling name-based network discovery.
#[allow(dead_code)]
pub fn encode_directory_record(
    key: &SecretKey,
    network_pkarr_pubkey: &EndpointId,
    membership_dht_pubkey: &EndpointId,
) -> Result<SignedPacket> {
    let values = vec![
        RECORD_VERSION.to_string(),
        format!("n,{network_pkarr_pubkey}"),
        format!("m,{membership_dht_pubkey}"),
    ];
    SignedPacket::from_txt_strings(key, RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build directory packet: {e}"))
}

/// Decodes a signed pkarr directory packet, extracting the network and membership pubkeys.
#[allow(dead_code)]
pub fn decode_directory_record(packet: &SignedPacket) -> Result<(EndpointId, EndpointId)> {
    let records = packet.txt_records(RECORD_NAME);
    ensure!(!records.is_empty(), "no directory records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );

    let mut network_pub = None;
    let mut membership_pub = None;

    for record in &records[1..] {
        if let Some(id_str) = record.strip_prefix("n,") {
            network_pub = Some(id_str.parse::<EndpointId>().context("invalid network pubkey")?);
        } else if let Some(id_str) = record.strip_prefix("m,") {
            membership_pub =
                Some(id_str.parse::<EndpointId>().context("invalid membership pubkey")?);
        }
    }

    Ok((
        network_pub.context("missing network pkarr pubkey (n,)")?,
        membership_pub.context("missing membership DHT pubkey (m,)")?,
    ))
}

/// Publishes a directory record to the pkarr relay.
#[allow(dead_code)]
pub async fn publish_directory(
    client: &PkarrRelayClient,
    key: &SecretKey,
    network_pkarr_pubkey: &EndpointId,
    membership_dht_pubkey: &EndpointId,
) -> Result<()> {
    let packet = encode_directory_record(key, network_pkarr_pubkey, membership_dht_pubkey)?;
    client
        .publish(&packet)
        .await
        .map_err(|e| anyhow::anyhow!("failed to publish directory: {e}"))
}

/// Resolves the directory record for a network name from the pkarr relay.
#[allow(dead_code)]
pub async fn resolve_directory(
    client: &PkarrRelayClient,
    name: &str,
) -> Result<(EndpointId, EndpointId)> {
    let dht_id = directory_dht_id(name);
    let packet = client
        .resolve(dht_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve directory: {e}"))?;
    decode_directory_record(&packet)
}

// ---------------------------------------------------------------------------
// Seed list record
// ---------------------------------------------------------------------------

/// Encodes a list of bootstrap peer `EndpointId`s into a signed pkarr packet.
///
/// Each peer is encoded as a `p,<endpoint_id>` TXT value. The list may be empty.
#[allow(dead_code)]
pub fn encode_seed_list_record(key: &SecretKey, peers: &[EndpointId]) -> Result<SignedPacket> {
    let mut values = vec![RECORD_VERSION.to_string()];
    for peer in peers {
        values.push(format!("p,{peer}"));
    }
    SignedPacket::from_txt_strings(key, RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build seed list packet: {e}"))
}

/// Decodes a signed pkarr seed list packet, returning the list of peer `EndpointId`s.
#[allow(dead_code)]
pub fn decode_seed_list_record(packet: &SignedPacket) -> Result<Vec<EndpointId>> {
    let records = packet.txt_records(RECORD_NAME);
    ensure!(!records.is_empty(), "no seed list records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );

    let mut peers = Vec::new();
    for record in &records[1..] {
        if let Some(id_str) = record.strip_prefix("p,") {
            peers.push(id_str.parse::<EndpointId>().context("invalid peer endpoint ID")?);
        }
    }
    Ok(peers)
}

/// Publishes a seed list to the pkarr relay.
#[allow(dead_code)]
pub async fn publish_seed_list(
    client: &PkarrRelayClient,
    key: &SecretKey,
    peers: &[EndpointId],
) -> Result<()> {
    let packet = encode_seed_list_record(key, peers)?;
    client
        .publish(&packet)
        .await
        .map_err(|e| anyhow::anyhow!("failed to publish seed list: {e}"))
}

/// Resolves the seed list from the pkarr relay using the seed list's public key.
#[allow(dead_code)]
pub async fn resolve_seed_list(
    client: &PkarrRelayClient,
    seed_list_pubkey: EndpointId,
) -> Result<Vec<EndpointId>> {
    let packet = client
        .resolve(seed_list_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve seed list: {e}"))?;
    decode_seed_list_record(&packet)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    // -- Key derivation -------------------------------------------------------

    #[test]
    fn test_derive_membership_key_deterministic() {
        let key = SecretKey::generate();
        let k1 = derive_membership_key(&key, "gaming");
        let k2 = derive_membership_key(&key, "gaming");
        assert_eq!(k1.public(), k2.public());
    }

    #[test]
    fn test_derive_membership_key_differs_by_network() {
        let key = SecretKey::generate();
        let k1 = derive_membership_key(&key, "gaming");
        let k2 = derive_membership_key(&key, "work");
        assert_ne!(k1.public(), k2.public());
    }

    #[test]
    fn test_membership_dht_id() {
        let key = SecretKey::generate();
        let dht_id = membership_dht_id(&key, "gaming");
        let derived = derive_membership_key(&key, "gaming");
        assert_eq!(dht_id, derived.public());
    }

    #[test]
    fn test_derive_membership_key_differs_from_source() {
        let key = SecretKey::generate();
        let derived = derive_membership_key(&key, "gaming");
        assert_ne!(key.public(), derived.public());
    }

    // -- Hash encode / decode roundtrip ---------------------------------------

    #[test]
    fn test_encode_decode_hash_roundtrip() {
        let key = SecretKey::generate();
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let packet = encode_membership_record(&key, hash).unwrap();
        let decoded = decode_membership_record(&packet).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_record_version_check() {
        let key = SecretKey::generate();
        let packet = encode_membership_record(&key, "somehash").unwrap();
        let records = packet.txt_records("_pitopi");
        assert_eq!(records[0], "v1");
    }

    #[test]
    fn test_decode_skips_legacy_entries() {
        let key = SecretKey::generate();
        let values = vec!["v1", "c,legacy_id", "h,the_real_hash", "m,another_legacy"];
        let packet = SignedPacket::from_txt_strings(&key, "_pitopi", values, 300).unwrap();
        let hash = decode_membership_record(&packet).unwrap();
        assert_eq!(hash, "the_real_hash");
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        let key = SecretKey::generate();
        let values = vec!["v99".to_string()];
        let packet = SignedPacket::from_txt_strings(&key, "_pitopi", values, 300).unwrap();
        let result = decode_membership_record(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported record version"));
    }

    #[test]
    fn test_decode_rejects_empty_packet() {
        let key = SecretKey::generate();
        let values = vec!["v1".to_string()];
        let packet = SignedPacket::from_txt_strings(&key, "_other", values, 300).unwrap();
        let result = decode_membership_record(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no membership records found"));
    }

    #[test]
    fn test_decode_rejects_missing_hash() {
        let key = SecretKey::generate();
        let values = vec!["v1", "c,some_identity"];
        let packet = SignedPacket::from_txt_strings(&key, "_pitopi", values, 300).unwrap();
        let result = decode_membership_record(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no membership hash"));
    }

    // -- Directory record tests -----------------------------------------------

    #[test]
    fn directory_record_roundtrip() {
        let name = "bright-copper-moon";
        let dir_key = derive_directory_key(name);
        let net_key = SecretKey::generate();
        let mem_key = SecretKey::generate();
        let packet =
            encode_directory_record(&dir_key, &net_key.public(), &mem_key.public()).unwrap();
        let (net_pub, mem_pub) = decode_directory_record(&packet).unwrap();
        assert_eq!(net_pub, net_key.public());
        assert_eq!(mem_pub, mem_key.public());
    }

    #[test]
    fn directory_key_is_deterministic() {
        let a = derive_directory_key("test-name-one");
        let b = derive_directory_key("test-name-one");
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn different_names_produce_different_directory_keys() {
        let a = derive_directory_key("test-alpha-one");
        let b = derive_directory_key("test-beta-two");
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn directory_dht_id_matches_key() {
        let name = "calm-silver-wave";
        let key = derive_directory_key(name);
        let id = directory_dht_id(name);
        assert_eq!(id, key.public());
    }

    // -- Seed list record tests -----------------------------------------------

    #[test]
    fn seed_list_record_roundtrip() {
        let key = SecretKey::generate();
        let peers = vec![
            SecretKey::generate().public(),
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        ];
        let packet = encode_seed_list_record(&key, &peers).unwrap();
        let decoded = decode_seed_list_record(&packet).unwrap();
        assert_eq!(decoded, peers);
    }

    #[test]
    fn seed_list_empty_roundtrip() {
        let key = SecretKey::generate();
        let packet = encode_seed_list_record(&key, &[]).unwrap();
        let decoded = decode_seed_list_record(&packet).unwrap();
        assert!(decoded.is_empty());
    }
}
