//! DHT-based network record publishing and resolution.
//!
//! Each network has a single pkarr record containing the group blob hash and
//! seed peer list. Only the coordinator (holder of the per-network secret key)
//! can publish or update the record.

use anyhow::{Context as _, Result, ensure};
use iroh::{
    EndpointId, SecretKey, address_lookup::PkarrRelayClient, dns::DnsResolver, endpoint::Endpoint,
};
use iroh_dns::pkarr::SignedPacket;
use url::Url;

const RECORD_NAME: &str = "_rayfish";
const RECORD_VERSION: &str = "v1";
const RECORD_TTL: u32 = 300;
const PKARR_RELAY_URL: &str = "https://dns.iroh.link/pkarr";

/// Process-wide pkarr relay URL, set once at daemon startup from the
/// `discovery-dns` config. The discovery server is a set-once constant for the
/// daemon's lifetime, so a `OnceLock` avoids threading it through every
/// `create_pkarr_client` caller.
static PKARR_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Point the pkarr client at the configured `discovery-dns` server (first URL
/// wins). No-op when unset, keeping the n0 default. Called once in build_daemon.
pub fn set_discovery_override(o: &crate::config::ServerOverride) {
    if let Ok(urls) = crate::config::discovery_urls(o)
        && let Some(first) = urls.into_iter().next()
    {
        let _ = PKARR_OVERRIDE.set(first);
    }
}

/// The pkarr relay URL in effect: the configured override, else the n0 default.
pub fn effective_pkarr_url() -> String {
    PKARR_OVERRIDE
        .get()
        .cloned()
        .unwrap_or_else(|| PKARR_RELAY_URL.to_string())
}

/// pkarr record name for a user's contact key (`ray connect`). Published under
/// the contact key, it maps the contact id to the user's current transport
/// EndpointId so a peer can dial them without knowing the transport id.
const CONTACT_RECORD_NAME: &str = "_rayfish_contact";

// ---------------------------------------------------------------------------
// Pkarr client
// ---------------------------------------------------------------------------

pub fn create_pkarr_client(ep: &Endpoint) -> Result<PkarrRelayClient> {
    let tls_config = ep.tls_config().clone();
    let dns_resolver: DnsResolver = ep
        .dns_resolver()
        .context("endpoint has no DNS resolver")?
        .clone();
    let relay_url: Url = effective_pkarr_url().parse().expect("relay URL is valid");
    Ok(PkarrRelayClient::new(relay_url, tls_config, dns_resolver))
}

// ---------------------------------------------------------------------------
// Network record encoding / decoding
// ---------------------------------------------------------------------------

/// Encodes a network record into a signed pkarr packet.
///
/// The record contains the group blob hash, a list of seed peers, and the
/// publishing coordinator's mesh protocol version (`m,<v>` =
/// [`transport::MESH_PROTOCOL_VERSION`]). The version lets a joiner detect an
/// incompatible mesh protocol *before* dialing (where the versioned ALPN would
/// otherwise reject it opaquely), so it can surface a precise "run ray update"
/// error. The record is network-key-signed, so the version can't be spoofed.
pub fn encode_network_record(
    key: &SecretKey,
    blob_hash: &blake3::Hash,
    seed_peers: &[EndpointId],
) -> Result<SignedPacket> {
    let mut values = vec![
        RECORD_VERSION.to_string(),
        format!("h,{blob_hash}"),
        format!("m,{}", crate::transport::MESH_PROTOCOL_VERSION),
    ];
    for peer in seed_peers {
        values.push(format!("p,{peer}"));
    }
    SignedPacket::from_txt_strings(key, RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build network record: {e}"))
}

/// Extracts the coordinator's advertised mesh protocol version (`m,<v>`) from a
/// network record, if present. Returns `None` for older records published before
/// the version was added — callers treat that as "unknown, fall through to the
/// ALPN gate" rather than blocking.
pub fn mesh_version_from_record(packet: &SignedPacket) -> Option<u32> {
    packet
        .txt_records(RECORD_NAME)
        .iter()
        .find_map(|r| r.strip_prefix("m,").and_then(|v| v.parse::<u32>().ok()))
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
            blob_hash = Some(
                hash_str
                    .parse::<blake3::Hash>()
                    .context("invalid blob hash")?,
            );
        } else if let Some(id_str) = record.strip_prefix("p,") {
            peers.push(
                id_str
                    .parse::<EndpointId>()
                    .context("invalid peer endpoint ID")?,
            );
        }
    }

    Ok((blob_hash.context("missing blob hash (h,)")?, peers))
}

// ---------------------------------------------------------------------------
// Contact record encoding / decoding (ray connect)
// ---------------------------------------------------------------------------

/// Encode a contact record: maps the contact key to the user's current
/// transport EndpointId. Signed by (and published under) the contact key, so
/// only its holder can publish it. Carries nothing else — no roster, hostname,
/// or member identities.
pub fn encode_contact_record(
    contact_key: &SecretKey,
    endpoint: EndpointId,
) -> Result<SignedPacket> {
    let values = vec![RECORD_VERSION.to_string(), format!("e,{endpoint}")];
    SignedPacket::from_txt_strings(contact_key, CONTACT_RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build contact record: {e}"))
}

pub fn decode_contact_record(packet: &SignedPacket) -> Result<EndpointId> {
    let records = packet.txt_records(CONTACT_RECORD_NAME);
    ensure!(!records.is_empty(), "no contact records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );
    for record in &records[1..] {
        if let Some(id_str) = record.strip_prefix("e,") {
            return id_str
                .parse::<EndpointId>()
                .context("invalid contact endpoint ID");
        }
    }
    anyhow::bail!("missing contact endpoint (e,)")
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

/// Resolves the raw signed network record packet. Use this when you need fields
/// beyond `(blob_hash, seed_peers)` — e.g. [`mesh_version_from_record`] for the
/// pre-dial compatibility check. Decode the standard fields with
/// [`decode_network_record`].
pub async fn resolve_network_packet(
    client: &PkarrRelayClient,
    network_pubkey: EndpointId,
) -> Result<SignedPacket> {
    client
        .resolve(network_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve network record: {e}"))
}

pub async fn resolve_network(
    client: &PkarrRelayClient,
    network_pubkey: EndpointId,
) -> Result<(blake3::Hash, Vec<EndpointId>)> {
    let packet = resolve_network_packet(client, network_pubkey).await?;
    decode_network_record(&packet)
}

/// Publish this user's contact record (`contact_key -> current endpoint`).
pub async fn publish_contact(
    client: &PkarrRelayClient,
    contact_key: &SecretKey,
    endpoint: EndpointId,
) -> Result<()> {
    let packet = encode_contact_record(contact_key, endpoint)?;
    client
        .publish(&packet)
        .await
        .map_err(|e| anyhow::anyhow!("failed to publish contact record: {e}"))
}

/// Resolve a contact id to the holder's current transport EndpointId.
pub async fn resolve_contact(
    client: &PkarrRelayClient,
    contact_pubkey: EndpointId,
) -> Result<EndpointId> {
    let packet = client
        .resolve(contact_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve contact record: {e}"))?;
    decode_contact_record(&packet)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn effective_url_defaults_when_unset() {
        // The OnceLock is process-global; this binary never sets it, so the
        // default holds. (We avoid asserting the set path here to keep tests
        // order-independent.)
        assert_eq!(effective_pkarr_url(), PKARR_RELAY_URL);
    }

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
    fn network_record_carries_mesh_version() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let packet = encode_network_record(&key, &hash, &[]).unwrap();
        // A fresh record advertises this build's mesh protocol version, and the
        // standard hash/peers decode is unaffected by the added field.
        assert_eq!(
            mesh_version_from_record(&packet),
            Some(crate::transport::MESH_PROTOCOL_VERSION)
        );
        assert_eq!(decode_network_record(&packet).unwrap().0, hash);
    }

    #[test]
    fn mesh_version_absent_on_older_record() {
        // A record published before the `m,` field existed (only version + hash).
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let values = vec![RECORD_VERSION.to_string(), format!("h,{hash}")];
        let packet = SignedPacket::from_txt_strings(&key, RECORD_NAME, values, RECORD_TTL).unwrap();
        assert_eq!(mesh_version_from_record(&packet), None);
    }

    #[test]
    fn record_version_check() {
        let key = SecretKey::generate();
        let hash = blake3::hash(b"test");
        let packet = encode_network_record(&key, &hash, &[]).unwrap();
        let records = packet.txt_records("_rayfish");
        assert_eq!(records[0], "v1");
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let key = SecretKey::generate();
        let values = vec!["v99".to_string()];
        let packet = SignedPacket::from_txt_strings(&key, "_rayfish", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported record version")
        );
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
    fn contact_record_roundtrip() {
        let contact = SecretKey::generate();
        let endpoint = SecretKey::generate().public();
        let packet = encode_contact_record(&contact, endpoint).unwrap();
        let decoded = decode_contact_record(&packet).unwrap();
        assert_eq!(decoded, endpoint);
    }

    #[test]
    fn contact_record_rejects_unknown_version() {
        let key = SecretKey::generate();
        let endpoint = SecretKey::generate().public();
        let values = vec!["v99".to_string(), format!("e,{endpoint}")];
        let packet =
            SignedPacket::from_txt_strings(&key, CONTACT_RECORD_NAME, values, 300).unwrap();
        let result = decode_contact_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported record version")
        );
    }

    #[test]
    fn contact_record_rejects_missing_endpoint() {
        let key = SecretKey::generate();
        let values = vec!["v1".to_string()];
        let packet =
            SignedPacket::from_txt_strings(&key, CONTACT_RECORD_NAME, values, 300).unwrap();
        let result = decode_contact_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing contact endpoint")
        );
    }

    #[test]
    fn decode_rejects_missing_hash() {
        let key = SecretKey::generate();
        let peer = SecretKey::generate().public();
        let values = vec!["v1".to_string(), format!("p,{peer}")];
        let packet = SignedPacket::from_txt_strings(&key, "_rayfish", values, 300).unwrap();
        let result = decode_network_record(&packet);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing blob hash")
        );
    }
}
