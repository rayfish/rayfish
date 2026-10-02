//! Terminal, network-key-signed deletion. The separate discovery key is never
//! used by roster publishers, so a stale live publication cannot erase deletion.

use super::*;
use iroh::address_lookup::pkarr::PkarrError;

const DESTROYED: &str = "destroyed";
const KEY_CONTEXT: &str = "rayfish network destruction discovery v1";

pub(crate) fn discovery_key(key: &SecretKey) -> SecretKey {
    SecretKey::from(blake3::derive_key(KEY_CONTEXT, &key.to_bytes()))
}

pub(crate) fn discovery_id(packet: &SignedPacket) -> Option<EndpointId> {
    packet
        .txt_records(RECORD_NAME)
        .iter()
        .find_map(|r| r.strip_prefix("d,").and_then(|id| id.parse().ok()))
}

pub(crate) fn is_destroyed(packet: &SignedPacket) -> bool {
    let records = packet.txt_records(RECORD_NAME);
    records.first().is_some_and(|r| r == RECORD_VERSION) && records.iter().any(|r| r == DESTROYED)
}

pub(crate) fn encode(key: &SecretKey) -> Result<SignedPacket> {
    SignedPacket::from_txt_strings(
        key,
        RECORD_NAME,
        [
            RECORD_VERSION.to_string(),
            DESTROYED.to_string(),
            format!("d,{}", discovery_key(key).public()),
        ],
        RECORD_TTL,
    )
    .map_err(|e| anyhow::anyhow!("encode network destruction: {e}"))
}

pub(crate) fn encode_index(key: &SecretKey, record: &SignedPacket) -> Result<SignedPacket> {
    ensure!(
        record.public_key() == key.public() && is_destroyed(record),
        "invalid destruction record"
    );
    let proof = hex::encode(record.as_bytes());
    let values = std::iter::once(RECORD_VERSION.to_string()).chain(
        proof.as_bytes().chunks(200).map(|chunk| {
            // Hex is ASCII, so these boundaries are always valid UTF-8.
            format!("t,{}", String::from_utf8_lossy(chunk))
        }),
    );
    SignedPacket::from_txt_strings(&discovery_key(key), RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("encode destruction discovery record: {e}"))
}

pub(crate) fn decode_index(packet: &SignedPacket, network: EndpointId) -> Result<SignedPacket> {
    let records = packet.txt_records(RECORD_NAME);
    ensure!(
        records.first().is_some_and(|r| r == RECORD_VERSION),
        "unsupported destruction discovery version"
    );
    let bytes: String = records
        .iter()
        .filter_map(|r| r.strip_prefix("t,"))
        .collect();
    ensure!(!bytes.is_empty(), "missing destruction proof");
    let record = verify_network_record(&hex::decode(bytes)?, network)?;
    ensure!(
        is_destroyed(&record),
        "discovery record is not a destruction proof"
    );
    ensure!(
        discovery_id(&record) == Some(packet.public_key()),
        "wrong destruction discovery key"
    );
    Ok(record)
}

/// A missing discovery record is normal for a live network. Any record returned
/// must carry a valid proof signed by the original network key.
pub(crate) async fn resolve(
    client: &PkarrRelayClient,
    discovery: EndpointId,
    network: EndpointId,
) -> Result<Option<SignedPacket>> {
    match tokio::time::timeout(RESOLVE_TIMEOUT, client.resolve(discovery))
        .await
        .context("timed out checking network destruction")?
    {
        Ok(packet) => Ok(Some(decode_index(&packet, network)?)),
        Err(error) => {
            let error = anyhow::Error::new(error);
            if error.chain().any(|cause| {
                matches!(cause.downcast_ref::<PkarrError>(),
                Some(PkarrError::HttpRequest { status, .. }) if status.as_u16() == 404)
            }) {
                Ok(None)
            } else {
                Err(error.context("could not check network destruction"))
            }
        }
    }
}

pub(crate) async fn publish(client: &PkarrRelayClient, packet: &SignedPacket) -> Result<()> {
    tokio::time::timeout(PUBLISH_TIMEOUT, client.publish(packet))
        .await
        .context("timed out publishing network destruction")?
        .map_err(|e| anyhow::anyhow!("publish network destruction: {e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destruction_is_terminal_and_bound_to_the_network() {
        let key = SecretKey::from([7; 32]);
        let other = SecretKey::from([8; 32]);
        let record = encode(&key).unwrap();
        let index = encode_index(&key, &record).unwrap();
        assert!(is_destroyed(&record));
        assert!(decode_network_record(&record).is_err());
        assert!(verify_network_record(record.as_bytes(), other.public()).is_err());
        assert!(decode_index(&index, other.public()).is_err());
        assert_eq!(
            decode_index(&index, key.public()).unwrap().as_bytes(),
            record.as_bytes()
        );
        assert_ne!(index.public_key(), key.public());
        let active = encode_network_record(&key, &blake3::hash(b"roster"), &[]).unwrap();
        assert!(!is_destroyed(&active));
        assert_eq!(discovery_id(&active), Some(index.public_key()));
        assert!(encode_index(&key, &active).is_err());
    }
}
