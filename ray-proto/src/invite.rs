//! Invite-code encoding shared by daemon clients. The byte format is unchanged.

use std::fmt::{self, Debug, Formatter};

use anyhow::{Context, Result, bail};
use iroh::EndpointId;

/// Length of the random invite credential, in bytes.
pub const SECRET_LEN: usize = 16;
/// Bound code length before base58 decoding.
pub const MAX_CODE_LEN: usize = 120;

/// Payload of an invite code, before the checksum: two keys and the secret.
const PAYLOAD_LEN: usize = 32 + 32 + SECRET_LEN;
/// Bytes of blake3 appended as an integrity check (see [`encode_invite_code`]).
const CHECKSUM_LEN: usize = 4;

/// The checksum appended to an invite code: the leading bytes of the payload's
/// blake3 hash. Not a security control (the payload is public and anyone can
/// recompute it), purely error detection so a truncated or mistyped code fails
/// as "invalid invite code" instead of decoding into a plausible-looking
/// invite for a network that doesn't exist.
fn invite_checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let hash = blake3::hash(payload);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&hash.as_bytes()[..CHECKSUM_LEN]);
    out
}

/// Encode an invite code:
/// `bs58(network_pubkey(32) || coordinator(32) || secret(16) || checksum(4))`.
///
/// base58 carries no error detection of its own, so the trailing checksum is
/// what makes a mangled code fail cleanly: without it, dropping a character
/// divides the encoded number by 58 and can still land on a payload of the
/// right length, which then decodes into a well-formed invite pointing
/// nowhere.
pub fn encode_invite_code(
    network_pubkey: &EndpointId,
    coordinator: &EndpointId,
    secret: &[u8],
) -> String {
    let mut bytes = Vec::with_capacity(PAYLOAD_LEN + CHECKSUM_LEN);
    bytes.extend_from_slice(network_pubkey.as_bytes());
    bytes.extend_from_slice(coordinator.as_bytes());
    bytes.extend_from_slice(secret);
    bytes.extend_from_slice(&invite_checksum(&bytes));
    bs58::encode(&bytes).into_string()
}

/// [`decode_invite_code`]'s result, with names instead of positions.
pub struct DecodedInvite {
    pub network_key: EndpointId,
    pub coordinator: EndpointId,
    pub secret: Vec<u8>,
}

impl Debug for DecodedInvite {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedInvite")
            .field("network_key", &self.network_key)
            .field("coordinator", &self.coordinator)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Decode an invite code into `(network_pubkey, coordinator, secret)`.
///
/// Accepts both the checksummed form and the older unchecksummed one, so codes
/// minted before the checksum existed (and codes minted by a peer still on an
/// older build) keep working. A code carrying a checksum must have a correct
/// one.
pub fn decode_invite_code(code: &str) -> Result<DecodedInvite> {
    let code = code.trim();
    // Base58 decoding grows with the square of the length, and codes also
    // arrive from peers, so the length is checked before anything decodes.
    anyhow::ensure!(code.len() <= MAX_CODE_LEN, "invalid invite code: too long");
    let bytes = bs58::decode(code)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid invite code: {e}"))?;

    let payload = match bytes.len() {
        PAYLOAD_LEN => &bytes[..],
        len if len == PAYLOAD_LEN + CHECKSUM_LEN => {
            let (payload, checksum) = bytes.split_at(PAYLOAD_LEN);
            if checksum != invite_checksum(payload) {
                bail!("invalid invite code: checksum mismatch (was it copied in full?)");
            }
            payload
        }
        len => bail!(
            "invalid invite code: expected {} bytes, got {len}",
            PAYLOAD_LEN + CHECKSUM_LEN,
        ),
    };

    let net: [u8; 32] = payload[0..32]
        .try_into()
        .context("reading the invite network key")?;
    let coord: [u8; 32] = payload[32..64]
        .try_into()
        .context("reading the invite coordinator")?;
    let secret = payload[64..].to_vec();
    let network_pubkey = EndpointId::from_bytes(&net)
        .map_err(|e| anyhow::anyhow!("invalid network key in invite: {e}"))?;
    let coordinator = EndpointId::from_bytes(&coord)
        .map_err(|e| anyhow::anyhow!("invalid coordinator key in invite: {e}"))?;
    Ok(DecodedInvite {
        network_key: network_pubkey,
        coordinator,
        secret,
    })
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    #[test]
    fn checksummed_and_legacy_codes_decode_to_the_same_credentials() {
        let network = SecretKey::from_bytes(&[1; 32]).public();
        let coordinator = SecretKey::from_bytes(&[2; 32]).public();
        let secret = [3; SECRET_LEN];
        let code = encode_invite_code(&network, &coordinator, &secret);
        let decoded = decode_invite_code(&code).unwrap();
        assert_eq!(decoded.network_key, network);
        assert_eq!(decoded.coordinator, coordinator);
        assert_eq!(decoded.secret, secret);
        assert!(!format!("{decoded:?}").contains(&format!("{secret:?}")));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(network.as_bytes());
        bytes.extend_from_slice(coordinator.as_bytes());
        bytes.extend_from_slice(&secret);
        let legacy = decode_invite_code(&bs58::encode(&bytes).into_string()).unwrap();
        assert_eq!(legacy.secret, decoded.secret);
        assert_eq!(legacy.coordinator, decoded.coordinator);
    }

    #[test]
    fn corrupted_and_oversized_codes_are_rejected() {
        let network = SecretKey::from_bytes(&[1; 32]).public();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(network.as_bytes());
        bytes.extend_from_slice(network.as_bytes());
        bytes.extend_from_slice(&[3; SECRET_LEN]);
        bytes.extend_from_slice(&[0xff; CHECKSUM_LEN]);
        assert!(
            decode_invite_code(&bs58::encode(bytes).into_string())
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );
        assert!(decode_invite_code(&"1".repeat(MAX_CODE_LEN + 1)).is_err());
    }
}
