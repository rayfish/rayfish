//! The per-network **read key** and the sealed envelope it protects.
//!
//! The network public key is a discovery address, not a credential: the pkarr
//! record lives at it, the record names the group blob's hash, and the blob
//! store serves any hash to any dialer. So holding the room id used to buy a
//! full roster read. The read key closes that: the blob's bytes are sealed
//! under it.
//!
//! **The key is in no code.** It is asked for over the mesh
//! (`ControlMsg::ReadKeyRequest`) and granted against the same policy that
//! decides admission, so a code that is copied, refused, or never redeemed
//! opens nothing. A key riding in the bytes of a code could not say that: it
//! would be a read capability from the moment it was written down, outliving
//! the `ray requests deny` that refused its holder.
//!
//! Two properties the rest of the daemon depends on, both load-bearing:
//!
//! **The sealed bytes are what gets hashed.** The pkarr `h,` value doubles as
//! the iroh-blobs content address, and iroh-blobs BLAKE3-verifies a transfer
//! against it, so a hash over the plaintext would fail inside the fetch before
//! any of our code ran. Anything we want bound to the plaintext goes in the
//! AEAD's associated data instead.
//!
//! **Sealing is deterministic.** The nonce is derived from the plaintext, so
//! the same roster always seals to the same bytes and therefore the same hash.
//! A random nonce would make every `refresh_snapshot` produce a new hash for
//! unchanged state, which the lazy publisher reads as a change (it republishes
//! on a hash difference) and two co-coordinators would read as each other
//! reverting the roster. Determinism costs nothing here: the blob is already
//! content-addressed, so equal plaintexts were always observably equal.

use anyhow::{Result, bail};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// Magic prefix on a sealed group blob. Its absence means the bytes are a
/// plaintext blob from before this existed, which `open` still accepts.
const MAGIC: &[u8; 4] = b"rgb1";
const NONCE_LEN: usize = 24;

/// Domain separators for the two subkeys. Both are derived from the read key
/// rather than using it directly, so the value that travels on the wire and
/// sits in config is never itself a cipher key.
const CIPHER_CONTEXT: &str = "rayfish group blob v1";
const NONCE_CONTEXT: &str = "rayfish group blob nonce v1";

/// The per-network roster read key.
///
/// Distinct from the network *secret* key: that one signs and is held only by
/// coordinators, this one decrypts and is held by every member. Splitting them
/// is what lets a read be granted without granting a write.
///
/// `Debug` prints nothing. This value rides control frames and sits in
/// `NetworkConfig`, and a stray `{:?}` on either would otherwise put a roster
/// read capability in the log file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadKey([u8; 32]);

impl std::fmt::Debug for ReadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadKey(<redacted>)")
    }
}

impl ReadKey {
    /// A fresh random key. Called once per network, at `ray create` or on the
    /// first start of a coordinator that predates this feature.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The public commitment published in the pkarr record's `k,` value.
    ///
    /// The record is signed by the network key, so this hash is authentic, and
    /// a node handed a candidate key can check it without asking anyone. That
    /// is what makes [`crate::control::ControlMsg::ReadKeyGrant`] safe to
    /// accept: like `admin_grant_key_valid` for the network key, the grant
    /// authenticates against the signed record rather than against the sender.
    pub fn commitment(&self) -> blake3::Hash {
        blake3::hash(&self.0)
    }

    fn cipher_key(&self) -> [u8; 32] {
        blake3::derive_key(CIPHER_CONTEXT, &self.0)
    }

    fn nonce_key(&self) -> [u8; 32] {
        blake3::derive_key(NONCE_CONTEXT, &self.0)
    }
}

/// Whether `bytes` are a sealed blob rather than a plaintext one.
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

/// Seal a group blob's msgpack bytes: `"rgb1" || nonce(24) || ciphertext+tag`.
///
/// `network` is bound in as associated data, so a blob lifted from one network
/// cannot be replayed as another's even by a holder of both read keys.
pub fn seal(key: &ReadKey, network: &EndpointId, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = derive_nonce(key, plaintext);
    let cipher = XChaCha20Poly1305::new((&key.cipher_key()).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: network.as_bytes(),
            },
        )
        .map_err(|e| anyhow::anyhow!("sealing group blob failed: {e}"))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed group blob.
///
/// Plaintext input is returned untouched: a network created before this feature
/// publishes an unsealed blob, and its members have no key to open one with.
/// Sealed input with no key is an error rather than a silent empty roster.
pub fn open(key: Option<&ReadKey>, network: &EndpointId, bytes: &[u8]) -> Result<Vec<u8>> {
    if !is_sealed(bytes) {
        return Ok(bytes.to_vec());
    }
    let Some(key) = key else {
        bail!("group blob is encrypted and this node holds no read key for the network");
    };
    if bytes.len() < MAGIC.len() + NONCE_LEN {
        bail!("sealed group blob is truncated");
    }
    let nonce = &bytes[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let body = &bytes[MAGIC.len() + NONCE_LEN..];

    let cipher = XChaCha20Poly1305::new((&key.cipher_key()).into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: network.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("group blob did not decrypt under this network's read key"))
}

/// Nonce derived from the plaintext under a subkey of the read key, so sealing
/// is deterministic (see the module docs) without the nonce leaking anything
/// about the plaintext to someone who lacks the key.
fn derive_nonce(key: &ReadKey, plaintext: &[u8]) -> [u8; NONCE_LEN] {
    let full = blake3::keyed_hash(&key.nonce_key(), plaintext);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&full.as_bytes()[..NONCE_LEN]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn net(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        SecretKey::from(b).public()
    }

    fn key(seed: u8) -> ReadKey {
        let mut b = [0u8; 32];
        b[0] = seed;
        ReadKey::from_bytes(b)
    }

    #[test]
    fn seals_and_opens() {
        let k = key(1);
        let n = net(1);
        let sealed = seal(&k, &n, b"roster bytes").unwrap();
        assert!(is_sealed(&sealed));
        assert_eq!(open(Some(&k), &n, &sealed).unwrap(), b"roster bytes");
    }

    /// The property the publisher depends on. `spawn_lazy_publisher` republishes
    /// when the snapshot hash changes, and every member re-seals the roster it
    /// just applied; if sealing were randomized, unchanged state would produce a
    /// new hash on every tick and the record would churn forever.
    #[test]
    fn sealing_is_deterministic() {
        let k = key(1);
        let n = net(1);
        let a = seal(&k, &n, b"roster bytes").unwrap();
        let b = seal(&k, &n, b"roster bytes").unwrap();
        assert_eq!(a, b, "the same roster must seal to the same bytes");
        assert_eq!(
            blake3::hash(&a),
            blake3::hash(&b),
            "and therefore to the same content hash"
        );
    }

    #[test]
    fn a_different_roster_seals_differently() {
        let k = key(1);
        let n = net(1);
        assert_ne!(
            seal(&k, &n, b"roster one").unwrap(),
            seal(&k, &n, b"roster two").unwrap()
        );
    }

    #[test]
    fn the_wrong_key_does_not_open_it() {
        let n = net(1);
        let sealed = seal(&key(1), &n, b"roster bytes").unwrap();
        assert!(open(Some(&key(2)), &n, &sealed).is_err());
    }

    /// The associated data doing its job: the same key on a different network
    /// cannot lift a roster across, so a coordinator of two networks cannot
    /// replay one's blob as the other's.
    #[test]
    fn a_blob_does_not_open_under_another_network() {
        let k = key(1);
        let sealed = seal(&k, &net(1), b"roster bytes").unwrap();
        assert!(open(Some(&k), &net(2), &sealed).is_err());
    }

    /// Back-compat: a network from before this feature publishes plaintext, and
    /// its members hold no key. That has to keep working.
    #[test]
    fn plaintext_passes_through_without_a_key() {
        assert_eq!(open(None, &net(1), b"plain bytes").unwrap(), b"plain bytes");
    }

    #[test]
    fn sealed_bytes_without_a_key_is_an_error() {
        let sealed = seal(&key(1), &net(1), b"roster bytes").unwrap();
        assert!(open(None, &net(1), &sealed).is_err());
    }

    #[test]
    fn truncated_sealed_bytes_do_not_panic() {
        let sealed = seal(&key(1), &net(1), b"roster bytes").unwrap();
        assert!(open(Some(&key(1)), &net(1), &sealed[..10]).is_err());
    }

    /// A read key is a roster read capability, so it must not reach a log line.
    #[test]
    fn debug_does_not_print_the_key() {
        let k = ReadKey::from_bytes([0xab; 32]);
        let rendered = format!("{k:?}");
        assert!(!rendered.contains("ab"), "got {rendered}");
    }
}
