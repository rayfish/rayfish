//! Password-encrypted backups of the user identity (`enc1` blobs).
//!
//! The blob is fixed-layout, 92 bytes, base58-encoded into the single token a
//! user copies:
//!
//! ```text
//! enc1        4 bytes   magic + version
//! salt       16 bytes   random, Argon2 input
//! nonce      24 bytes   random, XChaCha20Poly1305 input
//! ciphertext 48 bytes   the 32-byte secret key + a 16-byte Poly1305 tag
//! ```
//!
//! The magic is inside the encoded bytes, so a printed backup code does not
//! visibly start with `enc1`. It earns its four bytes twice: garbage is
//! rejected with a clear error instead of failing later as "wrong password",
//! and a future `enc2` can change the KDF or cipher while restore still reads
//! both.
//!
//! Encryption is the caller's only protection here. The plaintext is the raw
//! Ed25519 key, so whoever holds the blob and the password holds the identity:
//! the format is built to be pasted into a password manager or handed to a
//! cloud file picker, not to be public.

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use iroh::SecretKey;

const MAGIC: [u8; 4] = *b"enc1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// The 32-byte secret key plus Poly1305's 16-byte tag.
const CIPHERTEXT_LEN: usize = 32 + 16;
const BLOB_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;

/// Derive the wrapping key. Argon2's defaults are the format: changing them
/// silently would make every existing backup undecryptable, so a change here
/// needs a new magic.
fn derive(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut derived = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut derived)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(derived)
}

/// Encrypt `key` under `password` and return the base58 backup code.
pub fn encrypt(key: &SecretKey, password: &str) -> Result<String> {
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    let salt: [u8; SALT_LEN] = rand::random();
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let derived = derive(password, &salt)?;

    let ciphertext = XChaCha20Poly1305::new((&derived).into())
        .encrypt(XNonce::from_slice(&nonce_bytes), key.to_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(bs58::encode(&blob).into_string())
}

/// Decrypt a base58 backup code produced by [`encrypt`].
///
/// A wrong password and a corrupted blob are the same error on purpose: the
/// AEAD cannot tell them apart, and pretending otherwise would invite a caller
/// to treat one as retryable.
pub fn decrypt(code: &str, password: &str) -> Result<SecretKey> {
    let blob = bs58::decode(code.trim())
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid backup code: {e}"))?;
    if blob.len() != BLOB_LEN {
        bail!(
            "invalid backup code: expected {BLOB_LEN} bytes, got {}",
            blob.len()
        );
    }
    if blob[..MAGIC.len()] != MAGIC {
        bail!("invalid backup code: unknown format");
    }

    let salt = &blob[4..4 + SALT_LEN];
    let nonce_bytes = &blob[4 + SALT_LEN..4 + SALT_LEN + NONCE_LEN];
    let ciphertext = &blob[4 + SALT_LEN + NONCE_LEN..];

    let derived = derive(password, salt)?;
    let plaintext = XChaCha20Poly1305::new((&derived).into())
        .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed: wrong password or corrupted backup"))?;

    let key_bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid key data"))?;
    Ok(SecretKey::from_bytes(&key_bytes))
}

/// Encrypt the identity currently on disk, returning the backup code and the
/// public key it belongs to (so a caller can show the user which identity it
/// just wrote out).
pub fn backup_current_identity(password: &str) -> Result<Backup> {
    let key = crate::identity::load_or_create().context("load identity")?;
    Ok(Backup {
        code: encrypt(&key, password)?,
        public_key: key.public().to_string(),
    })
}

/// An identity backup and the public key it restores to.
pub struct Backup {
    pub code: String,
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SecretKey::generate();
        let code = encrypt(&key, "correct horse").unwrap();
        let restored = decrypt(&code, "correct horse").unwrap();
        assert_eq!(restored.to_bytes(), key.to_bytes());
    }

    #[test]
    fn wrong_password_fails() {
        let code = encrypt(&SecretKey::generate(), "right").unwrap();
        let err = decrypt(&code, "wrong").unwrap_err().to_string();
        assert!(err.contains("wrong password"), "unexpected error: {err}");
    }

    #[test]
    fn empty_password_refused() {
        assert!(encrypt(&SecretKey::generate(), "").is_err());
    }

    #[test]
    fn salt_and_nonce_are_fresh_per_backup() {
        // Same key, same password, two calls: identical output would mean a
        // fixed salt or nonce, and a reused XChaCha nonce leaks the keystream.
        let key = SecretKey::generate();
        let a = encrypt(&key, "pw").unwrap();
        let b = encrypt(&key, "pw").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn foreign_magic_rejected() {
        let mut blob = bs58::decode(encrypt(&SecretKey::generate(), "pw").unwrap())
            .into_vec()
            .unwrap();
        blob[3] = b'2';
        let code = bs58::encode(&blob).into_string();
        let err = decrypt(&code, "pw").unwrap_err().to_string();
        assert!(err.contains("unknown format"), "unexpected error: {err}");
    }

    #[test]
    fn truncated_blob_rejected() {
        let code = encrypt(&SecretKey::generate(), "pw").unwrap();
        let blob = bs58::decode(&code).into_vec().unwrap();
        let short = bs58::encode(&blob[..BLOB_LEN - 1]).into_string();
        let err = decrypt(&short, "pw").unwrap_err().to_string();
        assert!(err.contains("expected"), "unexpected error: {err}");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let code = encrypt(&SecretKey::generate(), "pw").unwrap();
        let mut blob = bs58::decode(&code).into_vec().unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        let tampered = bs58::encode(&blob).into_string();
        assert!(decrypt(&tampered, "pw").is_err());
    }

    #[test]
    fn not_base58_rejected() {
        let err = decrypt("not a backup code!", "pw").unwrap_err().to_string();
        assert!(
            err.contains("invalid backup code"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn surrounding_whitespace_tolerated() {
        // Pasted from a password manager or a text file, a trailing newline is
        // the common case, not the odd one.
        let key = SecretKey::generate();
        let code = encrypt(&key, "pw").unwrap();
        let restored = decrypt(&format!("  {code}\n"), "pw").unwrap();
        assert_eq!(restored.to_bytes(), key.to_bytes());
    }
}
