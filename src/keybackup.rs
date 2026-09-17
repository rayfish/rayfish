//! Password-encrypted backups of the device identity and its saved networks.
//!
//! Backups are base58-encoded encrypted blobs. `enc1` contains only the device
//! key; `enc2` contains a msgpack payload with the key, pairing certificate,
//! and saved network configs:
//!
//! ```text
//! enc1/enc2   4 bytes   magic + version
//! salt       16 bytes   random, Argon2 input
//! nonce      24 bytes   random, XChaCha20Poly1305 input
//! ciphertext variable  encrypted payload + a 16-byte Poly1305 tag
//! ```
//!
//! The magic is inside the encoded bytes, so a printed backup code does not
//! visibly start with `enc1` or `enc2`. The format byte rejects unrelated input
//! and keeps old key-only backups readable.
//!
//! Encryption is the caller's only protection here. The plaintext contains the
//! Ed25519 key, so whoever holds the blob and password holds the identity:
//! the format is built to be pasted into a password manager or handed to a
//! cloud file picker, not to be public.

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};

use crate::config::{self, NetworkConfig};
use crate::control::DeviceCert;

const MAGIC_V1: [u8; 4] = *b"enc1";
const MAGIC_V2: [u8; 4] = *b"enc2";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// The 32-byte secret key plus Poly1305's 16-byte tag.
const CIPHERTEXT_LEN: usize = 32 + 16;
const BLOB_LEN: usize = MAGIC_V1.len() + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;
const MAX_PLAINTEXT_LEN: usize = 256 * 1024;
const MAX_CODE_LEN: usize = 512 * 1024;

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    secret_key: [u8; 32],
    device_cert: Option<DeviceCert>,
    networks: Vec<NetworkConfig>,
}

pub struct RestoredBackup {
    pub secret_key: SecretKey,
    pub device_cert: Option<DeviceCert>,
    pub networks: Vec<NetworkConfig>,
}

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
    encrypt_bytes(&MAGIC_V1, &key.to_bytes(), password)
}

fn encrypt_bytes(magic: &[u8; 4], plaintext: &[u8], password: &str) -> Result<String> {
    if password.is_empty() {
        bail!("password cannot be empty");
    }
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        bail!("identity backup is too large");
    }

    let salt: [u8; SALT_LEN] = rand::random();
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let derived = derive(password, &salt)?;

    let ciphertext = XChaCha20Poly1305::new((&derived).into())
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut blob = Vec::with_capacity(magic.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(magic);
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
    Ok(decrypt_backup(code, password)?.secret_key)
}

pub fn decrypt_backup(code: &str, password: &str) -> Result<RestoredBackup> {
    anyhow::ensure!(code.len() <= MAX_CODE_LEN, "invalid backup code: too large");
    let blob = bs58::decode(code.trim())
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid backup code: {e}"))?;
    if blob.len() < MAGIC_V1.len() {
        bail!("invalid backup code: too short");
    }
    let is_v1 = blob[..MAGIC_V1.len()] == MAGIC_V1;
    let is_v2 = blob[..MAGIC_V2.len()] == MAGIC_V2;
    if !is_v1 && !is_v2 {
        bail!("invalid backup code: unknown format");
    }
    if is_v1 && blob.len() != BLOB_LEN {
        bail!(
            "invalid backup code: expected {BLOB_LEN} bytes, got {}",
            blob.len()
        );
    }
    if blob.len() < MAGIC_V2.len() + SALT_LEN + NONCE_LEN + 16
        || blob.len() > MAGIC_V2.len() + SALT_LEN + NONCE_LEN + MAX_PLAINTEXT_LEN + 16
    {
        bail!("invalid backup code: invalid length");
    }

    let salt = &blob[4..4 + SALT_LEN];
    let nonce_bytes = &blob[4 + SALT_LEN..4 + SALT_LEN + NONCE_LEN];
    let ciphertext = &blob[4 + SALT_LEN + NONCE_LEN..];

    let derived = derive(password, salt)?;
    let plaintext = XChaCha20Poly1305::new((&derived).into())
        .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed: wrong password or corrupted backup"))?;

    let payload = if is_v1 {
        let key_bytes: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key data"))?;
        BackupPayload {
            secret_key: key_bytes,
            device_cert: None,
            networks: Vec::new(),
        }
    } else {
        rmp_serde::from_slice::<BackupPayload>(&plaintext).context("invalid backup contents")?
    };
    let secret_key = SecretKey::from_bytes(&payload.secret_key);
    if let Some(cert) = &payload.device_cert {
        anyhow::ensure!(cert.verify(), "invalid backup device certificate");
        anyhow::ensure!(
            cert.device_key == secret_key.public(),
            "backup certificate belongs to another device"
        );
    }
    Ok(RestoredBackup {
        secret_key,
        device_cert: payload.device_cert,
        networks: payload.networks,
    })
}

/// Encrypt the identity currently on disk, returning the backup code and the
/// public key it belongs to (so a caller can show the user which identity it
/// just wrote out).
pub fn backup_current_identity(password: &str) -> Result<Backup> {
    let key = crate::identity::load_or_create().context("load identity")?;
    let device_cert = crate::identity::load_device_cert().context("load device certificate")?;
    if let Some(cert) = &device_cert {
        anyhow::ensure!(
            cert.device_key == key.public(),
            "device certificate belongs to another identity"
        );
    }
    let networks = config::load().context("load saved networks")?.networks;
    let payload = BackupPayload {
        secret_key: key.to_bytes(),
        device_cert,
        networks,
    };
    let plaintext = rmp_serde::to_vec_named(&payload).context("encode backup")?;
    Ok(Backup {
        code: encrypt_bytes(&MAGIC_V2, &plaintext, password)?,
        public_key: key.public().to_string(),
    })
}

/// Restore the saved pairing proof and networks. An identity replacement removes
/// the old identity's networks; restoring the same key keeps newer local settings.
pub fn restore_metadata(backup: &RestoredBackup, same_identity: bool) -> Result<()> {
    for net in &backup.networks {
        // Validate all names before replacing any saved config. This also rejects
        // path components that could escape the per-network directory.
        let _ = config::load_network(&net.name)?;
        anyhow::ensure!(
            net.network_public_key.is_some() || net.network_secret_key.is_some(),
            "backup network has no key"
        );
    }
    if !same_identity {
        for old in config::load()?.networks {
            config::delete_network(&old.name)?;
        }
    }
    if let Some(cert) = &backup.device_cert {
        let existing = if same_identity {
            crate::identity::load_device_cert()?
        } else {
            None
        };
        let keep_existing = same_identity
            && existing.as_ref().is_some_and(|current| {
                current.device_key == cert.device_key
                    && current.user_identity == cert.user_identity
                    && current.generation >= cert.generation
            });
        if !keep_existing {
            crate::identity::store_device_cert(cert)?;
        }
    } else if !same_identity {
        crate::identity::delete_device_cert()?;
    }
    for net in &backup.networks {
        if !same_identity || config::load_network(&net.name)?.is_none() {
            config::save_network(net)?;
        }
    }
    Ok(())
}

/// An identity backup and the public key it restores to.
pub struct Backup {
    pub code: String,
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CONFIG_ENV_LOCK;

    #[test]
    fn round_trip() {
        let key = SecretKey::generate();
        let code = encrypt(&key, "correct horse").unwrap();
        let restored = decrypt(&code, "correct horse").unwrap();
        assert_eq!(restored.to_bytes(), key.to_bytes());
    }

    #[test]
    fn paired_backup_restores_certificate_and_networks() {
        let _env_lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", temp.path()) };

        let key = SecretKey::generate();
        let primary = SecretKey::generate();
        let cert = DeviceCert::create(&primary, &key.public(), 2);
        let network_key = SecretKey::generate().public();
        let net = NetworkConfig {
            name: "restored".to_string(),
            network_public_key: Some(network_key),
            ..NetworkConfig::default()
        };
        crate::identity::store_secret_key(&key).unwrap();
        crate::identity::store_device_cert(&cert).unwrap();
        config::save_network(&net).unwrap();
        let code = backup_current_identity("password").unwrap().code;
        crate::identity::delete_device_cert().unwrap();
        config::delete_network("restored").unwrap();
        let restored = decrypt_backup(&code, "password").unwrap();
        assert_eq!(restored.secret_key.public(), key.public());
        let old = NetworkConfig {
            name: "old".to_string(),
            network_public_key: Some(SecretKey::generate().public()),
            ..NetworkConfig::default()
        };
        config::save_network(&old).unwrap();
        restore_metadata(&restored, false).unwrap();
        assert_eq!(crate::identity::load_device_cert().unwrap(), Some(cert));
        assert!(config::load_network("old").unwrap().is_none());
        assert_eq!(
            config::load_network("restored")
                .unwrap()
                .unwrap()
                .network_public_key,
            Some(network_key)
        );

        match previous {
            Some(path) => unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", path) },
            None => unsafe { std::env::remove_var("RAYFISH_CONFIG_DIR") },
        }
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
        blob[3] = b'3';
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
