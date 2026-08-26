//! Persistent Ed25519 identity stored at `~/.config/rayfish/secret_key`.
//!
//! The same keypair is used across restarts, giving each node a stable
//! [`EndpointId`](iroh::EndpointId) and deterministic virtual IP.

use std::path::PathBuf;

use anyhow::{Context, Result};
use iroh::SecretKey;

use crate::control::DeviceCert;

use crate::config::config_dir;

fn key_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("secret_key"))
}

/// Loads the secret key from disk, or `None` if this device has none yet.
///
/// The distinction [`load_or_create`] erases: a caller that is about to write an
/// identity in (restore) must be able to see "no identity here" without minting
/// one first, or it ends up asking the user for permission to overwrite a key it
/// created a line earlier.
pub fn load_existing() -> Result<Option<SecretKey>> {
    let path = key_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes: [u8; 32] = std::fs::read(&path)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("corrupt secret key file"))?;
    Ok(Some(SecretKey::from_bytes(&bytes)))
}

/// Loads the secret key from disk, or generates and persists a new one.
pub fn load_or_create() -> Result<SecretKey> {
    if let Some(key) = load_existing()? {
        tracing::info!(id = %key.public().fmt_short(), "loaded identity");
        return Ok(key);
    }
    let key = SecretKey::generate();
    crate::config::write_file(&key_path()?, &key.to_bytes(), true)?;
    tracing::info!(id = %key.public().fmt_short(), "generated new identity");
    Ok(key)
}

/// Overwrite the stored identity, as `pair restore` does. The caller is
/// responsible for having asked: this discards whatever key was there, and the
/// old one is unrecoverable without a backup of its own.
pub fn store_secret_key(key: &SecretKey) -> Result<()> {
    let path = key_path()?;
    crate::config::write_file(&path, &key.to_bytes(), true).context("write secret key")?;
    tracing::info!(id = %key.public().fmt_short(), "stored identity");
    Ok(())
}

fn device_cert_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("device_cert"))
}

pub fn store_device_cert(cert: &DeviceCert) -> Result<()> {
    let path = device_cert_path()?;
    let bytes = rmp_serde::to_vec_named(cert).context("serialize device cert")?;
    crate::config::write_file(&path, &bytes, false).context("write device cert")?;
    tracing::info!(user = %cert.user_identity.fmt_short(), "stored device certificate");
    Ok(())
}

/// Delete this device's stored cert (`ray unpair` best-effort wipe on the
/// unpaired device). Idempotent: succeeds if the file is already absent.
pub fn delete_device_cert() -> Result<()> {
    let path = device_cert_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("delete device cert"),
    }
}

pub fn load_device_cert() -> Result<Option<DeviceCert>> {
    let path = device_cert_path()?;
    if path.exists() {
        let bytes = std::fs::read(&path).context("read device cert")?;
        let cert: DeviceCert = rmp_serde::from_slice(&bytes).context("decode device cert")?;
        if !cert.verify() {
            anyhow::bail!("stored device certificate has invalid signature");
        }
        Ok(Some(cert))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CONFIG_ENV_LOCK;

    #[test]
    fn load_existing_is_none_until_something_writes_one() {
        let _env_lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("RAYFISH_CONFIG_DIR", tmp.path());
        }

        // The point of the function: asking must not be what creates it.
        assert!(load_existing().unwrap().is_none());
        assert!(load_existing().unwrap().is_none());

        let created = load_or_create().unwrap();
        let found = load_existing().unwrap().expect("present after create");
        assert_eq!(found.to_bytes(), created.to_bytes());
    }

    #[test]
    fn store_secret_key_replaces_what_was_there() {
        let _env_lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("RAYFISH_CONFIG_DIR", tmp.path());
        }

        let first = load_or_create().unwrap();
        let replacement = SecretKey::generate();
        store_secret_key(&replacement).unwrap();

        let loaded = load_existing().unwrap().expect("present after store");
        assert_eq!(loaded.to_bytes(), replacement.to_bytes());
        assert_ne!(loaded.to_bytes(), first.to_bytes());
    }

    #[test]
    fn device_cert_store_then_load() {
        // Serialize against other tests that mutate `RAYFISH_CONFIG_DIR` (see
        // `daemon::headless_tests`), since lib tests share one process and run
        // on parallel threads.
        let _env_lock = CONFIG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("RAYFISH_CONFIG_DIR", tmp.path());
        }

        let user = SecretKey::generate();
        let device = SecretKey::generate().public();
        let cert = DeviceCert::create(&user, &device, 0);

        assert!(load_device_cert().unwrap().is_none());
        store_device_cert(&cert).unwrap();
        let loaded = load_device_cert()
            .unwrap()
            .expect("cert present after store");
        assert_eq!(loaded.user_identity, cert.user_identity);
        assert_eq!(loaded.device_key, cert.device_key);
        assert!(loaded.verify());
    }
}
