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

/// Loads the secret key from disk, or generates and persists a new one.
pub fn load_or_create() -> Result<SecretKey> {
    let path = key_path()?;
    if path.exists() {
        let bytes: [u8; 32] = std::fs::read(&path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt secret key file"))?;
        let key = SecretKey::from_bytes(&bytes);
        tracing::info!(id = %key.public().fmt_short(), "loaded identity");
        Ok(key)
    } else {
        let key = SecretKey::generate();
        crate::config::write_file(&path, &key.to_bytes(), true)?;
        tracing::info!(id = %key.public().fmt_short(), "generated new identity");
        Ok(key)
    }
}

fn collision_index_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("collision_index"))
}

pub fn load_collision_index() -> Result<u32> {
    let path = collision_index_path()?;
    if path.exists() {
        let s = std::fs::read_to_string(&path).context("read collision_index")?;
        s.trim().parse::<u32>().context("parse collision_index")
    } else {
        Ok(0)
    }
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
        let cert = DeviceCert::create(&user, &device);

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
