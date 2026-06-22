//! Persistent Ed25519 identity stored at `~/.config/pitopi/secret_key`.
//!
//! The same keypair is used across restarts, giving each node a stable
//! [`EndpointId`](iroh::EndpointId) and deterministic virtual IP.

use std::path::PathBuf;

use anyhow::{Context, Result};
use iroh::{EndpointId, SecretKey};

use crate::control::DeviceCert;

fn config_dir() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("pitopi");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

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
        std::fs::write(&path, key.to_bytes())?;
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

pub fn create_device_cert(user_secret: &SecretKey, device_pubkey: &EndpointId) -> DeviceCert {
    DeviceCert::create(user_secret, device_pubkey)
}

pub fn store_device_cert(cert: &DeviceCert) -> Result<()> {
    let path = device_cert_path()?;
    let bytes = rmp_serde::to_vec_named(cert).context("serialize device cert")?;
    std::fs::write(&path, bytes).context("write device cert")?;
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
