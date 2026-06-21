//! Persistent Ed25519 identity stored at `~/.config/pitopi/secret_key`.
//!
//! The same keypair is used across restarts, giving each node a stable
//! [`EndpointId`](iroh::EndpointId) and deterministic virtual IP.

use std::path::PathBuf;

use anyhow::{Context, Result};
use iroh::SecretKey;

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
        let s = std::fs::read_to_string(&path)
            .context("read collision_index")?;
        s.trim().parse::<u32>()
            .context("parse collision_index")
    } else {
        Ok(0)
    }
}

pub fn save_collision_index(index: u32) -> Result<()> {
    let path = collision_index_path()?;
    std::fs::write(&path, index.to_string())
        .context("write collision_index")
}
