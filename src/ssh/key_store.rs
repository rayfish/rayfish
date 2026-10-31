//! Persistent host key for installations without a system SSH host key.

use anyhow::{Context, Result};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};

pub(super) fn load_or_generate_host_key() -> Result<PrivateKey> {
    let path = crate::config::config_dir()?.join("ssh_host_key");
    if path.exists() {
        let pem = std::fs::read_to_string(&path).context("reading ssh host key")?;
        return PrivateKey::from_openssh(&pem).context("parsing ssh host key");
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("generating ssh host key")?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .context("encoding ssh host key")?;
    crate::config::write_file(&path, pem.as_bytes(), true)?;
    Ok(key)
}
