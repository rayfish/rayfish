//! Host-key discovery and SFTP subsystem lookup.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use russh::keys::{Algorithm, PrivateKey};
use tracing::{info, warn};

pub(super) fn load_host_key() -> Result<PrivateKey> {
    if let Some((path, key)) = discover_host_ed25519_key() {
        info!(path = %path.display(), "mesh SSH: reusing host ed25519 key");
        return Ok(key);
    }
    let key = load_or_generate_host_key()?;
    warn!(
        fingerprint = %key.public_key().fingerprint(Default::default()),
        "mesh SSH: no reusable system sshd host key found; serving a generated one. \
         Clients that already know this host by another address will see a host-key \
         change for the mesh name"
    );
    Ok(key)
}

fn discover_host_ed25519_key() -> Option<(PathBuf, PrivateKey)> {
    let dump = run_sshd_dump()?;
    for path in parse_hostkey_paths(&dump) {
        let Ok(pem) = std::fs::read_to_string(&path) else {
            continue;
        };
        match PrivateKey::from_openssh(&pem) {
            Ok(key) if !key.is_encrypted() && key.algorithm() == Algorithm::Ed25519 => {
                return Some((path, key));
            }
            _ => continue,
        }
    }
    None
}

fn run_sshd_dump() -> Option<String> {
    for binary in ["sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd"] {
        match std::process::Command::new(binary)
            .arg("-T")
            .stderr(Stdio::null())
            .output()
        {
            Ok(output) if output.status.success() => return String::from_utf8(output.stdout).ok(),
            _ => continue,
        }
    }
    None
}

pub(super) fn parse_hostkey_paths(dump: &str) -> Vec<PathBuf> {
    dump.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            parts
                .next()?
                .eq_ignore_ascii_case("hostkey")
                .then(|| parts.next().map(PathBuf::from))
                .flatten()
        })
        .collect()
}

const SFTP_SERVER_PATHS: [&str; 5] = [
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/lib/sftp-server",
];

pub(super) fn sftp_subsystem_command() -> Option<String> {
    if let Some(command) = run_sshd_dump().as_deref().and_then(parse_sftp_subsystem) {
        return Some(command);
    }
    SFTP_SERVER_PATHS
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_string())
}

pub(super) fn parse_sftp_subsystem(dump: &str) -> Option<String> {
    dump.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        if !parts.next()?.eq_ignore_ascii_case("subsystem") || parts.next()? != "sftp" {
            return None;
        }
        let command = parts.collect::<Vec<_>>();
        let binary = Path::new(command.first()?);
        (binary.is_absolute() && binary.is_file()).then(|| command.join(" "))
    })
}

fn load_or_generate_host_key() -> Result<PrivateKey> {
    use russh::keys::ssh_key::LineEnding;

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
