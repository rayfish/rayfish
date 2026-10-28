//! Host-key discovery and SFTP subsystem lookup.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use russh::keys::{Algorithm, PrivateKey};
use tracing::{info, warn};

const DEFAULT_HOST_KEY_PATHS: [&str; 2] = [
    "/etc/ssh/ssh_host_ed25519_key",
    "/usr/local/etc/ssh/ssh_host_ed25519_key",
];

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
    let dump = run_sshd_dump();
    for path in host_key_paths(dump.as_deref()) {
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

pub(super) fn host_key_paths(sshd_dump: Option<&str>) -> Vec<PathBuf> {
    match sshd_dump {
        Some(dump) => parse_hostkey_paths(dump),
        None => DEFAULT_HOST_KEY_PATHS.iter().map(PathBuf::from).collect(),
    }
}

/// How long `sshd -T` may take. It reads config and host keys, nothing slow,
/// so one that has not answered by now is wedged.
const SSHD_DUMP_TIMEOUT: Duration = Duration::from_secs(5);

fn run_sshd_dump() -> Option<String> {
    for binary in ["sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd"] {
        let mut command = Command::new(binary);
        command.arg("-T");
        if let Some(dump) = bounded_output(command, SSHD_DUMP_TIMEOUT) {
            return Some(dump);
        }
    }
    None
}

/// Run `command` and return its stdout if it exits successfully within
/// `timeout`. One that hangs is killed rather than holding up the caller.
fn bounded_output(mut command: Command, timeout: Duration) -> Option<String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Drained on its own thread so a large dump cannot fill the pipe and stall
    // the child while we wait on it.
    let mut stdout = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).map(|_| out)
    });
    let status = crate::child::wait_bounded(&mut child, timeout);
    let out = reader.join().ok()?.ok()?;
    if !status.ok()?.success() {
        return None;
    }
    String::from_utf8(out).ok()
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

/// How long a looked-up sftp command is reused before `sshd -T` runs again.
/// Long enough that a burst of `scp` runs costs one lookup, short enough that
/// installing sftp-server or editing sshd_config is picked up without a restart.
const SFTP_COMMAND_TTL: Duration = Duration::from_secs(60);

struct CachedSftpCommand {
    at: Instant,
    command: Option<String>,
}

/// The sftp server command, cached for [`SFTP_COMMAND_TTL`]. Blocking: it may
/// run `sshd -T`, so async callers go through `spawn_blocking`.
pub(super) fn sftp_subsystem_command() -> Option<String> {
    static CACHE: Mutex<Option<CachedSftpCommand>> = Mutex::new(None);
    // Held across the lookup on purpose, so concurrent requests share one
    // `sshd -T` instead of each starting their own.
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cached) = cache.as_ref()
        && cached.at.elapsed() < SFTP_COMMAND_TTL
    {
        return cached.command.clone();
    }
    let command = lookup_sftp_subsystem_command();
    *cache = Some(CachedSftpCommand {
        at: Instant::now(),
        command: command.clone(),
    });
    command
}

fn lookup_sftp_subsystem_command() -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hung_sshd_dump_is_killed_not_waited_on() {
        let mut command = Command::new("sleep");
        command.arg("30");
        let started = Instant::now();
        assert_eq!(bounded_output(command, Duration::from_millis(200)), None);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_quick_command_returns_its_output() {
        let mut command = Command::new("echo");
        command.arg("subsystem sftp /bin/true");
        assert_eq!(
            bounded_output(command, Duration::from_secs(10)).as_deref(),
            Some("subsystem sftp /bin/true\n")
        );
    }
}
