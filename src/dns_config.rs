//! OS-level DNS resolver configuration for Magic DNS.
//!
//! Configures the system to route `.pi` queries to our local resolver at 100.64.0.1:53.
//! Supports multiple backends with automatic detection and fallback.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::DNS_DOMAIN;

const RESOLVER_IP: &str = "127.0.0.1";
const BACKUP_SUFFIX: &str = ".before-pitopi";
const HEADER_COMMENT: &str = "# Added by pitopi - do not edit\n";

pub trait DnsConfigurator: Send + Sync {
    fn apply(&self) -> Result<()>;
    fn revert(&self) -> Result<()>;
    fn name(&self) -> &'static str;
}

pub fn detect_and_configure() -> Result<Box<dyn DnsConfigurator>> {
    #[cfg(target_os = "macos")]
    {
        let configurator = MacosResolver;
        configurator.apply()?;
        return Ok(Box::new(configurator));
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(c) = try_systemd_resolved() {
            c.apply()?;
            return Ok(Box::new(c));
        }
        if let Some(c) = try_resolvconf() {
            c.apply()?;
            return Ok(Box::new(c));
        }
        let c = DirectResolvConf;
        c.apply()?;
        return Ok(Box::new(c));
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("DNS configuration not supported on this platform");
    }
}

pub fn restore_stale_backups() {
    let paths = [
        PathBuf::from(format!("/etc/resolver/{DNS_DOMAIN}")),
        PathBuf::from("/etc/resolv.conf"),
    ];
    for path in &paths {
        let backup = backup_path(path);
        if backup.exists() {
            tracing::info!(path = %path.display(), "restoring stale DNS backup from previous crash");
            if let Err(e) = std::fs::copy(&backup, path) {
                tracing::warn!(error = %e, "failed to restore DNS backup");
            }
            let _ = std::fs::remove_file(&backup);
        }
    }
}

fn backup_path(original: &Path) -> PathBuf {
    let mut s = original.as_os_str().to_owned();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

fn backup_file(path: &Path) -> Result<()> {
    let backup = backup_path(path);
    if path.exists() {
        std::fs::copy(path, &backup)
            .with_context(|| format!("backing up {}", path.display()))?;
    }
    Ok(())
}

fn restore_file(path: &Path) -> Result<()> {
    let backup = backup_path(path);
    if backup.exists() {
        std::fs::copy(&backup, path)
            .with_context(|| format!("restoring {}", path.display()))?;
        std::fs::remove_file(&backup)?;
    } else if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS: /etc/resolver/pi
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
struct MacosResolver;

#[cfg(target_os = "macos")]
impl DnsConfigurator for MacosResolver {
    fn apply(&self) -> Result<()> {
        let dir = Path::new("/etc/resolver");
        if !dir.exists() {
            std::fs::create_dir_all(dir).context("creating /etc/resolver")?;
        }
        let path = dir.join(DNS_DOMAIN);
        backup_file(&path)?;
        let content = format!("{HEADER_COMMENT}nameserver {RESOLVER_IP}\n");
        std::fs::write(&path, content).context("writing /etc/resolver file")?;
        tracing::info!("configured macOS scoped resolver for .{DNS_DOMAIN} via {RESOLVER_IP}");
        Ok(())
    }

    fn revert(&self) -> Result<()> {
        let path = PathBuf::from(format!("/etc/resolver/{DNS_DOMAIN}"));
        restore_file(&path)?;
        tracing::info!("reverted macOS resolver configuration");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "macos-scoped-resolver"
    }
}

// ---------------------------------------------------------------------------
// Linux: systemd-resolved
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
struct SystemdResolved {
    tun_iface: String,
}

#[cfg(target_os = "linux")]
fn try_systemd_resolved() -> Option<SystemdResolved> {
    use std::process::Command;
    let output = Command::new("resolvectl").arg("status").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(SystemdResolved {
        tun_iface: "utun_pitopi".to_string(),
    })
}

#[cfg(target_os = "linux")]
impl DnsConfigurator for SystemdResolved {
    fn apply(&self) -> Result<()> {
        use std::process::Command;
        let status = Command::new("resolvectl")
            .args(["dns", &self.tun_iface, RESOLVER_IP])
            .status()
            .context("resolvectl dns")?;
        anyhow::ensure!(status.success(), "resolvectl dns failed");

        let status = Command::new("resolvectl")
            .args(["domain", &self.tun_iface, &format!("~{DNS_DOMAIN}")])
            .status()
            .context("resolvectl domain")?;
        anyhow::ensure!(status.success(), "resolvectl domain failed");

        tracing::info!("configured systemd-resolved for .{DNS_DOMAIN} via {}", self.tun_iface);
        Ok(())
    }

    fn revert(&self) -> Result<()> {
        use std::process::Command;
        let _ = Command::new("resolvectl")
            .args(["revert", &self.tun_iface])
            .status();
        tracing::info!("reverted systemd-resolved configuration");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "systemd-resolved"
    }
}

// ---------------------------------------------------------------------------
// Linux: resolvconf
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
struct Resolvconf;

#[cfg(target_os = "linux")]
fn try_resolvconf() -> Option<Resolvconf> {
    let paths = ["/sbin/resolvconf", "/usr/sbin/resolvconf"];
    if paths.iter().any(|p| Path::new(p).exists()) {
        Some(Resolvconf)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
impl DnsConfigurator for Resolvconf {
    fn apply(&self) -> Result<()> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let config = format!("nameserver {RESOLVER_IP}\n");
        let mut child = Command::new("resolvconf")
            .args(["-a", "tun-pitopi.inet"])
            .stdin(Stdio::piped())
            .spawn()
            .context("spawning resolvconf")?;
        child.stdin.as_mut().unwrap().write_all(config.as_bytes())?;
        let status = child.wait()?;
        anyhow::ensure!(status.success(), "resolvconf -a failed");
        tracing::info!("configured resolvconf for .{DNS_DOMAIN}");
        Ok(())
    }

    fn revert(&self) -> Result<()> {
        use std::process::Command;
        let _ = Command::new("resolvconf")
            .args(["-d", "tun-pitopi.inet"])
            .status();
        tracing::info!("reverted resolvconf configuration");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "resolvconf"
    }
}

// ---------------------------------------------------------------------------
// Linux fallback: direct /etc/resolv.conf
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
struct DirectResolvConf;

#[cfg(target_os = "linux")]
impl DnsConfigurator for DirectResolvConf {
    fn apply(&self) -> Result<()> {
        let path = Path::new("/etc/resolv.conf");
        backup_file(path)?;
        let existing = std::fs::read_to_string(path).unwrap_or_default();
        let new_content = format!("{HEADER_COMMENT}nameserver {RESOLVER_IP}\n{existing}");
        std::fs::write(path, new_content).context("writing /etc/resolv.conf")?;
        tracing::info!("configured /etc/resolv.conf directly (fallback)");
        Ok(())
    }

    fn revert(&self) -> Result<()> {
        let path = Path::new("/etc/resolv.conf");
        restore_file(path)?;
        tracing::info!("reverted /etc/resolv.conf");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "direct-resolv.conf"
    }
}
