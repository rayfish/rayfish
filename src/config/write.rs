//! Durable, atomic writes for configuration files.

#[cfg(not(windows))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs::OpenOptions, path::Path};

use anyhow::{Context, Result};

#[cfg(not(windows))]
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub(super) fn sync_file_and_parent(path: &Path) -> Result<()> {
    let dir = path.parent().context("config path has no parent")?;
    OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {} to sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    sync_dir(dir)
}

pub fn write_file(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let dir = path.parent().context("config path has no parent")?;
    super::ensure_dir(dir)?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    #[cfg(windows)]
    let tmp = super::windows_config_stage_path(dir, filename);
    #[cfg(not(windows))]
    let tmp = {
        let sequence = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        dir.join(format!(
            ".{filename}.tmp.{}.{}",
            std::process::id(),
            sequence
        ))
    };

    let staged = stage_temp(&tmp, bytes, secret).and_then(|()| {
        #[cfg(all(windows, not(test)))]
        super::validate_existing_windows_config_child(path)?;
        std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))
    });
    if staged.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return staged;
    }
    sync_dir(dir)
}

fn stage_temp(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    use std::io::Write;

    #[cfg(windows)]
    let mut file = super::create_windows_config_stage(path)?;
    #[cfg(not(windows))]
    let mut file =
        std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;

    #[cfg(windows)]
    let _ = secret;
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let mode = if secret { 0o600 } else { 0o640 };
        let _ = std::fs::set_permissions(path, Permissions::from_mode(mode));
    }
    #[cfg(target_os = "linux")]
    super::set_owner(path, secret);
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = dir;
        Ok(())
    }
    #[cfg(not(windows))]
    std::fs::File::open(dir)
        .with_context(|| format!("opening {} to sync", dir.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", dir.display()))
}

pub(super) fn write_atomic(path: &Path, contents: &str, secret: bool) -> Result<()> {
    write_file(path, contents.as_bytes(), secret)
}

pub fn restrict_perms(path: &Path, secret: bool) {
    #[cfg(all(windows, test))]
    let _ = (path, secret);
    #[cfg(all(windows, not(test)))]
    if secret && let Err(error) = crate::windows_security::protect_file(path) {
        tracing::error!(path = %path.display(), %error, "failed to protect Windows config file");
    }
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let mode = if secret { 0o600 } else { 0o640 };
        let _ = std::fs::set_permissions(path, Permissions::from_mode(mode));
    }
    #[cfg(target_os = "linux")]
    super::set_owner(path, secret);
}
