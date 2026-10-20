//! Durable, atomic writes for configuration files.

#[cfg(not(windows))]
use std::fs::File;
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
    let mut file = create_stage(path, secret)?;
    // Set mode and owner before any bytes land, so a secret is never readable
    // by anyone else, even for the moment between write and rename.
    #[cfg(windows)]
    let _ = secret;
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let result = file.set_permissions(Permissions::from_mode(stage_mode(secret)));
        if secret {
            result.with_context(|| format!("setting permissions on {}", path.display()))?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        let gid = super::owner_gid(secret);
        if let Err(error) = std::os::unix::fs::fchown(&file, Some(0), Some(gid)) {
            // An unprivileged caller (tests, a user config dir) cannot chown to
            // root. Its file stays owned by itself with the mode above, which is
            // private enough; as root a failure on a secret is a real error.
            // SAFETY: geteuid has no preconditions and cannot fail.
            if secret && unsafe { libc::geteuid() } == 0 {
                return Err(error).with_context(|| format!("chown {}", path.display()));
            }
            tracing::debug!(path = %path.display(), %error, "chown failed (non-fatal)");
        }
    }
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn stage_mode(secret: bool) -> u32 {
    if secret { 0o600 } else { 0o640 }
}

/// Create the staging file fresh with its final mode. A file already at this
/// name is a leftover from a crashed write (the name carries a pid that can be
/// reused after a reboot), so remove it and try once more rather than writing
/// into a file someone else may hold open.
#[cfg(not(windows))]
fn create_stage(path: &Path, secret: bool) -> Result<File> {
    use std::io::ErrorKind;

    let open = || {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(stage_mode(secret))
                .custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(not(unix))]
        let _ = secret;
        options.open(path)
    };
    match open() {
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale {}", path.display()))?;
            open()
        }
        other => other,
    }
    .with_context(|| format!("creating {}", path.display()))
}

pub(super) fn sync_dir(dir: &Path) -> Result<()> {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("written file exists")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn secret_and_plain_files_get_their_modes() {
        let dir = tempfile::tempdir().expect("tempdir is creatable in tests");
        let secret = dir.path().join("key");
        let plain = dir.path().join("config.toml");
        write_file(&secret, b"secret", true).expect("secret write succeeds");
        write_file(&plain, b"plain", false).expect("plain write succeeds");
        assert_eq!(mode(&secret), 0o600);
        assert_eq!(mode(&plain), 0o640);
        assert_eq!(std::fs::read(&secret).expect("readable"), b"secret");
    }

    #[test]
    fn stage_replaces_a_leftover_temp_file() {
        let dir = tempfile::tempdir().expect("tempdir is creatable in tests");
        let tmp = dir.path().join(".key.tmp.1.0");
        std::fs::write(&tmp, b"stale").expect("seed leftover");
        std::fs::set_permissions(&tmp, Permissions::from_mode(0o644)).expect("chmod leftover");
        stage_temp(&tmp, b"fresh", true).expect("stage over a leftover succeeds");
        assert_eq!(mode(&tmp), 0o600);
        assert_eq!(std::fs::read(&tmp).expect("readable"), b"fresh");
    }
}
