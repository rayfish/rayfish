//! Writing, backing up and restoring `/etc/resolv.conf` (Linux direct mode).
//!
//! Every write goes to a temporary file next to the target, is synced, and is
//! renamed over it, so a crash or power cut leaves either the old file or the
//! new one, never a truncated one. Some hosts cannot rename over the file:
//! containers and WSL bind-mount it, and a rename onto a mount point fails with
//! `EBUSY` (or `EXDEV`). There we write in place, and remember that the rename
//! is broken so later writes skip straight to it.
//!
//! A symlinked `/etc/resolv.conf` (to a file under `/run` that NetworkManager,
//! resolvconf or resolved renders) is backed up as a symlink and replaced with
//! a regular file. Writing through the link would edit the other program's
//! file, which it regenerates without telling us, and which the `/etc` watch
//! cannot see. Restoring renames the saved link back, so a crash leaves enough
//! on disk for the next start to put the link back too.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once a rename over the file has failed in a way that will not change.
static RENAME_BROKEN: AtomicBool = AtomicBool::new(false);

/// Set once the "cannot write" warning has been logged.
static WARNED_READ_ONLY: AtomicBool = AtomicBool::new(false);

const DEFAULT_MODE: u32 = 0o644;

/// Whether `path` exists, without following a symlink. A saved symlink whose
/// target is gone (resolved stopped, so `/run/systemd/resolve` is empty) is
/// still a backup to restore.
pub(crate) fn exists_no_follow(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Replace `path` with `contents`, atomically where the host allows it.
pub(crate) fn write_resolv_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let result = write_resolv_file_inner(path, contents);
    if let Err(e) = &result {
        warn_once_if_read_only(path, e);
    }
    result
}

fn write_resolv_file_inner(path: &Path, contents: &[u8]) -> io::Result<()> {
    if !RENAME_BROKEN.load(Ordering::Relaxed) {
        match write_via_rename(path, contents, mode_of(path)) {
            Ok(()) => return Ok(()),
            Err(e) if rename_unsupported(&e) => {
                RENAME_BROKEN.store(true, Ordering::Relaxed);
                tracing::info!(
                    path = %path.display(), error = %e,
                    "cannot replace this file by rename (bind mount?); writing it in place from now on"
                );
            }
            Err(e) => return Err(e),
        }
    }
    write_in_place(path, contents)
}

/// Save `path` to `backup` so [`restore_resolv_backup`] can put it back. A
/// symlink is saved as a symlink to the same target, and left in place: the
/// next [`write_resolv_file`] renames a regular file over it.
pub(crate) fn backup_resolv_file(path: &Path, backup: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        let tmp = temp_path(backup);
        let _ = fs::remove_file(&tmp);
        symlink(&target, &tmp)?;
        if let Err(e) = fs::rename(&tmp, backup) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        sync_parent(backup);
        return Ok(());
    }
    let contents = fs::read(path)?;
    write_via_rename(backup, &contents, meta.permissions().mode() & 0o7777)
}

/// Put `backup` back at `path` and drop it. A rename, so a saved symlink comes
/// back as a symlink and a saved file keeps its mode.
pub(crate) fn restore_resolv_backup(backup: &Path, path: &Path) -> io::Result<()> {
    match fs::rename(backup, path) {
        Ok(()) => {
            sync_parent(path);
            Ok(())
        }
        Err(e) if rename_unsupported(&e) => {
            // Same bind mount that breaks writes: copy the saved contents in.
            let contents = fs::read(backup)?;
            write_in_place(path, &contents)?;
            fs::remove_file(backup)
        }
        Err(e) => {
            warn_once_if_read_only(path, &e);
            Err(e)
        }
    }
}

fn write_via_rename(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let tmp = temp_path(path);
    // A temp file already there is a leftover from a crashed write. Created
    // fresh and never through a link, so a planted symlink cannot redirect the
    // write.
    let _ = fs::remove_file(&tmp);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(contents)?;
        // The umask may have narrowed the mode `open` asked for.
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    sync_parent(path);
    Ok(())
}

fn write_in_place(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(DEFAULT_MODE)
        .open(path)?;
    f.write_all(contents)?;
    f.sync_all()
}

/// The mode to give the replacement: the current file's, so a write does not
/// change who can read it, or 0644 when there is no regular file there.
fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .ok()
        .filter(|m| m.file_type().is_file())
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(DEFAULT_MODE)
}

/// A hidden sibling of `path`. Same directory, so the rename never crosses a
/// filesystem, and a name the `/etc` watch's `resolv.conf` filter ignores.
fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.rayfish-tmp"))
}

fn sync_parent(path: &Path) {
    if let Some(dir) = path.parent()
        && let Ok(d) = File::open(dir)
    {
        let _ = d.sync_all();
    }
}

fn rename_unsupported(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EBUSY | libc::EXDEV))
}

/// An immutable (`chattr +i`) or read-only file fails every write the same
/// way, and the retry loop only logs at debug, so say it once where it shows.
fn warn_once_if_read_only(path: &Path, e: &io::Error) {
    let read_only = matches!(e.raw_os_error(), Some(libc::EPERM | libc::EROFS))
        || e.kind() == io::ErrorKind::PermissionDenied;
    if read_only && !WARNED_READ_ONLY.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            path = %path.display(), error = %e,
            "cannot write this file, so .ray names will not resolve through it; \
             it may be immutable (`lsattr`, `chattr -i`) or on a read-only filesystem"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn write_replaces_the_file_and_keeps_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.0.2.1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        write_resolv_file(&path, b"nameserver 200::53\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 200::53\n");
        assert_eq!(mode(&path), 0o640);
        // No temporary file left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// The case the symlink handling exists for: writing must not go through
    /// the link into the other program's file, and restoring must bring the
    /// link itself back.
    #[test]
    fn a_symlinked_file_is_saved_as_a_link_and_replaced_by_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("managed.conf");
        let path = dir.path().join("resolv.conf");
        let backup = dir.path().join("resolv.conf.before-rayfish");
        fs::write(&target, "nameserver 192.0.2.1\n").unwrap();
        symlink(&target, &path).unwrap();

        backup_resolv_file(&path, &backup).unwrap();
        assert_eq!(fs::read_link(&backup).unwrap(), target);

        write_resolv_file(&path, b"nameserver 200::53\n").unwrap();
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "nameserver 192.0.2.1\n",
            "the link's target was written through"
        );

        restore_resolv_backup(&backup, &path).unwrap();
        assert_eq!(fs::read_link(&path).unwrap(), target);
        assert!(!exists_no_follow(&backup));
    }

    /// A saved link whose target is gone is still a backup.
    #[test]
    fn a_dangling_saved_link_still_counts_as_a_backup() {
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("saved");
        symlink(dir.path().join("gone"), &backup).unwrap();
        assert!(!backup.exists());
        assert!(exists_no_follow(&backup));
    }

    #[test]
    fn a_regular_backup_restores_contents_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        let backup = dir.path().join("resolv.conf.before-rayfish");
        fs::write(&path, "nameserver 192.0.2.1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        backup_resolv_file(&path, &backup).unwrap();
        write_resolv_file(&path, b"nameserver 200::53\n").unwrap();
        restore_resolv_backup(&backup, &path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 192.0.2.1\n");
        assert_eq!(mode(&path), 0o600);
        assert!(!exists_no_follow(&backup));
    }

    #[test]
    fn backing_up_a_missing_file_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("b");
        backup_resolv_file(&dir.path().join("absent"), &backup).unwrap();
        assert!(!exists_no_follow(&backup));
    }
}
