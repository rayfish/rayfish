//! Where the macOS network extension saves received files.
//!
//! The extension runs as root, but macOS privacy controls still refuse it the
//! user's Downloads, Desktop and Documents (`EPERM`). So it saves every file
//! under `INCOMING/<uid>/`, which only that user can open, and the app, which
//! runs as the user, moves each file to the folder it was meant for.
//! Auto-accepted files land in `auto/`; each manual accept gets a directory
//! the app names. Keep [`INCOMING`] in step with `FileHandoff.root` in the app.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, lchown};
use std::path::{Path, PathBuf};

pub(crate) const INCOMING: &str = "/Library/Application Support/Rayfish/Incoming";

/// Create `root/<uid>/auto` for `uid` and return it. `root` is the daemon's
/// own; `<uid>` is handed to the user with mode 0700.
pub(crate) fn prepare(root: &Path, uid: u32) -> io::Result<PathBuf> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(root)?;
    let user = root.join(uid.to_string());
    make_dir(&user)?;
    // Nobody but root can replace an entry of `root`, so `user` is the
    // directory just checked when it is changed below.
    let meta = fs::symlink_metadata(&user)?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            user.display()
        )));
    }
    if meta.uid() != uid {
        lchown(&user, Some(uid), primary_gid(uid))?;
    }
    fs::set_permissions(&user, fs::Permissions::from_mode(0o700))?;
    // The user owns `user` and may swap `auto` for a link, so it is only
    // created and given away here, never followed. The receive refuses a
    // link in an auto-accept directory.
    let auto = user.join("auto");
    make_dir(&auto)?;
    lchown(&auto, Some(uid), primary_gid(uid))?;
    Ok(auto)
}

fn make_dir(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

fn primary_gid(uid: u32) -> Option<u32> {
    let mut buf = vec![0u8; 4096];
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut found = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call: `pwd` and `found` are
    // writable, and `buf` is writable for `buf.len()` bytes. On success
    // `found` points at `pwd`, whose strings point into `buf`.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        return None;
    }
    // SAFETY: `getpwuid_r` succeeded, so it filled in `pwd`.
    let pwd = unsafe { pwd.assume_init() };
    Some(pwd.pw_gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> u32 {
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() }
    }

    #[test]
    fn prepares_a_private_directory_per_user() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Incoming");
        let auto = prepare(&root, me()).unwrap();
        assert_eq!(auto, root.join(me().to_string()).join("auto"));
        assert!(auto.is_dir());
        let mode = fs::metadata(root.join(me().to_string()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        // Running it again keeps what is there.
        fs::write(auto.join("file"), b"x").unwrap();
        assert_eq!(prepare(&root, me()).unwrap(), auto);
        assert!(auto.join("file").exists());
    }

    #[test]
    fn refuses_a_file_in_place_of_the_user_directory() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(me().to_string()), b"x").unwrap();
        assert!(prepare(tmp.path(), me()).is_err());
    }
}
