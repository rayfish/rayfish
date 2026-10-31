//! Where an accepted file lands, opened without trusting the path.
//!
//! The daemon runs as root, but the directory a file is saved to comes from a
//! local caller (`ray files accept -o`) and the file name from a peer. Writing
//! through a plain path would let either one aim root's write elsewhere: a
//! symlink planted at the file name redirects it, and a directory the caller
//! cannot write to is one they could never have put a file in themselves.
//!
//! So the directory is opened once and everything after that is relative to
//! the descriptor: its owner is checked with `fstat` on the open directory (not
//! the path, which can change underneath), missing components are created with
//! `mkdirat` and handed to the recipient before descending into them, and the
//! file itself is created with `O_CREAT | O_EXCL | O_NOFOLLOW`, so nothing that
//! already exists at the name is ever opened, let alone followed.

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf, absolute};

use super::Recipient;
use super::dest_name::{MAX_NAME_ATTEMPTS, missing_names, numbered_name, root_len};

/// Where a newly created destination file sits: its directory and the name it
/// was created under, after any collision suffix.
pub(super) struct Destination {
    dir: OwnedFd,
    pub(super) name: OsString,
}

impl Destination {
    /// Remove the file again, after a failed write. Best effort: the error
    /// that caused the cleanup is the one worth reporting.
    pub(super) fn discard(&self) {
        let Ok(name) = c_name(&self.name) else {
            return;
        };
        // SAFETY: `self.dir` is an open directory descriptor owned by this
        // struct and `name` is a valid NUL-terminated string that outlives the
        // call.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            tracing::debug!(
                "remove partial {:?}: {}",
                self.name,
                io::Error::last_os_error()
            );
        }
    }
}

/// Open (creating as needed) `dir` for `recipient` and create `file_name` in
/// it, or a free `name (n).ext` variant when the name is taken. Returns the
/// empty file, owned by the recipient, ready to be written.
pub(super) fn create(
    dir: &Path,
    file_name: &str,
    recipient: Recipient,
) -> io::Result<(Destination, File)> {
    let dir = open_dir(dir, &recipient)?;
    let (name, file) = create_file(&dir, file_name, recipient.owner)?;
    Ok((Destination { dir, name }, file))
}

/// Open `path` as a directory, creating its missing trailing components.
fn open_dir(path: &Path, recipient: &Recipient) -> io::Result<OwnedFd> {
    // A relative path means the daemon's working directory, as it always has;
    // the walk below needs the absolute form to find an existing ancestor.
    let path = &absolute(path)?;
    let components: Vec<Component<'_>> = path.components().collect();
    // Find the deepest prefix that already exists. Nothing is created until
    // that directory has passed the owner check, so a refused request leaves
    // no trace on disk.
    let mut existing = components.len();
    let mut dir = loop {
        let prefix: PathBuf = components[..existing].iter().collect();
        match open_dir_at(None, prefix.as_os_str(), false) {
            Ok(fd) => break fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound && existing > root_len(path) => {
                existing -= 1
            }
            Err(e) => return Err(with_path(e, path)),
        }
    };
    let missing = missing_names(path, existing)?;
    check_dir_owner(&dir, recipient, path)?;
    for name in missing {
        make_dir_at(&dir, name, recipient.owner).map_err(|e| with_path(e, path))?;
        dir = open_dir_at(Some(&dir), name, true).map_err(|e| with_path(e, path))?;
        check_dir_owner(&dir, recipient, path)?;
    }
    Ok(dir)
}

/// `mkdirat` one component, handing it to `owner` when this call created it.
fn make_dir_at(parent: &OwnedFd, name: &OsStr, owner: Option<(u32, u32)>) -> io::Result<()> {
    let c = c_name(name)?;
    // SAFETY: `parent` is an open directory descriptor for the duration of the
    // call and `c` is a valid NUL-terminated string.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
        let e = io::Error::last_os_error();
        // Created concurrently: it is checked like any existing directory.
        if e.kind() == io::ErrorKind::AlreadyExists {
            return Ok(());
        }
        return Err(e);
    }
    if let Some((uid, gid)) = owner {
        // SAFETY: as above; `AT_SYMLINK_NOFOLLOW` keeps the call on the entry
        // itself should it have been swapped for a link since `mkdirat`.
        let rc = unsafe {
            libc::fchownat(
                parent.as_raw_fd(),
                c.as_ptr(),
                uid,
                gid,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            tracing::debug!("chown {name:?}: {}", io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Open a directory, relative to `parent` when given. `no_follow` refuses a
/// symlink as the last component; the caller-named path itself may contain
/// links (a `~/Downloads` pointing at another disk), since what is checked is
/// the directory the descriptor ends up on.
fn open_dir_at(parent: Option<&OwnedFd>, name: &OsStr, no_follow: bool) -> io::Result<OwnedFd> {
    let c = c_name(name)?;
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if no_follow {
        flags |= libc::O_NOFOLLOW;
    }
    let base = parent.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
    // SAFETY: `base` is `AT_FDCWD` or a descriptor borrowed from `parent` for
    // the call, and `c` is a valid NUL-terminated string.
    let fd = unsafe { libc::openat(base, c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` just returned this descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Refuse a directory the recipient does not own, when they chose it.
fn check_dir_owner(dir: &OwnedFd, recipient: &Recipient, path: &Path) -> io::Result<()> {
    let Some(uid) = recipient.required_dir_owner() else {
        return Ok(());
    };
    // SAFETY: an all-zero `stat` is a valid value for the out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is an open descriptor and `st` is a valid, writable
    // `stat` that lives for the call.
    if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
        return Err(with_path(io::Error::last_os_error(), path));
    }
    if st.st_uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "'{}' is not owned by uid {uid}; choose a directory of your own",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Create `file_name` (or the first free `name (n).ext`) in `dir`, exclusively
/// and without following a link, then hand it to `owner`.
fn create_file(
    dir: &OwnedFd,
    file_name: &str,
    owner: Option<(u32, u32)>,
) -> io::Result<(OsString, File)> {
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let name = numbered_name(file_name, attempt);
        let c = c_name(OsStr::new(&name))?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `dir` is an open directory descriptor, `c` a valid
        // NUL-terminated string, and the mode argument is supplied because
        // `O_CREAT` is set.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, 0o644 as libc::c_uint) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(e);
        }
        // SAFETY: `openat` just returned this descriptor and nothing else owns it.
        let file = unsafe { File::from_raw_fd(fd) };
        if let Some((uid, gid)) = owner {
            // SAFETY: `file` holds an open descriptor for the call.
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                tracing::debug!("chown {name}: {}", io::Error::last_os_error());
            }
        }
        return Ok((OsString::from(name), file));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("'{file_name}' and its numbered alternatives all exist"),
    ))
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.to_os_string().into_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn with_path(e: io::Error, path: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("'{}': {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn me() -> (u32, u32) {
        // SAFETY: getuid and getgid cannot fail and touch no memory.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    fn caller(owner: (u32, u32)) -> Recipient {
        Recipient {
            owner: Some(owner),
            caller_chose_dir: true,
        }
    }

    #[test]
    fn a_directory_someone_else_owns_is_refused_and_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid) = me();
        let other = (uid.wrapping_add(1).max(1), gid);
        let nested = tmp.path().join("new/sub");
        let Err(e) = create(&nested, "f.bin", caller(other)) else {
            panic!("a directory owned by another uid must be refused");
        };
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            !tmp.path().join("new").exists(),
            "nothing is created under a refused directory"
        );
        let Err(e) = create(tmp.path(), "f.bin", caller(other)) else {
            panic!("a directory owned by another uid must be refused");
        };
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(!tmp.path().join("f.bin").exists());
    }

    #[test]
    fn root_and_configured_targets_skip_the_owner_check() {
        let tmp = tempfile::tempdir().unwrap();
        let other = me().0.wrapping_add(1).max(1);
        let configured = Recipient {
            owner: None,
            caller_chose_dir: false,
        };
        assert!(create(tmp.path(), "a.bin", configured).is_ok());
        let auto = Recipient {
            owner: Some((other, other)),
            caller_chose_dir: false,
        };
        assert_eq!(auto.required_dir_owner(), None);
        assert_eq!(caller((0, 0)).required_dir_owner(), None);
    }

    #[test]
    fn a_link_at_the_name_is_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let dir = tmp.path().join("in");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("f.bin")).unwrap();
        let (dest, _file) = create(&dir, "f.bin", caller(me())).unwrap();
        assert_eq!(dest.name, "f (1).bin");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(dir.join("f.bin").symlink_metadata().unwrap().is_symlink());
    }

    #[test]
    fn an_escaping_path_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let escape = tmp.path().join("missing/../../x");
        assert!(create(&escape, "f.bin", caller(me())).is_err());
        assert!(!tmp.path().join("missing").exists());
    }

    #[test]
    fn created_directories_and_files_belong_to_the_recipient() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b");
        create(&nested, "f.bin", caller(me())).unwrap();
        let (uid, _) = me();
        assert_eq!(std::fs::metadata(tmp.path().join("a")).unwrap().uid(), uid);
        assert_eq!(std::fs::metadata(&nested).unwrap().uid(), uid);
        assert_eq!(std::fs::metadata(nested.join("f.bin")).unwrap().uid(), uid);
    }

    #[test]
    fn discard_removes_the_created_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (dest, _file) = create(tmp.path(), "f.bin", caller(me())).unwrap();
        dest.discard();
        assert!(!tmp.path().join("f.bin").exists());
    }
}
