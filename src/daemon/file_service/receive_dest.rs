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
//!
//! The file is written under a temporary name and moved to its real name only
//! once every byte is on disk, without replacing anything already there. A
//! receive that is canceled or interrupted partway removes the temporary file,
//! so it never leaves a truncated file under the name a retry would then have
//! to number around.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf, absolute};

use super::Recipient;
use super::dest_name::{MAX_NAME_ATTEMPTS, missing_names, numbered_name, root_len, temp_name};

/// A received file being written under a temporary name in its directory.
/// Dropping it before [`Staged::commit`] removes the temporary file.
pub(super) struct Staged {
    dir: OwnedFd,
    temp: OsString,
    /// The name the file should end up under, before any collision suffix.
    wanted: String,
    committed: bool,
}

impl Staged {
    /// Move the written file to its name, or the first free `name (n).ext`,
    /// never replacing an existing entry. Returns the name it got.
    pub(super) fn commit(mut self) -> io::Result<OsString> {
        let temp = c_name(&self.temp)?;
        for attempt in 0..MAX_NAME_ATTEMPTS {
            let name = numbered_name(&self.wanted, attempt);
            let to = c_name(OsStr::new(&name))?;
            match rename_no_replace(&self.dir, &temp, &to) {
                Ok(()) => {
                    self.committed = true;
                    return Ok(OsString::from(name));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("'{}' and its numbered alternatives all exist", self.wanted),
        ))
    }
}

impl Drop for Staged {
    /// Remove the partial file. Best effort: whatever stopped the receive is
    /// the error worth reporting.
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let Ok(name) = c_name(&self.temp) else {
            return;
        };
        if let Err(e) = unlink_at(&self.dir, &name) {
            tracing::debug!("remove partial {:?}: {e}", self.temp);
        }
    }
}

/// Open (creating as needed) `dir` for `recipient` and create a temporary
/// file in it for `file_name`. Returns the empty file, owned by the
/// recipient, ready to be written and then committed.
pub(super) fn create(
    dir: &Path,
    file_name: &str,
    recipient: Recipient,
) -> io::Result<(Staged, File)> {
    let dir = open_dir(dir, &recipient)?;
    let (temp, file) = create_temp(&dir, recipient.owner)?;
    let staged = Staged {
        dir,
        temp,
        wanted: file_name.to_string(),
        committed: false,
    };
    Ok((staged, file))
}

/// How far the directory a file lands in is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DirTrust {
    /// Root asked, or an embedder that runs as the user anyway: root could
    /// write there itself.
    Any,
    /// The caller with this uid named the directory. The path may go through
    /// links (a Downloads folder on another disk), but the directory it ends
    /// on must be theirs.
    Owner(u32),
    /// Root configured the directory, for this non-root uid if any. Trusted
    /// as configured only when no component is a link: a user who can
    /// replace part of the path (their own `~/Downloads`) could otherwise
    /// point it at `/etc`. Through a link, it must end on the uid's own
    /// directory, as for [`DirTrust::Owner`].
    Configured(Option<u32>),
}

/// Open `path` as a directory, creating its missing trailing components.
fn open_dir(path: &Path, recipient: &Recipient) -> io::Result<OwnedFd> {
    // A relative path means the daemon's working directory, as it always has;
    // the walk below needs the absolute form to find an existing ancestor.
    let path = &absolute(path)?;
    let trust = recipient.dir_trust();
    // Find the deepest prefix that already exists. Nothing is created until
    // that directory has passed the check, so a refused request leaves no
    // trace on disk.
    let walked = match trust {
        DirTrust::Configured(_) => walk_without_links(path)?,
        DirTrust::Any | DirTrust::Owner(_) => None,
    };
    let link_free = walked.is_some();
    let (mut dir, existing) = match walked {
        Some(found) => found,
        None => deepest_existing(path)?,
    };
    let missing = missing_names(path, existing)?;
    check_dir(&dir, trust, link_free, path)?;
    for name in missing {
        make_dir_at(&dir, name, recipient.owner).map_err(|e| with_path(e, path))?;
        dir = open_dir_at(Some(&dir), name, true).map_err(|e| with_path(e, path))?;
        check_dir(&dir, trust, link_free, path)?;
    }
    Ok(dir)
}

/// The deepest existing prefix of `path`, opened through any links in it,
/// and how many components it has.
fn deepest_existing(path: &Path) -> io::Result<(OwnedFd, usize)> {
    let components: Vec<Component<'_>> = path.components().collect();
    let mut existing = components.len();
    loop {
        let prefix: PathBuf = components[..existing].iter().collect();
        match open_dir_at(None, prefix.as_os_str(), false) {
            Ok(fd) => return Ok((fd, existing)),
            Err(e) if e.kind() == io::ErrorKind::NotFound && existing > root_len(path) => {
                existing -= 1
            }
            Err(e) => return Err(with_path(e, path)),
        }
    }
}

/// Like [`deepest_existing`], but one component at a time from the root,
/// each opened relative to the last without following a link. `None` when a
/// component is a link.
fn walk_without_links(path: &Path) -> io::Result<Option<(OwnedFd, usize)>> {
    let components: Vec<Component<'_>> = path.components().collect();
    let root = root_len(path);
    let prefix: PathBuf = components[..root].iter().collect();
    let mut dir = open_dir_at(None, prefix.as_os_str(), true).map_err(|e| with_path(e, path))?;
    for (index, component) in components.iter().enumerate().skip(root) {
        let name = component.as_os_str();
        match open_dir_at(Some(&dir), name, true) {
            Ok(next) => dir = next,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Some((dir, index))),
            Err(e) => {
                if is_link_at(&dir, name)? {
                    return Ok(None);
                }
                return Err(with_path(e, path));
            }
        }
    }
    Ok(Some((dir, components.len())))
}

/// Whether `name` in `dir` is a symbolic link.
fn is_link_at(dir: &OwnedFd, name: &OsStr) -> io::Result<bool> {
    let c = c_name(name)?;
    // SAFETY: an all-zero `stat` is a valid value for the out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is an open directory descriptor, `c` a valid
    // NUL-terminated string and `st` a writable `stat` for the call.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFLNK)
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

/// Refuse a directory `trust` does not allow. `link_free` is whether the
/// path to it was walked without following a link.
fn check_dir(dir: &OwnedFd, trust: DirTrust, link_free: bool, path: &Path) -> io::Result<()> {
    let uid = match trust {
        DirTrust::Any => return Ok(()),
        DirTrust::Configured(_) if link_free => return Ok(()),
        DirTrust::Owner(uid) | DirTrust::Configured(Some(uid)) => uid,
        DirTrust::Configured(None) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "'{}' goes through a link; set the download directory to the real path",
                    path.display()
                ),
            ));
        }
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

/// Create a fresh temporary file in `dir`, exclusively and without
/// following a link, then hand it to `owner`.
fn create_temp(dir: &OwnedFd, owner: Option<(u32, u32)>) -> io::Result<(OsString, File)> {
    for _ in 0..MAX_NAME_ATTEMPTS {
        let name = temp_name();
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
        "could not pick a free temporary file name",
    ))
}

/// Rename `from` to `to` inside `dir`, failing with `AlreadyExists` rather
/// than replacing an entry at `to`.
///
/// An exclusive rename where the kernel has one. Where the filesystem lacks
/// it, a hard link to the new name (which fails on an existing entry) and an
/// unlink of the old one. Where it has neither (Android's shared storage), a
/// plain rename after checking the name is free: the only race left is with
/// something created in the same directory at that moment, and a rename moves
/// the entry itself, so even then nothing is written through a link.
fn rename_no_replace(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    match exclusive_rename(dir, from, to) {
        Err(e) if unsupported(&e) => {}
        result => return result,
    }
    match link_no_replace(dir, from, to) {
        // Android's shared storage refuses hard links with `EPERM`.
        Err(e) if unsupported(&e) || e.raw_os_error() == Some(libc::EPERM) => {}
        result => return result,
    }
    checked_rename(dir, from, to)
}

/// Hard-link `from` as `to`, which fails on an existing entry, then unlink
/// `from`.
fn link_no_replace(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is an open directory descriptor for the call and both
    // names are valid NUL-terminated strings.
    let linked = unsafe {
        libc::linkat(
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    };
    if linked != 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(e) = unlink_at(dir, from) {
        tracing::warn!("remove temporary {from:?} after saving: {e}");
    }
    Ok(())
}

/// A plain rename once `to` is known to be free.
fn checked_rename(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    if exists_at(dir, to)? {
        return Err(io::Error::from(io::ErrorKind::AlreadyExists));
    }
    // SAFETY: `dir` is an open directory descriptor for the call and both
    // names are valid NUL-terminated strings.
    if unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `renameat2(RENAME_NOREPLACE)`. Called through `syscall` since not every
/// libc wraps it. Not on Android, whose app sandbox filters system calls and
/// on older releases kills the process for one it does not know.
#[cfg(target_os = "linux")]
fn exclusive_rename(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is an open directory descriptor for the call, both names
    // are valid NUL-terminated strings, and `renameat2` takes exactly these
    // five arguments.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
fn exclusive_rename(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is an open directory descriptor for the call and both
    // names are valid NUL-terminated strings.
    let rc = unsafe {
        libc::renameatx_np(
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn exclusive_rename(_dir: &OwnedFd, _from: &CStr, _to: &CStr) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// The filesystem or kernel does not offer the operation at all.
fn unsupported(e: &io::Error) -> bool {
    // `ENOTSUP` and `EOPNOTSUPP` are one value on Linux and two on macOS.
    e.raw_os_error().is_some_and(|code| {
        [libc::EINVAL, libc::ENOSYS, libc::ENOTSUP, libc::EOPNOTSUPP].contains(&code)
    })
}

/// Whether anything, a dangling link included, is at `name` in `dir`.
fn exists_at(dir: &OwnedFd, name: &CStr) -> io::Result<bool> {
    // SAFETY: an all-zero `stat` is a valid value for the out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is an open directory descriptor, `name` a valid
    // NUL-terminated string and `st` a writable `stat` for the call.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::NotFound {
        return Ok(false);
    }
    Err(e)
}

fn unlink_at(dir: &OwnedFd, name: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is an open directory descriptor for the call and `name`
    // is a valid NUL-terminated string.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    use std::io::Write;
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

    fn configured(owner: Option<(u32, u32)>) -> Recipient {
        Recipient {
            owner,
            caller_chose_dir: false,
        }
    }

    #[test]
    fn trust_follows_who_chose_the_directory() {
        assert_eq!(caller((0, 0)).dir_trust(), DirTrust::Any);
        assert_eq!(caller((7, 7)).dir_trust(), DirTrust::Owner(7));
        assert_eq!(configured(None).dir_trust(), DirTrust::Configured(None));
        assert_eq!(
            configured(Some((0, 0))).dir_trust(),
            DirTrust::Configured(None)
        );
        assert_eq!(
            configured(Some((7, 7))).dir_trust(),
            DirTrust::Configured(Some(7))
        );
    }

    #[test]
    fn a_configured_directory_without_links_is_trusted_whoever_owns_it() {
        let tmp = tempfile::tempdir().unwrap();
        let other = me().0.wrapping_add(1).max(1);
        assert!(create(tmp.path(), "a.bin", configured(None)).is_ok());
        let nested = tmp.path().join("new/sub");
        let (staged, _file) = create(&nested, "a.bin", configured(Some((other, other)))).unwrap();
        staged.commit().unwrap();
        assert!(nested.join("a.bin").exists());
    }

    /// A user who replaces their configured Downloads with a link must not
    /// steer root's write to a directory that is not theirs.
    #[test]
    fn a_configured_directory_through_a_link_must_be_the_users_own() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("Downloads");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let other = me().0.wrapping_add(1).max(1);
        for recipient in [configured(Some((other, other))), configured(None)] {
            for dir in [link.clone(), link.join("sub")] {
                let Err(e) = create(&dir, "f.bin", recipient.clone()) else {
                    panic!("{dir:?} leads to a directory that is not theirs");
                };
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
            }
        }
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
        // Through a link to their own directory, as a Downloads folder on
        // another disk would be, it still works.
        let (staged, _file) = create(&link, "f.bin", configured(Some(me()))).unwrap();
        staged.commit().unwrap();
        assert!(real.join("f.bin").exists());
    }

    #[test]
    fn a_link_at_the_name_is_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let dir = tmp.path().join("in");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("f.bin")).unwrap();
        let (staged, _file) = create(&dir, "f.bin", caller(me())).unwrap();
        assert_eq!(staged.commit().unwrap(), "f (1).bin");
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
        let (staged, _file) = create(&nested, "f.bin", caller(me())).unwrap();
        staged.commit().unwrap();
        let (uid, _) = me();
        assert_eq!(std::fs::metadata(tmp.path().join("a")).unwrap().uid(), uid);
        assert_eq!(std::fs::metadata(&nested).unwrap().uid(), uid);
        assert_eq!(std::fs::metadata(nested.join("f.bin")).unwrap().uid(), uid);
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_file_is_written_under_a_temporary_name_until_committed() {
        let tmp = tempfile::tempdir().unwrap();
        let (staged, mut file) = create(tmp.path(), "f.bin", caller(me())).unwrap();
        file.write_all(b"data").unwrap();
        let during = names(tmp.path());
        assert_eq!(during.len(), 1);
        assert!(during[0].starts_with(".rayfish-"), "{during:?}");
        drop(file);
        assert_eq!(staged.commit().unwrap(), "f.bin");
        assert_eq!(names(tmp.path()), ["f.bin"]);
        assert_eq!(std::fs::read(tmp.path().join("f.bin")).unwrap(), b"data");
    }

    #[test]
    fn dropping_before_commit_leaves_nothing_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let (staged, mut file) = create(tmp.path(), "f.bin", caller(me())).unwrap();
        file.write_all(b"partial").unwrap();
        drop(staged);
        assert!(names(tmp.path()).is_empty());
    }

    #[test]
    fn commit_never_replaces_a_file_that_appeared_meanwhile() {
        let tmp = tempfile::tempdir().unwrap();
        let (staged, mut file) = create(tmp.path(), "f.bin", caller(me())).unwrap();
        file.write_all(b"new").unwrap();
        std::fs::write(tmp.path().join("f.bin"), b"keep").unwrap();
        assert_eq!(staged.commit().unwrap(), "f (1).bin");
        assert_eq!(std::fs::read(tmp.path().join("f.bin")).unwrap(), b"keep");
        assert_eq!(std::fs::read(tmp.path().join("f (1).bin")).unwrap(), b"new");
        assert_eq!(names(tmp.path()), ["f (1).bin", "f.bin"]);
    }

    /// The fallbacks for filesystems without an exclusive rename refuse an
    /// existing name the same way.
    #[test]
    fn rename_fallbacks_refuse_an_existing_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = open_dir_at(None, tmp.path().as_os_str(), false).unwrap();
        let c = |name: &str| CString::new(name).unwrap();
        for (i, rename) in [link_no_replace, checked_rename].into_iter().enumerate() {
            let from = format!("from-{i}");
            let to = format!("to-{i}");
            std::fs::write(tmp.path().join(&from), b"new").unwrap();
            std::fs::write(tmp.path().join(&to), b"keep").unwrap();
            let e = rename(&dir, &c(&from), &c(&to)).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(std::fs::read(tmp.path().join(&to)).unwrap(), b"keep");
            std::fs::remove_file(tmp.path().join(&to)).unwrap();
            rename(&dir, &c(&from), &c(&to)).unwrap();
            assert_eq!(std::fs::read(tmp.path().join(&to)).unwrap(), b"new");
            assert!(!tmp.path().join(&from).exists());
        }
    }
}
