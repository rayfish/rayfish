//! Where an accepted file lands on Windows, written as LocalSystem only where
//! the requesting user could have written it themselves.
//!
//! The service runs as LocalSystem, but the directory comes from a local
//! caller (`ray files accept -o`) and the file name from a peer. Writing
//! through the caller's path as SYSTEM would let any user who may accept
//! files drop one into `C:\Windows\System32`. The Unix writer answers that
//! with a uid comparison; Windows has no single owner to compare, so the
//! daemon asks Windows instead: `AccessCheck` with the caller's own token
//! (kept from the named pipe) against the directory's security descriptor.
//! The pipe is opened at `SECURITY_IDENTIFICATION`, so that token can be
//! checked but not impersonated, which is why the check is explicit rather
//! than a create done as the caller.
//!
//! What is checked is the directory a handle is open on, not the path. Each
//! directory is opened without `FILE_SHARE_DELETE`, so while the handle is
//! held neither it nor any directory above it can be renamed or removed, and
//! what is created next to it goes through the handle's final path
//! (`GetFinalPathNameByHandleW`), which has no junction or link left in it.
//! Directories created for the caller are opened back with
//! `FILE_FLAG_OPEN_REPARSE_POINT` and refused if they turned into a link, and
//! the file is created with `CREATE_NEW | FILE_FLAG_OPEN_REPARSE_POINT`, so
//! nothing that already exists at the name is opened, let alone followed. A
//! taken name moves on to `name (1).ext`, as on Unix.
//!
//! In place of the Unix `chown`, what is created for a caller carries an ACE
//! granting that caller full control, on top of what it inherits.
//!
//! As on Unix, the file is written under a temporary name and renamed through
//! its own handle once complete, without replacing an existing file. One
//! dropped before that is deleted, so a canceled receive leaves nothing under
//! the real name.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, absolute};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AccessCheck, DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
    LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo,
    FileRenameInfo, GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL,
    SetFileInformationByHandle, VOLUME_NAME_DOS,
};

use super::dest_name::{
    MAX_NAME_ATTEMPTS, missing_names, numbered_name, root_len, temp_name, windows_file_name,
};
use super::{Recipient, WindowsCaller};
use crate::windows_identity::ClientToken;
use crate::windows_security::OwnedSecurityDescriptor;

/// A received file being written under a temporary name: a second handle to
/// it, kept to rename or delete it, and the directory it is in. Dropping it
/// before [`Staged::commit`] deletes the file.
pub(super) struct Staged {
    file: File,
    dir: PathBuf,
    temp: OsString,
    /// The name the file should end up under, before any collision suffix.
    wanted: String,
    committed: bool,
}

impl Staged {
    /// Rename the written file to its name, or the first free `name (n).ext`,
    /// never replacing an existing file. Returns the name it got.
    pub(super) fn commit(mut self) -> io::Result<OsString> {
        for attempt in 0..MAX_NAME_ATTEMPTS {
            let name = numbered_name(&self.wanted, attempt);
            match rename_by_handle(&self.file, &self.dir.join(&name)) {
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
    fn drop(&mut self) {
        if !self.committed {
            delete_on_close(&self.file, &self.temp);
        }
    }
}

/// How far the destination directory has to be checked.
enum DirCheck<'a> {
    /// LocalSystem chose it, and could write there anyway.
    Trusted,
    /// An Administrator configured it as the auto-accept target. Trusted as
    /// configured, so no component may be a junction or link: a user who can
    /// replace part of the path (their own Downloads) could otherwise point
    /// it at `C:\Windows\System32`.
    Configured,
    /// The caller chose it: they must be able to write there themselves.
    Caller(&'a ClientToken),
}

impl DirCheck<'_> {
    fn caller_sid(&self) -> Option<&str> {
        match self {
            Self::Trusted | Self::Configured => None,
            Self::Caller(token) => Some(token.sid()),
        }
    }

    /// Refuse `dir` unless the caller holds `access` on it.
    fn require(&self, dir: &OpenDir, access: u32, path: &Path) -> io::Result<()> {
        let Self::Caller(token) = self else {
            return Ok(());
        };
        if caller_has_access(&dir.handle, token, access).map_err(|e| with_path(e, path))? {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "'{}' is not a directory you can write to; choose one of your own",
                path.display()
            ),
        ))
    }
}

fn dir_check(recipient: &Recipient) -> io::Result<DirCheck<'_>> {
    if !recipient.caller_chose_dir {
        return Ok(DirCheck::Configured);
    }
    match &recipient.caller {
        WindowsCaller::System => Ok(DirCheck::Trusted),
        WindowsCaller::User(token) => Ok(DirCheck::Caller(token)),
        WindowsCaller::Unknown => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the requesting user could not be identified, so the file is not written \
             to a directory they chose",
        )),
    }
}

/// Open (creating as needed) `dir` for `recipient` and create a temporary
/// file in it for `file_name`. Returns the empty file, ready to be written
/// and then committed.
pub(super) fn create(
    dir: &Path,
    file_name: &str,
    recipient: Recipient,
) -> io::Result<(Staged, File)> {
    let check = dir_check(&recipient)?;
    let wanted = windows_file_name(file_name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{file_name}' is not a usable file name on Windows"),
        )
    })?;
    let dir = open_dir(dir, &check)?;
    let (temp, file) = create_temp(&dir, check.caller_sid())?;
    let keep = match file.try_clone() {
        Ok(keep) => keep,
        Err(e) => {
            delete_on_close(&file, &temp);
            return Err(e);
        }
    };
    let staged = Staged {
        file: keep,
        dir: dir.final_path,
        temp,
        wanted,
        committed: false,
    };
    Ok((staged, file))
}

/// A directory held open, and the path it really has.
struct OpenDir {
    handle: File,
    final_path: PathBuf,
}

/// Open `path` as a directory, creating its missing trailing components.
fn open_dir(path: &Path, check: &DirCheck<'_>) -> io::Result<OpenDir> {
    // A relative path means the daemon's working directory, as it always has;
    // the walk below needs the absolute form to find an existing ancestor.
    let path = &absolute(path)?;
    // Find the deepest prefix that already exists. Nothing is created until
    // that directory has passed the check, so a refused request leaves no
    // trace on disk. The caller's path may go through a link (a Downloads
    // folder redirected to another disk): what is checked is the directory
    // the handle ends up on.
    let (mut dir, existing) = match check {
        DirCheck::Configured => walk_without_links(path)?,
        DirCheck::Trusted | DirCheck::Caller(_) => deepest_existing(path)?,
    };
    for name in missing_names(path, existing)? {
        check.require(&dir, FILE_ADD_SUBDIRECTORY, path)?;
        let child = dir.final_path.join(name);
        make_dir(&child, check.caller_sid()).map_err(|e| with_path(e, path))?;
        dir = open_dir_handle(&child, true).map_err(|e| with_path(e, path))?;
    }
    check.require(&dir, FILE_ADD_FILE, path)?;
    Ok(dir)
}

/// The deepest existing prefix of `path`, opened through any links in it,
/// and how many components it has.
fn deepest_existing(path: &Path) -> io::Result<(OpenDir, usize)> {
    let components: Vec<Component<'_>> = path.components().collect();
    let mut existing = components.len();
    loop {
        let prefix: PathBuf = components[..existing].iter().collect();
        match open_dir_handle(&prefix, false) {
            Ok(dir) => return Ok((dir, existing)),
            Err(e) if e.kind() == io::ErrorKind::NotFound && existing > root_len(path) => {
                existing -= 1
            }
            Err(e) => return Err(with_path(e, path)),
        }
    }
}

/// Like [`deepest_existing`], but one component at a time from the root,
/// refusing any that is a reparse point. Each directory stays open while the
/// next is opened, and an open directory cannot be renamed, so the next
/// component is looked up in the directory that was just checked.
fn walk_without_links(path: &Path) -> io::Result<(OpenDir, usize)> {
    let components: Vec<Component<'_>> = path.components().collect();
    let root = root_len(path);
    let mut prefix: PathBuf = components[..root].iter().collect();
    let mut dir = open_dir_handle(&prefix, true).map_err(|e| with_path(e, path))?;
    for (index, component) in components.iter().enumerate().skip(root) {
        prefix.push(component);
        match open_dir_handle(&prefix, true) {
            Ok(next) => dir = next,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((dir, index)),
            Err(e) => return Err(with_path(e, path)),
        }
    }
    Ok((dir, components.len()))
}

/// Open a directory for reading its security and attributes. `no_follow`
/// refuses a reparse point (junction, symlink) as the last component.
fn open_dir_handle(path: &Path, no_follow: bool) -> io::Result<OpenDir> {
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
    if no_follow {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    let wide = wide(path.as_os_str());
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call;
    // the null security attributes and template handle are allowed.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            // No FILE_SHARE_DELETE: while this handle is open the directory,
            // and every one above it, keeps its name.
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` just returned this handle and nothing else owns it.
    let handle = unsafe { File::from_raw_handle(handle) };
    let attributes = handle.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "not a directory",
        ));
    }
    if no_follow && attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a link or junction where a plain directory was expected",
        ));
    }
    let final_path = final_path(&handle)?;
    Ok(OpenDir { handle, final_path })
}

/// The path `file` is really open on, with links resolved, in `\\?\` form.
fn final_path(file: &File) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    loop {
        let capacity = u32::try_from(buffer.len()).map_err(io::Error::other)?;
        // SAFETY: the handle is open for the call and `buffer` is writable for
        // `capacity` UTF-16 units.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                capacity,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        let len = usize::try_from(len).map_err(io::Error::other)?;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..len])));
        }
        // Too small: `len` is the size needed, terminator included.
        buffer.resize(len, 0);
    }
}

/// Whether `token`'s user is granted `access` on the directory `dir` is open
/// on, by its owner, DACL and integrity label.
fn caller_has_access(dir: &File, token: &ClientToken, access: u32) -> io::Result<bool> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is open with READ_CONTROL for the call; the
    // individual out-pointers may be null when the descriptor is requested,
    // and `descriptor` receives a LocalAlloc'd block freed below.
    let status = unsafe {
        GetSecurityInfo(
            dir.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    let descriptor = LocalDescriptor(descriptor);
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    // Room for a PRIVILEGE_SET. None is expected, since no privilege-gated
    // right is asked for, but the call wants a buffer either way.
    let mut privileges = [0u64; 32];
    let mut privileges_len =
        u32::try_from(std::mem::size_of_val(&privileges)).map_err(io::Error::other)?;
    let mut granted = 0u32;
    let mut allowed = 0;
    // SAFETY: `descriptor` is a valid self-relative descriptor with owner,
    // group and DACL; the token handle is open with TOKEN_QUERY and is an
    // impersonation (identification-level) token; every out-pointer refers
    // to a live, writable local of the right size.
    let ok = unsafe {
        AccessCheck(
            descriptor.0,
            token.as_raw(),
            access,
            &mapping,
            privileges.as_mut_ptr().cast(),
            &mut privileges_len,
            &mut granted,
            &mut allowed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(allowed != 0 && granted & access == access)
}

/// A security descriptor `GetSecurityInfo` allocated.
struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `GetSecurityInfo`, which allocates it
        // with LocalAlloc, and is freed only here.
        unsafe { LocalFree(self.0.cast()) };
    }
}

/// A descriptor whose DACL grants `sid` full control (inherited by children
/// when `inherit`), merged with what the parent hands down. `None` without a
/// SID, which leaves the new object to inheritance alone.
fn caller_descriptor(
    sid: Option<&str>,
    inherit: bool,
) -> io::Result<Option<OwnedSecurityDescriptor>> {
    let Some(sid) = sid else {
        return Ok(None);
    };
    let flags = if inherit { "OICI" } else { "" };
    // No `P` (protected) flag, so inheritable ACEs from the parent still apply.
    OwnedSecurityDescriptor::from_sddl(&format!("D:(A;{flags};FA;;;{sid})"))
        .map(Some)
        .map_err(|e| io::Error::other(format!("{e:#}")))
}

fn attributes_ptr(attributes: Option<&SECURITY_ATTRIBUTES>) -> *const SECURITY_ATTRIBUTES {
    attributes.map_or(std::ptr::null(), std::ptr::from_ref)
}

/// Create one directory for the caller. One that appeared concurrently is
/// fine: the caller opens it back and checks it like any other.
fn make_dir(path: &Path, sid: Option<&str>) -> io::Result<()> {
    let mut descriptor = caller_descriptor(sid, true)?;
    let attributes = descriptor.as_mut().map(OwnedSecurityDescriptor::attributes);
    let wide = wide(path.as_os_str());
    // SAFETY: `wide` is a NUL-terminated path, and the security attributes
    // (when present) point at a descriptor that `descriptor` keeps alive
    // across the call.
    let ok = unsafe { CreateDirectoryW(wide.as_ptr(), attributes_ptr(attributes.as_ref())) };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == i32::try_from(ERROR_ALREADY_EXISTS).ok() {
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

/// Create a fresh temporary file in `dir`, exclusively and without following
/// a reparse point.
fn create_temp(dir: &OpenDir, sid: Option<&str>) -> io::Result<(OsString, File)> {
    let mut descriptor = caller_descriptor(sid, false)?;
    let attributes = descriptor.as_mut().map(OwnedSecurityDescriptor::attributes);
    for _ in 0..MAX_NAME_ATTEMPTS {
        let name = temp_name();
        let wide = wide(dir.final_path.join(&name).as_os_str());
        // SAFETY: `wide` is a NUL-terminated path, the security attributes
        // (when present) point at a descriptor `descriptor` keeps alive, and
        // the template handle may be null.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE | DELETE,
                FILE_SHARE_READ,
                attributes_ptr(attributes.as_ref()),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(e);
        }
        // SAFETY: `CreateFileW` just returned this handle and nothing else owns it.
        let file = unsafe { File::from_raw_handle(handle) };
        return Ok((OsString::from(name), file));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not pick a free temporary file name",
    ))
}

/// Rename the file `file` is open on to `to`, a full path in the same
/// directory, failing with `AlreadyExists` instead of replacing a file there.
/// Through the handle, so it is the file this module created that moves,
/// whatever has happened to its temporary name.
fn rename_by_handle(file: &File, to: &Path) -> io::Result<()> {
    let name: Vec<u16> = to.as_os_str().encode_wide().collect();
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| io::Error::other("file name too long"))?;
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    // Room for the header, the name and a terminator, rounded up to whole
    // `u64`s so the buffer is aligned for the struct.
    let size = header
        .checked_add(name_bytes)
        .and_then(|n| n.checked_add(std::mem::size_of::<u16>()))
        .ok_or_else(|| io::Error::other("file name too long"))?
        .max(std::mem::size_of::<FILE_RENAME_INFO>());
    let mut buffer = vec![0u64; size.div_ceil(std::mem::size_of::<u64>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let length = u32::try_from(name_bytes).map_err(io::Error::other)?;
    let size = u32::try_from(size).map_err(io::Error::other)?;
    // SAFETY: `buffer` is zeroed, aligned for `FILE_RENAME_INFO` and large
    // enough for its header followed by `name` and a terminator, so the field
    // writes and the copy into the trailing `FileName` array stay inside it.
    // A zeroed header already means "do not replace" and no root directory.
    unsafe {
        (*info).FileNameLength = length;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    // SAFETY: the handle is open with DELETE access for the call, and `info`
    // points at `size` initialized bytes laid out as a FILE_RENAME_INFO.
    let ok = unsafe {
        SetFileInformationByHandle(file.as_raw_handle(), FileRenameInfo, info.cast(), size)
    };
    if ok == 0 {
        // A taken name is `ERROR_ALREADY_EXISTS` or `ERROR_FILE_EXISTS`,
        // both `AlreadyExists`.
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mark the file `file` is open on for deletion. Through the handle, so it is
/// the file this module created, whatever has happened to its name since.
fn delete_on_close(file: &File, name: &OsStr) {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    let Ok(size) = u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>()) else {
        return;
    };
    // SAFETY: the handle is open with DELETE access for the call, and `info`
    // is a live FILE_DISPOSITION_INFO of the size passed.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast(),
            size,
        )
    };
    if ok == 0 {
        tracing::debug!("remove partial {name:?}: {}", io::Error::last_os_error());
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn win32_error(code: u32) -> io::Error {
    match i32::try_from(code) {
        Ok(code) => io::Error::from_raw_os_error(code),
        Err(_) => io::Error::other(format!("Win32 error {code}")),
    }
}

fn with_path(e: io::Error, path: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("'{}': {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> Recipient {
        Recipient {
            owner: None,
            caller_chose_dir: false,
            caller: WindowsCaller::System,
        }
    }

    #[test]
    fn an_unidentified_caller_is_refused_and_nothing_is_created() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("new");
        let unknown = Recipient {
            owner: None,
            caller_chose_dir: true,
            caller: WindowsCaller::Unknown,
        };
        let Err(e) = create(&nested, "f.bin", unknown) else {
            panic!("a caller with no token must not choose the directory");
        };
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(!nested.exists());
    }

    fn me() -> Recipient {
        let token = ClientToken::current_user().expect("this process has a token");
        Recipient {
            owner: None,
            caller_chose_dir: true,
            caller: WindowsCaller::User(std::sync::Arc::new(token)),
        }
    }

    #[test]
    fn a_directory_the_caller_cannot_write_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        // Only LocalSystem may add to it. The test user owns it, which grants
        // READ_CONTROL and WRITE_DAC but not the right to add a file.
        let locked = tmp.path().join("locked");
        let mut descriptor = OwnedSecurityDescriptor::from_sddl("D:P(A;OICI;FA;;;SY)").unwrap();
        let attributes = descriptor.attributes();
        let path = wide(locked.as_os_str());
        // SAFETY: `path` is NUL-terminated and `attributes` points at a
        // descriptor that outlives the call.
        assert_ne!(unsafe { CreateDirectoryW(path.as_ptr(), &attributes) }, 0);
        let Err(e) = create(&locked, "f.bin", me()) else {
            panic!("a directory only SYSTEM may write must be refused");
        };
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        let Err(e) = create(&locked.join("sub"), "f.bin", me()) else {
            panic!("nothing may be created under it either");
        };
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // The same directory is fine when the caller could write it.
        let (staged, file) = create(tmp.path(), "f.bin", me()).unwrap();
        drop(file);
        assert_eq!(staged.commit().unwrap(), "f.bin");
    }

    #[test]
    fn a_taken_name_gets_a_number_and_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f.bin"), b"keep").unwrap();
        let (staged, file) = create(tmp.path(), "f.bin", configured()).unwrap();
        drop(file);
        assert_eq!(staged.commit().unwrap(), "f (1).bin");
        assert_eq!(std::fs::read(tmp.path().join("f.bin")).unwrap(), b"keep");
    }

    #[test]
    fn a_stream_name_becomes_a_plain_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("notes.txt"), b"keep").unwrap();
        let (staged, file) = create(tmp.path(), "notes.txt:hidden", configured()).unwrap();
        drop(file);
        assert_eq!(staged.commit().unwrap(), "notes.txt_hidden");
    }

    #[test]
    fn missing_directories_are_created_and_a_dropped_file_is_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b");
        let (staged, file) = create(&nested, "f.bin", configured()).unwrap();
        drop(file);
        drop(staged);
        assert!(nested.is_dir());
        assert_eq!(std::fs::read_dir(&nested).unwrap().count(), 0);
    }

    #[test]
    fn commit_never_replaces_a_file_that_appeared_meanwhile() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let (staged, mut file) = create(tmp.path(), "f.bin", configured()).unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        std::fs::write(tmp.path().join("f.bin"), b"keep").unwrap();
        assert_eq!(staged.commit().unwrap(), "f (1).bin");
        assert_eq!(std::fs::read(tmp.path().join("f.bin")).unwrap(), b"keep");
        assert_eq!(std::fs::read(tmp.path().join("f (1).bin")).unwrap(), b"new");
    }

    /// A user who turns their configured Downloads into a junction must not
    /// steer SYSTEM's write somewhere else.
    #[test]
    fn a_junction_in_a_configured_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let junction = tmp.path().join("Downloads");
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&real)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        for dir in [junction.clone(), junction.join("sub")] {
            let Err(e) = create(&dir, "f.bin", configured()) else {
                panic!("{dir:?} goes through a junction");
            };
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        }
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
    }
}
