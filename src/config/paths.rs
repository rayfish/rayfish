//! Where the config tree lives on each platform, the overrides that move it,
//! and the one-time migration of the blob store out of it on Linux.

use super::*;

/// Look up the `rayfish` group's gid (Linux), if the group exists.
#[cfg(target_os = "linux")]
pub(super) fn rayfish_gid() -> Option<u32> {
    use std::{ffi::CString, mem::zeroed, ptr::null_mut};
    let name = CString::new("rayfish").ok()?;
    // getgrnam_r, never getgrnam: the legacy call returns a pointer into a
    // process-wide buffer that any concurrent getgr*/getpw* call is allowed
    // to move or free. Config saves run on many threads at once, and on musl
    // that race corrupted the heap and took the daemon down with SIGSEGV.
    // The reentrant variant copies into our own buffer, which is the whole
    // reason it exists.
    let mut buf_len = 4096;
    loop {
        let mut buf = vec![0u8; buf_len];
        let mut grbuf: libc::group = unsafe { zeroed() };
        let mut result: *mut libc::group = null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut grbuf,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        return Some(unsafe { (*result).gr_gid });
    }
}

/// The group a config path is owned by: `rayfish` for a non-secret path when the
/// group exists, otherwise root.
#[cfg(target_os = "linux")]
pub(super) fn owner_gid(secret: bool) -> u32 {
    if secret {
        0
    } else {
        rayfish_gid().unwrap_or(0)
    }
}

/// Best-effort `chown` to root, with group `rayfish` for non-secret paths (or
/// root for secret ones). No-op off Linux. Silent on failure so the daemon
/// still starts if the group is missing.
#[cfg(target_os = "linux")]
pub(super) fn set_owner(path: &Path, secret: bool) {
    if crate::instance::is_rootless() {
        return;
    }
    if let Err(e) = std::os::unix::fs::chown(path, Some(0), Some(owner_gid(secret))) {
        tracing::debug!(path = %path.display(), error = %e, "chown failed (non-fatal)");
    }
}

/// Unit tests use caller-owned temporary directories and must not replace their
/// inherited ACL with the service-only ProgramData ACL.
#[cfg(all(windows, test))]
pub(super) fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
}

#[cfg(all(windows, not(test)))]
pub(super) fn ensure_dir(dir: &Path) -> Result<()> {
    crate::windows_security::ensure_protected_dir(dir)
}

/// Create `dir` (and parents) with restrictive perms: 0750 root:rayfish on
/// Unix. Idempotent.
#[cfg(not(windows))]
pub(super) fn ensure_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Some(instance) = crate::instance::user_instance() {
        return crate::instance::ensure_private_dir(dir, instance.owner_uid);
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::set_permissions(dir, Permissions::from_mode(0o750));
        set_owner(dir, false);
    }
    Ok(())
}

/// Resolve the `RAYFISH_CONFIG_DIR` override from its raw environment value. An
/// unset *or empty* var means "no override": an exported-but-empty var is a
/// common shell accident and must not resolve the config tree to the current
/// directory. Split out from [`config_dir`] so it is testable without touching
/// the real platform path.
pub(super) fn config_dir_override(raw: Option<OsString>) -> Option<PathBuf> {
    raw.filter(|d| !d.is_empty()).map(PathBuf::from)
}

/// Config directory published by an embedder rather than by the environment.
///
/// `ray-mobile`'s `Node::new` passes Android's `Context.getFilesDir()` here. It
/// used to write that path into `RAYFISH_CONFIG_DIR` instead, which is a
/// mutation of the process environment: undefined behaviour once any other
/// thread is running, and in the lib tests it redirected a concurrent test's
/// config reads between its own write and read. The directory is fixed for the
/// life of the process, so a process-wide cell holds it without threading a
/// handle through every [`config_dir`] caller (as `dht::PKARR_OVERRIDE` does
/// for the discovery server).
pub(super) static CONFIG_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Point every config read at `dir`, ahead of `RAYFISH_CONFIG_DIR`.
///
/// For embedders that know their config location at startup; the CLI and the
/// daemon use the environment variable. Must run before any config or identity
/// read, and takes precedence because the environment write it replaces did.
pub fn set_config_dir_override(dir: PathBuf) {
    *CONFIG_DIR_OVERRIDE
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(dir);
}

/// Pick between the two override sources: the embedder's first, then the
/// environment's. `None` means the platform default applies, and an empty path
/// from either source is "no override" rather than the current directory.
///
/// Split out from [`effective_override`], the way [`config_dir_override`] is
/// split out of [`config_dir`], so the precedence is testable without mutating
/// the process environment (which is what this whole override exists to avoid).
pub(super) fn resolve_override(
    embedder: Option<PathBuf>,
    env: Option<OsString>,
) -> Option<PathBuf> {
    embedder
        .filter(|d| !d.as_os_str().is_empty())
        .or_else(|| config_dir_override(env))
}

#[cfg(test)]
thread_local! {
    /// A config tree for this thread alone, ahead of both overrides. The other
    /// two are process-wide, so a test running two daemons at once gives each a
    /// runtime whose threads set this to its own tree.
    static THREAD_CONFIG_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Point this thread's config reads at `dir`. See [`THREAD_CONFIG_DIR`].
#[cfg(test)]
pub(crate) fn set_thread_config_dir(dir: PathBuf) {
    THREAD_CONFIG_DIR.with(|cell| *cell.borrow_mut() = Some(dir));
}

/// The rootless instance directory, or the embedder's [`set_config_dir_override`]
/// followed by `RAYFISH_CONFIG_DIR`. Tests can override these per thread.
/// `None` means the platform default applies.
pub(super) fn effective_override() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = THREAD_CONFIG_DIR.with(|cell| cell.borrow().clone()) {
        return Some(dir);
    }
    if let Some(instance) = crate::instance::user_instance() {
        return Some(instance.directory.clone());
    }
    resolve_override(
        CONFIG_DIR_OVERRIDE
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone(),
        std::env::var_os("RAYFISH_CONFIG_DIR"),
    )
}

/// The platform's config location, before the `RAYFISH_CONFIG_DIR` override and
/// without creating anything.
///
/// This is always the *daemon's* directory, never the calling process's. macOS
/// is where the difference bites: the daemon runs as root under launchd, so its
/// config lives under `/var/root`, and resolving `dirs::config_dir()` in an
/// unprivileged `ray` would name an empty directory in that user's home instead
/// (and, through [`config_dir`], create it).
pub(super) fn platform_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    let dir = PathBuf::from("/etc/rayfish");
    #[cfg(target_os = "freebsd")]
    let dir = PathBuf::from("/usr/local/etc/rayfish");
    // Android without the override falls back to a fixed app-private path so the
    // library still compiles/runs standalone.
    #[cfg(target_os = "android")]
    let dir = PathBuf::from("/data/local/tmp/rayfish");
    #[cfg(target_os = "macos")]
    let dir = PathBuf::from("/var/root/Library/Application Support/rayfish");
    // Machine-wide, for the same reason macOS is: the daemon is a LocalSystem
    // service, and `dirs::config_dir()` would name that account's roaming
    // profile under `C:\Windows\system32\config\systemprofile` for the daemon
    // and the operator's own `%APPDATA%` for `ray`.
    #[cfg(target_os = "windows")]
    let dir = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("rayfish");
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "windows"
    )))]
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("rayfish");
    Ok(dir)
}

/// Base directory for all rayfish config + state. Created if missing.
///
/// `RAYFISH_CONFIG_DIR` overrides the platform default on every platform. The
/// daemon and the CLI must agree on it, so setting it for one and not the other
/// points them at different trees: export it in the service unit (or the daemon's
/// environment) as well as the shell you run `ray` from.
///
/// Platform defaults: Linux `/etc/rayfish` (system service location,
/// root:rayfish), FreeBSD `/usr/local/etc/rayfish`, macOS the daemon's
/// `/var/root/Library/Application Support/rayfish` (root-only; under launchd
/// root's home is `/var/root`, not the home of whoever ran `sudo`), Android the
/// app's `Context.getFilesDir()` (passed by `ray-mobile`'s `Node::new` through
/// [`set_config_dir_override`], which outranks the variable).
///
/// Use [`config_dir_for_read`] from anything that only reads: creating the tree
/// is the daemon's job, and a reader that does it can end up reporting the
/// directory it just made as the daemon's config.
pub fn config_dir() -> Result<PathBuf> {
    let dir = match effective_override() {
        Some(dir) => dir,
        None => platform_config_dir()?,
    };
    ensure_dir(&dir)?;
    Ok(dir)
}

/// Where the daemon keeps its content-addressed blob store: membership
/// snapshots and file transfers in flight. Created if missing.
///
/// On Linux it lives under `/var/lib/rayfish`, not the config tree: transfers
/// can be large, `/etc` is often on a small or read-only root filesystem, and
/// the store is state, not configuration. A store left in `/etc/rayfish/blobs`
/// by an older release is moved on first start. Elsewhere, and whenever
/// `RAYFISH_CONFIG_DIR` is set, it stays inside the config directory.
pub fn blobs_dir() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if effective_override().is_none() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        let old = config_dir()?.join("blobs");
        let state = Path::new(LINUX_STATE_DIR);
        let dir = match DirBuilder::new().recursive(true).mode(0o700).create(state) {
            Ok(()) => migrate_blobs(&old, &state.join("blobs")),
            Err(error) => {
                tracing::warn!(dir = LINUX_STATE_DIR, %error, "cannot create the state directory; keeping blobs in the config directory");
                old
            }
        };
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        return Ok(dir);
    }
    let dir = config_dir()?.join("blobs");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

#[cfg(target_os = "linux")]
pub(super) const LINUX_STATE_DIR: &str = "/var/lib/rayfish";

/// Move a blob store from `old` to `new` and return the one to use. Across
/// filesystems (a separate `/var`) the store is copied next to `new`, checked,
/// and only then renamed into place, so a half-finished copy is never used. On
/// any failure the old location stays in use.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) fn migrate_blobs(old: &Path, new: &Path) -> PathBuf {
    if !old.is_dir() {
        return new.to_path_buf();
    }
    if new.exists() {
        tracing::warn!(
            old = %old.display(),
            new = %new.display(),
            "both blob store locations exist; using the new one and leaving the old one alone"
        );
        return new.to_path_buf();
    }
    match std::fs::rename(old, new) {
        Ok(()) => {
            tracing::info!(old = %old.display(), new = %new.display(), "moved the blob store");
            new.to_path_buf()
        }
        Err(error) if error.kind() == ErrorKind::CrossesDevices => {
            match copy_blob_store(old, new) {
                Ok(()) => {
                    tracing::info!(old = %old.display(), new = %new.display(), "copied the blob store to the state directory");
                    if let Err(error) = fs::remove_dir_all(old) {
                        tracing::warn!(old = %old.display(), %error, "copied the blob store but could not remove the old one");
                    }
                    new.to_path_buf()
                }
                Err(error) => {
                    tracing::warn!(
                        old = %old.display(),
                        new = %new.display(),
                        %error,
                        "could not copy the blob store; it stays where it is"
                    );
                    old.to_path_buf()
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                old = %old.display(),
                new = %new.display(),
                %error,
                "could not move the blob store; it stays where it is"
            );
            old.to_path_buf()
        }
    }
}

/// Copy the store at `old` to `new`, which must not exist, through a staging
/// directory beside `new`. Every file and directory is synced and the copy's
/// file list and sizes are compared with the original before the rename that
/// makes it visible. `old` is left untouched.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) fn copy_blob_store(old: &Path, new: &Path) -> io::Result<()> {
    let parent = new
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "blob store path has no parent"))?;
    let staging = parent.join(".blobs.migrating");
    // A leftover from an attempt that was interrupted; never in use.
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    let result = (|| {
        fs::create_dir(&staging)?;
        copy_tree(old, &staging)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        }
        File::open(&staging)?.sync_all()?;
        let mut original = Vec::new();
        list_tree(old, Path::new(""), &mut original)?;
        let mut check = Vec::new();
        list_tree(&staging, Path::new(""), &mut check)?;
        original.sort();
        check.sort();
        if original != check {
            return Err(io::Error::other(
                "copied blob store does not match the original",
            ));
        }
        fs::rename(&staging, new)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// One regular file in a blob store, by path relative to the store and size.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) type StoreEntry = (PathBuf, u64);

/// Copy the tree under `from` into the existing directory `to`, syncing each
/// file and directory.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&dst)?;
            copy_tree(&src, &dst)?;
            fs::set_permissions(&dst, fs::metadata(&src)?.permissions())?;
        } else if kind.is_file() {
            fs::copy(&src, &dst)?;
            File::open(&dst)?.sync_all()?;
        } else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                format!("{} is not a file or directory", src.display()),
            ));
        }
    }
    File::open(to)?.sync_all()
}

/// Every regular file under `dir`, with its size.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) fn list_tree(dir: &Path, rel: &Path, out: &mut Vec<StoreEntry>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let rel = rel.join(entry.file_name());
        if metadata.is_dir() {
            list_tree(&entry.path(), &rel, out)?;
        } else {
            out.push((rel, metadata.len()));
        }
    }
    Ok(())
}

/// [`config_dir`] for a reader: same directory, never created.
///
/// A missing directory is not an error here — it reads as an empty config, which
/// is what a reader wants to say about a daemon that has saved nothing.
pub fn config_dir_for_read() -> Result<PathBuf> {
    match effective_override() {
        Some(dir) => Ok(dir),
        None => platform_config_dir(),
    }
}
