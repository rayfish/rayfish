//! Process setup shared by PTY and pipe SSH sessions.

use std::io::Error;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Whether a client-controlled variable is safe to pass to a login session.
pub(super) fn env_accepted(name: &str) -> bool {
    matches!(name, "LANG" | "TZ" | "COLORTERM" | "TERM") || name.starts_with("LC_")
}

pub(super) fn login_program() -> Option<PathBuf> {
    if uzers::get_effective_uid() != 0 || std::env::var_os("RAYFISH_SSH_NO_LOGIN").is_some() {
        return None;
    }
    ["/bin/login", "/usr/bin/login"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| {
            std::fs::metadata(path)
                .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

pub(super) fn tty_name(pts: &impl AsRawFd) -> Option<String> {
    let mut buf = [0 as libc::c_char; 128];
    let result = unsafe { libc::ttyname_r(pts.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if result != 0 {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    name.to_str().ok().map(str::to_string)
}

pub(super) fn drop_privs(
    uid: u32,
    gid: u32,
    name: &str,
) -> Result<impl FnMut() -> std::io::Result<()> + Send + Sync + 'static> {
    let name = std::ffi::CString::new(name).context("user name contains NUL")?;
    let already_dropped =
        uid != 0 && unsafe { libc::geteuid() } == uid && unsafe { libc::getegid() } == gid;
    Ok(move || {
        if already_dropped {
            return Ok(());
        }
        unsafe {
            #[cfg(target_os = "macos")]
            let basegroup = gid as libc::c_int;
            #[cfg(not(target_os = "macos"))]
            let basegroup = gid as libc::gid_t;
            if libc::initgroups(name.as_ptr(), basegroup) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    })
}

pub(super) fn login_env<'a>(
    home: &Path,
    shell: &Path,
    name: &str,
) -> [(&'a str, std::ffi::OsString); 5] {
    [
        ("HOME", home.into()),
        ("USER", name.into()),
        ("LOGNAME", name.into()),
        ("SHELL", shell.into()),
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ),
    ]
}
