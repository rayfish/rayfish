//! Process setup shared by PTY and pipe SSH sessions.

use std::ffi::{CStr, OsString};
use std::io::{Error, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
#[cfg(target_os = "linux")]
use std::time::Duration;

use anyhow::Result;

use super::login::LoginInfo;
#[cfg(target_os = "linux")]
use crate::child::wait_bounded;

/// Whether a client-controlled variable is safe to pass to a login session.
pub(super) fn env_accepted(name: &str) -> bool {
    matches!(name, "LANG" | "TZ" | "COLORTERM" | "TERM") || name.starts_with("LC_")
}

pub(super) fn login_program() -> Option<PathBuf> {
    // illumos login(1) has no pre-authenticated `-f` mode, so the handoff
    // would prompt for a password and fail with "Login incorrect".
    if cfg!(target_os = "illumos") {
        return None;
    }
    if uzers::get_effective_uid() != 0 || std::env::var_os("RAYFISH_SSH_NO_LOGIN").is_some() {
        return None;
    }
    ["/bin/login", "/usr/bin/login"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| is_executable(path))
}

/// illumos ptys are STREAMS devices: the slave is not a terminal until
/// `ptem` and `ldterm` are pushed onto it.
#[cfg(target_os = "illumos")]
pub(super) fn prepare_pts(pts: &impl AsRawFd) {
    const STR: libc::c_int = (b'S' as libc::c_int) << 8;
    const I_PUSH: libc::c_int = STR | 0o02;
    const I_FIND: libc::c_int = STR | 0o13;
    let fd = pts.as_raw_fd();
    for module in [c"ptem", c"ldterm"] {
        unsafe {
            if libc::ioctl(fd, I_FIND, module.as_ptr()) == 0 {
                libc::ioctl(fd, I_PUSH, module.as_ptr());
            }
        }
    }
}

#[cfg(not(target_os = "illumos"))]
pub(super) fn prepare_pts(_pts: &impl AsRawFd) {}

pub(super) fn tty_name(pts: &impl AsRawFd) -> Option<String> {
    let mut buf = [0 as libc::c_char; 128];
    let result = unsafe { libc::ttyname_r(pts.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if result != 0 {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    name.to_str().ok().map(str::to_string)
}

/// How to start a session's shell when it does not go through `login(1)`.
pub(super) struct Launch {
    pub(super) program: PathBuf,
    pub(super) args: Vec<OsString>,
    /// Whether the child still runs as the daemon's user and must switch to
    /// the session user in `pre_exec`. False once a wrapper does it.
    pub(super) drop_in_child: bool,
}

/// Tools that start a session in its own systemd scope.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ScopeTools {
    systemd_run: PathBuf,
    setpriv: PathBuf,
}

/// The shell invocation for a session, run in its own transient systemd scope
/// when possible.
///
/// Without `login(1)` the shell would otherwise stay in the daemon's service
/// cgroup, so restarting rayfish (an update, `ray down`) kills every session
/// and any job it left running, as `KillMode=control-group` intends for the
/// service itself. `systemd-run --scope` and `setpriv` both exec in place, so
/// the pid we signal, the exit status, the environment and the stdio pipes are
/// those of the shell itself, the same as a direct spawn. `setpriv` does the
/// group and user switch in that fresh single-threaded process.
///
/// Finding the tools stats a few paths and, once per daemon, runs a probe, so
/// it happens on the blocking pool rather than a runtime worker.
pub(super) async fn shell_launch(info: &LoginInfo, command: Option<&str>) -> Launch {
    let shell_args: Vec<OsString> = match command {
        Some(command) => vec!["-c".into(), command.into()],
        None => vec!["-l".into()],
    };
    let tools = tokio::task::spawn_blocking(scope_tools)
        .await
        .ok()
        .flatten();
    match tools {
        Some(tools) => scoped_launch(&tools, info, shell_args),
        None => Launch {
            program: info.shell.clone(),
            args: shell_args,
            drop_in_child: true,
        },
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn scoped_launch(tools: &ScopeTools, info: &LoginInfo, shell_args: Vec<OsString>) -> Launch {
    let mut args: Vec<OsString> = vec![
        "--scope".into(),
        "--quiet".into(),
        "--collect".into(),
        format!("--description=rayfish SSH session for {}", info.name).into(),
        "--".into(),
        tools.setpriv.clone().into(),
        format!("--reuid={}", info.uid).into(),
        format!("--regid={}", info.gid).into(),
        "--init-groups".into(),
        "--".into(),
        info.shell.clone().into(),
    ];
    args.extend(shell_args);
    Launch {
        program: tools.systemd_run.clone(),
        args,
        drop_in_child: false,
    }
}

#[cfg(target_os = "linux")]
fn scope_tools() -> Option<ScopeTools> {
    // Only root can create a scope in the system manager and switch users.
    if unsafe { libc::geteuid() } != 0 || !Path::new("/run/systemd/system").is_dir() {
        return None;
    }
    let find = |name: &str| {
        ["/usr/bin", "/bin"]
            .into_iter()
            .map(|dir| Path::new(dir).join(name))
            .find(|path| is_executable(path))
    };
    let tools = ScopeTools {
        systemd_run: find("systemd-run")?,
        setpriv: find("setpriv")?,
    };
    // The binaries can exist while the wrapper still fails: no access to PID 1
    // in a container, an SELinux denial, or a busybox `setpriv` without
    // `--reuid` and `--init-groups`. It would then exit 1 after the session
    // started, so check once that the whole wrapper really runs.
    static SCOPES_WORK: OnceLock<bool> = OnceLock::new();
    SCOPES_WORK
        .get_or_init(|| probe_scope(&tools, find("true").as_deref()))
        .then_some(tools)
}

/// Find the scope tools and run their probe now, off the session path, so the
/// first session does not wait for it. Called when the SSH server starts.
pub(super) fn warm_scope_tools() {
    #[cfg(target_os = "linux")]
    tokio::task::spawn_blocking(scope_tools);
}

/// Run `true` through the same wrapper a session uses, switching to root as
/// root (a no-op), within a short bound. This blocks, but only once per daemon.
#[cfg(target_os = "linux")]
fn probe_scope(tools: &ScopeTools, true_bin: Option<&Path>) -> bool {
    const TIMEOUT: Duration = Duration::from_secs(3);
    let true_bin = true_bin.unwrap_or(Path::new("true"));
    let spawned = Command::new(&tools.systemd_run)
        .args(["--scope", "--quiet", "--collect", "--"])
        .arg(&tools.setpriv)
        .args(["--reuid=0", "--regid=0", "--init-groups", "--"])
        .arg(true_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!(%error, "systemd-run unavailable, SSH sessions stay in the daemon's cgroup");
            return false;
        }
    };
    match wait_bounded(&mut child, TIMEOUT) {
        Ok(status) if status.success() => true,
        Ok(status) => {
            tracing::warn!(%status, "systemd-run --scope with setpriv failed, SSH sessions stay in the daemon's cgroup");
            false
        }
        Err(error) => {
            tracing::warn!(%error, "systemd-run --scope with setpriv failed, SSH sessions stay in the daemon's cgroup");
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn scope_tools() -> Option<ScopeTools> {
    None
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Build the `pre_exec` hook that switches the child to the session user.
///
/// The supplementary groups are resolved here, in the parent. The hook runs
/// between fork and exec in a multithreaded process, where an NSS lookup such
/// as `initgroups` can deadlock on a lock another thread held at fork time, so
/// the child only makes the raw set*id calls and checks they took effect.
pub(super) fn drop_privs(
    info: &LoginInfo,
) -> Result<impl FnMut() -> std::io::Result<()> + Send + Sync + 'static> {
    let (uid, gid) = (info.uid, info.gid);
    let already_dropped =
        uid != 0 && unsafe { libc::geteuid() } == uid && unsafe { libc::getegid() } == gid;
    let groups = if already_dropped {
        Vec::new()
    } else {
        info.groups.clone()
    };
    Ok(move || {
        if already_dropped {
            return Ok(());
        }
        // SAFETY: only async-signal-safe syscalls on memory owned by the
        // closure; `groups` is not reallocated here.
        unsafe {
            if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(Error::last_os_error());
            }
            if libc::getuid() != uid
                || libc::geteuid() != uid
                || libc::getgid() != gid
                || libc::getegid() != gid
            {
                return Err(Error::from(ErrorKind::PermissionDenied));
            }
        }
        Ok(())
    })
}

/// The user's group list (primary group included), as `initgroups` would set.
pub(super) fn group_list(name: &CStr, gid: u32) -> Result<Vec<libc::gid_t>> {
    // The kernel's NGROUPS_MAX on Linux; far beyond any real account.
    const MAX_GROUPS: usize = 65_536;
    let mut capacity = 64usize;
    loop {
        let mut count = capacity as libc::c_int;
        #[cfg(target_os = "macos")]
        let (result, mut groups) = {
            let mut groups = vec![0 as libc::c_int; capacity];
            // SAFETY: `groups` holds `count` entries and outlives the call.
            let result = unsafe {
                libc::getgrouplist(
                    name.as_ptr(),
                    gid as libc::c_int,
                    groups.as_mut_ptr(),
                    &mut count,
                )
            };
            let groups: Vec<libc::gid_t> = groups.into_iter().map(|g| g as libc::gid_t).collect();
            (result, groups)
        };
        #[cfg(not(target_os = "macos"))]
        let (result, mut groups) = {
            let mut groups = vec![0 as libc::gid_t; capacity];
            // SAFETY: `groups` holds `count` entries and outlives the call.
            let result =
                unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
            (result, groups)
        };
        if result >= 0 {
            groups.truncate(count.max(0) as usize);
            // macOS setgroups rejects more than NGROUPS_MAX (16) entries;
            // initgroups truncates the same way. The primary group is first.
            #[cfg(target_os = "macos")]
            groups.truncate(16);
            return Ok(groups);
        }
        drop(groups);
        anyhow::ensure!(
            capacity < MAX_GROUPS,
            "user is in more than {MAX_GROUPS} groups"
        );
        // glibc reports the size it needs; other libcs only say "too small".
        capacity = (count.max(0) as usize).max(capacity * 2).min(MAX_GROUPS);
    }
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

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn scoped_launch_execs_the_shell_as_the_user_inside_a_scope() {
        let tools = ScopeTools {
            systemd_run: "/usr/bin/systemd-run".into(),
            setpriv: "/usr/bin/setpriv".into(),
        };
        let info = LoginInfo {
            uid: 1000,
            gid: 1001,
            home: "/home/user".into(),
            shell: "/bin/bash".into(),
            name: "user".into(),
            groups: vec![1001],
        };
        let launch = scoped_launch(&tools, &info, vec!["-c".into(), "echo hi".into()]);
        assert_eq!(launch.program, Path::new("/usr/bin/systemd-run"));
        assert!(!launch.drop_in_child);
        let args: Vec<&str> = launch
            .args
            .iter()
            .map(|arg| arg.to_str().expect("test args are UTF-8"))
            .collect();
        assert_eq!(
            args,
            [
                "--scope",
                "--quiet",
                "--collect",
                "--description=rayfish SSH session for user",
                "--",
                "/usr/bin/setpriv",
                "--reuid=1000",
                "--regid=1001",
                "--init-groups",
                "--",
                "/bin/bash",
                "-c",
                "echo hi",
            ]
        );
    }

    #[test]
    fn group_list_includes_the_primary_group() {
        let name = uzers::get_current_username().expect("test runs as a named user");
        let name = CString::new(name.into_encoded_bytes()).expect("user names have no NUL");
        let gid = uzers::get_current_gid();
        let groups = group_list(&name, gid).expect("group lookup succeeds");
        assert!(groups.contains(&gid));
    }
}
