//! Unix-socket work for forwarding, done as the login account.
//!
//! The daemon is root, and on a unix socket the filesystem is the access
//! control: a root `connect` ignores it, and the listening service reads the
//! caller's uid with `SO_PEERCRED` and sees 0. Checking permissions first and
//! then acting as root is a race (the path can be swapped for a symlink in
//! between) and still hands the service the wrong uid. So each operation runs
//! in a short-lived forked child that has already become the login account,
//! and a socket it opens comes back to the daemon over a socketpair.
//!
//! The child lives between fork and `_exit` in a multithreaded process, so it
//! only makes raw syscalls on memory prepared before the fork, the same rule
//! as the session `pre_exec` hook in [`super::session_env`].

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{AcquireError, Semaphore};
use tokio::time::timeout;

use super::login::LoginInfo;
use super::session_env::drop_privs;

/// Pending connections a reverse-forwarded socket queues, as sshd's.
const LISTEN_BACKLOG: libc::c_int = 128;

/// How long the daemon waits for a helper before killing it. A lookup on a
/// path the account controls can block forever (a FUSE mount that never
/// answers), and the waiting thread belongs to tokio's shared blocking pool.
const HELPER_DEADLINE: Duration = Duration::from_secs(10);

/// Helpers running at once across every connection. Each holds a thread of
/// tokio's shared blocking pool for up to [`HELPER_DEADLINE`], and the login
/// account can stall its own helpers, so without a cap a few thousand
/// forwards would starve everything else in the daemon that uses that pool.
const MAX_HELPERS: usize = 32;

/// Helpers one account may run at once, so an account stalling its own fills
/// its own places and not the shared ones.
const MAX_HELPERS_PER_ACCOUNT: usize = 4;

/// How long a request waits for a helper place before failing. `-R` and agent
/// setup wait inside the connection's session task, which must not stall.
const QUEUE_WAIT: Duration = Duration::from_secs(2);

static HELPERS: LazyLock<HelperLimits> =
    LazyLock::new(|| HelperLimits::new(MAX_HELPERS, MAX_HELPERS_PER_ACCOUNT, QUEUE_WAIT));

/// The places helpers run under: one per account, then one of the shared.
struct HelperLimits {
    total: Arc<Semaphore>,
    per_account: usize,
    accounts: Mutex<HashMap<u32, Arc<Semaphore>>>,
    queue_wait: Duration,
}

impl HelperLimits {
    fn new(total: usize, per_account: usize, queue_wait: Duration) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            per_account,
            accounts: Mutex::default(),
            queue_wait,
        }
    }

    /// `uid`'s own places. One entry per account that ever forwarded a
    /// socket, which the host's account list bounds.
    fn account(&self, uid: u32) -> Arc<Semaphore> {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            accounts
                .entry(uid)
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_account))),
        )
    }
}

/// The filesystem identity of a socket file a helper bound, so cleanup removes
/// that file and not a newer socket bound at the same path since.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SocketFile {
    dev: u64,
    ino: u64,
}

/// A listening socket and the file it is bound to.
pub(super) struct Bound {
    pub(super) listener: UnixListener,
    pub(super) file: SocketFile,
}

#[derive(Clone, Copy)]
enum Op {
    Connect,
    Listen,
    RemoveSocket(SocketFile),
    CreateDir,
    RemoveDir,
    /// Never answers, standing in for a lookup that blocks forever.
    #[cfg(test)]
    Hang,
    /// Answers EEXIST if the daemon's descriptor `fd` is open in the helper.
    #[cfg(test)]
    Inherited(RawFd),
}

/// What the helper sends back: an errno (0 for success), the bound file's
/// identity for `Listen`, and the socket over SCM_RIGHTS when there is one.
const REPORT_LEN: usize = size_of::<libc::c_int>() + 2 * size_of::<u64>();

/// Dial the unix socket at `path` as `info`'s account.
pub(super) async fn connect(info: Arc<LoginInfo>, path: PathBuf) -> Result<UnixStream> {
    let fd = run_blocking(info, path, Op::Connect)
        .await?
        .fd
        .context("the helper returned no socket")?;
    Ok(UnixStream::from_std(StdUnixStream::from(fd))?)
}

/// Bind and listen on `path` as `info`'s account. A stale socket the account
/// owns at that path is replaced; anything else there is an error.
pub(super) async fn listen(info: Arc<LoginInfo>, path: PathBuf) -> Result<Bound> {
    let answer = run_blocking(info, path, Op::Listen).await?;
    let fd = answer.fd.context("the helper returned no socket")?;
    Ok(Bound {
        listener: UnixListener::from_std(StdUnixListener::from(fd))?,
        file: answer.file,
    })
}

/// Remove the socket file `file` at `path` as `info`'s account. Anything else
/// at the path (another socket bound since, not a socket, or nothing) is left
/// alone.
pub(super) async fn remove_socket(
    info: Arc<LoginInfo>,
    path: PathBuf,
    file: SocketFile,
) -> Result<()> {
    run_blocking(info, path, Op::RemoveSocket(file))
        .await
        .map(drop)
}

/// Create a mode 0700 directory at `path` as `info`'s account. Fails if
/// anything already exists there.
pub(super) async fn create_dir(info: Arc<LoginInfo>, path: PathBuf) -> Result<()> {
    run_blocking(info, path, Op::CreateDir).await.map(drop)
}

/// Remove the empty directory at `path` as `info`'s account.
pub(super) async fn remove_dir(info: Arc<LoginInfo>, path: PathBuf) -> Result<()> {
    run_blocking(info, path, Op::RemoveDir).await.map(drop)
}

async fn run_blocking(info: Arc<LoginInfo>, path: PathBuf, op: Op) -> Result<Answer> {
    run_gated(&HELPERS, info, path, op).await
}

/// Wait for a place under `limits` (the account's own first, then a shared
/// one), then run `op` in a helper. Waiting longer than the queue allows is a
/// `TimedOut` error; a caller that gives up while queued frees its turn; a
/// running helper keeps its places until it has been reaped.
async fn run_gated(
    limits: &'static HelperLimits,
    info: Arc<LoginInfo>,
    path: PathBuf,
    op: Op,
) -> Result<Answer> {
    let shown = path.display().to_string();
    let places = timeout(limits.queue_wait, async {
        let own = limits.account(info.uid).acquire_owned().await?;
        let shared = Arc::clone(&limits.total).acquire_owned().await?;
        Ok::<_, AcquireError>((own, shared))
    })
    .await
    .map_err(|_| Error::from(ErrorKind::TimedOut))
    .context("socket helpers are busy")?
    .context("socket helper limit closed")?;
    tokio::task::spawn_blocking(move || {
        let _places = places;
        run(&info, &path, op, HELPER_DEADLINE)
    })
    .await
    .context("socket helper task failed")?
    .with_context(|| format!("{shown} as the login account"))
}

/// Fork, become the account, do `op`, and collect its result, killing the
/// helper if it has not answered within `deadline`.
fn run(info: &LoginInfo, path: &Path, op: Op, deadline: Duration) -> Result<Answer> {
    let mut become_user = drop_privs(info)?;
    let c_path = CString::new(path.as_os_str().as_bytes()).context("path contains NUL")?;
    let addr = match op {
        Op::Connect | Op::Listen => Some(SocketAddr::new(&c_path)?),
        _ => None,
    };
    let (parent_end, child_end) =
        StdUnixStream::pair().context("creating the helper socketpair")?;
    let inherited = open_descriptors();

    // SAFETY: the child runs only `child`, which makes async-signal-safe
    // syscalls on memory set up above and ends in `_exit`, never returning
    // into code that could take a lock another thread held at fork time.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::last_os_error()).context("forking the socket helper");
    }
    if pid == 0 {
        close_inherited(child_end.as_raw_fd(), &inherited);
        let errno = match become_user() {
            Ok(()) => 0,
            Err(e) => e.raw_os_error().unwrap_or(libc::EPERM),
        };
        child(errno, op, &c_path, addr.as_ref(), child_end.as_raw_fd());
    }
    drop(child_end);
    let answer = match wait_readable(parent_end.as_raw_fd(), deadline) {
        Ok(()) => receive(parent_end.as_raw_fd()),
        Err(e) => {
            // SAFETY: signals our own child, which has not been reaped yet.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            Err(e)
        }
    };
    reap(pid);
    let answer = answer?;
    if answer.errno != 0 {
        return Err(Error::from_raw_os_error(answer.errno).into());
    }
    Ok(answer)
}

/// The descriptors open in this process, listed before a fork for platforms
/// where the child cannot close a range in one call. Empty where it can.
fn open_descriptors() -> Vec<RawFd> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        static CLOSE_RANGE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        // SAFETY: an empty range at the top of the fd space closes nothing;
        // it only asks whether the kernel has close_range.
        let works = *CLOSE_RANGE.get_or_init(|| unsafe {
            libc::syscall(
                libc::SYS_close_range,
                libc::c_uint::MAX,
                libc::c_uint::MAX,
                0,
            ) == 0
        });
        if works {
            return Vec::new();
        }
    }
    let dir = if cfg!(any(target_os = "linux", target_os = "android")) {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// In the forked child: close every descriptor above stdio except `keep`, so
/// a helper the account stalls holds none of the daemon's sockets, pipes or
/// devices open after the daemon has let go of them.
fn close_inherited(keep: RawFd, listed: &[RawFd]) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let Ok(keep_u) = libc::c_uint::try_from(keep) else {
            return;
        };
        // SAFETY: close_range only closes descriptors of this (child) process.
        let closed = unsafe {
            (keep_u <= 3 || libc::syscall(libc::SYS_close_range, 3, keep_u - 1, 0) == 0)
                && libc::syscall(libc::SYS_close_range, keep_u + 1, libc::c_uint::MAX, 0) == 0
        };
        if closed {
            return;
        }
    }
    // A kernel without close_range, or not Linux: the list taken before the
    // fork. A descriptor another thread opened after it can still slip by.
    for &fd in listed {
        if fd > 2 && fd != keep {
            // SAFETY: closes a descriptor of this (child) process.
            unsafe { libc::close(fd) };
        }
    }
}

/// Wait until the helper's answer (or its exit) is readable on `fd`.
fn wait_readable(fd: RawFd, deadline: Duration) -> Result<()> {
    let until = Instant::now() + deadline;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::from(ErrorKind::TimedOut)).context("the socket helper is stuck");
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        // SAFETY: polls one valid pollfd that lives on this frame.
        match unsafe { libc::poll(&mut pfd, 1, ms) } {
            n if n > 0 => return Ok(()),
            0 => continue,
            _ if errno_now() == libc::EINTR => continue,
            _ => return Err(Error::last_os_error()).context("waiting for the socket helper"),
        }
    }
}

/// The forked child. Never returns.
fn child(
    errno: libc::c_int,
    op: Op,
    path: &CString,
    addr: Option<&SocketAddr>,
    report: RawFd,
) -> ! {
    if errno != 0 {
        send(report, errno, None, None);
    }
    // SAFETY: plain syscalls on `path` and `addr`, both valid for the call.
    unsafe {
        let p = path.as_ptr();
        let mut file = None;
        let result: Result<Option<RawFd>, libc::c_int> = match (op, addr) {
            (Op::Connect, Some(addr)) => open_socket().and_then(|fd| {
                let rc = libc::connect(fd, addr.as_ptr(), addr.len);
                if rc == 0 || errno_now() == libc::EINPROGRESS {
                    Ok(Some(fd))
                } else {
                    Err(errno_now())
                }
            }),
            (Op::Listen, Some(addr)) => {
                let mut st: libc::stat = zeroed();
                if libc::lstat(p, &mut st) == 0
                    && st.st_mode & libc::S_IFMT == libc::S_IFSOCK
                    && st.st_uid == libc::getuid()
                {
                    libc::unlink(p);
                }
                libc::umask(0o177);
                open_socket().and_then(|fd| {
                    let mut st: libc::stat = zeroed();
                    if libc::bind(fd, addr.as_ptr(), addr.len) == 0
                        && libc::listen(fd, LISTEN_BACKLOG) == 0
                        && libc::lstat(p, &mut st) == 0
                    {
                        file = Some(SocketFile::of(&st));
                        Ok(Some(fd))
                    } else {
                        Err(errno_now())
                    }
                })
            }
            (Op::RemoveSocket(file), _) => {
                let mut st: libc::stat = zeroed();
                if libc::lstat(p, &mut st) == 0
                    && st.st_mode & libc::S_IFMT == libc::S_IFSOCK
                    && SocketFile::of(&st) == file
                    && libc::unlink(p) != 0
                {
                    Err(errno_now())
                } else {
                    Ok(None)
                }
            }
            (Op::CreateDir, _) => {
                libc::umask(0o077);
                if libc::mkdir(p, 0o700) == 0 {
                    Ok(None)
                } else {
                    Err(errno_now())
                }
            }
            (Op::RemoveDir, _) => {
                if libc::rmdir(p) == 0 {
                    Ok(None)
                } else {
                    Err(errno_now())
                }
            }
            #[cfg(test)]
            (Op::Hang, _) => loop {
                libc::pause();
            },
            #[cfg(test)]
            (Op::Inherited(fd), _) => {
                if libc::fcntl(fd, libc::F_GETFD) == -1 {
                    Ok(None)
                } else {
                    Err(libc::EEXIST)
                }
            }
            (Op::Connect | Op::Listen, None) => Err(libc::EINVAL),
        };
        match result {
            Ok(fd) => send(report, 0, fd, file),
            Err(errno) => send(report, errno, None, None),
        }
    }
}

/// A nonblocking unix stream socket, ready for tokio. Close-on-exec is set
/// by the receiver: it is a descriptor flag and does not travel with the fd.
///
/// # Safety
/// Only raw syscalls; safe to call in the forked child.
unsafe fn open_socket() -> Result<RawFd, libc::c_int> {
    // SAFETY: plain syscalls on an fd this function owns.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(errno_now());
        }
        if libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) != 0 {
            return Err(errno_now());
        }
        Ok(fd)
    }
}

fn errno_now() -> libc::c_int {
    Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// Send the result to the daemon and exit. Uses stack memory only.
fn send(report: RawFd, errno: libc::c_int, fd: Option<RawFd>, file: Option<SocketFile>) -> ! {
    let file = file.unwrap_or(SocketFile { dev: 0, ino: 0 });
    let mut payload = [0u8; REPORT_LEN];
    let (head, rest) = payload.split_at_mut(size_of::<libc::c_int>());
    let (dev, ino) = rest.split_at_mut(size_of::<u64>());
    head.copy_from_slice(&errno.to_ne_bytes());
    dev.copy_from_slice(&file.dev.to_ne_bytes());
    ino.copy_from_slice(&file.ino.to_ne_bytes());
    // SAFETY: the message, iovec and control buffer all live on this stack
    // frame for the duration of `sendmsg`; `_exit` skips every destructor.
    unsafe {
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut control = [0u64; 4];
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
            libc::CMSG_DATA(cmsg).cast::<RawFd>().write_unaligned(fd);
        }
        let code = if libc::sendmsg(report, &msg, 0) < 0 {
            1
        } else {
            0
        };
        libc::_exit(code)
    }
}

struct Answer {
    errno: libc::c_int,
    fd: Option<OwnedFd>,
    file: SocketFile,
}

/// Read the child's answer: an errno, the bound file, and the socket when
/// there is one. The socket arrives close-on-exec, so it never leaks into a
/// session process the daemon spawns later.
fn receive(report: RawFd) -> Result<Answer> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const FLAGS: libc::c_int = 0;

    let mut payload = [0u8; REPORT_LEN];
    let mut control = [0u64; 4];
    // SAFETY: the buffers outlive `recvmsg`, and a received fd is owned by
    // this process from then on, so wrapping it in `OwnedFd` is sound.
    unsafe {
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[u64; 4]>() as _;
        let n = loop {
            let n = libc::recvmsg(report, &mut msg, FLAGS);
            if n >= 0 || errno_now() != libc::EINTR {
                break n;
            }
        };
        if n < 0 {
            return Err(Error::last_os_error()).context("reading the socket helper's answer");
        }
        let mut fd = None;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        {
            let raw = libc::CMSG_DATA(cmsg).cast::<RawFd>().read_unaligned();
            let owned = OwnedFd::from_raw_fd(raw);
            // Without MSG_CMSG_CLOEXEC (macOS), a session spawned on another
            // thread between `recvmsg` and this call can still inherit it.
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            if libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) != 0 {
                return Err(Error::last_os_error()).context("marking a received socket");
            }
            fd = Some(owned);
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(Error::from(ErrorKind::InvalidData))
                .context("the socket helper's answer was truncated");
        }
        if n as usize != payload.len() {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "the socket helper died",
            ))
            .context("reading the socket helper's answer");
        }
        let (head, rest) = payload.split_at(size_of::<libc::c_int>());
        let (dev, ino) = rest.split_at(size_of::<u64>());
        let bytes = |b: &[u8]| -> [u8; 8] { b.try_into().unwrap_or_default() };
        Ok(Answer {
            errno: libc::c_int::from_ne_bytes(head.try_into().unwrap_or_default()),
            fd,
            file: SocketFile {
                dev: u64::from_ne_bytes(bytes(dev)),
                ino: u64::from_ne_bytes(bytes(ino)),
            },
        })
    }
}

fn reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: waits on our own child; EINTR is retried.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 && errno_now() == libc::EINTR {}
}

impl SocketFile {
    fn of(st: &libc::stat) -> Self {
        // `dev_t` and `ino_t` widths differ by platform; both fit in u64.
        #[allow(clippy::unnecessary_cast)]
        Self {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
        }
    }
}

/// A `sockaddr_un` built before the fork.
struct SocketAddr {
    addr: libc::sockaddr_un,
    len: libc::socklen_t,
}

impl SocketAddr {
    fn new(path: &CString) -> Result<Self> {
        // SAFETY: an all-zero sockaddr_un is a valid empty address.
        let mut addr: libc::sockaddr_un = unsafe { zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_bytes_with_nul();
        if bytes.len() > addr.sun_path.len() {
            return Err(Error::from_raw_os_error(libc::ENAMETOOLONG).into());
        }
        for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
            *dst = *src as libc::c_char;
        }
        let offset = size_of::<libc::sockaddr_un>() - addr.sun_path.len();
        let len = libc::socklen_t::try_from(offset + bytes.len()).context("socket address")?;
        Ok(Self { addr, len })
    }

    fn as_ptr(&self) -> *const libc::sockaddr {
        (&self.addr as *const libc::sockaddr_un).cast()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    fn me() -> Arc<LoginInfo> {
        let name = uzers::get_current_username().expect("a passwd entry");
        Arc::new(super::super::login::resolve_login(&name.to_string_lossy()).expect("login"))
    }

    #[tokio::test]
    async fn listen_connect_and_clean_up() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sub = dir.path().join("private");
        create_dir(me(), sub.clone()).await.expect("create dir");
        let path = sub.join("s.sock");
        let bound = listen(me(), path.clone()).await.expect("listen");
        let _client = connect(me(), path.clone()).await.expect("connect");
        let (accepted, _) = bound.listener.accept().await.expect("accept");
        let cred = accepted.peer_cred().expect("peer credentials");
        assert_eq!(cred.uid(), me().uid);
        // Linux records the pid that connected. macOS reports the last process
        // to use the peer socket, which is this one once the helper hands it
        // back; the uid is still the one fixed at connect time.
        #[cfg(target_os = "linux")]
        assert_ne!(cred.pid(), Some(std::process::id() as i32));

        remove_socket(me(), path.clone(), bound.file)
            .await
            .expect("remove socket");
        assert!(!path.exists());
        remove_dir(me(), sub.clone()).await.expect("remove dir");
        assert!(!sub.exists());
    }

    fn close_on_exec(fd: RawFd) -> bool {
        // SAFETY: F_GETFD on an fd the caller holds open.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed");
        flags & libc::FD_CLOEXEC != 0
    }

    #[tokio::test]
    async fn returned_sockets_are_not_inherited_by_spawned_sessions() {
        // A forward's socket must not leak into the next shell the daemon
        // spawns, which may belong to another account. Close-on-exec is a
        // descriptor flag and does not travel over SCM_RIGHTS.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("s.sock");
        let bound = listen(me(), path.clone()).await.expect("listen");
        let client = connect(me(), path).await.expect("connect");
        assert!(close_on_exec(bound.listener.as_raw_fd()), "listener leaks");
        assert!(close_on_exec(client.as_raw_fd()), "stream leaks");
    }

    #[test]
    fn a_stuck_helper_is_killed_at_the_deadline() {
        // A login account can make a path lookup block forever (a FUSE mount
        // that never answers). The daemon thread must get its answer anyway.
        let dir = tempfile::tempdir().expect("temp dir");
        let err = run(&me(), dir.path(), Op::Hang, Duration::from_millis(200))
            .err()
            .expect("the helper never answers");
        let io = err.downcast_ref::<Error>().expect("an io error");
        assert_eq!(io.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn a_helper_holds_none_of_the_daemons_descriptors() {
        // A helper the account stalls lives for up to the deadline. Holding
        // the daemon's listeners and connections that long keeps ports bound
        // and connections from closing after the daemon let go of them.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let dir = tempfile::tempdir().expect("temp dir");
        run(
            &me(),
            dir.path(),
            Op::Inherited(listener.as_raw_fd()),
            HELPER_DEADLINE,
        )
        .map(drop)
        .expect("the helper inherited a daemon socket");
    }

    fn leaked_limits(
        total: usize,
        per_account: usize,
        queue_wait: Duration,
    ) -> &'static HelperLimits {
        Box::leak(Box::new(HelperLimits::new(total, per_account, queue_wait)))
    }

    #[tokio::test]
    async fn helpers_wait_for_a_free_place() {
        // Helpers occupy blocking-pool threads, so how many run at once is
        // capped across every connection; the rest queue.
        let limits = leaked_limits(1, 1, Duration::from_secs(20));
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("missing.sock");
        let held = limits.total.acquire().await.expect("the only place");
        let waiting = run_gated(limits, me(), missing, Op::Connect);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut waiting)
                .await
                .is_err(),
            "a helper ran without a free place"
        );
        drop(held);
        let err = waiting.await.err().expect("nothing listens there");
        let io = err.downcast_ref::<Error>().expect("an io error");
        assert_eq!(io.kind(), ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn a_full_queue_fails_instead_of_stalling_the_session() {
        // `-R` and agent setup wait inside the connection's session task, so
        // a wait for a helper must end in an error, not hang that session.
        let limits = leaked_limits(1, 1, Duration::from_millis(200));
        let dir = tempfile::tempdir().expect("temp dir");
        let _held = limits.total.acquire().await.expect("the only place");
        let err = tokio::time::timeout(
            Duration::from_secs(20),
            run_gated(limits, me(), dir.path().join("s.sock"), Op::Connect),
        )
        .await
        .expect("the queue wait is bounded")
        .err()
        .expect("no helper place");
        let io = err.downcast_ref::<Error>().expect("an io error");
        assert_eq!(io.kind(), ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn an_account_at_its_limit_waits_alone() {
        // One account stalling its own helpers fills only its own places.
        let limits = leaked_limits(8, 1, Duration::from_millis(200));
        let info = me();
        let _held = limits
            .account(info.uid)
            .acquire_owned()
            .await
            .expect("place");
        let dir = tempfile::tempdir().expect("temp dir");
        let err = run_gated(limits, info, dir.path().join("s.sock"), Op::Connect)
            .await
            .err()
            .expect("the account is at its limit");
        let io = err.downcast_ref::<Error>().expect("an io error");
        assert_eq!(io.kind(), ErrorKind::TimedOut);
        assert_eq!(
            limits.total.available_permits(),
            8,
            "it took a shared place"
        );
        assert!(
            limits.account(u32::MAX).try_acquire_owned().is_ok(),
            "another account is blocked"
        );
    }

    #[tokio::test]
    async fn cleanup_spares_a_socket_bound_again_at_the_same_path() {
        // A replaced `-R` forward: the new one rebinds the path, then the old
        // one's cleanup runs. It must not take the new socket with it.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("s.sock");
        let old = listen(me(), path.clone()).await.expect("first listen");
        let new = listen(me(), path.clone()).await.expect("second listen");
        remove_socket(me(), path.clone(), old.file)
            .await
            .expect("old cleanup");
        assert!(path.exists(), "the new socket's file was removed");
        remove_socket(me(), path.clone(), new.file)
            .await
            .expect("new cleanup");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn connect_reports_the_kernels_refusal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let err = connect(me(), dir.path().join("missing.sock"))
            .await
            .expect_err("nothing listens there");
        let io = err.downcast_ref::<Error>().expect("an io error");
        assert_eq!(io.kind(), ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn listen_never_replaces_a_file_that_is_not_a_socket() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("plain");
        std::fs::write(&path, b"keep").expect("write file");
        assert!(
            listen(me(), path.clone()).await.is_err(),
            "a file is in the way"
        );
        let meta = std::fs::metadata(&path).expect("metadata");
        let file = SocketFile {
            dev: meta.dev(),
            ino: meta.ino(),
        };
        remove_socket(me(), path.clone(), file)
            .await
            .expect("not a socket is fine");
        assert_eq!(std::fs::read(&path).expect("read"), b"keep");
    }
}
