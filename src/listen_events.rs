//! Noticing when the host's set of listening TCP sockets changes.
//!
//! [`crate::v4bridge`] needs to know when a service starts or stops listening,
//! and the portable way to find out is to re-read the host's socket table on a
//! timer. That works, but it is a poll: it costs a scan whether or not anything
//! changed, and it pays for the answer twice over, since `/proc/net/tcp` holds
//! every socket on the host and a listener is a small fraction of them. It also
//! bounds how late the bridge can be by the interval itself.
//!
//! Linux can just say. The `sock:inet_sock_set_state` tracepoint (4.16 and up)
//! fires on every TCP state transition, so a socket entering `TCP_LISTEN` is an
//! event we can wait on, and the wait costs nothing while the host is quiet.
//! Reaching it needs neither eBPF nor a new dependency: ftrace will write the
//! events to a file we read, and the daemon already runs as root.
//!
//! Three things make that safe to do in a long-lived daemon:
//!
//! - **A private instance.** `tracing/instances/<name>/` is its own ring buffer
//!   with its own enabled events and its own `trace_pipe`, so enabling a
//!   tracepoint here does not disturb a `perf` or `bpftrace` session using the
//!   top-level one. The instance is removed when the watcher stops.
//! - **A filter that names both endpoints of a transition.** See `FILTER`:
//!   the obvious spelling of "a listening socket changed" also matches every
//!   inbound connection the host accepts, which is a firehose rather than the
//!   handful of events we want.
//! - **A buffer sized on purpose.** A fresh instance takes about 1.4 MB of
//!   kernel memory *per CPU*, which on a many-core host is tens of megabytes
//!   standing by for a few events a day.
//!
//! What arrives is a trigger and never data: the caller rescans the socket
//! table, exactly as it would have on its timer. The event says *when* to look,
//! it is not itself an answer about what the host is listening on. That is the
//! same rule the control plane holds for its own sync messages, and it is what
//! keeps this module from having to reason about the state of a socket it saw
//! one transition of.

use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;

/// Watch for changes to the host's listening TCP sockets, or `None` where the
/// kernel here will not report them, which leaves the caller on its timer.
///
/// Each message means "the set of listening sockets may have changed". The
/// channel holds one: a trigger that is already pending says everything a
/// second one would, so a burst coalesces into a single rescan.
#[cfg(target_os = "linux")]
pub(crate) fn watch(token: &CancellationToken) -> Option<Receiver<()>> {
    linux::watch(INSTANCE, token)
}

/// No equivalent notification. macOS has no listen event to subscribe to, and
/// Android's `/proc/net/tcp` shows only the caller's own sockets, so there is
/// nothing to watch there either.
#[cfg(not(target_os = "linux"))]
pub(crate) fn watch(_token: &CancellationToken) -> Option<Receiver<()>> {
    None
}

/// The ftrace instance the daemon owns.
///
/// Fixed rather than per-process on purpose. The panic hook `abort()`s, so a
/// run can end without removing its instance, and a fixed name means the next
/// start adopts that one instead of leaving a new directory behind on every
/// crash. Only one daemon runs per host, so there is nothing to collide with;
/// what does need its own name is a test, which is why the name is a parameter
/// one level down.
///
/// tracefs is not namespaced, so two daemons that could both see one would
/// contend for this directory. Containers do not get tracefs mounted, which is
/// what keeps that theoretical, and it degrades the safe way if it ever is not:
/// the loser's reads end, its watcher stops, and the caller puts its timer
/// back.
#[cfg(target_os = "linux")]
const INSTANCE: &str = "rayfish";

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File};
    use std::io::{ErrorKind, Read};
    use std::path::{Path, PathBuf};

    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc::{self, Receiver, Sender};
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, warn};

    /// The tracepoint, as it is named under `events/`.
    const EVENT: &str = "sock/inet_sock_set_state";

    /// The two transitions worth waking for: a socket entering `TCP_LISTEN`
    /// (10), and a listening socket closing (10 to `TCP_CLOSE`, 7).
    ///
    /// Naming both endpoints of the second one is load-bearing. `oldstate==10`
    /// on its own reads as "a listening socket changed", but it also matches
    /// `TCP_LISTEN` to `TCP_SYN_RECV`, which is *every inbound connection the
    /// host accepts*. Measured on one moderately busy box that was 241 events
    /// in twelve seconds against the 7 real listen changes in the same window,
    /// and it scales with the host's traffic rather than with its listeners.
    const FILTER: &str = "newstate==10 || (oldstate==10 && newstate==7)";

    /// Per-CPU ring buffer size. The kernel rounds this up to whole pages, and
    /// the events are a line each at a rate of a few per minute at worst, so
    /// the floor is plenty: what matters is not inheriting the ~1.4 MB per CPU
    /// a fresh instance defaults to.
    const BUFFER_KB: &str = "32";

    /// Where tracefs is mounted, in the order to try. The second is the older
    /// mount point, still the only one on some kernels.
    const ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

    pub(super) fn watch(name: &str, token: &CancellationToken) -> Option<Receiver<()>> {
        let instance = Instance::open(name)?;
        let pipe = instance.open_pipe()?;
        // Depth one: see `watch`'s contract. `try_send` dropping a message
        // because one is already queued is the coalescing, not a loss.
        let (tx, rx) = mpsc::channel(1);
        let token = token.clone();
        tokio::spawn(async move {
            read_loop(pipe, tx, &token).await;
            // Explicit, and ordered: the pipe is dropped by `read_loop`
            // returning, and the instance cannot be removed while a file inside
            // it is still open.
            drop(instance);
        });
        Some(rx)
    }

    /// Wait for lines and turn each batch into one trigger.
    ///
    /// The lines themselves are never parsed. The filter has already made any
    /// line mean "a listening socket changed", and the answer to all of them is
    /// the same rescan, so there is nothing a parse could decide. It also gives
    /// the kernel's own `CPU:N [LOST M EVENTS]` marker the right behaviour for
    /// free: a lost event and a delivered one both mean look again.
    async fn read_loop(pipe: AsyncFd<File>, tx: Sender<()>, token: &CancellationToken) {
        let mut buf = [0u8; 4096];
        loop {
            let mut guard = tokio::select! {
                _ = token.cancelled() => break,
                readable = pipe.readable() => match readable {
                    Ok(guard) => guard,
                    Err(e) => {
                        warn!(error = %e, "listen events: cannot wait on the trace pipe");
                        break;
                    }
                },
            };
            // `&File` reads, and the guard wants the syscall to report
            // `WouldBlock` itself so it can clear the readiness it just saw.
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(&mut buf)
            }) {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => {
                    if tx.is_closed() {
                        break;
                    }
                    let _ = tx.try_send(());
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "listen events: cannot read the trace pipe");
                    break;
                }
                // Not actually readable after all; the guard has cleared it.
                Err(_would_block) => continue,
            }
        }
        debug!("listen events: watcher stopped");
    }

    /// A private ftrace instance, removed when this is dropped.
    pub(super) struct Instance {
        dir: PathBuf,
    }

    impl Instance {
        /// Create (or adopt) the instance and enable the tracepoint in it.
        pub(super) fn open(name: &str) -> Option<Self> {
            let root = ROOTS
                .iter()
                .map(Path::new)
                .find(|root| root.join("events").join(EVENT).is_dir())?;
            let dir = root.join("instances").join(name);
            match fs::create_dir(&dir) {
                Ok(()) => {}
                // Left behind by a run that ended in the panic hook's abort().
                // Adopting it is right: every setting below is rewritten, so a
                // stale filter from an older build cannot survive.
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => {
                    debug!(error = %e, "listen events: cannot create a trace instance");
                    return None;
                }
            }
            let instance = Self { dir };
            // Ordered: quiet first, so resizing an adopted buffer is not
            // refused for being in use, then the filter, and only then the
            // events it selects.
            let _ = instance.write("enable", "0");
            if let Err(e) = instance.write("buffer", BUFFER_KB) {
                warn!(error = %e, "listen events: cannot size the trace buffer");
            }
            if let Err(e) = instance.write("filter", FILTER) {
                debug!(error = %e, "listen events: cannot filter the listen tracepoint");
                return None;
            }
            if let Err(e) = instance.write("enable", "1") {
                debug!(error = %e, "listen events: cannot enable the listen tracepoint");
                return None;
            }
            debug!(instance = %instance.dir.display(), "listen events: watching for listen changes");
            Some(instance)
        }

        pub(super) fn open_pipe(&self) -> Option<AsyncFd<File>> {
            use std::os::unix::fs::OpenOptionsExt;
            // Non-blocking so the read is a readiness wait the cancellation
            // token can interrupt, rather than a thread parked in the kernel
            // for as long as the host stays quiet.
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(self.dir.join("trace_pipe"))
                .map_err(|e| debug!(error = %e, "listen events: cannot open the trace pipe"))
                .ok()?;
            AsyncFd::new(file)
                .map_err(|e| debug!(error = %e, "listen events: cannot watch the trace pipe"))
                .ok()
        }

        /// One of the instance's control files. `enable` and `filter` are the
        /// tracepoint's own; `buffer` is the instance-wide ring buffer size.
        fn write(&self, what: &str, value: &str) -> std::io::Result<()> {
            let path = match what {
                "buffer" => self.dir.join("buffer_size_kb"),
                other => self.dir.join("events").join(EVENT).join(other),
            };
            fs::write(path, value)
        }
    }

    impl Drop for Instance {
        fn drop(&mut self) {
            // Leave the tracepoint off even if the directory outlives us, so a
            // failed removal does not leave the kernel writing events nobody
            // reads.
            let _ = self.write("enable", "0");
            if let Err(e) = fs::remove_dir(&self.dir) {
                debug!(error = %e, "listen events: cannot remove the trace instance");
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    /// Its own instance name: the daemon's is fixed, and adopting the one a
    /// running daemon owns would have this test remove it on the way out.
    const TEST_INSTANCE: &str = "rayfish_selftest";

    /// The whole path, against the real kernel: enable the tracepoint, start
    /// listening, and expect to be told, then accept a connection on that same
    /// listener and expect *not* to be.
    ///
    /// Both halves matter and the second one is the reason this test exists.
    /// The filter's obvious spelling reports an accepted connection as a listen
    /// change, which is correct-looking, silent, and turns a few events a
    /// minute into one per inbound connection on the host. Nothing but the
    /// kernel can answer whether the filter still draws that line, so the test
    /// asks it.
    ///
    /// Needs root and a mounted tracefs, and skips without them, so this is not
    /// the coverage that carries the feature; `tests/e2e/v4bridge` runs it with
    /// privileges on every run.
    #[tokio::test]
    async fn a_listen_is_reported_and_an_accepted_connection_is_not() {
        let token = CancellationToken::new();
        let Some(mut events) = linux::watch(TEST_INSTANCE, &token) else {
            eprintln!("no tracefs access here (needs root); skipping");
            return;
        };
        // Bound after the watcher is up, so the trigger can only be this one.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port");
        let addr = listener.local_addr().expect("the bound address");
        let listened = timeout(Duration::from_secs(5), events.recv()).await;
        assert_eq!(
            listened.expect("a listen event within five seconds"),
            Some(()),
            "the watcher stopped instead of reporting the listen"
        );

        // Drain the settled state, then make the transition that must not wake
        // us: an inbound connection, which moves the listening socket to
        // TCP_SYN_RECV and back without changing what the host listens on.
        while events.try_recv().is_ok() {}
        let client = TcpStream::connect(addr).await.expect("connecting");
        let (accepted, _) = listener.accept().await.expect("accepting");
        let quiet = timeout(Duration::from_secs(1), events.recv()).await;
        assert!(
            quiet.is_err(),
            "an accepted connection was reported as a listen change: the \
             filter matches TCP_LISTEN on either side of a transition, so \
             every inbound connection on the host now triggers a rescan"
        );

        drop((client, accepted, listener));
        token.cancel();
    }
}
