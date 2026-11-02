//! `TunRead` / `TunWrite` over an Android `VpnService` file descriptor.
//!
//! Kotlin hands us the raw `int` fd returned by `VpnService.Builder.establish()`
//! after `detachFd()`, transferring ownership to native code. The reader takes
//! ownership of that fd directly; the writer owns a single `dup()` of it. Both
//! close on drop, so the underlying tunnel closes once the reader and writer (and
//! their tasks) drop: exactly two owned fds, each closed exactly once, no leak.
//! `tokio::io::unix::AsyncFd` drives readiness; the raw `read`/`write` syscalls
//! move one IP packet at a time.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use rayfish::tun::{TunRead, TunWrite};
use tokio::io::unix::AsyncFd;

/// One IP packet never exceeds the interface MTU (1500 bytes); we
/// keep at least this much contiguous spare capacity before each read so a
/// packet is never truncated.
const READ_CHUNK: usize = 2048;
const RECEIVE_POOL_CHUNK: usize = 64 * 1024;

/// Mark an already-owned fd non-blocking (required by `AsyncFd`), in place.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL only reads the descriptor's status flags; an invalid fd
    // is reported as -1/EBADF, not undefined behaviour.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL with the flags just read plus O_NONBLOCK touches only
    // this descriptor's status flags, and the caller owns the descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `dup` the caller's fd, mark the copy non-blocking, and take ownership of it.
///
/// The dup shares the underlying open-file-description, so `O_NONBLOCK` set on
/// either fd applies to both; we set it explicitly here to be safe.
fn dup_nonblocking(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `dup` returns a fresh, independent descriptor we then own.
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` is a valid, owned fd; wrap it so it closes on drop.
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    set_nonblocking(owned.as_raw_fd())?;
    Ok(owned)
}

/// Read half of the Android `VpnService` fd.
pub struct AndroidTunReader {
    fd: AsyncFd<OwnedFd>,
    buffer: BytesMut,
}

impl AndroidTunReader {
    /// Take the detached `VpnService` fd directly (no dup), consuming the
    /// caller's ownership of it. Taking `OwnedFd` rather than a raw `int` is
    /// what makes the failure paths safe: if either step below fails, `fd` is
    /// dropped and closed here instead of being stranded with no owner, which
    /// would leave the `VpnService` interface up for the life of the process.
    pub fn new(fd: OwnedFd) -> Result<Self> {
        set_nonblocking(fd.as_raw_fd())?;
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            buffer: BytesMut::with_capacity(RECEIVE_POOL_CHUNK),
        })
    }
}

impl TunRead for AndroidTunReader {
    async fn read_packet(&mut self) -> Result<Bytes> {
        if self.buffer.capacity() - self.buffer.len() < READ_CHUNK {
            self.buffer.reserve(RECEIVE_POOL_CHUNK);
        }
        loop {
            let mut guard = self.fd.readable_mut().await?;
            let out = guard.try_io(|inner| {
                let raw = inner.get_ref().as_raw_fd();
                let spare = self.buffer.spare_capacity_mut();
                // SAFETY: read writes at most `spare.len()` bytes into the
                // uninitialised spare capacity; we advance the length only by
                // the returned count below.
                let n = unsafe {
                    libc::read(raw, spare.as_mut_ptr().cast::<libc::c_void>(), spare.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match out {
                // read() == 0 on a stream fd means end-of-stream: the VpnService
                // descriptor was revoked/closed. Per the `TunRead` contract this
                // MUST be an error, never a perpetual `Ok(0)` (which would make
                // `run_mesh` busy-spin at 100% CPU).
                Ok(Ok(0)) => bail!("android tun fd reached EOF (revoked or closed)"),
                Ok(Ok(n)) => {
                    // SAFETY: the kernel initialised exactly `n` spare bytes.
                    unsafe { self.buffer.advance_mut(n) };
                    return Ok(self.buffer.split_to(n).freeze());
                }
                Ok(Err(e)) => return Err(e.into()),
                // Spurious readiness (would-block): re-arm and wait again.
                Err(_would_block) => continue,
            }
        }
    }
}

/// Write half of the Android `VpnService` fd.
pub struct AndroidTunWriter {
    fd: AsyncFd<OwnedFd>,
}

impl AndroidTunWriter {
    pub fn new(fd: RawFd) -> Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(dup_nonblocking(fd)?)?,
        })
    }
}

impl TunWrite for AndroidTunWriter {
    /// One `write` per packet. A TUN takes a whole packet or none of it, so a
    /// short write is an error: writing the remainder again would hand the
    /// kernel a second, truncated packet made of the first one's tail.
    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        loop {
            let mut guard = self.fd.writable_mut().await?;
            let out = guard.try_io(|inner| {
                let raw = inner.get_ref().as_raw_fd();
                // SAFETY: writes at most `packet.len()` bytes from a valid slice.
                let n = unsafe {
                    libc::write(raw, packet.as_ptr().cast::<libc::c_void>(), packet.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match out {
                Ok(Ok(n)) if n == packet.len() => return Ok(()),
                Ok(Ok(n)) => bail!(
                    "android tun accepted {n} of {} bytes; packet dropped",
                    packet.len()
                ),
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    /// A pipe stands in for the TUN fd: with its buffer at one page, a larger
    /// write is accepted only in part, which is the case a TUN must never
    /// receive as two packets.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_short_write_is_an_error_not_a_second_packet() {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors pipe writes.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both descriptors were just returned by pipe and are owned here.
        let (read_end, write_end) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: F_SETPIPE_SZ resizes the pipe buffer of a descriptor we own.
        let size = unsafe { libc::fcntl(write_end.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
        assert!(size >= 4096);
        let page = usize::try_from(size).expect("pipe size is positive");

        let mut writer = AndroidTunWriter::new(write_end.as_raw_fd()).expect("writer");
        let packet = vec![0u8; page * 2];
        let result = tokio::time::timeout(Duration::from_secs(10), writer.write_packet(&packet))
            .await
            .expect("a short write must fail, not wait to write the rest");
        assert!(result.is_err());
        drop(read_end);
    }
}
