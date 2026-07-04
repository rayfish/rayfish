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
use bytes::{BufMut, BytesMut};
use rayfish::tun::{TunRead, TunWrite};
use tokio::io::unix::AsyncFd;

/// One IP packet never exceeds the interface MTU (1280 on the desktop TUN); we
/// keep at least this much contiguous spare capacity before each read so a
/// packet is never truncated.
const READ_CHUNK: usize = 2048;

/// Mark an already-owned fd non-blocking (required by `AsyncFd`), in place.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
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
}

impl AndroidTunReader {
    /// Take ownership of the detached `VpnService` fd directly (no dup). The fd
    /// is closed on drop, so the caller must not close it again.
    ///
    /// # Safety
    /// `fd` must be an open, owned descriptor (e.g. from Kotlin `detachFd()`)
    /// that nothing else will close.
    pub unsafe fn from_owned_fd(fd: RawFd) -> Result<Self> {
        set_nonblocking(fd)?;
        // SAFETY: caller guarantees `fd` is a valid, owned descriptor; wrap it so
        // it closes exactly once on drop.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd: AsyncFd::new(owned)?,
        })
    }
}

impl TunRead for AndroidTunReader {
    async fn read_into(&mut self, buf: &mut BytesMut) -> Result<usize> {
        if buf.capacity() - buf.len() < READ_CHUNK {
            buf.reserve(READ_CHUNK);
        }
        loop {
            let mut guard = self.fd.readable_mut().await?;
            let out = guard.try_io(|inner| {
                let raw = inner.get_ref().as_raw_fd();
                let spare = buf.spare_capacity_mut();
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
                    unsafe { buf.advance_mut(n) };
                    return Ok(n);
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
    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < packet.len() {
            let mut guard = self.fd.writable_mut().await?;
            let out = guard.try_io(|inner| {
                let raw = inner.get_ref().as_raw_fd();
                let chunk = &packet[off..];
                // SAFETY: writes at most `chunk.len()` bytes from a valid slice.
                let n =
                    unsafe { libc::write(raw, chunk.as_ptr().cast::<libc::c_void>(), chunk.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match out {
                Ok(Ok(n)) => off += n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}
