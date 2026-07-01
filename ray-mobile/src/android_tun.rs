//! `TunRead` / `TunWrite` over an Android `VpnService` file descriptor.
//!
//! Kotlin hands us the raw `int` fd returned by `VpnService.Builder.establish()`.
//! We `dup()` it so the reader and writer each own an independent descriptor that
//! is closed on drop; the underlying tunnel closes once every dup is dropped and
//! Kotlin closes its own copy. `tokio::io::unix::AsyncFd` drives readiness; the
//! raw `read`/`write` syscalls move one IP packet at a time.

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

/// `dup` the caller's fd, mark the copy non-blocking (required by `AsyncFd`), and
/// take ownership of the copy.
fn dup_nonblocking(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `dup` returns a fresh, independent descriptor we then own.
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` is a valid, owned fd; wrap it so it closes on drop.
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Read half of the Android `VpnService` fd.
pub struct AndroidTunReader {
    fd: AsyncFd<OwnedFd>,
}

impl AndroidTunReader {
    pub fn new(fd: RawFd) -> Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(dup_nonblocking(fd)?)?,
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
                let n = unsafe {
                    libc::write(raw, chunk.as_ptr().cast::<libc::c_void>(), chunk.len())
                };
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
