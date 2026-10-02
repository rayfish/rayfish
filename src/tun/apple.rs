//! Batched macOS utun I/O using the private `sendmsg_x` and `recvmsg_x`
//! entry points. Symbols are resolved at runtime and callers fall back to
//! tun-rs when either is unavailable.

use std::collections::VecDeque;
use std::ffi::{c_int, c_uint, c_void};
use std::io;
use std::mem::{replace, transmute};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::null_mut;
use std::sync::OnceLock;

use bytes::{Bytes, BytesMut};
use libc::{AF_INET, AF_INET6, F_DUPFD_CLOEXEC, fcntl, iovec};
use tokio::io::unix::AsyncFd;

use super::TUN_MTU;

pub(super) const BATCH_SIZE: usize = 64;

const EMPTY_IOVEC: iovec = iovec {
    iov_base: null_mut(),
    iov_len: 0,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct MsgHdrX {
    msg_name: *mut c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut iovec,
    msg_iovlen: c_int,
    msg_control: *mut c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: c_int,
    msg_datalen: usize,
}

impl MsgHdrX {
    const ZEROED: Self = Self {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: null_mut(),
        msg_iovlen: 0,
        msg_control: null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
        msg_datalen: 0,
    };
}

type RecvMsgX = unsafe extern "C" fn(RawFd, *mut MsgHdrX, c_uint, c_int) -> isize;
type SendMsgX = unsafe extern "C" fn(RawFd, *const MsgHdrX, c_uint, c_int) -> isize;

struct BatchSyscalls {
    recvmsg_x: RecvMsgX,
    sendmsg_x: SendMsgX,
}

fn batch_syscalls() -> Option<&'static BatchSyscalls> {
    static SYSCALLS: OnceLock<Option<BatchSyscalls>> = OnceLock::new();
    SYSCALLS
        .get_or_init(|| {
            // SAFETY: RTLD_DEFAULT is a valid lookup handle and both names are
            // nul-terminated string literals.
            let recvmsg_x = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"recvmsg_x".as_ptr()) };
            let sendmsg_x = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"sendmsg_x".as_ptr()) };
            if recvmsg_x.is_null() || sendmsg_x.is_null() {
                tracing::info!("batched utun I/O unavailable; using per-packet I/O");
                return None;
            }
            tracing::info!(batch_size = BATCH_SIZE, "using batched utun I/O");
            Some(BatchSyscalls {
                // SAFETY: the symbols have the ABI declared in XNU's
                // socket_private.h and mirrored by the aliases above.
                recvmsg_x: unsafe { transmute::<*mut c_void, RecvMsgX>(recvmsg_x) },
                sendmsg_x: unsafe { transmute::<*mut c_void, SendMsgX>(sendmsg_x) },
            })
        })
        .as_ref()
}

fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl does not take ownership of fd and returns a new descriptor.
    let duplicate = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

pub(super) fn is_available() -> bool {
    batch_syscalls().is_some()
}

pub(super) fn split(fd: OwnedFd) -> io::Result<(Reader, Writer)> {
    let syscalls = batch_syscalls().expect("availability checked before splitting utun");
    let writer = duplicate(fd.as_raw_fd())?;
    Ok((Reader::new(fd, syscalls)?, Writer::new(writer, syscalls)?))
}

#[derive(Clone, Copy, Default)]
struct ReceivedPacket {
    family: u32,
    len: usize,
}

pub(super) struct Reader {
    fd: AsyncFd<OwnedFd>,
    syscalls: &'static BatchSyscalls,
    buffers: Vec<BytesMut>,
    pending: VecDeque<Bytes>,
}

impl Reader {
    fn new(fd: OwnedFd, syscalls: &'static BatchSyscalls) -> io::Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            syscalls,
            buffers: (0..BATCH_SIZE)
                .map(|_| BytesMut::zeroed(TUN_MTU as usize))
                .collect(),
            pending: VecDeque::with_capacity(BATCH_SIZE),
        })
    }

    pub(super) async fn read_packet(&mut self) -> io::Result<Bytes> {
        loop {
            if let Some(packet) = self.pending.pop_front() {
                return Ok(packet);
            }

            let fd = &self.fd;
            let buffers = &mut self.buffers;
            let mut guard = fd.readable().await?;
            let received = match guard.try_io(|inner| {
                // SAFETY: AsyncFd owns the open utun descriptor, and buffers
                // remain valid until recvmsg_x returns.
                unsafe { recv_batch(self.syscalls, inner.get_ref().as_raw_fd(), buffers) }
            }) {
                Ok(result) => result?,
                Err(_) => continue,
            };
            if received.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "packet tunnel closed",
                ));
            }

            for (index, packet) in received.into_iter().enumerate() {
                if packet.len == 0 {
                    continue;
                }
                let replacement = BytesMut::zeroed(TUN_MTU as usize);
                let mut bytes = replace(&mut self.buffers[index], replacement);
                bytes.truncate(packet.len);
                let version = bytes.first().map(|byte| byte >> 4);
                let expected = match packet.family as c_int {
                    AF_INET => Some(4),
                    AF_INET6 => Some(6),
                    _ => None,
                };
                if version != expected {
                    tracing::debug!(
                        family = packet.family,
                        ?version,
                        "utun packet family mismatch"
                    );
                    continue;
                }
                self.pending.push_back(bytes.freeze());
            }
        }
    }
}

pub(super) struct Writer {
    fd: AsyncFd<OwnedFd>,
    syscalls: &'static BatchSyscalls,
}

impl Writer {
    fn new(fd: OwnedFd, syscalls: &'static BatchSyscalls) -> io::Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            syscalls,
        })
    }

    pub(super) async fn write_packets(&mut self, packets: &[Bytes]) -> io::Result<()> {
        let mut offset = 0;
        while offset < packets.len() {
            let end = (offset + BATCH_SIZE).min(packets.len());
            let fd = &self.fd;
            let mut guard = fd.writable().await?;
            let sent = match guard.try_io(|inner| {
                // SAFETY: AsyncFd owns the open utun descriptor and the packet
                // buffers remain valid until sendmsg_x returns.
                unsafe {
                    send_batch(
                        self.syscalls,
                        inner.get_ref().as_raw_fd(),
                        &packets[offset..end],
                    )
                }
            }) {
                Ok(result) => result?,
                Err(_) => continue,
            };
            if sent == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            offset += sent;
        }
        Ok(())
    }
}

unsafe fn recv_batch(
    syscalls: &BatchSyscalls,
    fd: RawFd,
    buffers: &mut [BytesMut],
) -> io::Result<Vec<ReceivedPacket>> {
    let count = buffers.len().min(BATCH_SIZE);
    let mut families = [[0u8; 4]; BATCH_SIZE];
    let mut iovs = [[EMPTY_IOVEC; 2]; BATCH_SIZE];
    let mut messages = [MsgHdrX::ZEROED; BATCH_SIZE];

    for index in 0..count {
        buffers[index].resize(TUN_MTU as usize, 0);
        iovs[index] = [
            iovec {
                iov_base: families[index].as_mut_ptr().cast(),
                iov_len: families[index].len(),
            },
            iovec {
                iov_base: buffers[index].as_mut_ptr().cast(),
                iov_len: buffers[index].len(),
            },
        ];
        messages[index] = MsgHdrX {
            msg_iov: iovs[index].as_mut_ptr(),
            msg_iovlen: 2,
            ..MsgHdrX::ZEROED
        };
    }

    // SAFETY: all message headers and their iovecs point into live stack or
    // caller-owned buffers for the duration of the call.
    let received = unsafe { (syscalls.recvmsg_x)(fd, messages.as_mut_ptr(), count as c_uint, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = received as usize;
    if received > count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg_x returned more packets than requested",
        ));
    }
    let mut packets = Vec::with_capacity(received);
    for index in 0..received {
        let len = if messages[index].msg_flags & libc::MSG_TRUNC != 0 {
            0
        } else {
            messages[index]
                .msg_datalen
                .saturating_sub(families[index].len())
                .min(TUN_MTU as usize)
        };
        packets.push(ReceivedPacket {
            family: u32::from_be_bytes(families[index]),
            len,
        });
    }
    Ok(packets)
}

unsafe fn send_batch(syscalls: &BatchSyscalls, fd: RawFd, packets: &[Bytes]) -> io::Result<usize> {
    let count = packets.len().min(BATCH_SIZE);
    let mut families = [[0u8; 4]; BATCH_SIZE];
    let mut iovs = [[EMPTY_IOVEC; 2]; BATCH_SIZE];
    let mut messages = [MsgHdrX::ZEROED; BATCH_SIZE];

    for index in 0..count {
        let family = match packets[index].first().map(|byte| byte >> 4) {
            Some(4) => AF_INET,
            Some(6) => AF_INET6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun write is not an IP packet",
                ));
            }
        };
        families[index] = (family as u32).to_be_bytes();
        iovs[index] = [
            iovec {
                iov_base: families[index].as_ptr() as *mut c_void,
                iov_len: families[index].len(),
            },
            iovec {
                iov_base: packets[index].as_ptr() as *mut c_void,
                iov_len: packets[index].len(),
            },
        ];
        messages[index] = MsgHdrX {
            msg_iov: iovs[index].as_mut_ptr(),
            msg_iovlen: 2,
            ..MsgHdrX::ZEROED
        };
    }

    // SAFETY: all message headers and their iovecs point into live stack or
    // caller-owned packet buffers for the duration of the call.
    let sent = unsafe { (syscalls.sendmsg_x)(fd, messages.as_ptr(), count as c_uint, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let sent = sent as usize;
    if sent > count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sendmsg_x returned more packets than requested",
        ));
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use super::*;

    #[test]
    fn message_header_matches_apple_lp64_layout() {
        assert_eq!(size_of::<MsgHdrX>(), 56);
        assert_eq!(offset_of!(MsgHdrX, msg_iov), 16);
        assert_eq!(offset_of!(MsgHdrX, msg_flags), 44);
        assert_eq!(offset_of!(MsgHdrX, msg_datalen), 48);
    }
}
