//! Binding a TCP listener beside one the host already has.
//!
//! Its own module because both users need it and one of them does not exist on
//! every platform: this used to live in `ssh`, which is Unix-only, so `v4bridge`
//! reaching into it stopped the Windows build compiling.

use std::io;
use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, setsockopt,
};

/// Bind a TCP listener on one specific address. Unix reuse options allow
/// coexistence with a wildcard host daemon. Windows reserves the endpoint
/// exclusively so another local process cannot take delivery of its traffic.
pub(crate) fn bind_listener(ip: IpAddr, port: u16) -> Result<TcpListener> {
    let domain = if ip.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(unix)]
    sock.set_reuse_address(true)?;
    #[cfg(windows)]
    reserve_windows_endpoint(&sock)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = (ip, port).into();
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    let std_listener: std::net::TcpListener = sock.into();
    Ok(TcpListener::from_std(std_listener)?)
}

/// Pause between failed accepts so an accept loop neither dies nor spins.
///
/// Most accept errors are about the listener's process, not the listener:
/// `EMFILE`/`ENFILE` when descriptors run out, `ECONNABORTED` for a client that
/// gave up in the backlog. Ending the loop on one takes the whole service down
/// for a single bad moment, and retrying at once on `EMFILE` is a busy loop,
/// because the pending connection stays queued and the next accept fails the
/// same way. So wait, doubling up to [`Self::MAX`], and start over after a
/// success. A client giving up needs no wait (see [`Self::wait`]).
pub(crate) struct AcceptBackoff {
    delay: Duration,
}

impl AcceptBackoff {
    const MIN: Duration = Duration::from_millis(5);
    const MAX: Duration = Duration::from_secs(1);

    pub(crate) const fn new() -> Self {
        Self { delay: Self::MIN }
    }

    /// An accept succeeded: the next failure starts from the shortest wait.
    pub(crate) fn reset(&mut self) {
        self.delay = Self::MIN;
    }

    /// Log a failed accept and sleep before the next attempt.
    ///
    /// A client that reset or abandoned its connection in the backlog is
    /// routine, not a fault of the listener: the next accept can succeed at
    /// once, so it is logged at debug and not waited on.
    pub(crate) async fn wait(&mut self, error: &io::Error, listener: &str) {
        if matches!(
            error.kind(),
            io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
        ) {
            tracing::debug!(%error, listener, "client left before accept");
            return;
        }
        tracing::warn!(%error, listener, retry_in = ?self.delay, "accept failed");
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(Self::MAX);
    }
}

#[cfg(windows)]
fn reserve_windows_endpoint(socket: &Socket) -> Result<()> {
    use std::io::Error as IoError;
    use std::mem::size_of_val;

    let enabled = 1_i32;
    // SAFETY: This owns the unbound socket. The option value is an initialized
    // integer whose buffer and declared length remain valid for the call.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket().try_into()?,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            size_of_val(&enabled).try_into()?,
        )
    };
    if result == SOCKET_ERROR {
        // SAFETY: Read the error immediately after this thread's Winsock call.
        return Err(IoError::from_raw_os_error(unsafe { WSAGetLastError() }).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::net::Ipv4Addr;

    use tokio::time::Instant;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn accept_backoff_doubles_to_a_cap_and_resets() {
        let error = io::Error::from_raw_os_error(24); // EMFILE
        let mut backoff = AcceptBackoff::new();
        let mut waits = Vec::new();
        for _ in 0..10 {
            let started = Instant::now();
            backoff.wait(&error, "test").await;
            waits.push(started.elapsed());
        }
        assert_eq!(waits[0], AcceptBackoff::MIN);
        assert_eq!(waits[1], AcceptBackoff::MIN * 2);
        assert!(waits.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(*waits.last().unwrap(), AcceptBackoff::MAX);

        backoff.reset();
        let started = Instant::now();
        backoff.wait(&error, "test").await;
        assert_eq!(started.elapsed(), AcceptBackoff::MIN);
    }

    /// A client that gave up in the backlog is routine: the next accept can
    /// succeed at once, so there is no wait and the backoff does not grow.
    #[tokio::test(start_paused = true)]
    async fn a_client_giving_up_is_not_backed_off() {
        let mut backoff = AcceptBackoff::new();
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
        ] {
            let started = Instant::now();
            backoff.wait(&io::Error::from(kind), "test").await;
            assert_eq!(started.elapsed(), Duration::ZERO, "{kind:?}");
        }
        let started = Instant::now();
        backoff
            .wait(&io::Error::from_raw_os_error(24), "test")
            .await;
        assert_eq!(started.elapsed(), AcceptBackoff::MIN);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_listener_rejects_a_competing_reuse_address_bind() {
        let listener = bind_listener(Ipv4Addr::LOCALHOST.into(), 0)
            .expect("the first loopback listener must bind");
        let address = listener.local_addr().expect("the listener has an address");
        let competing = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("the competing socket must open");
        competing
            .set_reuse_address(true)
            .expect("the competing socket must enable address reuse");
        assert!(
            competing.bind(&address.into()).is_err(),
            "a second process must not bind the reserved listener endpoint"
        );
    }
}
