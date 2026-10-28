//! Binding a TCP listener beside one the host already has.
//!
//! Its own module because both users need it and one of them does not exist on
//! every platform: this used to live in `ssh`, which is Unix-only, so `v4bridge`
//! reaching into it stopped the Windows build compiling.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpListener;

/// Bind a TCP listener on one specific address with SO_REUSEADDR (and
/// SO_REUSEPORT on Unix) so it can coexist with a host daemon bound on the
/// wildcard address: the SSH server's port alongside a host sshd on
/// `0.0.0.0:22`, and every port `v4bridge` claims on the mesh address alongside
/// the `0.0.0.0` listener it bridges to. Returns a tokio listener ready to
/// accept.
pub(crate) fn bind_listener(ip: IpAddr, port: u16) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if ip.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    // Unix only, and deliberately not "because Windows has no SO_REUSEPORT".
    // Windows spells SO_REUSEADDR differently enough to matter: it lets *any*
    // process, including one running as another unprivileged user, bind the
    // same address and take delivery. The Unix pair is a coexistence primitive;
    // the Windows option is a hijack primitive, which is why SO_EXCLUSIVEADDRUSE
    // exists. Nothing binds through here on Windows today (`v4bridge` has no
    // port enumeration there), so the first caller that does needs to set
    // SO_EXCLUSIVEADDRUSE by hand: socket2 0.6 does not expose it.
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
/// success.
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
    pub(crate) async fn wait(&mut self, error: &io::Error, listener: &str) {
        tracing::warn!(%error, listener, retry_in = ?self.delay, "accept failed");
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(Self::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::time::Instant;

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
}
