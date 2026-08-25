//! Binding a TCP listener beside one the host already has.
//!
//! Its own module because both users need it and one of them does not exist on
//! every platform: this used to live in `ssh`, which is Unix-only, so `v4bridge`
//! reaching into it stopped the Windows build compiling.

use std::net::{IpAddr, SocketAddr};

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
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = (ip, port).into();
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    let std_listener: std::net::TcpListener = sock.into();
    Ok(TcpListener::from_std(std_listener)?)
}
