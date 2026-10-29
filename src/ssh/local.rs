//! Self-SSH uses the client socket's local owner, not the node's mesh grants.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

/// A separate IPv6-only listener avoids colliding with an IPv4 host sshd.
/// Do not use SO_REUSEPORT: another process must not share these sessions.
pub(super) fn bind(address: Ipv6Addr, port: u16) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(address), port).into())?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

/// A cancelled listener can take a scheduler turn to release its old port.
pub(super) async fn bind_retry(address: Ipv6Addr, port: u16) -> io::Result<TcpListener> {
    use std::time::Duration;
    use tokio::time::sleep;

    for _ in 0..10 {
        match bind(address, port) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                sleep(Duration::from_millis(50)).await;
            }
            result => return result,
        }
    }
    bind(address, port)
}

/// The public-port listener accepts only self-traffic. Peer traffic uses the
/// internal listener after passing the mesh firewall and port translation.
pub(super) async fn accept(
    mesh: &TcpListener,
    local: Option<&TcpListener>,
) -> io::Result<(TcpStream, SocketAddr)> {
    let Some(local) = local else {
        return mesh.accept().await;
    };
    loop {
        tokio::select! {
            accepted = mesh.accept() => return accepted,
            accepted = local.accept() => {
                let (stream, client) = accepted?;
                if client.ip() == stream.local_addr()?.ip() {
                    return Ok((stream, client));
                }
            }
        }
    }
}

/// Match the complete client-side socket tuple while the accepted server socket
/// is held open. Missing, closed, or ambiguous client sockets fail closed.
///
/// So does a client socket this process holds. The daemon dials TCP as root on
/// a peer's behalf (`ssh -L`, `-J`), and a dial to its own self-SSH port would
/// otherwise be read as a root login on this host.
pub(super) async fn uid(client: SocketAddr, server: SocketAddr) -> Option<u32> {
    if client.ip() != server.ip() {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        let table = tokio::fs::read_to_string("/proc/net/tcp6").await.ok()?;
        let owner = proc_owner(&table, client, server)?;
        if held_by_this_process(owner.inode).await {
            tracing::warn!(%client, "mesh SSH: refusing self-SSH from a socket the daemon holds");
            return None;
        }
        Some(owner.uid)
    }
    #[cfg(target_os = "macos")]
    {
        use std::time::Duration;
        use tokio::process::Command;
        use tokio::time::timeout;

        let output = timeout(
            Duration::from_secs(3),
            Command::new("/usr/sbin/lsof")
                .args([
                    "-nP",
                    "-a",
                    "-Fpun",
                    "-i",
                    &format!("6TCP:{}", client.port()),
                    "-sTCP:ESTABLISHED",
                ])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .ok()?
        .ok()?;
        if !output.status.success() {
            return None;
        }
        let owner = lsof_owner(std::str::from_utf8(&output.stdout).ok()?, client, server)?;
        if owner.pid == std::process::id() {
            tracing::warn!(%client, "mesh SSH: refusing self-SSH from a socket the daemon holds");
            return None;
        }
        Some(owner.uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

/// The owner of a client socket in `/proc/net/tcp6`.
#[cfg(any(target_os = "linux", test))]
struct ProcOwner {
    uid: u32,
    inode: u64,
}

/// Whether one of this process's descriptors is the socket `inode`. Fails
/// closed: if the descriptor table cannot be read, the answer is yes.
#[cfg(target_os = "linux")]
async fn held_by_this_process(inode: u64) -> bool {
    let target = format!("socket:[{inode}]");
    let Ok(mut fds) = tokio::fs::read_dir("/proc/self/fd").await else {
        return true;
    };
    loop {
        match fds.next_entry().await {
            Ok(Some(fd)) => {
                if tokio::fs::read_link(fd.path())
                    .await
                    .is_ok_and(|link| link.as_os_str() == target.as_str())
                {
                    return true;
                }
            }
            Ok(None) => return false,
            Err(_) => return true,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn proc_owner(table: &str, client: SocketAddr, server: SocketAddr) -> Option<ProcOwner> {
    fn endpoint(address: SocketAddr) -> Option<String> {
        let IpAddr::V6(ip) = address.ip() else {
            return None;
        };
        let mut text = String::new();
        for word in ip.octets().as_chunks::<4>().0 {
            let word = u32::from_ne_bytes(*word);
            text.push_str(&format!("{word:08X}"));
        }
        Some(format!("{text}:{:04X}", address.port()))
    }
    let client = endpoint(client)?;
    let server = endpoint(server)?;
    let mut owner = None;
    for line in table.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(1) == Some(&client.as_str()) && fields.get(2) == Some(&server.as_str()) {
            // ESTABLISHED and a live inode, never a TIME_WAIT row's default UID.
            let inode = fields.get(9)?.parse::<u64>().ok()?;
            if fields.get(3) != Some(&"01") || inode == 0 {
                return None;
            }
            let uid = fields.get(7)?.parse().ok()?;
            if owner.replace(ProcOwner { uid, inode }).is_some() {
                return None;
            }
        }
    }
    owner
}

/// The process holding a client socket, from `lsof -F`.
#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, PartialEq, Eq)]
struct LsofOwner {
    uid: u32,
    pid: u32,
}

/// The one process holding the client end. Two processes holding it (a
/// descriptor shared across fork) are ambiguous and fail closed.
#[cfg(any(target_os = "macos", test))]
fn lsof_owner(output: &str, client: SocketAddr, server: SocketAddr) -> Option<LsofOwner> {
    let endpoint = format!("{client}->{server}");
    let mut pid = None;
    let mut uid = None;
    let mut owner = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix('p') {
            pid = Some(value.parse::<u32>().ok()?);
            uid = None;
        } else if let Some(value) = line.strip_prefix('u') {
            uid = Some(value.parse::<u32>().ok()?);
        } else if line.strip_prefix('n') == Some(endpoint.as_str()) {
            let found = LsofOwner {
                uid: uid?,
                pid: pid?,
            };
            if owner.is_some_and(|owner| owner != found) {
                return None;
            }
            owner = Some(found);
        }
    }
    owner
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn local_listener_coexists_with_ipv4_and_has_one_owner() -> io::Result<()> {
        let host = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        let port = host.local_addr()?.port();
        let local = bind(Ipv6Addr::LOCALHOST, port)?;
        assert!(bind(Ipv6Addr::LOCALHOST, port).is_err());
        let client = TcpStream::connect(local.local_addr()?).await?;
        let (server, peer) = local.accept().await?;
        assert_eq!(peer, client.local_addr()?);
        assert_eq!(server.local_addr()?, local.local_addr()?);
        Ok(())
    }

    /// A TCP client to `address` owned by a separate `nc` process, the way a
    /// real self-SSH client is. `None` (and the test skips) without `nc`.
    #[cfg(target_os = "linux")]
    pub(in crate::ssh) fn nc_client(address: SocketAddr) -> Option<tokio::process::Child> {
        tokio::process::Command::new("nc")
            .arg(address.ip().to_string())
            .arg(address.port().to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| eprintln!("skipped: cannot run nc: {e}"))
            .ok()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refuses_a_client_socket_the_daemon_itself_holds() -> io::Result<()> {
        // The daemon dials TCP as root for `ssh -L` and `-J`. A connection it
        // makes to its own self-SSH port must not log in as root because the
        // client socket is root's.
        let listener = bind(Ipv6Addr::LOCALHOST, 0)?;
        let _client = TcpStream::connect(listener.local_addr()?).await?;
        let (server, peer) = listener.accept().await?;
        assert_eq!(uid(peer, server.local_addr()?).await, None);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn looks_up_the_live_client_socket() -> io::Result<()> {
        let listener = bind(Ipv6Addr::LOCALHOST, 0)?;
        let Some(_client) = nc_client(listener.local_addr()?) else {
            return Ok(());
        };
        let (server, peer) = listener.accept().await?;
        assert_eq!(
            uid(peer, server.local_addr()?).await,
            Some(unsafe { libc::getuid() })
        );
        assert_eq!(
            uid(SocketAddr::new(peer.ip(), 0), server.local_addr()?).await,
            None
        );
        Ok(())
    }

    #[test]
    fn proc_lookup_requires_a_live_exact_tuple() {
        let client = "[::1]:40000".parse().expect("client address");
        let server = "[::1]:2222".parse().expect("server address");
        let row = "0: 00000000000000000000000001000000:9C40 00000000000000000000000001000000:08AE 01 0:0 0:0 0 1000 0 123";
        let table = format!("header\n{row}\n");
        let owner = proc_owner(&table, client, server).expect("the live row");
        assert_eq!((owner.uid, owner.inode), (1000, 123));
        assert!(proc_owner(&table, server, client).is_none());
        assert!(proc_owner(&table.replace(" 01 ", " 06 "), client, server).is_none());
        assert!(proc_owner(&table.replace(" 123", " 0"), client, server).is_none());
        assert!(proc_owner(&format!("{table}{row}\n"), client, server).is_none());
    }

    #[test]
    fn lsof_lookup_matches_client_direction_and_rejects_ambiguous_owners() {
        let client = "[200::1]:40000".parse().expect("client address");
        let server = "[200::1]:2222".parse().expect("server address");
        let output = format!("p1\nu0\nn{server}->{client}\np2\nu1000\nn{client}->{server}\n");
        assert!(lsof_owner(&output, client, server) == Some(LsofOwner { uid: 1000, pid: 2 }));
        assert!(
            lsof_owner(
                &format!("{output}p3\nu0\nn{client}->{server}\n"),
                client,
                server
            )
            .is_none()
        );
        assert!(lsof_owner(&format!("p2\nn{client}->{server}\n"), client, server).is_none());
    }
}
