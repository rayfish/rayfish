//! Let the endpoint's own DNS sockets past the macOS exit filter.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, TokioRuntimeProvider};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Lets the endpoint's own DNS reach `server` past the macOS exit filter. The
/// first use of a server reloads pf, so it runs on the blocking pool.
async fn allow(server: SocketAddr, tcp: bool) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    tokio::task::spawn_blocking(move || {
        crate::exit_node::allow_control_dns(crate::exit_node::ControlDnsServer { server, tcp })
            .map_err(io::Error::other)
    })
    .await??;
    #[cfg(not(target_os = "macos"))]
    let _ = (server, tcp);
    Ok(())
}

pub(super) struct UnderlayUdp {
    socket: UdpSocket,
}

impl UnderlayUdp {
    pub(super) async fn new(socket: UdpSocket, server: SocketAddr) -> io::Result<Self> {
        allow(server, false).await?;
        Ok(Self { socket })
    }
}

#[async_trait]
impl DnsUdpSocket for UnderlayUdp {
    type Time = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut read = ReadBuf::new(buf);
        self.socket
            .poll_recv_from(cx, &mut read)
            .map_ok(|addr| (read.filled().len(), addr))
    }
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.socket.poll_send_to(cx, buf, target)
    }
}

pub(super) struct UnderlayTcp {
    socket: TcpStream,
}

impl UnderlayTcp {
    pub(super) async fn connect(socket: TcpSocket, server: SocketAddr) -> io::Result<Self> {
        allow(server, true).await?;
        Ok(Self {
            socket: socket.connect(server).await?,
        })
    }
}

impl AsyncRead for UnderlayTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
impl AsyncWrite for UnderlayTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
