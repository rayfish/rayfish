//! Keep macOS DNS firewall exceptions tied to the lifetime of their bound sockets.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, TokioRuntimeProvider};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

struct Permit {
    #[cfg(target_os = "macos")]
    socket: crate::exit_node::ControlDnsSocket,
}

impl Permit {
    fn new(local_port: u16, server: SocketAddr, tcp: bool) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let socket = crate::exit_node::ControlDnsSocket {
                local_port,
                server,
                tcp,
            };
            crate::exit_node::allow_control_dns(socket).map_err(io::Error::other)?;
            Ok(Self { socket })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (local_port, server, tcp);
            Ok(Self {})
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        crate::exit_node::remove_control_dns(&self.socket);
    }
}

pub(super) struct UnderlayUdp {
    _permit: Permit,
    socket: UdpSocket,
}

impl UnderlayUdp {
    pub(super) fn new(socket: UdpSocket, server: SocketAddr) -> io::Result<Self> {
        let permit = Permit::new(socket.local_addr()?.port(), server, false)?;
        Ok(Self {
            socket,
            _permit: permit,
        })
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
    _permit: Permit,
    socket: TcpStream,
}

impl UnderlayTcp {
    pub(super) async fn connect(socket: TcpSocket, server: SocketAddr) -> io::Result<Self> {
        let permit = Permit::new(socket.local_addr()?.port(), server, true)?;
        Ok(Self {
            socket: socket.connect(server).await?,
            _permit: permit,
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
