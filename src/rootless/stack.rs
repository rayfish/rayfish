//! Bounded IPv6 TCP stack. Its packet queues implement the existing TUN contract.
//! One task owns every smoltcp socket; local streams supply ordinary async I/O.
//! Validated path MTU errors lower the shared TCP segmentation limit until restart.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use futures::task::AtomicWaker;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket, SocketBuffer, State};
use smoltcp::time::Instant as StackInstant;
use smoltcp::wire::{
    HardwareAddress, Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr, IpEndpoint, IpProtocol,
    Ipv6Packet, TcpPacket,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, Sleep, sleep};
use tokio_util::sync::CancellationToken;

use crate::tun::{TUN_MTU, TunRead, TunWrite};

const PACKETS: usize = 256;
const MAX_FLOWS: usize = 128;
const BUFFER: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct Stack {
    commands: mpsc::Sender<Open>,
}

struct Open {
    remote: SocketAddrV6,
    reply: oneshot::Sender<io::Result<DuplexStream>>,
}

impl Stack {
    pub(crate) async fn connect(&self, remote: SocketAddrV6) -> Result<DuplexStream> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Open { remote, reply })
            .await
            .context("userspace stack stopped")?;
        Ok(tokio::time::timeout(CONNECT_TIMEOUT, result)
            .await
            .context("mesh TCP connection timed out")???)
    }
}

pub(crate) struct PacketReader {
    packets: mpsc::Receiver<Bytes>,
    wake: Arc<AtomicWaker>,
    active: Arc<AtomicBool>,
}

impl TunRead for PacketReader {
    async fn read_packet(&mut self) -> Result<Bytes> {
        loop {
            let packet = self
                .packets
                .recv()
                .await
                .context("userspace stack stopped")?;
            self.wake.wake();
            if self.active.load(Ordering::SeqCst) {
                return Ok(packet);
            }
        }
    }
}

pub(crate) struct PacketWriter(mpsc::Sender<Bytes>);

impl TunWrite for PacketWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.0
            .send(Bytes::copy_from_slice(packet))
            .await
            .context("userspace stack stopped")
    }
}

struct PacketDevice {
    incoming: VecDeque<Bytes>,
    outgoing: mpsc::Sender<Bytes>,
    mtu: usize,
}

struct ReceiveToken(Bytes);
impl RxToken for ReceiveToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TransmitToken<'a>(mpsc::Permit<'a, Bytes>);
impl TxToken for TransmitToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.send(Bytes::from(packet));
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = ReceiveToken;
    type TxToken<'a> = TransmitToken<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(ReceiveToken, TransmitToken<'_>)> {
        if self.incoming.is_empty() {
            return None;
        }
        let permit = self.outgoing.try_reserve().ok()?;
        Some((
            ReceiveToken(self.incoming.pop_front()?),
            TransmitToken(permit),
        ))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<TransmitToken<'_>> {
        self.outgoing.try_reserve().ok().map(TransmitToken)
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

enum Completion {
    Outgoing(oneshot::Sender<io::Result<DuplexStream>>),
    Incoming(mpsc::Sender<DuplexStream>),
}

impl Completion {
    fn is_closed(&self) -> bool {
        match self {
            Self::Outgoing(reply) => reply.is_closed(),
            Self::Incoming(accepted) => accepted.is_closed(),
        }
    }
    fn send(self, result: io::Result<DuplexStream>) -> bool {
        match self {
            Self::Outgoing(reply) => reply.send(result).is_ok(),
            Self::Incoming(accepted) => {
                result.is_ok_and(|stream| accepted.try_send(stream).is_ok())
            }
        }
    }
}

struct PendingConnect {
    reply: Completion,
    stream: DuplexStream,
}

struct Flow {
    handle: SocketHandle,
    local: DuplexStream,
    pending: Option<PendingConnect>,
    read_closed: bool,
    write_closed: bool,
}

struct Listener {
    port: u16,
    handle: SocketHandle,
    accepted: mpsc::Sender<DuplexStream>,
}

pub(crate) struct BoundListener {
    pub port: u16,
    pub accepted: mpsc::Receiver<DuplexStream>,
}

pub(crate) struct Driver {
    interface: Interface,
    sockets: SocketSet<'static>,
    device: PacketDevice,
    input: mpsc::Receiver<Bytes>,
    commands: mpsc::Receiver<Open>,
    flows: Vec<Flow>,
    retired: Vec<SocketHandle>,
    listeners: Vec<Listener>,
    wake: Arc<AtomicWaker>,
    start: Instant,
    timer: Pin<Box<Sleep>>,
    next_port: u16,
    active: Arc<AtomicBool>,
}

pub(crate) struct NetworkStack {
    pub stack: Stack,
    pub reader: PacketReader,
    pub writer: PacketWriter,
    pub driver: Driver,
    pub listeners: Vec<BoundListener>,
}

fn socket() -> Socket<'static> {
    let mut socket = Socket::new(
        SocketBuffer::new(vec![0; BUFFER]),
        SocketBuffer::new(vec![0; BUFFER]),
    );
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
    socket
}

fn interface(ip: Ipv6Addr, device: &mut PacketDevice, now: StackInstant) -> Result<Interface> {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut interface = Interface::new(config, device, now);
    let mut address_set = false;
    interface.update_ip_addrs(|addrs| {
        address_set = addrs.push(IpCidr::new(IpAddress::Ipv6(ip), 7)).is_ok();
    });
    anyhow::ensure!(address_set, "userspace stack address table is full");
    Ok(interface)
}

pub(crate) fn new(ip: Ipv6Addr, ports: &[u16], active: Arc<AtomicBool>) -> Result<NetworkStack> {
    anyhow::ensure!(ports.len() <= 16, "at most 16 exposed ports are supported");
    let (outgoing, packets) = mpsc::channel(PACKETS);
    let (writer, input) = mpsc::channel(PACKETS);
    let (commands, requests) = mpsc::channel(64);
    let wake = Arc::new(AtomicWaker::new());
    let mut device = PacketDevice {
        incoming: VecDeque::new(),
        outgoing,
        mtu: usize::from(TUN_MTU),
    };
    let interface = interface(ip, &mut device, StackInstant::ZERO)?;
    let mut sockets = SocketSet::new(Vec::new());
    let mut listeners = Vec::new();
    let mut bound = Vec::new();
    for &port in ports {
        anyhow::ensure!(
            port != 0 && !listeners.iter().any(|l: &Listener| l.port == port),
            "duplicate or zero exposed port"
        );
        let mut socket = socket();
        socket
            .listen(port)
            .map_err(|e| anyhow::anyhow!("listen: {e}"))?;
        let handle = sockets.add(socket);
        let (accepted, receiver) = mpsc::channel(16);
        listeners.push(Listener {
            port,
            handle,
            accepted,
        });
        bound.push(BoundListener {
            port,
            accepted: receiver,
        });
    }
    Ok(NetworkStack {
        stack: Stack { commands },
        reader: PacketReader {
            packets,
            wake: Arc::clone(&wake),
            active: Arc::clone(&active),
        },
        writer: PacketWriter(writer),
        driver: Driver {
            interface,
            sockets,
            device,
            input,
            commands: requests,
            flows: Vec::new(),
            retired: Vec::new(),
            listeners,
            wake,
            start: Instant::now(),
            timer: Box::pin(sleep(Duration::ZERO)),
            next_port: 49152,
            active,
        },
        listeners: bound,
    })
}

impl Driver {
    pub(crate) async fn run(&mut self, cancel: CancellationToken) -> Result<()> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = poll_fn(|cx| self.poll(cx)) => result,
        }
    }

    fn open(&mut self, open: Open) {
        if !self.active.load(Ordering::SeqCst) {
            drop(
                open.reply
                    .send(Err(io::Error::other("rootless data plane is on standby"))),
            );
            return;
        }
        if self.flows.len() + self.retired.len() >= MAX_FLOWS {
            // A cancelled caller deliberately drops its error receiver.
            drop(
                open.reply
                    .send(Err(io::Error::other("userspace connection limit reached"))),
            );
            return;
        }
        let mut tcp = socket();
        let port = (0..16384).find_map(|_| {
            let port = self.next_port;
            self.next_port = self.next_port.checked_add(1).unwrap_or(49152);
            let busy = self.sockets.iter().any(|(_, s)| match s {
                smoltcp::socket::Socket::Tcp(tcp) => {
                    tcp.local_endpoint().is_some_and(|e| e.port == port)
                }
            });
            (!busy).then_some(port)
        });
        let result = port
            .ok_or_else(|| io::Error::other("no free userspace TCP ports"))
            .and_then(|port| {
                tcp.connect(
                    self.interface.context(),
                    (IpAddress::Ipv6(*open.remote.ip()), open.remote.port()),
                    port,
                )
                .map_err(|error| io::Error::other(error.to_string()))
            });
        if let Err(error) = result {
            drop(open.reply.send(Err(error)));
            return;
        }
        let handle = self.sockets.add(tcp);
        let (local, stream) = duplex(BUFFER);
        self.flows.push(Flow {
            handle,
            local,
            pending: Some(PendingConnect {
                reply: Completion::Outgoing(open.reply),
                stream,
            }),
            read_closed: false,
            write_closed: false,
        });
    }

    fn path_mtu(&self, packet: &[u8]) -> Option<usize> {
        let packet = Ipv6Packet::new_checked(packet).ok()?;
        if packet.next_header() != IpProtocol::Icmpv6
            || !self
                .interface
                .has_ip_addr(IpAddress::Ipv6(packet.dst_addr()))
        {
            return None;
        }
        let icmp = Icmpv6Packet::new_checked(packet.payload()).ok()?;
        let Icmpv6Repr::PktTooBig { mtu, header, data } = Icmpv6Repr::parse(
            &packet.src_addr(),
            &packet.dst_addr(),
            &icmp,
            &ChecksumCapabilities::default(),
        )
        .ok()?
        else {
            return None;
        };
        let mtu = usize::try_from(mtu).ok()?;
        // Leave room for IPv6 and the largest TCP header. This is a TCP
        // segmentation limit, not an OS link MTU; legacy QUIC paths can be smaller
        // than IPv6's minimum link MTU.
        if mtu <= 100
            || mtu >= self.device.mtu
            || mtu >= header.buffer_len() + header.payload_len
            || header.next_header != IpProtocol::Tcp
            || header.src_addr != packet.dst_addr()
            || header.dst_addr != packet.src_addr()
        {
            return None;
        }
        let quoted = TcpPacket::new_checked(data).ok()?;
        let local = IpEndpoint::new(IpAddress::Ipv6(header.src_addr), quoted.src_port());
        let remote = IpEndpoint::new(IpAddress::Ipv6(header.dst_addr), quoted.dst_port());
        self.sockets
            .iter()
            .any(|(_, socket)| {
                let smoltcp::socket::Socket::Tcp(tcp) = socket;
                tcp.local_endpoint() == Some(local) && tcp.remote_endpoint() == Some(remote)
            })
            .then_some(mtu)
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.wake.register(cx.waker());
        if self.device.outgoing.is_closed() {
            return Poll::Ready(Err(anyhow::anyhow!("packet reader stopped")));
        }
        let elapsed = self.start.elapsed().as_micros();
        let now = StackInstant::from_micros(i64::try_from(elapsed).unwrap_or(i64::MAX));
        while self.device.incoming.len() < PACKETS {
            match self.input.poll_recv(cx) {
                Poll::Ready(Some(packet)) => {
                    if let Some(mtu) = self.path_mtu(&packet) {
                        self.device.mtu = mtu;
                        let ip = self.interface.ip_addrs()[0].address();
                        let IpAddress::Ipv6(ip) = ip;
                        // smoltcp caches capabilities when constructing an interface.
                        // An IP-only interface has no neighbor or link state; retain
                        // the existing sockets and refresh only its segmentation cap.
                        self.interface = match interface(ip, &mut self.device, now) {
                            Ok(interface) => interface,
                            Err(error) => return Poll::Ready(Err(error)),
                        };
                    }
                    self.device.incoming.push_back(packet);
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow::anyhow!("packet writer stopped")));
                }
                Poll::Pending => break,
            }
        }
        for _ in 0..64 {
            match self.commands.poll_recv(cx) {
                Poll::Ready(Some(open)) => self.open(open),
                _ => break,
            }
        }
        let incoming_count = self.device.incoming.len();
        self.interface.poll_maintenance(now);
        self.interface
            .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        if self.device.incoming.len() < incoming_count {
            cx.waker().wake_by_ref();
        }
        for listener in &mut self.listeners {
            let tcp = self.sockets.get_mut::<Socket>(listener.handle);
            if matches!(
                tcp.state(),
                State::SynReceived | State::Established | State::CloseWait
            ) {
                if self.flows.len() + self.retired.len() >= MAX_FLOWS
                    || listener.accepted.is_closed()
                {
                    tcp.abort();
                    continue;
                }
                let handle = listener.handle;
                let mut replacement = socket();
                if let Err(error) = replacement.listen(listener.port) {
                    return Poll::Ready(Err(anyhow::anyhow!("userspace listen failed: {error}")));
                }
                listener.handle = self.sockets.add(replacement);
                let (local, stream) = duplex(BUFFER);
                self.flows.push(Flow {
                    handle,
                    local,
                    pending: Some(PendingConnect {
                        reply: Completion::Incoming(listener.accepted.clone()),
                        stream,
                    }),
                    read_closed: false,
                    write_closed: false,
                });
            } else if tcp.state() == State::Closed
                && tcp.local_endpoint().is_none()
                && let Err(error) = tcp.listen(listener.port)
            {
                return Poll::Ready(Err(anyhow::anyhow!("userspace listen failed: {error}")));
            }
        }
        self.flows.retain_mut(|flow| {
            let tcp = self.sockets.get_mut::<Socket>(flow.handle);
            if !self.active.load(Ordering::SeqCst) {
                tcp.abort();
            }
            if flow
                .pending
                .as_ref()
                .is_some_and(|pending| pending.reply.is_closed())
            {
                tcp.abort();
            }
            if matches!(tcp.state(), State::Established | State::CloseWait)
                && let Some(pending) = flow.pending.take()
                && !pending.reply.send(Ok(pending.stream))
            {
                tcp.abort();
            }
            let keep = if flow.pending.is_some() && tcp.state() != State::Closed {
                true
            } else {
                pump(flow, tcp, cx)
            };
            if !keep {
                if tcp.local_endpoint().is_some() {
                    // Keep aborted sockets until smoltcp emits their final RST.
                    self.retired.push(flow.handle);
                } else {
                    self.sockets.remove(flow.handle);
                }
            }
            keep
        });
        self.interface
            .poll_egress(now, &mut self.device, &mut self.sockets);
        self.retired.retain(|handle| {
            if self
                .sockets
                .get::<Socket>(*handle)
                .local_endpoint()
                .is_none()
            {
                self.sockets.remove(*handle);
                false
            } else {
                true
            }
        });
        let delay = self
            .interface
            .poll_delay(now, &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_secs(1))
            .clamp(Duration::from_millis(1), Duration::from_secs(1));
        let deadline = Instant::now() + delay;
        if self.timer.as_mut().poll(cx).is_ready() || self.timer.deadline() > deadline {
            self.timer.as_mut().reset(deadline);
            // Poll once to register the current task with the reset timer.
            let _ = self.timer.as_mut().poll(cx);
        }
        Poll::Pending
    }
}

fn pump(flow: &mut Flow, tcp: &mut Socket<'_>, cx: &mut Context<'_>) -> bool {
    if tcp.can_recv() {
        let result = tcp.recv(
            |bytes| match Pin::new(&mut flow.local).poll_write(cx, bytes) {
                Poll::Ready(Ok(n)) => {
                    if n > 0 {
                        cx.waker().wake_by_ref();
                    }
                    (n, n == 0)
                }
                Poll::Ready(Err(_)) => (0, true),
                Poll::Pending => (0, false),
            },
        );
        if result.is_ok_and(|failed| failed) {
            tcp.abort();
            return false;
        }
    }
    if !tcp.may_recv() && !tcp.can_recv() && !flow.write_closed {
        match Pin::new(&mut flow.local).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => flow.write_closed = true,
            Poll::Ready(Err(_)) => {
                tcp.abort();
                return false;
            }
            Poll::Pending => {}
        }
    }
    if tcp.can_send() && !flow.read_closed {
        let result = tcp.send(|bytes| {
            let mut buffer = ReadBuf::new(bytes);
            match Pin::new(&mut flow.local).poll_read(cx, &mut buffer) {
                Poll::Ready(Ok(())) => {
                    let n = buffer.filled().len();
                    cx.waker().wake_by_ref();
                    (n, Some(n == 0))
                }
                Poll::Ready(Err(_)) => (0, Some(true)),
                Poll::Pending => (0, None),
            }
        });
        if result.is_ok_and(|eof| eof == Some(true)) {
            flow.read_closed = true;
            tcp.close();
        }
    }
    if tcp.state() == State::Closed {
        if let Some(pending) = flow.pending.take() {
            // A disconnected caller no longer needs the connection error.
            pending.reply.send(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "mesh TCP connection refused",
            )));
        }
        return tcp.can_recv();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use smol_str::SmolStr;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinSet;

    use crate::dns;
    use crate::exit_node::ExitContext;
    use crate::firewall::{Action, FirewallConfig, SharedFirewall};
    use crate::forward::{ForwardCtx, MeshForwarder, spawn_peer_reader, spawn_tun_writer};
    use crate::membership::derive_ipv6;
    use crate::peers::{DeviceUserMap, PeerTable};
    use crate::stats::ForwardMetrics;

    fn active_stack(ip: Ipv6Addr, ports: &[u16]) -> NetworkStack {
        new(ip, ports, Arc::new(AtomicBool::new(true))).unwrap()
    }

    struct MeshNode {
        endpoint: Endpoint,
        network: NetworkStack,
    }

    async fn node(ports: &[u16]) -> MeshNode {
        let endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![crate::transport::mesh_alpn()])
            .bind()
            .await
            .unwrap();
        let network = active_stack(derive_ipv6(&endpoint.id()), ports);
        MeshNode { endpoint, network }
    }

    fn forward(
        node: MeshNode,
        connection: iroh::endpoint::Connection,
        remote: &Endpoint,
        cancel: &CancellationToken,
        tasks: &mut JoinSet<Result<()>>,
    ) -> Stack {
        let peers = PeerTable::new();
        let ip = derive_ipv6(&node.endpoint.id());
        peers.set_local_mtu(TUN_MTU);
        peers.add(
            derive_ipv6(&remote.id()),
            connection.clone(),
            remote.id(),
            "mesh",
        );
        peers.note_receive_mtu(&remote.id(), &connection, TUN_MTU);
        peers.add_inbound_handle_by_id(&remote.id(), &connection, 1, SmolStr::new("mesh"));
        let firewall = SharedFirewall::new(FirewallConfig {
            // The service accepts test connections; the client keeps inbound denial.
            default_inbound: if node.network.driver.listeners.is_empty() {
                Action::Deny
            } else {
                Action::Allow
            },
            ..Default::default()
        });
        let stats = Arc::new(ForwardMetrics::default());
        let (tun_tx, tun_rx) = mpsc::channel(256);
        let writer = spawn_tun_writer(
            node.network.writer,
            tun_rx,
            Arc::new(AtomicBool::new(true)),
            Arc::clone(&stats),
        );
        let reader = spawn_peer_reader(
            connection,
            remote.id(),
            peers.clone(),
            ForwardCtx {
                firewall: firewall.clone(),
                tun_tx: Arc::new(ArcSwap::from_pointee(tun_tx.clone())),
                token: cancel.clone(),
                stats: Arc::clone(&stats),
                device_user_map: DeviceUserMap::new(),
                exit: ExitContext {
                    my_v6: ip,
                    ..Default::default()
                },
            },
        );
        // Child handles are aborted and awaited when their owning test task stops.
        let child_cancel = cancel.clone();
        tasks.spawn(async move {
            child_cancel.cancelled().await;
            writer.abort();
            reader.abort();
            drop(writer.await);
            drop(reader.await);
            Ok(())
        });
        let forwarder = MeshForwarder {
            tun: node.network.reader,
            local_ipv6: ip,
            peers,
            firewall,
            token: cancel.clone(),
            stats,
            resolver: Arc::new(dns::resolver::Resolver::new(
                dns::new_hostname_table(),
                dns::new_reverse_table(),
            )),
            tun_tx,
            dialer: None,
        };
        let forward_cancel = cancel.clone();
        tasks.spawn(async move {
            tokio::select! { biased; _ = forward_cancel.cancelled() => Ok(()), result = forwarder.run() => result }
        });
        let mut driver = node.network.driver;
        let driver_cancel = cancel.clone();
        tasks.spawn(async move { driver.run(driver_cancel).await });
        node.network.stack
    }

    #[tokio::test]
    async fn tcp_over_real_mesh_supports_large_transfers_half_close_and_parallel_connections() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut server = node(&[8022]).await;
            let client = node(&[]).await;
            let server_endpoint = server.endpoint.clone();
            let client_endpoint = client.endpoint.clone();
            let alpn = crate::transport::mesh_alpn();
            let (outbound, inbound) = tokio::join!(
                client.endpoint.connect(server.endpoint.addr(), &alpn),
                async { server.endpoint.accept().await.unwrap().await.unwrap() }
            );
            let mut accepted = server.network.listeners.remove(0).accepted;
            let cancel = CancellationToken::new();
            let mut tasks = JoinSet::new();
            let _server = forward(server, inbound, &client_endpoint, &cancel, &mut tasks);
            let client = forward(
                client,
                outbound.unwrap(),
                &server_endpoint,
                &cancel,
                &mut tasks,
            );
            let remote = SocketAddrV6::new(derive_ipv6(&server_endpoint.id()), 8022, 0, 0);
            let service = tokio::spawn(async move {
                let mut sessions = JoinSet::new();
                for _ in 0..4 {
                    let mut stream = accepted.recv().await.unwrap();
                    sessions.spawn(async move {
                        let mut request = Vec::new();
                        stream.read_to_end(&mut request).await.unwrap();
                        stream.write_all(&request).await.unwrap();
                        stream.shutdown().await.unwrap();
                    });
                }
                while let Some(result) = sessions.join_next().await {
                    result.unwrap();
                }
            });
            let mut sessions = JoinSet::new();
            for index in 0..4 {
                let client = client.clone();
                sessions.spawn(async move {
                    let mut stream = client.connect(remote).await.unwrap();
                    let request = vec![index; 512 * 1024];
                    stream.write_all(&request).await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, request);
                });
            }
            while let Some(result) = sessions.join_next().await {
                result.unwrap();
            }
            service.await.unwrap();
            assert!(
                client
                    .connect(SocketAddrV6::new(*remote.ip(), 8023, 0, 0))
                    .await
                    .is_err()
            );
            cancel.cancel();
            while let Some(result) = tasks.join_next().await {
                result.unwrap().unwrap();
            }
            server_endpoint.close().await;
            client_endpoint.close().await;
        })
        .await
        .expect("TCP sessions must complete without a kernel TUN");
    }

    #[tokio::test]
    async fn cancelling_a_dial_releases_its_slot() {
        let mut network = active_stack("200::1".parse().unwrap(), &[]);
        let (reply, result) = oneshot::channel();
        drop(result);
        network.driver.open(Open {
            remote: "[200::2]:22".parse().unwrap(),
            reply,
        });
        assert_eq!(network.driver.flows.len(), 1);
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(network.driver.poll(&mut context).is_pending());
        assert!(network.driver.flows.is_empty());
        let reset = network
            .reader
            .packets
            .try_recv()
            .expect("cancelled dial sends a TCP reset before freeing its socket");
        let tcp = TcpPacket::new_checked(&reset[40..]).unwrap();
        assert!(tcp.rst());
        assert!(network.driver.retired.is_empty());
    }
    #[tokio::test]
    async fn tcp_reduces_packet_sizes_after_path_mtu_errors() {
        for mtu in [1280, 1160] {
            let mut client = active_stack("200::1".parse().unwrap(), &[]);
            let mut server = active_stack("200::2".parse().unwrap(), &[80]);
            let (reply, mut connected) = oneshot::channel();
            client.driver.open(Open {
                remote: "[200::2]:80".parse().unwrap(),
                reply,
            });
            let waker = futures::task::noop_waker();
            let mut context = Context::from_waker(&waker);
            let request = vec![42; 4096];
            let mut remote = None;
            let mut service = None;
            let mut received = Vec::new();
            let mut injected = 0;
            for tick in 0..500 {
                for network in [&mut client, &mut server] {
                    // Advance the stack's clock deterministically, including retransmissions.
                    network.driver.start = Instant::now() - Duration::from_millis(tick * 10);
                    assert!(network.driver.poll(&mut context).is_pending());
                }
                if let Ok(Ok(mut stream)) = connected.try_recv() {
                    stream.write_all(&request).await.unwrap();
                    // Keep the sending half alive until every byte is acknowledged.
                    remote = Some(stream);
                }
                while let Ok(packet) = client.reader.packets.try_recv() {
                    client.reader.wake.wake();
                    if packet.len() > mtu {
                        let info = crate::firewall::parse_packet_info(&packet).unwrap();
                        let reply = crate::reject::build_packet_too_big(
                            &packet,
                            &info,
                            u16::try_from(mtu).unwrap(),
                        )
                        .unwrap();
                        client.writer.0.try_send(reply).unwrap();
                        injected += 1;
                    } else {
                        server.writer.0.try_send(packet).unwrap();
                    }
                }
                while let Ok(packet) = server.reader.packets.try_recv() {
                    server.reader.wake.wake();
                    client.writer.0.try_send(packet).unwrap();
                }
                if let Ok(stream) = server.listeners[0].accepted.try_recv() {
                    service = Some(stream);
                }
                if let Some(stream) = service.as_mut() {
                    let mut data = [0; 4096];
                    let mut buffer = ReadBuf::new(&mut data);
                    if let Poll::Ready(Ok(())) =
                        Pin::new(stream).poll_read(&mut context, &mut buffer)
                    {
                        received.extend_from_slice(buffer.filled());
                    }
                }
                if received.len() == request.len() {
                    break;
                }
            }
            assert!(
                injected > 0,
                "the transfer must encounter the smaller path MTU"
            );
            assert_eq!(
                received, request,
                "TCP must recover after a path MTU error ({mtu})"
            );
            drop(remote);
        }
    }

    #[tokio::test]
    async fn path_mtu_errors_require_a_valid_checksum_and_live_outgoing_tuple() {
        let mut network = active_stack("200::1".parse().unwrap(), &[]);
        let (reply, _connected) = oneshot::channel();
        network.driver.open(Open {
            remote: "[200::2]:80".parse().unwrap(),
            reply,
        });
        let waker = futures::task::noop_waker();
        assert!(
            network
                .driver
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let mut quoted = network.reader.packets.try_recv().unwrap().to_vec();
        quoted.resize(1500, 0);
        quoted[4..6].copy_from_slice(&1460u16.to_be_bytes());
        let info = crate::firewall::parse_packet_info(&quoted).unwrap();
        let reply = crate::reject::build_packet_too_big(&quoted, &info, 1280).unwrap();
        assert_eq!(network.driver.path_mtu(&reply), Some(1280));

        let mut invalid = reply.to_vec();
        invalid[42] ^= 1;
        assert_eq!(network.driver.path_mtu(&invalid), None);
        for mtu in [0, 100, TUN_MTU] {
            let reply = crate::reject::build_packet_too_big(&quoted, &info, mtu).unwrap();
            assert_eq!(network.driver.path_mtu(&reply), None);
        }
        quoted[40..42].copy_from_slice(&1u16.to_be_bytes());
        let info = crate::firewall::parse_packet_info(&quoted).unwrap();
        let reply = crate::reject::build_packet_too_big(&quoted, &info, 1280).unwrap();
        assert_eq!(network.driver.path_mtu(&reply), None);
    }
}
