//! Mesh packet forwarding between TUN device and peer QUIC connections.
//!
//! Three concurrent tasks handle the data plane:
//! - [`run_mesh`]: reads outgoing packets from TUN, routes to correct peer via [`PeerTable`]
//! - [`spawn_peer_reader`]: one per peer, reads incoming datagrams and forwards to TUN writer
//! - [`spawn_tun_writer`]: single task, writes incoming packets to the TUN device

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use iroh::EndpointId;
use iroh::endpoint::{Connection, ConnectionError, VarInt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::firewall::{self, Direction, SharedFirewall};
use crate::peers::{DeviceUserMap, PeerTable};
use crate::stats::{DropReason, ForwardMetrics};

/// Maximum datagram size accepted from a peer. Anything larger is dropped before
/// being parsed or written to the TUN device, bounding memory use under a flood
/// of oversized datagrams from a malicious or buggy peer.
const MAX_PEER_DATAGRAM: usize = 1500;

/// Size of the TUN read pool. One allocation is amortized across the ~50
/// datagrams that fit in a chunk: each packet is sliced off with a zero-copy
/// `split_to(n).freeze()`, and a fresh chunk is only allocated once the current
/// one is exhausted (the old chunk stays alive via the `Bytes` already handed to
/// quinn and is freed as those datagrams are sent).
const TX_POOL_CHUNK: usize = 64 * 1024;

/// The port a stock `ssh` client targets (`ssh user@host.ray`). Defined here in
/// the always-compiled forward core because the userspace SSH NAT below rewrites
/// it on every platform, including Android, where the desktop-only `crate::ssh`
/// module (which re-exports this) is gated out.
pub(crate) const SSH_PORT: u16 = 22;

/// Internal port the embedded SSH server binds. Mesh `:22` is translated
/// to/from this port by the userspace NAT below. Chosen below the ephemeral
/// source-port ranges so the outbound NAT (which matches `src_port == this`)
/// can't collide with a kernel-assigned ephemeral port. See `crate::ssh`.
pub(crate) const SSH_LISTEN_PORT: u16 = 30022;

/// Userspace NAT that maps this node's mesh `:22` to/from the embedded SSH
/// server's internal listen port ([`SSH_LISTEN_PORT`]). The kernel
/// won't let us bind `<mesh-ip>:22` alongside a host sshd on `0.0.0.0:22`, so
/// instead of an OS-firewall redirect (which would be Linux-only) we translate
/// the port inside our own forwarding path — portable across every platform the
/// TUN runs on. Inbound (peer -> us) rewrites dest `22 -> listen`; outbound
/// (us -> peer) rewrites source `listen -> 22`. Active only while `ray firewall
/// ssh` is on.
struct SshNat {
    active: AtomicBool,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    listen_port: u16,
}

static SSH_NAT: OnceLock<SshNat> = OnceLock::new();

/// Register this node's mesh addresses + SSH listen port. Called once at daemon
/// start; the NAT stays inactive until [`set_ssh_nat_active`].
pub fn init_ssh_nat(v4: Ipv4Addr, v6: Ipv6Addr, listen_port: u16) {
    let _ = SSH_NAT.set(SshNat {
        active: AtomicBool::new(false),
        v4,
        v6,
        listen_port,
    });
}

/// Toggle the SSH port NAT (on when the mesh SSH server is running).
pub fn set_ssh_nat_active(on: bool) {
    if let Some(nat) = SSH_NAT.get() {
        nat.active.store(on, Ordering::Relaxed);
    }
}

/// The NAT config, or `None` when unset or inactive.
fn ssh_nat() -> Option<&'static SshNat> {
    SSH_NAT.get().filter(|n| n.active.load(Ordering::Relaxed))
}

impl SshNat {
    fn is_ours(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v) => v == self.v4,
            IpAddr::V6(v) => v == self.v6,
        }
    }
}

/// RFC 1624 incremental checksum update for a single changed 16-bit word:
/// `HC' = ~(~HC + ~m + m')`. Used so a port rewrite doesn't require recomputing
/// the whole TCP checksum.
fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    let mut sum = (!check as u32) + (!old as u32 & 0xffff) + new as u32;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Rewrite a TCP port in place for the SSH NAT, fixing the TCP checksum. When
/// `inbound`, maps dest `22 -> listen_port` (packet addressed to our mesh `:22`);
/// otherwise maps source `listen_port -> 22` (our SSH server's reply). Returns
/// `true` if it rewrote. `info` is the already-parsed header, so the common case
/// (no match) costs nothing.
fn rewrite_ssh_port(pkt: &mut [u8], info: &firewall::PacketInfo, inbound: bool) -> bool {
    let Some(nat) = ssh_nat() else { return false };
    if info.protocol != 6 {
        return false; // TCP only
    }
    let ihl = match pkt.first().map(|b| b >> 4) {
        Some(4) => ((pkt[0] & 0x0f) as usize) * 4,
        Some(6) => 40, // rayfish packets carry no IPv6 extension headers
        _ => return false,
    };
    if pkt.len() < ihl + 18 {
        return false;
    }
    let (port_off, old, new) = if inbound {
        if !nat.is_ours(info.dst_ip) || info.dst_port != SSH_PORT {
            return false;
        }
        (ihl + 2, SSH_PORT, nat.listen_port)
    } else {
        if !nat.is_ours(info.src_ip) || info.src_port != nat.listen_port {
            return false;
        }
        (ihl, nat.listen_port, SSH_PORT)
    };
    pkt[port_off..port_off + 2].copy_from_slice(&new.to_be_bytes());
    let ck_off = ihl + 16;
    let old_ck = u16::from_be_bytes([pkt[ck_off], pkt[ck_off + 1]]);
    let new_ck = csum_replace2(old_ck, old, new);
    pkt[ck_off..ck_off + 2].copy_from_slice(&new_ck.to_be_bytes());
    true
}

/// Decision returned by [`evaluate_inbound`] for a datagram received from a peer.
pub(crate) enum InboundDecision {
    /// Packet passed the firewall check and may be written to the TUN.
    Accept,
    /// Dropped by the local firewall. Carries the parsed packet so a fail-fast
    /// REJECT reply can be built without re-parsing.
    DropFirewall(firewall::PacketInfo),
    /// Dropped: too large or not a parseable IP packet.
    DropMalformed,
    /// Dropped: the packet's source IP is not the sending peer's assigned mesh
    /// address. A peer may only source packets from its own mesh IP, so this
    /// blocks one peer from impersonating another's IP (ingress anti-spoofing).
    DropSpoof,
}

/// Pure evaluation of an inbound peer datagram against the firewall and basic
/// packet validity. Extracted from [`spawn_peer_reader`] so it can be unit-tested.
///
/// Non-IP / truncated / oversized packets are rejected (`DropMalformed`) rather
/// than passed through — previously such packets bypassed the firewall entirely.
pub(crate) fn evaluate_inbound(
    packet: &[u8],
    firewall: &SharedFirewall,
    peer_id: &EndpointId,
    peer_ip: Ipv4Addr,
    peer_ipv6: Ipv6Addr,
    network: &str,
) -> InboundDecision {
    if packet.len() > MAX_PEER_DATAGRAM {
        return InboundDecision::DropMalformed;
    }
    let Some(info) = firewall::parse_packet_info(packet) else {
        return InboundDecision::DropMalformed;
    };
    // Ingress anti-spoofing: a peer may only inject packets sourced from its own
    // assigned mesh address. Anything else (e.g. one peer forging another's mesh
    // IP) is dropped before the firewall or any in-daemon listener sees it, so
    // identity-from-source-IP (used by mesh SSH) stays trustworthy.
    let src_ok = match info.src_ip {
        IpAddr::V4(v4) => v4 == peer_ip,
        IpAddr::V6(v6) => v6 == peer_ipv6,
    };
    if !src_ok {
        return InboundDecision::DropSpoof;
    }
    if firewall
        .evaluate_packet(Direction::In, &info, peer_id, Some(network))
        .is_deny()
    {
        return InboundDecision::DropFirewall(info);
    }
    InboundDecision::Accept
}

/// Application close code a peer sends when it deliberately leaves a network
/// (`ray leave`). Distinguishes an intentional departure from a transient drop
/// (timeout/reset), so only deliberate leaves prune the canonical member list.
pub const LEAVE_CODE: u32 = 0x1ea5e;

/// Application close code used to drop a peer that floods the control plane with
/// messages (see [`crate::ratelimit::ControlGate`]). Distinct from
/// [`LEAVE_CODE`]: a flooded-out peer did not depart the network, so it is
/// treated as a non-intentional disconnect (the peer may reconnect; no quarantine).
pub const ABUSE_CODE: u32 = 0xab05e;

/// Application close code a coordinator (or any member pruning a stale roster
/// entry) sends when it removes a peer from the network (`ray kick`). On the
/// receiving (kicked) side it is treated like [`LEAVE_CODE`] — an intentional
/// disconnect — so the kicked node stops reconnecting instead of churning back
/// into the coordinator's pending queue. The pruning side does not observe its
/// own close code (that read is a local close), so it relies on the shared
/// `pruned_peers` set to suppress its reconnect loop.
pub const KICK_CODE: u32 = 0x14ced;

/// Sent by [`spawn_peer_reader`] when a peer connection drops,
/// consumed by the reconnect loop (joiner) or cleanup task (coordinator).
pub struct DisconnectEvent {
    pub endpoint_id: EndpointId,
    pub ip: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    /// The network whose connection dropped. A multi-homed peer keeps its routes
    /// in the other networks; only this network's connection is torn down.
    pub network: String,
    /// True when the peer closed gracefully with [`LEAVE_CODE`] (it ran
    /// `ray leave`), as opposed to a timeout/reset.
    pub intentional: bool,
    /// [`Connection::stable_id`] of the connection that dropped, so a consumer
    /// can tell whether the connection currently stored for this peer is still
    /// the one that died. `None` for a synthetic kick that is not tied to a live
    /// connection (the cold-restore reconnect seed), which always proceeds.
    ///
    /// Guards an ABA race: when a peer's process is killed and it re-dials with
    /// the same identity, the coordinator registers the fresh connection before
    /// the old one's idle timeout fires. Without this id, the stale connection's
    /// delayed disconnect would evict the fresh connection and drop the peer.
    pub conn_stable_id: Option<usize>,
}

/// Shared data-plane handles threaded into every per-peer reader. All fields are
/// cheap `Clone` (channels and Arc-backed handles), so a reader is spawned with a
/// single bundle instead of six separate arguments. Built per spawn from the
/// daemon's `MeshCtx` via `MeshCtx::forward_ctx`.
pub struct ForwardCtx {
    pub firewall: SharedFirewall,
    /// Swappable sender cell for the TUN writer. Peer readers outlive TUN
    /// attach/detach cycles (the control plane stays up across a VPN toggle), so
    /// they resolve the current writer per packet via `tun_tx.load_full()` rather
    /// than capturing one sender. After a detach + re-attach the cell points at
    /// the new writer, so a reader spawned during the first `up()` keeps
    /// forwarding after the next one. See [`DaemonState::attach_tun`].
    pub tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
    pub disconnect_tx: mpsc::Sender<DisconnectEvent>,
    pub token: CancellationToken,
    pub stats: Arc<ForwardMetrics>,
    pub device_user_map: DeviceUserMap,
}

/// True when a parsed packet is a DNS query addressed to the magic resolver IP.
pub(crate) fn is_magic_dns(info: &firewall::PacketInfo) -> bool {
    info.dst_port == 53 && info.dst_ip == IpAddr::V4(crate::dns::MAGIC_DNS_V4)
}

/// Main TUN read loop. Reads packets from the TUN device, extracts the destination IP,
/// looks up the peer in [`PeerTable`], and sends the packet as a QUIC datagram.
/// Packets with no matching peer are silently dropped.
#[allow(clippy::too_many_arguments)]
pub async fn run_mesh<R: crate::tun::TunRead>(
    mut tun: R,
    peers: PeerTable,
    firewall: SharedFirewall,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
    resolver: Arc<crate::dns_resolver::Resolver>,
    tun_tx: mpsc::Sender<Bytes>,
) -> Result<()> {
    let mut pool = BytesMut::with_capacity(TX_POOL_CHUNK);
    loop {
        // Ensure a full MTU of contiguous spare capacity before reading (a short
        // buffer would truncate the packet). `reserve` reuses the current chunk
        // until it's exhausted, then allocates a fresh one — so allocation is
        // amortized across many packets instead of paid per packet.
        if pool.capacity() < MAX_PEER_DATAGRAM {
            pool.reserve(TX_POOL_CHUNK);
        }
        // Race the read against cancellation, but return only the byte count so
        // no borrow of `pool` escapes the `select!` (it's reused right below).
        let n = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = tun.read_into(&mut pool) => result?,
        };
        if n == 0 {
            continue;
        }
        // Zero-copy hand-off: slice the packet out of the pool as an owned
        // `Bytes` sharing the chunk's allocation — no copy, no per-packet malloc.
        let pkt = pool.split_to(n).freeze();
        tracing::debug!(len = n, first_byte = pkt[0], "TUN read");
        let Some(info) = firewall::parse_packet_info(&pkt) else {
            tracing::debug!(len = n, "not IP, dropping");
            continue;
        };
        if is_magic_dns(&info) {
            let resolver = resolver.clone();
            let tun_tx = tun_tx.clone();
            let pkt = pkt.clone();
            tokio::spawn(async move {
                resolver.handle_tun_query(&pkt, &info, &tun_tx).await;
            });
            continue; // do not fall through to peer routing
        }
        let lookup = match info.dst_ip {
            IpAddr::V4(v4) => peers.lookup_v4(&v4),
            IpAddr::V6(v6) => peers.lookup_v6(&v6),
        };
        let Some(route) = lookup else {
            tracing::debug!(dst = %info.dst_ip, "no peer for dst");
            stats.record_drop(DropReason::NoPeer);
            continue;
        };
        // Reachability is "we share a network" — enforced by connection
        // existence. The per-host firewall is the fine-grained gate.
        if firewall
            .evaluate_packet(
                Direction::Out,
                &info,
                &route.endpoint_id,
                Some(&route.network),
            )
            .is_deny()
        {
            tracing::debug!(dst = %info.dst_ip, port = info.dst_port, "firewall denied outbound");
            stats.record_drop(DropReason::Firewall);
            // Fail fast (opt-in): inject a RST / ICMP-unreachable back into our own
            // TUN so the local app's socket fails immediately instead of hanging.
            if firewall.reject_enabled()
                && let Some(reply) = crate::reject::build_reject(&pkt, &info)
            {
                stats.record_reject();
                let _ = tun_tx.send(reply).await;
            }
            continue;
        }
        tracing::debug!(dst = %info.dst_ip, "routing to peer");
        // Drop-newest at the application boundary: if the peer's QUIC datagram send
        // buffer is too full to accept this packet without evicting an already-queued
        // (older) one, drop the *new* packet here instead of calling `send_datagram`,
        // which would drop the *oldest* queued packet (see N6 in the datagram audit).
        // This keeps the send path non-blocking (no cross-peer head-of-line blocking
        // in this single TUN read loop) while preferring drop-newest over drop-oldest.
        // Full per-peer backpressure (`send_datagram_wait` in a per-peer writer task)
        // is the sized follow-up that needs the e2e harness to land safely.
        if route.conn.datagram_send_buffer_space() < n {
            tracing::trace!(
                dst = %info.dst_ip,
                space = route.conn.datagram_send_buffer_space(),
                len = n,
                "datagram send buffer full; dropping newest",
            );
            stats.record_drop(DropReason::Backpressure);
            continue;
        }
        // SSH NAT: rewrite our reply's source port (listen -> 22) so the peer
        // sees it as coming from `:22`. The cheap pre-check (TCP + source port ==
        // listen port) gates the copy; `rewrite_ssh_port` still confirms the
        // source IP is ours and no-ops otherwise, so ordinary traffic is untouched.
        let pkt = if ssh_nat().is_some_and(|n| info.protocol == 6 && info.src_port == n.listen_port)
        {
            let mut v = pkt.to_vec();
            rewrite_ssh_port(&mut v, &info, false);
            Bytes::from(v)
        } else {
            pkt
        };
        match route.conn.send_datagram(pkt) {
            Ok(()) => stats.record_tx(n),
            Err(e) => {
                tracing::debug!(dst = %info.dst_ip, error = %e, "datagram send failed");
                stats.record_drop(DropReason::SendFailure);
            }
        }
    }
}

/// Spawns a task that reads QUIC datagrams from a single peer connection and
/// forwards them to the TUN writer via `tun_tx`. On connection loss, sends a
/// [`DisconnectEvent`] and exits.
pub fn spawn_peer_reader(
    conn: Connection,
    peer_id: EndpointId,
    peer_ip: Ipv4Addr,
    peer_ipv6: Ipv6Addr,
    network: String,
    ctx: ForwardCtx,
) -> JoinHandle<()> {
    let ForwardCtx {
        firewall,
        tun_tx,
        disconnect_tx,
        token,
        stats,
        device_user_map,
    } = ctx;
    use tracing::Instrument as _;
    // Tag every event from this reader (drops, connection-lost) with the peer
    // and network so the report bundle's logs are correlatable per peer.
    let span = tracing::info_span!("peer", peer = %peer_id.fmt_short(), net = %network);
    let reader = async move {
        loop {
            // Wait for the next datagram, exiting on cancellation or connection
            // loss. Keeping the `select!` to "yield a datagram or return" leaves
            // the actual forwarding below at loop-body depth.
            let datagram = tokio::select! {
                _ = token.cancelled() => return,
                result = conn.read_datagram() => match result {
                    Ok(d) => d,
                    Err(e) => {
                        let intentional = matches!(
                            &e,
                            ConnectionError::ApplicationClosed(ac)
                                if ac.error_code == VarInt::from_u32(LEAVE_CODE)
                                    || ac.error_code == VarInt::from_u32(KICK_CODE)
                        );
                        tracing::warn!(peer = %peer_id.fmt_short(), ip = %peer_ip, error = %e, intentional, "peer connection lost");
                        let _ = disconnect_tx
                            .send(DisconnectEvent {
                                endpoint_id: peer_id,
                                ip: peer_ip,
                                ipv6: peer_ipv6,
                                network: network.clone(),
                                intentional,
                                conn_stable_id: Some(conn.stable_id()),
                            })
                            .await;
                        return;
                    }
                },
            };

            let peer_user = device_user_map.resolve(&peer_id);
            match evaluate_inbound(
                &datagram, &firewall, &peer_user, peer_ip, peer_ipv6, &network,
            ) {
                InboundDecision::Accept => {
                    stats.record_rx(datagram.len());
                    // SSH NAT: a packet to our mesh `:22` is rewritten to the
                    // SSH server's internal listen port before injection. The
                    // anti-spoof + firewall checks above already ran on the
                    // original `:22` packet. Cheap pre-check avoids a copy on
                    // ordinary traffic.
                    let datagram = match ssh_nat() {
                        Some(_) => match firewall::parse_packet_info(&datagram) {
                            Some(info) if info.protocol == 6 && info.dst_port == SSH_PORT => {
                                let mut v = datagram.to_vec();
                                rewrite_ssh_port(&mut v, &info, true);
                                Bytes::from(v)
                            }
                            _ => datagram,
                        },
                        None => datagram,
                    };
                    // Resolve the live writer for each packet: the sender is
                    // swapped on every TUN re-attach (VPN toggle). A send error
                    // means the writer is currently down (standby between a
                    // detach and the next attach); drop the packet and keep the
                    // reader alive so it forwards again once a new TUN attaches.
                    let _ = tun_tx.load_full().send(datagram).await;
                }
                InboundDecision::DropFirewall(info) => {
                    stats.record_drop(DropReason::Firewall);
                    // Fail fast (opt-in): send a RST / ICMP-unreachable back over
                    // this connection so the initiator on the other host fails
                    // immediately. Its conntrack admits the reply (a RST matches
                    // its outbound flow; the seeded `allow in icmp` rule admits an
                    // ICMP error), so the initiator's app sees "connection refused".
                    if firewall.reject_enabled()
                        && let Some(reply) = crate::reject::build_reject(&datagram, &info)
                    {
                        stats.record_reject();
                        let _ = conn.send_datagram(reply);
                    }
                }
                InboundDecision::DropMalformed => stats.record_drop(DropReason::Malformed),
                InboundDecision::DropSpoof => {
                    stats.record_drop(DropReason::Spoof);
                    tracing::debug!(
                        peer = %peer_id.fmt_short(),
                        "dropped inbound packet with spoofed source IP"
                    );
                }
            }
        }
    };
    tokio::spawn(reader.instrument(span))
}

/// Spawns a task that consumes packets from `tun_rx` and writes them to the TUN
/// device. Single instance per session, serializes writes without a Mutex.
/// `active` is the data-plane gate: while it is false (standby, after `ray
/// down`) inbound datagrams are dropped instead of written, so a node that
/// stays connected to peers still carries no traffic.
pub fn spawn_tun_writer<W: crate::tun::TunWrite>(
    mut tun: W,
    mut tun_rx: mpsc::Receiver<Bytes>,
    active: Arc<AtomicBool>,
) -> JoinHandle<()> {
    use std::sync::atomic::Ordering;
    tokio::spawn(async move {
        while let Some(packet) = tun_rx.recv().await {
            if !active.load(Ordering::Relaxed) {
                // Data plane is down (standby). Drain and drop so the channel
                // never backs up while we keep the control plane connected.
                continue;
            }
            if let Err(e) = tun.write_packet(&packet).await {
                tracing::warn!(error = %e, "TUN write failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::Action;

    #[derive(Default)]
    struct FakeTunWriter {
        written: std::sync::Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl crate::tun::TunWrite for FakeTunWriter {
        async fn write_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
            self.written.lock().await.push(packet.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn tun_writer_writes_when_active() {
        use std::sync::atomic::AtomicBool;
        let writer = FakeTunWriter::default();
        let sink = writer.written.clone();
        let (tx, rx) = mpsc::channel::<Bytes>(8);
        let active = std::sync::Arc::new(AtomicBool::new(true));
        let handle = spawn_tun_writer(writer, rx, active);
        tx.send(Bytes::from_static(b"kept")).await.unwrap();
        drop(tx); // close channel so the writer task exits
        handle.await.unwrap();
        let got = sink.lock().await;
        assert_eq!(got.as_slice(), &[b"kept".to_vec()]);
    }

    #[tokio::test]
    async fn tun_writer_drops_when_inactive() {
        use std::sync::atomic::AtomicBool;
        let writer = FakeTunWriter::default();
        let sink = writer.written.clone();
        let (tx, rx) = mpsc::channel::<Bytes>(8);
        let active = std::sync::Arc::new(AtomicBool::new(false));
        let handle = spawn_tun_writer(writer, rx, active);
        tx.send(Bytes::from_static(b"dropped")).await.unwrap();
        drop(tx);
        handle.await.unwrap();
        assert!(sink.lock().await.is_empty());
    }

    #[test]
    fn test_parse_packet_valid_ipv4() {
        let mut packet = vec![0u8; 24];
        packet[0] = 0x45;
        packet[9] = 6; // TCP
        packet[16] = 100;
        packet[17] = 64;
        packet[18] = 0;
        packet[19] = 3;
        let info = firewall::parse_packet_info(&packet).unwrap();
        assert_eq!(info.dst_ip, Ipv4Addr::new(100, 64, 0, 3));
        assert_eq!(info.protocol, 6);
    }

    #[test]
    fn test_parse_packet_too_short() {
        assert!(firewall::parse_packet_info(&[0x45; 10]).is_none());
    }

    #[test]
    fn test_parse_packet_ipv6() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // IPv6
        packet[6] = 6; // TCP next header
        // dst at bytes 24-39
        packet[24] = 0x02;
        packet[25] = 0x01;
        let info = firewall::parse_packet_info(&packet).unwrap();
        assert!(info.dst_ip.is_ipv6());
    }

    /// Mesh address the test packets are sourced from; passed to
    /// `evaluate_inbound` as the sending peer's assigned IP so the ingress
    /// anti-spoof check passes.
    const TEST_V4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
    const TEST_V6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

    fn make_tcp_packet(dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45; // IPv4, IHL=5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&[100, 64, 0, 5]); // src ip (TEST_V4)
        p[16..20].copy_from_slice(&[100, 64, 0, 3]); // dst ip
        p[20] = 0;
        p[21] = 80; // src port 80
        p[22] = (dst_port >> 8) as u8;
        p[23] = dst_port as u8;
        p
    }

    fn inbound_fw(default: Action, rules: Vec<firewall::FirewallRule>) -> SharedFirewall {
        SharedFirewall::new(firewall::FirewallConfig {
            default_inbound: default,
            default_outbound: Action::Allow,
            reject: false,
            disabled: false,
            rules,
        })
    }

    #[test]
    fn inbound_oversized_datagram_dropped_as_malformed() {
        let fw = SharedFirewall::new(firewall::FirewallConfig::default());
        let peer = iroh::SecretKey::generate().public();
        let huge = vec![0u8; MAX_PEER_DATAGRAM + 1];
        assert!(matches!(
            evaluate_inbound(&huge, &fw, &peer, TEST_V4, TEST_V6, "test-net"),
            InboundDecision::DropMalformed
        ));
    }

    #[test]
    fn inbound_ipv6_evaluated_by_firewall() {
        let fw = inbound_fw(Action::Deny, vec![]);
        let peer = iroh::SecretKey::generate().public();
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // IPv6
        pkt[6] = 6; // TCP
        assert!(matches!(
            evaluate_inbound(&pkt, &fw, &peer, TEST_V4, TEST_V6, "test-net"),
            InboundDecision::DropFirewall(_)
        ));
    }

    #[test]
    fn inbound_firewall_denied_port() {
        let peer = iroh::SecretKey::generate().public();
        let fw = inbound_fw(
            Action::Allow,
            vec![firewall::FirewallRule {
                direction: Direction::In,
                action: Action::Deny,
                protocol: firewall::Protocol::Tcp,
                port: Some(firewall::PortRange { start: 22, end: 22 }),
                peer: firewall::PeerFilter::Any,
                network: None,
                origin: firewall::RuleOrigin::Local,
            }],
        );
        let blocked = make_tcp_packet(22);
        let allowed = make_tcp_packet(80);
        assert!(matches!(
            evaluate_inbound(&blocked, &fw, &peer, TEST_V4, TEST_V6, "test-net"),
            InboundDecision::DropFirewall(_)
        ));
        assert!(matches!(
            evaluate_inbound(&allowed, &fw, &peer, TEST_V4, TEST_V6, "test-net"),
            InboundDecision::Accept
        ));
    }

    #[test]
    fn inbound_clean_tcp_denied_by_secure_default() {
        // The built-in default denies unsolicited inbound TCP (no service port is
        // exposed out of the box).
        let peer = iroh::SecretKey::generate().public();
        let fw = SharedFirewall::new(firewall::FirewallConfig::default());
        let pkt = make_tcp_packet(443);
        assert!(matches!(
            evaluate_inbound(&pkt, &fw, &peer, TEST_V4, TEST_V6, "test-net"),
            InboundDecision::DropFirewall(_)
        ));
    }

    #[test]
    fn inbound_icmp_accepted_by_default() {
        // Inbound ICMP is allowed-by-default so ping/reachability works out of the
        // box even under the deny-inbound default.
        let peer = iroh::SecretKey::generate().public();
        let fw = SharedFirewall::new(firewall::FirewallConfig::default());
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&[100, 64, 0, 5]); // src ip (TEST_V4)
        pkt[16..20].copy_from_slice(&[100, 64, 0, 3]); // dst ip
        assert!(matches!(
            evaluate_inbound(&pkt, &fw, &peer, TEST_V4, TEST_V6, "test-net"),
            InboundDecision::Accept
        ));
    }

    /// Compute the TCP checksum of a v4 packet (20-byte IP header) with the
    /// checksum field treated as zero — what a correct packet's field should hold.
    fn tcp_csum_v4(pkt: &[u8]) -> u16 {
        let tcp = &pkt[20..];
        let mut sum = 0u32;
        for off in [12, 14, 16, 18] {
            sum += u16::from_be_bytes([pkt[off], pkt[off + 1]]) as u32;
        }
        sum += 6; // protocol
        sum += tcp.len() as u32;
        let mut i = 0;
        while i + 1 < tcp.len() {
            if i != 16 {
                // skip the checksum field itself
                sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
            }
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn ssh_nat_rewrites_port_and_keeps_checksum_valid() {
        // `SSH_NAT` is a process-global `OnceLock`, so another test in this binary
        // (e.g. the headless daemon build) may seed it first, making our
        // `init_ssh_nat` a no-op. Read the addresses the NAT actually holds and
        // build the packet from those, so the test is independent of run order.
        init_ssh_nat(Ipv4Addr::new(100, 88, 0, 1), Ipv6Addr::LOCALHOST, 41384);
        set_ssh_nat_active(true);
        let (our_v4, listen_port) = {
            let nat = ssh_nat().expect("nat active");
            (nat.v4, nat.listen_port)
        };

        // v4 TCP packet from a peer to our mesh :22, with a correct checksum.
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[100, 88, 0, 9]); // src (peer)
        pkt[16..20].copy_from_slice(&our_v4.octets()); // dst (us)
        pkt[20..22].copy_from_slice(&5000u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&22u16.to_be_bytes()); // dst port 22
        pkt[32] = 0x50; // data offset = 5 (20-byte TCP header)
        let ck = tcp_csum_v4(&pkt);
        pkt[36..38].copy_from_slice(&ck.to_be_bytes());

        let info = firewall::parse_packet_info(&pkt).unwrap();
        assert!(rewrite_ssh_port(&mut pkt, &info, true));
        let info2 = firewall::parse_packet_info(&pkt).unwrap();
        assert_eq!(
            info2.dst_port, listen_port,
            "dest port rewritten 22 -> listen"
        );
        // The incrementally-updated checksum must equal a freshly computed one.
        let field = u16::from_be_bytes([pkt[36], pkt[37]]);
        assert_eq!(
            field,
            tcp_csum_v4(&pkt),
            "checksum stays valid after rewrite"
        );

        // Inactive -> no rewrite.
        set_ssh_nat_active(false);
        let mut pkt2 = pkt.clone();
        let info3 = firewall::parse_packet_info(&pkt2).unwrap();
        assert!(!rewrite_ssh_port(&mut pkt2, &info3, true));
    }

    #[test]
    fn csum_replace2_round_trips() {
        // Swapping a field value and swapping it back restores the checksum.
        let c = 0x1234u16;
        assert_eq!(csum_replace2(csum_replace2(c, 22, 41384), 41384, 22), c);
    }

    #[test]
    fn inbound_spoofed_source_ip_dropped() {
        // A packet whose source IP isn't the sending peer's assigned mesh IP is
        // dropped as spoofed, before the firewall or any in-daemon listener sees
        // it — even when the firewall would otherwise allow it.
        let peer = iroh::SecretKey::generate().public();
        let fw = inbound_fw(Action::Allow, vec![]);
        let pkt = make_tcp_packet(80); // sourced from TEST_V4 (100.64.0.5)
        // Same packet, but the peer is supposedly assigned a different IP.
        assert!(matches!(
            evaluate_inbound(
                &pkt,
                &fw,
                &peer,
                Ipv4Addr::new(100, 64, 0, 9),
                TEST_V6,
                "test-net"
            ),
            InboundDecision::DropSpoof
        ));
        // With the matching peer IP it passes.
        assert!(matches!(
            evaluate_inbound(&pkt, &fw, &peer, TEST_V4, TEST_V6, "test-net"),
            InboundDecision::Accept
        ));
    }

    #[test]
    fn magic_dns_predicate_matches_only_magic_ip_port_53() {
        let mk = |ip: IpAddr, port: u16| firewall::PacketInfo {
            src_ip: "100.64.0.5".parse().unwrap(),
            dst_ip: ip,
            protocol: 17,
            src_port: 50000,
            dst_port: port,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        assert!(is_magic_dns(&mk(IpAddr::V4(crate::dns::MAGIC_DNS_V4), 53)));
        assert!(!is_magic_dns(&mk(IpAddr::V4(crate::dns::MAGIC_DNS_V4), 80)));
        assert!(!is_magic_dns(&mk("100.64.0.9".parse().unwrap(), 53)));
    }

    #[test]
    fn inbound_tcp_accepted_when_port_explicitly_opened() {
        // An explicit allow rule opens a port under the deny-inbound default.
        let peer = iroh::SecretKey::generate().public();
        let fw = inbound_fw(
            Action::Deny,
            vec![firewall::FirewallRule {
                direction: Direction::In,
                action: Action::Allow,
                protocol: firewall::Protocol::Tcp,
                port: Some(firewall::PortRange {
                    start: 8080,
                    end: 8080,
                }),
                peer: firewall::PeerFilter::Any,
                network: None,
                origin: firewall::RuleOrigin::Local,
            }],
        );
        assert!(matches!(
            evaluate_inbound(
                &make_tcp_packet(8080),
                &fw,
                &peer,
                TEST_V4,
                TEST_V6,
                "test-net"
            ),
            InboundDecision::Accept
        ));
        // A different port stays denied.
        assert!(matches!(
            evaluate_inbound(
                &make_tcp_packet(9090),
                &fw,
                &peer,
                TEST_V4,
                TEST_V6,
                "test-net"
            ),
            InboundDecision::DropFirewall(_)
        ));
    }
}
