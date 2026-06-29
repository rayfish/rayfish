//! Mesh packet forwarding between TUN device and peer QUIC connections.
//!
//! Three concurrent tasks handle the data plane:
//! - [`run_mesh`]: reads outgoing packets from TUN, routes to correct peer via [`PeerTable`]
//! - [`spawn_peer_reader`]: one per peer, reads incoming datagrams and forwards to TUN writer
//! - [`spawn_tun_writer`]: single task, writes incoming packets to the TUN device

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use iroh::EndpointId;
use iroh::endpoint::{Connection, ConnectionError, VarInt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::firewall::{self, Direction, SharedFirewall};
use crate::peers::{DeviceUserMap, PeerTable};
use crate::stats::{DropReason, ForwardMetrics};
use crate::tun::{TunReader, TunWriter};

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

/// Decision returned by [`evaluate_inbound`] for a datagram received from a peer.
pub(crate) enum InboundDecision {
    /// Packet passed the firewall check and may be written to the TUN.
    Accept,
    /// Dropped by the local firewall. Carries the parsed packet so a fail-fast
    /// REJECT reply can be built without re-parsing.
    DropFirewall(firewall::PacketInfo),
    /// Dropped: too large or not a parseable IP packet.
    DropMalformed,
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
    network: &str,
) -> InboundDecision {
    if packet.len() > MAX_PEER_DATAGRAM {
        return InboundDecision::DropMalformed;
    }
    let Some(info) = firewall::parse_packet_info(packet) else {
        return InboundDecision::DropMalformed;
    };
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

/// Sent by [`spawn_peer_reader`] when a peer connection drops,
/// consumed by the reconnect loop (joiner) or cleanup task (coordinator).
pub struct DisconnectEvent {
    pub endpoint_id: EndpointId,
    pub ip: Ipv4Addr,
    pub ipv6: std::net::Ipv6Addr,
    /// The network whose connection dropped. A multi-homed peer keeps its routes
    /// in the other networks; only this network's connection is torn down.
    pub network: String,
    /// True when the peer closed gracefully with [`LEAVE_CODE`] (it ran
    /// `ray leave`), as opposed to a timeout/reset.
    pub intentional: bool,
}

/// Shared data-plane handles threaded into every per-peer reader. All fields are
/// cheap `Clone` (channels and Arc-backed handles), so a reader is spawned with a
/// single bundle instead of six separate arguments. Built per spawn from the
/// daemon's `MeshCtx` via `MeshCtx::forward_ctx`.
pub struct ForwardCtx {
    pub firewall: SharedFirewall,
    pub tun_tx: mpsc::Sender<Bytes>,
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
pub async fn run_mesh(
    mut tun: TunReader,
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
    peer_ipv6: std::net::Ipv6Addr,
    network: String,
    ctx: ForwardCtx,
) -> tokio::task::JoinHandle<()> {
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
                        );
                        tracing::warn!(peer = %peer_id.fmt_short(), ip = %peer_ip, error = %e, intentional, "peer connection lost");
                        let _ = disconnect_tx
                            .send(DisconnectEvent {
                                endpoint_id: peer_id,
                                ip: peer_ip,
                                ipv6: peer_ipv6,
                                network: network.clone(),
                                intentional,
                            })
                            .await;
                        return;
                    }
                },
            };

            let peer_user = device_user_map.resolve(&peer_id);
            match evaluate_inbound(&datagram, &firewall, &peer_user, &network) {
                InboundDecision::Accept => {
                    stats.record_rx(datagram.len());
                    if tun_tx.send(datagram).await.is_err() {
                        return;
                    }
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
pub fn spawn_tun_writer(
    mut tun: TunWriter,
    mut tun_rx: mpsc::Receiver<Bytes>,
    active: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
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

    fn make_tcp_packet(dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45; // IPv4, IHL=5
        p[9] = 6; // TCP
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
            rules,
        })
    }

    #[test]
    fn inbound_oversized_datagram_dropped_as_malformed() {
        let fw = SharedFirewall::new(firewall::FirewallConfig::default());
        let peer = iroh::SecretKey::generate().public();
        let huge = vec![0u8; MAX_PEER_DATAGRAM + 1];
        assert!(matches!(
            evaluate_inbound(&huge, &fw, &peer, "test-net"),
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
            evaluate_inbound(&pkt, &fw, &peer, "test-net"),
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
            evaluate_inbound(&blocked, &fw, &peer, "test-net"),
            InboundDecision::DropFirewall(_)
        ));
        assert!(matches!(
            evaluate_inbound(&allowed, &fw, &peer, "test-net"),
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
            evaluate_inbound(&pkt, &fw, &peer, "test-net"),
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
        pkt[16..20].copy_from_slice(&[100, 64, 0, 3]); // dst ip
        assert!(matches!(
            evaluate_inbound(&pkt, &fw, &peer, "test-net"),
            InboundDecision::Accept
        ));
    }

    #[test]
    fn magic_dns_predicate_matches_only_magic_ip_port_53() {
        let mk = |ip: std::net::IpAddr, port: u16| firewall::PacketInfo {
            src_ip: "100.64.0.5".parse().unwrap(),
            dst_ip: ip,
            protocol: 17,
            src_port: 50000,
            dst_port: port,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        assert!(is_magic_dns(&mk(
            std::net::IpAddr::V4(crate::dns::MAGIC_DNS_V4),
            53
        )));
        assert!(!is_magic_dns(&mk(
            std::net::IpAddr::V4(crate::dns::MAGIC_DNS_V4),
            80
        )));
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
            evaluate_inbound(&make_tcp_packet(8080), &fw, &peer, "test-net"),
            InboundDecision::Accept
        ));
        // A different port stays denied.
        assert!(matches!(
            evaluate_inbound(&make_tcp_packet(9090), &fw, &peer, "test-net"),
            InboundDecision::DropFirewall(_)
        ));
    }
}
