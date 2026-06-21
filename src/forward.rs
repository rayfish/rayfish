//! Mesh packet forwarding between TUN device and peer QUIC connections.
//!
//! Three concurrent tasks handle the data plane:
//! - [`run_mesh`]: reads outgoing packets from TUN, routes to correct peer via [`PeerTable`]
//! - [`spawn_peer_reader`]: one per peer, reads incoming datagrams and forwards to TUN writer
//! - [`spawn_tun_writer`]: single task, writes incoming packets to the TUN device

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::acl::AclData;
use crate::firewall::{self, Action, Direction, SharedFirewall};
use crate::peers::PeerTable;
use crate::stats::{DropReason, ForwardMetrics};
use crate::tun::{TunReader, TunWriter};

/// Maximum datagram size accepted from a peer. Anything larger is dropped before
/// being parsed or written to the TUN device, bounding memory use under a flood
/// of oversized datagrams from a malicious or buggy peer.
const MAX_PEER_DATAGRAM: usize = 1500;

/// Decision returned by [`evaluate_inbound`] for a datagram received from a peer.
pub(crate) enum InboundDecision {
    /// Packet passed ACL + firewall checks and may be written to the TUN.
    Accept,
    /// Dropped by the network ACL.
    DropAcl,
    /// Dropped by the local firewall.
    DropFirewall,
    /// Dropped: too large or not a parseable IP packet.
    DropMalformed,
}

/// Pure evaluation of an inbound peer datagram against ACL, firewall, and basic
/// packet validity. Extracted from [`spawn_peer_reader`] so it can be unit-tested.
///
/// Non-IP / truncated / oversized packets are rejected (`DropMalformed`) rather
/// than passed through — previously such packets bypassed the firewall entirely.
pub(crate) fn evaluate_inbound(
    packet: &[u8],
    acl: &AclData,
    firewall: &SharedFirewall,
    peer_id: &EndpointId,
    local_id: &EndpointId,
) -> InboundDecision {
    if packet.len() > MAX_PEER_DATAGRAM {
        return InboundDecision::DropMalformed;
    }
    if !acl.is_allowed(peer_id, local_id) {
        return InboundDecision::DropAcl;
    }
    let Some(info) = firewall::parse_packet_info(packet) else {
        return InboundDecision::DropMalformed;
    };
    if firewall.evaluate_packet(Direction::In, &info, peer_id) == Action::Deny {
        return InboundDecision::DropFirewall;
    }
    InboundDecision::Accept
}

#[derive(Clone)]
pub struct SharedAcl {
    inner: Arc<DashMap<String, AclData>>,
}

impl SharedAcl {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn set(&self, network: &str, acl: AclData) {
        self.inner.insert(network.to_string(), acl);
    }

    pub fn remove(&self, network: &str) {
        self.inner.remove(network);
    }

    pub fn get(&self, network: &str) -> AclData {
        self.inner
            .get(network)
            .map(|e| e.value().clone())
            .unwrap_or_else(AclData::empty)
    }
}

/// Sent by [`spawn_peer_reader`] when a peer connection drops,
/// consumed by the reconnect loop (joiner) or cleanup task (coordinator).
pub struct DisconnectEvent {
    pub endpoint_id: EndpointId,
    pub ip: Ipv4Addr,
    pub ipv6: std::net::Ipv6Addr,
}

/// Main TUN read loop. Reads packets from the TUN device, extracts the destination IP,
/// looks up the peer in [`PeerTable`], and sends the packet as a QUIC datagram.
/// Packets with no matching peer are silently dropped.
pub async fn run_mesh(
    mut tun: TunReader,
    peers: PeerTable,
    local_id: EndpointId,
    shared_acl: SharedAcl,
    firewall: SharedFirewall,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
) -> Result<()> {
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = tun.read_packet(&mut buf) => {
                let n = result?;
                if n > 0 {
                    tracing::debug!(len = n, first_byte = buf[0], "TUN read");
                    let pkt = &buf[..n];
                    if let Some(info) = firewall::parse_packet_info(pkt) {
                        let lookup = match info.dst_ip {
                            IpAddr::V4(v4) => peers.lookup_v4(&v4),
                            IpAddr::V6(v6) => peers.lookup_v6(&v6),
                        };
                        if let Some((conn, peer_endpoint_id, network)) = lookup {
                            let acl = shared_acl.get(&network);
                            if !acl.is_allowed(&local_id, &peer_endpoint_id) {
                                tracing::debug!(dst = %info.dst_ip, "ACL denied outbound");
                                stats.record_drop(DropReason::Acl);
                                continue;
                            }
                            if firewall.evaluate_packet(Direction::Out, &info, &peer_endpoint_id) == Action::Deny {
                                tracing::debug!(dst = %info.dst_ip, port = info.dst_port, "firewall denied outbound");
                                stats.record_drop(DropReason::Firewall);
                                continue;
                            }
                            tracing::debug!(dst = %info.dst_ip, "routing to peer");
                            match conn.send_datagram(Bytes::copy_from_slice(pkt)) {
                                Ok(()) => stats.record_tx(n),
                                Err(e) => {
                                    tracing::debug!(dst = %info.dst_ip, error = %e, "datagram send failed");
                                    stats.record_drop(DropReason::SendFailure);
                                }
                            }
                        } else {
                            tracing::debug!(dst = %info.dst_ip, "no peer for dst");
                            stats.record_drop(DropReason::NoPeer);
                        }
                    } else {
                        tracing::debug!(len = n, "not IP, dropping");
                    }
                }
            }
        }
    }
}

/// Spawns a task that reads QUIC datagrams from a single peer connection and
/// forwards them to the TUN writer via `tun_tx`. On connection loss, sends a
/// [`DisconnectEvent`] and exits.
#[allow(clippy::too_many_arguments)]
pub fn spawn_peer_reader(
    conn: Connection,
    peer_id: EndpointId,
    peer_ip: Ipv4Addr,
    peer_ipv6: std::net::Ipv6Addr,
    local_id: EndpointId,
    network: String,
    shared_acl: SharedAcl,
    firewall: SharedFirewall,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<ForwardMetrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                result = conn.read_datagram() => {
                    match result {
                        Ok(datagram) => {
                            let acl = shared_acl.get(&network);
                            match evaluate_inbound(&datagram, &acl, &firewall, &peer_id, &local_id) {
                                InboundDecision::Accept => {
                                    stats.record_rx(datagram.len());
                                    if tun_tx.send(datagram.to_vec()).await.is_err() {
                                        return;
                                    }
                                }
                                InboundDecision::DropAcl => stats.record_drop(DropReason::Acl),
                                InboundDecision::DropFirewall => stats.record_drop(DropReason::Firewall),
                                InboundDecision::DropMalformed => stats.record_drop(DropReason::Malformed),
                            }
                        }
                        Err(e) => {
                            tracing::warn!(peer = %peer_id.fmt_short(), ip = %peer_ip, error = %e, "peer connection lost");
                            let _ = disconnect_tx.send(DisconnectEvent { endpoint_id: peer_id, ip: peer_ip, ipv6: peer_ipv6 }).await;
                            return;
                        }
                    }
                }
            }
        }
    })
}

/// Spawns a task that consumes packets from `tun_rx` and writes them to the TUN device.
/// Single instance per session — serializes writes without a Mutex.
pub fn spawn_tun_writer(
    mut tun: TunWriter,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(packet) = tun_rx.recv().await {
            if let Err(e) = tun.write_packet(&packet).await {
                tracing::warn!(error = %e, "TUN write failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl;

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
        p[20] = 0; p[21] = 80; // src port 80
        p[22] = (dst_port >> 8) as u8;
        p[23] = dst_port as u8;
        p
    }

    fn inbound_fw(default: Action, rules: Vec<firewall::FirewallRule>) -> SharedFirewall {
        SharedFirewall::new(firewall::FirewallConfig { default_action: default, rules })
    }

    #[test]
    fn inbound_oversized_datagram_dropped_as_malformed() {
        let acl = AclData::empty();
        let fw = SharedFirewall::new(firewall::FirewallConfig::default());
        let peer = iroh::SecretKey::generate().public();
        let me = iroh::SecretKey::generate().public();
        let huge = vec![0u8; MAX_PEER_DATAGRAM + 1];
        assert!(matches!(
            evaluate_inbound(&huge, &acl, &fw, &peer, &me),
            InboundDecision::DropMalformed
        ));
    }

    #[test]
    fn inbound_ipv6_evaluated_by_firewall() {
        let acl = AclData::empty();
        let fw = inbound_fw(Action::Deny, vec![]);
        let peer = iroh::SecretKey::generate().public();
        let me = iroh::SecretKey::generate().public();
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // IPv6
        pkt[6] = 6; // TCP
        assert!(matches!(
            evaluate_inbound(&pkt, &acl, &fw, &peer, &me),
            InboundDecision::DropFirewall
        ));
    }

    #[test]
    fn inbound_acl_denied_before_firewall() {
        let peer = iroh::SecretKey::generate().public();
        let me = iroh::SecretKey::generate().public();
        let acl = AclData {
            tags: vec![],
            rules: vec![acl::AclRule { src: acl::Target::Identity(peer), dst: acl::Target::Identity(me) }],
        };
        // Rule allows peer->me, so a different src should be denied. Use a third id.
        let other = iroh::SecretKey::generate().public();
        let fw = SharedFirewall::new(firewall::FirewallConfig::default());
        let pkt = make_tcp_packet(443);
        assert!(matches!(
            evaluate_inbound(&pkt, &acl, &fw, &other, &me),
            InboundDecision::DropAcl
        ));
    }

    #[test]
    fn inbound_firewall_denied_port() {
        let peer = iroh::SecretKey::generate().public();
        let me = iroh::SecretKey::generate().public();
        let acl = AclData::empty();
        let fw = inbound_fw(
            Action::Allow,
            vec![firewall::FirewallRule {
                direction: Direction::In,
                action: Action::Deny,
                protocol: firewall::Protocol::Tcp,
                port: Some(firewall::PortRange { start: 22, end: 22 }),
                peer: firewall::PeerFilter::Any,
            }],
        );
        let blocked = make_tcp_packet(22);
        let allowed = make_tcp_packet(80);
        assert!(matches!(
            evaluate_inbound(&blocked, &acl, &fw, &peer, &me),
            InboundDecision::DropFirewall
        ));
        assert!(matches!(
            evaluate_inbound(&allowed, &acl, &fw, &peer, &me),
            InboundDecision::Accept
        ));
    }

    #[test]
    fn inbound_clean_tcp_accepted() {
        let peer = iroh::SecretKey::generate().public();
        let me = iroh::SecretKey::generate().public();
        let acl = AclData::empty();
        let fw = SharedFirewall::new(firewall::FirewallConfig::default());
        let pkt = make_tcp_packet(443);
        assert!(matches!(
            evaluate_inbound(&pkt, &acl, &fw, &peer, &me),
            InboundDecision::Accept
        ));
    }
}
