//! Mesh packet forwarding between TUN device and peer QUIC connections.
//!
//! Three concurrent tasks handle the data plane:
//! - [`run_mesh`]: reads outgoing packets from TUN, routes to correct peer via [`PeerTable`]
//! - [`spawn_peer_reader`]: one per peer, reads incoming datagrams and forwards to TUN writer
//! - [`spawn_tun_writer`]: single task, writes incoming packets to the TUN device

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::acl::AclData;
use crate::peers::PeerTable;
use crate::stats::Stats;
use crate::tun::{TunReader, TunWriter};

/// Per-network ACL state shared across all forwarding tasks.
///
/// Uses `std::sync::RwLock` (not tokio) because reads happen on every packet
/// and writes are rare. The inner map is keyed by network name.
#[derive(Clone)]
pub struct SharedAcl {
    inner: Arc<std::sync::RwLock<HashMap<String, AclData>>>,
}

impl SharedAcl {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    pub fn set(&self, network: &str, acl: AclData) {
        self.inner.write().unwrap().insert(network.to_string(), acl);
    }

    pub fn remove(&self, network: &str) {
        self.inner.write().unwrap().remove(network);
    }

    pub fn get(&self, network: &str) -> AclData {
        self.inner
            .read()
            .unwrap()
            .get(network)
            .cloned()
            .unwrap_or_else(AclData::empty)
    }
}

/// Sent by [`spawn_peer_reader`] when a peer connection drops,
/// consumed by the reconnect loop (joiner) or cleanup task (coordinator).
pub struct DisconnectEvent {
    pub endpoint_id: EndpointId,
    pub ip: Ipv4Addr,
}

/// Extracts the destination IPv4 address from bytes 16–19 of an IPv4 packet header.
fn dest_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// Main TUN read loop. Reads packets from the TUN device, extracts the destination IP,
/// looks up the peer in [`PeerTable`], and sends the packet as a QUIC datagram.
/// Packets with no matching peer are silently dropped.
pub async fn run_mesh(
    mut tun: TunReader,
    peers: PeerTable,
    local_id: EndpointId,
    shared_acl: SharedAcl,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = tun.read_packet(&mut buf) => {
                let n = result?;
                if n > 0 {
                    tracing::debug!(len = n, first_byte = buf[0], "TUN read");
                    if let Some(dst) = dest_ip(&buf[..n]) {
                        if let Some((conn, peer_endpoint_id, network)) = peers.lookup_full(&dst) {
                            let acl = shared_acl.get(&network);
                            if !acl.is_allowed(&local_id, &peer_endpoint_id) {
                                tracing::debug!(%dst, "ACL denied outbound");
                                stats.record_drop();
                                continue;
                            }
                            tracing::debug!(%dst, "routing to peer");
                            match conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                                Ok(()) => stats.record_tx(n),
                                Err(e) => {
                                    tracing::debug!(%dst, error = %e, "datagram send failed");
                                    stats.record_drop();
                                }
                            }
                        } else {
                            tracing::debug!(%dst, "no peer for dst");
                            stats.record_drop();
                        }
                    } else {
                        tracing::debug!(len = n, "not IPv4, dropping");
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
    local_id: EndpointId,
    network: String,
    shared_acl: SharedAcl,
    tun_tx: mpsc::Sender<Vec<u8>>,
    disconnect_tx: mpsc::Sender<DisconnectEvent>,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                result = conn.read_datagram() => {
                    match result {
                        Ok(datagram) => {
                            if !shared_acl.get(&network).is_allowed(&peer_id, &local_id) {
                                stats.record_drop();
                                continue;
                            }
                            stats.record_rx(datagram.len());
                            if tun_tx.send(datagram.to_vec()).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(peer = %peer_id.fmt_short(), ip = %peer_ip, error = %e, "peer connection lost");
                            let _ = disconnect_tx.send(DisconnectEvent { endpoint_id: peer_id, ip: peer_ip }).await;
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

    #[test]
    fn test_dest_ip_valid_ipv4() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[16] = 100;
        packet[17] = 64;
        packet[18] = 0;
        packet[19] = 3;
        assert_eq!(dest_ip(&packet), Some(Ipv4Addr::new(100, 64, 0, 3)));
    }

    #[test]
    fn test_dest_ip_too_short() {
        assert_eq!(dest_ip(&[0x45; 10]), None);
    }

    #[test]
    fn test_dest_ip_not_ipv4() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x60;
        assert_eq!(dest_ip(&packet), None);
    }
}
