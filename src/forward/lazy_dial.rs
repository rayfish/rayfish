//! Bounded packet retention while an on-demand peer connection is opening.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use iroh::EndpointId;

pub(super) const MAX_PACKETS_PER_PEER: usize = 64;
pub(super) const MAX_BYTES_PER_PEER: usize = 128 * 1024;
pub(super) const MAX_PACKETS_TOTAL: usize = 512;
pub(super) const MAX_BYTES_TOTAL: usize = 1024 * 1024;
pub(super) const MAX_IN_FLIGHT: usize = 16;

/// Packets retained while one peer's connection establishment is in flight.
/// The forwarding loop owns this state, so it needs no locks or atomics.
#[derive(Default)]
pub(super) struct LazyDialBuffers {
    pub(super) by_peer: HashMap<EndpointId, LazyDialQueue>,
    pub(super) packets: usize,
    pub(super) bytes: usize,
}

#[derive(Default)]
pub(super) struct LazyDialQueue {
    packets: VecDeque<Bytes>,
    bytes: usize,
}

impl LazyDialBuffers {
    /// Retain the oldest packets within both the per-peer and process budgets.
    pub(super) fn push(&mut self, peer: EndpointId, packet: Bytes) -> bool {
        let bytes = packet.len();
        if self.packets >= MAX_PACKETS_TOTAL || self.bytes.saturating_add(bytes) > MAX_BYTES_TOTAL {
            return false;
        }

        let queue = self.by_peer.entry(peer).or_default();
        if queue.packets.len() >= MAX_PACKETS_PER_PEER
            || queue.bytes.saturating_add(bytes) > MAX_BYTES_PER_PEER
        {
            return false;
        }

        queue.bytes += bytes;
        queue.packets.push_back(packet);
        self.packets += 1;
        self.bytes += bytes;
        true
    }

    /// Return one peer's packets in arrival order and release their budget.
    pub(super) fn take(&mut self, peer: &EndpointId) -> VecDeque<Bytes> {
        let Some(queue) = self.by_peer.remove(peer) else {
            return VecDeque::new();
        };
        self.packets -= queue.packets.len();
        self.bytes -= queue.bytes;
        queue.packets
    }
}
