//! Mesh v6 packet framing. Whole packets keep `[handle:u16][IP packet]`.
//! Fragments use `[handle:u16][0:u8][id:u64][total:u16][offset:u16][bytes]`,
//! with integers in network byte order. The zero marker cannot be an IP version.
//! Fragmentation is below IP: only complete packets reach policy or the TUN.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use super::{TAG_LEN, tag_datagram};
use crate::stats::DropReason;

pub(super) const MAX_PACKET: usize = 1500;
const HEADER: usize = TAG_LEN + 1 + 8 + 2 + 2;
const MAX_FRAGMENTS: usize = 16;
const MAX_PENDING: usize = 64;
pub(super) const TIMEOUT: Duration = Duration::from_secs(5);
// Includes the packet buffer, coverage bitmap and allowance for map metadata.
const ASSEMBLY_COST: usize = MAX_PACKET + 512;
const GLOBAL_BUDGET: usize = 8 * 1024 * 1024;
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

pub(super) enum Encoded {
    Whole(Bytes),
    Fragments(Vec<Bytes>),
}

impl Encoded {
    pub(super) fn datagrams(&self) -> &[Bytes] {
        match self {
            Self::Whole(packet) => std::slice::from_ref(packet),
            Self::Fragments(parts) => parts,
        }
    }
}

/// The entire packet's send-buffer cost, including every fragment header.
pub(super) fn wire_size(len: usize, max: usize) -> Option<usize> {
    if len == 0 || len > MAX_PACKET {
        return None;
    }
    if len + TAG_LEN <= max {
        return Some(len + TAG_LEN);
    }
    let chunk = max.checked_sub(HEADER).filter(|n| *n > 0)?;
    let count = len.div_ceil(chunk);
    (count <= MAX_FRAGMENTS).then_some(len + count * HEADER)
}

pub(super) fn encode(handle: u16, packet: &[u8], max: usize) -> Option<Encoded> {
    wire_size(packet.len(), max)?;
    if handle == 0 {
        return None;
    }
    if packet.len() + TAG_LEN <= max {
        return Some(Encoded::Whole(tag_datagram(handle, packet)));
    }
    let chunk = max - HEADER;
    // Unique across concurrent senders and networks; reassembly is also scoped
    // to a connection, so daemon restarts cannot mix IDs with old fragments.
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut parts = Vec::with_capacity(packet.len().div_ceil(chunk));
    for (index, payload) in packet.chunks(chunk).enumerate() {
        let mut part = BytesMut::with_capacity(HEADER + payload.len());
        part.extend_from_slice(&handle.to_be_bytes());
        part.extend_from_slice(&[0]);
        part.extend_from_slice(&id.to_be_bytes());
        part.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        part.extend_from_slice(&((index * chunk) as u16).to_be_bytes());
        part.extend_from_slice(payload);
        parts.push(part.freeze());
    }
    Some(Encoded::Fragments(parts))
}

struct Assembly {
    packet: Vec<u8>,
    covered: [u64; MAX_PACKET.div_ceil(64)],
    received: usize,
    deadline: Instant,
    _budget: OwnedSemaphorePermit,
}

/// One per authenticated QUIC connection. No allocation before the caller
/// validates the network handle. Both per-connection and process-wide limits
/// apply; dropping a reader releases all its reservations.
pub(super) struct Reassembler {
    pending: HashMap<(u16, u64), Assembly>,
    budget: Arc<Semaphore>,
}

impl Default for Reassembler {
    fn default() -> Self {
        static BUDGET: OnceLock<Arc<Semaphore>> = OnceLock::new();
        Self {
            pending: HashMap::new(),
            budget: BUDGET
                .get_or_init(|| Arc::new(Semaphore::new(GLOBAL_BUDGET)))
                .clone(),
        }
    }
}

impl Reassembler {
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.pending.values().map(|p| p.deadline).min()
    }

    pub(super) fn expire(&mut self, now: Instant) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, p| now < p.deadline);
        before - self.pending.len()
    }

    /// The datagram still includes its validated network handle. Whole packets
    /// are returned without copying. Reordered and identical duplicate fragments
    /// are accepted; conflicting overlaps or sizes discard the assembly.
    pub(super) fn accept(
        &mut self,
        datagram: Bytes,
        now: Instant,
    ) -> Result<Option<Bytes>, DropReason> {
        let malformed = DropReason::Malformed;
        if datagram.len() <= TAG_LEN || datagram.len() > MAX_PACKET + TAG_LEN {
            return Err(malformed);
        }
        let handle = u16::from_be_bytes([datagram[0], datagram[1]]);
        if handle == 0 {
            return Err(malformed);
        }
        if matches!(datagram[TAG_LEN] >> 4, 4 | 6) {
            return Ok(Some(datagram.slice(TAG_LEN..)));
        }
        if datagram[TAG_LEN] != 0 || datagram.len() <= HEADER {
            return Err(malformed);
        }
        let id = u64::from_be_bytes(datagram[3..11].try_into().unwrap());
        let total = u16::from_be_bytes([datagram[11], datagram[12]]) as usize;
        let offset = u16::from_be_bytes([datagram[13], datagram[14]]) as usize;
        let payload = &datagram[HEADER..];
        let key = (handle, id);
        if total == 0 || total > MAX_PACKET || offset + payload.len() > total {
            self.pending.remove(&key);
            return Err(malformed);
        }
        // The timer also expires quiet connections. Check this entry here so a
        // busy peer cannot extend its deadline by racing the cleanup tick.
        if self.pending.get(&key).is_some_and(|p| now >= p.deadline) {
            self.pending.remove(&key);
            return Err(DropReason::ReassemblyTimeout);
        }
        if !self.pending.contains_key(&key) {
            if self.pending.len() >= MAX_PENDING {
                return Err(DropReason::ReassemblyLimit);
            }
            let permit = self
                .budget
                .clone()
                .try_acquire_many_owned(ASSEMBLY_COST as u32)
                .map_err(|_| DropReason::ReassemblyLimit)?;
            self.pending.insert(
                key,
                Assembly {
                    packet: vec![0; total],
                    covered: [0; MAX_PACKET.div_ceil(64)],
                    received: 0,
                    deadline: now + TIMEOUT,
                    _budget: permit,
                },
            );
        }
        let part = self.pending.get_mut(&key).unwrap();
        if part.packet.len() != total {
            self.pending.remove(&key);
            return Err(malformed);
        }
        for (pos, byte) in (offset..).zip(payload) {
            let mask = 1u64 << (pos % 64);
            if part.covered[pos / 64] & mask != 0 {
                if part.packet[pos] != *byte {
                    self.pending.remove(&key);
                    return Err(malformed);
                }
            } else {
                part.covered[pos / 64] |= mask;
                part.packet[pos] = *byte;
                part.received += 1;
            }
        }
        if part.received == total {
            let part = self.pending.remove(&key).unwrap();
            return Ok(Some(Bytes::from(part.packet)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn receiver(slots: usize) -> Reassembler {
        Reassembler {
            pending: HashMap::new(),
            budget: Arc::new(Semaphore::new(slots * ASSEMBLY_COST)),
        }
    }

    fn packet(len: usize) -> Vec<u8> {
        let mut p: Vec<_> = (0..len).map(|n| n as u8).collect();
        p[0] = 0x60;
        p
    }

    #[test]
    fn ipv6_minimum_packet_survives_1160_byte_payload_limit() {
        let packet = packet(1280);
        let encoded = encode(7, &packet, 1162).unwrap();
        let parts = encoded.datagrams();
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|p| p.len() <= 1162));
        let mut receiver = receiver(2);
        let now = Instant::now();
        // Deliver the tail first, twice. No truncated IP packet may escape.
        assert_eq!(receiver.accept(parts[1].clone(), now).unwrap(), None);
        assert_eq!(receiver.accept(parts[1].clone(), now).unwrap(), None);
        assert_eq!(
            receiver.accept(parts[0].clone(), now).unwrap(),
            Some(Bytes::from(packet))
        );
        assert!(receiver.pending.is_empty());
        assert_eq!(receiver.budget.available_permits(), 2 * ASSEMBLY_COST);
    }

    #[test]
    fn whole_packet_keeps_original_framing_and_zero_copy_receive() {
        let p = packet(1280);
        let encoded = encode(7, &p, 1282).unwrap();
        let [wire] = encoded.datagrams() else {
            panic!("unexpected fragmentation")
        };
        assert_eq!(wire, &tag_datagram(7, &p));
        let start = wire[TAG_LEN..].as_ptr();
        let mut receiver = receiver(0);
        let decoded = receiver
            .accept(wire.clone(), Instant::now())
            .unwrap()
            .unwrap();
        assert_eq!(decoded.as_ptr(), start);
    }

    #[test]
    fn mtu_changes_between_packets_preserve_in_flight_reassembly() {
        let p = packet(1280);
        let before = encode(1, &p, 1162).unwrap();
        let larger_path = encode(1, &p, 1400).unwrap();
        let smaller_path = encode(1, &p, 1000).unwrap();
        let now = Instant::now();
        let mut receiver = receiver(2);
        assert_eq!(
            receiver.accept(before.datagrams()[0].clone(), now).unwrap(),
            None
        );
        assert_eq!(
            receiver
                .accept(larger_path.datagrams()[0].clone(), now)
                .unwrap()
                .as_deref(),
            Some(p.as_slice())
        );
        assert_eq!(
            receiver
                .accept(smaller_path.datagrams()[0].clone(), now)
                .unwrap(),
            None
        );
        assert_eq!(
            receiver
                .accept(before.datagrams()[1].clone(), now)
                .unwrap()
                .as_deref(),
            Some(p.as_slice())
        );
        assert_eq!(
            receiver
                .accept(smaller_path.datagrams()[1].clone(), now)
                .unwrap()
                .as_deref(),
            Some(p.as_slice())
        );
        assert!(receiver.pending.is_empty());
    }

    #[test]
    fn missing_fragment_expires_without_extending_on_duplicate() {
        let encoded = encode(1, &packet(1280), 1162).unwrap();
        let first = encoded.datagrams()[0].clone();
        let mut receiver = receiver(1);
        let now = Instant::now();
        receiver.accept(first.clone(), now).unwrap();
        receiver.accept(first, now + TIMEOUT / 2).unwrap();
        assert_eq!(receiver.expire(now + TIMEOUT), 1);
        assert_eq!(receiver.budget.available_permits(), ASSEMBLY_COST);
        // A late tail alone must not produce a packet from expired state.
        assert_eq!(
            receiver
                .accept(encoded.datagrams()[1].clone(), now + TIMEOUT)
                .unwrap(),
            None
        );
    }

    #[test]
    fn rejects_conflicting_overlap_and_length_and_releases_memory() {
        let encoded = encode(1, &packet(1280), 1162).unwrap();
        let first = encoded.datagrams()[0].clone();
        let now = Instant::now();
        for index in [HEADER + 10, 12] {
            let mut receiver = receiver(1);
            receiver.accept(first.clone(), now).unwrap();
            let mut corrupt = first.to_vec();
            corrupt[index] ^= 1;
            assert_eq!(
                receiver.accept(Bytes::from(corrupt), now),
                Err(DropReason::Malformed)
            );
            assert!(receiver.pending.is_empty());
            assert_eq!(receiver.budget.available_permits(), ASSEMBLY_COST);
        }
    }

    #[test]
    fn same_id_on_different_networks_and_connections_cannot_mix() {
        let encoded = encode(1, &packet(1280), 1162).unwrap();
        let now = Instant::now();
        let mut receiver = receiver(4);
        receiver
            .accept(encoded.datagrams()[0].clone(), now)
            .unwrap();
        let mut tail = encoded.datagrams()[1].to_vec();
        tail[..2].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(receiver.accept(Bytes::from(tail), now).unwrap(), None);
        let mut other_connection = Reassembler {
            pending: HashMap::new(),
            budget: Arc::new(Semaphore::new(ASSEMBLY_COST)),
        };
        assert_eq!(
            other_connection
                .accept(encoded.datagrams()[1].clone(), now)
                .unwrap(),
            None
        );
        assert!(
            receiver
                .accept(encoded.datagrams()[1].clone(), now)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn reassembly_limits_are_shared_and_released_on_disconnect() {
        let now = Instant::now();
        let mut a = receiver(MAX_PENDING + 1);
        let budget = a.budget.clone();
        for _ in 0..MAX_PENDING {
            let encoded = encode(1, &packet(1280), 1162).unwrap();
            a.accept(encoded.datagrams()[0].clone(), now).unwrap();
        }
        let extra = encode(1, &packet(1280), 1162).unwrap();
        assert_eq!(
            a.accept(extra.datagrams()[0].clone(), now),
            Err(DropReason::ReassemblyLimit)
        );
        let mut b = Reassembler {
            pending: HashMap::new(),
            budget: budget.clone(),
        };
        b.accept(extra.datagrams()[0].clone(), now).unwrap();
        let extra2 = encode(1, &packet(1280), 1162).unwrap();
        assert_eq!(
            b.accept(extra2.datagrams()[0].clone(), now),
            Err(DropReason::ReassemblyLimit)
        );
        drop(a);
        assert_eq!(budget.available_permits(), MAX_PENDING * ASSEMBLY_COST);
        b.accept(extra2.datagrams()[0].clone(), now).unwrap();
        drop(b);
        assert_eq!(
            budget.available_permits(),
            (MAX_PENDING + 1) * ASSEMBLY_COST
        );
    }

    #[test]
    fn malformed_headers_do_not_allocate() {
        let encoded = encode(1, &packet(1280), 1162).unwrap();
        let wire = &encoded.datagrams()[0];
        let mut receiver = receiver(1);
        let now = Instant::now();
        for len in 0..=HEADER {
            assert_eq!(
                receiver.accept(wire.slice(..len), now),
                Err(DropReason::Malformed)
            );
        }
        for (pos, value) in [(2, 1), (11, 255), (13, 255)] {
            let mut malformed = wire.to_vec();
            malformed[pos] = value;
            assert_eq!(
                receiver.accept(Bytes::from(malformed), now),
                Err(DropReason::Malformed)
            );
        }
        assert!(receiver.pending.is_empty());
        assert_eq!(receiver.budget.available_permits(), ASSEMBLY_COST);
        assert!(encode(0, &packet(1280), 1162).is_none());
        assert!(encode(1, &packet(MAX_PACKET + 1), 1162).is_none());
        assert!(encode(1, &packet(1280), HEADER + 1).is_none());
    }

    proptest! {
        #[test]
        fn packets_survive_different_path_budgets(
            mut p in prop::collection::vec(any::<u8>(), 40..=MAX_PACKET),
            max in 128usize..=1502,
            ipv4 in any::<bool>(),
        ) {
            p[0] = if ipv4 { 0x45 } else { 0x60 };
            let encoded = encode(9, &p, max).unwrap();
            let mut receiver = receiver(1);
            let now = Instant::now();
            let mut complete = None;
            let mut wire_bytes = 0;
            for wire in encoded.datagrams().iter().rev() {
                prop_assert!(wire.len() <= max);
                wire_bytes += wire.len();
                let decoded = receiver.accept(wire.clone(), now).unwrap();
                if decoded.is_some() {
                    prop_assert!(complete.is_none());
                    complete = decoded;
                }
            }
            prop_assert_eq!(wire_size(p.len(), max), Some(wire_bytes));
            prop_assert_eq!(complete.as_deref(), Some(p.as_slice()));
        }

        #[test]
        fn arbitrary_frames_do_not_panic_or_exceed_budget(
            frames in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..1600), 0..32),
        ) {
            let mut receiver = receiver(2);
            for frame in frames {
                let _ = receiver.accept(Bytes::from(frame), Instant::now());
                prop_assert!(receiver.pending.len() <= 2);
            }
        }
    }
}
