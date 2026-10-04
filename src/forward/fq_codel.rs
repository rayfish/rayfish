//! FQ-CoDel for inner flows, before mesh fragmentation enters QUIC's FIFO.
//!
//! RFC 8290: salted flow buckets, byte deficits, new/old active lists, and
//! RFC 8289 CoDel per bucket (5 ms target, 100 ms interval). We drop rather
//! than mark ECN. The `fq-codel` engine uses loss-tolerant congestion control
//! and a short QUIC queue:
//! backpressure must retain packets here for scheduling and delay measurement.
//! This controls our queue, not queues already built in a router or Wi-Fi link.

use std::collections::VecDeque;
use std::future::ready;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use ahash::RandomState;
use iroh::endpoint::Connection;
use tokio::sync::mpsc::{Receiver, Sender as PacketSender, channel, error::TrySendError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use super::fragment::Encoded;
use crate::firewall::PacketInfo;
use crate::peers::{ActivityClock, PeerRoute};
use crate::stats::{DropReason, ForwardMetrics};

const BUCKETS: usize = 1024;
const QUANTUM: i64 = 1514;
const TARGET: Duration = Duration::from_millis(5);
const INTERVAL: Duration = Duration::from_millis(100);
const MAX_BYTES: usize = 1024 * 1024;
const MAX_PACKETS: usize = 10_240;
const INGRESS_CAPACITY: usize = 256;
const INGRESS_BATCH: usize = 64;
const SEND_BATCH: usize = 32;
const PACKET_OVERHEAD: usize = 256;
static BUDGET: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(8 * MAX_BYTES)));

pub(crate) struct Sender {
    ingress: PacketSender<Packet>,
    hash: RandomState,
    backlog: Arc<AtomicUsize>,
    stats: Arc<ForwardMetrics>,
}

impl Sender {
    pub(super) fn spawn(route: &PeerRoute, stats: Arc<ForwardMetrics>) -> Self {
        let (ingress, rx) = channel(INGRESS_CAPACITY);
        tokio::spawn(run_sender(
            route.conn.clone(),
            route.activity_clock(),
            rx,
            Arc::clone(&stats),
        ));
        Self {
            ingress,
            hash: RandomState::new(),
            backlog: Arc::new(AtomicUsize::new(0)),
            stats,
        }
    }

    pub(super) fn enqueue(&self, info: &PacketInfo, handle: u16, encoded: Encoded, ip_len: usize) {
        let bytes = encoded.datagrams().iter().map(|p| p.len()).sum::<usize>();
        let Ok(permit) =
            Arc::clone(&BUDGET).try_acquire_many_owned((bytes + PACKET_OVERHEAD) as u32)
        else {
            self.stats.record_drop(DropReason::QueueFull);
            return;
        };
        let bucket = self.hash.hash_one((
            handle,
            info.src_ip,
            info.dst_ip,
            info.protocol,
            info.src_port,
            info.dst_port,
        )) as usize
            % BUCKETS;
        self.backlog.fetch_add(bytes, Ordering::Relaxed);
        let packet = Packet {
            bucket,
            encoded,
            ip_len,
            bytes,
            arrived: Instant::now(),
            backlog: Arc::clone(&self.backlog),
            _permit: permit,
        };
        if let Err(error) = self.ingress.try_send(packet) {
            self.stats.record_drop(match error {
                TrySendError::Closed(_) => DropReason::NoPeer,
                TrySendError::Full(_) => DropReason::QueueFull,
            });
        }
    }

    pub(crate) fn queued_bytes(&self) -> usize {
        self.backlog.load(Ordering::Relaxed)
    }
}

async fn run_sender(
    conn: Connection,
    activity: ActivityClock,
    mut rx: Receiver<Packet>,
    stats: Arc<ForwardMetrics>,
) {
    let mut queue = Queue::new(Arc::clone(&stats));
    'worker: loop {
        if rx.is_closed() {
            break;
        }
        let next = tokio::select! {
            biased;
            _ = conn.closed() => break,
            packet = rx.recv() => match packet {
                Some(packet) => Some(packet),
                None => break,
            },
            _ = ready(()), if queue.packets > 0 => None,
        };
        if let Some(packet) = next {
            queue.enqueue(packet);
        }
        // Classify a bounded batch before selecting a flow.
        for _ in 0..INGRESS_BATCH {
            let Ok(packet) = rx.try_recv() else { break };
            queue.enqueue(packet);
        }
        for _ in 0..SEND_BATCH {
            let Some(packet) = queue.dequeue(Instant::now()) else {
                break;
            };
            match send_packet(&conn, &mut rx, &mut queue, &packet).await {
                Ok(()) => {
                    stats.record_tx(packet.ip_len);
                    activity.touch();
                }
                Err(reason) => {
                    stats.record_drop(reason);
                    if reason == DropReason::NoPeer {
                        break 'worker;
                    }
                }
            }
        }
        tokio::task::yield_now().await;
    }
    // Close before draining so racing producers cannot retain packets.
    rx.close();
    while let Ok(packet) = rx.try_recv() {
        drop(packet);
        stats.record_drop(DropReason::NoPeer);
    }
    for _ in 0..queue.packets {
        stats.record_drop(DropReason::NoPeer);
    }
}

async fn send_packet(
    conn: &Connection,
    rx: &mut Receiver<Packet>,
    queue: &mut Queue,
    packet: &Packet,
) -> Result<(), DropReason> {
    let frames = packet.encoded.datagrams();
    if conn.datagram_send_buffer_space() >= packet.bytes {
        return match conn.send_many_datagrams(frames) {
            Ok(n) if n == frames.len() => Ok(()),
            _ => Err(DropReason::SendFailure),
        };
    }
    for frame in frames {
        let send = conn.send_datagram_wait(frame.clone());
        tokio::pin!(send);
        let mut incoming_batch = 0;
        loop {
            tokio::select! {
                biased;
                _ = conn.closed() => return Err(DropReason::NoPeer),
                result = &mut send => {
                    result.map_err(|_| DropReason::SendFailure)?;
                    break;
                },
                incoming = rx.recv() => {
                    let Some(incoming) = incoming else {
                        return Err(DropReason::NoPeer);
                    };
                    queue.enqueue(incoming);
                    incoming_batch += 1;
                    if incoming_batch == INGRESS_BATCH {
                        incoming_batch = 0;
                        tokio::task::yield_now().await;
                    }
                },
            }
        }
    }
    Ok(())
}

struct Packet {
    bucket: usize,
    encoded: Encoded,
    ip_len: usize,
    bytes: usize,
    arrived: Instant,
    backlog: Arc<AtomicUsize>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Packet {
    fn drop(&mut self) {
        self.backlog.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct CoDel {
    first_above: Option<Instant>,
    drop_next: Option<Instant>,
    dropping: bool,
    count: u32,
    last_count: u32,
}

impl CoDel {
    fn should_drop(
        &mut self,
        packet: Option<&Packet>,
        remaining: usize,
        max_packet: usize,
        now: Instant,
    ) -> bool {
        let Some(packet) = packet else {
            self.first_above = None;
            return false;
        };
        if now.saturating_duration_since(packet.arrived) < TARGET || remaining <= max_packet {
            self.first_above = None;
            return false;
        }
        match self.first_above {
            Some(deadline) => now >= deadline,
            None => {
                self.first_above = Some(now + INTERVAL);
                false
            }
        }
    }

    fn control_law(time: Instant, count: u32) -> Instant {
        time + INTERVAL.div_f64(f64::from(count.max(1)).sqrt())
    }
}

#[derive(Default)]
struct Flow {
    packets: VecDeque<Packet>,
    bytes: usize,
    deficit: i64,
    active: bool,
    codel: CoDel,
}

struct Queue {
    flows: Vec<Flow>,
    new: VecDeque<usize>,
    old: VecDeque<usize>,
    bytes: usize,
    packets: usize,
    max_packet: usize,
    stats: Arc<ForwardMetrics>,
}

impl Queue {
    fn new(stats: Arc<ForwardMetrics>) -> Self {
        Self {
            flows: (0..BUCKETS).map(|_| Flow::default()).collect(),
            new: VecDeque::new(),
            old: VecDeque::new(),
            bytes: 0,
            packets: 0,
            max_packet: QUANTUM as usize,
            stats,
        }
    }

    fn enqueue(&mut self, packet: Packet) {
        let index = packet.bucket;
        let flow = &mut self.flows[index];
        self.max_packet = self.max_packet.max(packet.bytes);
        self.bytes += packet.bytes;
        self.packets += 1;
        flow.bytes += packet.bytes;
        flow.packets.push_back(packet);
        if !flow.active {
            flow.active = true;
            flow.deficit = QUANTUM;
            self.new.push_back(index);
        }
        // Shed the fattest queue, preserving sparse traffic under overload.
        while self.bytes > MAX_BYTES || self.packets > MAX_PACKETS {
            let Some((index, flow)) = self.flows.iter().enumerate().max_by_key(|(_, f)| f.bytes)
            else {
                break;
            };
            let count = (flow.packets.len() / 2).clamp(1, 64);
            for _ in 0..count {
                if self.pop(index).is_some() {
                    self.stats.record_drop(DropReason::QueueFull);
                }
            }
        }
    }

    fn pop(&mut self, index: usize) -> Option<Packet> {
        let flow = &mut self.flows[index];
        let packet = flow.packets.pop_front()?;
        flow.bytes -= packet.bytes;
        self.bytes -= packet.bytes;
        self.packets -= 1;
        Some(packet)
    }

    fn codel_pop(&mut self, index: usize, now: Instant) -> Option<Packet> {
        let mut packet = self.pop(index);
        let mut should_drop =
            self.flows[index]
                .codel
                .should_drop(packet.as_ref(), self.bytes, self.max_packet, now);
        if self.flows[index].codel.dropping {
            if !should_drop {
                self.flows[index].codel.dropping = false;
            }
            while self.flows[index].codel.dropping
                && self.flows[index].codel.drop_next.is_some_and(|t| now >= t)
            {
                drop(packet);
                self.stats.record_drop(DropReason::QueueDelay);
                self.flows[index].codel.count = self.flows[index].codel.count.saturating_add(1);
                packet = self.pop(index);
                should_drop = self.flows[index].codel.should_drop(
                    packet.as_ref(),
                    self.bytes,
                    self.max_packet,
                    now,
                );
                let codel = &mut self.flows[index].codel;
                if !should_drop {
                    codel.dropping = false;
                } else if let Some(next) = codel.drop_next {
                    codel.drop_next = Some(CoDel::control_law(next, codel.count));
                }
            }
        } else if should_drop {
            drop(packet);
            self.stats.record_drop(DropReason::QueueDelay);
            packet = self.pop(index);
            self.flows[index]
                .codel
                .should_drop(packet.as_ref(), self.bytes, self.max_packet, now);
            let codel = &mut self.flows[index].codel;
            codel.dropping = true;
            let delta = codel.count.saturating_sub(codel.last_count);
            codel.count = if delta > 1
                && codel
                    .drop_next
                    .is_some_and(|t| now.saturating_duration_since(t) < INTERVAL * 16)
            {
                delta
            } else {
                1
            };
            codel.last_count = codel.count;
            codel.drop_next = Some(CoDel::control_law(now, codel.count));
        }
        packet
    }

    fn dequeue(&mut self, now: Instant) -> Option<Packet> {
        loop {
            let from_new = !self.new.is_empty();
            let index = *if from_new {
                self.new.front()?
            } else {
                self.old.front()?
            };
            if self.flows[index].deficit <= 0 {
                self.flows[index].deficit += QUANTUM;
                if from_new {
                    self.new.pop_front();
                } else {
                    self.old.pop_front();
                }
                self.old.push_back(index);
                continue;
            }
            if let Some(packet) = self.codel_pop(index, now) {
                self.flows[index].deficit -= packet.bytes as i64;
                return Some(packet);
            }
            if from_new {
                // Even an empty new flow passes through the old list, preventing
                // repeated sparse arrivals from starving established flows.
                self.new.pop_front();
                self.old.push_back(index);
            } else {
                self.old.pop_front();
                self.flows[index].active = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::Ipv6Addr;
    use tokio::time::timeout;

    fn packet(bucket: usize, bytes: usize, arrived: Instant) -> Packet {
        let backlog = Arc::new(AtomicUsize::new(bytes));
        let permit = Arc::new(Semaphore::new(bytes + PACKET_OVERHEAD))
            .try_acquire_many_owned((bytes + PACKET_OVERHEAD) as u32)
            .unwrap();
        Packet {
            bucket,
            encoded: Encoded::Whole(Bytes::from(vec![0; bytes])),
            ip_len: bytes,
            bytes,
            arrived,
            backlog,
            _permit: permit,
        }
    }

    #[tokio::test]
    async fn ingress_overflow_and_close_release_packet_budget() {
        let stats = Arc::new(ForwardMetrics::default());
        let (ingress, mut rx) = channel(2);
        let sender = Sender {
            ingress,
            hash: RandomState::new(),
            backlog: Arc::new(AtomicUsize::new(0)),
            stats: Arc::clone(&stats),
        };
        let info = PacketInfo {
            src_ip: Ipv6Addr::LOCALHOST.into(),
            dst_ip: Ipv6Addr::UNSPECIFIED.into(),
            protocol: 6,
            src_port: 12345,
            dst_port: 22,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        for _ in 0..3 {
            sender.enqueue(&info, 0, Encoded::Whole(Bytes::from_static(b"packet")), 6);
        }
        assert_eq!(sender.queued_bytes(), 12);
        assert_eq!(stats.drop_count(DropReason::QueueFull), 1);
        // An idle worker can receive packets sent before it starts waiting.
        drop(
            timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(sender.queued_bytes(), 6);
        rx.close();
        sender.enqueue(&info, 0, Encoded::Whole(Bytes::from_static(b"rejected")), 8);
        assert_eq!(sender.queued_bytes(), 6);
        assert_eq!(stats.drop_count(DropReason::NoPeer), 1);
        // Closing rejects new packets while allowing retained packets to drain.
        while let Ok(packet) = rx.try_recv() {
            drop(packet);
        }
        assert_eq!(sender.queued_bytes(), 0);
        assert!(rx.recv().await.is_none());
    }

    #[test]
    fn sparse_flow_overtakes_established_bulk_flow() {
        let now = Instant::now();
        let mut queue = Queue::new(Arc::new(ForwardMetrics::default()));
        for _ in 0..100 {
            queue.enqueue(packet(0, 1500, now));
        }
        // Consume its first quantum and move the bulk flow onto the old list.
        assert_eq!(queue.dequeue(now).unwrap().bucket, 0);
        assert_eq!(queue.dequeue(now).unwrap().bucket, 0);
        assert_eq!(queue.dequeue(now).unwrap().bucket, 0);
        queue.enqueue(packet(1, 100, now));
        assert_eq!(queue.dequeue(now).unwrap().bucket, 1);
        assert_eq!(queue.dequeue(now).unwrap().bucket, 0);
    }

    #[test]
    fn round_robin_accounts_for_bytes_and_preserves_order() {
        let now = Instant::now();
        let mut queue = Queue::new(Arc::new(ForwardMetrics::default()));
        for sequence in 0..500 {
            let mut small = packet(0, 100, now);
            small.ip_len = sequence;
            queue.enqueue(small);
            queue.enqueue(packet(1, 1500, now));
        }
        let mut small_bytes = 0;
        let mut big_bytes = 0;
        let mut sequence = 0;
        for _ in 0..200 {
            let packet = queue.dequeue(now).unwrap();
            if packet.bucket == 0 {
                assert_eq!(packet.ip_len, sequence);
                sequence += 1;
                small_bytes += packet.bytes;
            } else {
                big_bytes += packet.bytes;
            }
        }
        assert!(small_bytes.abs_diff(big_bytes) <= 2 * QUANTUM as usize);
    }

    #[test]
    fn transient_delay_does_not_drop_but_sustained_delay_does() {
        let stats = Arc::new(ForwardMetrics::default());
        let mut queue = Queue::new(Arc::clone(&stats));
        let now = Instant::now();
        for _ in 0..100 {
            queue.enqueue(packet(0, 1500, now));
        }
        queue.dequeue(now + TARGET);
        queue.dequeue(now + INTERVAL);
        assert_eq!(stats.total_drops(), 0);
        queue.dequeue(now + INTERVAL + TARGET);
        assert_eq!(stats.total_drops(), 1);
        assert!(queue.flows[0].codel.dropping);
        queue.dequeue(now + INTERVAL * 2 + TARGET);
        assert_eq!(stats.total_drops(), 2);
        // A return below target leaves the dropping state.
        for p in &mut queue.flows[0].packets {
            p.arrived = now + INTERVAL * 3;
        }
        queue.dequeue(now + INTERVAL * 3);
        assert!(!queue.flows[0].codel.dropping);
        assert_eq!(stats.total_drops(), 2);
    }

    #[test]
    fn short_queue_is_preserved_even_when_delayed() {
        let stats = Arc::new(ForwardMetrics::default());
        let mut queue = Queue::new(Arc::clone(&stats));
        let now = Instant::now();
        for _ in 0..2 {
            queue.enqueue(packet(0, 1500, now));
        }
        assert!(queue.dequeue(now + INTERVAL * 20).is_some());
        assert!(queue.dequeue(now + INTERVAL * 21).is_some());
        assert!(queue.dequeue(now + INTERVAL * 22).is_none());
        assert_eq!(stats.total_drops(), 0);
    }

    #[test]
    fn overflow_sheds_bulk_flow_and_releases_retention_budget() {
        let stats = Arc::new(ForwardMetrics::default());
        let mut queue = Queue::new(Arc::clone(&stats));
        let now = Instant::now();
        let sparse = packet(1, 100, now);
        let backlog = Arc::clone(&sparse.backlog);
        queue.enqueue(sparse);
        for _ in 0..1000 {
            queue.enqueue(packet(0, 1500, now));
        }
        assert!(queue.bytes <= MAX_BYTES);
        assert!(stats.total_drops() > 0);
        assert_eq!(queue.flows[1].packets.len(), 1);
        assert_eq!(queue.dequeue(now).unwrap().bucket, 1);
        assert_eq!(backlog.load(Ordering::Relaxed), 0);
        drop(queue);
    }

    #[test]
    fn drained_flow_can_reactivate_without_duplicate_list_entries() {
        let now = Instant::now();
        let mut queue = Queue::new(Arc::new(ForwardMetrics::default()));
        for _ in 0..100 {
            queue.enqueue(packet(0, 100, now));
            assert!(queue.dequeue(now).is_some());
            assert!(queue.dequeue(now).is_none());
            assert!(queue.new.is_empty());
            assert!(queue.old.is_empty());
            assert!(!queue.flows[0].active);
        }
    }

    #[tokio::test]
    async fn scheduled_packets_cross_quic_and_close_releases_queue() {
        use crate::config::QuicEngine;
        use crate::membership::derive_ipv6;
        use crate::peers::PeerTable;
        use iroh::Endpoint;
        use iroh::endpoint::presets;

        async fn endpoint() -> Endpoint {
            Endpoint::builder(presets::Minimal)
                .alpns(vec![crate::transport::mesh_alpn()])
                .transport_config(crate::transport::quic_transport_config(QuicEngine::FqCodel))
                .bind()
                .await
                .unwrap()
        }
        let a = endpoint().await;
        let b = endpoint().await;
        let alpn = crate::transport::mesh_alpn();
        let (send, recv) = timeout(Duration::from_secs(5), async {
            tokio::join!(a.connect(b.addr(), &alpn), async {
                b.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let send = send.unwrap();
        let peers = PeerTable::new().with_engine(QuicEngine::FqCodel);
        let b_ip = derive_ipv6(&b.id());
        peers.add(b_ip, send.clone(), b.id(), "test");
        let route = peers.lookup_v6(&b_ip).unwrap();
        assert!(route.scheduler.is_some());
        let stats = Arc::new(ForwardMetrics::default());
        let sender = route
            .scheduler
            .as_ref()
            .unwrap()
            .get_or_init(|| Sender::spawn(&route, Arc::clone(&stats)));
        let info = PacketInfo {
            src_ip: derive_ipv6(&a.id()).into(),
            dst_ip: b_ip.into(),
            protocol: 6,
            src_port: 12345,
            dst_port: 22,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        let frames = Encoded::Fragments(vec![
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
        ]);
        sender.enqueue(&info, route.handle, frames, 11);
        assert_eq!(
            timeout(Duration::from_secs(5), recv.read_datagram())
                .await
                .unwrap()
                .unwrap(),
            b"first"[..]
        );
        assert_eq!(
            timeout(Duration::from_secs(5), recv.read_datagram())
                .await
                .unwrap()
                .unwrap(),
            b"second"[..]
        );
        assert_eq!(stats.packets_tx.get(), 1);
        assert_eq!(stats.bytes_tx.get(), 11);
        assert_eq!(sender.queued_bytes(), 0);
        // Dropping a sender stops its worker without closing the peer connection.
        let stopped_stats = Arc::new(ForwardMetrics::default());
        let standalone = Sender::spawn(&route, Arc::clone(&stopped_stats));
        let backlog = Arc::clone(&standalone.backlog);
        standalone.enqueue(
            &info,
            route.handle,
            Encoded::Whole(Bytes::from_static(b"pending")),
            7,
        );
        drop(standalone);
        timeout(Duration::from_secs(5), async {
            while backlog.load(Ordering::Relaxed) > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(stopped_stats.total_drops(), 1);
        assert!(send.close_reason().is_none());
        for _ in 0..256 {
            sender.enqueue(
                &info,
                route.handle,
                Encoded::Whole(Bytes::from(vec![0; 1400])),
                1400,
            );
        }
        send.close(0u32.into(), b"test complete");
        timeout(Duration::from_secs(5), async {
            while sender.queued_bytes() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        a.close().await;
        b.close().await;
    }
}
