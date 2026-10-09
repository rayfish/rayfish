//! Focused, deterministic measurements for the former Swift packet bridge and
//! the current owned-packet handoff. Run with `cargo bench --bench apple_bridge`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

struct CountingAllocator;

static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: All allocation operations are forwarded unchanged to `System`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) && !pointer.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) && !new_pointer.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const PACKET_SIZES: &[usize] = &[64, 256, 1200, 1500];
const BATCH_SIZES: &[usize] = &[1, 8, 32];
const ITERATIONS: usize = 10_000;
const POOL_CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, strum::Display)]
enum Path {
    #[strum(to_string = "bridge-per-packet")]
    PerPacketBridge,
    #[strum(to_string = "bridge-batched")]
    BatchedBridge,
    #[strum(to_string = "owned-handoff")]
    OwnedHandoff,
}

impl Path {
    fn copies_per_packet(self) -> usize {
        match self {
            Self::PerPacketBridge | Self::BatchedBridge => 2,
            Self::OwnedHandoff => 0,
        }
    }
}

fn main() {
    println!(
        "path,packet_bytes,batch,packets_per_second,mib_per_second,p50_ns_per_packet,p99_ns_per_packet,cpu_percent,allocations_per_packet,copies_per_packet,max_queue_depth,drops"
    );
    for &packet_size in PACKET_SIZES {
        let packet = packet(packet_size);
        for &batch_size in BATCH_SIZES {
            for path in [
                Path::PerPacketBridge,
                Path::BatchedBridge,
                Path::OwnedHandoff,
            ] {
                let report = measure(path, &packet, batch_size);
                println!(
                    "{},{},{},{:.0},{:.2},{:.0},{:.0},{:.1},{:.3},{},{},{}",
                    path,
                    packet_size,
                    batch_size,
                    report.packets_per_second,
                    report.mib_per_second,
                    report.p50_ns_per_packet,
                    report.p99_ns_per_packet,
                    report.cpu_percent,
                    report.allocations_per_packet,
                    path.copies_per_packet(),
                    report.max_queue_depth,
                    report.drops,
                );
            }
        }
    }
}

struct Report {
    packets_per_second: f64,
    mib_per_second: f64,
    p50_ns_per_packet: f64,
    p99_ns_per_packet: f64,
    cpu_percent: f64,
    allocations_per_packet: f64,
    max_queue_depth: usize,
    drops: usize,
}

fn measure(path: Path, packet: &[u8], batch_size: usize) -> Report {
    let owned_packet = Bytes::copy_from_slice(packet);
    let mut samples = Vec::with_capacity(ITERATIONS);
    let mut pool = BytesMut::with_capacity(POOL_CHUNK);
    let (per_packet_tx, mut per_packet_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let (batch_tx, mut batch_rx) = tokio::sync::mpsc::channel::<Vec<Vec<u8>>>(1);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    let cpu_before = cpu_time();
    let started = Instant::now();
    COUNT_ALLOCATIONS.store(true, Ordering::Relaxed);

    for _ in 0..ITERATIONS {
        let batch_started = Instant::now();
        match path {
            Path::PerPacketBridge => {
                for _ in 0..batch_size {
                    per_packet_tx
                        .try_send(black_box(packet).to_vec())
                        .expect("single-slot benchmark queue must have capacity");
                    let packet = per_packet_rx
                        .try_recv()
                        .expect("benchmark packet must be queued");
                    pool.extend_from_slice(black_box(&packet));
                    pool.clear();
                }
            }
            Path::BatchedBridge => {
                let packets = (0..batch_size)
                    .map(|_| black_box(packet).to_vec())
                    .collect::<Vec<_>>();
                batch_tx
                    .try_send(packets)
                    .expect("single-slot batch queue must have capacity");
                let packets = batch_rx.try_recv().expect("benchmark batch must be queued");
                for packet in packets {
                    pool.extend_from_slice(black_box(&packet));
                    pool.clear();
                }
            }
            Path::OwnedHandoff => {
                for _ in 0..batch_size {
                    black_box(owned_packet.clone());
                }
            }
        }
        samples.push(batch_started.elapsed().as_nanos() as u64 / batch_size as u64);
    }

    COUNT_ALLOCATIONS.store(false, Ordering::Relaxed);
    let elapsed = started.elapsed();
    let cpu_elapsed = cpu_time().saturating_sub(cpu_before);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    samples.sort_unstable();

    let packets = (ITERATIONS * batch_size) as f64;
    let seconds = elapsed.as_secs_f64();
    let bytes_per_second = packets * packet.len() as f64 / seconds;
    Report {
        packets_per_second: packets / seconds,
        mib_per_second: bytes_per_second / (1024.0 * 1024.0),
        p50_ns_per_packet: percentile(&samples, 0.50) as f64,
        p99_ns_per_packet: percentile(&samples, 0.99) as f64,
        cpu_percent: cpu_elapsed.as_secs_f64() / seconds * 100.0,
        allocations_per_packet: allocations as f64 / packets,
        // The harness synchronously drains each single-slot queue after every
        // send, so its observed high-water mark is one and it cannot drop.
        max_queue_depth: if matches!(path, Path::OwnedHandoff) {
            0
        } else {
            1
        },
        drops: 0,
    }
}

fn percentile(samples: &[u64], percentile: f64) -> u64 {
    let index = ((samples.len() - 1) as f64 * percentile).ceil() as usize;
    samples[index]
}

fn packet(size: usize) -> Vec<u8> {
    let mut packet = vec![0; size];
    if size >= 24 {
        packet[0] = 0x45;
        packet[9] = 6;
        packet[16..20].copy_from_slice(&[100, 64, 0, 3]);
    }
    packet
}

#[cfg(unix)]
fn cpu_time() -> Duration {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` points to writable storage for the complete `rusage`.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return Duration::ZERO;
    }
    // SAFETY: `getrusage` initialized the struct when it returned zero.
    let usage = unsafe { usage.assume_init() };
    let user = timeval_duration(usage.ru_utime);
    let system = timeval_duration(usage.ru_stime);
    user + system
}

#[cfg(unix)]
fn timeval_duration(value: libc::timeval) -> Duration {
    Duration::from_secs(value.tv_sec as u64) + Duration::from_micros(value.tv_usec as u64)
}

#[cfg(not(unix))]
fn cpu_time() -> Duration {
    Duration::ZERO
}
