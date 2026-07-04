//! Microbenchmarks for the per-packet data path.
//!
//! These isolate the CPU/allocation work rayfish does **per forwarded packet**,
//! away from the network. The Scaleway harness (`tests/bench/`) measures
//! end-to-end throughput, but on a shared-vCPU box single-stream TCP is
//! loss/congestion-bound, which hides per-packet CPU savings. These benches are
//! the complementary instrument: they hold everything else constant and time
//! only the work the data plane does, so a regression (or the gain from the
//! zero-copy hand-off) is visible and stable run-to-run.
//!
//! Two groups:
//! - `handoff` — the packet ownership transfer that the zero-copy change
//!   touched. `copy` reproduces the old allocate-and-copy (`Bytes::copy_from_slice`
//!   on TX, `Vec::to_vec` on RX); `zerocopy` is the current pooled
//!   `split_to(n).freeze()` (TX) and `Bytes` clone (RX). The delta is the saving.
//! - `firewall` — `parse_packet_info` + `evaluate_packet`, the unavoidable
//!   per-packet work run once per direction on every packet. A regression guard.

use bytes::{Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use rayfish::firewall::{
    self, Action, Direction, FirewallConfig, FirewallRule, PeerFilter, PortRange, Protocol,
    RuleOrigin, SharedFirewall,
};

/// Datagram sizes spanning the MTU: a 64-byte control/ACK-ish packet and a
/// full 1280-byte (TUN MTU) data packet. The copy cost scales with size; the
/// zero-copy path should be flat.
const SIZES: &[usize] = &[64, 1280];

/// Pool chunk size mirrors `forward::TX_POOL_CHUNK` (64 KiB) so the amortized
/// allocation behaviour matches production.
const POOL_CHUNK: usize = 64 * 1024;
const MAX_DATAGRAM: usize = 1500;

/// Build a minimal but valid IPv4/TCP packet of `len` bytes destined for
/// `100.64.0.3:dst_port`, padded with zeros. Mirrors the test helpers in
/// `forward.rs` so the parser walks a realistic header.
fn ipv4_tcp_packet(len: usize, dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; len.max(24)];
    p[0] = 0x45; // IPv4, IHL=5
    p[9] = 6; // TCP
    p[16..20].copy_from_slice(&[100, 64, 0, 3]); // dst ip
    p[20] = 0;
    p[21] = 80; // src port 80
    p[22] = (dst_port >> 8) as u8;
    p[23] = dst_port as u8;
    p.truncate(len.max(24));
    p
}

/// The packet ownership hand-off: old copy path vs. current zero-copy path,
/// for both the TX (TUN -> peer) and RX (peer -> TUN) directions.
fn bench_handoff(c: &mut Criterion) {
    let mut group = c.benchmark_group("handoff");
    for &size in SIZES {
        let packet = ipv4_tcp_packet(size, 443);
        group.throughput(Throughput::Bytes(size as u64));

        // TX old: allocate a fresh Bytes and copy the packet into it — what
        // `Bytes::copy_from_slice(&buf[..n])` did before the pooled path.
        group.bench_with_input(BenchmarkId::new("tx_copy", size), &packet, |b, pkt| {
            b.iter(|| {
                let owned = Bytes::copy_from_slice(black_box(&pkt[..]));
                black_box(owned)
            });
        });

        // TX new: read into a reused pool and slice the packet out as an owned
        // Bytes sharing the chunk allocation — `split_to(n).freeze()`. The pool
        // is reserved across iterations exactly as `run_mesh` does, so a fresh
        // 64 KiB chunk is amortized over ~50 packets, not paid per iteration.
        group.bench_with_input(BenchmarkId::new("tx_zerocopy", size), &packet, |b, pkt| {
            let mut pool = BytesMut::with_capacity(POOL_CHUNK);
            b.iter(|| {
                if pool.capacity() < MAX_DATAGRAM {
                    pool.reserve(POOL_CHUNK);
                }
                pool.extend_from_slice(black_box(&pkt[..]));
                let out = pool.split_to(pkt.len()).freeze();
                black_box(out)
            });
        });

        // RX old: `datagram.to_vec()` — a heap allocation + copy per inbound
        // packet before handing it to the TUN writer channel.
        let datagram = Bytes::copy_from_slice(&packet);
        group.bench_with_input(BenchmarkId::new("rx_copy", size), &datagram, |b, dg| {
            b.iter(|| {
                let v = black_box(dg).to_vec();
                black_box(v)
            });
        });

        // RX new: the datagram is already an owned `Bytes`; forwarding it is a
        // refcount bump, no copy. This is what `tun_tx.send(datagram)` now does.
        group.bench_with_input(BenchmarkId::new("rx_zerocopy", size), &datagram, |b, dg| {
            b.iter(|| {
                let cloned = black_box(dg).clone();
                black_box(cloned)
            });
        });
    }
    group.finish();
}

/// `parse_packet_info` + `evaluate_packet`: the per-packet work that runs
/// regardless of the hand-off strategy, once per direction on every packet.
fn bench_firewall(c: &mut Criterion) {
    let peer = iroh::SecretKey::generate().public();
    let net = "bench-net";

    // Default config, no rules: the cheapest path (parse + default action +
    // conntrack insert on the outbound). Outbound defaults to allow, so the
    // outbound benchmark below still exercises the track-and-allow path.
    let allow_all = SharedFirewall::new(FirewallConfig::default());

    // A small whitelist ending in a catch-all deny — the shape `materialize_
    // suggestions` produces. Forces the rule scan to walk several entries.
    let whitelist = SharedFirewall::new(FirewallConfig {
        default_inbound: Action::Allow,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
        rules: vec![
            rule(Direction::In, Action::Allow, Protocol::Tcp, Some((22, 22))),
            rule(Direction::In, Action::Allow, Protocol::Tcp, Some((80, 80))),
            rule(
                Direction::In,
                Action::Allow,
                Protocol::Tcp,
                Some((443, 443)),
            ),
            rule(Direction::In, Action::Deny, Protocol::Any, None),
        ],
    });

    let packet = ipv4_tcp_packet(1280, 443);

    let mut group = c.benchmark_group("firewall");
    group.throughput(Throughput::Elements(1));

    group.bench_function("parse_only", |b| {
        b.iter(|| black_box(firewall::parse_packet_info(black_box(&packet))));
    });

    group.bench_function("parse_eval_out_allow", |b| {
        b.iter(|| {
            let info = firewall::parse_packet_info(black_box(&packet)).unwrap();
            black_box(allow_all.evaluate_packet(Direction::Out, &info, &peer, Some(net)))
        });
    });

    group.bench_function("parse_eval_in_whitelist", |b| {
        b.iter(|| {
            let info = firewall::parse_packet_info(black_box(&packet)).unwrap();
            black_box(whitelist.evaluate_packet(Direction::In, &info, &peer, Some(net)))
        });
    });

    group.finish();
}

fn rule(
    direction: Direction,
    action: Action,
    protocol: Protocol,
    port: Option<(u16, u16)>,
) -> FirewallRule {
    FirewallRule {
        direction,
        action,
        protocol,
        port: port.map(|(start, end)| PortRange { start, end }),
        peer: PeerFilter::Any,
        network: None,
        origin: RuleOrigin::Local,
    }
}

criterion_group!(benches, bench_handoff, bench_firewall);
criterion_main!(benches);
