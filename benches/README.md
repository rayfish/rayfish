# Data-path microbenchmarks

Criterion benchmarks that time the CPU/allocation work rayfish does **per
forwarded packet**, in isolation from the network. They complement the cloud
end-to-end harness (`tests/bench/`): on a shared-vCPU box single-stream TCP is
loss/congestion-bound, which hides per-packet CPU savings, so these hold
everything else constant and measure only the data plane.

```bash
cargo bench                       # all benches
cargo bench --bench forward       # just this one
cargo bench --bench forward -- handoff   # filter by group/id
```

Criterion writes HTML reports + regression baselines under `target/criterion/`;
a second run prints `change: [...]` deltas vs the stored baseline.

## Groups (`benches/forward.rs`)

- **`handoff`** compares the old allocation-and-copy packet handoff with the
  current `Bytes` paths for TX and RX.
- **`tun_ingress`** compares the old scratch-buffer copy plus pool copy with
  extending the owned packet buffer directly.
- **`apple_tun_ingress`** compares the Swift bridge queue, `Vec` allocation and
  pool copy with the direct owned-buffer path.
- **`writer_resolve`** compares resolving the swappable TUN sender on each
  packet with the reader's cached lookup.
- **`firewall`** measures packet parsing and evaluation for the default allow
  path and a small inbound whitelist.

Ingress cases use 64, 1280 and 1500 byte packets. They measure buffer copies,
allocation and queue overhead in memory. They do not call an OS TUN or utun
device, so they estimate the per-packet CPU saved in those paths, not end-to-end
packet latency. The old and new variants are benchmark fixtures, not live code
paths.
