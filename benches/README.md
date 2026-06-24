# Data-path microbenchmarks

Criterion benchmarks that time the CPU/allocation work rayfish does **per
forwarded packet**, in isolation from the network. They complement the Scaleway
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

- **`handoff`** — the packet ownership transfer the zero-copy change touched,
  TX (TUN→peer) and RX (peer→TUN), old copy path vs current zero-copy, at 64 B
  and 1280 B (TUN MTU):
  - `tx_copy` = old `Bytes::copy_from_slice` (allocate + copy) ·
    `tx_zerocopy` = pooled `BytesMut::split_to(n).freeze()`
  - `rx_copy` = old `datagram.to_vec()` · `rx_zerocopy` = `Bytes` clone (refcount)
- **`firewall`** — `parse_packet_info` + `evaluate_packet`, the unavoidable
  per-packet work run once per direction. A regression guard
  (`parse_only`, `parse_eval_out_allow`, `parse_eval_in_whitelist`).

The `*_copy` variants reproduce the pre-optimization code so the delta to the
`*_zerocopy` variant is exactly the saving; they are bench-only fixtures, not
live code paths.
