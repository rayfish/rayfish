# Phase 1: Harden the Foundation

Make the two-peer point-to-point VPN rock-solid before adding multi-peer complexity in Phase 2.

## Current state

~150 lines across 5 modules. Creator listens for one connection, joiner connects by EndpointId. Hardcoded IPs (100.64.0.1 / .2). No reconnection, no signal handling, no stats. Packets forwarded as QUIC datagrams. TUN MTU is 1200 bytes, which fits within QUIC datagram limits — all packets use `send_datagram` / `read_datagram`.

## Scope

Four components, layered so each builds on the previous:

1. Shutdown & signal handling
2. Stats collection
3. Reconnect loop
4. Root privilege check

**Dropped from original TODO:** Oversized packet handling. The TUN MTU of 1200 bytes guarantees all packets fit in QUIC datagrams. No stream fallback needed.

---

## 1. Shutdown & Signal Handling

### New module: `src/shutdown.rs`

A `tokio_util::sync::CancellationToken` is the shared shutdown signal. Created in `main()`, cloned into every async task.

A dedicated task listens for OS signals:

- `tokio::signal::ctrl_c()` on both macOS and Linux (SIGINT)
- `tokio::signal::unix::signal(SIGTERM)` on Linux (for systemd/process managers)

When either fires, the task calls `token.cancel()`.

### Integration with existing loops

Every async loop in `forward.rs` (`tun_read_loop`, `iroh_read_loop`) adds `token.cancelled()` as a `tokio::select!` branch. When the token fires:

- Forwarding loops stop reading/writing and return
- The iroh connection is closed (dropped)
- The TUN device is dropped (kernel reclaims the interface)
- Stats prints a final session summary before exit

### New dependency

- `tokio_util` (for `CancellationToken`)

---

## 2. Stats Collection

### New module: `src/stats.rs`

```
struct Stats {
    packets_rx: AtomicU64,
    packets_tx: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    drops: AtomicU64,
    start_time: Instant,
}
```

Wrapped in `Arc<Stats>`, shared with forwarding loops.

### Recording

The forwarding loops call `stats.record_rx(len)` / `stats.record_tx(len)` on every packet — just `AtomicU64::fetch_add`, no locking, no contention. Drops are counted when `send_datagram` fails or the mpsc channel is full.

### Periodic logging

A background task logs a one-liner every 30 seconds with **delta** counters (reset each interval) so you see current throughput:

```
INFO  stats: rx=142 tx=138 bytes_rx=85.2KB bytes_tx=72.1KB drops=0 (30s)
```

### Shutdown summary

When the cancellation token fires, the stats task prints cumulative totals before exiting:

```
INFO  session: duration=4m12s total_rx=1847 total_tx=1821 total_bytes=1.1MB
```

`start_time: Instant` tracks session duration.

---

## 3. Reconnect Loop

### Structural change to `main()`

Currently, TUN creation and iroh connection are interleaved. They need to be separated:

1. `main()` creates the TUN device **once**, outside any loop
2. Enters a loop: connect → forward → (disconnect) → retry
3. On shutdown signal, break out of the loop

### Backoff strategy

Exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s (capped at 30s). Reset to 1s on successful connection.

The backoff sleep uses `tokio::select!` with the cancellation token so ctrl+c during a retry exits immediately instead of waiting out the sleep.

### Creator vs joiner

- **Joiner**: on disconnect, retry `connect_to_peer()` with the same EndpointId
- **Creator**: on disconnect, go back to `accept_connection()` and wait for the peer to reconnect

### Forwarding loop changes

`forward::run()` returns a `Result` instead of running forever. The caller (reconnect loop) inspects the error to decide whether to retry or exit:

- Connection closed / reset → retry
- Shutdown signal → exit

---

## 4. Root Privilege Check

### Change to `main()`

First thing, before loading identity or binding iroh:

```rust
fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("pitopi requires root privileges to create TUN devices. Run with sudo.");
        std::process::exit(1);
    }
}
```

Uses `libc::geteuid()` — works on both macOS and Linux. `libc` is already a transitive dependency (no new deps).

Replaces the current behavior where forgetting sudo produces an opaque TUN creation error.

---

## New dependencies

| Crate | Purpose |
|-------|---------|
| `tokio-util` | `CancellationToken` for shutdown signaling |
| `libc` | `geteuid()` for root check (already transitive, adding as direct) |

## Files changed

| File | Change |
|------|--------|
| `Cargo.toml` | Add `tokio-util`, `libc` |
| `src/main.rs` | Root check, create TUN outside loop, reconnect loop, pass cancellation token |
| `src/shutdown.rs` | New — signal handler + cancellation token setup |
| `src/stats.rs` | New — atomic counters, periodic logger, session summary |
| `src/forward.rs` | Accept `CancellationToken` + `Arc<Stats>`, return `Result` on disconnect |
| `src/tun.rs` | No changes (TUN creation logic stays the same) |
| `src/transport.rs` | No changes |
| `src/identity.rs` | No changes |
