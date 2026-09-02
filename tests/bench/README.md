# Rayfish throughput / latency benchmark

Spins up **2 droplets in the same region** and measures, for both
directions, the cost rayfish adds on top of the raw link:

- **latency**: `ping` mean RTT, direct (public IP) vs rayfish (`200::/7` TUN)
- **throughput** — `iperf3` TCP, direct vs rayfish, forward (`tx`) and reverse (`rx`)

The two peers join an **open** network (`ray create --open` / `ray join <room>`),
so no invite handshake is needed.

## Prerequisites

Same as `tests/e2e/device-cert`: an authenticated `doctl` CLI, an SSH key on the
DigitalOcean account, Docker running (for `cross`), plus `jq` and
`just`. Shared SSH/deploy plumbing lives in `tests/lib/`.

## Usage

```bash
tests/e2e.sh bench            # provision (if needed) + deploy ray + iperf3, benchmark, print table
tests/e2e.sh bench provision  # just create 2 droplets -> tests/bench/.servers
tests/e2e.sh bench teardown   # destroy the instances when done
```

`tests/e2e.sh` is the shared dispatcher (the benchmark steps live in `run.sh`
here, which you can also invoke directly once `.servers` exists). Overrides:
`REGION`, `SIZE`, `IMAGE` (provision); `DURATION` (seconds/iperf run), `SSH_KEY`,
`KEEP_STATE=1` (skip the state wipe and re-use an existing network) for the run.
Results are printed and saved to `results/<stamp>.md` (+ `.raw` TSV).

Each run also performs a 100-packet-per-second latency profile and reports
mean, p50, p95, p99, maximum, and loss for the direct and Rayfish paths. This
is intentionally separate from the low-rate mean RTT: queueing bugs can leave
the mean looking reasonable while causing large tail spikes. Set `PING_COUNT`
and `PING_INTERVAL` to adjust it (defaults: `300`, `0.01` seconds).

## Caveats

`s-1vcpu-1gb` has a single shared vCPU, so single-stream TCP is **CPU-bound**:
rayfish's userspace TUN + iroh QUIC datagram encryption is the bottleneck, and
absolute numbers are noisy run-to-run. Use a larger `SIZE` (e.g. `s-2vcpu-4gb`,
or a CPU-optimized `c-2`) for steadier throughput; the *direct-vs-rayfish ratio*
is the signal,
not the absolute Mbit/s. rayfish also runs an MTU of 1280 (the IPv6 minimum, per
WireGuard/Tailscale), which caps per-packet payload below the link's native MTU.
