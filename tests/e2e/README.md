# Rayfish end-to-end tests

Each scenario provisions real Scaleway instances, deploys `ray` over SSH, drives a
flow end to end, and prints a `PASS`/`FAIL` line per check (exit non-zero on any
failure). The shared SSH/deploy/reset/assert plumbing lives in
[`../lib/`](../lib) and is sourced by every scenario.

## Scenarios

| Dir | Hosts | What it proves |
|-----|-------|----------------|
| [`device-cert/`](device-cert) | 3 | A third peer reaches a user identity backed by two paired devices (`ray pair` + DeviceCert), over a closed (invite-gated) network. |
| [`connect/`](connect) | 2 | The `ray connect` direct 2-peer friend-request flow over the public pkarr DHT — request, approve, `[direct]` network, ping + `ray send`, per-network firewall, offline negative case. |
| [`firewall/`](firewall) | 3 | The coordinator suggested-firewall pipeline (`suggest` → `pending`/`accept`, `auto-accept`, additive whitelist vs blacklist) and the per-packet rule matrix (UDP, port ranges, same-selector replace, `--network` scoping) over a real TUN. |
| [`closed-net/`](closed-net) | 3 | Closed-net admission + lifecycle commands: live approval (`requests`/`accept`/`deny`), co-coordinator (`admin add`) gatekeeper resilience with a reusable key, `ray hostname` + magic-DNS, `ray leave`/`nuke`, and a `ray apply` smoke. |
| [`apply/`](apply) | 3 | Declarative `ray apply` deploy end to end: create-if-absent + membership-gap diff, `--invite-missing`, `ray identityof`, alias/group expansion (`--dry-run`), real suggestion publish + data-plane enforcement, and `--prune`. |

Everything runs through one dispatcher, [`../e2e.sh`](../e2e.sh):

```bash
tests/e2e.sh <scenario>             # provision (if needed) + deploy + drive + assert
tests/e2e.sh <scenario> provision   # just spin up instances -> <dir>/.servers
tests/e2e.sh <scenario> teardown    # destroy the instances (manual)
```

where `<scenario>` is `device-cert`, `connect`, `firewall`, `closed-net`,
`apply`, `dns`, or `bench` (run `tests/e2e.sh` with no scenario for usage). The per-scenario run steps live in `<dir>/run.sh`
(still runnable directly once `.servers` exists); the fleet definitions and the
provision/teardown/assert bodies are shared in [`../lib/`](../lib).

The throughput/latency benchmark (`tests/e2e.sh bench`) is a sibling suite
under [`../bench/`](../bench) (same shared `tests/lib/`).

## Prerequisites (all scenarios)

- `scw` authenticated (`scw account project list` should work) and `jq` installed.
- Docker running (used by `cross` for the x86_64-linux build behind `just deploy`),
  plus `just`.
- Your `~/.ssh/id_ed25519` public key registered in the Scaleway account so the
  instances accept `root@<ip>`. Override the key with `SSH_KEY=…`.

## Common environment overrides

| Var | Default | Meaning |
|-----|---------|---------|
| `ZONE` | `fr-par-1` | Scaleway zone (provision) |
| `TYPE` | `DEV1-S` | instance type (provision) |
| `IMAGE` | `ubuntu_jammy` | instance image label (provision) |
| `SSH_KEY` | `~/.ssh/id_ed25519` | private key for `root@<ip>` |
| `KEEP_STATE` | `0` | `1` skips the per-run rayfish state wipe |
