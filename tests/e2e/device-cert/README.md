# Device-cert 3-peer e2e test

End-to-end test that a third peer can communicate, over a rayfish **closed**
network (admission gated by hostname-bound invites), with a user identity backed
by **two** physical devices — an original device and a second device paired into
the same identity via a `DeviceCert`.

Design: `docs/superpowers/specs/2026-06-24-device-cert-e2e-design.md`.

## Topology

| Host  | Identity | Role |
|-------|----------|------|
| srv-a | U        | primary device, coordinator of the closed network |
| srv-b | U (DeviceCert) | paired into A's identity via `ray pair` |
| srv-c | V        | independent third peer |

srv-a and srv-b resolve to the same user identity, so they share one derived VPN
IP (the multi-homed-peer model). The test pings and `ray send`s between srv-c and
**both** physical devices of identity U.

## Prerequisites

- `scw` authenticated (`scw account project list` should work).
- `jq` installed.
- Docker running (used by `cross` for the x86_64-linux build behind `just deploy`).
- Your `~/.ssh/id_ed25519` public key registered in the Scaleway account (so the
  instances accept `root@<ip>`). Override the key with `SSH_KEY=...`.

## Run

```bash
tests/e2e.sh device-cert            # provision (if needed) + deploy + pair + create/join + assert
tests/e2e.sh device-cert provision  # just create 3 DEV1-S Ubuntu instances in fr-par-1
tests/e2e.sh device-cert teardown   # destroy the instances when done (manual)
```

`tests/e2e.sh` is the shared dispatcher; the scenario-specific steps live in
`run.sh` here (sourcing the SSH/deploy/assert plumbing from `tests/lib/`). You
can also invoke `tests/e2e/device-cert/run.sh` directly once `.servers` exists.

- `provision` writes `tests/e2e/device-cert/.servers` (gitignored:
  `id ip label zone`). It is a no-op while that file exists; delete it to
  provision a fresh set.
- The run is fully re-runnable against the same `.servers`: it **resets each
  host's rayfish state** (stops the daemon, wipes `/root/.config/rayfish`) at the
  start of every run, so you get a clean slate from scratch each time — fresh
  identities, no leftover `e2e` network. Just run `tests/e2e.sh device-cert`
  again. Pass `KEEP_STATE=1 tests/e2e.sh device-cert` to skip the reset
  (re-run against the existing network). It prints a `PASS`/`FAIL` line per check
  and exits non-zero if any failed.

> **Note on the device-cert restart.** `ray pair` stores the cert to disk but
> doesn't refresh the running daemon's in-memory copy, so the script restarts
> srv-b's daemon after pairing and before joining. This is a workaround for a
> real product bug (see "Findings" below); without the restart srv-b would join
> as an independent identity rather than as user U.
- Servers are **left running** after the run so you can inspect them
  (`ssh root@<ip> ray status`). `tests/e2e.sh device-cert teardown` terminates
  them and removes `.servers`.

## Environment overrides

| Var      | Default      | Meaning                         |
|----------|--------------|---------------------------------|
| `ZONE`   | `fr-par-1`   | Scaleway zone                   |
| `TYPE`   | `DEV1-S`     | instance type                   |
| `IMAGE`  | `ubuntu_jammy` | instance image label          |
| `SSH_KEY`| `~/.ssh/id_ed25519` | private key for `root@<ip>` |

## What it asserts

1. `ray pair` binds srv-b's transport key to srv-a's user identity.
2. All three peers get **distinct per-device IPs** (rayfish derives the IP from
   the per-device `EndpointId`, not the user identity — so paired devices share a
   *user identity* but are addressed separately, Tailscale-style).
3. The coordinator resolves srv-b's transport key to srv-a's **user identity**
   (shown as a `user:<prefix>` tag) — i.e. the device cert is recognized at the
   network level, unifying srv-a and srv-b under one user.
4. Bidirectional `ping` over the TUN: srv-c↔srv-a and srv-c↔srv-b (C reaches
   both physical devices of identity U).
5. `ray send` round-trips (sha256-verified) srv-c→srv-a, srv-c→srv-b, and
   srv-a→srv-c.

## Findings (from the first runs)

- **Fixed — fresh-daemon ALPN gap (`src/daemon.rs`):** at startup the endpoint
  only advertised the per-network + blobs ALPNs; `PAIR_ALPN`/`FILES_ALPN` were
  added later by `refresh_alpns()` (on create/join). So a freshly-started daemon
  with no network rejected `ray pair`/`ray send` with "peer doesn't support any
  known protocol". Fix: advertise both ALPNs from boot.
- **Open — pairing doesn't refresh the in-memory device cert:** the
  `PairWithDevice` handler writes the cert to disk but never updates the running
  daemon's `self.device_cert`, so a `ray pair` followed by `ray join` in the same
  session joins **without** the cert (coordinator records an independent
  identity). Restarting the daemon reloads the cert and fixes it (what this
  script does). Proper fix: update the in-memory cert in the pair handler.
