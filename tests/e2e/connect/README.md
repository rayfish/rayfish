# `ray connect` direct-connection e2e

End-to-end test for the **direct 2-peer connection** flow (`ray connect`) over two
real Scaleway hosts and the public pkarr DHT. Companion to the 3-peer device-cert
test in `tests/e2e/device-cert/`; shared plumbing lives in `tests/lib/`.

## Topology

```
srv-a  identity U   initiator   (ray connect <B-contact-id>)
srv-b  identity V   recipient   (ray connections approve <id>)
```

## What it proves

1. Both nodes publish a **contact id** (`ray contact id`), also shown in `ray status`.
2. `ray connect <contact-id>` resolves the id via pkarr, dials, and queues as **pending**.
3. The recipient sees it in `ray connections` and `ray connections approve <id>`.
4. A real 2-peer network forms, shown as role **`[direct]`** with its room id hidden.
5. The two peers get distinct VPN IPs and reach each other by **ICMP ping** (both ways).
6. `ray send` / `ray files accept` round-trips a file both ways (sha256 verified).
7. The **per-device firewall is enforced and network-scoped** on the direct net:
   a `--network <net> in deny icmp` rule breaks ping (100% loss), removing it recovers it.
8. Negative: connecting to an offline/rotated contact errors cleanly (no hang).

## Usage

```bash
# Requires: scw (authenticated), jq, just, cross + docker, an SSH key.
tests/e2e.sh connect             # provision (if needed), cross-build, deploy, drive, assert
tests/e2e.sh connect provision   # just spin up 2 DEV1-S instances -> .servers
tests/e2e.sh connect teardown    # destroy the instances when done
```

`tests/e2e.sh` is the shared dispatcher (the scenario steps live in `run.sh`,
which you can also invoke directly once `.servers` exists). Env knobs: `ZONE`,
`TYPE`, `IMAGE` (provision); `SSH_KEY`, `KEEP_STATE=1` (run, skips the per-run
state reset). The run is re-runnable — it resets rayfish state on each host
(fresh identities, contact ids, and a fresh direct network) unless
`KEEP_STATE=1`.
