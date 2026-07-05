# Unpair (device-cert revocation) 3-peer e2e test

End-to-end test that `ray unpair` revokes a paired device mesh-wide, enforced
verifier-side via a **cert-generation floor**. Builds on the device-cert
topology: a user identity backed by two physical devices, then the primary
unpairs the second (bumps its generation, publishes the new floor, drops the
device).

## Topology

| Host  | Identity | Role |
|-------|----------|------|
| srv-a | U        | primary device, coordinator of the closed network |
| srv-b | U (DeviceCert) | paired into A's identity via `ray pair` |
| srv-c | V        | independent third peer, also a member |

## What it proves

1. `ray pair list` on the primary shows the paired secondary.
2. `ray unpair srv-b` bumps srv-a's cert generation and publishes the new
   `_rayfish_certgen` floor, removes srv-b from the roster, and severs it.
3. The floor propagates: srv-c (a different user) can no longer reach srv-b after
   its poller/reconverge picks up the floor and prunes it.
4. srv-b cannot re-join — its cert is below the floor at admission.
5. A secondary is refused (`ray unpair` is primary-only).
6. Best-effort: srv-b's on-disk `device_cert` is wiped (informational, since the
   authoritative revocation is the signed floor, not the wipe).

Not covered by this 3-host topology: the **keeper-refresh** path — a device you
*keep* being auto-re-issued a fresh cert at the new generation (pushed over the
mesh, or refreshed on reconnect if it was offline during the bump). Verifying it
needs a second device paired into U (add an `srv-d` host).

## Prerequisites & run

Same as the sibling e2e tests (Scaleway infra via `provision.sh`, `scw`/`jq`,
Docker for the cross build). Provision with `./provision.sh`, then `./run.sh`.
Reads `.servers`; does not modify infra. Re-runnable.
