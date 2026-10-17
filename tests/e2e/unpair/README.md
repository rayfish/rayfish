# Unpair (device-cert revocation) 3-peer e2e test

End-to-end test that `ray unpair` revokes a paired device mesh-wide. Revocation
is per device: the primary saves the device key in its `revoked_devices` and
adds it to the **nullifier set** of every network it coordinates, which rides
the network-key-signed blob, so every verifier rejects that device's cert.
Builds on the device-cert topology: a user identity backed by two physical
devices, then the primary unpairs the second.

## Topology

| Host  | Identity | Role |
|-------|----------|------|
| srv-a | U        | primary device, coordinator of the closed network |
| srv-b | U (DeviceCert) | paired into A's identity via `ray pair` |
| srv-c | V        | independent third peer, also a member |

## What it proves

1. `ray pair list` on the primary shows the paired secondary.
2. `ray unpair srv-b` saves srv-b's key as revoked, nullifies it in the
   network's signed blob, removes srv-b from the roster, and severs it.
3. The nullifier propagates: srv-c (a different user) can no longer reach srv-b
   once its poller/reconverge applies the republished blob and prunes it.
4. srv-b cannot re-join: the coordinator rejects its nullified cert at admission.
5. A secondary is refused (`ray unpair` is primary-only).
6. srv-b's on-disk `device_cert` is wiped. srv-a tells srv-b, dialing it, and
   repeats until srv-b confirms its cleanup; this run checks once, so a notice
   still in flight is reported as a note, not a failure. The authoritative
   revocation is the nullifier, not the wipe.

Not covered by this 3-host topology: a second device paired into U, which
per-device revocation leaves untouched. Verifying that it keeps working after
srv-b is unpaired needs another host (add an `srv-d`).

## Prerequisites & run

Same as the sibling e2e tests (droplets via `provision.sh`, `doctl`/`jq`,
Docker for the cross build). Provision with `./provision.sh`, then `./run.sh`.
Reads `.servers`; does not modify infra. Re-runnable.
