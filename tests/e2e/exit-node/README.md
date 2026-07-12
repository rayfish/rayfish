# exit-node e2e

Three real Linux hosts. `srv-a` is the exit node (internet gateway), `srv-b` is a
client allowed to use it, `srv-c` is a client that is **not**.

```sh
./tests/e2e.sh exit-node            # provision (if needed) + run
./tests/e2e.sh exit-node teardown   # destroy the instances
```

## What it proves

The exit-node data path is the one part of rayfish that lives in the kernel
(forwarding, NAT, policy routing), so it is invisible to unit tests. This
scenario is the only thing that exercises it:

| | Assertion |
|---|---|
| Gateway | `exit-node allow` turns on the forwarding sysctls and installs the `rayfish_exit` nftables masquerade table |
| Discovery | the offer rides the signed roster: clients see it in `exit-node status` and `ray status` shows the `(exit)` badge |
| Egress | with `exit-node use`, srv-b's public IP **as an external service sees it** becomes srv-a's (IPv4, plus IPv6 where the instances have it) |
| **Loop prevention** | the mesh survives the full tunnel. This is what the SO_MARK fork chain exists for: with `0.0.0.0/0` in the TUN, iroh's own underlay UDP must still escape (SO_MARK + the fwmark `ip rule`) or the tunnel deadlocks and *everything* dies |
| Deny path | srv-c selects the same exit but is not on the allow-list: it gets no internet through srv-a **and** does not silently leak out its own uplink |
| Teardown | `exit-node none` reverts egress and removes the ip rules; `ray down` removes the nft table and restores the sysctls (the host must not stay a router) |

## Why the client phase is a detached script

A full tunnel routes the client's replies to *our* public IP through the exit
node, where they get NATed — so the source address changes and **our SSH session
to the client dies** the moment `exit-node use` lands. That is standard
full-tunnel VPN behavior (SSH over the *mesh* IP keeps working), not a bug.

So the client phase can't be a plain `ssh <cmd>`: it would hang. Instead the
orchestrator writes a probe script to the host and launches it detached. The
script runs the probes, writes results to `/tmp/exit-*.out`, then reverts, which
brings SSH back; the orchestrator polls for `/tmp/exit-probe.done` and reads the
results. A failsafe (`sleep 180; exit-node none; ray down; ray up`) fires
independently, so a crashed probe can never strand an instance.
