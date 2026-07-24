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
| **Inbound connections** | our SSH session to srv-b's **public IP** keeps working under the full tunnel (see below) |
| Deny path | srv-c selects the same exit but is not on the allow-list: it gets no internet through srv-a **and** does not silently leak out its own uplink |
| Teardown | `exit-node none` reverts egress and removes the ip rules; `ray down` removes the nft table and restores the sysctls (the host must not stay a router) |

## The inbound-connection assertion

A default route into the TUN captures *everything* that has no more specific
route, including the replies of connections that arrived from outside the tunnel.
So sshd's answer to your laptop egresses via the exit node, gets masqueraded to
*its* address, and your client drops a reply from a host it never contacted: a
headless box locks itself out the instant you run `exit-node use`. The client's
conntrack-mark rules (`rayfish_exit_client`) are what prevent this, and step 4
asserts it directly by running an ordinary `ssh` command while the tunnel is up.

Every step that turns a tunnel on still arms a self-revert failsafe on the host
first (`sleep N; exit-node none; ray down; ray up`, cancelled on success). One bad
rule is the difference between a working tunnel and an instance that has cut off
its own SSH, and a test must never be able to strand a machine.
