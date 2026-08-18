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
| **IPv6-only client** | srv-b restarts in IPv6-only mode and uses the same exit (see below) |

## The IPv6-only step

Step 9 puts srv-b in the mode it runs in when it shares a host with Tailscale,
and asserts the tunnel takes IPv6 **and only IPv6**: the v6 default goes into
table 29793, no v4 rule is installed at all, `curl -6` reports srv-a's address
and `curl -4` still reports srv-b's own. That last one is a deliberate
non-property, not an oversight, so it is checked rather than assumed.

It also stands in for the co-resident VPN the mode exists for, by putting a
route in table 52 behind a rule at priority 5250 before turning the tunnel on,
and asserting both that it was mirrored into the tunnel table and that a rule at
priority 98 sends that destination there. Without the mirror our catch-all rule
at priority 102 wins and the foreign prefix is never reached; without the rule,
the two rules at 99 and 100 look up `main`, which is exactly where a
policy-routing VPN does not keep its prefixes, so traffic sourced from its
address (or carrying our conntrack mark) misses and takes the physical default.
Either way that VPN goes dark the moment `exit-node use` runs.

DNS is asserted only as far as the claim goes: both a non-mesh name and a `.ray`
name must still resolve. Where the non-mesh query *went* is deliberately not
asserted, because on a split-DNS backend it leaves over the host's own IPv4 by
design in this mode, which is a documented gap rather than a regression.

Whether srv-a can serve such a client depends on srv-a having IPv6 egress, which
not every instance has. Both branches are asserted: with a v6 uplink the tunnel
must work, without one the selection must be **refused by name** rather than
installed and left to black-hole.

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
