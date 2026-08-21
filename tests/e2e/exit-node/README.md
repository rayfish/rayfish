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
| Gateway | `exit-node allow` turns on IPv6 forwarding and installs the `rayfish_exit` nftables masquerade table, and leaves IPv4 forwarding and `100.64.0.0/10` alone |
| Discovery | the offer rides the signed roster: clients see it in `exit-node status` and `ray status` shows the `(exit)` badge |
| Egress | with `exit-node use`, srv-b's public **IPv6** as an external service sees it becomes srv-a's, while its IPv4 is untouched |
| **Loop prevention** | the mesh survives the full tunnel. This is what the SO_MARK fork chain exists for: with `::/0` in the TUN, iroh's own underlay UDP must still escape (SO_MARK + the fwmark `ip rule`) or the tunnel deadlocks and *everything* dies |
| **Inbound connections** | our SSH session to srv-b's **public IP** keeps working under the full tunnel (see below) |
| **Co-resident VPN** | another VPN's routes survive the tunnel (see below) |
| Deny path | srv-c selects the same exit but is not on the allow-list: it gets no internet through srv-a **and** does not silently leak out its own uplink |
| Teardown | `exit-node none` reverts egress and removes the ip rules; `ray down` removes the nft table and restores the sysctls (the host must not stay a router) |

## One family, and the non-properties that go with it

The overlay carries no IPv4, so a tunnel takes IPv6 **and only IPv6**: the v6
default goes into table 29793, no v4 rule is installed at all, `curl -6` reports
srv-a's address and `curl -4` still reports srv-b's own. That last one is a
deliberate non-property, not an oversight, so it is checked rather than assumed —
claiming the host's IPv4 would source transit from a range the daemon leaves
unrouted and take IPv4 away from whatever else shares the box.

The gateway has the same two halves. Step 2 asserts IPv6 forwarding and the
masquerade table are live, *and* that `ip_forward` is exactly where the run found
it and no `ip saddr` rule was installed: a v4 masquerade rule is scoped to traffic
leaving the uplink, so with no mesh IPv4 left the only thing it could still catch
is a co-resident VPN's.

## The co-resident VPN

Step 4 stands in for one before turning the tunnel on, by putting a route in
table 52 behind a rule at priority 5250 (Tailscale's range and preference band).
It then asserts both that the route was mirrored into the tunnel table and that a
rule at priority 98 sends that destination there.

Without the mirror our catch-all at priority 102 wins and the foreign prefix is
never reached. Without the rule, the two rules at 99 and 100 look up `main`, which
is exactly where a policy-routing VPN does *not* keep its prefixes, so traffic
sourced from its address (or carrying our conntrack mark) misses and takes the
physical default. Either way that VPN goes dark the moment `exit-node use` runs.
`clean_kernel` removes the stand-in, so a later run cannot pass on state it never
installed itself.

DNS is asserted only as far as the claim goes: both a non-mesh name and a `.ray`
name must still resolve. Where the non-mesh query *went* is deliberately not
asserted, because on a split-DNS backend it leaves over the host's own IPv4 by
design, which is a documented gap rather than a regression.

## When srv-a has no IPv6 uplink

Whether srv-a can serve a client at all is a fact about srv-a's uplink, and not
every instance has IPv6 egress. Both branches are asserted rather than one being
skipped: with a v6 uplink the tunnel must work; without one srv-a must not appear
in `available_v6`, and the selection must be **refused by name** ("cannot carry
IPv6") and exit non-zero, rather than installed and left to black-hole. A gateway
that cannot carry IPv6 can now carry nothing at all, so that refusal is the whole
of the feature on such a fleet.

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
