# `dns` e2e scenario

Two hosts on one closed network `dns` (coordinator `srv-a`, member `srv-b`),
exercising the TUN-intercepted Magic DNS resolver end to end on real Linux —
the parts unit tests can't reach: the system resolver actually routing `.ray`
to the in-daemon resolver, coexistence with port 53, and the `resolv.conf`
takeover/restore lifecycle.

## What it proves

| Step | Coverage |
|------|----------|
| 2 | **Magic DNS works end to end**: after join, each host's *system* resolver (`getent`/libc — the same path `ping` uses) resolves the peer's `<host>.<net>.ray` to its mesh IPv6. This only passes if Magic DNS started (no `:53` bind failure) and the OS was pointed at the magic IP. |
| 3 | Resolution drives **real reachability** — ping by `.ray` name (DNS + data plane). |
| 4 | The resolver **binds no host `:53` socket** — it answers via the magic IP (`200::53`) routed through the TUN, so it coexists with any existing `:53` resolver (AdGuard/Pi-hole/dnsmasq — the umbrelOS case) by construction. |
| 5 | **Non-`.ray` names still resolve** while the VPN is up — split-DNS passthrough on hosts with a split-DNS backend, or the resolver forwarding to the captured upstream in direct mode. The feature must not black-hole public DNS. |
| 6 | *(conditional)* On a host that fell to the **direct `/etc/resolv.conf` takeover** (no split-DNS backend), `resolv.conf` carries the magic IP under the `# Added by rayfish` marker. Skipped cleanly on split-DNS hosts. |
| 7 | **`ray down` reverts system DNS**: `.ray` names stop resolving; in direct mode the original `resolv.conf` is restored (marker gone). |

DNS is probed through the system resolver (`getent ahostsv6` for `.ray` names,
which answer AAAA only; `ahostsv4` for the public names the forwarding checks
use), so it tests the
whole chain (OS config → magic IP → TUN interception → in-daemon resolver), not
just the resolver in isolation. Roster→DNS sync and the `dns_config` apply take
a moment, so the assertions poll (`retry_until`).

## Run

```bash
tests/e2e.sh dns            # provision (if needed) + deploy + drive + assert
tests/e2e.sh dns teardown   # destroy the instances
```

See [`../README.md`](../README.md) for prerequisites and environment overrides.

## Note on the umbrelOS case

Stock DigitalOcean Ubuntu runs systemd-resolved, so the split-DNS path is usually
taken and step 6 is skipped. The hardest real-world environment (NetworkManager
in default mode **with** a `:53` resolver like AdGuard, which forces the direct
takeover) is covered by step 4's coexistence guarantee plus the conditional
direct-mode checks; full reproduction of that environment is a manual test on an
umbrel-like host.
