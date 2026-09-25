# `v4bridge` e2e scenario

Two hosts on one closed network `v4br` (coordinator `srv-a`, member `srv-b`),
exercising the IPv4-only listener bridge (`src/v4bridge.rs`) end to end on real
Linux. The mesh is IPv6-only, so a service bound to `0.0.0.0` has a socket the
kernel will never hand an IPv6 packet: it needs a real TUN, a real host listener
table and a real peer to test at all.

## What it proves

| Step | Coverage |
|------|----------|
| 2 | The daemon **holds the mesh address** for a port whose only listener is on `0.0.0.0`, within a rescan of that service starting. |
| 3 | **The firewall is upstream of the bridge**: with the listener demonstrably up, a probe against a deny-by-default port still reads CLOSED. The bridge is not a way around `ray firewall`. |
| 4 | **The headline**: once the port is allowed, `srv-a` reaches an IPv4-only service at `srv-b`'s mesh address. This is what did not work before. |
| 5 | The bridge **carries a payload**, not just the handshake: HTTP 200 with a body, by mesh IP and by `.ray` name (Magic DNS + bridge together). |
| 6 | A **`127.0.0.1` service is never bridged**, even with its port allowed. Binding loopback is a choice to stay local, and the allow rule removes the only other reason the probe could fail. |
| 7 | **No flap across rescans.** A bridged port is itself an IPv6 listener on the mesh address; a scan that does not recognise its own socket unbinds and rebinds it every cycle. That shipped once and left every bridged port answering half the time, which a single probe passes straight through. |
| 8-9 | The bridge **follows the service**: stop it and the port is released, start it and the port comes back. |
| 10 | **`ray config set v4-bridge off`/`on`** takes effect on a live daemon, no restart. |
| 11 | The bridge **lives and dies with the data plane**: `ray down` releases the port (it binds an address that goes down with the TUN), `ray up` restores it. |
| 12 | **The kernel reports the listener, a timer does not find it.** Where `sock:inet_sock_set_state` is readable the timer is only a 300s backstop, so taking a new port within seconds can have come from nothing else. On a host without tracefs the same step asserts the timer fallback instead, and says so rather than reporting the event path as covered. |

Reachability is probed with the shared `fw_allows`/`fw_denies` helpers, so a
probe is a real TCP handshake over the TUN. "Is it bridged" is answered
separately, from `ss` on the far host, because the two can disagree: the
firewall closes reachability with the listener still up, and telling those apart
is what makes steps 3 and 6 mean anything.

The scenario binds its own listeners rather than using `start_tcp_listener`,
which binds `::` on purpose so the firewall scenarios do not depend on this
feature.

## Run

```bash
./tests/e2e.sh v4bridge                      # DigitalOcean droplets (default)
E2E_BACKEND=docker ./tests/e2e.sh v4bridge   # local containers
./tests/e2e.sh v4bridge teardown
```

Ports `8400` (wildcard), `8401` (loopback) and `8402` (wildcard, bound late to
time the pickup) on `srv-b`. Allow ~3 minutes of run time after provisioning:
the waits are ceilings sized for a host with no listen events, and step 7
deliberately sits through two of them.

**Backend note.** Step 12's event path runs on droplets and not under docker: a
privileged container has `/sys/kernel/tracing` as an empty directory with
tracefs not mounted, so the daemon finds no tracepoint and stays on its timer.
The host's tracefs is deliberately not mounted in, since tracefs is not
namespaced and both nodes would then contend for one instance directory.
