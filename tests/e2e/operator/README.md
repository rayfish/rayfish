# `operator` e2e scenario

Two hosts on one closed network `operator` (coordinator `srv-a`, member
`srv-b`). `srv-a` carries two unprivileged local users; `srv-b` is the far end
that makes an operator's change observable on the wire.

The daemon runs as root and its IPC socket is world-connectable on purpose:
authority is a per-request `SO_PEERCRED` check in `Daemon::check_authorized`,
not the socket's file mode. Nothing below the process boundary can test that
split, so this scenario supplies what it needs: a second real local user, a
real socket, a real root daemon.

## What it proves

| Step | Coverage |
|------|----------|
| 2 | The daemon's config tree is unreadable to an unprivileged user, so anything they report has to have come over IPC rather than off disk. |
| 3 | **Reads are open to any local user**: `status`, `firewall show`, `config get`, `connections`. The status a non-root user gets carries the daemon's roster, not an empty local view. A read creates **no config tree of its own** (`config_dir_for_read`, not `config_dir`) and leaves `/etc/rayfish` untouched. |
| 4 | **Mutations are denied**: `config set`, `firewall add` and `down` all refuse, exit non-zero, and name the fix (`sudo ray set-operator`). The setting is unchanged afterwards and the node is still up. |
| 5 | **A non-root user cannot grant itself operator** — the `SetOperator` arm is checked before the operator arm, so this holds even for a user who is already the operator (step 8). |
| 6-7 | After `sudo ray set-operator alice`, alice's `config set` sticks in the daemon's config, and a firewall rule she installs **reaches the packet path**: a port closed to srv-b before her rule is open to srv-b after it. |
| 8 | The grant is **one UID**: mallory is still denied, still allowed to read, and alice cannot hand the grant on. |
| 9 | The grant is persisted, not in-memory: it survives `systemctl restart rayfish`. |
| 10 | `set-operator` on an unknown user fails cleanly and leaves the existing operator alone. |
| 11 | `ray report` is an open read, and the bundle it hands an unprivileged requester is `0600` and owned by them — it packs the root daemon's logs, so a widened mode would publish them to every other local user. |

The users are made with `useradd` and driven with `su -s /bin/bash <user> -c`
(the node image has no sudo, and root needs no password). Assertions check the
refusal *wording* as well as the exit status: a denial that does not name
`ray set-operator` leaves the user with no way forward, which is the failure
this feature exists to avoid.

## Run

```bash
tests/e2e.sh operator            # provision (if needed) + deploy + drive + assert
tests/e2e.sh operator teardown   # destroy the instances
```

Runs unchanged on both backends. See [`../README.md`](../README.md) for
prerequisites and environment overrides.
