# `apply` e2e scenario

Three hosts driving `ray apply` end to end against a live daemon: coordinator +
apply driver `srv-a`, members `srv-b` and `srv-c`, on a closed network `infra`.
Where the `closed-net` scenario only smoke-tests `--example`/`--dry-run` (no
mutation), this one reconciles real state: it creates the network, mints the
gap's invites, and proves the alias/group expansion materializes into rules that
gate real packets.

## What it proves

| Step | Coverage |
|------|----------|
| 1 | **Create + diff**: apply mints the missing closed `infra` (never joins) and reports the membership gap as `ray invite … --hostname srv-b/srv-c` lines. |
| 2 | **`--invite-missing`**: those invites are minted; `srv-b`/`srv-c` join under their bound hostnames (`--auto-accept-firewall`). Re-apply reports the net already active. |
| 3 | **`ray identityof`**: prints a joined host's identity (and `--json` `paired=false`); errors for a host that hasn't joined. |
| 4 | **Aliases + groups (dry-run)**: a spec aliases `srv-b` as a user and groups it with the literal `srv-c`, referenced as a firewall peer; `--dry-run` shows the group resolving to `srv-b` + `srv-c`, with no `bob`/`team` sugar left behind. |
| 5 | **Real apply publishes the expansion**: the coordinator materializes its own inbound `tcp:22` allow for each resolved team member. |
| 6 | **Data plane**: the resolved allow opens `tcp:22` on `srv-a` for `srv-b` over the TUN, while an un-allowed port stays denied. |
| 7 | **`--prune`**: an out-of-band suggestion (subject `srv-a`) is dropped because the spec doesn't name it, while the spec's own rules survive. |

## Run

```bash
tests/e2e.sh apply            # provision (if needed) + deploy + drive + assert
tests/e2e.sh apply teardown   # destroy the instances
```

See [`../README.md`](../README.md) for prerequisites and environment overrides.
