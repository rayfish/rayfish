# coordinators e2e

One closed network with three coordinators, under edits, restarts, a lagging
coordinator and racing joins. Five hosts; shared plumbing lives in `tests/lib/`.

## Topology

```
srv-a  creates `coord`, coordinator (renames itself srv-aa in check 3)
srv-b  member promoted with `ray admin add`, coordinator
srv-c  member promoted with `ray admin add`, coordinator (renames itself srv-cc)
srv-d  member: watches for rollbacks, restarted in checks 3 and 4
srv-e  member admitted and kicked by different coordinators, then the joiner
       of checks 5 and 6
```

## What it proves

1. **Edits on each coordinator converge.** srv-a admits srv-e, srv-b kicks it,
   srv-c admits it again, srv-c renames itself. Each edit has to reach every
   coordinator and member within `COORD_EDIT_WAIT` (120 s, under one 150 s
   renewal). The time per host is printed.
2. **A restarted creator polls.** srv-e is cut off, srv-a restarts, and srv-b
   kicks srv-e. A coordinator ignores `MemberSync`, nothing srv-e says can reach
   srv-a, and srv-a's first renewal is at least 150 s after it started, so
   dropping srv-e before then is the group poller's doing.
3. **Lagging coordinator.** srv-b (whose last edit means it holds a published
   record for its roster) is cut off with only srv-d allowed. srv-a renames
   itself. Then srv-a and srv-c are cut off and srv-d restarts, so srv-b is the
   only coordinator it can reach. For 30 s srv-d must keep `srv-aa`, never
   `srv-a`, and its saved `last_record_timestamp` must not go down. A logged
   replay refusal on srv-d shows srv-b really handed it the older record (a
   `SKIP` says when that did not happen). Once uncut, srv-b catches up and
   srv-d still holds the newer roster. srv-e, back online, leaves on the kick
   from check 2.
4. **A restarted member keeps its network.** srv-d after `systemctl restart`,
   `kill -9` and `ray down`/`ray up`: the network is in config and in status
   with the full roster, and the saved floor is present and never lower.
5. **Racing joins.** srv-e runs `ray join <reusable key> --name ra` and
   `--name rb` at once. Exactly one wins, the other is refused saying the
   network is already joined, status shows the network once, no config is
   saved for the losing name, and coordinators list srv-e once. Then a join
   under a third name races the restore: srv-e's cached roster is marked
   unconfirmed and srv-e is cut off, so the restore takes the cold path and
   holds the network through the pkarr resolve timeout, and the join is
   retried from the moment the daemon starts. It must be refused (a `SKIP`
   notes when it only landed after the restore). Leaving removes the network
   from status and config, and neither side reaches the other over the mesh
   any more.
6. **Leave and rejoin right away.** srv-e joins as `coord`, then leaves and
   rejoins under the same name with a new hostname. After 30 s every host has
   `srv-ee` and no `srv-e` or `-1` duplicate, srv-e's roster matches srv-aa's,
   `srv-ee.coord.ray` answers, `srv-e.coord.ray` resolves nowhere (allowing
   one group poll), and srv-e logs no clash with the old instance. The leave
   and rejoin run in one SSH command, but whether a member reconverges between
   them is a race, so the stale-name failure below shows up in some runs only.

## Known failure

A member that sees a peer leave and rejoin under a new hostname before it has
reconverged keeps answering the old `.ray` name. The member seats the rejoiner
itself on its hello (`admit_approved_member`), and `dns::update_hostname` adds
the new name without dropping the old one for that address. The next signed
record then matches the member's roster, so it only raises the floor and
Magic DNS is never resynced.
7. **Logs.** On every host: IPC answers, no panic, no crash restart beyond the
   deliberate `kill -9`, and no protocol warning repeated three times outside
   the isolation windows (where failed publishes and refused replays are the
   point).

A cut is a set of tc drop filters that keep ARP, the runner's SSH session and
an allowlist of fleet addresses. The relays and the pkarr relay go too, so the
only path left is the direct one to the allowlist.

## Running

```bash
E2E_BACKEND=docker tests/e2e.sh coordinators
E2E_BACKEND=docker tests/e2e.sh coordinators teardown
```

A run takes about 20 minutes.
