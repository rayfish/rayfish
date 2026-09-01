# churn e2e

The other scenarios each take one lifecycle event on a quiet mesh. This one takes
the events they skip and runs them while the mesh is moving: repeated flap,
`ray kick` and `ray nuke` delivered while a member is offline, and a health sweep
at the end. Four hosts; shared plumbing lives in `tests/lib/`.

## Topology

```
srv-a  coordinator of a closed network `churn`
srv-b  member, the stable observer  <- never flaps; every convergence assertion
                                       is read from here
srv-c  member, the absentee         <- offline whenever the roster changes
srv-d  member, the victim           <- data-plane flapper, then kicked
```

`srv-b` never restarts on purpose. A "did everyone converge" check read from a
node that was itself mid-restore can pass for the wrong reason, so the observer is
held still. `srv-c` is the opposite: it is stopped before every roster change, so
what it knows when it returns came from the signed blob and not from a broadcast.

## What it proves

1. **Repeated hard flap.** `srv-c`'s daemon is stopped and started three times,
   with a full roster + data-plane check between rounds. One restart working is
   `restore-offline`'s claim; the point here is that the third does. A reconnect
   path that leaks a peer entry, a route or a pruned-peer marker per cycle passes
   round 1 and fails round 3.
2. **Simultaneous flap.** `srv-c` and `srv-d` go down and come back together, so
   each one's restore dials a peer that is itself still restoring. Asserted
   separately: that the two re-link *to each other*, not only to the nodes that
   stayed up.
3. **Coordinator flap.** The node holding the network key restarts. This is the
   direction `restore-offline` does not cover, and the one that risks the roster
   itself: the coordinator is the only node that can republish, so a restart that
   lost or re-derived any of it would push that damage to every member. Asserted:
   the members hold the mesh together while it is down, it comes back with the
   *same* roster, and it is still the coordinator rather than demoted by its own
   restore.
4. **Data-plane flap.** Three `ray down` / `ray up` cycles on `srv-d`. Standby is
   not leave, so the assertion is a pair: traffic stops, and the roster entry does
   not drop.
4b. **The same flap with no `ip` binary.** `srv-d`'s iproute2 is moved aside and
   the cycle is repeated: the link must still go down, come back up, get its
   `200::/7` route and carry traffic, and the journal must hold no link-state
   failure. Link state is netlink's job, not a spawned process's, and while it
   was not, a service PATH without iproute2 failed that one step and succeeded at
   every other, activating onto a link that had never come up. `ray ping` answers
   over the control plane throughout, so the node looked reachable while the
   tunnel swallowed everything. The binary is restored on every exit path.
5. **A kick the absentee never sees.** `srv-c` is stopped, then `srv-d` is kicked.
   The coordinator and the online member drop it; the kicked node leaves the
   network itself, which it does on the signed record rather than on the message
   (`confirm_kick_and_leave`); and it is off the data plane in both directions.
6. **The point.** `srv-c` comes back and reaches the same roster on its own,
   having never received the `MemberSync` that announced the kick. This is the
   "control messages are triggers, never trusted data" invariant, tested from the
   side that missed the trigger. Converging by forgetting everyone is not
   converging, so the step also asserts `srv-c` is fully re-meshed and passing
   packets afterwards.
7. **Recovery.** The kicked node cannot walk back in on the bare room id, and a
   fresh invite does re-admit it: a kick is a removal, not a ban.
8. **Nuke with a member offline.** The coordinator nukes and the members lose it.
   What a member does with its own *local* network entry after a nuke is printed
   rather than asserted: the empty record a nuke publishes names a blob nobody is
   left to serve, so there is nothing for a member to converge onto, and the suite
   does not pin a behaviour the design has not committed to. What is asserted is
   what a user sees: the coordinator is gone and unreachable.
9. **Health sweep.** Every daemon still answers IPC, no journal carries a panic
   line, and systemd never scheduled a restart of its own. `NRestarts` is
   deliberately not the evidence: systemd resets it on a manual start, and this
   test issues plenty.

## Usage

```bash
# Requires: doctl (authenticated), jq, just, cross + docker, an SSH key.
tests/e2e.sh churn             # provision (if needed), cross-build, deploy, drive, assert
tests/e2e.sh churn provision   # create the four droplets only
tests/e2e.sh churn teardown    # destroy them

E2E_BACKEND=docker tests/e2e.sh churn   # same scenario on local containers
ROUNDS=6 DOWN_ROUNDS=6 tests/e2e.sh churn   # more flap cycles
```

The docker backend runs it unchanged: every host action here is `systemctl` and
`ray`, both of which the container image provides. Cloud hosts are still the
better signal for the reconnect timings, since a single bridge hides NAT
traversal and relay fallback entirely.

Re-runnable: each run resets rayfish state on all four hosts unless `KEEP_STATE=1`.
