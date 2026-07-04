# member-restore-with-coordinator-offline e2e

End-to-end regression test for the bug where a member whose daemon restarts while
its coordinator is offline silently drops the network from its running state.
Runs over two real Scaleway hosts; shared plumbing lives in `tests/lib/`.

Background: PR #60 / issue #59.

## Topology

```
srv-a  coordinator of a closed network `priv`
srv-b  member (admitted with an invite)   <- restarted mid-test
srv-c  member (admitted with an invite)   <- stays up, the peer srv-b must find
```

The third host is what makes the core claim testable: with the coordinator
stopped, the restarted member has to re-mesh with the *other* member on its own,
proving the fix connects to any available peer rather than just the coordinator.

## The bug this guards against

A member (non-coordinator) already holds the verified group blob, so being *in* a
network must not depend on the coordinator being reachable at restore time. Before
the fix, member restore dialed the coordinator first and, on failure, aborted
before registering the network: no ALPN handler, absent from `ray status`, inbound
mesh connections rejected with `no handler for ALPN` then `closed by peer: 0`.
Startup restore runs once with no retry, so the network stayed gone until the node
happened to restart again while the coordinator was reachable (its config was
never lost). One member was observed stuck for ~13 hours.

## What it proves

1. `srv-a` creates a closed network; `srv-b` and `srv-c` join with invites and
   the three full-mesh.
2. `srv-a`'s daemon is stopped entirely (`systemctl stop`, not `ray down` standby),
   so the coordinator endpoint is genuinely unreachable; `srv-b` and `srv-c` see it
   go offline but stay linked to each other.
3. `srv-b`'s daemon is restarted while the coordinator is offline (the exact
   failure path).
4. **The fix:** `srv-b` still has `priv` after the restart, **reconnects to
   `srv-c` while the coordinator is still down** (connect to any available peer,
   not just the coordinator), and lists the coordinator as an offline peer.
   Pre-fix, this step fails with "no active networks".
5. **Recovery:** the coordinator is brought back and the full mesh reconverges on
   its own (the reconnect loop seeded at restore keeps dialing with backoff), with
   no manual step on the members.

Running this scenario against a pre-fix binary fails at step 4; against the fixed
binary it passes end to end.

## Usage

```bash
# Requires: scw (authenticated), jq, just, cross + docker, an SSH key.
tests/e2e.sh restore-offline             # provision (if needed), cross-build, deploy, drive, assert
tests/e2e.sh restore-offline provision   # create the two Scaleway instances only
tests/e2e.sh restore-offline teardown    # destroy them
```

Re-runnable: each run resets rayfish state on both hosts unless `KEEP_STATE=1`.
