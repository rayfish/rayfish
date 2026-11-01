# mixed-version e2e

A mesh where half the nodes run this tree's build and half run an older release.
Upgrades roll out one machine at a time, so every network spends a while like
this. Four hosts; shared plumbing lives in `tests/lib/`.

## Topology

```
srv-a  NEW  coordinator of `alpha`, later a member of `beta`
srv-b  OLD  coordinator of `beta`, member then co-coordinator of `alpha`
srv-c  OLD  member of `alpha` and `beta`, kicked from `beta` by srv-d
srv-d  NEW  member then co-coordinator of `beta`, member of `alpha`,
            kicked from `alpha` by srv-b
```

Each network has one coordinator of each version, so every check below runs in
both directions.

## What it proves

1. **Joins.** OLD nodes join a NEW coordinator by invite and a NEW node joins an
   OLD coordinator. Rosters converge on every host, each side derives the same
   mesh address for the other, pings cross both ways and `<host>.<net>.ray`
   resolves. No peer is flagged incompatible.
2. **Co-coordinators.** `ray admin add` makes srv-b (OLD) a co-coordinator of
   `alpha` and srv-d (NEW) one of `beta`. An admission by the co-coordinator of
   the other version converges on all hosts. Then the run waits two renewal
   cycles (`RENEWAL_WAIT`, default 330s) while every host must keep the full
   roster, every coordinator must publish at least twice, and the NEW nodes must
   refuse none of the OLD node's records.
3. **Kicks.** srv-b (OLD) kicks srv-d (NEW) from `alpha`, and srv-d (NEW) kicks
   srv-c (OLD) from `beta`. The others drop the kicked node, it leaves that
   network and keeps the other, and its `.ray` name stops resolving.
4. **Restarts.** srv-a (NEW coordinator of `alpha`, member of `beta`) and srv-d
   (NEW co-coordinator of `beta`) restart. They keep their roles, rejoin, carry
   pings, and do not bring back a network they were kicked from. This runs on
   the saved record floor (`last_record_timestamp` in the network config), which
   the OLD build does not write or read.
5. **Files.** `ray send` + `ray files accept`, OLD to NEW and NEW to OLD on each
   network, sha256 checked.
6. **Logs.** On every host: IPC still answers, no panic, no crash restart, and
   no protocol warning repeated three or more times.

The mesh address check is not decoration: `derive_ipv6` was rewritten after the
release, and a different result on either side would route packets to nowhere.

## Running

The older binary is a local file named by `OLD_RAY_BIN`. Keep it outside the
repository. For a release:

```bash
mkdir -p /path/to/old && cd /path/to/old
gh release download v0.5.13 -R rayfish/rayfish -p 'ray-linux-x86_64' -p 'ray-linux-x86_64.sha256'
sha256sum -c ray-linux-x86_64.sha256
```

Then:

```bash
OLD_RAY_BIN=/path/to/old/ray-linux-x86_64 E2E_BACKEND=docker tests/e2e.sh mixed-version
tests/e2e.sh mixed-version teardown
```

The NEW nodes get the usual `just cross` build. A run takes about 15 minutes,
most of it the renewal wait. Both builds may print the same `ray --version`, so
step 0 tells them apart by the sha256 of the installed file and checks that the
running daemon's executable is that file.
