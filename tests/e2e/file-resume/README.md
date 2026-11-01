# file-resume e2e

Interrupted file receives resume and finish correctly, driven through the real
CLI (`ray send`, `ray files accept <id> --output <dir>`, `ray files --json`).

## Topology

```
srv-a  coordinator of a closed network `files`; sends every file
srv-b  member; accepts and receives them
```

## What it proves

Every check sends a fresh random file (512 MiB by default) and ends with the
same assertions: the sha256 matches, the output directory holds exactly that
one file (no `.rayfish-*.part` left, no `name (1)` copy), the offer is not
back in the receiver's queue, and the sender recorded the delivery (the send
left its `outbox.json`, nothing for it listed as failed, and a `done` entry
carries no leftover "interrupted" note).

1. **Baseline.** While it runs, both ends list it as transferring, and
   `ray files` shows the progress row.
2. **Network cut.** srv-b's network is cut partway while its daemon keeps
   running. It must show the receive as transferring with `interrupted,
   retrying` (not failed), retry several times during the outage, write
   nothing to the output directory while the data is incomplete, and finish
   on its own once the network is back.
3. **Lid close.** The same cut, with the daemon frozen (`SIGSTOP`) for the
   whole outage, then thawed: the receive logs a retry after waking (the
   connection really died) and finishes.
4. **Receiver `systemctl restart`** mid-fetch: `pending-files.json` holds the
   receive as `accepted`, it restarts without a second accept, and resumes
   from what it had rather than from zero.
5. **Receiver `kill -9`, then start**: the same.
6. **Receiver `kill -9` while writing the temp file.** A helper on srv-b
   spins on the directory and kills the daemon once the per-offer `.part`
   file holds 1 MiB. The resumed receive replaces that leftover.
7. **Receiver `kill -9` right after the rename,** before the delivery is
   recorded: the restarted receive finds the saved file and does not save a
   second copy.
8. **Sender `systemctl restart`** mid-transfer.
9. **Sender `kill -9`, then start** mid-transfer.
10. **Long name.** A 253-byte name (83 three-byte characters plus `.bin`;
    ext4 on the sender allows 255) is saved cut at a character boundary to
    at most 249 bytes, keeping `.bin`. A second copy lands as
    `<short> (1).bin` without replacing the first.
11. A size-mismatched offer is **skipped**: the daemon sizes an offer from the
    blob it imports, so the real CLI cannot produce one. The unit test
    `a_blob_larger_than_offered_ends_the_receive` covers it.

Checks 6 and 7 race the daemon on purpose. When the kill lands too late for
the state they aim at, they print `SKIP` with what happened and still check the
end state.

## Known product bug

The sender's `done` check fails on the receiver `kill -9` check (check 5): when
the aborted pull's end is seen after the resumed pull has started, the entry finishes as `done` but keeps
"interrupted; the recipient resumes it when it can", since `finish_entry` in
`src/daemon/transfers.rs` never clears `error`. The failure line says
`KNOWN PRODUCT BUG`.

## How it interrupts

- **Rate limit.** srv-a's egress is held to `FR_RATE` (default `160mbit`)
  with a `tbf` qdisc, so a transfer lasts long enough to interrupt at 25%.
- **Network cut.** `tc` drop filters on srv-b's ethernet interfaces that let
  through only ARP and the runner's SSH session. The interface stays up, so
  the daemon sees silence rather than a link change, and both the direct path
  and the relays are gone: what a closed lid or a dead access point looks
  like from the far end. Removing a qdisc restores it; an `EXIT` trap does
  that on any failure.

## Usage

```bash
E2E_BACKEND=docker tests/e2e.sh file-resume
tests/e2e.sh file-resume teardown
```

| Var | Default | Meaning |
|-----|---------|---------|
| `FR_SIZE_MB` | `512` | size of the interrupted transfers |
| `FR_RATE` | `160mbit` | srv-a egress limit |
| `FR_OUTAGE_SECS` | `90` | how long a cut lasts after the first retry |

A run takes about 20 minutes.
