# files-authz e2e

Who may send a file, and where a received file may be written, driven through
the real CLI (`ray send`, `ray files accept --output`, `ray files`) and, for
requests the CLI never builds, a raw IPC client ([`ipc.py`](ipc.py)).

## Topology

```
srv-a  coordinator of a closed network `fauthz`; the sender
srv-b  member; the receiver
```

Both hosts have two unprivileged users: `alice`, whom root makes the operator,
and `mallory`, who never is.

## What it proves

1. **Sending.** `mallory`'s `ray send` is refused with `sudo ray set-operator`
   named, and so is the same request built by hand. The operator and root can
   send. Nothing of a refused send shows up on either end. All eight files
   of one `ray send` must be offered within 30 s (see below).
2. **Descriptor, not path.** The operator's `ray send` of `/root/...`,
   `/etc/shadow` or a link to a root-only file fails in the CLI's own open.
   Built by hand, a path send (`SendFile`) is refused for her and accepted
   for root (the positive control for the raw client), `SendFileStaged` is
   refused at the IPC boundary, and a `/dev/zero` descriptor is refused. A
   grep of srv-a's blob store finds root's imported file and not the secret.
3. **`--output`.** The operator's accept is refused, before any download
   (no receive row appears, the offer stays queued), for `/etc`, `/root`,
   `/tmp`, another user's directory, links to `/etc` and to another user's
   directory, and missing directories under either. Nothing is written there
   and no missing directory is created. Her own directory, a link to it, a
   missing `new1/a/b` under her home and the default `~/Downloads` work: every
   created directory and file is hers and not group or world writable. Root
   may write anywhere.
4. **Collisions.** An existing file, a link to a root-owned file, a dangling
   link and a dot file at the name are left alone and their targets
   untouched. The new file lands as `name (1).ext` (`.e2e-dot (1)`), and a
   second copy as `name (2).ext`.
5. **Names.** A hand-built send named `../../etc/cron.d/x`, `/etc/x` or `..`
   leaves srv-a as `x`, `x` and `file`. A `back\slash.txt` is declined by the
   receiver and the sender shows `invalid file name`. Leading dots and control
   characters are saved byte for byte. `ray files` must not print the ESC
   bytes of a name carrying terminal escape sequences. A modified peer sending
   `../x` directly is covered by the unit tests
   `only_plain_file_names_are_safe` and
   `an_offer_with_a_traversing_name_is_declined` (`src/daemon/file_service.rs`).
6. **Reads and mutations.** `mallory` can run `ray files`, `ray status`,
   `download-dir`, `download-user` and `auto-accept list`. She is refused
   `accept`, `reject`, `cancel-transfer` (both ends) and `auto-accept`, and
   the offer she tried stays queued. `download-dir` and `download-user` are
   refused as root-only for her and for the operator. The operator can reject.
7. **Auto-accept.** Into a root-configured missing directory, created and
   owned by `download-user`. Refused (logged, nothing written, offer left
   queued) when the user replaced the path with a link to a root-owned
   directory. Allowed through a link to the user's own directory. With neither
   setting, the operator's `~/Downloads`.
8. No panic and no crash restart in either journal.

## Stranded offers

An offer queued while another delivery to the same peer is running is left in
the outbox: `flush_outbox_for` returns early when its `flushing` guard is
taken, and the flush already running never rereads the outbox. The 120 s
sweep only visits peers with a live mesh connection, which an idle peer does
not have, so the offer waits for the next send or reconnect. Check 1 sends
eight files in one `ray send` to catch it. Elsewhere, a wait for an offer
nudges after 30 s by sending one more small file (a send starts a new delivery
pass), so the other checks still run, and the log says so.

Not covered: races between the destination check and the write (the
descriptor-based walk in `receive_dest.rs` is what closes them), and a planted
link at the per-offer `.rayfish-*.part` name, whose hash the CLI does not
expose (`remove_leftover` refuses anything but a regular file the daemon or
the recipient owns).

## Usage

```bash
E2E_BACKEND=docker tests/e2e.sh files-authz
tests/e2e.sh files-authz teardown
```

A run takes about three minutes.
