#!/usr/bin/env bash
# Who may send files, and where a received file may be written.
#
# Topology:
#   srv-a  coordinator of a closed network `fauthz`; the sender
#   srv-b  member; the receiver
#
# Both hosts carry two unprivileged local users: alice, whom root makes the
# operator (`ray set-operator`), and mallory, who never is. The daemon runs as
# root, so every check here is about the daemon refusing to use its own
# privileges on a caller's behalf:
#
#   1. sending needs root or the operator; the refusal names the fix
#   2. a send never makes the daemon open a path for a non-root caller: the CLI
#      opens the file itself, and hand-built path frames are refused (proved
#      with a raw IPC client, ipc.py, and a blob-store grep with a positive
#      control)
#   3. `ray files accept --output` writes only into a directory the accepting
#      user owns: refused (before any download) for /etc, /tmp, /root, another
#      user's dir, and links or missing paths that end in those; allowed for
#      their own dir, a link to it, and a missing dir under it (created and
#      owned by them)
#   4. an existing file, link or dangling link at the name is never replaced or
#      followed: the file lands as `name (1)`
#   5. peer-chosen names: path tricks in a hand-built send are cut to the base
#      name by the sender, a backslash name is declined by the receiver, dots
#      and control characters are saved byte for byte, and terminal escape
#      sequences in a name must not reach the terminal through `ray files`
#   6. reads are open to any local user; file mutations are not
#   7. auto-accept writes only where root configured it, as the configured
#      user, and not through a link to a directory that user does not own
#   8. no panic or crash restart in either daemon's log
#
# Reads tests/e2e/files-authz/.servers (written by provision). Re-runnable.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS, run '$ROOT/tests/e2e.sh files-authz provision' first"; exit 1; }
A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

NET=fauthz
OP=alice              # the operator on both hosts
NO=mallory            # never authorized
OPH=/home/$OP
NOH=/home/$NO
IPC=/usr/local/bin/ray-ipc

skip(){ printf '  \033[33mSKIP\033[0m %s\n' "$*"; }

# as <ip> <user> <command...> : run a command on <ip> as an unprivileged local
# user, combined output on stdout, the command's own exit status returned.
# Keep the command free of single quotes: it is passed through one.
as(){
  local ip="$1" user="$2"; shift 2
  on "$ip" "LC_ALL=C LANG=C su -s /bin/bash $user -c '$*' 2>&1"
}

# denied <output> : the refusal a non-operator is meant to see, naming the fix.
denied(){ grep -qi 'permission denied' <<<"$1" && grep -q 'set-operator' <<<"$1"; }

# indent <tag> : prefix each line, for showing what a command printed.
indent(){ strip | sed "s/^/      $1| /"; }

files_json(){ on "$1" 'timeout --kill-after=2s 15s ray files --json' 2>/dev/null; }

# offer_id <name> : srv-b's pending offer id for <name>, or empty.
offer_id(){
  files_json "$B" | jq -r --arg f "$1" '[.pending[] | select(.filename == $f)] | .[0].id // empty'
}

# nudge : have srv-a deliver every offer still waiting in its outbox, by
# queueing one more (a send starts a fresh delivery pass for that peer). An
# offer queued while another delivery to the same peer is running can be left
# behind, and nothing else retries it soon: the 120 s sweep skips a peer with
# no live mesh connection. Step 3 checks that bug on its own; elsewhere the
# nudge keeps the other checks from depending on it.
NUDGES=0
nudge(){
  NUDGES=$((NUDGES + 1))
  on "$A" "head -c 64 /dev/urandom > /root/fa-nudge-$NUDGES.bin && ray send srv-b /root/fa-nudge-$NUDGES.bin" >/dev/null 2>&1
}

# retry_nudged <cond> : retry_until 20, then nudge and try again, four rounds.
retry_nudged(){
  local round
  for round in 1 2 3 4; do
    retry_until 20 "$1" && return 0
    nudge
  done
  return 1
}

# wait_offer <name> : wait for <name> to be offered to srv-b; echo its id.
wait_offer(){
  local q; q="$(printf '%q' "$1")"
  if retry_until 30 "[[ -n \"\$(offer_id $q)\" ]]"; then offer_id "$1"; return 0; fi
  echo "      note: $q was offered only after a nudge" >&2
  if retry_nudged "[[ -n \"\$(offer_id $q)\" ]]"; then offer_id "$1"; else return 1; fi
}

# recv_rows <name> : how many incoming transfers srv-b lists for <name>.
recv_rows(){
  files_json "$B" | jq --arg f "$1" '[.transfers[] | select(.outgoing == false and .filename == $f)] | length'
}

# absent_everywhere <name> : both ends answer, and neither lists <name> as
# pending, queued or transferring. A failed query is not absence.
absent_everywhere(){
  local h json
  for h in "$A" "$B"; do
    json="$(files_json "$h")" || return 1
    jq -e --arg f "$1" \
      '([.pending[], .queued[], .transfers[]] | map(select(.filename == $f)) | length) == 0' \
      >/dev/null 2>&1 <<<"$json" || return 1
  done
}

# owner_mode <ip> <path> : `user:group mode type` of the path itself (no follow).
owner_mode(){ on "$1" "stat -c '%U:%G %a %F' '$2' 2>/dev/null" | tr -d '\r'; }

# mode_safe <octal> : not group- or world-writable, no setuid/setgid/sticky bits.
mode_safe(){ (( (8#$1 & 8#7022) == 0 )); }

sha_of(){ on "$1" "sha256sum '$2' 2>/dev/null | cut -d' ' -f1"; }

# hexof <string> : the string's bytes as lowercase hex.
hexof(){ printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

# hexnames <ip> <dir> : every entry name in <dir> as hex, sorted, space separated.
hexnames(){
  on "$1" "python3 -c 'import os,sys;print(\" \".join(sorted(n.encode(\"utf-8\",\"surrogateescape\").hex() for n in os.listdir(sys.argv[1]))))' '$2'"
}

# no_trace <ip> <dir> <name> : neither <name> nor a temp file is in <dir>.
no_trace(){
  on "$1" "! test -e '$2/$3' && ! test -L '$2/$3' && ! ls -A '$2' 2>/dev/null | grep -q '^\.rayfish-.*\.part\$'"
}

# make_file <ip> <owner> <path> : a small random file, owned by <owner>; echo sha256.
make_file(){
  on "$1" "mkdir -p \"\$(dirname '$3')\" && head -c 4096 /dev/urandom > '$3' && chown $2: '$3' && chmod 644 '$3' && sha256sum '$3' | cut -d' ' -f1"
}

# accept_as <user> <id> [dir] : `ray files accept` on srv-b as <user>; sets OUT, RC.
accept_as(){
  local user="$1" id="$2" dir="${3:-}" cmd
  cmd="timeout 120 ray files accept $id"
  [[ -n "$dir" ]] && cmd+=" --output $dir"
  if [[ "$user" == root ]]; then
    OUT="$(on "$B" "$cmd" 2>&1)"; RC=$?
  else
    OUT="$(as "$B" "$user" "$cmd")"; RC=$?
  fi
}

# ipc_msg <json> : the message of a raw-IPC reply.
ipc_msg(){ jq -r '(.Ok.message // .Error.message // .HelperError // .) | tostring' <<<"$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
step "0. wait for SSH on both hosts, deploy, bring the VPN up"
wait_all_ssh "$A" "$B"
seed_known_hosts "$A" "$B"
reset_state "$A" "$B"
deploy_all "$ROOT" "$A" "$B"
activate_daemons "$A" "$B" || summary

# ---------------------------------------------------------------------------
step "1. srv-a creates the closed network; srv-b joins via invite"
on "$A" "ray create --name $NET --hostname srv-a" | strip | sed 's/^/   a| /'
INV_B="$(mint_invite "$A" "$NET" srv-b)"
[[ -n "$INV_B" ]] && pass "minted invite for srv-b" || { fail "invite mint failed"; summary; }
on "$B" "ray join $INV_B --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'
wait_roster "$A" srv-b
wait_roster "$B" srv-a

# ---------------------------------------------------------------------------
step "2. local users, the raw IPC client, and the operator grant on both hosts"
IPC_B64="$(base64 -w0 "$DIR/ipc.py")"
for h in "$A" "$B"; do
  on "$h" "for u in $OP $NO; do id -u \$u >/dev/null 2>&1 || useradd -m -s /bin/bash \$u; done
    echo $IPC_B64 | base64 -d > $IPC && chmod 755 $IPC
    rm -rf $OPH/* $OPH/.e2e* $NOH/* /etc/e2e-* /root/fa-*"
  OUT="$(on "$h" "ray set-operator $OP" 2>&1)" \
    && pass "root made $OP the operator on $h" || fail "set-operator $OP on $h: $OUT"
done
OP_UID="$(on "$B" "id -u $OP" | tr -d '[:space:]')"
NO_UID="$(on "$B" "id -u $NO" | tr -d '[:space:]')"
[[ -n "$OP_UID" && -n "$NO_UID" && "$OP_UID" != 0 && "$NO_UID" != 0 ]] \
  && pass "two unprivileged users ($OP=$OP_UID $NO=$NO_UID)" || { fail "user setup failed"; summary; }

# ---------------------------------------------------------------------------
step "3. who may send: root and the operator, not a plain user"
make_file "$A" "$NO" "$NOH/m-plain.txt" >/dev/null
OUT="$(as "$A" "$NO" "ray send srv-b ~/m-plain.txt")"; rc=$?
echo "$OUT" | indent mallory
[[ $rc -ne 0 ]] && denied "$OUT" \
  && pass "$NO cannot send; the refusal names 'sudo ray set-operator'" \
  || fail "$NO's send was not refused with the fix named (rc=$rc)"

# The CLI is not the gate: the same request built by hand is refused too.
RAW="$(as "$A" "$NO" "$IPC SendFileFd filename=m-raw.txt peer=srv-b --fd ~/m-plain.txt")"
denied "$(ipc_msg "$RAW")" \
  && pass "$NO's hand-built descriptor send is refused by the daemon" \
  || fail "$NO's raw SendFileFd was not refused: $RAW"

SHA_OP="$(make_file "$A" "$OP" "$OPH/a-op.txt")"
OUT="$(as "$A" "$OP" "ray send srv-b ~/a-op.txt")"; rc=$?
[[ $rc -eq 0 ]] && pass "the operator can send" || { fail "the operator's send failed (rc=$rc)"; echo "$OUT" | indent alice; }
make_file "$A" root /root/fa-root.txt >/dev/null
OUT="$(on "$A" "ray send srv-b /root/fa-root.txt" 2>&1)"; rc=$?
[[ $rc -eq 0 ]] && pass "root can send" || { fail "root's send failed (rc=$rc)"; echo "$OUT" | indent a; }

ID_OP="$(wait_offer a-op.txt)" && pass "srv-b got the operator's offer (id $ID_OP)" \
  || fail "the operator's offer never reached srv-b"
ID_ROOT="$(wait_offer fa-root.txt)" && pass "srv-b got root's offer (id $ID_ROOT)" \
  || fail "root's offer never reached srv-b"
# Both authorized offers arrived, so a refused one that had been queued would
# be visible by now on at least one end.
for n in m-plain.txt m-raw.txt; do
  if absent_everywhere "$n"; then
    pass "nothing of $NO's refused send ($n) exists on either end"
  else
    fail "$NO's refused send $n was queued or offered anyway"
  fi
done

# One `ray send` with several files queues them back to back. Every one of
# them has to reach the peer, without waiting for some later event.
on "$A" "rm -rf /root/fa-burst && mkdir /root/fa-burst && for i in 1 2 3 4 5 6 7 8; do head -c 2048 /dev/urandom > /root/fa-burst/fa-burst\$i.bin; done"
on "$A" "cd /root/fa-burst && ray send srv-b fa-burst*.bin" >/dev/null 2>&1
burst_count(){ files_json "$B" | jq '[.pending[] | select(.filename | startswith("fa-burst"))] | length'; }
if retry_until 30 '[[ "$(burst_count)" == 8 ]]'; then
  pass "all 8 files of one 'ray send' are offered within 30 s"
else
  got="$(burst_count)"
  fail "only ${got:-?} of 8 files of one 'ray send' were offered within 30 s: an offer queued while a delivery to the same peer is running is skipped (flush_outbox_for returns early on its 'flushing' guard and the running flush never rereads the outbox), and the 120 s sweep skips a peer with no live mesh connection, so the rest wait for the next send or reconnect"
  retry_nudged '[[ "$(burst_count)" == 8 ]]' \
    && pass "the stranded offers arrive once a later send starts a new delivery pass" \
    || fail "the stranded offers did not arrive even after later sends ($(burst_count) of 8)"
fi
for id in $(files_json "$B" | jq -r '.pending[] | select(.filename | test("^fa-(burst|nudge)")) | .id'); do
  on "$B" "ray files reject $id" >/dev/null
done

# ---------------------------------------------------------------------------
step "4. sends go by descriptor; the daemon never opens a path for a non-root caller"
TOKEN_SECRET="e2e-secret-$RANDOM$RANDOM"
TOKEN_ROOT="e2e-rootpath-$RANDOM$RANDOM"
on "$A" "printf '%s\n' $TOKEN_SECRET > /root/fa-secret.txt && chmod 600 /root/fa-secret.txt
  printf '%s\n' $TOKEN_ROOT > /root/fa-rootpath.txt
  ln -sfn /root/fa-secret.txt $OPH/fa-secret-link && chown -h $OP: $OPH/fa-secret-link
  echo fd-ok > $OPH/fa-fd-ok.txt && chown $OP: $OPH/fa-fd-ok.txt"

for target in /root/fa-secret.txt "$OPH/fa-secret-link" /etc/shadow; do
  OUT="$(as "$A" "$OP" "ray send srv-b $target")"; rc=$?
  if [[ $rc -ne 0 ]] && grep -qi 'cannot read' <<<"$OUT"; then
    pass "operator 'ray send $target' fails in the CLI's own open (cannot read)"
  else
    fail "operator 'ray send $target' was not stopped at the open (rc=$rc): $OUT"
  fi
done

# Positive control: the raw client builds a path send the daemon accepts from root.
RAW="$(on "$A" "$IPC SendFile path=/root/fa-rootpath.txt peer=srv-b")"; rc=$?
[[ $rc -eq 0 ]] && pass "root's hand-built path send is accepted (raw client works)" \
  || fail "root's raw SendFile failed, so the refusals below prove nothing: $RAW"

for path in /root/fa-secret.txt /etc/shadow; do
  RAW="$(as "$A" "$OP" "$IPC SendFile path=$path peer=srv-b")"; rc=$?
  if [[ $rc -eq 1 ]] && grep -q 'requires root' <<<"$(ipc_msg "$RAW")"; then
    pass "operator's hand-built path send of $path is refused (by path requires root)"
  else
    fail "operator's raw SendFile $path was not refused (rc=$rc): $RAW"
  fi
done
RAW="$(as "$A" "$OP" "$IPC SendFileStaged path=/root/fa-secret.txt filename=fa-staged.txt peer=srv-b")"; rc=$?
if [[ $rc -eq 1 ]] && grep -qi 'internal file-transfer frame' <<<"$(ipc_msg "$RAW")"; then
  pass "operator's SendFileStaged (the Windows-internal path frame) is refused"
else
  fail "operator's SendFileStaged was not refused (rc=$rc): $RAW"
fi
RAW="$(as "$A" "$OP" "$IPC SendFileFd filename=fa-zero.bin peer=srv-b --fd /dev/zero")"; rc=$?
if [[ $rc -eq 1 ]] && grep -qi 'not a regular file' <<<"$(ipc_msg "$RAW")"; then
  pass "a descriptor that is not a regular file (/dev/zero) is refused"
else
  fail "a /dev/zero descriptor was not refused (rc=$rc): $RAW"
fi
RAW="$(as "$A" "$OP" "$IPC SendFileFd filename=fa-fd-ok.txt peer=srv-b --fd ~/fa-fd-ok.txt")"; rc=$?
[[ $rc -eq 0 ]] && pass "operator's hand-built descriptor send of her own file is accepted" \
  || fail "operator's raw SendFileFd of her own file failed: $RAW"

ID_ROOTPATH="$(wait_offer fa-rootpath.txt)" && pass "root's path send reached srv-b" \
  || fail "root's path send never reached srv-b"
ID_FDOK="$(wait_offer fa-fd-ok.txt)" && pass "the operator's descriptor send reached srv-b" \
  || fail "the operator's descriptor send never reached srv-b"
for n in fa-secret.txt fa-secret-link shadow fa-staged.txt fa-zero.bin; do
  if absent_everywhere "$n"; then
    pass "no trace of the refused send '$n' on either end"
  else
    fail "the refused send '$n' was queued or offered"
  fi
done
# The bytes themselves: a send imports the file into srv-a's blob store
# (/var/lib/rayfish/blobs) before offering it. Root's path send must be there
# (the grep can see an import), and the secret must not.
STORES="/etc/rayfish /var/lib/rayfish"
if on "$A" "grep -rqaF $TOKEN_ROOT $STORES"; then
  pass "control: an imported file's bytes are visible in srv-a's state"
  on "$A" "grep -rqaF $TOKEN_SECRET $STORES" \
    && fail "the root-only file's bytes are in srv-a's blob store" \
    || pass "the root-only file's bytes never entered srv-a's blob store"
else
  skip "imported bytes are not greppable in /etc/rayfish, so the secret check cannot be made"
fi

# ---------------------------------------------------------------------------
step "5. reads are open to any local user; file mutations are not"
OUT="$(as "$B" "$NO" "ray files --json")"; rc=$?
if [[ $rc -eq 0 ]] && jq -e --arg f a-op.txt '.pending | any(.filename == $f)' >/dev/null 2>&1 <<<"$OUT"; then
  pass "$NO can list files and sees the daemon's pending offers"
else
  fail "$NO could not read the file list (rc=$rc)"
fi
for cmd in "ray files" "ray status --json" "ray files download-dir" "ray files download-user" "ray files auto-accept list"; do
  as "$B" "$NO" "$cmd" >/dev/null && pass "$NO can run the open read: $cmd" \
    || fail "$NO was refused an open read: $cmd"
done
OUT="$(as "$A" "$NO" "ray status --json")"
jq -e --arg n "$NET" '.networks | any(.name == $n)' >/dev/null 2>&1 <<<"$OUT" \
  && pass "$NO can read status on srv-a too" || fail "$NO cannot read status on srv-a"

for cmd in "ray files accept $ID_ROOT --output $NOH" "ray files reject $ID_ROOT" \
           "ray files cancel-transfer 1" "ray files auto-accept add srv-a" \
           "ray files auto-accept $NET on"; do
  OUT="$(as "$B" "$NO" "timeout 30 $cmd")"; rc=$?
  [[ $rc -ne 0 ]] && denied "$OUT" && pass "$NO is refused: $cmd" \
    || { fail "$NO was not refused with the fix named: $cmd (rc=$rc)"; echo "$OUT" | indent mallory; }
done
[[ "$(offer_id fa-root.txt)" == "$ID_ROOT" ]] && no_trace "$B" "$NOH" fa-root.txt \
  && pass "the offer $NO tried to take is still queued and nothing was written" \
  || fail "$NO's refused accept/reject changed the offer or wrote a file"
[[ "$(on "$B" 'ray files auto-accept list --json' | jq 'length')" == 0 ]] \
  && pass "the auto-accept list is still empty" \
  || fail "$NO's refused auto-accept add took effect"

for who in "$NO" "$OP"; do
  for cmd in "ray files download-dir $OPH" "ray files download-user $OP"; do
    OUT="$(as "$B" "$who" "$cmd")"; rc=$?
    [[ $rc -ne 0 ]] && grep -q 'only root may set' <<<"$OUT" \
      && pass "$who is refused '$cmd' (root only)" \
      || { fail "$who was not refused '$cmd' as root-only (rc=$rc)"; echo "$OUT" | indent "$who"; }
  done
done
DD="$(on "$B" "ray files download-dir --json" | jq -r '.download_dir')"
[[ "$DD" == null ]] && pass "download-dir is still unset" || fail "download-dir changed to $DD"

# Sender side: a plain user cannot cancel someone else's outgoing transfer.
TX="$(files_json "$A" | jq -r '[.transfers[] | select(.outgoing and .filename == "a-op.txt")] | .[0].id // empty')"
if [[ -n "$TX" ]]; then
  OUT="$(as "$A" "$NO" "ray files cancel-transfer $TX")"; rc=$?
  [[ $rc -ne 0 ]] && denied "$OUT" && pass "$NO cannot cancel an outgoing transfer on srv-a" \
    || fail "$NO's cancel-transfer on srv-a was not refused: $OUT"
else
  skip "srv-a lists no outgoing row for a-op.txt to try cancelling"
fi

# And the operator's mutations do work.
OUT="$(as "$B" "$OP" "ray files reject $ID_ROOT")"; rc=$?
[[ $rc -eq 0 && -z "$(offer_id fa-root.txt)" ]] && pass "the operator can reject an offer" \
  || fail "the operator's reject failed (rc=$rc): $OUT"

# ---------------------------------------------------------------------------
step "6. --output: only a directory the accepting user owns"
on "$B" "mkdir -p $OPH/in-own $OPH/real-own $NOH/drop && chown $OP: $OPH/in-own $OPH/real-own
  chown $NO: $NOH/drop && chmod 755 $NOH/drop
  ln -sfn /etc $OPH/to-etc && ln -sfn $NOH/drop $OPH/to-other && ln -sfn $OPH/real-own $OPH/link-own
  chown -h $OP: $OPH/to-etc $OPH/to-other $OPH/link-own"

# Refused targets: each must fail with the ownership reason, before any
# download (no receive row appears), leave the offer queued, and write nothing.
declare -a REFUSED=(
  "/etc|/etc|"
  "/root|/root|"
  "/tmp|/tmp|"
  "$NOH/drop|$NOH/drop|"
  "$OPH/to-etc|/etc|"
  "$OPH/to-other|$NOH/drop|"
  "$OPH/to-etc/e2e-newsub|/etc|/etc/e2e-newsub"
  "$NOH/drop/newsub|$NOH/drop|$NOH/drop/newsub"
)
for row in "${REFUSED[@]}"; do
  IFS='|' read -r target real missing <<<"$row"
  accept_as "$OP" "$ID_OP" "$target"
  if [[ $RC -ne 0 ]] && grep -qiE 'not owned by|goes through a link' <<<"$OUT"; then
    pass "refused --output $target ($(grep -oiE 'not owned by uid [0-9]+|goes through a link' <<<"$OUT" | head -1))"
  else
    fail "--output $target was not refused for ownership (rc=$RC)"; echo "$OUT" | indent alice
  fi
  no_trace "$B" "$real" a-op.txt && pass "nothing written in $real" \
    || fail "accepting into $target left a file or temp file in $real"
  if [[ -n "$missing" ]]; then
    on "$B" "! test -e '$missing'" && pass "the missing $missing was not created" \
      || fail "a refused accept created $missing"
  fi
done
[[ "$(offer_id a-op.txt)" == "$ID_OP" ]] && pass "after every refusal the offer is still queued" \
  || fail "a refused accept consumed the offer"
[[ "$(recv_rows a-op.txt)" == 0 ]] && pass "no refused accept started a download" \
  || fail "a refused accept started a receive: $(files_json "$B" | jq -c '.transfers')"

accept_as "$OP" "$ID_OP" "$OPH/in-own"
[[ $RC -eq 0 ]] && pass "accept into her own directory succeeds" || { fail "accept into $OPH/in-own failed"; echo "$OUT" | indent alice; }
[[ "$(sha_of "$B" "$OPH/in-own/a-op.txt")" == "$SHA_OP" ]] && pass "the saved bytes match" \
  || fail "the saved file's sha256 does not match"
read -r own mode _ <<<"$(owner_mode "$B" "$OPH/in-own/a-op.txt")"
[[ "$own" == "$OP:$OP" ]] && pass "the saved file is owned by $OP ($own)" || fail "the saved file is owned by '$own', not $OP"
mode_safe "${mode:-777}" && pass "the saved file's mode is $mode (not group/world writable)" \
  || fail "the saved file's mode is $mode"
no_trace "$B" "$OPH/in-own" nothing && pass "no temp file left beside it" || fail "a .part file was left in $OPH/in-own"

accept_as "$OP" "$ID_FDOK" "$OPH/link-own"
if [[ $RC -eq 0 ]] && [[ "$(owner_mode "$B" "$OPH/real-own/fa-fd-ok.txt")" == "$OP:$OP "* ]]; then
  pass "a link that ends on her own directory is allowed; the file lands there, hers"
else
  fail "accept through a link to her own dir failed (rc=$RC): $OUT"
fi

# Missing components under her home are created, each handed to her.
make_file "$A" "$OP" "$OPH/fa-nest.txt" >/dev/null
as "$A" "$OP" "ray send srv-b ~/fa-nest.txt" >/dev/null
if ID="$(wait_offer fa-nest.txt)"; then
  accept_as "$OP" "$ID" "$OPH/new1/a/b"
  [[ $RC -eq 0 ]] && pass "accept into a missing $OPH/new1/a/b succeeds" || { fail "accept into a missing dir failed"; echo "$OUT" | indent alice; }
  for d in new1 new1/a new1/a/b new1/a/b/fa-nest.txt; do
    read -r own mode kind <<<"$(owner_mode "$B" "$OPH/$d")"
    if [[ "$own" == "$OP:$OP" ]] && mode_safe "${mode:-777}"; then
      pass "created $d is $OP's ($own $mode $kind)"
    else
      fail "created $d is '$own' mode '$mode'"
    fi
  done
else
  fail "fa-nest.txt never reached srv-b"
fi

# No --output: the CLI picks the caller's own ~/Downloads, created for her.
make_file "$A" "$OP" "$OPH/fa-dl.txt" >/dev/null
as "$A" "$OP" "ray send srv-b ~/fa-dl.txt" >/dev/null
if ID="$(wait_offer fa-dl.txt)"; then
  on "$B" "rm -rf $OPH/Downloads"
  accept_as "$OP" "$ID"
  read -r own _ <<<"$(owner_mode "$B" "$OPH/Downloads")"
  read -r fown _ <<<"$(owner_mode "$B" "$OPH/Downloads/fa-dl.txt")"
  [[ $RC -eq 0 && "$own" == "$OP:$OP" && "$fown" == "$OP:$OP" ]] \
    && pass "with no --output the file lands in her ~/Downloads, created and owned by her" \
    || { fail "default ~/Downloads accept: rc=$RC dir='$own' file='$fown'"; echo "$OUT" | indent alice; }
else
  fail "fa-dl.txt never reached srv-b"
fi

# Root is not held to ownership: it could write there anyway.
accept_as root "$ID_ROOTPATH" /etc/e2e-rootdir
read -r own _ <<<"$(owner_mode "$B" /etc/e2e-rootdir/fa-rootpath.txt)"
[[ $RC -eq 0 && "$own" == root:root ]] && pass "root may accept into a missing dir under /etc (file is root's)" \
  || fail "root's accept into /etc/e2e-rootdir: rc=$RC owner='$own' $OUT"

# ---------------------------------------------------------------------------
step "7. name collisions: never replaced, never followed"
C=$OPH/coll
on "$B" "mkdir -p $C && echo OLD > $C/same.txt && echo DOT > $C/.e2e-dot
  echo VICTIM > /etc/e2e-victim && chmod 644 /etc/e2e-victim
  ln -sfn /etc/e2e-victim $C/link.txt && ln -sfn /etc/e2e-dangle $C/dangle.txt
  chown -R $OP: $C && chown -h $OP: $C/link.txt $C/dangle.txt"
declare -A CSHA=()
for n in same.txt link.txt dangle.txt .e2e-dot; do
  CSHA[$n]="$(make_file "$A" "$OP" "$OPH/c/$n")"
done
as "$A" "$OP" "cd ~/c && ray send srv-b same.txt link.txt dangle.txt .e2e-dot" | indent send
for n in same.txt link.txt dangle.txt .e2e-dot; do
  if ID="$(wait_offer "$n")"; then
    accept_as "$OP" "$ID" "$C"
    [[ $RC -eq 0 ]] || { fail "accepting $n into $C failed"; echo "$OUT" | indent alice; }
  else
    fail "$n never reached srv-b"
  fi
done
[[ "$(on "$B" "cat $C/same.txt")" == OLD ]] && pass "an existing same.txt is left alone" \
  || fail "the existing same.txt was overwritten"
[[ "$(sha_of "$B" "$C/same (1).txt")" == "${CSHA[same.txt]}" ]] && pass "the new one is saved as 'same (1).txt'" \
  || fail "'same (1).txt' is missing or wrong"
[[ "$(on "$B" "readlink $C/link.txt")" == /etc/e2e-victim ]] && pass "a link at the name is still that link" \
  || fail "the link at link.txt was replaced"
read -r own _ <<<"$(owner_mode "$B" /etc/e2e-victim)"
[[ "$(on "$B" "cat /etc/e2e-victim")" == VICTIM && "$own" == root:root ]] \
  && pass "the link's target (/etc/e2e-victim) is untouched, still root's" \
  || fail "the receive wrote through link.txt into /etc/e2e-victim (owner $own)"
[[ "$(sha_of "$B" "$C/link (1).txt")" == "${CSHA[link.txt]}" ]] && pass "the file is saved as 'link (1).txt'" \
  || fail "'link (1).txt' is missing or wrong"
on "$B" "test -L $C/dangle.txt && ! test -e /etc/e2e-dangle" \
  && pass "a dangling link is not followed: /etc/e2e-dangle was not created" \
  || fail "the dangling link was followed or replaced"
[[ "$(sha_of "$B" "$C/dangle (1).txt")" == "${CSHA[dangle.txt]}" ]] && pass "the file is saved as 'dangle (1).txt'" \
  || fail "'dangle (1).txt' is missing or wrong"
[[ "$(on "$B" "cat $C/.e2e-dot")" == DOT && "$(sha_of "$B" "$C/.e2e-dot (1)")" == "${CSHA[.e2e-dot]}" ]] \
  && pass "a dot file collides as '.e2e-dot (1)'" || fail "the .e2e-dot collision went wrong"
as "$A" "$OP" "ray send srv-b ~/c/same.txt" >/dev/null
if ID="$(wait_offer same.txt)"; then
  accept_as "$OP" "$ID" "$C"
  [[ "$(sha_of "$B" "$C/same (2).txt")" == "${CSHA[same.txt]}" && "$(on "$B" "cat $C/same.txt")" == OLD ]] \
    && pass "a second copy lands as 'same (2).txt'" || fail "the second copy did not land as 'same (2).txt'"
else
  fail "the second same.txt never reached srv-b"
fi

# ---------------------------------------------------------------------------
step "8. peer-chosen names"
# A hand-built send can name the file anything. The sender keeps only the
# base name, so the offer that leaves srv-a carries none of the path.
on "$A" "echo name-trick > /root/fa-n.txt"
declare -a TRICKS=("../../etc/cron.d/e2e-evil|e2e-evil" "/etc/e2e-abs|e2e-abs" "..|file")
for row in "${TRICKS[@]}"; do
  IFS='|' read -r asked want <<<"$row"
  RAW="$(on "$A" "$IPC SendFileFd 'filename=$asked' peer=srv-b --fd /root/fa-n.txt")"
  if ID="$(wait_offer "$want")"; then
    pass "a send named '$asked' is offered as '$want'"
    on "$B" "ray files reject $ID" >/dev/null
  else
    fail "a send named '$asked' did not arrive as '$want' ($RAW): $(files_json "$B" | jq -c '[.pending[].filename]')"
  fi
done
files_json "$B" | jq -e '[.pending[].filename] | any(test("/"))' >/dev/null \
  && fail "an offer with a '/' in its name reached srv-b" || pass "no offer name on srv-b contains '/'"

# Real files with awkward names, sent by the real CLI.
N_DOT=".e2e-hidden"
N_DOTS="..e2e-dots"
N_BACK='back\slash.txt'
N_CTL=$'ctl-\x01\x7f\t-mark'
N_ESC=$'esc-\e]0;e2e-title\a\e[2K-mark.txt'
HEXES=""
for n in "$N_DOT" "$N_DOTS" "$N_BACK" "$N_CTL" "$N_ESC"; do HEXES+=" $(hexof "$n")"; done
on "$A" "rm -rf /root/fa-names && mkdir /root/fa-names && python3 -c 'import os,sys
for h in sys.argv[1:]:
    open(os.path.join(\"/root/fa-names\", bytes.fromhex(h).decode()), \"w\").write(h)' $HEXES"
on "$A" "cd /root/fa-names && find . -maxdepth 1 -type f -print0 | xargs -0 ray send srv-b" 2>&1 | indent send

# A backslash is a separator on Windows, so the receiver declines the name and
# the sender is told why.
if retry_nudged "files_json '$A' | jq -e --arg f '$N_BACK' '.transfers | any(.filename == \$f and (.error // \"\" | test(\"invalid file name\")))' >/dev/null"; then
  pass "a backslash name is declined by the receiver; the sender shows 'invalid file name'"
else
  fail "the backslash name was not declined with a reason: $(files_json "$A" | jq -c --arg f "$N_BACK" '[.transfers[] | select(.filename == $f)]')"
fi
[[ -z "$(offer_id "$N_BACK")" ]] && pass "and it is not queued on srv-b" || fail "the backslash name was queued on srv-b"

# The receiving user reads these names in `ray files`. Output here is not a
# terminal, so the CLI writes no escape sequences of its own: any ESC byte in
# it came from the peer's name. A name that carries one can retitle the
# terminal, erase the line it sits on, or worse.
if wait_offer "$N_ESC" >/dev/null; then
  LIST="$(as "$B" "$OP" "ray files")"
  if ! grep -qa 'mark.txt' <<<"$LIST"; then
    fail "the escape-name offer does not show in 'ray files', so the check below proves nothing"
  elif [[ "$LIST" == *$'\e'* ]]; then
    fail "a peer's file name reaches the terminal raw: 'ray files' printed its ESC bytes: $(grep -a 'mark.txt' <<<"$LIST" | head -1 | cat -v)"
  else
    pass "'ray files' shows a name with escape sequences without emitting them"
  fi
fi

on "$B" "mkdir -p $OPH/names && chown $OP: $OPH/names"
for n in "$N_DOT" "$N_DOTS" "$N_CTL" "$N_ESC"; do
  shown="$(printf '%q' "$n")"
  if ID="$(wait_offer "$n")"; then
    accept_as "$OP" "$ID" "$OPH/names"
    [[ $RC -eq 0 ]] && pass "accepted $shown" || { fail "accepting $shown failed"; echo "$OUT" | cat -v | indent alice; }
  else
    fail "$shown never reached srv-b"
  fi
done
WANT="$(for n in "$N_DOT" "$N_DOTS" "$N_CTL" "$N_ESC"; do hexof "$n"; echo; done | LC_ALL=C sort | tr '\n' ' ')"
GOT="$(hexnames "$B" "$OPH/names")"
[[ "${GOT% }" == "${WANT% }" ]] && pass "dot, double-dot and control-character names are saved byte for byte" \
  || fail "saved names differ: want [$WANT] got [$GOT]"
for n in "$N_DOT" "$N_CTL"; do
  read -r own _ <<<"$(owner_mode "$B" "$OPH/names/$n")"
  [[ "$own" == "$OP:$OP" ]] && pass "$(printf '%q' "$n") is $OP's" || fail "$(printf '%q' "$n") is owned by '$own'"
done

# ---------------------------------------------------------------------------
step "9. auto-accept writes only where root configured it, as that user"
for id in $(files_json "$B" | jq -r '.pending[].id'); do on "$B" "ray files reject $id" >/dev/null; done
OUT="$(on "$B" "ray files auto-accept add srv-a && ray files download-user $OP && ray files download-dir $OPH/auto/in" 2>&1)" \
  && pass "root enabled auto-accept from srv-a into $OPH/auto/in for $OP" \
  || { fail "auto-accept setup failed"; echo "$OUT" | indent b; }

# send_auto <name> : srv-a's root sends a fresh file; echo its sha256.
send_auto(){
  local sha
  sha="$(make_file "$A" root "/root/$1")"
  on "$A" "ray send srv-b /root/$1" >/dev/null 2>&1
  echo "$sha"
}

SHA="$(send_auto fa-auto1.bin)"
if retry_until 90 "[[ \"\$(sha_of '$B' '$OPH/auto/in/fa-auto1.bin')\" == '$SHA' ]]"; then
  pass "an auto-accepted file lands in the configured directory, bytes intact"
  for d in auto auto/in auto/in/fa-auto1.bin; do
    read -r own mode _ <<<"$(owner_mode "$B" "$OPH/$d")"
    [[ "$own" == "$OP:$OP" ]] && mode_safe "${mode:-777}" && pass "$d is $OP's ($own $mode)" \
      || fail "$d is '$own' mode '$mode', not $OP's"
  done
  [[ -z "$(offer_id fa-auto1.bin)" ]] && pass "and it did not stay queued" || fail "fa-auto1.bin is still queued"
else
  fail "fa-auto1.bin was not auto-accepted into $OPH/auto/in"
fi

# The download user replaced part of the configured path with a link to a
# directory that is not theirs: no write there, the offer stays queued.
on "$B" "mkdir -p /etc/e2e-autodst && ln -sfn /etc/e2e-autodst $OPH/auto-link && chown -h $OP: $OPH/auto-link"
on "$B" "ray files download-dir $OPH/auto-link" >/dev/null
SINCE="$(on "$B" 'date +%s' | tr -d '[:space:]')"
send_auto fa-auto2.bin >/dev/null
if retry_until 90 "on '$B' \"journalctl -u rayfish --since @$SINCE --no-pager -o cat | grep -q 'file auto-accept failed'\""; then
  pass "auto-accept through a link to a root-owned dir is refused"
  on "$B" "journalctl -u rayfish --since @$SINCE --no-pager -o cat | grep 'file auto-accept failed' | head -1" | indent b
else
  fail "no auto-accept refusal logged for a link to /etc/e2e-autodst"
fi
[[ -z "$(on "$B" 'ls -A /etc/e2e-autodst')" ]] && pass "nothing was written in /etc/e2e-autodst" \
  || fail "auto-accept wrote into /etc/e2e-autodst: $(on "$B" 'ls -A /etc/e2e-autodst')"
[[ -n "$(offer_id fa-auto2.bin)" ]] && pass "the offer stays queued for a manual accept" \
  || fail "fa-auto2.bin is not queued after the refused auto-accept"

# A link that ends on the download user's own directory is fine.
on "$B" "mkdir -p $OPH/auto-real && chown $OP: $OPH/auto-real && ln -sfn $OPH/auto-real $OPH/auto-ownlink && chown -h $OP: $OPH/auto-ownlink"
on "$B" "ray files download-dir $OPH/auto-ownlink" >/dev/null
SHA="$(send_auto fa-auto3.bin)"
if retry_until 90 "[[ \"\$(sha_of '$B' '$OPH/auto-real/fa-auto3.bin')\" == '$SHA' ]]"; then
  read -r own _ <<<"$(owner_mode "$B" "$OPH/auto-real/fa-auto3.bin")"
  [[ "$own" == "$OP:$OP" ]] && pass "a link to the user's own dir is followed; the file is $OP's" \
    || fail "fa-auto3.bin is owned by '$own'"
else
  fail "fa-auto3.bin was not auto-accepted through a link to $OP's own dir"
fi

# With neither set, the operator's ~/Downloads is the fallback.
on "$B" "ray files download-dir --clear && ray files download-user --clear && rm -rf $OPH/Downloads" >/dev/null
SHA="$(send_auto fa-auto4.bin)"
if retry_until 90 "[[ \"\$(sha_of '$B' '$OPH/Downloads/fa-auto4.bin')\" == '$SHA' ]]"; then
  read -r own _ <<<"$(owner_mode "$B" "$OPH/Downloads/fa-auto4.bin")"
  read -r down _ <<<"$(owner_mode "$B" "$OPH/Downloads")"
  [[ "$own" == "$OP:$OP" && "$down" == "$OP:$OP" ]] \
    && pass "with no download-dir/user the operator's ~/Downloads is used, created and owned by $OP" \
    || fail "fallback ownership: dir='$down' file='$own'"
else
  fail "fa-auto4.bin was not auto-accepted into the operator's ~/Downloads"
fi
on "$B" "ray files auto-accept remove srv-a" >/dev/null

# ---------------------------------------------------------------------------
step "10. daemon logs: no panic, no crash restart"
for h in "$A" "$B"; do
  log="$(on "$h" 'journalctl -u rayfish --no-pager -o cat')"
  [[ -n "$log" ]] || { fail "$h: empty journal"; continue; }
  panics="$(grep -cE 'panicked at|panic: ' <<<"$log")"
  [[ "$panics" == 0 ]] && pass "$h logged no panic" \
    || { fail "$h logged $panics panic line(s)"; grep -E 'panicked at|panic: ' <<<"$log" | head -3 | sed 's/^/      /'; }
  crashes="$(on "$h" "journalctl -u rayfish --no-pager | grep -c 'Scheduled restart job'" | tr -d '[:space:]')"
  [[ "$crashes" == 0 ]] && pass "$h never crash-restarted" || fail "$h crash-restarted ${crashes:-?} time(s)"
done

summary
