#!/usr/bin/env bash
# Interrupted file receives resume and finish correctly.
#
# Topology:
#   srv-a  coordinator of a closed network `files`; sends every file
#   srv-b  member; accepts and receives them
#
# Each check sends a fresh random file, accepts it with the real CLI
# (`ray files accept <id> --output <dir>`, backgrounded because it waits for
# the receive), interrupts it partway, and then requires that it finishes on
# its own: sha256 matches, the directory holds exactly the one file (no
# `.rayfish-*.part` left, no `name (1)` copy), the offer is not back in the
# queue, and the sender's view ends delivered rather than failed.
#
# Interruptions:
#   1. none (baseline)
#   2. the receiver loses its network while the daemon keeps running
#   3. lid close: the receiver's network is cut and its daemon frozen (SIGSTOP)
#   4. receiver `systemctl restart` mid-fetch
#   5. receiver `kill -9` mid-fetch, then start
#   6. receiver `kill -9` while the file is being written to its temp file
#   7. receiver `kill -9` right after the rename, before the delivery is recorded
#   8. sender `systemctl restart` mid-transfer
#   9. sender `kill -9` mid-transfer, then start
#  10. a 253-byte UTF-8 file name, saved shortened; a second copy is numbered
#
# The sender's egress is rate limited with tc so a transfer lasts long enough
# to interrupt. Network cuts are tc drop filters on the receiver that keep ARP
# and the runner's SSH session, so the harness can still drive the host.
#
# Reads tests/e2e/file-resume/.servers (written by provision). Re-runnable
# (resets rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS, run '$ROOT/tests/e2e.sh file-resume provision' first"; exit 1; }
A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

NET=files
SIZE_MB="${FR_SIZE_MB:-512}"    # size of the interrupted transfers
RATE="${FR_RATE:-160mbit}"      # sender egress limit, about 20 MB/s
OUTAGE="${FR_OUTAGE_SECS:-90}"  # how long a cut lasts after the first retry
SRC=/root/fr-src                # sender's files
RECV=/root/fr-recv              # receiver's output dirs, one per check
STATE=/etc/rayfish

skip(){ printf '  \033[33mSKIP\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Host helpers
# ---------------------------------------------------------------------------

# ether_devs <ip> : the host's ethernet interfaces (not lo, not the TUN).
ether_devs(){
  on "$1" "ip -o link show | awk -F': ' '/link\\/ether/ {print \$2}' | cut -d@ -f1" 2>/dev/null
}

# throttle <ip> / unthrottle <ip> : limit the host's egress on every ethernet
# interface, so the peer's pull is slow enough to interrupt.
throttle(){
  local dev
  for dev in $(ether_devs "$1"); do
    on "$1" "tc qdisc replace dev $dev root tbf rate $RATE burst 256kb latency 400ms" || return 1
  done
}
unthrottle(){
  local dev
  for dev in $(ether_devs "$1"); do on "$1" "tc qdisc del dev $dev root 2>/dev/null"; done
  return 0
}

# cut_net <ip> : drop every packet on the host's ethernet interfaces except
# ARP and traffic to and from the runner (its SSH session). The interface
# stays up and the daemon notices nothing but silence, like a laptop whose
# network went away. Both the direct path and the relays are gone.
cut_net(){
  local ip="$1" runner proto match bits dev d dir
  runner="$(on "$ip" 'echo ${SSH_CLIENT%% *}')"
  [[ -n "$runner" ]] || { echo "   cannot tell the runner's address on $ip"; return 1; }
  if [[ "$runner" == *:* ]]; then proto=ipv6; match=ip6; bits=128; else proto=ip; match=ip; bits=32; fi
  for dev in $(ether_devs "$ip"); do
    on "$ip" "tc qdisc del dev $dev clsact 2>/dev/null; tc qdisc add dev $dev clsact" || return 1
    for d in ingress egress; do
      if [[ "$d" == ingress ]]; then dir=src; else dir=dst; fi
      on "$ip" "tc filter add dev $dev $d prio 1 protocol arp matchall action pass \
        && tc filter add dev $dev $d prio 2 protocol $proto u32 match $match $dir $runner/$bits action pass \
        && tc filter add dev $dev $d prio 3 protocol all matchall action drop" || return 1
    done
  done
}
restore_net(){
  local dev
  for dev in $(ether_devs "$1"); do on "$1" "tc qdisc del dev $dev clsact 2>/dev/null"; done
  return 0
}

# A failed run must not leave a cloud host cut off or throttled.
cleanup(){ restore_net "$B" >/dev/null 2>&1; on "$B" 'systemctl kill -s CONT rayfish' >/dev/null 2>&1; unthrottle "$A" >/dev/null 2>&1; }
trap cleanup EXIT

daemon_pid(){ on "$1" 'systemctl show -p MainPID --value rayfish' 2>/dev/null | tr -d '[:space:]'; }

# bring_back <ip> : after a stop or a kill, make sure the daemon runs again,
# answers IPC and is active.
bring_back(){
  on "$1" 'systemctl is-active -q rayfish || systemctl start rayfish' >/dev/null 2>&1
  if retry_until 60 "daemon_ready '$1'"; then
    on "$1" 'ray up' >/dev/null 2>&1
    return 0
  fi
  fail "daemon on $1 did not come back"
  return 1
}

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

files_json(){ on "$1" 'timeout --kill-after=2s 15s ray files --json' 2>/dev/null; }

# make_src <name> <bytes> : a random file on srv-a; echo its sha256.
make_src(){
  on "$A" "mkdir -p $SRC && head -c $2 /dev/urandom > '$SRC/$1' && sha256sum '$SRC/$1' | cut -d' ' -f1"
}

# offer_id <name> : the receiver's pending offer id for <name>, or empty.
offer_id(){
  files_json "$B" | jq -r --arg f "$1" '[.pending[] | select(.filename == $f)] | .[0].id // empty'
}

# send_and_accept <name> <dir> : srv-a sends <name>, srv-b accepts it into
# <dir> in the background. Sets OFFER. Returns 1 when either step fails.
send_and_accept(){
  local name="$1" dir="$2"
  OFFER=""
  on "$A" "ray send srv-b '$SRC/$name'" 2>&1 | strip | sed 's/^/      send| /'
  # A send right after a restart can be queued until the peer reconnects.
  if ! retry_until 150 "[[ -n \"\$(offer_id '$name')\" ]]"; then
    fail "no offer for $name reached srv-b"; return 1
  fi
  OFFER="$(offer_id "$name")"
  on "$B" "rm -rf '$dir' && mkdir -p '$dir'" || { fail "cannot create $dir on srv-b"; return 1; }
  # Its own command: a backgrounded `a && b &` list would keep ssh's output
  # open, and this call would wait for the whole receive.
  on "$B" "setsid nohup ray files accept $OFFER --output '$dir' > /root/fr-accept-$OFFER.log 2>&1 < /dev/null &"
  return 0
}

# recv_row <name> : the receiver's newest incoming transfer for <name> as
# `state transferred size error`, state lowercased.
recv_row(){
  files_json "$B" | jq -r --arg f "$1" '
    [.transfers[] | select(.outgoing == false and .filename == $f)] | last
    | if . == null then empty
      else "\(.state | ascii_downcase) \(.transferred) \(.size) \(.error // "")" end'
}

# send_rows <name> : the sender's transfers for <name>, one `state error` line each.
send_rows(){
  files_json "$A" | jq -r --arg f "$1" '
    .transfers[] | select(.outgoing == true and .filename == $f)
    | "\(.state | ascii_downcase) \(.error // "")"'
}

# wait_partway <name> <pct> : poll every second until the receive of <name>
# has at least <pct>% (and not all) of the bytes. Echoes the bytes received.
wait_partway(){
  local name="$1" pct="$2" row state got size end=$((SECONDS + 180))
  while (( SECONDS < end )); do
    row="$(recv_row "$name")"
    read -r state got size _ <<< "$row"
    if [[ "${state:-}" == transferring && "${size:-0}" -gt 0 ]]; then
      if (( got * 100 >= pct * size )); then
        if (( got < size )); then echo "$got"; return 0; fi
        return 1
      fi
    elif [[ "${state:-}" == done || "${state:-}" == failed ]]; then
      return 1
    fi
    sleep 1
  done
  return 1
}

# saved <dir> <name> <bytes> : the file is in place at full size and no temp
# file is left beside it.
saved(){
  on "$B" "[ \"\$(stat -c %s '$1/$2' 2>/dev/null)\" = '$3' ] \
    && ! ls -A '$1' | grep -q '^\.rayfish-.*\.part\$'" 2>/dev/null
}

# retry_lines <since-epoch> : how many times srv-b logged a receive retry.
retry_lines(){
  on "$B" "journalctl -u rayfish --since @$1 --no-pager -o cat | grep -c 'file receive interrupted; retrying'" 2>/dev/null \
    | tr -d '[:space:]'
}

# sender_delivered <name> : the sender recorded the delivery (the send left
# its outbox) and lists nothing for it as failed.
sender_delivered(){
  local outbox rows
  outbox="$(on "$A" "cat $STATE/outbox.json 2>/dev/null || echo []")" || return 1
  echo "$outbox" | jq -e --arg f "$1" 'type == "array" and all(.[]; .filename != $f)' >/dev/null 2>&1 || return 1
  rows="$(send_rows "$1")"
  ! grep -q '^failed' <<< "$rows"
}

# verify <label> <dir> <name> <sha> : the end state every check shares.
verify(){
  local label="$1" dir="$2" name="$3" want="$4" got listing rows
  got="$(on "$B" "sha256sum '$dir/$name' 2>/dev/null | cut -d' ' -f1")"
  if [[ -n "$got" && "$got" == "$want" ]]; then
    pass "$label: sha256 matches (${want:0:12})"
  else
    fail "$label: sha256 mismatch (sent ${want:0:12}, got ${got:-nothing})"
  fi
  listing="$(on "$B" "ls -A '$dir'")"
  if [[ "$listing" == "$name" ]]; then
    pass "$label: exactly one file saved (no .part left, no numbered copy)"
  else
    fail "$label: unexpected directory contents: $(tr '\n' ' ' <<< "$listing")"
  fi
  if [[ -z "$(offer_id "$name")" ]]; then
    pass "$label: offer not back in the receiver's queue"
  else
    fail "$label: offer is queued again on the receiver"
  fi
  if retry_until 60 "sender_delivered '$name'"; then
    rows="$(send_rows "$name" | tr '\n' ';')"
    pass "$label: sender recorded the delivery (sender view: ${rows:-entry expired})"
    # A send whose pull was interrupted and then completed must not keep its
    # "interrupted" note next to `done`. A receiver `kill -9` (no connection
    # close) makes the old pull's abort arrive after the resumed pull started.
    if grep -q '^done .' <<< "$(send_rows "$name")"; then
      fail "$label: sender shows done with a stale note: $(grep '^done .' <<< "$(send_rows "$name")" | head -1)"
    fi
  else
    rows="$(send_rows "$name" | tr '\n' ';')"
    fail "$label: sender did not record the delivery (sender view: ${rows:-none})"
  fi
}

# finish <label> <dir> <name> <sha> <bytes> <secs> : wait for the file to land,
# then verify it and clean up both ends.
finish(){
  local label="$1" dir="$2" name="$3" sha="$4" bytes="$5" secs="$6" t0=$SECONDS
  if retry_until "$secs" "saved '$dir' '$name' '$bytes'"; then
    pass "$label: receive finished on its own (landed $((SECONDS - t0))s after the wait began)"
  else
    fail "$label: receive did not finish within ${secs}s (last: $(recv_row "$name"))"
    on "$B" "ls -la '$dir'; tail -3 /root/fr-accept-*.log" 2>&1 | sed 's/^/      b| /'
  fi
  verify "$label" "$dir" "$name" "$sha"
  on "$A" "rm -f '$SRC/$name'"
  on "$B" "rm -rf '$dir'"
}

# killer <mode> <dir> <name> : on srv-b, spin until the watched entry appears
# in <dir> and SIGKILL the daemon at that moment. mode `part`: the temp file
# (the blob is complete and being written out), once it holds 1 MiB; mode `final`: the file under
# its real name (the rename just happened). Prints what it found right after
# the kill, before systemd can restart the daemon.
install_killer(){
  on "$B" "cat > /root/fr-killer.sh <<'EOF'
#!/bin/bash
mode=\$1 dir=\$2 name=\$3
pid=\$(systemctl show -p MainPID --value rayfish)
shopt -s nullglob dotglob
end=\$((SECONDS + 600))
while (( SECONDS < end )); do
  if [[ \$mode == part ]]; then
    parts=(\"\$dir\"/.rayfish-*.part)
    (( \${#parts[@]} )) || continue
    # Wait for some data in it, so the leftover is a partial file, not an
    # empty one. If it is renamed first, report that instead.
    while [[ -e \${parts[0]} ]] && (( \$(stat -c %s \"\${parts[0]}\" 2>/dev/null || echo 0) < 1048576 )); do :; done
    kill -9 \"\$pid\"
    sleep 0.05
    f=\${parts[0]}
    if [[ -e \$f ]]; then echo \"LEFTOVER \${f##*/} \$(stat -c %s \"\$f\")\"; else echo GONE; fi
    exit 0
  else
    [[ -e \$dir/\$name ]] || continue
    kill -9 \"\$pid\"
    sleep 0.05
    if grep -q '\"saved_as\"' $STATE/pending-files.json 2>/dev/null; then echo UNRECORDED; else echo RECORDED; fi
    exit 0
  fi
done
echo TIMEOUT
exit 1
EOF
chmod +x /root/fr-killer.sh"
}

BYTES=$((SIZE_MB * 1048576))

# ---------------------------------------------------------------------------
step "0. deploy, create the network, srv-b joins"
wait_all_ssh "$A" "$B"
seed_known_hosts "$A" "$B"
reset_state "$A" "$B"
deploy_all "$ROOT" "$A" "$B"
activate_daemons "$A" "$B" || summary
on "$A" "ray create --name $NET --hostname srv-a" 2>&1 | strip | sed 's/^/   a| /'
INV_B="$(mint_invite "$A" "$NET" srv-b)"
[[ -n "$INV_B" ]] && pass "minted invite for srv-b" || { fail "invite mint failed"; summary; }
on "$B" "ray join $INV_B --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'
wait_roster "$A" srv-b
wait_roster "$B" srv-a
on "$B" "rm -rf $RECV /root/fr-accept-*.log"
on "$A" "rm -rf $SRC"
install_killer || { fail "could not install the kill helper on srv-b"; summary; }
if throttle "$A"; then
  pass "srv-a egress limited to $RATE"
else
  fail "could not rate-limit srv-a with tc"; summary
fi

# ---------------------------------------------------------------------------
step "1. baseline: a ${SIZE_MB} MiB file arrives intact"
NAME=baseline.bin; OUT="$RECV/1"
SHA="$(make_src "$NAME" "$BYTES")"
if send_and_accept "$NAME" "$OUT"; then
  if wait_partway "$NAME" 5 >/dev/null; then
    row="$(recv_row "$NAME")"
    pass "receiver lists it as transferring with progress: $(cut -d' ' -f1-3 <<< "$row")"
    human="$(on "$B" 'ray files' | strip)"
    if grep -q "$NAME (transferring)" <<< "$human"; then
      pass "'ray files' shows the receive in progress"
    else
      fail "'ray files' does not show the receive in progress"; sed 's/^/      b| /' <<< "$human"
    fi
    srow="$(send_rows "$NAME" | head -1)"
    [[ "$srow" == transferring* ]] && pass "sender lists it as transferring" \
      || fail "sender's view mid-transfer: '${srow:-none}'"
  else
    fail "baseline: never saw the receive in progress"
  fi
  finish "baseline" "$OUT" "$NAME" "$SHA" "$BYTES" 180
fi

# ---------------------------------------------------------------------------
# cut_check <label> <name> <dir> <freeze> : cut srv-b off partway, wait until it
# has failed and retried, keep it cut for $OUTAGE more seconds, restore.
# <freeze>=1 also stops the daemon process for the outage (a suspend).
cut_check(){
  local label="$1" name="$2" out="$3" freeze="$4" sha got since row n
  sha="$(make_src "$name" "$BYTES")"
  send_and_accept "$name" "$out" || return
  if ! got="$(wait_partway "$name" 25)"; then
    fail "$label: could not catch the receive partway"; return
  fi
  echo "   interrupting at $((got / 1048576)) MiB of $SIZE_MB"
  since="$(on "$B" 'date +%s')"
  cut_net "$B" || { fail "$label: could not cut srv-b's network"; restore_net "$B"; return; }
  if [[ "$freeze" == 1 ]]; then
    on "$B" 'systemctl kill -s STOP rayfish'
    echo "   srv-b network cut and daemon frozen for ${OUTAGE}s"
    sleep "$OUTAGE"   # the outage itself, not a wait for a condition
    restore_net "$B"
    on "$B" 'systemctl kill -s CONT rayfish'
    finish "$label" "$out" "$name" "$sha" "$BYTES" 300
    # The frozen connection must have died and been replaced, not survived.
    n="$(retry_lines "$since")"
    if [[ "${n:-0}" -ge 1 ]]; then
      pass "$label: the receive was interrupted and retried after waking ($n retries logged)"
    else
      fail "$label: no retry logged, so the outage never interrupted the receive"
    fi
    return
  else
    if retry_until 150 "[[ \"\$(recv_row '$name')\" == *'interrupted, retrying'* ]]"; then
      row="$(recv_row "$name")"
      if [[ "$row" == transferring* ]]; then
        pass "$label: receiver shows it as transferring, interrupted and retrying (not failed)"
      else
        fail "$label: receiver shows: $row"
      fi
    else
      fail "$label: receiver never reported the interruption (last: $(recv_row "$name"))"
    fi
    echo "   keeping srv-b offline for ${OUTAGE}s more"
    sleep "$OUTAGE"   # the outage itself, not a wait for a condition
    n="$(retry_lines "$since")"
    if [[ "${n:-0}" -ge 2 ]]; then
      pass "$label: retried $n times while offline"
    else
      fail "$label: expected repeated retries while offline, saw ${n:-0}"
    fi
    row="$(recv_row "$name")"
    [[ "$row" == transferring* ]] && pass "$label: still transferring, not failed, after ${OUTAGE}s offline" \
      || fail "$label: after the outage the receive shows: $row"
    on "$B" "ls -A '$out' | grep -q '^\.rayfish-.*\.part\$'" \
      && fail "$label: a temp file exists before the data is complete" \
      || pass "$label: nothing written to the output dir while the data is incomplete"
    restore_net "$B"
  fi
  finish "$label" "$out" "$name" "$sha" "$BYTES" 300
}

step "2. receiver loses its network mid-transfer, daemon keeps running"
cut_check "network cut" netcut.bin "$RECV/2" 0

step "3. lid close: receiver's network cut and daemon frozen mid-transfer"
cut_check "lid close" lidclose.bin "$RECV/3" 1

# ---------------------------------------------------------------------------
# restart_check <label> <name> <dir> <host> <how> : interrupt the transfer at
# 25% by restarting a daemon. <host> is the ip; <how> is `restart` or `kill`.
restart_check(){
  local label="$1" name="$2" out="$3" host="$4" how="$5" sha got pid row resumed_at
  sha="$(make_src "$name" "$BYTES")"
  send_and_accept "$name" "$out" || return
  if ! got="$(wait_partway "$name" 25)"; then
    fail "$label: could not catch the receive partway"; return
  fi
  echo "   interrupting at $((got / 1048576)) MiB of $SIZE_MB"
  if [[ "$host" == "$B" ]]; then
    if on "$B" "grep -F '\"accepted\"' $STATE/pending-files.json | grep -qF '\"filename\":\"$name\"'"; then
      pass "$label: accepted receive saved in pending-files.json"
    else
      fail "$label: pending-files.json does not record the accepted receive"
    fi
  fi
  if [[ "$how" == restart ]]; then
    on "$host" 'systemctl restart rayfish'
  else
    pid="$(daemon_pid "$host")"
    on "$host" "kill -9 $pid; systemctl start rayfish" >/dev/null 2>&1
  fi
  bring_back "$host" || return
  if [[ "$host" == "$B" ]]; then
    # The first reading after the restart is what the store kept: a receive
    # that started over would show a few MiB here, not most of what it had.
    if retry_until 30 "[[ \"\$(recv_row '$name' | cut -d' ' -f2)\" -gt 0 ]] 2>/dev/null"; then
      row="$(recv_row "$name")"
      resumed_at="$(cut -d' ' -f2 <<< "$row")"
      if [[ -z "$(offer_id "$name")" ]]; then
        pass "$label: receive restarted by itself, no second accept (state: $(cut -d' ' -f1 <<< "$row"))"
      else
        fail "$label: the offer went back to the queue"
      fi
      if (( resumed_at * 4 >= got * 3 )); then
        pass "$label: resumed at $((resumed_at / 1048576)) MiB (had $((got / 1048576)) MiB), not from zero"
      else
        fail "$label: resumed at $((resumed_at / 1048576)) MiB after having $((got / 1048576)) MiB"
      fi
    else
      fail "$label: no receive in progress after the restart"
    fi
  fi
  finish "$label" "$out" "$name" "$sha" "$BYTES" 240
}

step "4. receiver daemon restart (systemctl restart) mid-transfer"
restart_check "receiver restart" rrestart.bin "$RECV/4" "$B" restart

step "5. receiver daemon kill -9 mid-transfer, then start"
restart_check "receiver kill -9" rkill.bin "$RECV/5" "$B" kill

# ---------------------------------------------------------------------------
step "6. receiver kill -9 while writing the temp file: the resume replaces it"
NAME=writekill.bin; OUT="$RECV/6"
SHA="$(make_src "$NAME" "$BYTES")"
if send_and_accept "$NAME" "$OUT"; then
  SEEN="$(on "$B" "/root/fr-killer.sh part '$OUT'")"
  echo "   killer saw: $SEEN"
  case "$SEEN" in
    LEFTOVER*)
      LEFT="$(cut -d' ' -f2 <<< "$SEEN")"
      pass "daemon killed mid-write, left $LEFT ($(cut -d' ' -f3 <<< "$SEEN") of $BYTES bytes)"
      bring_back "$B"
      finish "write kill" "$OUT" "$NAME" "$SHA" "$BYTES" 180
      ;;
    GONE)
      skip "write kill: the temp file was renamed before the kill landed (write too fast to catch)"
      bring_back "$B"
      finish "write kill" "$OUT" "$NAME" "$SHA" "$BYTES" 180
      ;;
    *)
      fail "write kill: never saw a temp file in $OUT"
      bring_back "$B"
      ;;
  esac
fi

# ---------------------------------------------------------------------------
step "7. receiver kill -9 right after the rename: no second copy"
NAME=renamekill.bin; OUT="$RECV/7"
SHA="$(make_src "$NAME" "$BYTES")"
if send_and_accept "$NAME" "$OUT"; then
  SINCE="$(on "$B" 'date +%s')"
  SEEN="$(on "$B" "/root/fr-killer.sh final '$OUT' '$NAME'")"
  echo "   killer saw: $SEEN"
  case "$SEEN" in
    UNRECORDED)
      pass "daemon killed after the rename, before the delivery was recorded"
      bring_back "$B"
      if retry_until 60 "on '$B' \"journalctl -u rayfish --since @$SINCE --no-pager -o cat | grep -q 'found the file saved before a restart'\""; then
        pass "rename kill: the restarted receive found the saved file instead of fetching again"
      else
        fail "rename kill: the restarted receive did not report the saved file"
      fi
      ;;
    RECORDED)
      skip "rename kill: the delivery was recorded before the kill landed (window missed)"
      bring_back "$B"
      ;;
    *)
      fail "rename kill: never saw the file under its name"
      bring_back "$B"
      ;;
  esac
  [[ "$SEEN" == UNRECORDED || "$SEEN" == RECORDED ]] && finish "rename kill" "$OUT" "$NAME" "$SHA" "$BYTES" 120
fi

# ---------------------------------------------------------------------------
step "8. sender daemon restart (systemctl restart) mid-transfer"
restart_check "sender restart" srestart.bin "$RECV/8" "$A" restart

step "9. sender daemon kill -9 mid-transfer, then start"
restart_check "sender kill -9" skill.bin "$RECV/9" "$A" kill

# ---------------------------------------------------------------------------
step "10. a name too long to save as is gets shortened; a second copy is numbered"
# 83 three-byte characters plus `.bin`: 253 bytes, the most ext4 on the sender
# allows is 255, and the receiver keeps names to 249 so ` (999)` still fits.
LONG="$(python3 -c 'print("あ" * 83 + ".bin")')"
OUT="$RECV/10"
SHA="$(make_src "$LONG" 4194304)"
for copy in 1 2; do
  on "$A" "ray send srv-b '$SRC/$LONG'" 2>&1 | strip | sed 's/^/      send| /'
  if ! retry_until 60 "[[ -n \"\$(offer_id '$LONG')\" ]]"; then fail "long name: no offer (copy $copy)"; break; fi
  OFFER="$(offer_id "$LONG")"
  on "$B" "mkdir -p '$OUT' && timeout 120 ray files accept $OFFER --output '$OUT'" 2>&1 | strip | sed 's/^/      recv| /'
done
mapfile -t SAVED < <(on "$B" "find '$OUT' -mindepth 1 -maxdepth 1 -printf '%f\\n'")
echo "   saved: ${#SAVED[@]} file(s), byte lengths: $(for f in "${SAVED[@]}"; do printf '%s ' "$(printf '%s' "$f" | wc -c)"; done)"
if [[ ${#SAVED[@]} -eq 2 ]]; then
  FIRST="${SAVED[0]}"; SECOND="${SAVED[1]}"
  [[ "$FIRST" == *" (1).bin" ]] && { FIRST="${SAVED[1]}"; SECOND="${SAVED[0]}"; }
  STEM="${LONG%.bin}"; SHORT_STEM="${FIRST%.bin}"
  if (( $(printf '%s' "$FIRST" | wc -c) <= 249 )) && [[ "$FIRST" == *.bin && "$STEM" == "$SHORT_STEM"* && "$FIRST" != "$LONG" ]] \
     && python3 -c 'import sys; sys.argv[1].encode("utf-8", "strict")' "$FIRST" 2>/dev/null; then
    pass "long name: saved as a ${#FIRST}-character, $(printf '%s' "$FIRST" | wc -c)-byte prefix keeping .bin"
  else
    fail "long name: unexpected saved name '$FIRST'"
  fi
  if [[ "$SECOND" == "$SHORT_STEM (1).bin" ]]; then
    pass "long name: the second copy is '<short> (1).bin', $(printf '%s' "$SECOND" | wc -c) bytes"
  else
    fail "long name: second copy saved as '$SECOND'"
  fi
  for f in "$FIRST" "$SECOND"; do
    got="$(on "$B" "sha256sum '$OUT/$f' | cut -d' ' -f1")"
    [[ "$got" == "$SHA" ]] && pass "long name: content intact ($(printf '%s' "$f" | wc -c)-byte name)" \
      || fail "long name: content differs for '$f'"
  done
else
  fail "long name: expected two saved files, got: ${SAVED[*]:-none}"
fi
on "$A" "rm -f '$SRC/$LONG'"; on "$B" "rm -rf '$OUT'"

# ---------------------------------------------------------------------------
step "11. size mismatch"
skip "an offer whose blob differs from the offered size cannot be made with the real CLI (the daemon sizes the offer from the blob it imports); covered by the unit test a_blob_larger_than_offered_ends_the_receive"

# ---------------------------------------------------------------------------
step "12. no daemon panicked"
for h in "$A" "$B"; do
  n="$(on "$h" "journalctl -u rayfish --no-pager -o cat | grep -ci 'panicked'" | tr -d '[:space:]')"
  [[ "${n:-0}" == 0 ]] && pass "no panic logged on $h" || fail "$n panic line(s) logged on $h"
done

unthrottle "$A"
summary
