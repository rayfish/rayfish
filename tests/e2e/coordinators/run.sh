#!/usr/bin/env bash
# Multi-coordinator networks under edits, restarts and racing joins.
#
# Topology, one closed network `coord`:
#   srv-a  creates it, coordinator
#   srv-b  member promoted with `ray admin add`, coordinator
#   srv-c  member promoted with `ray admin add`, coordinator (renamed srv-cc in 1d)
#   srv-d  member: the observer for rollbacks and the restart target of check 4
#   srv-e  member admitted and kicked by different coordinators, then the racing
#          joiner of checks 5 and 6
#
# Checks:
#   1. an edit on each coordinator in turn (A admits E, B kicks E, C admits E,
#      C renames itself) reaches every coordinator and member in bounded time,
#      printed per host
#   2. the creating coordinator restarts, B kicks E (offline), and A drops E
#      before its own first renewal could have told it
#   3. lagging coordinator: B is cut off, A renames itself, D restarts with only
#      B reachable. D must not roll back to the old roster from B, and holds the
#      newer one after B catches up. D's saved record floor never goes down
#   4. D restarts three ways (systemctl restart, kill -9, ray down/up) and keeps
#      the network in config and status, with its record floor present and not
#      going down
#   5. E runs `ray join <key> --name ra` and `--name rb` at once: one wins, the
#      other is refused, the network shows once, and leaving it leaves nothing.
#      Then a join under a third name races the restore of the first
#   6. E leaves and rejoins under the same name right away (new hostname): after
#      30 s no host holds the old name, and E's roster matches the coordinators'
#   7. every daemon log: no panic, no crash restart, no repeated protocol error
#
# Isolation ("cut") is a set of tc drop filters that keep ARP, the runner's SSH
# session and an allowlist of fleet addresses. A cut host loses the relays and
# the pkarr relay too, so the only path left is the direct one to the allowlist.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS, run '$ROOT/tests/e2e.sh coordinators provision' first"; exit 1; }
A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
D="$(server_ip "$SERVERS" srv-d || true)"
E="$(server_ip "$SERVERS" srv-e || true)"
[[ -n "$A" && -n "$B" && -n "$C" && -n "$D" && -n "$E" ]] || { echo "missing srv-a..srv-e in $SERVERS"; exit 1; }
ALL=("$A" "$B" "$C" "$D" "$E")
declare -A NAME=([$A]=srv-a [$B]=srv-b [$C]=srv-c [$D]=srv-d [$E]=srv-e)

NET=coord
# A coordinator renews its record every RECORD_TTL / 2 = 150 s and polls the
# record every 60 s. An edit has to land well inside one renewal.
EDIT_WAIT="${COORD_EDIT_WAIT:-120}"
RENEWAL=150


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------

# roster_names <ip> : sorted hostnames <ip> knows on $NET, itself included.
# Empty when the network is absent or status cannot be read.
roster_names(){
  status_json "$1" | jq -r --arg n "$NET" '
    (.networks // []) | map(select(.name == $n)) | .[0]
    | if . == null then "" else ([.my_hostname] + [.peers[].hostname]) | map(select(. != null)) | sort | join(",") end' 2>/dev/null
}

# c_has <ip> <host> / c_lacks <ip> <host> / c_gone <ip> _ : convergence
# conditions. c_lacks needs the network present, so an absent network is not
# taken for a dropped peer.
c_has(){ [[ ",$(roster_names "$1")," == *",$2,"* ]]; }
c_lacks(){ local r; r="$(roster_names "$1")"; [[ -n "$r" && ",$r," != *",$2,"* ]]; }
c_gone(){ net_absent "$1" "$NET"; }

# converge <secs> <what> <cond> <arg> <ip...> : poll every host until <cond>
# holds on it, timing each from T0 (set by the caller right before the edit).
# PASS/FAIL per host with its time. Sets CONV_MAX to the slowest time.
converge(){
  local secs="$1" what="$2" cond="$3" arg="$4"; shift 4
  local -A took=()
  local end=$((T0 + secs)) ip left
  while :; do
    left=0
    for ip in "$@"; do
      [[ -n "${took[$ip]:-}" ]] && continue
      if "$cond" "$ip" "$arg"; then took[$ip]=$((SECONDS - T0)); else left=1; fi
    done
    (( left == 0 || SECONDS >= end )) && break
    sleep 2
  done
  CONV_MAX=0
  for ip in "$@"; do
    if [[ -n "${took[$ip]:-}" ]]; then
      pass "${NAME[$ip]}: $what after ${took[$ip]}s"
      (( took[$ip] > CONV_MAX )) && CONV_MAX=${took[$ip]}
    else
      fail "${NAME[$ip]}: $what did not happen within ${secs}s (roster [$(roster_names "$ip")])"
    fi
  done
}

# floor <ip> : the record floor saved in <ip>'s network config, or empty.
floor(){
  on "$1" "sed -n 's/^last_record_timestamp = \([0-9]\+\).*/\1/p' /etc/rayfish/networks/$NET.toml 2>/dev/null" | tr -d '[:space:]'
}

# check_floor <ip> <when> : the saved floor is present and not below the
# highest value seen on that host so far.
declare -A FLOOR_MAX
check_floor(){
  local ip="$1" when="$2" f prev
  f="$(floor "$ip")"
  prev="${FLOOR_MAX[$ip]:-0}"
  if [[ ! "$f" =~ ^[0-9]+$ ]]; then
    fail "${NAME[$ip]} has no saved record floor $when"
  elif (( f < prev )); then
    fail "${NAME[$ip]}'s record floor went down $when ($prev -> $f)"
  else
    pass "${NAME[$ip]}'s record floor is present and did not go down $when ($f)"
    FLOOR_MAX[$ip]=$f
  fi
}

# join_with_invite <coord-ip> <joiner-ip> <hostname> : mint a hostname-bound
# invite on the coordinator and join with it.
join_with_invite(){
  local code; code="$(mint_invite "$1" "$NET" "$3")"
  [[ -n "$code" ]] || { fail "no invite minted on ${NAME[$1]} for $3"; return 1; }
  on "$2" "timeout 120 ray join $code --hostname $3" 2>&1 | strip | sed "s/^/   $3| /"
}

# restart_daemon <ip> : systemctl restart, wait for IPC, re-activate.
restart_daemon(){
  on "$1" 'systemctl restart rayfish' >/dev/null 2>&1 || return 1
  retry_until 60 "daemon_ready '$1'" || return 1
  on "$1" 'ray up' >/dev/null 2>&1 || true
  retry_until 30 "status_json '$1' | jq -e '.active == true' >/dev/null 2>&1"
}

# net_live <ip> : the network is registered (in `networks`, not only saved).
net_live(){ has_net "$1" "$NET"; }

# config_saved <ip> [name] : the network's config file exists.
config_saved(){ on "$1" "test -f /etc/rayfish/networks/${2:-$NET}.toml"; }

# key_count <ip> <key> : how many registered or saved-but-inactive networks on
# <ip> carry the network key <key>.
key_count(){
  status_json "$1" | jq -r --arg k "$2" '
    ([(.networks // [])[] | select(.network_key == $k)] | length)
    + ([(.inactive_networks // [])[] | select((.saved.network_key // "") == $k)] | length)' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------

ether_devs(){
  on "$1" "ip -o link show | awk -F': ' '/link\\/ether/ {print \$2}' | cut -d@ -f1" 2>/dev/null
}

# isolate <ip> [allowed-ip...] : drop everything on the host's ethernet interfaces
# except ARP, the runner's SSH session and the listed (IPv4) fleet addresses.
# The daemon keeps running and sees silence from everyone else, the relays and
# the pkarr relay included.
isolate(){
  local ip="$1"; shift
  local runner dev d dir peer prio
  runner="$(on "$ip" 'echo ${SSH_CLIENT%% *}')"
  [[ -n "$runner" && "$runner" != *:* ]] || { echo "   cannot tell the runner's IPv4 address on $ip"; return 1; }
  for dev in $(ether_devs "$ip"); do
    on "$ip" "tc qdisc del dev $dev clsact 2>/dev/null; tc qdisc add dev $dev clsact" || return 1
    for d in ingress egress; do
      if [[ "$d" == ingress ]]; then dir=src; else dir=dst; fi
      on "$ip" "tc filter add dev $dev $d prio 1 protocol arp matchall action pass \
        && tc filter add dev $dev $d prio 2 protocol ip u32 match ip $dir $runner/32 action pass" || return 1
      prio=3
      for peer in "$@"; do
        on "$ip" "tc filter add dev $dev $d prio $prio protocol ip u32 match ip $dir $peer/32 action pass" || return 1
        prio=$((prio + 1))
      done
      on "$ip" "tc filter add dev $dev $d prio 99 protocol all matchall action drop" || return 1
    done
  done
}
unisolate(){
  local dev
  for dev in $(ether_devs "$1"); do on "$1" "tc qdisc del dev $dev clsact 2>/dev/null"; done
  return 0
}

# A failed run must not leave a host cut off.
cleanup(){ local h; for h in "${ALL[@]}"; do unisolate "$h" >/dev/null 2>&1; done; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Logs. Deliberate isolation produces warnings by design (failed publishes,
# refused replays), so the repeated-error sweep leaves those windows out.
# Panics and crash restarts are checked over the whole run.
# ---------------------------------------------------------------------------

declare -A SINCE WINDOWS EXPECTED_RESTARTS
host_now(){ on "$1" "date -u '+%Y-%m-%d %H:%M:%S'" | tr -d '\r'; }
# window_open <ip...> / window_close <ip...> : mark a window to leave out.
declare -A WOPEN
window_open(){ local h; for h in "$@"; do WOPEN[$h]="$(host_now "$h")"; done; }
window_close(){ local h; for h in "$@"; do WINDOWS[$h]+="${WOPEN[$h]}|$(host_now "$h");"; done; }

journal(){ on "$1" "journalctl -u rayfish --utc --since '${SINCE[$1]}' --no-pager -o cat 2>/dev/null"; }
# journal_outside <ip> : the journal since SINCE minus the marked windows.
journal_outside(){
  local ip="$1" from="${SINCE[$1]}" w a b
  IFS=';' read -ra ws <<< "${WINDOWS[$ip]:-}"
  for w in "${ws[@]}"; do
    [[ -n "$w" ]] || continue
    a="${w%%|*}"; b="${w##*|}"
    on "$ip" "journalctl -u rayfish --utc --since '$from' --until '$a' --no-pager -o cat 2>/dev/null"
    from="$b"
  done
  on "$ip" "journalctl -u rayfish --utc --since '$from' --no-pager -o cat 2>/dev/null"
}
restart_lines(){ on "$1" "journalctl -u rayfish --utc --since '${SINCE[$1]}' --no-pager 2>/dev/null | grep -c 'Scheduled restart job'" | tr -d '[:space:]'; }

# ---------------------------------------------------------------------------
step "0. deploy, srv-a creates $NET, srv-b/c/d join, srv-b and srv-c become coordinators"
wait_all_ssh "${ALL[@]}"
seed_known_hosts "${ALL[@]}"
reset_state "${ALL[@]}"
deploy_all "$ROOT" "${ALL[@]}"
activate_daemons "${ALL[@]}" || summary
for h in "${ALL[@]}"; do
  SINCE[$h]="$(host_now "$h")"
  [[ -n "${SINCE[$h]}" ]] || { echo "could not read the clock on $h"; exit 1; }
done

CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   srv-a| /'
echo "$CREATE" | grep -q 'ray join' && pass "srv-a created $NET" || { fail "create $NET failed"; summary; }
NET_KEY="$(status_json "$A" | jq -r --arg n "$NET" '.networks[] | select(.name == $n) | .network_key // empty')"
[[ -n "$NET_KEY" ]] || { fail "srv-a reports no network key for $NET"; summary; }
join_with_invite "$A" "$B" srv-b
join_with_invite "$A" "$C" srv-c
join_with_invite "$A" "$D" srv-d
T0=$SECONDS
converge 150 "roster is srv-a,srv-b,srv-c,srv-d" c_has srv-d "$A" "$B" "$C"
converge 150 "roster is srv-a,srv-b,srv-c,srv-d" c_has srv-c "$D"

for p in "$B" "$C"; do
  id="$(peer_endpoint "$A" "${NAME[$p]}" "$NET")"
  [[ -n "$id" ]] || { fail "could not resolve ${NAME[$p]}'s id on srv-a"; summary; }
  on "$A" "ray admin $NET add $id" 2>&1 | strip | sed 's/^/   srv-a| /'
  if retry_until 90 "[[ \"\$(net_role '$p' '$NET')\" == coordinator ]] && holds_key '$p' '$NET'"; then
    pass "${NAME[$p]} is a coordinator of $NET"
  else
    fail "promotion of ${NAME[$p]} did not land"; summary
  fi
done
n="$(on "$A" "ray admin $NET list --json" | jq 'length' 2>/dev/null)"
[[ "$n" == 3 ]] && pass "srv-a lists three key holders" || fail "srv-a lists '$n' key holders, want 3"
for h in "$A" "$B" "$C" "$D"; do check_floor "$h" "after setup"; done

# ---------------------------------------------------------------------------
step "1. an edit on each coordinator in turn converges everywhere (bound ${EDIT_WAIT}s)"
echo "   1a. srv-a admits srv-e"
T0=$SECONDS
join_with_invite "$A" "$E" srv-e
converge "$EDIT_WAIT" "has srv-e" c_has srv-e "$A" "$B" "$C" "$D"
converge "$EDIT_WAIT" "srv-e sees the whole roster" c_has srv-d "$E"

echo "   1b. srv-b kicks srv-e"
T0=$SECONDS
on "$B" "ray kick $NET srv-e --yes" 2>&1 | strip | sed 's/^/   srv-b| /'
converge "$EDIT_WAIT" "dropped srv-e" c_lacks srv-e "$A" "$B" "$C" "$D"
converge "$EDIT_WAIT" "left $NET after the kick" c_gone _ "$E"

echo "   1c. srv-c admits srv-e again"
T0=$SECONDS
join_with_invite "$C" "$E" srv-e
converge "$EDIT_WAIT" "has srv-e" c_has srv-e "$A" "$B" "$C" "$D"

echo "   1d. srv-c renames itself to srv-cc"
T0=$SECONDS
on "$C" "ray hostname $NET srv-cc" 2>&1 | strip | sed 's/^/   srv-c| /'
converge "$EDIT_WAIT" "has srv-cc" c_has srv-cc "$A" "$B" "$C" "$D" "$E"
converge "$EDIT_WAIT" "no longer has srv-c" c_lacks srv-c "$A" "$B" "$D" "$E"
NAME[$C]=srv-cc
for h in "$A" "$B" "$C" "$D" "$E"; do check_floor "$h" "after the edits"; done

# ---------------------------------------------------------------------------
step "2. the creating coordinator restarts, then srv-b makes an edit"
# srv-e is cut off first, so the kick reaches srv-a only through the signed
# record (nothing srv-e says can tell srv-a), and srv-a ignores MemberSync as a
# coordinator. A restarted coordinator next renews (and so reads the record) at
# least RENEWAL seconds after it started: seeing the kick before that is the
# poller's doing.
window_open "$E"
isolate "$E" || { fail "could not cut srv-e off"; summary; }
T_RESTART=$SECONDS
restart_daemon "$A" && pass "srv-a restarted" || fail "srv-a did not come back from a restart"
retry_until 60 "[[ \"\$(net_role '$A' '$NET')\" == coordinator ]] && c_has '$A' srv-e" \
  && pass "srv-a restored $NET as coordinator ($((SECONDS - T_RESTART))s after the restart)" \
  || fail "srv-a did not restore $NET as coordinator with its full roster"
T0=$SECONDS
on "$B" "ray kick $NET srv-e --yes" 2>&1 | strip | sed 's/^/   srv-b| /'
bound=$((T_RESTART + RENEWAL - 5 - T0))
echo "   srv-b kicked srv-e $((T0 - T_RESTART))s after srv-a's restart; srv-a's first renewal is at least ${bound}s away"
converge "$bound" "dropped srv-e (before srv-a's first renewal)" c_lacks srv-e "$A"
converge "$EDIT_WAIT" "dropped srv-e" c_lacks srv-e "$C" "$D"
check_floor "$A" "after the restart"

# ---------------------------------------------------------------------------
step "3. lagging coordinator: srv-b is cut off, srv-a renames itself, srv-d reconnects to srv-b only"
# srv-b made the last edit (the kick), so the record it published matches its
# roster and is what it hands a reconnecting member. Cut off with srv-d still
# allowed, it cannot learn srv-a's rename.
window_open "$B" "$D"
isolate "$B" "$D" || { fail "could not cut srv-b off"; summary; }
T0=$SECONDS
on "$A" "ray hostname $NET srv-aa" 2>&1 | strip | sed 's/^/   srv-a| /'
converge "$EDIT_WAIT" "has srv-aa" c_has srv-aa "$A" "$C" "$D"
NAME[$A]=srv-aa
if c_has "$B" srv-a && c_lacks "$B" srv-aa; then
  pass "srv-b lags: it still has srv-a, not srv-aa"
else
  fail "srv-b is not lagging (roster [$(roster_names "$B")]), so this check proves nothing"
fi
check_floor "$D" "after the rename"
FLOOR_BEFORE="${FLOOR_MAX[$D]:-0}"

# Now srv-d may reach srv-b and nobody else of the coordinators. It keeps its
# internet, so it can still read the newer record from the pkarr relay.
window_open "$A" "$C"
isolate "$A" || fail "could not cut srv-a off"
isolate "$C" || fail "could not cut srv-c off"
D_RESTART="$(host_now "$D")"
restart_daemon "$D" && pass "srv-d restarted" || fail "srv-d did not come back from a restart"
if retry_until 120 "[[ \"\$(peer_online '$D' srv-b '$NET')\" == 1 ]]"; then
  pass "srv-d reconnected to srv-b, the only coordinator it can reach"
else
  fail "srv-d did not reconnect to srv-b"
fi
# Hold for 30 s: every sample must have the newer roster.
bad=""; end=$((SECONDS + 30))
while (( SECONDS < end )); do
  r="$(roster_names "$D")"
  [[ ",$r," == *",srv-aa,"* && ",$r," != *",srv-a,"* ]] || bad+="[$r]@$(date -u +%T) "
  f="$(floor "$D")"
  [[ "$f" =~ ^[0-9]+$ ]] && (( f >= FLOOR_BEFORE )) || bad+="floor=$f@$(date -u +%T) "
  sleep 3
done
if [[ -z "$bad" ]]; then
  pass "srv-d kept srv-aa and its record floor while connected only to the lagging srv-b"
else
  fail "srv-d rolled back to srv-b's older roster or floor: $bad"
fi
handed="$(on "$D" "journalctl -u rayfish --utc --since '$D_RESTART' --no-pager -o cat" | grep -c 'rejecting a signed record older than the last one applied')"
if [[ "$handed" =~ ^[1-9] ]]; then
  pass "srv-b handed srv-d its older record and srv-d refused it as a replay ($handed time(s))"
else
  skip "no replay refusal logged on srv-d: srv-b did not hand it a record, so the roll-back path was not exercised"
fi
check_floor "$D" "while connected only to srv-b"

for h in "$A" "$B" "$C"; do unisolate "$h"; done
window_close "$A" "$C"
T0=$SECONDS
converge "$EDIT_WAIT" "srv-b caught up (has srv-aa)" c_has srv-aa "$B"
converge 10 "srv-b dropped srv-a" c_lacks srv-a "$B"
window_close "$B" "$D"
converge 30 "still has srv-aa after srv-b caught up" c_has srv-aa "$D"
check_floor "$D" "after srv-b caught up"

# srv-e comes back: the kick from check 2 reaches it through the signed record.
unisolate "$E"
window_close "$E"
T0=$SECONDS
converge 180 "left $NET after the kick made while it was offline" c_gone _ "$E"

# ---------------------------------------------------------------------------
step "4. a restarted member keeps its network"
WANT_D="$(roster_names "$A")"
echo "   roster on srv-aa: [$WANT_D]"
d_member_back(){
  retry_until 90 "net_live '$D'" || { fail "srv-d does not list $NET after $1"; return; }
  config_saved "$D" && pass "srv-d still has $NET in config after $1" || fail "srv-d lost $NET's config after $1"
  if retry_until 90 "[[ \"\$(roster_names '$D')\" == '$WANT_D' ]]"; then
    pass "srv-d lists $NET with the full roster after $1"
  else
    fail "srv-d's roster after $1 is [$(roster_names "$D")], want [$WANT_D]"
  fi
  check_floor "$D" "after $1"
}
restart_daemon "$D" || fail "srv-d did not come back from systemctl restart"
d_member_back "systemctl restart"

before="$(restart_lines "$D")"
on "$D" 'systemctl kill -s KILL rayfish' >/dev/null 2>&1
if retry_until 60 "daemon_ready '$D'"; then
  pass "srv-d came back after kill -9 (systemd restarted it)"
else
  on "$D" 'systemctl start rayfish' >/dev/null 2>&1
  retry_until 60 "daemon_ready '$D'" && pass "srv-d started after kill -9" || fail "srv-d did not come back after kill -9"
fi
on "$D" 'ray up' >/dev/null 2>&1
after="$(restart_lines "$D")"
EXPECTED_RESTARTS[$D]=$(( ${EXPECTED_RESTARTS[$D]:-0} + ${after:-0} - ${before:-0} ))
d_member_back "kill -9"

on "$D" 'ray down' 2>&1 | strip | sed 's/^/   srv-d| /'
if retry_until 20 "status_json '$D' | jq -e '.active == false' >/dev/null 2>&1"; then
  pass "srv-d is in standby"
else
  fail "srv-d did not go to standby"
fi
config_saved "$D" && pass "srv-d keeps $NET in config while down" || fail "srv-d dropped $NET's config on ray down"
on "$D" 'ray up' 2>&1 | strip | sed 's/^/   srv-d| /'
retry_until 30 "status_json '$D' | jq -e '.active == true' >/dev/null 2>&1" || fail "srv-d did not come back up"
d_member_back "ray down / ray up"

# ---------------------------------------------------------------------------
step "5. racing joins on srv-e (out of $NET since check 3)"
REUSE="$(mint_reusable "$A" "$NET")"
[[ -n "$REUSE" ]] || { fail "no reusable key minted on srv-aa"; summary; }
on "$E" "rm -f /root/j-ra.log /root/j-rb.log
  (timeout 120 ray join $REUSE --name ra --hostname srv-e; echo rc=\$?) > /root/j-ra.log 2>&1 &
  (timeout 120 ray join $REUSE --name rb --hostname srv-e; echo rc=\$?) > /root/j-rb.log 2>&1 &
  wait"
OUT_A="$(on "$E" 'cat /root/j-ra.log' | strip)"
OUT_B="$(on "$E" 'cat /root/j-rb.log' | strip)"
echo "$OUT_A" | sed 's/^/   join ra| /'
echo "$OUT_B" | sed 's/^/   join rb| /'
RC_A="$(echo "$OUT_A" | sed -n 's/^rc=//p')"; RC_B="$(echo "$OUT_B" | sed -n 's/^rc=//p')"
WIN=""; LOSE_OUT=""
if [[ "$RC_A" == 0 && "$RC_B" != 0 ]]; then WIN=ra; LOSER=rb; LOSE_OUT="$OUT_B"
elif [[ "$RC_B" == 0 && "$RC_A" != 0 ]]; then WIN=rb; LOSER=ra; LOSE_OUT="$OUT_A"
fi
if [[ -n "$WIN" ]]; then
  pass "exactly one join won ($WIN), the other exited $([[ $WIN == ra ]] && echo "$RC_B" || echo "$RC_A")"
  if grep -qiE 'already (in this network|being joined)|being joined or restored|already in network' <<<"$LOSE_OUT"; then
    pass "the losing join was refused with a clear message: $(grep -iE 'already|being joined' <<<"$LOSE_OUT" | head -1)"
  else
    fail "the losing join failed without saying the network is already joined"
  fi
else
  fail "want exactly one winning join, got rc ra=$RC_A rb=$RC_B"
  WIN=ra; LOSER=rb
fi
if retry_until 60 "has_net '$E' '$WIN'"; then pass "srv-e is on the network as $WIN"; else fail "srv-e does not list $WIN"; fi
sleep 10
kc="$(key_count "$E" "$NET_KEY")"
[[ "$kc" == 1 ]] && pass "srv-e's status shows the network once" || fail "srv-e's status shows the network $kc times"
on "$E" "test ! -e /etc/rayfish/networks/$LOSER.toml" && pass "no config was saved for the losing name $LOSER" \
  || fail "a config for the losing name $LOSER was saved"
T0=$SECONDS
converge "$EDIT_WAIT" "has srv-e" c_has srv-e "$A" "$B" "$C" "$D"
for h in "$A" "$D"; do
  r="$(roster_names "$h")"
  if [[ "$(tr ',' '\n' <<<"$r" | grep -c '^srv-e')" == 1 ]]; then
    pass "${NAME[$h]} lists srv-e once ([$r])"
  else
    fail "${NAME[$h]} lists srv-e more than once ([$r])"
  fi
done

echo "   5b. a join under a third name races the restore of $WIN"
# A member restore runs beside the daemon's IPC, not before it, but a warm
# resume from the cached roster takes milliseconds. So the cache is marked
# unconfirmed (as after a crash before the publish was seen) and srv-e is cut
# off: the restore then takes the cold path and holds the network for the
# pkarr resolve timeout. The join is retried from the moment the daemon starts.
window_open "$E"
on "$E" "systemctl stop rayfish && sed -i 's/^last_group_hash_published = true/last_group_hash_published = false/' /etc/rayfish/networks/$WIN.toml"
on "$E" "grep -q '^last_group_hash_published = false' /etc/rayfish/networks/$WIN.toml" \
  || echo "   (no cached-roster flag to clear: the restore may take the warm path)"
isolate "$E" || fail "could not cut srv-e off"
on "$E" "rm -f /root/j-rc.log; systemctl start rayfish --no-block
  for i in \$(seq 1 400); do
    out=\$(timeout 60 ray join $REUSE --name rc --hostname srv-e 2>&1); rc=\$?
    case \"\$out\" in *daemon*not*running*|*onnection*refused*|*No*such*file*|*not*running*) sleep 0.05; continue ;; esac
    printf '%s\nrc=%s\n' \"\$out\" \"\$rc\" > /root/j-rc.log; break
  done"
OUT_C="$(on "$E" 'cat /root/j-rc.log 2>/dev/null' | strip)"
echo "$OUT_C" | sed 's/^/   join rc| /'
RC_C="$(echo "$OUT_C" | sed -n 's/^rc=//p')"
unisolate "$E"
retry_until 60 "daemon_ready '$E'" && on "$E" 'ray up' >/dev/null 2>&1
if [[ -z "$RC_C" ]]; then
  fail "the racing join never got an answer from the daemon"
elif [[ "$RC_C" == 0 ]]; then
  fail "a join under a third name succeeded while $WIN was saved: the network is joined twice"
elif grep -qi 'being joined or restored' <<<"$OUT_C"; then
  pass "the join landed during the restore and was refused"
elif grep -qi 'already in this network as' <<<"$OUT_C"; then
  pass "the join was refused as already joined"
  skip "the join landed after the restore had finished, so it did not race it"
else
  fail "the racing join failed for another reason"
fi
if retry_until 150 "has_net '$E' '$WIN'"; then pass "srv-e restored $WIN"; else fail "srv-e did not restore $WIN after the race"; fi
sleep 5
kc="$(key_count "$E" "$NET_KEY")"
[[ "$kc" == 1 ]] && pass "srv-e's status shows the network once after the race" || fail "srv-e's status shows the network $kc times after the race"
on "$E" "test ! -e /etc/rayfish/networks/rc.toml" && pass "no config was saved for rc" || fail "a config for rc was saved"
window_close "$E"

echo "   5c. leaving $WIN leaves no live copy"
IP_E="$(my_ip "$E" "$WIN")"
on "$E" "ray leave $WIN" 2>&1 | strip | sed 's/^/   srv-e| /'
if retry_until 30 "[[ \"\$(key_count '$E' '$NET_KEY')\" == 0 ]]"; then
  pass "srv-e's status no longer shows the network"
else
  fail "srv-e still shows the network after leaving $WIN"
fi
left="$(on "$E" "ls /etc/rayfish/networks/ 2>/dev/null | grep -E '^(ra|rb|rc)\.toml$'")"
[[ -z "$left" ]] && pass "no config is left for ra, rb or rc" || fail "configs left behind: $left"
T0=$SECONDS
converge "$EDIT_WAIT" "dropped srv-e after it left" c_lacks srv-e "$A" "$B" "$C" "$D"
IP_D="$(my_ip "$D" "$NET")"
if [[ -n "$IP_E" && -n "$IP_D" ]]; then
  if on "$E" "ping -c 2 -W 2 $IP_D" >/dev/null 2>&1; then
    fail "srv-e still reaches srv-d over the mesh after leaving: a copy is still up"
  else
    pass "srv-e no longer reaches srv-d over the mesh"
  fi
  if on "$D" "ping -c 2 -W 2 $IP_E" >/dev/null 2>&1; then
    fail "srv-d still reaches srv-e's old mesh address after it left"
  else
    pass "srv-d no longer reaches srv-e's old mesh address"
  fi
else
  fail "no mesh addresses to probe (srv-e '$IP_E', srv-d '$IP_D')"
fi

# ---------------------------------------------------------------------------
step "6. leave and rejoin under the same name right away"
on "$E" "timeout 120 ray join $REUSE --name $NET --hostname srv-e" 2>&1 | strip | sed 's/^/   srv-e| /'
retry_until 60 "has_net '$E' '$NET'" && pass "srv-e joined as $NET" || fail "srv-e did not join $NET"
T0=$SECONDS
converge "$EDIT_WAIT" "has srv-e" c_has srv-e "$A" "$B" "$C" "$D"
REJOIN_AT="$(host_now "$E")"
on "$E" "ray leave $NET && timeout 120 ray join $REUSE --name $NET --hostname srv-ee" 2>&1 | strip | sed 's/^/   srv-e| /'
retry_until 60 "has_net '$E' '$NET'" && pass "srv-e is back on $NET" || fail "srv-e is not back on $NET"
T0=$SECONDS
converge "$EDIT_WAIT" "has srv-ee" c_has srv-ee "$A" "$B" "$C" "$D" "$E"
echo "   waiting 30s for anything stale to come back"
sleep 30
WANT_E="$(roster_names "$A")"
for h in "${ALL[@]}"; do
  r="$(roster_names "$h")"
  if [[ ",$r," == *",srv-ee,"* && ",$r," != *",srv-e,"* && "$r" != *-1* ]]; then
    pass "${NAME[$h]} has srv-ee and no stale srv-e ([$r])"
  else
    fail "${NAME[$h]} has a stale or duplicated name ([$r])"
  fi
done
r="$(roster_names "$E")"
[[ "$r" == "$WANT_E" ]] && pass "srv-e's roster matches srv-aa's" || fail "srv-e's roster [$r] differs from srv-aa's [$WANT_E]"
kc="$(key_count "$E" "$NET_KEY")"
[[ "$kc" == 1 ]] && pass "srv-e's status shows the network once" || fail "srv-e's status shows the network $kc times"
[[ "$(status_json "$E" | jq -r --arg n "$NET" '.networks[] | select(.name == $n) | .my_hostname')" == srv-ee ]] \
  && pass "srv-e's own hostname is srv-ee" || fail "srv-e's own hostname is not srv-ee"
IP_EE="$(my_ip "$E" "$NET")"
if [[ -n "$IP_EE" ]] && retry_until 60 "on '$D' 'ping -c 2 -W 3 srv-ee.$NET.ray' >/dev/null 2>&1"; then
  pass "srv-d reaches srv-ee.$NET.ray"
else
  fail "srv-d cannot reach srv-ee.$NET.ray"
fi
# A name left from the old instance must go by the next group poll at the
# latest. If it is still there, give that poll its chance before failing.
old_name_resolves(){ on "$1" "getent ahosts srv-e.$NET.ray" 2>/dev/null | grep -qE '^2[0-9a-f]{2}:'; }
for h in "$A" "$B" "$C" "$D"; do
  if ! old_name_resolves "$h"; then
    pass "srv-e.$NET.ray no longer resolves on ${NAME[$h]}"
  elif retry_until 75 "! old_name_resolves '$h'"; then
    pass "srv-e.$NET.ray stopped resolving on ${NAME[$h]} after a group poll"
  else
    fail "${NAME[$h]} still answers srv-e.$NET.ray (and srv-ee) for srv-e's address 75s after a poll: a member that seats the rejoiner itself on its hello adds the new name without dropping the old one, and the next signed record matches its roster, so Magic DNS is never resynced"
  fi
done
stale="$(on "$E" "journalctl -u rayfish --utc --since '$REJOIN_AT' --no-pager -o cat" | grep -ciE 'already active|already in network|already being joined')"
[[ "$stale" == 0 ]] && pass "srv-e logged no clash with the old instance" || fail "srv-e logged $stale clash line(s) with the old instance"

# ---------------------------------------------------------------------------
step "7. daemon health and logs on every host"
PROTO='incompatible|does not decode|undecodable|do not match the signed hash|rejecting|older than the last one applied|from non-coordinator|could not fetch verified blob|no handler for ALPN|deserializ'
for h in "${ALL[@]}"; do
  log="$(journal "$h")" || { fail "${NAME[$h]}: could not read the journal"; continue; }
  [[ -n "$log" ]] || { fail "${NAME[$h]}: empty journal, so the checks below prove nothing"; continue; }
  daemon_ready "$h" && pass "${NAME[$h]} still answers IPC" || fail "${NAME[$h]} does not answer IPC"
  panics="$(grep -cE 'panicked at|panic: ' <<<"$log")"
  [[ "$panics" == 0 ]] && pass "${NAME[$h]} logged no panic" \
    || { fail "${NAME[$h]} logged $panics panic line(s)"; grep -E 'panicked at|panic: ' <<<"$log" | head -3 | sed 's/^/      /'; }
  crashes="$(restart_lines "$h")"
  extra=$(( ${crashes:-0} - ${EXPECTED_RESTARTS[$h]:-0} ))
  [[ "$extra" == 0 ]] && pass "${NAME[$h]} never crash-restarted (${EXPECTED_RESTARTS[$h]:-0} from the kill -9)" \
    || fail "${NAME[$h]} crash-restarted $extra time(s) beyond the kill -9"
  outside="$(journal_outside "$h")"
  repeats="$(grep -iE "$PROTO" <<<"$outside" | grep -E 'WARN|ERROR' \
    | sed -E 's/^[^ ]+ +(WARN|ERROR) +//; s/[0-9a-f]{10,}/<id>/g; s/[0-9]+/N/g' \
    | sort | uniq -c | sort -rn | awk '$1 >= 3')"
  if [[ -z "$repeats" ]]; then
    pass "${NAME[$h]} logged no repeated protocol error outside the isolation windows"
  else
    fail "${NAME[$h]} repeated protocol errors:"
    echo "$repeats" | head -8 | cut -c1-240 | sed 's/^/      /'
  fi
  once="$(grep -iE "$PROTO" <<<"$log" | grep -cE 'WARN|ERROR')"
  if [[ "$once" != 0 ]]; then
    echo "   ${NAME[$h]}: $once protocol warning line(s) in the whole run, last ones:"
    grep -iE "$PROTO" <<<"$log" | grep -E 'WARN|ERROR' | tail -3 | cut -c1-240 | sed 's/^/      /'
  fi
done

summary
