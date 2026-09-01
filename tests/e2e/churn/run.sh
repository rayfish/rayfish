#!/usr/bin/env bash
# Rayfish churn / lifecycle-under-churn end-to-end test.
#
# Topology:
#   srv-a  coordinator of a closed network `churn`
#   srv-b  member, the stable observer (never flaps). Every "did it converge"
#          assertion is read from here, so a check can't pass because the node
#          asking was itself mid-restart
#   srv-c  member, the one that is offline whenever something happens to the
#          roster. It is how the suite tells a *trigger* from the *source of
#          truth*: a node that missed the broadcast must still converge.
#   srv-d  member, the victim (kicked) and the data-plane flapper
#
# The other scenarios each take one lifecycle event on a quiet mesh. This one
# takes the events the quiet ones skip and runs them while the mesh is moving:
#
#   - repeated hard flap (`systemctl stop/start`) of one member, then of two at
#     once, with a full reconvergence + data-plane check after each round
#   - `ray down` / `ray up` flap: the data plane goes away and comes back while
#     the control plane never drops, which is a different code path from a
#     daemon restart and the one a laptop lid actually takes
#   - the same flap on a host with no `ip` binary at all: the link state is the
#     kernel's business (netlink), not a spawned process's, so a service PATH
#     without iproute2 must still bring the tunnel up, down and back
#   - a kick delivered while a member is offline. The kicked node must leave on
#     the signed record; the offline node must reach the same roster on its own
#     when it returns, having never seen the `MemberSync` that announced it
#   - a nuke delivered while a member is offline
#   - a health sweep: no panic, no unexpected service restart, no daemon left
#     unresponsive after all of it
#
# Reads tests/e2e/churn/.servers (written by provision.sh). Does NOT modify
# infra. Re-runnable (resets rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS, run $DIR/provision.sh first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
D="$(server_ip "$SERVERS" srv-d || true)"
[[ -n "$A" && -n "$B" && -n "$C" && -n "$D" ]] || { echo "missing srv-a/b/c/d in $SERVERS"; exit 1; }

NET=churn
ROUNDS="${ROUNDS:-3}"          # hard-flap rounds in step 2
DOWN_ROUNDS="${DOWN_ROUNDS:-3}" # ray down/up rounds in step 4

# ---------------------------------------------------------------------------
# Churn helpers. Every one of these is a *host* action plus the wait that makes
# the next assertion meaningful; the waits are here rather than inline so a
# round reads as the event it is.
# ---------------------------------------------------------------------------

# daemon_stop <ip> : take a node's whole daemon down (endpoint included).
daemon_stop(){ on "$1" 'systemctl stop rayfish' >/dev/null 2>&1 || true; }

# daemon_start <ip> : bring it back the way a boot does, and wait for IPC.
# `ray up` after the start: activation is not persisted across a stop in every
# path the suite exercises, and re-running it on an already-active daemon is a
# no-op. Mirrors tests/e2e/restore-offline.
daemon_start(){
  on "$1" 'systemctl start rayfish' >/dev/null 2>&1 || true
  # Wait for IPC *before* `ray up`, not after. A 1-vCPU droplet can take well
  # over a fixed sleep to bring up the TUN, bind the endpoint and dial its saved
  # networks; `ray up` then cannot reach the socket, `|| true` swallows it, and
  # the node comes back in standby. The control plane still converges, so
  # `wait_back` passes and only the data-plane assertions of that round fail.
  retry_until 60 "on '$1' 'ray status' >/dev/null 2>&1" || return 1
  on "$1" 'ray up' >/dev/null 2>&1 || true
  retry_until 30 "on '$1' 'ray status' >/dev/null 2>&1"
}

# wait_gone <observer-ip> <peer-host> <secs> : block until <observer> reports the
# peer offline. Returns non-zero on timeout so the caller decides pass/fail.
wait_gone(){ retry_until "$3" "[[ \"\$(peer_online '$1' '$2' '$NET')\" == 0 ]]"; }

# wait_back <observer-ip> <peer-host> <secs> : the same, for a peer coming back.
wait_back(){ retry_until "$3" "[[ \"\$(peer_online '$1' '$2' '$NET')\" == 1 ]]"; }

# wait_unlisted <observer-ip> <peer-host> <secs> : block until the peer is not in
# the roster at all (kicked), as opposed to listed-but-offline.
wait_unlisted(){ retry_until "$3" "[[ -z \"\$(peer_ip '$1' '$2' '$NET')\" ]]"; }

# ping_ok <from-ip> <target-vpn-ip> : 0 exit iff the target answers over the TUN.
ping_ok(){ on "$1" "ping -c 2 -W 3 $2" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all hosts"
wait_all_ssh "$A" "$B" "$C" "$D"
seed_known_hosts "$A" "$B" "$C" "$D"
reset_state "$A" "$B" "$C" "$D"
deploy_all "$ROOT" "$A" "$B" "$C" "$D"
for h in "$A" "$B" "$C" "$D"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B" "$C" "$D"

# The health sweep at the end reads the journal, and a `.servers` fleet is reused
# across runs by design, so without a floor one panic would fail every later run
# on that fleet forever. Read the host's own clock, not ours: `--since` is
# interpreted there.
declare -A SINCE
for h in "$A" "$B" "$C" "$D"; do
  SINCE[$h]="$(on "$h" "date -u '+%Y-%m-%d %H:%M:%S'" | tr -d '[:space:]\r')"
  [[ -n "${SINCE[$h]}" ]] || { echo "could not read the clock on $h"; exit 1; }
done

# ---------------------------------------------------------------------------
step "1. closed network, four nodes, full mesh"
CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
ROOM="$(echo "$CREATE" | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1)"
[[ -n "$ROOM" ]] && pass "network '$NET' created (room ${ROOM:0:12}…)" \
  || { fail "create failed"; summary; }

for pair in "B:srv-b" "C:srv-c" "D:srv-d"; do
  host="${pair%%:*}"; name="${pair##*:}"
  code="$(mint_invite "$A" "$NET" "$name")"
  [[ -n "$code" ]] || { fail "no invite minted for $name"; summary; }
  on "${!host}" "ray join $code --hostname $name" 2>&1 | strip | sed "s/^/   ${name}| /"
done

wait_roster "$A" srv-b srv-c srv-d
wait_roster "$B" srv-a srv-c srv-d

# Mesh addresses, resolved once. They derive from the identity and never rotate,
# so a kick or a restart cannot change them and every later step reuses these.
IP_A="$(my_ip "$A" "$NET")"; IP_B="$(my_ip "$B" "$NET")"
IP_C="$(my_ip "$C" "$NET")"; IP_D="$(my_ip "$D" "$NET")"
[[ -n "$IP_A" && -n "$IP_B" && -n "$IP_C" && -n "$IP_D" ]] \
  || { fail "could not read all four mesh addresses"; summary; }
echo "   a=$IP_A b=$IP_B c=$IP_C d=$IP_D"

png "$B" "$IP_C" "srv-b -> srv-c (baseline)"
png "$C" "$IP_D" "srv-c -> srv-d (baseline)"
png "$D" "$IP_A" "srv-d -> srv-a (baseline)"


# ---------------------------------------------------------------------------
step "2. hard flap: stop/start srv-c $ROUNDS times, converging in between"
# The point is not that one restart works (restore-offline covers that) but that
# the Nth does: a reconnect path that leaks a peer entry, a route, or a pruned
# marker per cycle passes round 1 and fails round 3.
for r in $(seq 1 "$ROUNDS"); do
  echo "   -- round $r/$ROUNDS --"
  daemon_stop "$C"
  if wait_gone "$B" srv-c 60; then
    pass "round $r: srv-b sees srv-c drop"
  else
    fail "round $r: srv-c still shows online on srv-b after its daemon stopped"
  fi
  daemon_start "$C"
  if wait_back "$B" srv-c 120 && wait_back "$A" srv-c 120; then
    pass "round $r: srv-c is back on both srv-a and srv-b"
  else
    fail "round $r: srv-c did not reconverge (a=$(peer_online "$A" srv-c "$NET") b=$(peer_online "$B" srv-c "$NET"))"
  fi
  # The roster reconverging is not the data plane working; check the packet path
  # too, in both directions, since the two are separate registrations.
  if retry_until 60 "on '$B' 'ping -c 2 -W 3 $IP_C' >/dev/null 2>&1"; then
    pass "round $r: srv-b -> srv-c carries packets again"
  else
    fail "round $r: srv-b -> srv-c does not ping after reconnect"
  fi
  ping_ok "$C" "$IP_B" && pass "round $r: srv-c -> srv-b carries packets again" \
    || fail "round $r: srv-c -> srv-b does not ping after reconnect"
done

# The flapper's own view has to be whole too, not just everyone else's view of it.
wait_roster "$C" srv-a srv-b srv-d

# ---------------------------------------------------------------------------
step "3. simultaneous flap: srv-c and srv-d down together"
# Two nodes returning at once is the case where each one's restore dials a peer
# that is itself still restoring.
daemon_stop "$C"; daemon_stop "$D"
if wait_gone "$B" srv-c 60 && wait_gone "$B" srv-d 60; then
  pass "srv-b sees both flappers drop"
else
  fail "srv-b did not see both flappers drop"
fi
# srv-a and srv-b keep each other through it.
[[ "$(peer_online "$B" srv-a "$NET")" == 1 ]] \
  && pass "srv-a <-> srv-b unaffected by the other two dropping" \
  || fail "srv-b lost the coordinator while srv-c/srv-d were down"

daemon_start "$C"; daemon_start "$D"
if wait_back "$B" srv-c 150 && wait_back "$B" srv-d 150; then
  pass "both flappers reconverged on srv-b"
else
  fail "simultaneous restart did not reconverge (c=$(peer_online "$B" srv-c "$NET") d=$(peer_online "$B" srv-d "$NET"))"
fi
# And the two that restarted together found *each other*, not just the nodes
# that stayed up. That is the pair with no stable side to dial.
if retry_until 120 "[[ \"\$(peer_online '$C' srv-d '$NET')\" == 1 ]]"; then
  pass "srv-c and srv-d re-linked to each other"
else
  fail "srv-c and srv-d did not re-link (each only found the nodes that stayed up)"
fi
if retry_until 60 "on '$C' 'ping -c 2 -W 3 $IP_D' >/dev/null 2>&1"; then
  pass "srv-c -> srv-d carries packets after the simultaneous restart"
else
  fail "srv-c -> srv-d does not ping after the simultaneous restart"
fi

# ---------------------------------------------------------------------------
step "3b. coordinator flap: the node holding the network key restarts"
# `restore-offline` covers a member restarting while the coordinator is down.
# This is the other direction, and the one that risks the roster itself: the
# coordinator is the only node that can republish, so if a restart lost or
# re-derived any of it, the members would converge onto the damage.
ROSTER_BEFORE="$(status_json "$B" | jq -S -r --arg n "$NET" \
  '(.networks // []) | map(select(.name == $n)) | .[0].peers | map(.hostname) | sort | join(",")')"
daemon_stop "$A"
if wait_gone "$B" srv-a 60; then
  pass "srv-b sees the coordinator drop"
else
  fail "coordinator still shows online on srv-b after its daemon stopped"
fi
# The members hold the mesh together without it, which is the whole point of the
# roster being a signed blob rather than a service the coordinator runs.
[[ "$(peer_online "$B" srv-c "$NET")" == 1 ]] \
  && pass "srv-b <-> srv-c stay linked with the coordinator down" \
  || fail "srv-b lost srv-c when the coordinator went down"
daemon_start "$A"
if wait_back "$B" srv-a 150 && wait_back "$A" srv-b 150; then
  pass "the coordinator is back and re-meshed"
else
  fail "the coordinator did not re-mesh after its restart"
fi
# And it came back with the same roster, not a rebuilt one. A coordinator that
# re-derived a member would republish that, and every member would take it.
ROSTER_AFTER="$(status_json "$B" | jq -S -r --arg n "$NET" \
  '(.networks // []) | map(select(.name == $n)) | .[0].peers | map(.hostname) | sort | join(",")')"
if [[ -n "$ROSTER_BEFORE" && "$ROSTER_BEFORE" == "$ROSTER_AFTER" ]]; then
  pass "the roster is unchanged across the coordinator restart ($ROSTER_AFTER)"
else
  fail "the roster changed across the coordinator restart ('$ROSTER_BEFORE' -> '$ROSTER_AFTER')"
fi
# Still the coordinator, not demoted to a plain member by its own restore.
[[ "$(net_role "$A" "$NET")" == coordinator ]] \
  && pass "srv-a is still the coordinator after restarting" \
  || fail "srv-a came back as '$(net_role "$A" "$NET")' rather than coordinator"
if retry_until 60 "on '$C' 'ping -c 2 -W 3 $IP_A' >/dev/null 2>&1"; then
  pass "srv-c -> srv-a carries packets after the coordinator restart"
else
  fail "srv-c -> srv-a does not ping after the coordinator restart"
fi

# ---------------------------------------------------------------------------
step "4. data-plane flap: 'ray down' / 'ray up' on srv-d $DOWN_ROUNDS times"
# `down` is standby: the TUN and routes go, the peer connections stay. So the
# assertion is the pair: traffic stops, and the roster entry does *not* drop.
for r in $(seq 1 "$DOWN_ROUNDS"); do
  on "$D" 'ray down' >/dev/null 2>&1 || true
  if retry_until 30 "! on '$B' 'ping -c 1 -W 2 $IP_D' >/dev/null 2>&1"; then
    pass "round $r: srv-d stops answering on the data plane after 'ray down'"
  else
    fail "round $r: srv-d still answers pings while down"
  fi
  # Standby keeps the control plane: srv-b must still have srv-d in its roster.
  [[ -n "$(peer_ip "$B" srv-d "$NET")" ]] \
    && pass "round $r: srv-d stays in srv-b's roster while in standby" \
    || fail "round $r: 'ray down' dropped srv-d out of the roster (standby is not leave)"
  on "$D" 'ray up' >/dev/null 2>&1 || true
  if retry_until 60 "on '$B' 'ping -c 2 -W 3 $IP_D' >/dev/null 2>&1"; then
    pass "round $r: srv-d answers again after 'ray up'"
  else
    fail "round $r: srv-d does not answer after 'ray up'"
  fi
done

# ---------------------------------------------------------------------------
step "4b. the same flap on a host with no 'ip' binary"
# The data plane must not need iproute2 on the daemon's PATH: the link goes up
# and down over netlink, like the address and the peer route beside it. While it
# did not, a host whose service PATH had no `ip` failed that one step and
# succeeded at every other, so the daemon activated onto a link it had never
# brought up. The kernel then flushed the address and refused the connected
# route, `ray ping` kept answering (that rides the control plane, not the TUN),
# and every packet through the tunnel vanished. Standby had the mirror of it,
# leaving the link up with `200::/7` still routed at nothing.
TUN_D="$(on "$D" "ip -6 route 2>/dev/null | awk '/^200::\\/7 /{print \$3; exit}'" | tr -d '[:space:]')"
IP_REAL="$(on "$D" 'readlink -f "$(command -v ip)" 2>/dev/null' | tr -d '[:space:]')"
PROBE=/usr/local/lib/ip.e2e-probe
if [[ -z "$TUN_D" || -z "$IP_REAL" ]]; then
  fail "srv-d: no TUN device or no 'ip' to hide (tun='$TUN_D' ip='$IP_REAL')"
else
  # A copy under another name, so these checks can still read link state with
  # the daemon's `ip` gone, and a restore on every exit path: a run that dies in
  # the middle must not leave the host without iproute2.
  restore_ip(){
    on "$D" "test -e '$IP_REAL.e2e-hidden' && mv -f '$IP_REAL.e2e-hidden' '$IP_REAL'; rm -f '$PROBE'" \
      >/dev/null 2>&1 || true
  }
  link_up(){ on "$D" "'$PROBE' -o link show '$TUN_D' 2>/dev/null | grep -qE '[<,]UP[,>]'"; }
  trap restore_ip EXIT
  on "$D" "install -D -m 0755 '$IP_REAL' '$PROBE' && mv '$IP_REAL' '$IP_REAL.e2e-hidden'" >/dev/null 2>&1
  if on "$D" 'command -v ip' >/dev/null 2>&1; then
    fail "srv-d still resolves 'ip', so the rest of this step would prove nothing"
  else
    pass "srv-d has no 'ip' binary to spawn"

    on "$D" 'ray down' >/dev/null 2>&1 || true
    if retry_until 30 '! link_up'; then
      pass "'ray down' takes the link down with no 'ip' on the host"
    else
      fail "srv-d's $TUN_D is still up after 'ray down' (the state never reached the kernel)"
    fi

    on "$D" 'ray up' >/dev/null 2>&1 || true
    if retry_until 30 'link_up'; then
      pass "'ray up' brings the link back with no 'ip' on the host"
    else
      fail "srv-d's $TUN_D never came up after 'ray up'"
    fi
    if retry_until 30 "on '$D' \"'$PROBE' -6 route show 2>/dev/null | grep -q '^200::/7 '\""; then
      pass "the 200::/7 route is back on srv-d"
    else
      fail "srv-d has no 200::/7 route after 'ray up' (peer traffic would take the default route)"
    fi
    if retry_until 60 "on '$B' 'ping -c 2 -W 3 $IP_D' >/dev/null 2>&1"; then
      pass "srv-b reaches srv-d again over the tunnel"
    else
      fail "srv-d does not answer after an up/down cycle with no 'ip' on the host"
    fi

    # The warning this used to produce was the only trace of the whole failure,
    # and it went to the journal where nobody was looking. Assert it is absent.
    tunfail="$(on "$D" "journalctl -u rayfish --utc --since '${SINCE[$D]}' --no-pager 2>/dev/null | grep -c 'bring TUN interface'" | tr -d '[:space:]')"
    if [[ ! "$tunfail" =~ ^[0-9]+$ ]]; then
      fail "srv-d: could not read the journal, so the link-state check proves nothing"
    elif [[ "$tunfail" == "0" ]]; then
      pass "srv-d logged no TUN link-state failure"
    else
      fail "srv-d logged $tunfail TUN link-state failure(s) (the daemon is still spawning for it)"
    fi
  fi
  restore_ip
  trap - EXIT
  on "$D" 'command -v ip' >/dev/null 2>&1 \
    && pass "srv-d's 'ip' binary is back" \
    || fail "srv-d was left without its 'ip' binary"
fi

# ---------------------------------------------------------------------------
step "5. kick srv-d while srv-c is offline"
# The headline case. `broadcast_member_sync` is a *trigger*, and srv-c is not
# there to receive it; the signed blob is the source of truth, so srv-c has to
# arrive at the same roster on its own when it comes back.
daemon_stop "$C"
wait_gone "$B" srv-c 60 || fail "srv-c did not go offline before the kick"

on "$A" "ray kick $NET srv-d" 2>&1 | strip | sed 's/^/   a| /'

# 5a. The coordinator drops it.
if wait_unlisted "$A" srv-d 60; then
  pass "coordinator dropped srv-d from the roster"
else
  fail "srv-d still in the coordinator's roster after kick"
fi
# 5b. The online member reconverges from the broadcast it did receive.
if wait_unlisted "$B" srv-d 90; then
  pass "srv-b dropped srv-d (reconverged from the MemberSync trigger)"
else
  fail "srv-b still lists srv-d after the kick"
fi
# 5c. The kicked node leaves the network itself, on the signed record rather
#     than on the message: `confirm_kick_and_leave`.
if retry_until 120 "! has_net '$D' '$NET'"; then
  pass "srv-d left '$NET' after confirming the kick against the signed record"
else
  fail "srv-d still holds '$NET' after being kicked"
fi
# 5d. And it is off the data plane, which is the part a user would notice.
if retry_until 60 "! on '$D' 'ping -c 1 -W 2 $IP_A' >/dev/null 2>&1"; then
  pass "kicked srv-d can no longer reach the coordinator over the mesh"
else
  fail "kicked srv-d still reaches srv-a on the data plane"
fi
# 5e. The reverse direction, read from the node that stayed: a kicked peer must
#     not still be reachable *from* the mesh either.
if retry_until 60 "! on '$B' 'ping -c 1 -W 2 $IP_D' >/dev/null 2>&1"; then
  pass "srv-b can no longer reach the kicked node"
else
  fail "srv-b still reaches srv-d after the kick"
fi

# ---------------------------------------------------------------------------
step "6. THE POINT: srv-c converges to the kick it never saw"
daemon_start "$C"
if retry_until 60 "has_net '$C' '$NET'"; then
  pass "srv-c came back with '$NET' intact"
else
  fail "srv-c lost the network across the restart"; summary
fi
# The group poll is the backstop for exactly this; it is 60s off Android, so
# allow a couple of cycles.
if wait_unlisted "$C" srv-d 180; then
  pass "srv-c dropped srv-d from the roster without ever receiving the trigger"
else
  fail "srv-c still lists srv-d: it never reconverged from the signed blob"
fi
# It also has to be *whole* otherwise: converging by forgetting everyone is not
# converging.
if wait_back "$C" srv-a 120 && wait_back "$C" srv-b 120; then
  pass "srv-c is fully re-meshed with the remaining members"
else
  fail "srv-c did not re-mesh with srv-a/srv-b after returning"
fi
if retry_until 60 "on '$C' 'ping -c 2 -W 3 $IP_B' >/dev/null 2>&1"; then
  pass "srv-c -> srv-b carries packets after the kick it missed"
else
  fail "srv-c -> srv-b does not ping after returning"
fi

# ---------------------------------------------------------------------------
step "7. the kicked node cannot walk back in on the bare room id"
# A single-use invite is spent and the kick removed the approval, so the only way
# back is a fresh admission. Anything else would make `ray kick` advisory.
#
# Read from the COORDINATOR'S roster rather than from `has_net` on the joiner.
# Both are true assertions (a queued join returns before `finalize_join`, so a
# pending joiner registers no network at all), but they test different things:
# `has_net` on the victim is really a second reading of step 5's "did it leave",
# while the coordinator's roster is admission itself. Keep them separate, or a
# regression in the leave path shows up here as an admission failure.
FRESH="$(mint_invite "$A" "$NET" srv-d)"
on "$D" "ray join $ROOM --hostname srv-d" 2>&1 | strip | sed 's/^/   d| /'
sleep 15
if [[ -z "$(peer_ip "$A" srv-d "$NET")" ]]; then
  pass "a bare room id does not re-admit the kicked node (not in the coordinator's roster)"
else
  fail "srv-d is back in the coordinator's roster with only the room id"
fi
# The claim that matters to a user: still no traffic. A pending joiner holds live
# QUIC connections, so this is the check that separates dialling from membership.
if ! on "$D" "ping -c 1 -W 2 $IP_A" >/dev/null 2>&1; then
  pass "a pending joiner still carries no traffic to the coordinator"
else
  fail "srv-d reaches srv-a on the data plane while only pending approval"
fi
# A fresh invite does let it back: a kick is a removal, not a permanent ban, and
# the recovery path has to work.
if [[ -n "$FRESH" ]]; then
  on "$D" "ray join $FRESH --hostname srv-d" 2>&1 | strip | sed 's/^/   d| /'
  if retry_until 120 "[[ -n \"\$(peer_ip '$A' srv-d '$NET')\" ]]"; then
    pass "a fresh invite re-admits srv-d into the coordinator's roster"
  else
    fail "srv-d could not re-join with a fresh invite"
  fi
  if retry_until 120 "[[ \"\$(peer_online '$B' srv-d '$NET')\" == 1 ]]"; then
    pass "srv-b sees the re-admitted srv-d online"
  else
    fail "srv-b never saw srv-d come back after re-admission"
  fi
  if retry_until 60 "on '$D' 'ping -c 2 -W 3 $IP_A' >/dev/null 2>&1"; then
    pass "re-admitted srv-d carries packets to the coordinator again"
  else
    fail "re-admitted srv-d still cannot reach srv-a"
  fi
else
  fail "coordinator would not mint a fresh invite for srv-d"
fi

# ---------------------------------------------------------------------------
step "8. nuke the network while srv-c is offline"
daemon_stop "$C"
wait_gone "$B" srv-c 60 || fail "srv-c did not go offline before the nuke"

on "$A" "ray nuke $NET --force" 2>&1 | strip | sed 's/^/   a| /'
if retry_until 60 "! has_net '$A' '$NET'"; then
  pass "nuke removed the network from the coordinator"
else
  fail "coordinator still holds '$NET' after nuke --force"
fi
# The coordinator is gone from the mesh, so the members lose it as a peer. This
# is the assertion that holds regardless of what a member does with the network
# entry itself: there is no daemon left to answer.
if retry_until 90 "[[ \"\$(peer_online '$B' srv-a '$NET')\" == 0 ]]"; then
  pass "srv-b sees the coordinator leave after the nuke"
else
  fail "srv-b still shows the coordinator online after it nuked the network"
fi
if retry_until 60 "! on '$B' 'ping -c 1 -W 2 $IP_A' >/dev/null 2>&1"; then
  pass "srv-b can no longer reach the nuked coordinator"
else
  fail "srv-b still reaches srv-a after the nuke"
fi
# A nuke orphans the members rather than deleting their local network entry:
# the empty record it publishes names a blob nobody is left to serve, so a
# member has nothing to converge onto. Reported, not asserted: the suite should
# not pin a behaviour the design has not committed to. What IS asserted above is
# that the coordinator is unreachable, which is what the user sees.
echo "   srv-b after the nuke: network present=$(has_net "$B" "$NET" && echo yes || echo no)"
daemon_start "$C"
echo "   srv-c after the nuke (returned from offline): network present=$(has_net "$C" "$NET" && echo yes || echo no)"

# ---------------------------------------------------------------------------
step "9. health sweep: nothing crashed on the way through"
# `NRestarts` is not the evidence here: systemd resets it on a manual start, and
# this test issues plenty. The journal is not reset, so read it instead: a
# "Scheduled restart job" line is systemd reacting to a daemon that died, which
# for this binary means the panic hook's `abort()`.
for pair in "A:srv-a" "B:srv-b" "C:srv-c" "D:srv-d"; do
  host="${pair%%:*}"; name="${pair##*:}"; ip="${!host}"
  # Every daemon still answers IPC after all of it.
  if on "$ip" 'ray status' >/dev/null 2>&1; then
    pass "$name daemon still responds to IPC"
  else
    fail "$name daemon is not responding after the churn"
  fi
  # Both counts are bounded by this run's start (see SINCE) and both distinguish
  # "read zero" from "read nothing": an ssh that fails leaves the capture empty,
  # and `${x:-0}` would turn that into a PASS on a journal nobody looked at.
  since="${SINCE[$ip]}"
  # The daemon's own hook logs `panic: <msg>`; a panic before it is installed, or
  # on a thread that bypasses it, still logs the default `panicked at`.
  panics="$(on "$ip" "journalctl -u rayfish --utc --since '$since' --no-pager 2>/dev/null | grep -cE 'panicked at|panic: '" | tr -d '[:space:]')"
  if [[ ! "$panics" =~ ^[0-9]+$ ]]; then
    fail "$name: could not read the journal, so the panic check proves nothing"
  elif [[ "$panics" == "0" ]]; then
    pass "$name logged no panic"
  else
    fail "$name logged $panics panic line(s) (journalctl -u rayfish --since '$since' | grep -E 'panicked at|panic: ')"
  fi
  # A crash-restart is systemd's own line, and it survives the manual stops this
  # test performs. Anything here is a daemon that died rather than one we stopped.
  crashes="$(on "$ip" "journalctl -u rayfish --utc --since '$since' --no-pager 2>/dev/null | grep -c 'Scheduled restart job'" | tr -d '[:space:]')"
  if [[ ! "$crashes" =~ ^[0-9]+$ ]]; then
    fail "$name: could not read the journal, so the crash check proves nothing"
  elif [[ "$crashes" == "0" ]]; then
    pass "$name never crash-restarted"
  else
    fail "$name crash-restarted $crashes time(s) during the run"
  fi
done

# ---------------------------------------------------------------------------
summary
