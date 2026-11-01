#!/usr/bin/env bash
# Remote management (`ray machines`, `ray controller`, `--delegate`, and the
# SSH grants `ray apply` sends) end to end, and its scope rule: a controller
# may only make a managed machine join or leave networks it coordinates.
#
# Topology:
#   srv-c  controller; coordinator of the closed network `ctl`
#   srv-m  managed machine, enrolled with srv-c
#   srv-y  coordinator of the closed network `other`, which srv-c only belongs
#          to as a member
#
# Checks:
#   1. enrollment: srv-m accepts srv-c's ticket; both sides list it; the
#      one-time ticket cannot enroll a second machine
#   2. `ray join --delegate` puts srv-m in `ctl`: roster and ping both ways
#   3. `ray apply` SSH grants on `ctl` land on srv-m and admit a real login
#   4. `ray leave --delegate` takes srv-m out of `ctl`
#   5. srv-c cannot make srv-m leave `other` (srv-m joined it itself)
#   6. srv-c's SSH grants for `other` are refused by srv-m
#   7. srv-c cannot make srv-m join `other`
#   8. srv-m restarts: the grant survives and srv-c can manage it again
#   9. srv-m revokes srv-c: srv-c's next action is refused
#  10. no panic or crash restart in any daemon's log
#
# Reads tests/e2e/manage/.servers (written by provision). Re-runnable (resets
# rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS, run '$ROOT/tests/e2e.sh manage provision' first"; exit 1; }
C="$(server_ip "$SERVERS" srv-c || true)"
M="$(server_ip "$SERVERS" srv-m || true)"
Y="$(server_ip "$SERVERS" srv-y || true)"
[[ -n "$C" && -n "$M" && -n "$Y" ]] || { echo "missing srv-c/srv-m/srv-y in $SERVERS"; exit 1; }
ALL=("$C" "$M" "$Y")
declare -A NAME=([$C]=srv-c [$M]=srv-m [$Y]=srv-y)

CTL=ctl      # srv-c coordinates
OTHER=other  # srv-y coordinates; srv-c is a member
LOGIN=meshtest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# machines_json : srv-c's probed inventory (`ray machines --json`).
machines_json(){ on "$C" 'timeout --kill-after=2s 20s ray machines --json' 2>/dev/null; }

# machine_field <jq-filter> : a field of srv-m's inventory entry on srv-c.
machine_field(){ machines_json | jq -r --arg id "$M_ID" "map(select(.identity == \$id)) | .[0] | $1 // empty"; }

# controllers_json <ip> : `ray controller list --json` on a host.
controllers_json(){ on "$1" 'timeout --kill-after=2s 10s ray controller list --json' 2>/dev/null; }

# trusts_c <ip> : the host lists srv-c as a controller, both in
# `ray controller list` and in `ray status --json`.
trusts_c(){
  controllers_json "$1" | jq -e --arg id "$C_ID" 'any(.[]; .identity == $id)' >/dev/null 2>&1 \
    && status_json "$1" | jq -e --arg id "$C_ID" 'any(.controllers[]; .identity == $id)' >/dev/null 2>&1
}

# trusts_nobody <ip> : both views agree the host has no controller.
trusts_nobody(){
  controllers_json "$1" | jq -e 'type == "array" and length == 0' >/dev/null 2>&1 \
    && status_json "$1" | jq -e '.controllers | type == "array" and length == 0' >/dev/null 2>&1
}

# delegate <join|leave> <net> : run `ray <verb> --delegate <srv-m> <net>` on
# srv-c. Sets OUT (stripped output) and RC (exit status).
delegate(){
  OUT="$(on "$C" "timeout --kill-after=5s 150s ray $1 --delegate $M_HOST $2" 2>&1 | strip)"
  RC=$?   # pipefail: the ray exit status, since strip succeeds
  echo "$OUT" | sed "s/^/   c| /"
}

# ping_ok <from-ip> <target>
ping_ok(){ on "$1" "ping -c 2 -W 3 $2" >/dev/null 2>&1; }

# wait_ping <from-ip> <target> <label>
wait_ping(){
  if retry_until 60 "ping_ok '$1' '$2'"; then pass "ping $3"; else fail "ping $3 ($2)"; fi
}

# ssh_try <from-ip> <dst-mesh-ip> <user> <cmd> : a stock OpenSSH client with no
# usable key, so only the mesh SSH server's identity check can let it in.
ssh_try(){
  on "$1" "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=8 -o PreferredAuthentications=none,publickey \
    $3@$2 $4 2>&1 || true"
}

# ssh_grant_on <ip> <net> : srv-m's SSH allow entries for <net> naming srv-c
# (a controller grant keeps the spec's hostname, a local one stores the
# identity), as `peer:user,user` lines (empty when there are none).
ssh_grant_on(){
  on "$1" 'timeout --kill-after=2s 10s ray ssh show --json' 2>/dev/null | jq -r --arg n "$2" --arg id "$C_ID" '
    (.networks // []) | map(select(.network == $n)) | .[0].allow // []
    | map(select(.peer == "srv-c" or .peer == $id)) | .[] | "\(.peer):\(.users | join(","))"'
}

# managed_grant_saved <ip> <net> : the network's config holds a controller
# grant (managed_ssh_allow), not a local `ray ssh allow`.
managed_grant_saved(){ on "$1" "grep -q '^\\[\\[managed_ssh_allow\\]\\]' /etc/rayfish/networks/$2.toml" 2>/dev/null; }

# journal <ip> : this run's daemon journal on a host.
journal(){ on "$1" "journalctl -u rayfish --utc --since '${SINCE[$1]}' --no-pager -o cat 2>/dev/null"; }

# restart_daemon <ip> : restart the service, wait for IPC, re-activate.
restart_daemon(){
  on "$1" 'systemctl restart rayfish' >/dev/null 2>&1 || return 1
  retry_until 60 "daemon_ready '$1'" || return 1
  on "$1" 'ray up' >/dev/null 2>&1 || true
  retry_until 30 "status_json '$1' | jq -e '.active == true' >/dev/null 2>&1"
}

# still_absent <secs> <ip> <net> : <net> never shows up on <ip> for <secs>.
# A refused join leaves nothing behind at once, so this is the window in
# which a join that slipped through would land.
still_absent(){
  local end=$((SECONDS + $1))
  while (( SECONDS < end )); do
    net_absent "$2" "$3" || return 1
    sleep 3
  done
}

# still_present <secs> <ip> <net> : the same for a refused leave.
still_present(){
  local end=$((SECONDS + $1))
  while (( SECONDS < end )); do
    has_net "$2" "$3" || return 1
    sleep 3
  done
}

# ---------------------------------------------------------------------------
step "0. deploy and activate"
wait_all_ssh "${ALL[@]}"
seed_known_hosts "${ALL[@]}"
reset_state "${ALL[@]}"
deploy_all "$ROOT" "${ALL[@]}"
activate_daemons "${ALL[@]}" || summary

declare -A SINCE
for h in "${ALL[@]}"; do
  SINCE[$h]="$(on "$h" "date -u '+%Y-%m-%d %H:%M:%S'" | tr -d '\r')"
  [[ -n "${SINCE[$h]}" ]] || { echo "could not read the clock on $h"; exit 1; }
done

C_ID="$(status_json "$C" | jq -r '.endpoint // empty')"
M_ID="$(status_json "$M" | jq -r '.endpoint // empty')"
[[ -n "$C_ID" && -n "$M_ID" ]] || { fail "could not read the endpoint ids of srv-c and srv-m"; summary; }
echo "   srv-c ${C_ID:0:10}  srv-m ${M_ID:0:10}"

# The login the SSH grants name, on the managed machine only.
on "$M" "id $LOGIN >/dev/null 2>&1 || useradd -m -s /bin/bash $LOGIN" \
  || { fail "could not create the $LOGIN account on srv-m"; summary; }

on "$C" "ray create --name $CTL --hostname srv-c" 2>&1 | strip | sed 's/^/   c| /'
on "$Y" "ray create --name $OTHER --hostname srv-y" 2>&1 | strip | sed 's/^/   y| /'
[[ "$(net_role "$C" "$CTL")" == coordinator ]] && pass "srv-c coordinates $CTL" \
  || fail "srv-c is not the coordinator of $CTL"
[[ "$(net_role "$Y" "$OTHER")" == coordinator ]] && pass "srv-y coordinates $OTHER" \
  || fail "srv-y is not the coordinator of $OTHER"

# ---------------------------------------------------------------------------
step "1. enrollment"
ENROLL="$(on "$C" 'ray machines enroll --json' 2>/dev/null)"
TICKET="$(jq -r '.ticket // empty' <<<"$ENROLL" 2>/dev/null)"
[[ -n "$TICKET" ]] && pass "srv-c minted a one-time enrollment ticket" \
  || { fail "srv-c minted no enrollment ticket: $ENROLL"; summary; }

trusts_nobody "$M" && pass "srv-m has no controller before enrolling" \
  || fail "srv-m already lists a controller before enrolling"

ADD="$(on "$M" "ray controller add $TICKET" 2>&1 | strip)"; ADD_RC=$?
echo "$ADD" | sed 's/^/   m| /'
if [[ $ADD_RC -eq 0 ]] && grep -q 'enrolled' <<<"$ADD"; then
  pass "srv-m accepted srv-c's ticket"
else
  fail "srv-m could not enroll with srv-c's ticket"
fi

trusts_c "$M" && pass "srv-m lists srv-c as its controller (controller list and status --json)" \
  || fail "srv-m does not list srv-c as a controller"

M_HOST="$(machines_json | jq -r --arg id "$M_ID" 'map(select(.identity == $id)) | .[0].hostname // empty')"
if [[ -n "$M_HOST" ]]; then
  pass "srv-c's inventory holds srv-m as '$M_HOST'"
else
  fail "srv-c's inventory does not hold srv-m"; summary
fi
if retry_until 30 "[[ \"\$(machine_field .state)\" == online ]]"; then
  pass "srv-c probes srv-m as online"
else
  fail "srv-c probes srv-m as '$(machine_field .state)', want online"
fi
on "$C" 'ray status --machines --json' 2>/dev/null \
  | jq -e --arg id "$M_ID" 'any(.managed_machines[]; .identity == $id)' >/dev/null 2>&1 \
  && pass "srv-c's status --machines --json lists srv-m" \
  || fail "srv-c's status --machines --json does not list srv-m"

# The ticket was one-time: a second machine must be turned away, and must not
# end up trusting srv-c.
REUSE="$(on "$Y" "ray controller add $TICKET" 2>&1 | strip)"; REUSE_RC=$?
echo "$REUSE" | sed 's/^/   y| /'
if [[ $REUSE_RC -ne 0 ]] && grep -qi 'already used' <<<"$REUSE"; then
  pass "the one-time ticket refuses a second machine"
else
  fail "a second machine reused the one-time ticket (rc=$REUSE_RC)"
fi
trusts_nobody "$Y" && pass "srv-y trusts no controller after the refused enrollment" \
  || fail "srv-y lists a controller after a refused enrollment"
[[ "$(machines_json | jq 'length')" == 1 ]] && pass "srv-c's inventory still holds only srv-m" \
  || fail "srv-c's inventory changed after the refused enrollment: $(machines_json | jq -c 'map(.hostname)')"

# ---------------------------------------------------------------------------
step "2. srv-c makes srv-m join $CTL"
net_absent "$M" "$CTL" && pass "srv-m is not on $CTL yet" || fail "srv-m is already on $CTL"
delegate join "$CTL"
[[ $RC -eq 0 ]] && pass "ray join --delegate $M_HOST $CTL succeeded" \
  || fail "ray join --delegate $M_HOST $CTL failed (rc=$RC)"
if retry_until 60 "has_net '$M' '$CTL'"; then
  pass "srv-m is on $CTL"
else
  fail "srv-m never joined $CTL"
fi
[[ "$(net_role "$M" "$CTL")" == member ]] && pass "srv-m is a plain member of $CTL" \
  || fail "srv-m's role on $CTL is '$(net_role "$M" "$CTL")'"
retry_until 120 "peer_in_roster '$C' '$M_HOST' '$CTL'" && pass "srv-c's $CTL roster holds $M_HOST" \
  || fail "srv-c's $CTL roster lacks $M_HOST"
retry_until 120 "peer_in_roster '$M' srv-c '$CTL'" && pass "srv-m's $CTL roster holds srv-c" \
  || fail "srv-m's $CTL roster lacks srv-c"
M_CTL_IP="$(my_ip "$M" "$CTL")"
C_CTL_IP="$(my_ip "$C" "$CTL")"
[[ -n "$M_CTL_IP" ]] && wait_ping "$C" "$M_CTL_IP" "srv-c -> srv-m on $CTL"
[[ -n "$C_CTL_IP" ]] && wait_ping "$M" "$C_CTL_IP" "srv-m -> srv-c on $CTL"
retry_until 30 "machine_field '.networks | index(\"$CTL\") != null' | grep -qx true" \
  && pass "srv-c's probe reports srv-m on $CTL" \
  || fail "srv-c's probe does not report srv-m on $CTL"

# ---------------------------------------------------------------------------
step "3. srv-c applies SSH grants for srv-m on $CTL"
OUT="$(ssh_try "$C" "$M_CTL_IP" "$LOGIN" whoami)"
if ! grep -qx "$LOGIN" <<<"$OUT"; then
  pass "before the grant, srv-c cannot log in to srv-m as $LOGIN"
else
  fail "srv-c logs in to srv-m before any grant: $OUT"
fi
on "$C" "printf 'networks:\n  $CTL:\n    srv-c: {}\n    $M_HOST:\n      ssh:\n        srv-c: [$LOGIN]\n' > /tmp/manage-ctl-ssh.yaml"
APPLY="$(on "$C" 'timeout --kill-after=5s 180s ray apply /tmp/manage-ctl-ssh.yaml' 2>&1 | strip)"
echo "$APPLY" | sed 's/^/   c| /'
grep -q 'grant(s) applied' <<<"$APPLY" && pass "apply reports the grant applied on srv-m" \
  || fail "apply did not report an applied SSH grant"
[[ "$(ssh_grant_on "$M" "$CTL")" == "srv-c:$LOGIN" ]] && pass "srv-m allows srv-c as $LOGIN on $CTL" \
  || fail "srv-m's SSH allow list for $CTL is '$(ssh_grant_on "$M" "$CTL")'"
managed_grant_saved "$M" "$CTL" && pass "srv-m saved it as a controller grant" \
  || fail "srv-m did not save a managed SSH grant for $CTL"
if retry_until 30 "ssh_try '$C' '$M_CTL_IP' '$LOGIN' whoami | grep -qx '$LOGIN'"; then
  pass "srv-c logs in to srv-m as $LOGIN over the mesh"
else
  fail "srv-c cannot log in to srv-m as $LOGIN: $(ssh_try "$C" "$M_CTL_IP" "$LOGIN" whoami | tail -2)"
fi

# ---------------------------------------------------------------------------
step "4. srv-c makes srv-m leave $CTL"
delegate leave "$CTL"
[[ $RC -eq 0 ]] && pass "ray leave --delegate $M_HOST $CTL succeeded" \
  || fail "ray leave --delegate $M_HOST $CTL failed (rc=$RC)"
retry_until 60 "net_absent '$M' '$CTL'" && pass "srv-m left $CTL" || fail "srv-m is still on $CTL"
retry_until 60 "peer_absent '$C' '$M_HOST' '$CTL'" && pass "srv-c's $CTL roster dropped $M_HOST" \
  || fail "srv-c's $CTL roster still holds $M_HOST"
trusts_c "$M" && pass "srv-m still trusts srv-c after leaving" || fail "srv-m lost its controller grant"

# ---------------------------------------------------------------------------
step "5. srv-c cannot make srv-m leave $OTHER"
# srv-c joins as a member, so `other` is active on it and the request reaches
# srv-m. srv-m joins by itself, with srv-y's invite.
CODE="$(mint_invite "$Y" "$OTHER" srv-c)"
on "$C" "ray join $CODE --hostname srv-c" 2>&1 | strip | sed 's/^/   c| /'
CODE="$(mint_invite "$Y" "$OTHER" "$M_HOST")"
on "$M" "ray join $CODE --hostname $M_HOST" 2>&1 | strip | sed 's/^/   m| /'
retry_until 120 "peer_in_roster '$Y' srv-c '$OTHER' && peer_in_roster '$Y' '$M_HOST' '$OTHER'" \
  && pass "srv-y's $OTHER roster holds srv-c and $M_HOST" \
  || fail "srv-c and srv-m did not both join $OTHER"
[[ "$(net_role "$C" "$OTHER")" == member ]] && pass "srv-c is only a member of $OTHER" \
  || fail "srv-c's role on $OTHER is '$(net_role "$C" "$OTHER")'"
retry_until 120 "peer_in_roster '$M' srv-c '$OTHER'" && pass "srv-m sees srv-c in $OTHER's signed roster" \
  || fail "srv-m does not see srv-c in $OTHER"
M_OTHER_IP="$(my_ip "$M" "$OTHER")"
[[ -n "$M_OTHER_IP" ]] && wait_ping "$Y" "$M_OTHER_IP" "srv-y -> srv-m on $OTHER"

delegate leave "$OTHER"
if [[ $RC -ne 0 ]] && grep -q "does not coordinate network '$OTHER'" <<<"$OUT"; then
  pass "srv-m refused to leave $OTHER for srv-c"
else
  fail "the delegated leave of $OTHER was not refused by srv-m (rc=$RC)"
fi
still_present 20 "$M" "$OTHER" && pass "srv-m is still on $OTHER" || fail "srv-m left $OTHER on srv-c's order"
peer_in_roster "$Y" "$M_HOST" "$OTHER" && pass "srv-y's $OTHER roster still holds $M_HOST" \
  || fail "srv-y's $OTHER roster dropped $M_HOST"
[[ -n "$M_OTHER_IP" ]] && wait_ping "$Y" "$M_OTHER_IP" "srv-y -> srv-m on $OTHER after the refusal"

# ---------------------------------------------------------------------------
step "6. srv-m refuses srv-c's SSH grants for $OTHER"
on "$C" "printf 'networks:\n  $OTHER:\n    srv-c: {}\n    srv-y: {}\n    $M_HOST:\n      ssh:\n        srv-c: [$LOGIN]\n' > /tmp/manage-other-ssh.yaml"
APPLY="$(on "$C" 'timeout --kill-after=5s 180s ray apply /tmp/manage-other-ssh.yaml' 2>&1 | strip)"
echo "$APPLY" | sed 's/^/   c| /'
grep -q "SSH apply failed on '$M_HOST': controller is not a coordinator of this network" <<<"$APPLY" \
  && pass "srv-m refused the SSH grant on $OTHER" \
  || fail "apply did not report srv-m refusing the grant on $OTHER"
[[ -z "$(ssh_grant_on "$M" "$OTHER")" ]] && pass "srv-m allows srv-c nothing on $OTHER" \
  || fail "srv-m allows srv-c on $OTHER: $(ssh_grant_on "$M" "$OTHER")"
managed_grant_saved "$M" "$OTHER" && fail "srv-m saved a controller grant for $OTHER" \
  || pass "srv-m saved no controller grant for $OTHER"
on "$M" 'ray ssh show --json' 2>/dev/null | jq -e '.enabled == true' >/dev/null 2>&1 \
  && pass "srv-m's mesh SSH server is still on (step 3 enabled it)" \
  || fail "srv-m's mesh SSH server is off, so the login check below proves nothing"
OUT="$(ssh_try "$C" "$M_OTHER_IP" "$LOGIN" whoami)"
if grep -qx "$LOGIN" <<<"$OUT"; then
  fail "srv-c logs in to srv-m as $LOGIN over $OTHER"
else
  pass "srv-c cannot log in to srv-m over $OTHER"
fi
# Positive control: the same login with a grant srv-m makes itself, so the
# refusal above is the missing grant and not a server that never listens on
# $OTHER.
on "$M" "ray ssh allow $OTHER srv-c -u $LOGIN" >/dev/null 2>&1
if retry_until 30 "ssh_try '$C' '$M_OTHER_IP' '$LOGIN' whoami | grep -qx '$LOGIN'"; then
  pass "with srv-m's own grant on $OTHER the same login works"
else
  fail "srv-c cannot log in over $OTHER even with srv-m's own grant, so the refusal proves nothing"
fi
on "$M" "ray ssh deny $OTHER srv-c" >/dev/null 2>&1
still_present 6 "$M" "$OTHER" && pass "srv-m is still on $OTHER after the apply" \
  || fail "the apply took srv-m off $OTHER"

# ---------------------------------------------------------------------------
step "7. srv-c cannot make srv-m join $OTHER"
on "$M" "ray leave $OTHER" 2>&1 | strip | sed 's/^/   m| /'
retry_until 30 "net_absent '$M' '$OTHER'" && pass "srv-m left $OTHER by itself" \
  || fail "srv-m could not leave $OTHER"
retry_until 60 "peer_absent '$Y' '$M_HOST' '$OTHER'" && pass "srv-y's $OTHER roster dropped $M_HOST" \
  || fail "srv-y's $OTHER roster still holds $M_HOST"
delegate join "$OTHER"
# srv-c refuses before anything reaches srv-m: the join's invite is minted on
# the controller, which needs the network key. See README.md.
if [[ $RC -ne 0 ]] && grep -q "only the coordinator of '$OTHER'" <<<"$OUT"; then
  pass "srv-c refused the delegated join of $OTHER (it does not coordinate it)"
else
  fail "the delegated join of $OTHER was not refused for lack of the network key (rc=$RC)"
fi
still_absent 30 "$M" "$OTHER" && pass "srv-m did not join $OTHER" || fail "srv-m joined $OTHER on srv-c's order"
peer_absent "$Y" "$M_HOST" "$OTHER" && pass "srv-y's $OTHER roster does not hold $M_HOST" \
  || fail "srv-y admitted $M_HOST to $OTHER"

# ---------------------------------------------------------------------------
step "8. srv-m restarts"
restart_daemon "$M" && pass "srv-m restarted and is active" || fail "srv-m did not come back after a restart"
trusts_c "$M" && pass "srv-m still lists srv-c as its controller" \
  || fail "srv-m forgot srv-c across the restart"
retry_until 60 "[[ \"\$(machine_field .state)\" == online ]]" && pass "srv-c probes srv-m as online again" \
  || fail "srv-c probes srv-m as '$(machine_field .state)' after the restart"
delegate join "$CTL"
[[ $RC -eq 0 ]] && pass "srv-c's delegated join works after the restart" \
  || fail "srv-c's delegated join fails after the restart (rc=$RC)"
retry_until 60 "has_net '$M' '$CTL'" && pass "srv-m is on $CTL again" || fail "srv-m did not rejoin $CTL"
M_CTL_IP="$(my_ip "$M" "$CTL")"
[[ -n "$M_CTL_IP" ]] && wait_ping "$C" "$M_CTL_IP" "srv-c -> srv-m on $CTL after the restart"

# ---------------------------------------------------------------------------
step "9. srv-m revokes srv-c"
on "$M" "ray controller revoke ${C_ID:0:16}" 2>&1 | strip | sed 's/^/   m| /'
trusts_nobody "$M" && pass "srv-m lists no controller" || fail "srv-m still lists a controller"
delegate leave "$CTL"
if [[ $RC -ne 0 ]] && grep -q 'revoked this controller' <<<"$OUT"; then
  pass "srv-m refused srv-c's leave after the revoke"
else
  fail "srv-c's leave after the revoke was not refused as unauthorized (rc=$RC)"
fi
still_present 15 "$M" "$CTL" && pass "srv-m is still on $CTL" || fail "srv-m left $CTL after revoking srv-c"
retry_until 30 "[[ \"\$(machine_field .state)\" == unauthorized ]]" \
  && pass "srv-c probes srv-m as unauthorized" \
  || fail "srv-c probes srv-m as '$(machine_field .state)', want unauthorized"

# ---------------------------------------------------------------------------
step "10. daemon logs"
for h in "${ALL[@]}"; do
  log="$(journal "$h")" || { fail "${NAME[$h]}: could not read the journal"; continue; }
  [[ -n "$log" ]] || { fail "${NAME[$h]}: empty journal, so the checks below prove nothing"; continue; }
  panics="$(grep -cE 'panicked at|panic: ' <<<"$log")"
  [[ "$panics" == 0 ]] && pass "${NAME[$h]} logged no panic" \
    || { fail "${NAME[$h]} logged $panics panic line(s)"; grep -E 'panicked at|panic: ' <<<"$log" | head -3 | sed 's/^/      /'; }
  crashes="$(on "$h" "journalctl -u rayfish --utc --since '${SINCE[$h]}' --no-pager 2>/dev/null | grep -c 'Scheduled restart job'")"
  [[ "$crashes" == 0 ]] && pass "${NAME[$h]} never crash-restarted" \
    || fail "${NAME[$h]} crash-restarted ${crashes:-?} time(s)"
done

summary
