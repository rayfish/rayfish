#!/usr/bin/env bash
# Mixed-version mesh e2e: this tree's build and an older release in one mesh.
#
# Topology (OLD = the binary at $OLD_RAY_BIN, NEW = this tree's cross build):
#   srv-a  NEW  coordinator of `alpha`, later a member of `beta`
#   srv-b  OLD  coordinator of `beta`, member then co-coordinator of `alpha`
#   srv-c  OLD  member of `alpha` and `beta` (kicked from `beta` by a NEW node)
#   srv-d  NEW  member then co-coordinator of `beta`, member of `alpha`
#               (kicked from `alpha` by an OLD node)
#
# Checks, in both directions where the direction matters:
#   1. joins across versions (NEW coordinator + OLD joiners, OLD coordinator +
#      NEW joiner), roster convergence, mesh addresses agreeing, ping both ways
#      and Magic DNS names
#   2. mixed-version co-coordinators: an admission made by the co-coordinator
#      of the other version converges everywhere, and both coordinators renew
#      the network record (two renewal cycles) with no record refused
#   3. a kick by an OLD coordinator removes a NEW member and the reverse
#   4. a NEW member and a NEW coordinator restart and rejoin with their saved
#      record floor (`last_record_timestamp`, a key the OLD build ignores)
#   5. `ray send` / `ray files accept` OLD -> NEW and NEW -> OLD, sha256 match
#   6. every daemon log: no panic, no crash restart, no repeated protocol error
#
# Needs OLD_RAY_BIN, a local x86_64 Linux `ray` binary (see README.md).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS, run tests/e2e.sh mixed-version provision first"; exit 1; }

OLD_BIN="${OLD_RAY_BIN:-}"
if [[ -z "$OLD_BIN" || ! -f "$OLD_BIN" ]]; then
  echo "OLD_RAY_BIN must name a local x86_64 Linux ray binary (got '${OLD_BIN}')." >&2
  echo "See tests/e2e/mixed-version/README.md for fetching a release." >&2
  exit 2
fi
NEW_BIN="$ROOT/target/cross/x86_64-unknown-linux-gnu/release/ray"

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
D="$(server_ip "$SERVERS" srv-d || true)"
[[ -n "$A" && -n "$B" && -n "$C" && -n "$D" ]] || { echo "missing srv-a/b/c/d in $SERVERS"; exit 1; }
ALL=("$A" "$B" "$C" "$D")
declare -A NAME=([$A]=srv-a [$B]=srv-b [$C]=srv-c [$D]=srv-d)

NA=alpha   # NEW coordinator
NB=beta    # OLD coordinator
# One renewal is RECORD_TTL / 2 = 150s. Two cycles plus margin.
RENEWAL_WAIT="${RENEWAL_WAIT:-330}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# join_with_invite <coord-ip> <net> <joiner-ip> <hostname> : mint a hostname-
# bound invite on the coordinator and join with it.
join_with_invite(){
  local code; code="$(mint_invite "$1" "$2" "$4")"
  [[ -n "$code" ]] || { fail "no invite minted on ${NAME[$1]} for $4 on $2"; return 1; }
  on "$3" "ray join $code --hostname $4" 2>&1 | strip | sed "s/^/   $4| /"
}

# known <text> : a defect of the OLD build that this tree fixes. Printed, not
# counted: the mixed mesh still works, and the NEW side of the same check is
# asserted next to it.
known(){ printf '  \033[33mKNOWN\033[0m %s\n' "$*"; }

# roster_has <ip> <net> <host...> : every named peer is in <ip>'s roster for
# <net>. Membership, not a live connection: idle connections close after a
# couple of minutes and reopen on demand, so "online" is the wrong question for
# convergence. The pings next to each roster check cover the data plane.
roster_has(){
  local ip="$1" net="$2"; shift 2
  local h
  for h in "$@"; do peer_in_roster "$ip" "$h" "$net" || return 1; done
}

# wait_net_roster [-t secs] <ip> <net> <host...> : bounded wait, PASS/FAIL.
wait_net_roster(){
  local secs=150
  if [[ "$1" == -t ]]; then secs="$2"; shift 2; fi
  local ip="$1" net="$2"; shift 2
  if retry_until "$secs" "roster_has '$ip' '$net' $*"; then
    pass "${NAME[$ip]} has $* in its $net roster"
  else
    fail "${NAME[$ip]} is missing some of $* from its $net roster"
  fi
}

# ping_ok <from-ip> <target> : the target (address or name) answers.
ping_ok(){ on "$1" "ping -c 2 -W 3 $2" >/dev/null 2>&1; }

# wait_ping <from-ip> <target> <label>
wait_ping(){
  if retry_until 60 "ping_ok '$1' '$2'"; then pass "ping $3"; else fail "ping $3 ($2)"; fi
}

# resolves <ip> <name> : the name resolves through the host's system resolver.
resolves(){ on "$1" "getent ahosts $2" 2>/dev/null | grep -qE '^2[0-9a-f]{2}:'; }

# wait_dns <from-ip> <host> <net> : the Magic DNS name resolves and answers.
wait_dns(){
  local fqdn="$2.$3.ray"
  if retry_until 60 "ping_ok '$1' '$fqdn'"; then
    pass "${NAME[$1]} resolves and reaches $fqdn"
  else
    fail "${NAME[$1]} cannot resolve or reach $fqdn"
  fi
}

# addresses_agree <a-ip> <b-ip> <a-host> <net> : the mesh address <a> derives for
# itself is the one <b> holds for it. The derivation was rewritten after the
# release, so a mismatch would route to nowhere.
addresses_agree(){
  local own seen
  own="$(my_ip "$1" "$4")"; seen="$(peer_ip "$2" "$3" "$4")"
  if [[ -n "$own" && "$own" == "$seen" ]]; then
    pass "$3's mesh address agrees on ${NAME[$2]} ($own)"
  else
    fail "$3's mesh address differs: own '$own', ${NAME[$2]} has '$seen'"
  fi
}

# no_incompatible <ip> : no peer on any network is flagged incompatible.
no_incompatible(){
  local n
  n="$(status_json "$1" | jq -r '[(.networks // [])[].peers[] | select(.incompatible == true) | .hostname] | join(",")')" \
    || { fail "${NAME[$1]}: could not read status"; return; }
  if [[ -z "$n" ]]; then pass "${NAME[$1]} flags no peer incompatible"; else fail "${NAME[$1]} flags incompatible peers: $n"; fi
}

# roster_names <ip> <net> : sorted hostnames this node knows on <net>, itself
# included.
roster_names(){
  status_json "$1" | jq -r --arg n "$2" '
    (.networks // []) | map(select(.name == $n)) | .[0]
    | if . == null then "" else ([.my_hostname] + [.peers[].hostname]) | map(select(. != null)) | sort | join(",") end'
}

# rosters_equal <net> <want> <ip...> : every host reports the same roster.
rosters_equal(){
  local net="$1" want="$2"; shift 2
  local ip
  for ip in "$@"; do [[ "$(roster_names "$ip" "$net")" == "$want" ]] || return 1; done
}

# journal <ip> : this run's daemon journal on a host.
journal(){ on "$1" "journalctl -u rayfish --utc --since '${SINCE[$1]}' --no-pager -o cat 2>/dev/null"; }

# restart_daemon <ip> : restart the service the way an upgrade or reboot does,
# wait for IPC, and re-activate.
restart_daemon(){
  on "$1" 'systemctl restart rayfish' >/dev/null 2>&1 || return 1
  retry_until 60 "daemon_ready '$1'" || return 1
  on "$1" 'ray up' >/dev/null 2>&1 || true
  retry_until 30 "status_json '$1' | jq -e '.active == true' >/dev/null 2>&1"
}

# ---------------------------------------------------------------------------
step "0. deploy: NEW on srv-a + srv-d, OLD on srv-b + srv-c"
wait_all_ssh "${ALL[@]}"
seed_known_hosts "${ALL[@]}"
reset_state "${ALL[@]}"
deploy_all "$ROOT" "$A" "$D"
deploy_old "$OLD_BIN" "$B" "$C"
activate_daemons "${ALL[@]}" || summary

NEW_SHA="$(sha256sum "$NEW_BIN" | cut -d' ' -f1)"
OLD_SHA="$(sha256sum "$OLD_BIN" | cut -d' ' -f1)"
[[ "$NEW_SHA" != "$OLD_SHA" ]] || { fail "OLD_RAY_BIN is the same file as the new build"; summary; }
declare -A WANT=([$A]=$NEW_SHA [$B]=$OLD_SHA [$C]=$OLD_SHA [$D]=$NEW_SHA)
declare -A KIND=([$A]=NEW [$B]=OLD [$C]=OLD [$D]=NEW)
for h in "${ALL[@]}"; do
  # The installed file, and the daemon actually running it: a daemon that kept
  # the previous binary open shows its exe as "(deleted)".
  got="$(on "$h" 'sha256sum /usr/local/bin/ray' | cut -d' ' -f1)"
  exe="$(on "$h" 'ls -l /proc/$(systemctl show -p MainPID --value rayfish)/exe 2>&1')"
  ver="$(on "$h" 'ray --version' 2>/dev/null | strip)"
  if [[ "$got" == "${WANT[$h]}" && "$exe" == *"/usr/local/bin/ray" ]]; then
    pass "${NAME[$h]} runs the ${KIND[$h]} binary ($ver, sha ${got:0:12})"
  else
    fail "${NAME[$h]} is not running the ${KIND[$h]} binary (sha ${got:0:12}, exe '$exe')"
  fi
done

# The journal sweep in step 6 is bounded by this, on each host's own clock.
declare -A SINCE
for h in "${ALL[@]}"; do
  SINCE[$h]="$(on "$h" "date -u '+%Y-%m-%d %H:%M:%S'" | tr -d '\r')"
  [[ -n "${SINCE[$h]}" ]] || { echo "could not read the clock on $h"; exit 1; }
done

# ---------------------------------------------------------------------------
step "1a. NEW coordinator, OLD members: srv-a creates $NA, srv-b + srv-c join"
CREATE="$(on "$A" "ray create --name $NA --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   srv-a| /'
echo "$CREATE" | grep -q 'ray join' && pass "srv-a (NEW) created $NA" || { fail "create $NA failed"; summary; }
join_with_invite "$A" "$NA" "$B" srv-b
join_with_invite "$A" "$NA" "$C" srv-c
wait_net_roster "$A" "$NA" srv-b srv-c
wait_net_roster "$B" "$NA" srv-a srv-c
wait_net_roster "$C" "$NA" srv-a srv-b
addresses_agree "$A" "$C" srv-a "$NA"
addresses_agree "$C" "$A" srv-c "$NA"
IP_A="$(my_ip "$A" "$NA")"; IP_B="$(my_ip "$B" "$NA")"; IP_C="$(my_ip "$C" "$NA")"
wait_ping "$A" "$IP_C" "srv-a (NEW) -> srv-c (OLD) on $NA"
wait_ping "$C" "$IP_A" "srv-c (OLD) -> srv-a (NEW) on $NA"
wait_dns "$C" srv-a "$NA"
wait_dns "$A" srv-c "$NA"

# ---------------------------------------------------------------------------
step "1b. OLD coordinator, NEW member: srv-b creates $NB, srv-d + srv-c join"
CREATE="$(on "$B" "ray create --name $NB --hostname srv-b" | strip)"
echo "$CREATE" | sed 's/^/   srv-b| /'
echo "$CREATE" | grep -q 'ray join' && pass "srv-b (OLD) created $NB" || { fail "create $NB failed"; summary; }
join_with_invite "$B" "$NB" "$D" srv-d
join_with_invite "$B" "$NB" "$C" srv-c
wait_net_roster "$B" "$NB" srv-d srv-c
wait_net_roster "$D" "$NB" srv-b srv-c
wait_net_roster "$C" "$NB" srv-b srv-d
addresses_agree "$D" "$B" srv-d "$NB"
addresses_agree "$B" "$D" srv-b "$NB"
IP_D="$(my_ip "$D" "$NB")"
wait_ping "$D" "$IP_B" "srv-d (NEW) -> srv-b (OLD) on $NB"
wait_ping "$B" "$IP_D" "srv-b (OLD) -> srv-d (NEW) on $NB"
wait_ping "$D" "$IP_C" "srv-d (NEW) -> srv-c (OLD) on $NB"
wait_dns "$D" srv-b "$NB"
wait_dns "$B" srv-d "$NB"
for h in "${ALL[@]}"; do no_incompatible "$h"; done

# ---------------------------------------------------------------------------
step "2a. mixed co-coordinators: srv-a (NEW) promotes srv-b (OLD) on $NA"
B_ID="$(peer_endpoint "$A" srv-b "$NA")"
[[ -n "$B_ID" ]] || { fail "could not resolve srv-b's id on srv-a"; summary; }
on "$A" "ray admin $NA add $B_ID" 2>&1 | strip | sed 's/^/   srv-a| /'
if retry_until 60 "[[ \"\$(net_role '$B' '$NA')\" == coordinator ]] && holds_key '$B' '$NA'"; then
  pass "srv-b (OLD) is a co-coordinator of $NA"
else
  fail "promotion of srv-b on $NA did not land"
fi

step "2b. mixed co-coordinators: srv-b (OLD) promotes srv-d (NEW) on $NB"
D_ID="$(peer_endpoint "$B" srv-d "$NB")"
[[ -n "$D_ID" ]] || { fail "could not resolve srv-d's id on srv-b"; summary; }
on "$B" "ray admin $NB add $D_ID" 2>&1 | strip | sed 's/^/   srv-b| /'
if retry_until 60 "[[ \"\$(net_role '$D' '$NB')\" == coordinator ]] && holds_key '$D' '$NB'"; then
  pass "srv-d (NEW) is a co-coordinator of $NB"
else
  fail "promotion of srv-d on $NB did not land"
fi

step "2c. an admission by the OLD co-coordinator converges: srv-b admits srv-d to $NA"
join_with_invite "$B" "$NA" "$D" srv-d
wait_net_roster "$A" "$NA" srv-b srv-c srv-d
wait_net_roster "$C" "$NA" srv-a srv-b srv-d
wait_net_roster "$D" "$NA" srv-a srv-b srv-c
wait_dns "$A" srv-d "$NA"
wait_dns "$C" srv-d "$NA"
wait_dns "$D" srv-a "$NA"

step "2d. an admission by the NEW co-coordinator converges: srv-d admits srv-a to $NB"
join_with_invite "$D" "$NB" "$A" srv-a
# srv-b created $NB, and the OLD build runs no group poller on the coordinator
# that created a network: it learns another coordinator's edit at its next
# renewal (up to 150s). Hence the longer wait on srv-b only.
wait_net_roster -t 210 "$B" "$NB" srv-a srv-c srv-d
wait_net_roster "$C" "$NB" srv-a srv-b srv-d
wait_net_roster "$A" "$NB" srv-b srv-c srv-d
wait_dns "$C" srv-a "$NB"
wait_dns "$A" srv-d "$NB"
# What srv-b learns at renewal goes through the OLD build's record-apply path,
# which updates the roster but not Magic DNS (fixed here: "Roster updates
# learned by polling now update .ray names and routes").
if retry_until 30 "resolves '$B' srv-a.$NB.ray"; then
  pass "srv-b (OLD) resolves srv-a.$NB.ray"
else
  known "srv-b (OLD creator of $NB) has no srv-a.$NB.ray name for an admission made by srv-d"
fi

step "2e. record renewal across versions (${RENEWAL_WAIT}s, two renewal cycles)"
# Both coordinators of each network renew its record every 150s, each first
# reading the canonical record. Throughout, every member must keep the full
# roster: a renewal that one version refuses, or one that republishes an
# older roster, shows up here as a member dropping out.
WANT_A="srv-a,srv-b,srv-c,srv-d"
declare -A PUB0
for h in "$A" "$B" "$D"; do
  PUB0[$h]="$(journal "$h" | grep -c 'published network record')"
done
end=$((SECONDS + RENEWAL_WAIT)); bad=""
while (( SECONDS < end )); do
  rosters_equal "$NA" "$WANT_A" "${ALL[@]}" || bad+="$NA@$(date -u +%T) "
  rosters_equal "$NB" "$WANT_A" "${ALL[@]}" || bad+="$NB@$(date -u +%T) "
  sleep 20
done
if [[ -z "$bad" ]]; then
  pass "both rosters stayed whole on every host through the renewals"
else
  fail "a roster was incomplete during renewal at: $bad"
  for h in "${ALL[@]}"; do echo "   ${NAME[$h]}: $NA=[$(roster_names "$h" "$NA")] $NB=[$(roster_names "$h" "$NB")]"; done
fi
for h in "$A" "$B" "$D"; do
  n="$(journal "$h" | grep -c 'published network record')"
  if [[ "$n" =~ ^[0-9]+$ ]] && (( n - ${PUB0[$h]:-0} >= 2 )); then
    pass "${NAME[$h]} (${KIND[$h]}) renewed its records during the window ($((n - ${PUB0[$h]:-0})) publishes)"
  else
    fail "${NAME[$h]} (${KIND[$h]}) did not renew during the window (${PUB0[$h]:-?} -> $n publishes)"
  fi
done
# The NEW build logs a refused record by name. The OLD build has no such line,
# so its side is the roster loop above.
for h in "$A" "$D"; do
  rej="$(journal "$h" | grep -cE 'rejecting a signed record|rejecting signed record|undecodable signed record|do not match the signed hash|does not decode against this build')"
  if [[ "$rej" == 0 ]]; then
    pass "${NAME[$h]} (NEW) refused no record from the OLD coordinator"
  else
    fail "${NAME[$h]} (NEW) refused $rej record(s):"
    journal "$h" | grep -E 'rejecting|undecodable|signed hash|does not decode' | tail -5 | sed 's/^/      /'
  fi
done

# ---------------------------------------------------------------------------
step "3a. OLD coordinator kicks a NEW member: srv-b kicks srv-d from $NA"
on "$B" "ray kick $NA srv-d --yes" 2>&1 | strip | sed 's/^/   srv-b| /'
for h in "$A" "$B" "$C"; do
  if retry_until 90 "peer_absent '$h' srv-d '$NA'"; then
    pass "${NAME[$h]} dropped srv-d from $NA"
  else
    fail "${NAME[$h]} still lists srv-d on $NA"
  fi
done
if retry_until 120 "net_absent '$D' '$NA'"; then
  pass "srv-d (NEW) left $NA after the OLD coordinator's kick"
else
  fail "srv-d (NEW) still holds $NA after being kicked"
fi
has_net "$D" "$NB" && pass "srv-d kept $NB" || fail "srv-d lost $NB along with $NA"
for h in "$A" "$C"; do
  if retry_until 60 "! resolves '$h' srv-d.$NA.ray"; then
    pass "srv-d.$NA.ray no longer resolves on ${NAME[$h]}"
  else
    fail "srv-d.$NA.ray still resolves on ${NAME[$h]}"
  fi
done

step "3b. NEW coordinator kicks an OLD member: srv-d kicks srv-c from $NB"
on "$D" "ray kick $NB srv-c --yes" 2>&1 | strip | sed 's/^/   srv-d| /'
for h in "$A" "$B" "$D"; do
  if retry_until 90 "peer_absent '$h' srv-c '$NB'"; then
    pass "${NAME[$h]} dropped srv-c from $NB"
  else
    fail "${NAME[$h]} still lists srv-c on $NB"
  fi
done
if retry_until 120 "net_absent '$C' '$NB'"; then
  pass "srv-c (OLD) left $NB after the NEW coordinator's kick"
else
  fail "srv-c (OLD) still holds $NB after being kicked"
fi
has_net "$C" "$NA" && pass "srv-c kept $NA" || fail "srv-c lost $NA along with $NB"
if retry_until 60 "! resolves '$A' srv-c.$NB.ray"; then
  pass "srv-c.$NB.ray no longer resolves on srv-a (NEW member)"
else
  fail "srv-c.$NB.ray still resolves on srv-a (NEW member)"
fi
# The same two OLD-build defects as in 2d: srv-b drops srv-c from its roster
# at renewal, through the path that leaves Magic DNS alone.
if retry_until 60 "! resolves '$B' srv-c.$NB.ray"; then
  pass "srv-c.$NB.ray no longer resolves on srv-b (OLD creator)"
else
  known "srv-c.$NB.ray still resolves on srv-b (OLD creator of $NB) after srv-d kicked srv-c"
fi

# ---------------------------------------------------------------------------
step "4. restart a NEW member and a NEW coordinator in the mixed mesh"
# Now: $NA = srv-a (NEW coord), srv-b (OLD co-coord), srv-c (OLD member);
#      $NB = srv-b (OLD coord), srv-d (NEW co-coord), srv-a (NEW member).
WANT_NA="srv-a,srv-b,srv-c"; WANT_NB="srv-a,srv-b,srv-d"
for h in "$A" "$D"; do
  for net in "$NA" "$NB"; do
    has_net "$h" "$net" || continue
    if on "$h" "grep -q '^last_record_timestamp = [0-9]' /etc/rayfish/networks/$net.toml"; then
      pass "${NAME[$h]} saved a record floor for $net"
    else
      fail "${NAME[$h]} has no saved record floor for $net"
    fi
  done
done

restart_daemon "$A" && pass "srv-a (NEW coordinator of $NA, member of $NB) restarted" \
  || fail "srv-a did not come back from a restart"
[[ "$(net_role "$A" "$NA")" == coordinator ]] && pass "srv-a is still coordinator of $NA" \
  || fail "srv-a came back as '$(net_role "$A" "$NA")' on $NA"
[[ "$(net_role "$A" "$NB")" == member ]] && pass "srv-a is still a member of $NB" \
  || fail "srv-a came back as '$(net_role "$A" "$NB")' on $NB"
wait_net_roster "$A" "$NA" srv-b srv-c
wait_net_roster "$A" "$NB" srv-b srv-d
wait_net_roster "$C" "$NA" srv-a
wait_net_roster "$B" "$NB" srv-a
wait_ping "$C" "$IP_A" "srv-c (OLD) -> restarted srv-a"
wait_ping "$A" "$IP_C" "restarted srv-a -> srv-c (OLD)"
[[ "$(peer_online "$C" srv-a "$NA")" == 1 ]] && pass "srv-c holds a live connection to srv-a again" \
  || fail "srv-c has no live connection to srv-a after the pings"

restart_daemon "$D" && pass "srv-d (NEW co-coordinator of $NB) restarted" \
  || fail "srv-d did not come back from a restart"
[[ "$(net_role "$D" "$NB")" == coordinator ]] && pass "srv-d is still a coordinator of $NB" \
  || fail "srv-d came back as '$(net_role "$D" "$NB")' on $NB"
net_absent "$D" "$NA" && pass "srv-d did not resurrect $NA, which it was kicked from" \
  || fail "srv-d holds $NA again after a restart"
wait_net_roster "$D" "$NB" srv-a srv-b
wait_net_roster "$B" "$NB" srv-d
wait_ping "$B" "$IP_D" "srv-b (OLD) -> restarted srv-d"
wait_ping "$D" "$IP_B" "restarted srv-d -> srv-b (OLD)"
[[ "$(peer_online "$B" srv-d "$NB")" == 1 ]] && pass "srv-b holds a live connection to srv-d again" \
  || fail "srv-b has no live connection to srv-d after the pings"

if retry_until 120 "rosters_equal '$NA' '$WANT_NA' '$A' '$B' '$C' && rosters_equal '$NB' '$WANT_NB' '$A' '$B' '$D'"; then
  pass "rosters agree on every host after the restarts ($NA=[$WANT_NA] $NB=[$WANT_NB])"
else
  fail "rosters disagree after the restarts"
  for h in "${ALL[@]}"; do echo "   ${NAME[$h]}: $NA=[$(roster_names "$h" "$NA")] $NB=[$(roster_names "$h" "$NB")]"; done
fi

# ---------------------------------------------------------------------------
step "5. file transfer across versions"
SR_PREFIX=/tmp/mixed_c2a send_recv "$C" "$A" srv-a "ray send srv-c (OLD) -> srv-a (NEW)"
SR_PREFIX=/tmp/mixed_a2c send_recv "$A" "$C" srv-c "ray send srv-a (NEW) -> srv-c (OLD)"
SR_PREFIX=/tmp/mixed_b2d send_recv "$B" "$D" srv-d "ray send srv-b (OLD) -> srv-d (NEW)"
SR_PREFIX=/tmp/mixed_d2b send_recv "$D" "$B" srv-b "ray send srv-d (NEW) -> srv-b (OLD)"

# ---------------------------------------------------------------------------
step "6. daemon health and logs on every host"
for h in "${ALL[@]}"; do no_incompatible "$h"; done
# Patterns of a protocol disagreement between the versions. One line can be
# the race of a restart; a repeat is a loop.
PROTO='incompatible|does not decode|undecodable|do not match the signed hash|rejecting|older than the last one applied|from non-coordinator|could not fetch verified blob|no handler for ALPN|deserializ'
for h in "${ALL[@]}"; do
  log="$(journal "$h")" || { fail "${NAME[$h]}: could not read the journal"; continue; }
  [[ -n "$log" ]] || { fail "${NAME[$h]}: empty journal, so the checks below prove nothing"; continue; }
  daemon_ready "$h" && pass "${NAME[$h]} still answers IPC" || fail "${NAME[$h]} does not answer IPC"
  panics="$(grep -cE 'panicked at|panic: ' <<<"$log")"
  [[ "$panics" == 0 ]] && pass "${NAME[$h]} logged no panic" \
    || { fail "${NAME[$h]} logged $panics panic line(s)"; grep -E 'panicked at|panic: ' <<<"$log" | head -3 | sed 's/^/      /'; }
  crashes="$(on "$h" "journalctl -u rayfish --utc --since '${SINCE[$h]}' --no-pager 2>/dev/null | grep -c 'Scheduled restart job'")"
  [[ "$crashes" == 0 ]] && pass "${NAME[$h]} never crash-restarted" \
    || fail "${NAME[$h]} crash-restarted ${crashes:-?} time(s)"
  # Group by message with the leading timestamp and level cut, so a line that
  # repeats is counted as one kind.
  repeats="$(grep -iE "$PROTO" <<<"$log" | grep -E 'WARN|ERROR' \
    | sed -E 's/^[^ ]+ +(WARN|ERROR) +//; s/[0-9a-f]{10,}/<id>/g; s/[0-9]+/N/g' \
    | sort | uniq -c | sort -rn | awk '$1 >= 3')"
  if [[ -z "$repeats" ]]; then
    pass "${NAME[$h]} (${KIND[$h]}) logged no repeated protocol error"
  else
    fail "${NAME[$h]} (${KIND[$h]}) repeated protocol errors:"
    echo "$repeats" | head -8 | cut -c1-240 | sed 's/^/      /'
  fi
  once="$(grep -iE "$PROTO" <<<"$log" | grep -cE 'WARN|ERROR')"
  if [[ "$once" != 0 ]]; then
    echo "   ${NAME[$h]}: $once protocol warning line(s) in total, last ones:"
    grep -iE "$PROTO" <<<"$log" | grep -E 'WARN|ERROR' | tail -3 | cut -c1-240 | sed 's/^/      /'
  fi
done

# ---------------------------------------------------------------------------
summary
