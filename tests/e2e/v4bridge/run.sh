#!/usr/bin/env bash
# IPv4-only listener bridge end-to-end test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `v4br`, and the client
#   srv-b  member running services that speak IPv4 only
#
# The mesh is IPv6-only, so a service bound to `0.0.0.0` has an IPv4 socket the
# kernel will never hand an IPv6 packet: before the bridge it was unreachable
# over the mesh whatever the firewall said. Everything here needs a real TUN, a
# real host listener table and a real peer, which is why none of it is a unit
# test:
#   - a `0.0.0.0` service on srv-b answers srv-a at srv-b's mesh address, and
#     carries a real HTTP payload, by IP and by `.ray` name;
#   - the daemon is what holds that mesh address:port (the bridge, not the app);
#   - the firewall still decides: denied before the rule, open after, with the
#     bridge's listener up the whole time, so it is not a bypass;
#   - a `127.0.0.1` service is never bridged, even with the port allowed;
#   - a bridged port stays bridged across rescans (the bridge's own listener
#     must not read back as the service having grown IPv6 support);
#   - the bridge follows the service (stop -> released, start -> rebound), the
#     `v4-bridge` setting, and the data plane (`ray down`/`up`).
#
# Reads tests/e2e/v4bridge/.servers (written by provision.sh). Does NOT modify
# infra. Re-runnable (resets rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run $DIR/provision.sh first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

NET=v4br
# Bound `0.0.0.0` on srv-b: the case the bridge exists for.
V4_PORT=8400
# Bound `127.0.0.1` on srv-b: deliberately local, and never bridged.
LO_PORT=8401
# Bound `0.0.0.0` late, in step 12, to time how long the bridge takes to notice.
EV_PORT=8402
# A host with no listen events falls back to a 15s timer
# (`v4bridge::RESCAN_INTERVAL`), so a change takes up to that long to notice;
# give a reconcile two of them plus slack. A host that has them is far quicker,
# and every wait below is a ceiling rather than a duration.
SETTLE=40
# What counts as "the kernel told us" in step 12. Each check is an ssh round
# trip, so this is generous against that noise while staying 30x under the 300s
# backstop that is the only other way the port could have been taken.
EVENT_PICKUP=10

# serve <host> <port> <bind-addr> : detached HTTP server on one address.
# `--bind 0.0.0.0` is the point of this scenario: the shared
# `start_tcp_listener` binds `::` precisely so the firewall scenarios do not
# depend on this feature.
serve(){
  on "$1" "setsid python3 -m http.server $2 --bind $3 >/tmp/v4br_$2.log 2>&1 </dev/null & sleep 1" \
    >/dev/null 2>&1 || true
}
unserve(){ on "$1" "pkill -f 'http.server $2'" >/dev/null 2>&1 || true; }

# bridged <host> <mesh-ip> <port> : 1 if the ray daemon holds a listener on that
# mesh address and port, 0 otherwise. This is what separates "the bridge is up"
# from "the peer can reach it": the firewall can close the second with the first
# still true, and the two steps below turn on telling them apart.
bridged(){
  on "$1" "ss -ltnpH 2>/dev/null | grep -F '[$2]:$3 ' | grep -c '\"ray\"' || true" \
    2>/dev/null | strip | tr -d '[:space:]'
}

# seconds_until_bridged <host> <mesh-ip> <port> <limit> : wall-clock seconds
# until the daemon holds that port, or <limit> if it never does. Measured from
# $SECONDS rather than counted in iterations, since each check is an ssh round
# trip of its own and would otherwise be counted as free.
seconds_until_bridged(){
  local host=$1 ip=$2 port=$3 limit=$4 start=$SECONDS
  while (( SECONDS - start < limit )); do
    if [[ "$(bridged "$host" "$ip" "$port")" == 1 ]]; then
      echo $(( SECONDS - start )); return 0
    fi
    sleep 1
  done
  echo "$limit"; return 1
}

# fetch <host> <url> : the HTTP status code the host gets, or 000.
fetch(){ on "$1" "curl -sS -m 8 -o /dev/null -w '%{http_code}' '$2' 2>/dev/null || true" | strip | tr -d '[:space:]'; }

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on both hosts"
wait_all_ssh "$A" "$B"
seed_known_hosts "$A" "$B"
reset_state "$A" "$B"
deploy_all "$ROOT" "$A" "$B"
for h in "$A" "$B"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B"

# ---------------------------------------------------------------------------
step "1. srv-a creates the closed network; srv-b joins via invite"
CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   a| /'
has_net "$A" "$NET" && pass "network '$NET' present on coordinator" || fail "create failed"

INV_B="$(mint_invite "$A" "$NET" srv-b)"
[[ -n "$INV_B" ]] && pass "minted invite for srv-b" || fail "invite mint failed"
on "$B" "ray join $INV_B --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'
wait_roster "$A" srv-b

A_IP="$(my_ip "$A" "$NET")"; B_IP="$(my_ip "$B" "$NET")"
echo "   A_IP=$A_IP  B_IP=$B_IP"
[[ -n "$A_IP" && -n "$B_IP" ]] || { fail "missing a VPN ip"; summary; }

# ---------------------------------------------------------------------------
step "2. srv-b starts an IPv4-only service on 0.0.0.0 and a loopback-only one"
serve "$B" "$V4_PORT" 0.0.0.0
serve "$B" "$LO_PORT" 127.0.0.1
# Sanity, locally on srv-b: both answer over IPv4, so anything that fails later
# is the mesh path and not the service.
[[ "$(fetch "$B" "http://127.0.0.1:$V4_PORT/")" == 200 ]] \
  && pass "srv-b: the 0.0.0.0 service answers on IPv4 locally" \
  || fail "srv-b: the 0.0.0.0 service is not answering at all"
[[ "$(fetch "$B" "http://127.0.0.1:$LO_PORT/")" == 200 ]] \
  && pass "srv-b: the 127.0.0.1 service answers on IPv4 locally" \
  || fail "srv-b: the 127.0.0.1 service is not answering at all"

# The bridge has to see the listener appear, which takes up to a rescan.
if retry_until "$SETTLE" "[[ \"\$(bridged '$B' '$B_IP' $V4_PORT)\" == 1 ]]"; then
  pass "the daemon holds [$B_IP]:$V4_PORT (the bridge, not the app)"
else
  fail "nothing bridged [$B_IP]:$V4_PORT"
fi

# ---------------------------------------------------------------------------
step "3. the firewall is upstream of the bridge, not bypassed by it"
# Inbound is deny-by-default, so with the listener demonstrably up (step 2), a
# probe must still read CLOSED: the SYN dies on the packet path before it can
# reach our socket. A bridge that answered here would be a hole around the
# firewall, which is the one thing it must never be.
fw_denies "$A" "$B_IP" "$V4_PORT" "srv-a cannot reach a bridged port the firewall denies"
[[ "$(bridged "$B" "$B_IP" "$V4_PORT")" == 1 ]] \
  && pass "and the bridge listener was up the whole time (denied, not absent)" \
  || fail "the listener vanished, so the deny above proved nothing"

# ---------------------------------------------------------------------------
step "4. with the port allowed, an IPv4-only service answers over the mesh"
on "$B" "ray firewall add in allow -p tcp -P $V4_PORT" 2>&1 | strip | sed 's/^/   b| /'
fw_allows "$A" "$B_IP" "$V4_PORT" "srv-a reaches srv-b's 0.0.0.0 service over the mesh"

# ---------------------------------------------------------------------------
step "5. the bridge carries a real payload, by IP and by .ray name"
# A SYN handshake only proves the accept. This proves the splice: a request goes
# out over IPv6 and a body comes back from a server that never spoke IPv6.
CODE="$(fetch "$A" "http://[$B_IP]:$V4_PORT/")"
[[ "$CODE" == 200 ]] \
  && pass "srv-a: HTTP 200 from http://[$B_IP]:$V4_PORT/ (bytes both ways)" \
  || fail "srv-a: expected 200 over the bridge, got '$CODE'"
if retry_until 60 "[[ \"\$(fetch '$A' 'http://srv-b.$NET.ray:$V4_PORT/')\" == 200 ]]"; then
  pass "srv-a: HTTP 200 from http://srv-b.$NET.ray:$V4_PORT/ (Magic DNS + bridge)"
else
  fail "srv-a could not fetch the bridged port by .ray name"
fi

# ---------------------------------------------------------------------------
step "6. a loopback-only service is not bridged, even with its port allowed"
# Binding 127.0.0.1 is a deliberate choice to stay off the network. The firewall
# rule below removes the only other reason a probe could fail, so a CLOSED here
# is the bridge declining, not the packet path.
on "$B" "ray firewall add in allow -p tcp -P $LO_PORT" 2>&1 | strip | sed 's/^/   b| /'
[[ "$(bridged "$B" "$B_IP" "$LO_PORT")" == 0 ]] \
  && pass "the daemon holds no listener for the 127.0.0.1 service" \
  || fail "a loopback-only service was bridged onto the mesh address"
fw_denies "$A" "$B_IP" "$LO_PORT" "srv-a cannot reach srv-b's loopback-only service"

# ---------------------------------------------------------------------------
step "7. a bridged port stays bridged across rescans"
# Regression: a bridged port is itself an IPv6 listener on the mesh address, so
# a scan that does not recognise its own socket reads it as the service having
# grown IPv6 support, unbinds, then finds the port bare and rebinds. That
# shipped once and left every bridged port answering half the time, which no
# single probe would catch.
sleep 35   # > 2 rescans
[[ "$(bridged "$B" "$B_IP" "$V4_PORT")" == 1 ]] \
  && pass "still bound after two rescans (no bind/unbind flap)" \
  || fail "the bridge released the port on a rescan"
fw_allows "$A" "$B_IP" "$V4_PORT" "and srv-a still reaches it"

# ---------------------------------------------------------------------------
step "8. the bridge follows the service: stop it and the port is released"
unserve "$B" "$V4_PORT"
if retry_until "$SETTLE" "[[ \"\$(bridged '$B' '$B_IP' $V4_PORT)\" == 0 ]]"; then
  pass "the daemon dropped [$B_IP]:$V4_PORT once the service stopped"
else
  fail "the bridge kept a port whose service is gone"
fi
fw_denies "$A" "$B_IP" "$V4_PORT" "srv-a no longer reaches the stopped service"

step "9. start it again and the bridge takes the port back"
serve "$B" "$V4_PORT" 0.0.0.0
if retry_until "$SETTLE" "[[ \"\$(bridged '$B' '$B_IP' $V4_PORT)\" == 1 ]]"; then
  pass "the daemon rebound [$B_IP]:$V4_PORT"
else
  fail "the bridge did not pick the service back up"
fi
fw_allows "$A" "$B_IP" "$V4_PORT" "srv-a reaches it again"

# ---------------------------------------------------------------------------
step "10. ray config set v4-bridge off/on takes effect without a restart"
on "$B" 'ray config set v4-bridge off' 2>&1 | strip | sed 's/^/   b| /'
if retry_until 30 "[[ \"\$(bridged '$B' '$B_IP' $V4_PORT)\" == 0 ]]"; then
  pass "'v4-bridge off' dropped the listener on a live daemon"
else
  fail "'v4-bridge off' left the listener up"
fi
fw_denies "$A" "$B_IP" "$V4_PORT" "and srv-a can no longer reach the service"
on "$B" 'ray config set v4-bridge on' 2>&1 | strip | sed 's/^/   b| /'
if retry_until "$SETTLE" "[[ \"\$(bridged '$B' '$B_IP' $V4_PORT)\" == 1 ]]"; then
  pass "'v4-bridge on' brought it back"
else
  fail "'v4-bridge on' did not restore the listener"
fi

# ---------------------------------------------------------------------------
step "11. the bridge lives and dies with the data plane"
# It binds the mesh address, which goes down with the TUN, so `ray down` must
# release it rather than leave a socket on an address that no longer exists.
on "$B" 'ray down' 2>&1 | strip | sed 's/^/   b| /'
if retry_until 30 "[[ \"\$(bridged '$B' '$B_IP' $V4_PORT)\" == 0 ]]"; then
  pass "'ray down' released the bridged port"
else
  fail "'ray down' left a listener on the mesh address"
fi
on "$B" 'ray up' >/dev/null 2>&1 || true
if retry_until "$SETTLE" "[[ \"\$(bridged '$B' '$B_IP' $V4_PORT)\" == 1 ]]"; then
  pass "'ray up' brought the bridge back"
else
  fail "the bridge did not return after 'ray up'"
fi

# ---------------------------------------------------------------------------
step "12. a new listener is picked up from the kernel, not from a timer"
# Where the kernel reports listen changes (`src/listen_events.rs`), the timer
# drops to a 300s backstop, so anything close to immediate can only have come
# from an event. That is what makes this assertion non-vacuous: it is not
# "faster than the poll" by a margin someone has to trust, it is a whole order
# of magnitude below the only other thing that could have caused it.
if on "$B" '[ -d /sys/kernel/tracing/events/sock/inet_sock_set_state ]' >/dev/null 2>&1; then
  serve "$B" "$EV_PORT" 0.0.0.0
  took="$(seconds_until_bridged "$B" "$B_IP" "$EV_PORT" 60)"
  if (( took <= EVENT_PICKUP )); then
    pass "bridged [$B_IP]:$EV_PORT in ${took}s (backstop is 300s)"
  else
    fail "took ${took}s to bridge: the listen events are not arriving"
  fi
  unserve "$B" "$EV_PORT"
else
  # The docker backend lands here: a privileged container has
  # /sys/kernel/tracing as an empty directory with tracefs not mounted, so the
  # daemon finds no events and stays on its 15s timer. Assert the fallback
  # rather than skipping, but do not claim to have covered the event path.
  serve "$B" "$EV_PORT" 0.0.0.0
  if retry_until "$SETTLE" "[[ \"\$(bridged '$B' '$B_IP' $EV_PORT)\" == 1 ]]"; then
    pass "no tracefs here: the timer fallback bridged [$B_IP]:$EV_PORT"
  else
    fail "the timer fallback did not bridge [$B_IP]:$EV_PORT"
  fi
  unserve "$B" "$EV_PORT"
  echo "   note: the kernel-event path is NOT covered on this backend"
fi

# Leave the hosts in a clean state for a re-run.
unserve "$B" "$V4_PORT"
unserve "$B" "$LO_PORT"

# ---------------------------------------------------------------------------
summary
