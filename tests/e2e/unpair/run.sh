#!/usr/bin/env bash
# `ray unpair` (device-cert revocation) e2e test orchestrator.
#
# Topology (mirrors the device-cert test):
#   srv-a  identity U   primary device + coordinator of a closed network
#   srv-b  identity U   paired into A's identity via a DeviceCert (ray pair)
#   srv-c  identity V   independent third peer, also a member
#
# Proves the full unpair flow over real hosts + the public pkarr DHT:
#   A pairs B  ->  B joins A's closed network  ->  A `ray unpair srv-b`
#   ->  A saves B's key as revoked, adds it to the network's nullifier set in the
#       signed blob, drops B from the roster, and severs it
#   ->  C prunes B on reconverge (cross-node propagation of the nullifier)
#   ->  B can no longer re-join (its cert is nullified)
#   ->  B's device cert is wiped once A's notice reaches it.
#
# NOTE: revocation is per device, so a second device paired into U keeps working
# after srv-b is unpaired. Checking that needs another host (add an srv-d). Not
# exercised by this 3-host topology.
#
# Reads .servers (written by provision.sh). Does NOT modify infra.
# Re-runnable: pairing/join steps tolerate "already done".
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"
SR_PREFIX=/tmp/u   # temp-file prefix for send_recv

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run $DIR/provision.sh first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/b/c in $SERVERS"; exit 1; }

# ---------------------------------------------------------------------------
step "0. wait for SSH on all hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"
reset_state "$A" "$B" "$C"
deploy_all "$ROOT" "$A" "$B" "$C"
wait_daemons "$A" "$B" "$C"

# ---------------------------------------------------------------------------
step "1. pair srv-b into srv-a's identity (device cert)"
A_ENDPOINT="$(on "$A" 'ray status' | strip | awk '/endpoint/{print $2}')"
echo "   srv-a endpoint/identity: $A_ENDPOINT"
TICKET="$(on "$A" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
if [[ -z "$TICKET" ]]; then fail "could not obtain pairing ticket from srv-a"; else
  B_PAIR=""
  for _ in 1 2 3 4 5; do
    B_PAIR="$(on "$B" "ray pair $TICKET" | strip)"
    echo "$B_PAIR" | grep -qi 'Paired successfully' && break
    sleep 3
    TICKET="$(on "$A" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
  done
  echo "$B_PAIR" | grep -qi 'Paired successfully' && pass "srv-b paired" || fail "srv-b pairing did not complete"
fi
# Restart srv-b so it loads the device cert from disk before joining.
on "$B" 'systemctl restart rayfish' >/dev/null 2>&1
for _ in $(seq 1 20); do on "$B" 'ray status' >/dev/null 2>&1 && break; sleep 3; done

# ---------------------------------------------------------------------------
step "2. create closed network on srv-a and admit srv-b + srv-c"
NET=e2e
CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   | /'
INV_B="$(mint_invite "$A" "$NET" srv-b)"
INV_C="$(mint_invite "$A" "$NET" srv-c)"
[[ -n "$INV_B" ]] && on "$B" "ray join $INV_B" 2>&1 | strip | sed 's/^/   b| /'
[[ -n "$INV_C" ]] && on "$C" "ray join $INV_C" 2>&1 | strip | sed 's/^/   c| /'
wait_roster "$A" srv-b srv-c
SB="$(on "$B" 'ray status' | strip)"; SC="$(on "$C" 'ray status' | strip)"
B_IP="$(own_ip "$SB")"; C_IP="$(own_ip "$SC")"
echo "   B_IP=$B_IP  C_IP=$C_IP"
# Hard stop, not a skipped probe. Step 5 asserts revocation by pinging $B_IP and
# reads an empty target as "no route", so a missing address here does not skip
# that assertion, it passes it: `ping` prints usage, the loss parse comes back
# empty, and the run reports a severed peer it never reached in the first place.
[[ -n "$B_IP" && -n "$C_IP" ]] || { fail "could not read srv-b/srv-c mesh IPv6"; summary; }

# Baseline: C can reach B before revocation.
png "$C" "$B_IP" "baseline: srv-c -> srv-b reachable"

# ---------------------------------------------------------------------------
step "3. srv-a lists its paired devices (ray pair list)"
PLIST="$(on "$A" 'ray pair list' | strip)"
echo "$PLIST" | sed 's/^/   a| /'
if echo "$PLIST" | grep -qi 'srv-b'; then
  pass "srv-b appears in 'ray pair list' on the primary"
else
  fail "srv-b not listed by 'ray pair list'"
fi

# ---------------------------------------------------------------------------
step "4. srv-a unpairs srv-b"
# A secondary cannot unpair (primary-only guard). Assert this *before* srv-a
# unpairs srv-b below: that unpair tells srv-b to wipe its own cert, after which
# srv-b is no longer a secondary and the guard would no longer apply.
SEC="$(on "$B" 'ray unpair srv-a' 2>&1 | strip || true)"
echo "$SEC" | grep -qi 'only your primary device can unpair' \
  && pass "secondary refused to unpair (primary-only)" \
  || fail "secondary was not refused (expected primary-only error)"

UNPAIR="$(on "$A" 'ray unpair srv-b' 2>&1 | strip)"
echo "$UNPAIR" | sed 's/^/   a| /'
if echo "$UNPAIR" | grep -qi 'nullified its device certificate'; then
  pass "srv-a unpaired srv-b"
else
  fail "ray unpair srv-b did not report success"
fi

# ---------------------------------------------------------------------------
step "5. nullifier propagates: srv-c drops srv-b"
# Give the republished blob time to publish + srv-c's poller/reconverge to run.
DROPPED=0
for _ in $(seq 1 12); do
  LOSS="$(ping_loss "$C" "$B_IP")"
  # After pruning, srv-c has no route to srv-b -> 100% loss (or ping errors).
  if [[ -z "$LOSS" || "$LOSS" == "100" ]]; then DROPPED=1; break; fi
  sleep 5
done
[[ "$DROPPED" == "1" ]] && pass "srv-c can no longer reach srv-b (revoked device severed)" \
  || fail "srv-c still reaching srv-b after unpair"

# srv-b should no longer be a member of the network on the coordinator.
if on "$A" 'ray status --json' 2>/dev/null | strip | grep -qi 'srv-b'; then
  fail "srv-b still in srv-a's roster after unpair"
else
  pass "srv-b removed from srv-a's roster"
fi

# ---------------------------------------------------------------------------
step "6. srv-b cannot re-join (its cert is revoked)"
# Restart srv-b so it re-dials, then confirm it does not re-appear in the roster.
on "$B" 'systemctl restart rayfish' >/dev/null 2>&1
for _ in $(seq 1 20); do on "$B" 'ray status' >/dev/null 2>&1 && break; sleep 3; done
REJOINED=0
for _ in $(seq 1 8); do
  on "$A" 'ray status --json' 2>/dev/null | strip | grep -qi 'srv-b' && { REJOINED=1; break; }
  sleep 5
done
[[ "$REJOINED" == "0" ]] && pass "srv-b did not re-join (revoked cert rejected at admission)" \
  || fail "srv-b re-joined despite revocation"

# ---------------------------------------------------------------------------
step "7. srv-b's device cert deleted"
# The primary saved that srv-b has yet to be told, and sends it
# ControlMsg::PairingRevoked, dialing it, until srv-b confirms its cleanup; srv-b
# deletes its own cert when told. Checked once here, so a notice still in flight
# is a note, not a hard failure.
if on "$B" 'test -f /etc/rayfish/device_cert'; then
  echo "   note: srv-b still has a device_cert on disk (the notice may still be in flight)"
else
  pass "srv-b's device cert was wiped"
fi

# ---------------------------------------------------------------------------
summary
