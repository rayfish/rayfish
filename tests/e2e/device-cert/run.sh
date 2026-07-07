#!/usr/bin/env bash
# Device-cert 3-peer e2e test orchestrator.
#
# Topology (see docs/superpowers/specs/2026-06-24-device-cert-e2e-design.md):
#   srv-a  identity U   primary device + coordinator of a closed network
#   srv-b  identity U   paired into A's identity via a DeviceCert (ray pair)
#   srv-c  identity V   independent third peer
#
# Proves that C can ping + ray-send to the U identity regardless of which
# physical device (A or B) backs it, and that A/B share one user identity/IP.
#
# Reads .servers (written by provision.sh). Does NOT modify infra.
# Re-runnable: pairing/join steps tolerate "already done".
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

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
step "2. pair srv-b into srv-a's identity (device cert)"
A_ENDPOINT="$(status_json "$A" | jq -r '.endpoint // empty')"
echo "   srv-a endpoint/identity: $A_ENDPOINT"

# `ray pair` on A arms the daemon's pairing accept loop and prints a ticket.
TICKET="$(on "$A" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
if [[ -z "$TICKET" ]]; then fail "could not obtain pairing ticket from srv-a"; else
  echo "   ticket: ${TICKET:0:16}…"
  # B accepts; retry a few times in case it races the arm on A.
  B_PAIR=""
  for _ in 1 2 3 4 5; do
    B_PAIR="$(on "$B" "ray pair $TICKET" | strip)"
    echo "$B_PAIR" | grep -qi 'Paired successfully' && break
    sleep 3
    TICKET="$(on "$A" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
  done
  echo "$B_PAIR" | sed 's/^/   | /'
  B_USER="$(echo "$B_PAIR" | awk -F': ' '/User identity/{print $2}' | tr -d ' ')"
  if echo "$B_PAIR" | grep -qi 'Paired successfully'; then
    pass "srv-b paired"
    if [[ -n "$B_USER" && "$B_USER" == "$A_ENDPOINT" ]]; then
      pass "srv-b user identity == srv-a identity ($B_USER)"
    else
      fail "srv-b user identity ($B_USER) != srv-a identity ($A_ENDPOINT)"
    fi
  else
    fail "srv-b pairing did not complete"
  fi
fi

# `ray pair` stores the device cert to disk but does NOT refresh the running
# daemon's in-memory copy (self.device_cert). A join in the same session would
# therefore omit the cert and the coordinator would record srv-b as an
# independent identity instead of user U. Restart srv-b so it loads the cert
# from disk before joining. (See run notes — this restart works around a real
# product bug.)
echo ">> restarting srv-b daemon so it loads the new device cert before joining"
on "$B" 'systemctl restart rayfish' >/dev/null 2>&1
for _ in $(seq 1 20); do on "$B" 'ray status' >/dev/null 2>&1 && break; sleep 3; done
pass "srv-b daemon restarted (device cert loaded)"

# ---------------------------------------------------------------------------
step "3. create closed network on srv-a + mint hostname-bound invites"
NET=e2e
# Closed is the default (no flag); invites gate admission.
CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   | /'
ROOM="$(echo "$CREATE" | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1)"
if [[ -n "$ROOM" ]]; then pass "network '$NET' created (room ${ROOM:0:12}…)"; else
  # maybe it already exists from a previous run
  on "$A" "ray status" | strip | grep -q "$NET" && { pass "network '$NET' already exists"; } || fail "network create failed"
fi

# mint_invite (coord-ip, net, hostname) comes from common.sh.
INV_B="$(mint_invite "$A" "$NET" srv-b)"
INV_C="$(mint_invite "$A" "$NET" srv-c)"
[[ -n "$INV_B" ]] && pass "invite for srv-b (${INV_B:0:12}…)" || fail "no invite for srv-b"
[[ -n "$INV_C" ]] && pass "invite for srv-c (${INV_C:0:12}…)" || fail "no invite for srv-c"

# ---------------------------------------------------------------------------
step "4. srv-b and srv-c join the closed network"
if [[ -n "$INV_B" ]]; then
  on "$B" "ray join $INV_B" 2>&1 | strip | sed 's/^/   b| /'
fi
if [[ -n "$INV_C" ]]; then
  on "$C" "ray join $INV_C" 2>&1 | strip | sed 's/^/   c| /'
fi
# Backstop: admit anything queued (a valid invite should auto-admit).
sleep 3
REQ="$(on "$A" "ray requests $NET" 2>/dev/null | strip || true)"
echo "$REQ" | grep -qiE '[0-9a-f]{6,}' && { echo "   pending requests found, accepting:"; echo "$REQ" | sed 's/^/   r| /'; \
  echo "$REQ" | awk '/^ /{print $1}' | while read -r rid; do [[ -n "$rid" ]] && on "$A" "ray accept $NET $rid" | strip | sed 's/^/   a| /'; done; }

# ---------------------------------------------------------------------------
step "5. wait for roster convergence (A, B, C all visible)"
# wait_roster (common.sh) blocks until the coordinator sees both members online
# (parsed from `ray status --json`, not table-grep) and PASS/FAILs.
wait_roster "$A" srv-b srv-c
SA="$(on "$A" 'ray status' | strip)"; SB="$(on "$B" 'ray status' | strip)"; SC="$(on "$C" 'ray status' | strip)"
echo "---- srv-a status ----"; echo "$SA" | sed 's/^/   a| /'
echo "---- srv-b status ----"; echo "$SB" | sed 's/^/   b| /'
echo "---- srv-c status ----"; echo "$SC" | sed 's/^/   c| /'

# Extract each node's own VPN IPv4 (own_ip from common.sh; CGNAT 100.64.0.0/10).
A_IP="$(own_ip "$SA")"; B_IP="$(own_ip "$SB")"; C_IP="$(own_ip "$SC")"
echo "   A_IP=$A_IP  B_IP=$B_IP  C_IP=$C_IP"

# ---------------------------------------------------------------------------
step "6. identity assertions"
# Rayfish derives the VPN IP from the per-device EndpointId (not the user
# identity), so paired devices share a USER IDENTITY but get DISTINCT IPs
# (Tailscale-style). Assert all three IPs are present and pairwise distinct.
if [[ -n "$A_IP" && -n "$B_IP" && -n "$C_IP" \
      && "$A_IP" != "$B_IP" && "$A_IP" != "$C_IP" && "$B_IP" != "$C_IP" ]]; then
  pass "three distinct per-device IPs (srv-a=$A_IP srv-b=$B_IP srv-c=$C_IP)"
else
  fail "expected three distinct IPs (srv-a=$A_IP srv-b=$B_IP srv-c=$C_IP)"
fi
# Network-level device-cert recognition: the coordinator (srv-a) must resolve
# srv-b's transport key to srv-a's own USER IDENTITY. Read it from the status
# JSON peer schema (`.user_identity`) instead of scraping the coloured table.
B_USER_SEEN="$(status_json "$A" | jq -r --arg h srv-b \
  '[ (.networks // [])[].peers[] | select((.hostname // "") == $h) ] | .[0].user_identity // empty')"
if [[ -n "$A_ENDPOINT" && "$B_USER_SEEN" == "$A_ENDPOINT" ]]; then
  pass "coordinator resolves srv-b to srv-a's user identity (${B_USER_SEEN:0:10}…) — device cert recognized"
else
  fail "coordinator tags srv-b user_identity='$B_USER_SEEN', expected srv-a '$A_ENDPOINT' (device cert not recognized at join)"
fi

# ---------------------------------------------------------------------------
step "7. reachability — ping over the TUN (both directions)"
# png (PASS on 0% loss) comes from common.sh.
# srv-c must reach BOTH physical devices backing identity U:
[[ -n "$C_IP" && -n "$A_IP" ]] && png "$C" "$A_IP" "srv-c -> srv-a ($A_IP, device A of U)"
[[ -n "$C_IP" && -n "$B_IP" ]] && png "$C" "$B_IP" "srv-c -> srv-b ($B_IP, device B of U)"
# ...and both U devices must reach srv-c:
[[ -n "$A_IP" && -n "$C_IP" ]] && png "$A" "$C_IP" "srv-a -> srv-c ($C_IP)"
[[ -n "$B_IP" && -n "$C_IP" ]] && png "$B" "$C_IP" "srv-b -> srv-c ($C_IP)"

# ---------------------------------------------------------------------------
step "8. data transfer — ray send / ray files accept"
# send_recv (1MiB random file, sha256 round-trip) comes from common.sh.
# C reaches BOTH physical devices backing identity U, addressed by hostname:
send_recv "$C" "$A" srv-a "ray send srv-c -> srv-a (device A of identity U)"
send_recv "$C" "$B" srv-b "ray send srv-c -> srv-b (device B of identity U)"
# reverse direction: a U device -> C
send_recv "$A" "$C" srv-c "ray send srv-a -> srv-c (reverse)"

# ---------------------------------------------------------------------------
summary
