#!/usr/bin/env bash
# Member-restore-with-coordinator-offline e2e test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `priv`
#   srv-b  member (admitted with an invite)  <- restarted mid-test
#   srv-c  member (admitted with an invite)  <- stays up, the peer srv-b must find
#
# Regression guard for the bug where a member whose daemon restarts while its
# coordinator is offline silently drops the network from its running state
# (`ray status` -> "no active networks", inbound mesh rejected with "no handler
# for ALPN"), and stays that way until it happens to restart while the
# coordinator is reachable again. See PR #60 / issue #59.
#
# The member already holds the verified group blob, so being in the network must
# not depend on the coordinator answering at restore time, and the member must
# connect to *any* available peer, not just the coordinator. The third host is
# what makes that second claim testable: with the coordinator stopped, the
# restarted member has to re-mesh with the other member on its own.
#
# Flow:
#   1. a-coordinator + b-member + c-member come up and full-mesh,
#   2. the coordinator daemon is stopped entirely (not `ray down` standby, so its
#      endpoint is genuinely unreachable); b and c stay linked to each other,
#   3. srv-b's daemon is restarted (the restore-with-coordinator-offline path),
#   4. asserts srv-b still has the network AND reconnects to srv-c while the
#      coordinator is still down  <- the whole fix; pre-fix it fails here,
#   5. brings the coordinator back and asserts the full mesh reconverges.
#
# Reads tests/e2e/restore-offline/.servers (written by provision). Does NOT
# modify infra. Re-runnable (resets rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run '$ROOT/tests/e2e.sh restore-offline provision' first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/srv-b/srv-c in $SERVERS"; exit 1; }

NET=priv

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"
reset_state "$A" "$B" "$C"
deploy_all "$ROOT" "$A" "$B" "$C"
for h in "$A" "$B" "$C"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B" "$C"

# ---------------------------------------------------------------------------
step "1. srv-a creates a closed network; srv-b and srv-c join with invites"
CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   a| /'
has_net "$A" "$NET" && pass "network '$NET' created on srv-a" || { fail "create failed"; summary; }

INV_B="$(mint_invite "$A" "$NET" srv-b)"
INV_C="$(mint_invite "$A" "$NET" srv-c)"
[[ -n "$INV_B" && -n "$INV_C" ]] && pass "srv-a minted invites for srv-b and srv-c" \
  || { fail "invite mint failed"; summary; }

on "$B" "ray join $INV_B --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'
on "$C" "ray join $INV_C --hostname srv-c" 2>&1 | strip | sed 's/^/   c| /'

# Full mesh: every node sees the other two online.
wait_roster "$A" srv-b srv-c
wait_roster "$B" srv-a srv-c
wait_roster "$C" srv-a srv-b

# ---------------------------------------------------------------------------
step "2. take the coordinator fully offline (systemctl stop, not 'ray down')"
# `ray down` is standby: the daemon stays connected to peers, so it would still
# answer the member's restore dial. We need the endpoint genuinely gone.
on "$A" 'systemctl stop rayfish' >/dev/null 2>&1 || true
if retry_until 45 "[[ \"\$(peer_online '$B' srv-a '$NET')\" == 0 && \"\$(peer_online '$C' srv-a '$NET')\" == 0 ]]"; then
  pass "srv-b and srv-c both see the coordinator go offline"
else
  fail "coordinator still shows online after stop"
fi
# The two members keep their direct link to each other with the coordinator gone.
[[ "$(peer_online "$B" srv-c "$NET")" == 1 ]] \
  && pass "srv-b <-> srv-c stay linked without the coordinator" \
  || fail "srv-b lost its link to srv-c when the coordinator went down"

# ---------------------------------------------------------------------------
step "3. restart the member daemon while the coordinator is offline"
# This is the exact failure path: startup restore dials the coordinator, which
# is unreachable. Pre-fix, restore aborted and the network was never registered.
on "$B" 'systemctl restart rayfish' >/dev/null 2>&1 || true
sleep 5
on "$B" 'ray up' >/dev/null 2>&1 || true
if retry_until 30 "on '$B' 'ray status' >/dev/null 2>&1"; then
  pass "srv-b daemon responds after restart"
else
  fail "srv-b daemon not responding after restart"; summary
fi

# ---------------------------------------------------------------------------
step "4. THE FIX: network survives + member re-meshes with the OTHER member"
# 4a. The network registers from the cached blob without the coordinator.
#     Pre-fix this stays "no active networks" forever.
if retry_until 60 "has_net '$B' '$NET'"; then
  pass "srv-b still has network '$NET' after restarting with coordinator offline"
else
  fail "REGRESSION: srv-b dropped '$NET' (no active networks) — restore gated on coordinator"; summary
fi
# 4b. The heart of the fix: connect to any available peer, not just the
#     coordinator. srv-b must reconnect to srv-c while srv-a is still down.
if retry_until 90 "[[ \"\$(peer_online '$B' srv-c '$NET')\" == 1 ]]"; then
  pass "srv-b reconnected to srv-c with the coordinator still offline"
else
  fail "srv-b did not re-mesh with srv-c — restore did not connect to available peers"
fi
# 4c. srv-c sees srv-b back too (the link is bidirectional and real).
if retry_until 60 "[[ \"\$(peer_online '$C' srv-b '$NET')\" == 1 ]]"; then
  pass "srv-c sees srv-b reconnected"
else
  fail "srv-c does not see srv-b after its restart"
fi
# 4d. The coordinator is still listed as a peer, and correctly offline.
[[ -n "$(peer_ip4 "$B" srv-a "$NET")" ]] \
  && pass "srv-b's roster still lists the coordinator (offline peer)" \
  || fail "srv-b's roster is missing the coordinator after blob restore"
[[ "$(peer_online "$B" srv-a "$NET")" == 0 ]] \
  && pass "coordinator correctly shows offline (no phantom connection)" \
  || fail "coordinator shows online while its daemon is stopped"

# ---------------------------------------------------------------------------
step "5. RECOVERY: bring the coordinator back, full mesh reconverges"
on "$A" 'systemctl start rayfish' >/dev/null 2>&1 || true
sleep 5
on "$A" 'ray up' >/dev/null 2>&1 || true
wait_daemons "$A"
# The reconnect loop (seeded at restore) keeps dialing with backoff, so links
# form without any manual step on the members.
wait_roster "$B" srv-a srv-c
wait_roster "$C" srv-a srv-b
wait_roster "$A" srv-b srv-c

summary
