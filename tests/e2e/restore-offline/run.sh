#!/usr/bin/env bash
# Member-restore-with-coordinator-offline e2e test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `priv`
#   srv-b  member (admitted with an invite)
#
# Regression guard for the bug where a member whose daemon restarts while its
# coordinator is offline silently drops the network from its running state
# (`ray status` -> "no active networks", inbound mesh rejected with "no handler
# for ALPN"), and stays that way until it happens to restart while the
# coordinator is reachable again. See PR #60 / issue #59.
#
# The member already holds the verified group blob, so being in the network must
# not depend on the coordinator answering at restore time. This test:
#   1. brings up a-coordinator + b-member and confirms they mesh,
#   2. stops the coordinator daemon entirely (not `ray down` standby — the
#      coordinator's endpoint must be genuinely unreachable),
#   3. restarts the member daemon (the restore-with-coordinator-offline path),
#   4. asserts the member STILL has the network + still lists the coordinator as
#      a (now offline) peer  <- this is the whole fix; pre-fix it fails here,
#   5. brings the coordinator back and asserts the member reconnects on its own.
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
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

NET=priv

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on both hosts"
wait_all_ssh "$A" "$B"
seed_known_hosts "$A" "$B"
reset_state "$A" "$B"
deploy_all "$ROOT" "$A" "$B"
for h in "$A" "$B"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B"

# ---------------------------------------------------------------------------
step "1. srv-a creates a closed network and srv-b joins with an invite"
CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   a| /'
has_net "$A" "$NET" && pass "network '$NET' created on srv-a" || { fail "create failed"; summary; }

INVITE="$(mint_invite "$A" "$NET" srv-b)"
[[ -n "$INVITE" ]] && pass "srv-a minted an invite (${INVITE:0:12}…)" || { fail "invite mint failed"; summary; }

on "$B" "ray join $INVITE --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'
wait_roster "$A" srv-b        # coordinator sees the member online
wait_roster "$B" srv-a        # member sees the coordinator online
has_net "$B" "$NET" && pass "srv-b joined '$NET'" || { fail "srv-b did not join"; summary; }

# ---------------------------------------------------------------------------
step "2. take the coordinator fully offline (systemctl stop, not 'ray down')"
# `ray down` is standby: the daemon stays connected to peers, so it would still
# answer the member's restore dial. We need the endpoint genuinely gone.
on "$A" 'systemctl stop rayfish' >/dev/null 2>&1 || true
if retry_until 45 "[[ \"\$(peer_online '$B' srv-a '$NET')\" == 0 ]]"; then
  pass "srv-b sees the coordinator go offline"
else
  fail "coordinator still shows online to srv-b after stop"
fi

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
step "4. THE FIX: the network survives a restart with the coordinator offline"
# Give restore a moment; the network should register from the cached blob
# without the coordinator. Pre-fix this stays "no active networks" forever.
if retry_until 60 "has_net '$B' '$NET'"; then
  pass "srv-b still has network '$NET' after restarting with coordinator offline"
else
  fail "REGRESSION: srv-b dropped '$NET' (no active networks) — restore gated on coordinator"
fi
# The coordinator must still appear in the member's roster (offline is fine): the
# network was registered from the blob, which lists it.
if retry_until 30 "[[ -n \"\$(peer_ip4 '$B' srv-a '$NET')\" ]]"; then
  pass "srv-b's roster still lists the coordinator (offline peer)"
else
  fail "srv-b's roster is missing the coordinator after blob restore"
fi
# And it must genuinely be offline right now (no live link to a stopped node).
[[ "$(peer_online "$B" srv-a "$NET")" == 0 ]] \
  && pass "coordinator correctly shows offline (no phantom connection)" \
  || fail "coordinator shows online while its daemon is stopped"

# ---------------------------------------------------------------------------
step "5. RECOVERY: bring the coordinator back, member reconnects on its own"
on "$A" 'systemctl start rayfish' >/dev/null 2>&1 || true
sleep 5
on "$A" 'ray up' >/dev/null 2>&1 || true
wait_daemons "$A"
# The reconnect loop (seeded at restore) keeps dialing with backoff, so the link
# forms without any manual step on the member.
wait_roster "$B" srv-a        # member reconnects to the coordinator
wait_roster "$A" srv-b        # coordinator sees the member again

summary
