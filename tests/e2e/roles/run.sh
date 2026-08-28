#!/usr/bin/env bash
# Coordinator-assigned roles e2e test orchestrator.
#
# Topology:
#   srv-a  coordinator + apply driver (closed network `hyperliquid`)
#   srv-b  sentry  (joined with the reusable --role sentry key)
#   srv-c  sentry  (joined with the SAME key, to prove one key seats a group)
#
# The point of roles is that a rule names a class of nodes, not one machine, so
# what this proves is the scale-out property a hostname cannot give:
#   - a reusable key may bind roles where it may not bind a hostname
#   - two nodes redeem the *same* code and are both seated as sentries
#   - a `role:` subject/peer resolves against the signed roster on each node
#   - a third sentry joining later is covered with NO second `ray apply`
#   - `--role` outside what the key grants refuses the join
#   - the resolved allow actually opens the port over the TUN
#
# Reads tests/e2e/roles/.servers (written by provision). Does NOT modify infra.
# Re-runnable (resets rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run provision first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/b/c in $SERVERS"; exit 1; }

NET=hyperliquid

# roles_of <ip> <hostname> : the roles the roster shows for a peer, comma-joined.
roles_of(){
  on "$1" 'ray status --json' 2>/dev/null | jq -r --arg h "$2" --arg n "$NET" \
    '[ .networks[]? | select(.name == $n) | .peers[]? | select(.hostname == $h)
       | .roles[]? ] | sort | join(",")'
}

# sugg_tcp_allow <ip> <port> : installed suggested-by-$NET inbound tcp ALLOW
# rules for <port>. One per resolved peer, so this counts role expansion.
sugg_tcp_allow(){
  on "$1" 'ray firewall show --json' 2>/dev/null | jq -r --arg p "$2" --arg n "$NET" \
    '[ .rules[]? | select((.suggested_by // "") == $n and .action == "allow"
        and (.protocol | ascii_downcase) == "tcp" and .port == $p) ] | length'
}

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"
reset_state "$A" "$B" "$C"
deploy_all "$ROOT" "$A" "$B" "$C"
# srv-a drives apply and is named as a literal subject, so pin its hostname.
# srv-b/srv-c deliberately do NOT get a pinned name: a reusable key cannot bind
# one, which is the whole reason policy keys on the role instead.
on "$A" 'ray up --hostname srv-a' >/dev/null 2>&1 || true
for h in "$B" "$C"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B" "$C"

# ---------------------------------------------------------------------------
step "1. apply publishes a role-keyed spec against an empty network"
# srv-a is the validator; every sentry may reach tcp:4000 on it. No sentry has
# joined yet, so this must publish cleanly and report the role as covering
# nobody rather than treating `role:sentry` as a host that failed to turn up.
on "$A" "printf 'networks:\n  $NET:\n    srv-a:\n      allows:\n        \"role:sentry\": \"tcp:4000\"\n' > /tmp/roles.yaml"
APPLY1="$(on "$A" "ray apply /tmp/roles.yaml" 2>&1 | strip)"
echo "$APPLY1" | sed 's/^/   a| /'
echo "$APPLY1" | grep -qi 'creating closed network' \
  && pass "apply created the closed network" || fail "apply did not create '$NET'"
echo "$APPLY1" | grep -q 'role:sentry' \
  && pass "apply reported the role it targets" || fail "role:sentry not reported"
echo "$APPLY1" | grep -qi 'no members yet' \
  && pass "role with no holders is called out" || fail "empty role not flagged"
# A role is not a host, so it must never appear as a gap to mint an invite for.
! echo "$APPLY1" | grep -q 'ray invite .* --hostname role:' \
  && pass "role is not reported as a missing host" || fail "role leaked into the host gap"
on "$A" "ray firewall auto-accept $NET on" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
step "2. one reusable key carries a role and seats two nodes"
# --hostname is refused on a reusable key; --role is not. That asymmetry is what
# lets a single code sit in user-data and cover a whole group.
HOSTBIND="$(on "$A" "ray invite $NET create --reusable --hostname sentry-01" 2>&1 | strip)"
# Assert on the message, not just a non-zero exit: a mistyped flag also fails,
# and would pass this check while testing nothing. clap rejects the pair before
# the daemon sees it, which is the refusal arriving one layer earlier.
echo "$HOSTBIND" | grep -qiE "cannot be used with|cannot bind a hostname" \
  && pass "a reusable key still refuses --hostname" \
  || fail "expected the hostname refusal, got: $HOSTBIND"
MINT="$(on "$A" "ray invite $NET create --reusable --role sentry --json" 2>&1 | strip | tail -1)"
echo "$MINT" | sed 's/^/   a| /'
KEY="$(echo "$MINT" | jq -r '.code')"
[[ -n "$KEY" && "$KEY" != null ]] \
  && pass "minted a reusable sentry key" || { fail "could not mint/parse the role key"; summary; }
[[ "$(echo "$MINT" | jq -r '.roles | join(",")')" == "sentry" ]] \
  && pass "--json echoes the role the key grants" || fail "minted key did not report its role"

# The same code on both hosts. This is the line a provisioner bakes into an image.
on "$B" "ray join $KEY --auto-accept-firewall" 2>&1 | strip | sed 's/^/   b| /'
on "$C" "ray join $KEY --auto-accept-firewall" 2>&1 | strip | sed 's/^/   c| /'
B_HOST="$(on "$B" 'ray status --json' | jq -r --arg n "$NET" '.networks[]?|select(.name==$n)|.my_hostname')"
C_HOST="$(on "$C" 'ray status --json' | jq -r --arg n "$NET" '.networks[]?|select(.name==$n)|.my_hostname')"
[[ -n "$B_HOST" && -n "$C_HOST" && "$B_HOST" != "$C_HOST" ]] \
  && pass "both nodes joined on one code, under distinct names ($B_HOST, $C_HOST)" \
  || fail "the shared key did not seat two distinct members"

# ---------------------------------------------------------------------------
step "3. the roster carries the role the coordinator assigned"
if retry_until 60 "[[ \"\$(roles_of '$A' '$B_HOST')\" == sentry ]]"; then
  pass "srv-b is a sentry in the signed roster"
else
  fail "srv-b roles = '$(roles_of "$A" "$B_HOST")', expected sentry"
fi
if retry_until 60 "[[ \"\$(roles_of '$A' '$C_HOST')\" == sentry ]]"; then
  pass "srv-c is a sentry in the signed roster"
else
  fail "srv-c roles = '$(roles_of "$A" "$C_HOST")', expected sentry"
fi

# ---------------------------------------------------------------------------
step "4. the role peer resolved to BOTH sentries with no re-apply"
# The suggestion published in step 1 named no members. Nothing has been applied
# since; the rules appear because the roster changed underneath it.
if retry_until 90 "[[ \"\$(sugg_tcp_allow '$A' 4000)\" -eq 2 ]]"; then
  pass "role:sentry materialized one rule per sentry, no second apply"
else
  fail "expected 2 suggested tcp:4000 allows on srv-a (got $(sugg_tcp_allow "$A" 4000))"
fi

# ---------------------------------------------------------------------------
step "5. the resolved allow actually opens the port over the TUN"
A_VPN="$(peer_ip "$B" srv-a "$NET")"
[[ -n "$A_VPN" ]] && pass "srv-b sees srv-a at $A_VPN" || { fail "srv-b cannot see srv-a"; summary; }
start_tcp_listener "$A" 4000
start_tcp_listener "$A" 8080   # not in the spec: default-deny covers it
fw_allows "$B" "$A_VPN" 4000 "a sentry reaches the role-allowed tcp:4000"
fw_denies "$B" "$A_VPN" 8080 "a sentry is still blocked on un-allowed tcp:8080"
stop_tcp_listener "$A" 4000
stop_tcp_listener "$A" 8080

# ---------------------------------------------------------------------------
step "6. asking for a role the key does not grant refuses the join"
# srv-c leaves and comes back asking to be a validator on a sentry key.
on "$C" "ray leave $NET" >/dev/null 2>&1 || true
retry_until 30 "! has_net '$C' '$NET'" >/dev/null 2>&1 || true
OUT="$(on "$C" "ray join $KEY --role validator" 2>&1 | strip)"
echo "$OUT" | sed 's/^/   c| /'
if has_net "$C" "$NET"; then
  fail "a join asking for an ungranted role was admitted anyway"
else
  pass "join refused for a role the key does not grant"
fi
echo "$OUT" | grep -qi 'role' \
  && pass "the refusal says it was about the role" || fail "refusal did not mention the role"

# ---------------------------------------------------------------------------
step "7. re-joining with the granted role works, and re-covers the rule"
on "$C" "ray join $KEY --role sentry --auto-accept-firewall" 2>&1 | strip | sed 's/^/   c| /'
if retry_until 90 "[[ \"\$(sugg_tcp_allow '$A' 4000)\" -eq 2 ]]"; then
  pass "the returning sentry is covered again with no apply"
else
  fail "expected 2 suggested tcp:4000 allows after re-join (got $(sugg_tcp_allow "$A" 4000))"
fi

# ---------------------------------------------------------------------------
summary
