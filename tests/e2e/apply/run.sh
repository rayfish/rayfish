#!/usr/bin/env bash
# `ray apply` declarative-deploy e2e test orchestrator.
#
# Topology:
#   srv-a  coordinator + apply driver (closed network `infra`)
#   srv-b  member (joined via an --invite-missing invite, auto-accepts firewall)
#   srv-c  member (joined via an --invite-missing invite, auto-accepts firewall)
#
# Exercises the full `ray apply` surface the closed-net smoke only touches at the
# --example/--dry-run level — here against a live daemon, end to end:
#   - create-if-absent: apply mints a missing closed network, never joins
#   - membership diff: the gap is reported as `ray invite … --hostname …` lines
#   - --invite-missing: those invites are minted, and the named hosts join under
#     their bound hostnames
#   - `ray identityof`: prints a joined host's identity (+ negative for a stranger)
#   - aliases/groups: a spec aliases a user and groups it with a literal hostname,
#     then references the group as a firewall subject/peer; --dry-run shows the
#     expansion resolving to concrete hostnames (sugar never survives)
#   - real apply publishes the expanded suggestions, the coordinator materializes
#     its own, and the resolved allow actually opens the port over the TUN
#   - --prune drops an out-of-band suggestion the spec doesn't mention
#
# Reads tests/e2e/apply/.servers (written by provision). Does NOT modify infra.
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

NET=infra

# sugg_tcp_allow <ip> <port> : count of installed *suggested-by-infra* inbound
# tcp ALLOW rules for <port> on a node (from `ray firewall show --json`). Proves
# an expanded suggestion materialized into a real rule.
sugg_tcp_allow(){
  on "$1" 'ray firewall show --json' 2>/dev/null | jq -r --arg p "$2" \
    '[ .rules[]? | select((.suggested_by // "") == "infra" and .action == "allow"
        and (.protocol | ascii_downcase) == "tcp" and .port == $p) ] | length'
}

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"
reset_state "$A" "$B" "$C"
deploy_all "$ROOT" "$A" "$B" "$C"
for h in "$A" "$B" "$C"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B" "$C"

# ---------------------------------------------------------------------------
step "1. apply creates the closed network + reports the membership gap"
# A spec naming srv-a (subject) plus srv-b/srv-c (peers). expected hosts =
# {srv-a, srv-b, srv-c}; only srv-a is joined, so the gap is srv-b + srv-c.
on "$A" "printf 'networks:\n  $NET:\n    srv-a:\n      allows:\n        srv-b: \"tcp:22\"\n        srv-c: \"tcp:22\"\n' > /tmp/spec1.yaml"
APPLY1="$(on "$A" "ray apply /tmp/spec1.yaml" 2>&1 | strip)"
echo "$APPLY1" | sed 's/^/   a| /'
echo "$APPLY1" | grep -qi 'creating closed network' \
  && pass "apply created the closed network" || fail "apply did not create '$NET'"
has_net "$A" "$NET" && pass "'$NET' now present on srv-a" || fail "'$NET' missing on srv-a after apply"
echo "$APPLY1" | grep -qi 'Missing hosts' \
  && pass "apply reported a membership gap" || fail "no membership gap reported"
echo "$APPLY1" | grep -q "ray invite $NET --hostname srv-b" \
  && pass "gap lists an invite command for srv-b" || fail "srv-b not in the gap"
echo "$APPLY1" | grep -q "ray invite $NET --hostname srv-c" \
  && pass "gap lists an invite command for srv-c" || fail "srv-c not in the gap"
# apply never joins — the members must not have the network yet.
! has_net "$B" "$NET" && ! has_net "$C" "$NET" \
  && pass "apply did not auto-join the members" || fail "apply unexpectedly joined a member"

# ---------------------------------------------------------------------------
step "2. --invite-missing mints invites; the named hosts join"
APPLY2="$(on "$A" "ray apply /tmp/spec1.yaml --invite-missing" 2>&1 | strip)"
echo "$APPLY2" | sed 's/^/   a| /'
echo "$APPLY2" | grep -qi 'already active' \
  && pass "second apply saw the network already active" || fail "network not reported active on re-apply"
# Each gap line ends in `→ <join-code>`; the code is a long bs58 token.
CODE_B="$(echo "$APPLY2" | grep -- '--hostname srv-b' | grep -oE '[A-Za-z0-9]{40,}' | tail -1)"
CODE_C="$(echo "$APPLY2" | grep -- '--hostname srv-c' | grep -oE '[A-Za-z0-9]{40,}' | tail -1)"
[[ -n "$CODE_B" && -n "$CODE_C" ]] \
  && pass "--invite-missing minted invites for srv-b + srv-c" \
  || { fail "could not parse minted invite codes"; summary; }
on "$B" "ray join $CODE_B --auto-accept-firewall" 2>&1 | strip | sed 's/^/   b| /'
on "$C" "ray join $CODE_C --auto-accept-firewall" 2>&1 | strip | sed 's/^/   c| /'
wait_roster "$A" srv-b srv-c

# ---------------------------------------------------------------------------
step "3. ray identityof prints a joined host's identity"
B_IDENT="$(on "$A" "ray identityof $NET srv-b" | strip | tr -d '[:space:]')"
[[ -n "$B_IDENT" ]] && pass "identityof srv-b printed an identity (${B_IDENT:0:16}…)" \
  || { fail "identityof srv-b printed nothing"; summary; }
# --json carries the same identity and paired=false (srv-b is unpaired).
PAIRED="$(on "$A" "ray identityof $NET srv-b --json" 2>/dev/null | jq -r '.paired')"
[[ "$PAIRED" == "false" ]] && pass "identityof --json reports paired=false" || fail "unexpected paired=$PAIRED"
# A stranger hostname must error (an alias can only name a joined member).
if on "$A" "ray identityof $NET ghost" >/dev/null 2>&1; then
  fail "identityof for a non-joined host should have failed"
else
  pass "identityof errors for a host that has not joined"
fi

# ---------------------------------------------------------------------------
step "4. aliases + groups expand to concrete hostnames (dry-run)"
# bob = srv-b's user (by identity); team = bob + the literal hostname srv-c.
# Reference `team` as a firewall peer; the expansion must resolve it to srv-b +
# srv-c and leave no `bob`/`team` sugar behind.
on "$A" "printf 'aliases:\n  bob: %s\ngroups:\n  team: [bob, srv-c]\nnetworks:\n  $NET:\n    \"*\":\n      allows:\n        team: \"tcp:22\"\n' '$B_IDENT' > /tmp/spec2.yaml"
DRY="$(on "$A" "ray apply /tmp/spec2.yaml --dry-run" 2>&1 | strip)"
echo "$DRY" | sed 's/^/   a| /'
echo "$DRY" | grep -qi 'Spec (expanded)' \
  && pass "dry-run echoed the expanded spec" || fail "dry-run did not expand the spec"
echo "$DRY" | grep -q 'srv-b' && echo "$DRY" | grep -q 'srv-c' \
  && pass "group resolved to srv-b + srv-c" || fail "group did not resolve to both hosts"
! echo "$DRY" | grep -qiE '(^|[^a-z])(bob|team)([^a-z]|$)' \
  && pass "no alias/group sugar survives expansion" || fail "alias/group name leaked into the expanded spec"

# ---------------------------------------------------------------------------
step "5. real apply publishes the expanded suggestions"
APPLY5="$(on "$A" "ray apply /tmp/spec2.yaml" 2>&1 | strip)"
echo "$APPLY5" | sed 's/^/   a| /'
# srv-a is subject `*`, so it materializes its own inbound tcp:22 allow for each
# resolved team member (srv-b + srv-c) — the coordinator installs its own.
if retry_until 60 "[[ \"\$(sugg_tcp_allow '$A' 22)\" -ge 2 ]]"; then
  pass "coordinator materialized 2 suggested tcp:22 allows (group expanded to 2 peers)"
else
  fail "expected ≥2 suggested tcp:22 allows on srv-a (got $(sugg_tcp_allow "$A" 22))"
fi

# ---------------------------------------------------------------------------
step "6. the resolved allow actually opens the port over the TUN"
A_VPN="$(peer_ip4 "$B" srv-a "$NET")"
[[ -n "$A_VPN" ]] && pass "srv-b sees srv-a at $A_VPN" || { fail "srv-b cannot see srv-a's VPN ip"; summary; }
start_tcp_listener "$A" 8080   # a port the spec does NOT allow (default-deny covers it)
# tcp:22 is sshd (always listening) and is the allowed port; 8080 is denied.
fw_allows "$B" "$A_VPN" 22 "team member reaches allowed tcp:22 on srv-a"
fw_denies "$B" "$A_VPN" 8080 "team member blocked on un-allowed tcp:8080"
stop_tcp_listener "$A" 8080

# ---------------------------------------------------------------------------
step "7. --prune drops an out-of-band suggestion"
# Suggest a rule the spec doesn't mention (subject srv-a, tcp:8080).
on "$A" "ray firewall suggest $NET --subject srv-a --allow tcp:8080" 2>&1 | strip | sed 's/^/   a| /'
if retry_until 30 "[[ \"\$(sugg_tcp_allow '$A' 8080)\" -ge 1 ]]"; then
  pass "out-of-band tcp:8080 suggestion installed on srv-a"
else
  fail "out-of-band suggestion never installed"
fi
# Apply spec2 (subject `*` only) with --prune: it publishes exactly the spec's
# subjects, so the subject-srv-a 8080 suggestion is dropped, tcp:22 survives.
on "$A" "ray apply /tmp/spec2.yaml --prune" 2>&1 | strip | sed 's/^/   a| /'
if retry_until 60 "[[ \"\$(sugg_tcp_allow '$A' 8080)\" -eq 0 ]]"; then
  pass "--prune dropped the out-of-band tcp:8080 suggestion"
else
  fail "--prune did not drop the out-of-band suggestion (got $(sugg_tcp_allow "$A" 8080))"
fi
[[ "$(sugg_tcp_allow "$A" 22)" -ge 2 ]] \
  && pass "--prune kept the spec's tcp:22 suggestions" || fail "--prune wrongly dropped the spec's own rules"

# ---------------------------------------------------------------------------
summary
