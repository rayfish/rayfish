#!/usr/bin/env bash
# Suggested-firewall + rule-matrix e2e test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `fw` (mints invites, suggests rules)
#   srv-b  member, NO --auto-accept-firewall  (suggestions queue in `pending`)
#   srv-c  member, --auto-accept-firewall      (suggestions auto-install)
#
# Proves the parts of the firewall the unit tests can't reach end to end:
#   - coordinator `suggest` -> rides the signed blob -> a non-auto-accept member
#     sees it in `firewall pending`, `firewall accept` installs it, and it shows
#     up tagged `(suggested by fw)` and actually changes data-plane reachability;
#   - `--auto-accept-firewall` installs without review; `auto-accept off` queues;
#   - whitelist (allow-list + the node's own default-deny) vs blacklist
#     (denies-only) semantics observed by real TCP probes;
#   - the rule matrix: UDP, a TCP port range, same-selector replace (allow↔deny),
#     and per-network rule scoping (`--network`) at the data plane;
#   - `ray send` reaches a deny-all host: file transfer rides FILES_ALPN (a
#     control-plane QUIC stream), not TUN/IP traffic, so the firewall never gates it.
#
# Reads tests/e2e/firewall/.servers (written by provision.sh). Does NOT modify
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
C="$(server_ip "$SERVERS" srv-c || true)"
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/b/c in $SERVERS"; exit 1; }

NET=fw

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"
reset_state "$A" "$B" "$C"
deploy_all "$ROOT" "$A" "$B" "$C"
for h in "$A" "$B" "$C"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B" "$C"

# ---------------------------------------------------------------------------
step "1. srv-a creates the closed network; srv-b + srv-c join via invites"
CREATE="$(on "$A" "ray create --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   a| /'
has_net "$A" "$NET" && pass "network '$NET' present on coordinator" || fail "create failed"

INV_B="$(mint_invite "$A" "$NET" srv-b)"
INV_C="$(mint_invite "$A" "$NET" srv-c)"
[[ -n "$INV_B" && -n "$INV_C" ]] && pass "minted invites for srv-b + srv-c" || fail "invite mint failed"
on "$B" "ray join $INV_B --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'
# srv-c joins with auto-accept so suggestions install without review.
on "$C" "ray join $INV_C --hostname srv-c --auto-accept-firewall" 2>&1 | strip | sed 's/^/   c| /'
wait_roster "$A" srv-b srv-c

A_IP="$(my_ip "$A" "$NET")"; B_IP="$(my_ip "$B" "$NET")"; C_IP="$(my_ip "$C" "$NET")"
echo "   A_IP=$A_IP  B_IP=$B_IP  C_IP=$C_IP"
[[ -n "$A_IP" && -n "$B_IP" && -n "$C_IP" ]] || { fail "missing a VPN ip"; summary; }

# ---------------------------------------------------------------------------
step "2. consent pipeline — coordinator suggests, non-auto-accept member reviews"
# A denies-only suggestion (no catch-all) keeps srv-b otherwise open, so it can't
# contaminate later sections. srv-b did NOT auto-accept, so it must queue.
on "$B" 'ray firewall default allow' 2>&1 | strip | sed 's/^/   b| /'   # so the deny is observable
start_tcp_listener "$B" 2099
on "$A" "ray firewall suggest $NET --subject srv-b --deny srv-c:tcp:2099" 2>&1 | strip | sed 's/^/   a| /'
# Reconverge is the 60s poller (or a blob trigger); poll until it lands.
if retry_until 90 "[[ \"\$(fw_pending_count '$B' '$NET')\" -ge 1 ]]"; then
  pass "suggested rule reached srv-b's pending queue"
else
  fail "suggested rule never appeared in srv-b's pending queue"
fi
on "$B" "ray firewall accept $NET" 2>&1 | strip | sed 's/^/   b| /'
if retry_until 30 "[[ \"\$(fw_suggested_count '$B' '$NET')\" -ge 1 ]]"; then
  pass "accepted rule is installed + tagged (suggested by $NET)"
else
  fail "accepted rule not present in firewall show"
fi
fw_denies "$C" "$B_IP" 2099 "blacklist: suggested deny blocks the named peer (srv-c)"
fw_allows "$A" "$B_IP" 2099 "blacklist: leaves other peers open (srv-a)"
stop_tcp_listener "$B" 2099
on "$B" 'ray firewall default deny' 2>&1 | strip | sed 's/^/   b| /'

# ---------------------------------------------------------------------------
step "3. auto-accept + whitelist semantics (subject srv-c)"
# srv-c joined with --auto-accept-firewall: an allow-list suggestion installs
# without review. Suggestions are additive (no synthesized catch-all) — the
# whitelist is the allow rule punching through srv-c's own inbound default-deny.
on "$C" 'ray firewall default deny' 2>&1 | strip | sed 's/^/   c| /'   # the default-deny is what blocks the rest
start_tcp_listener "$C" 2030
start_tcp_listener "$C" 2031
on "$A" "ray firewall suggest $NET --subject srv-c --allow srv-b:tcp:2030" 2>&1 | strip | sed 's/^/   a| /'
if retry_until 90 "[[ \"\$(fw_suggested_count '$C' '$NET')\" -ge 1 ]]"; then
  pass "auto-accept node installed the suggestion without review"
else
  fail "auto-accept node never installed the suggestion"
fi
[[ "$(fw_pending_count "$C" "$NET")" == "0" ]] && pass "auto-accept leaves nothing in pending" \
  || fail "auto-accept node unexpectedly queued the suggestion"
fw_allows "$B" "$C_IP" 2030 "whitelist: allow rule admits the listed peer:port (srv-b -> 2030)"
fw_denies "$B" "$C_IP" 2031 "whitelist: default-deny blocks an unlisted port (2031)"
fw_denies "$A" "$C_IP" 2030 "whitelist: allow is peer-scoped, default-deny blocks srv-a"

# Toggle auto-accept OFF: a further suggestion must now QUEUE instead of install.
on "$C" "ray firewall auto-accept $NET off" 2>&1 | strip | sed 's/^/   c| /'
on "$A" "ray firewall suggest $NET --subject srv-c --allow srv-b:tcp:2032" 2>&1 | strip | sed 's/^/   a| /'
if retry_until 90 "[[ \"\$(fw_pending_count '$C' '$NET')\" -ge 1 ]]"; then
  pass "auto-accept off: new suggestion queues for review"
else
  fail "auto-accept off: suggestion did not queue"
fi
on "$C" "ray firewall deny $NET" 2>&1 | strip | sed 's/^/   c| /'   # discard the queued one
on "$C" 'ray firewall default deny' 2>&1 | strip | sed 's/^/   c| /'

# ---------------------------------------------------------------------------
step "4. rule matrix — UDP, TCP port range, same-selector replace (local rules)"
# UDP (never exercised elsewhere): default-deny blocks it, an explicit allow opens.
# Port 5400 is used (not 5353) to avoid colliding with the daemon's own mDNS
# listener (UDP 5353). The receiver runs on srv-b, reached via its public ip ($B).
fw_denies "$A" "$B_IP" 5400 "UDP denied by default" udp "$B"
on "$B" 'ray firewall add in allow -p udp -P 5400' 2>&1 | strip | sed 's/^/   b| /'
fw_allows "$A" "$B_IP" 5400 "explicit allow opens UDP:5400" udp "$B"
on "$B" 'ray firewall remove 0' 2>&1 | strip | sed 's/^/   b| /'

# TCP port range: a single rule covers 8000-8010; inside opens, outside stays shut.
on "$B" 'ray firewall add in allow -p tcp -P 8000-8010' 2>&1 | strip | sed 's/^/   b| /'
start_tcp_listener "$B" 8005
start_tcp_listener "$B" 8011
fw_allows "$A" "$B_IP" 8005 "port range allows a mid-range port (8005)"
fw_denies "$A" "$B_IP" 8011 "port range excludes a port just outside it (8011)"
stop_tcp_listener "$B" 8005; stop_tcp_listener "$B" 8011
on "$B" 'ray firewall remove 0' 2>&1 | strip | sed 's/^/   b| /'

# Same-selector replace + first-match: add deny then allow on the same selector;
# the second replaces the first rather than stacking, so the latest action wins.
on "$B" 'ray firewall default allow' 2>&1 | strip | sed 's/^/   b| /'
start_tcp_listener "$B" 9100
on "$B" 'ray firewall add in deny -p tcp -P 9100' 2>&1 | strip | sed 's/^/   b| /'
fw_denies "$A" "$B_IP" 9100 "explicit deny beats default-allow (first-match)"
on "$B" 'ray firewall add in allow -p tcp -P 9100' 2>&1 | strip | sed 's/^/   b| /'
fw_allows "$A" "$B_IP" 9100 "re-adding allow on the same selector flips it (no dead rule)"
stop_tcp_listener "$B" 9100
on "$B" 'ray firewall remove 0' 2>&1 | strip | sed 's/^/   b| /'

# ---------------------------------------------------------------------------
step "5. per-network rule scoping (--network)"
# A rule scoped to another network must NOT match traffic arriving via `fw`.
# (srv-b need not even be on that network — the field is a match filter.)
start_tcp_listener "$B" 7000
on "$B" 'ray firewall add in deny -p tcp -P 7000 --network db' 2>&1 | strip | sed 's/^/   b| /'
fw_allows "$A" "$B_IP" 7000 "a db-scoped deny does not affect fw traffic"
# Assert the scope is recorded as `db`, not `any`.
SCOPED="$(on "$B" 'ray firewall show --json' | jq -r '[ (.rules//[])[] | select(.network=="db") ] | length')"
[[ "${SCOPED:-0}" -ge 1 ]] && pass "rule recorded with network scope = db" || fail "rule not scoped to db in firewall show"
on "$B" 'ray firewall add in deny -p tcp -P 7000' 2>&1 | strip | sed 's/^/   b| /'   # any-network
fw_denies "$A" "$B_IP" 7000 "an unscoped deny does match fw traffic"
stop_tcp_listener "$B" 7000
on "$B" 'ray firewall remove 0' 2>&1 | strip | sed 's/^/   b| /'
on "$B" 'ray firewall remove 0' 2>&1 | strip | sed 's/^/   b| /'
on "$B" 'ray firewall default deny' 2>&1 | strip | sed 's/^/   b| /'

# ---------------------------------------------------------------------------
step "6. file send bypasses the firewall (deny-all inbound)"
# srv-b is left at `default deny` (all inbound TCP/UDP blocked, ICMP-only) by the
# previous step. `ray send` rides the identity-level FILES_ALPN (rayfish/files/1)
# as a control-plane QUIC stream, NOT TUN/IP traffic — so the per-device firewall
# (which filters forwarded packets) never sees it. A deny-all host can still
# receive files. This proves send availability is gated by shared-network
# membership, not by the firewall posture.
DENY_DEFAULT="$(on "$B" 'ray firewall show --json' | jq -r '(.default_inbound // "") | ascii_downcase')"
[[ "$DENY_DEFAULT" == "deny" ]] \
  && pass "srv-b inbound default is deny (TCP/UDP blocked)" \
  || fail "srv-b inbound default is not deny (got '${DENY_DEFAULT}')"
send_recv "$A" "$B" srv-b "ray send srv-a -> srv-b succeeds despite deny-all firewall"

# ---------------------------------------------------------------------------
summary
