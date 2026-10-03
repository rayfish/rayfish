#!/usr/bin/env bash
# `ray connect` (direct 2-peer connection) e2e test orchestrator.
#
# Topology:
#   srv-a  identity U   the initiator (`ray connect`)
#   srv-b  identity V   the recipient (`ray connect approve`)
#
# Proves the full friend-request flow over real hosts + the public pkarr DHT:
#   B publishes a contact id  ->  A `ray connect <id>`  ->  B sees + approves
#   ->  a 2-peer `[direct]` network forms  ->  A<->B reach each other (ping +
#   ray send) and the network is tagged direct with its room id hidden.
# Plus a negative case: connecting to an offline contact fails cleanly.
#
# Reads tests/e2e/connect/.servers (written by provision.sh). Does NOT modify
# infra. Re-runnable (resets rayfish state on each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"
SR_PREFIX=/tmp/c   # temp-file prefix for send_recv

# check_offline_contact <from> <to> <old-contact-id> : prove that a fresh,
# unpublished contact id returns the expected lookup error within a deadline.
check_offline_contact(){
  local from="$1" to="$2" old_contact_id="$3"
  if ! on "$to" 'ray down' >/dev/null 2>&1; then
    fail "could not put srv-b in standby"; return 1
  fi
  if retry_until 10 "status_json '$to' | jq -e '.active == false' >/dev/null 2>&1"; then
    pass "srv-b entered standby (inactive)"
  else
    fail "srv-b did not enter standby after ray down"; return 1
  fi

  # Rotation in standby must succeed without publishing the new contact record.
  local rotated_json new_contact_id
  if ! rotated_json="$(on "$to" 'ray contact rotate --json' 2>/dev/null)"; then
    fail "could not rotate srv-b's contact id"; return 1
  fi
  if ! new_contact_id="$(printf '%s\n' "$rotated_json" | jq -er '
    .contact_id | select(type == "string" and test("^[A-Za-z0-9]{20,}$"))')" \
     || [[ "$new_contact_id" == "$old_contact_id" ]]; then
    fail "contact rotation did not return a valid new id"; return 1
  fi

  local offline_out offline_rc=0
  offline_out="$(on "$from" "timeout --kill-after=5s 30s ray connect $new_contact_id" 2>&1 | strip)" \
    || offline_rc=$?
  printf '%s\n' "$offline_out" | sed 's/^/   a| /'
  # The CLI exits 1 for this daemon error. Timeout, SSH/IPC errors, and a
  # successful command must fail even if their output mentions an offline peer.
  if [[ "$offline_rc" == 1 ]] && printf '%s\n' "$offline_out" \
      | grep -qE '^[[:space:]]*contact offline or unknown \(could not resolve contact id\)[[:space:]]*$'; then
    pass "connect to offline/unknown contact errors cleanly"
  else
    fail "connect to offline contact did not return the expected lookup error (exit=$offline_rc)"
    return 1
  fi
}

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run $DIR/provision.sh first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

# ---------------------------------------------------------------------------
step "0. wait for SSH on both hosts"
wait_all_ssh "$A" "$B"
seed_known_hosts "$A" "$B"
reset_state "$A" "$B"
deploy_all "$ROOT" "$A" "$B"
# Ensure the VPN is active on both (TUN up + contact publisher running). After a
# `systemctl restart` the daemon boots inactive, so activate explicitly.
activate_daemons "$A" "$B" || summary

# ---------------------------------------------------------------------------
step "2. read contact ids"
A_CID="$(on "$A" 'ray contact id' | strip | head -1 | tr -d ' ')"
B_CID="$(on "$B" 'ray contact id' | strip | head -1 | tr -d ' ')"
echo "   A contact id: ${A_CID:0:16}…"
echo "   B contact id: ${B_CID:0:16}…"
[[ -n "$A_CID" && "${#A_CID}" -ge 20 ]] && pass "srv-a has a contact id" || fail "srv-a contact id missing/short"
[[ -n "$B_CID" && "${#B_CID}" -ge 20 ]] && pass "srv-b has a contact id" || fail "srv-b contact id missing/short"
# The contact id must also surface in `ray status`.
on "$A" 'ray status' | strip | grep -qi "${A_CID:0:16}" && pass "contact id shown in ray status" \
  || fail "contact id not shown in ray status"

# ---------------------------------------------------------------------------
step "3. srv-a requests a direct connection to srv-b"
# B publishes its contact record to pkarr; retry until A's request is accepted.
CONNECT_OUT=""
for _ in $(seq 1 8); do
  CONNECT_OUT="$(on "$A" "ray connect $B_CID --hostname laptop" 2>&1 | strip)"
  echo "$CONNECT_OUT" | grep -qiE 'waiting for approval|connected' && break
  sleep 5
done
echo "$CONNECT_OUT" | sed 's/^/   a| /'
if echo "$CONNECT_OUT" | grep -qiE 'waiting for approval|connected'; then
  pass "srv-a connect request accepted (pending)"
else
  fail "srv-a connect request did not reach srv-b"
fi

# ---------------------------------------------------------------------------
step "4. srv-b sees the pending request and approves it"
REQ=""
for _ in $(seq 1 8); do
  REQ="$(on "$B" 'ray connect' 2>/dev/null | strip)"
  echo "$REQ" | grep -qiE "${A_CID:0:8}" && break
  sleep 3
done
echo "$REQ" | sed 's/^/   b| /'
if echo "$REQ" | grep -qiE "${A_CID:0:8}"; then
  pass "srv-b sees srv-a's request"
else
  fail "srv-b never saw srv-a's request"
fi
# Approve by srv-a's full contact id (the daemon matches it as a prefix), so we
# don't have to parse the short id out of the table.
APPROVE="$(on "$B" "ray connect approve $A_CID" 2>&1 | strip)"
echo "$APPROVE" | sed 's/^/   b| /'
echo "$APPROVE" | grep -qiE 'approved|already connected' && pass "srv-b approved the request" \
  || fail "srv-b approve failed"

# ---------------------------------------------------------------------------
step "5. wait for the 2-peer direct network to form on both sides"
converged=0
for _ in $(seq 1 18); do  # up to ~90s
  SA="$(on "$A" 'ray status' | strip)"; SB="$(on "$B" 'ray status' | strip)"
  if echo "$SA" | grep -qi 'direct' && echo "$SB" | grep -qi 'direct'; then converged=1; break; fi
  sleep 5
done
SA="$(on "$A" 'ray status' | strip)"; SB="$(on "$B" 'ray status' | strip)"
echo "---- srv-a status ----"; echo "$SA" | sed 's/^/   a| /'
echo "---- srv-b status ----"; echo "$SB" | sed 's/^/   b| /'
[[ "$converged" == 1 ]] && pass "both sides show a [direct] network" || fail "direct network did not form within timeout"

# A direct network must NOT print a shareable join/room id.
if echo "$SB" | grep -qiE 'join [A-Za-z0-9]{20,}'; then
  fail "direct network leaked a room id in status"
else
  pass "direct network hides its room id"
fi

# ---------------------------------------------------------------------------
step "5b. both peers are coordinators of the direct network"
# A direct link is symmetric: the requester is granted the network key on
# admission, so `ray admin list` on *each* side must show that node holding it.
NET_A="$(status_json "$A" | jq -r '(.networks // [])[] | select((.role|ascii_downcase)=="direct") | .name' | head -1)"
NET_B="$(status_json "$B" | jq -r '(.networks // [])[] | select((.role|ascii_downcase)=="direct") | .name' | head -1)"
echo "   net-a=$NET_A  net-b=$NET_B"
if [[ -n "$NET_A" ]] && retry_until 30 "holds_key '$A' '$NET_A'"; then
  pass "srv-a holds the network key (co-coordinator)"
else
  fail "srv-a is not a coordinator of the direct network"
fi
if [[ -n "$NET_B" ]] && retry_until 30 "holds_key '$B' '$NET_B'"; then
  pass "srv-b holds the network key (coordinator)"
else
  fail "srv-b is not a coordinator of the direct network"
fi

# ---------------------------------------------------------------------------
step "6. reachability — ping over the TUN (both directions)"
A_IP="$(my_ip "$A" "$NET_A")"; B_IP="$(my_ip "$B" "$NET_B")"
echo "   A_IP=$A_IP  B_IP=$B_IP"
if [[ -n "$A_IP" && -n "$B_IP" && "$A_IP" != "$B_IP" ]]; then
  pass "two distinct VPN IPs (srv-a=$A_IP srv-b=$B_IP)"
else
  fail "expected two distinct VPN IPs (srv-a=$A_IP srv-b=$B_IP)"
fi
# ping_loss / png come from common.sh.
[[ -n "$A_IP" && -n "$B_IP" ]] && png "$A" "$B_IP" "srv-a -> srv-b ($B_IP)"
[[ -n "$A_IP" && -n "$B_IP" ]] && png "$B" "$A_IP" "srv-b -> srv-a ($A_IP)"

# ---------------------------------------------------------------------------
step "7. data transfer — ray send / ray files accept (both directions)"
# `ray send` resolves the destination by hostname (or short id), not by IP.
PEER_OF_A="$(status_json "$A" | jq -r --arg n "$NET_A" '(.networks // []) | map(select(.name == $n)) | .[0].peers[0].hostname // empty')"
PEER_OF_B="$(status_json "$B" | jq -r --arg n "$NET_B" '(.networks // []) | map(select(.name == $n)) | .[0].peers[0].hostname // empty')"
echo "   peer-of-a=$PEER_OF_A  peer-of-b=$PEER_OF_B"
# send_recv comes from common.sh (SR_PREFIX=/tmp/c set above).
[[ -n "$PEER_OF_A" ]] && send_recv "$A" "$B" "$PEER_OF_A" "ray send srv-a -> srv-b" || fail "could not resolve srv-b hostname"
[[ -n "$PEER_OF_B" ]] && send_recv "$B" "$A" "$PEER_OF_B" "ray send srv-b -> srv-a (reverse)" || fail "could not resolve srv-a hostname"

# ---------------------------------------------------------------------------
step "8. firewall — removing the seeded allow-icmp rule denies inbound ICMP"
# Inbound ICMP is allowed out of the box by a single seeded `allow in icmp` rule
# (index 0), not a hard-coded default — so the way to deny ping is to remove that
# rule, after which the deny-inbound default covers ICMP. Remove it on srv-b,
# confirm srv-a -> srv-b ping breaks, then re-add it and confirm it recovers.
if [[ -n "$A_IP" && -n "$B_IP" ]]; then
  on "$B" 'ray firewall remove 0' 2>&1 | strip | sed 's/^/   b| /'
  if retry_until 15 "[[ \"\$(ping_loss '$A' '$B_IP')\" == '100' ]]"; then
    pass "removing the seeded allow-icmp rule blocks ICMP (100% loss)"
  else
    BLOCKED="$(ping_loss "$A" "$B_IP")"
    fail "ICMP not blocked after removing seed rule (loss=${BLOCKED:-?}%)"
  fi
  on "$B" 'ray firewall add in allow -p icmp' 2>&1 | strip | sed 's/^/   b| /'
  if retry_until 15 "[[ \"\$(ping_loss '$A' '$B_IP')\" == '0' ]]"; then
    pass "re-adding allow-icmp restores ICMP (0% loss)"
  else
    RECOVERED="$(ping_loss "$A" "$B_IP")"
    fail "ICMP did not recover after re-adding allow rule (loss=${RECOVERED:-?}%)"
  fi
else
  fail "could not determine IPs for firewall test"
fi

# ---------------------------------------------------------------------------
step "8b. firewall — unsolicited inbound TCP is denied by the secure default"
# Out of the box (no user rules) the firewall denies unsolicited inbound TCP, so
# a listening service on srv-b is NOT reachable from srv-a until a port is opened
# explicitly. ICMP stays allowed by default (verified in step 6). This is a fresh
# inbound connection with no prior outbound from srv-b, so conntrack never masks
# the result.
FWPORT=18080
if [[ -n "$A_IP" && -n "$B_IP" ]]; then
  # Listener on srv-b (binds ::, so it answers on the TUN); helpers in common.sh.
  start_tcp_listener "$B" "$FWPORT"
  # No prior outbound from srv-b, so conntrack never masks the default-deny.
  fw_denies "$A" "$B_IP" "$FWPORT" "unsolicited inbound is denied by default"
  # Open the port explicitly on srv-b, then the same probe must succeed.
  on "$B" "ray firewall add in allow -p tcp --port $FWPORT" 2>&1 | strip | sed 's/^/   b| /'
  fw_allows "$A" "$B_IP" "$FWPORT" "explicit allow rule opens the port"
  on "$B" 'ray firewall remove 0' 2>&1 | strip | sed 's/^/   b| /'
  stop_tcp_listener "$B" "$FWPORT"
else
  fail "could not determine IPs for unsolicited-inbound firewall test"
fi

# ---------------------------------------------------------------------------
step "9. negative — connecting to an offline contact fails cleanly"
# Stop publication, then rotate the contact id so lookup cannot race a cached
# record's TTL or reuse the already-established direct network.
check_offline_contact "$A" "$B" "$B_CID"
on "$B" 'ray up' >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
summary
