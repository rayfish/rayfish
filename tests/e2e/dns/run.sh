#!/usr/bin/env bash
# Magic DNS end-to-end test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `dns` (mints an invite)
#   srv-b  member that joins via invite
#
# Proves the parts of the TUN-intercepted Magic DNS resolver that unit tests
# can't reach end to end, on real Linux hosts:
#   - after `ray up` + join, a peer's `<host>.<net>.ray` resolves through the
#     *system* resolver (getent/libc) to its mesh IPv6, i.e. the OS was pointed
#     at the magic resolver IP and the in-daemon resolver answered it;
#   - resolution drives real reachability (ping by name);
#   - the resolver does NOT bind host port 53 — it answers via a magic IP routed
#     through the TUN, so it coexists with any existing :53 resolver (the
#     AdGuard/Pi-hole/umbrelOS case) by construction;
#   - non-`.ray` names still resolve while the VPN is up (split-DNS passthrough,
#     or the resolver forwarding to the captured upstream);
#   - `ray down` reverts system DNS: `.ray` names stop resolving;
#   - (conditional) on a host that fell to the direct `/etc/resolv.conf` takeover,
#     resolv.conf carries the magic IP under the rayfish marker while up, and the
#     original is restored on down.
#
# Reads tests/e2e/dns/.servers (written by provision.sh). Does NOT modify infra.
# Re-runnable (resets rayfish state each run unless KEEP_STATE=1).
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

NET=dns
MAGIC=200::53

# a6 <host-ip> <name> : the IPv6 the host's *system* resolver returns for <name>
# (libc/nsswitch path, the same one `ping` uses), or empty. This is the one that
# answers for `.ray`: the mesh has no IPv4, so an A query there is NODATA.
a6(){ on "$1" "getent ahostsv6 $2 2>/dev/null | awk 'NR==1{print \$1}'"; }

# a4 <host-ip> <name> : same for IPv4. Only meaningful for *public* names, which
# is exactly what the upstream-forwarding checks below want.
a4(){ on "$1" "getent ahostsv4 $2 2>/dev/null | awk 'NR==1{print \$1}'"; }

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
step "2. Magic DNS active: <host>.<net>.ray resolves via the system resolver"
# This is the headline assertion. If Magic DNS failed to start (e.g. the old
# 'Address already in use' on :53) or the OS wasn't pointed at the magic IP,
# the system resolver returns nothing and these fail. Roster->DNS sync + the
# dns_config apply take a moment, so poll.
if retry_until 60 "[[ \"\$(a6 '$A' srv-b.$NET.ray)\" == '$B_IP' ]]"; then
  pass "srv-a resolves srv-b.$NET.ray -> $B_IP (system resolver)"
else
  fail "srv-a could not resolve srv-b.$NET.ray to $B_IP (got '$(a6 "$A" srv-b.$NET.ray)')"
fi
if retry_until 60 "[[ \"\$(a6 '$B' srv-a.$NET.ray)\" == '$A_IP' ]]"; then
  pass "srv-b resolves srv-a.$NET.ray -> $A_IP (system resolver)"
else
  fail "srv-b could not resolve srv-a.$NET.ray to $A_IP (got '$(a6 "$B" srv-a.$NET.ray)')"
fi

# ---------------------------------------------------------------------------
step "3. resolution drives real reachability (ping by name)"
png "$A" "srv-b.$NET.ray" "srv-a pings srv-b by .ray name"
png "$B" "srv-a.$NET.ray" "srv-b pings srv-a by .ray name"

# ---------------------------------------------------------------------------
step "4. the resolver does NOT bind host port 53 (coexists with any :53 server)"
# The new architecture answers DNS via a magic IP routed through the TUN, never
# a host socket — so it never competes for :53 with AdGuard/Pi-hole/dnsmasq.
# Assert the ray daemon owns no :53 listener (UDP or TCP) on either host.
for h in "$A" "$B"; do
  RAY53="$(on "$h" "ss -lntup 2>/dev/null | grep ':53 ' | grep -c ray || true")"
  [[ "${RAY53:-0}" == "0" ]] \
    && pass "ray daemon holds no :53 socket on $h (coexists by design)" \
    || fail "ray daemon is bound to :53 on $h — should answer via the TUN magic IP"
done

# ---------------------------------------------------------------------------
step "5. non-.ray names still resolve while the VPN is up"
# Split-DNS hosts pass these straight to the system resolvers; direct-mode hosts
# forward them through rayfish to the captured upstream. Either way, a public
# name must still resolve — the feature must not black-hole non-.ray DNS.
for h in "$A" "$B"; do
  if retry_until 30 "[[ -n \"\$(a4 '$h' one.one.one.1)\" || -n \"\$(a4 '$h' dns.google)\" ]]"; then
    pass "non-.ray names still resolve on $h (upstream/passthrough works)"
  else
    fail "non-.ray resolution broken on $h while VPN up"
  fi
done

# ---------------------------------------------------------------------------
step "6. (conditional) direct-mode /etc/resolv.conf takeover + restore"
# Only meaningful on a host that fell to the direct manager (no split-DNS
# backend). Detect by the rayfish marker; skip cleanly on split-DNS hosts.
DIRECT_HOST=""
for h in "$A" "$B"; do
  if on "$h" 'grep -q "Added by rayfish" /etc/resolv.conf 2>/dev/null'; then DIRECT_HOST="$h"; break; fi
done
if [[ -z "$DIRECT_HOST" ]]; then
  echo "   (no host used the direct resolv.conf takeover — split-DNS path; skipping)"
else
  on "$DIRECT_HOST" "grep -q '^nameserver $MAGIC' /etc/resolv.conf" \
    && pass "direct mode: /etc/resolv.conf points at the magic IP ($MAGIC)" \
    || fail "direct mode: magic IP not the nameserver in /etc/resolv.conf"
fi

# ---------------------------------------------------------------------------
step "7. ray down reverts system DNS — .ray stops resolving"
on "$B" 'ray down' 2>&1 | strip | sed 's/^/   b| /'
if retry_until 30 "[[ -z \"\$(a6 '$B' srv-a.$NET.ray)\" ]]"; then
  pass "after 'ray down', srv-b no longer resolves srv-a.$NET.ray"
else
  fail "srv-b still resolves .ray after 'ray down' (DNS not reverted)"
fi
if [[ -n "$DIRECT_HOST" && "$DIRECT_HOST" == "$B" ]]; then
  on "$B" '! grep -q "Added by rayfish" /etc/resolv.conf' \
    && pass "direct mode: /etc/resolv.conf restored (rayfish marker gone) after down" \
    || fail "direct mode: rayfish marker still in /etc/resolv.conf after down"
fi
# Restore srv-b for re-runs / a clean end state.
on "$B" 'ray up' >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
summary
