#!/usr/bin/env bash
# Cloud exit test: authenticated offer, IPv4/IPv6 NAT, deny and teardown.
# Test-only SSH marking keeps the harness connected. Production client rules
# do not exempt inbound SSH sessions. Local kernel checks: tests/exit-ipv4-kernel.sh.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS: run $DIR/provision.sh first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/srv-b/srv-c in $SERVERS"; exit 1; }

NET=exit
MARK=0x7261      # exit_node::SOCKET_MARK
TABLE=29793      # exit_node::EXIT_TABLE

# pub4 <host> : the host's public IPv4 as an external service sees it (i.e. which
# uplink its traffic actually left by). Empty on failure/timeout.
pub4(){ on "$1" "curl -4 -s --max-time 20 https://api.ipify.org || curl -4 -s --max-time 20 https://ifconfig.me/ip" 2>/dev/null | tr -d '[:space:]'; }

# pub6 <host> : the host's public IPv6 as an external service sees it. Empty when
# the host has no IPv6 egress at all, which several instances do not.
#
# Two services, as `pub4` has: the baseline reading decides whether steps 4-6 run
# at all, so one flaky probe would turn the tunnel and deny-path assertions into
# skips whose message claims something about the host that was never established.
pub6(){ on "$1" "curl -6 -s --max-time 20 https://api6.ipify.org || curl -6 -s --max-time 20 https://icanhazip.com" 2>/dev/null | tr -d '[:space:]'; }

# exit_json <host> : `ray exit-node status --json` from a host.
exit_json(){ on "$1" "ray exit-node status --json" 2>/dev/null; }

# arm_failsafe <host> <seconds> : detached self-revert, armed BEFORE any full
# tunnel goes up. If we lose the host (a routing bug cutting our own SSH), it drops
# the tunnel on its own after <seconds> and the instance comes back. Cancelled by
# disarm_failsafe once egress is restored, so a passing run costs nothing.
arm_failsafe(){
  on "$1" "rm -f /tmp/exit-disarm; setsid nohup bash -c 'sleep $2; [ -f /tmp/exit-disarm ] || { ray exit-node none $NET; ray down; ray up; }' >/dev/null 2>&1 < /dev/null &" >/dev/null 2>&1
}
disarm_failsafe(){ on "$1" 'touch /tmp/exit-disarm' >/dev/null 2>&1; }

# clean_kernel <host...> : drop any exit-node kernel state a crashed earlier run
# may have left behind. `reset_state` wipes /etc/rayfish (including the forwarding
# snapshot), so without this a stale nft table / ip rule would survive into the
# next run and make assertions lie. Idempotent; ignores "not found".
clean_kernel(){
  step "reset leftover exit-node kernel state (nft table, ip rules, tunnel table)"
  local h f p
  for h in "$@"; do
    on "$h" "nft delete table inet rayfish_exit; nft delete table inet rayfish_exit_client" >/dev/null 2>&1
    for f in -4 -6; do
      # 99 holds one rule per physical address, so a single `del` leaves the rest
      # behind. 98 and 102 are one rule each, but both read back as
      # `lookup 29793`, and a leftover breaks a later run outright: step 4's "no
      # IPv4 tunnel rule" grep would match state this run never installed.
      for p in 98 99 100 101 102; do
        for _ in $(seq 1 64); do
          on "$h" "ip $f rule del pref $p" >/dev/null 2>&1 || break
        done
      done
      on "$h" "ip $f route flush table $TABLE" >/dev/null 2>&1
    done
    # The stand-in co-resident VPN step 4 installs (table 52 at pref 5250, in
    # Tailscale's range). Left behind it would make the next run's mirror
    # assertions pass on state this run never installed.
    for _ in $(seq 1 8); do
      on "$h" "ip -6 rule del pref 5250" >/dev/null 2>&1 || break
    done
    on "$h" "ip -6 route flush table 52" >/dev/null 2>&1
    on "$h" "sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0" >/dev/null 2>&1
    on "$h" "rm -f /tmp/exit-disarm" >/dev/null 2>&1
    echo "   cleaned $h"
  done
}

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all three hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"

# The gateway shells out to `nft` (and every host curls an echo service), so make
# sure both exist rather than failing later with a confusing "enable" error.
for h in "$A" "$B" "$C"; do
  on "$h" 'command -v nft >/dev/null && command -v curl >/dev/null' \
    || on "$h" 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables curl' >/dev/null 2>&1
done
for h in "$A" "$B" "$C"; do
  on "$h" 'command -v nft >/dev/null' && continue
  fail "nft not available on $h: the exit node cannot install its NAT table"
done

reset_state "$A" "$B" "$C"
clean_kernel "$A" "$B" "$C"
deploy_all "$ROOT" "$A" "$B" "$C"
for h in "$A" "$B" "$C"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B" "$C"

# ---------------------------------------------------------------------------
step "1. srv-a creates the network; srv-b and srv-c join"
on "$A" "ray create --name $NET --hostname srv-a" | strip | sed 's/^/   a| /'
has_net "$A" "$NET" && pass "network '$NET' present on coordinator" || fail "create failed"

for pair in "b:$B" "c:$C"; do
  n="${pair%%:*}"; h="${pair#*:}"
  INV="$(mint_invite "$A" "$NET" "srv-$n")"
  [[ -n "$INV" ]] || fail "invite mint failed for srv-$n"
  on "$h" "ray join $INV --hostname srv-$n" 2>&1 | strip | sed "s/^/   $n| /"
done
wait_roster "$A" srv-b srv-c

A_VPN="$(my_ip "$A" "$NET")"
echo "   srv-a mesh ip = $A_VPN"
[[ -n "$A_VPN" ]] || { fail "could not read srv-a's mesh IPv6"; summary; }

# Real public IPs (the baseline: each host normally egresses via its own uplink).
A_PUB="$(pub4 "$A")"; B_PUB="$(pub4 "$B")"; C_PUB="$(pub4 "$C")"
echo "   public IPv4: a=$A_PUB  b=$B_PUB  c=$C_PUB"
# The v6 baseline, taken before any tunnel exists: IPv6 is the family the tunnel
# carries, so these are what the egress assertions below compare against. Empty
# on an instance with no IPv6 egress, which those assertions then skip.
A_PUB_V6="$(pub6 "$A")"; B_PUB_V6="$(pub6 "$B")"; C_PUB_V6="$(pub6 "$C")"
echo "   public IPv6: a=${A_PUB_V6:-<none>}  b=${B_PUB_V6:-<none>}  c=${C_PUB_V6:-<none>}"
[[ -n "$A_PUB" && -n "$B_PUB" ]] || { fail "could not read baseline public IPs"; summary; }
[[ "$A_PUB" != "$B_PUB" ]] \
  && pass "baseline: srv-b egresses via its own uplink ($B_PUB), not srv-a's ($A_PUB)" \
  || fail "srv-a and srv-b already share a public IP: the egress assertion would be meaningless"

# ---------------------------------------------------------------------------
step "2. srv-a becomes an exit node (allow srv-b only)"
# Save the original value for the teardown assertion.
A_IP4FWD_BEFORE="$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward')"
on "$A" "ray exit-node allow $NET srv-b" 2>&1 | strip | sed 's/^/   a| /'
[[ "$(exit_json "$A" | jq -r --arg n "$NET" '.networks[] | select(.network==$n) | .offering')" == "true" ]] \
  && pass "srv-a reports offering: yes" || fail "srv-a does not report an exit-node offer"

# The gateway's kernel state must be live (it is already `up`, so the allow
# reconciles it immediately rather than waiting for the next `ray up`).
[[ "$(on "$A" 'cat /proc/sys/net/ipv6/conf/all/forwarding')" == "1" ]] \
  && pass "srv-a: IPv6 forwarding enabled" || fail "srv-a: ipv6 forwarding not enabled"
if on "$A" 'nft list table inet rayfish_exit 2>/dev/null | grep -q masquerade'; then
  pass "srv-a: nftables masquerade table installed"
else
  fail "srv-a: no nft masquerade table (traffic would forward but never come back)"
fi
[[ "$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward')" == "1" ]] \
  && pass "srv-a: IPv4 forwarding enabled" || fail "srv-a: IPv4 forwarding disabled"
on "$A" 'nft list table inet rayfish_exit | grep -q "ip saddr 198.19.0.0/16"' \
  && pass "srv-a: IPv4 exit pool is masqueraded" || fail "srv-a: IPv4 NAT missing"

# ---------------------------------------------------------------------------
step "3. the offer rides the signed roster: srv-b and srv-c discover it"
for pair in "b:$B" "c:$C"; do
  n="${pair%%:*}"; h="${pair#*:}"
  if retry_until 90 "[[ \"\$(exit_json '$h' | jq -r --arg net '$NET' '.networks[] | select(.network==\$net) | .available[]' 2>/dev/null | grep -c srv-a)\" == '1' ]]"; then
    pass "srv-$n sees srv-a advertised as an exit node (via the signed blob)"
  else
    fail "srv-$n never saw srv-a's exit-node offer in the roster"
  fi
done
# `ray status` carries an exit column: `offers` for a peer advertising an exit
# node, `in use` for the one actually carrying our traffic. srv-b has not selected
# srv-a yet, so it reads `offers` here (and `in use` after step 4).
on "$B" "ray status" | strip | grep -q 'srv-a.*offers' \
  && pass "ray status shows srv-a in the exit column as 'offers' on srv-b" \
  || fail "ray status did not flag srv-a as an exit node on srv-b"

# ---------------------------------------------------------------------------
# Only the test harness gets this exception; application connections still face
# the production kill switch. Mark before route lookup is repeated by nftables.
for h in "$B" "$C"; do
  on "$h" "nft delete table inet rayfish_exit_test" >/dev/null 2>&1
  on "$h" "nft 'add table inet rayfish_exit_test'; nft 'add chain inet rayfish_exit_test control { type route hook output priority mangle; policy accept; }'; nft 'add rule inet rayfish_exit_test control tcp sport 22 meta mark set $MARK'"
done

step "4. srv-b sends both IP families through srv-a"
arm_failsafe "$B" 240
on "$B" "ray exit-node use $NET srv-a" || { fail "exit selection failed"; summary; }
sleep 8
[[ "$(pub4 "$B")" == "$A_PUB" ]] \
  && pass "IPv4 exits through srv-a" || fail "IPv4 did not use srv-a"
if [[ -n "$A_PUB_V6" ]]; then
  [[ "$(pub6 "$B")" == "$A_PUB_V6" ]] \
    && pass "IPv6 exits through srv-a" || fail "IPv6 did not use srv-a"
else
  [[ -z "$(pub6 "$B")" ]] \
    && pass "unavailable IPv6 is blocked" || fail "IPv6 bypassed the exit"
fi
[[ "$(ping_loss "$B" "$A_VPN")" == "0" ]] \
  && pass "mesh transport survives full-tunnel routing" || fail "transport loop prevention failed"
for f in -4 -6; do
  on "$B" "ip $f route show table $TABLE" | grep -q default \
    && pass "$f default uses the tunnel" || fail "$f tunnel default missing"
done
on "$B" 'nft list table inet rayfish_exit_client | grep -q "policy drop"' \
  && pass "direct egress is blocked" || fail "client kill switch missing"
on "$B" 'getent hosts example.com' >/dev/null \
  && pass "public DNS resolves through the tunnel" || fail "public DNS failed"
on "$B" 'getent hosts srv-a.ray' >/dev/null \
  && pass "mesh DNS works" || fail "mesh DNS failed"

step "5. clearing the exit restores direct egress"
on "$B" "ray exit-node none $NET"
disarm_failsafe "$B"
[[ "$(pub4 "$B")" == "$B_PUB" ]] \
  && pass "direct IPv4 restored" || fail "direct IPv4 did not return"
on "$B" 'nft list table inet rayfish_exit_client' >/dev/null 2>&1 \
  && fail "client firewall survived explicit disconnect" || pass "client firewall removed"

step "6. denied peer has no direct fallback"
arm_failsafe "$C" 180
on "$C" "ray exit-node use $NET srv-a" || { fail "deny-path selection failed"; summary; }
[[ -z "$(pub4 "$C")" ]] && pass "denied IPv4 is blocked" || fail "denied IPv4 leaked"
[[ -z "$(pub6 "$C")" ]] && pass "denied IPv6 is blocked" || fail "denied IPv6 leaked"
on "$C" "ray exit-node none $NET"
disarm_failsafe "$C"
for h in "$B" "$C"; do on "$h" 'nft delete table inet rayfish_exit_test'; done

step "7. gateway teardown: 'ray down' removes forwarding + NAT"
on "$A" 'ray down' 2>&1 | strip | sed 's/^/   a| /'
sleep 3
on "$A" 'nft list table inet rayfish_exit' >/dev/null 2>&1 \
  && fail "srv-a's nft masquerade table survived 'ray down'" \
  || pass "srv-a's nft masquerade table was removed on 'ray down'"
[[ "$(on "$A" 'cat /proc/sys/net/ipv6/conf/all/forwarding')" == "0" ]] \
  && pass "srv-a's IPv6 forwarding sysctl was restored" \
  || fail "srv-a left IPv6 forwarding enabled after 'ray down' (host stays a router)"
# Restore the value saved before enabling forwarding.
[[ "$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward')" == "$A_IP4FWD_BEFORE" ]] \
  && pass "srv-a's IPv4 forwarding is still where the run found it" \
  || fail "srv-a's ip_forward changed across the exit-node lifecycle"
# Restore for re-runs / a clean end state.
on "$A" 'ray up' >/dev/null 2>&1 || true
sleep 3

# ---------------------------------------------------------------------------
step "8. the overlay survives the down/up cycle"
# Linux flushes an interface's global IPv6 addresses on link-down, so a standby
# cycle used to leave the node with no mesh address at all: it still routed
# 200::/7 into the TUN but owned nothing in it, and every peer silently got no
# answer. With no second family to limp along on, that is now total.
A_V6=$(on "$A" "ip -o -6 addr show scope global | awk '\$2 ~ /^rayfish/ {print \$4}' | cut -d/ -f1")
[[ -n "$A_V6" ]] \
  && pass "srv-a kept its overlay IPv6 address across 'ray down' + 'ray up' ($A_V6)" \
  || fail "srv-a lost its overlay IPv6 address on the down/up cycle (IPv4-only node)"
if [[ -n "$A_V6" ]] && on "$B" "ping6 -c2 -W2 $A_V6" >/dev/null 2>&1; then
  pass "srv-b still reaches srv-a over IPv6 after the cycle"
else
  fail "srv-b cannot reach srv-a over IPv6 after the cycle"
fi
# `ray status` must report the address the interface actually holds: the check
# above reads the link, this one reads what a user would be told to dial.
[[ "$(own_ip "$(on "$A" 'ray status' | strip)")" == "$A_V6" ]] \
  && pass "srv-a's 'ray status' reports the address on its TUN" \
  || fail "srv-a's 'ray status' address disagrees with its TUN ($A_V6)"

# ---------------------------------------------------------------------------
summary
