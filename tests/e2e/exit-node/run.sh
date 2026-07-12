#!/usr/bin/env bash
# Exit-node (internet gateway) end-to-end test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `exit`, and THE EXIT NODE
#   srv-b  member ALLOWED to route its internet traffic through srv-a
#   srv-c  member NOT allowed (the deny path: its traffic must be dropped, not leaked)
#
# Proves the parts of the exit-node feature no unit test can reach — the kernel
# forwarding/NAT and the client's full-tunnel policy routing, on real Linux hosts:
#   - `ray exit-node allow` turns srv-a into a gateway: forwarding sysctls go on
#     and the nftables masquerade table appears;
#   - the offer rides the signed roster, so srv-b/srv-c discover it (`exit-node
#     status` lists it, `ray status` flags the peer);
#   - `ray exit-node use` actually re-routes egress: srv-b's public IP as seen by
#     an external echo service becomes srv-a's (IPv4, and IPv6 where available);
#   - THE LOOP PREVENTION HOLDS: with 0.0.0.0/0 pointed into the TUN, iroh's own
#     underlay UDP still egresses (SO_MARK + the fwmark ip rule), so the mesh
#     connection survives. Without it the tunnel deadlocks and everything dies —
#     this is the single assertion the whole SO_MARK fork chain exists for;
#   - mesh traffic still flows under the full tunnel (peers stay pingable);
#   - a NON-allowed peer (srv-c) selecting the same exit gets dropped: no egress
#     via the gateway AND no leak out its own uplink;
#   - teardown restores everything: `exit-node none` reverts egress and removes the
#     ip rules; `ray down` on the gateway removes the nft table and the sysctls.
#
# NOTE ON SSH: a full tunnel routes the client's replies to *our* public IP through
# the exit node, so our SSH session to srv-b/srv-c dies the moment `exit-node use`
# lands (standard full-tunnel behavior — mesh-IP SSH keeps working). So the client
# phase runs as a DETACHED, SELF-REVERTING script on the host: it does its probes,
# writes results to /tmp, then reverts, which brings SSH back. A hard failsafe
# (`ray down`/`up`) also fires, so a crashed probe can never strand an instance.
#
# Reads tests/e2e/exit-node/.servers (written by provision.sh). Does NOT modify
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
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/srv-b/srv-c in $SERVERS"; exit 1; }

NET=exit
MARK=0x7261      # exit_node::SOCKET_MARK
TABLE=29793      # exit_node::EXIT_TABLE

# pub4 <host> : the host's public IPv4 as an external service sees it (i.e. which
# uplink its traffic actually left by). Empty on failure/timeout.
pub4(){ on "$1" "curl -4 -s --max-time 20 https://api.ipify.org || curl -4 -s --max-time 20 https://ifconfig.me/ip" 2>/dev/null | tr -d '[:space:]'; }

# exit_json <host> : `ray exit-node status --json` from a host.
exit_json(){ on "$1" "ray exit-node status --json" 2>/dev/null; }

# push <host> <remote-path> : stream stdin into a file on the host. `on` uses
# `ssh -n` (stdin from /dev/null), so it can't carry a heredoc — this can.
push(){ ssh "${SSH_OPTS[@]}" -i "$KEY" "root@$1" "cat > $2"; }

# clean_kernel <host...> : drop any exit-node kernel state a crashed earlier run
# may have left behind. `reset_state` wipes /etc/rayfish (including the forwarding
# snapshot), so without this a stale nft table / ip rule would survive into the
# next run and make assertions lie. Idempotent; ignores "not found".
clean_kernel(){
  step "reset leftover exit-node kernel state (nft table, ip rules, tunnel table)"
  local h f p
  for h in "$@"; do
    on "$h" "nft delete table inet rayfish_exit" >/dev/null 2>&1
    for f in -4 -6; do
      for p in 100 101 102; do on "$h" "ip $f rule del pref $p" >/dev/null 2>&1; done
      on "$h" "ip $f route flush table $TABLE" >/dev/null 2>&1
    done
    on "$h" "sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0" >/dev/null 2>&1
    on "$h" "rm -f /tmp/exit-*.out /tmp/exit-probe.done" >/dev/null 2>&1
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
  fail "nft not available on $h — the exit node cannot install its NAT table"
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

A_VPN="$(my_ip4 "$A" "$NET")"
echo "   srv-a mesh ip = $A_VPN"

# Real public IPs (the baseline: each host normally egresses via its own uplink).
A_PUB="$(pub4 "$A")"; B_PUB="$(pub4 "$B")"; C_PUB="$(pub4 "$C")"
echo "   public IPs: a=$A_PUB  b=$B_PUB  c=$C_PUB"
[[ -n "$A_PUB" && -n "$B_PUB" ]] || { fail "could not read baseline public IPs"; summary; }
[[ "$A_PUB" != "$B_PUB" ]] \
  && pass "baseline: srv-b egresses via its own uplink ($B_PUB), not srv-a's ($A_PUB)" \
  || fail "srv-a and srv-b already share a public IP — the egress assertion would be meaningless"

# ---------------------------------------------------------------------------
step "2. srv-a becomes an exit node (allow srv-b only)"
on "$A" "ray exit-node allow $NET srv-b" 2>&1 | strip | sed 's/^/   a| /'
[[ "$(exit_json "$A" | jq -r --arg n "$NET" '.networks[] | select(.network==$n) | .offering')" == "true" ]] \
  && pass "srv-a reports offering: yes" || fail "srv-a does not report an exit-node offer"

# The gateway's kernel state must be live (it is already `up`, so the allow
# reconciles it immediately rather than waiting for the next `ray up`).
[[ "$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward')" == "1" ]] \
  && pass "srv-a: IPv4 forwarding enabled" || fail "srv-a: ip_forward not enabled"
[[ "$(on "$A" 'cat /proc/sys/net/ipv6/conf/all/forwarding')" == "1" ]] \
  && pass "srv-a: IPv6 forwarding enabled" || fail "srv-a: ipv6 forwarding not enabled"
if on "$A" 'nft list table inet rayfish_exit 2>/dev/null | grep -q masquerade'; then
  pass "srv-a: nftables masquerade table installed"
else
  fail "srv-a: no nft masquerade table (traffic would forward but never come back)"
fi

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
on "$B" "ray status" | strip | grep -q 'srv-a.*(exit)' \
  && pass "ray status flags srv-a with the (exit) badge on srv-b" \
  || fail "ray status did not flag srv-a as an exit node on srv-b"

# ---------------------------------------------------------------------------
step "4. srv-b routes all its traffic through srv-a (the full tunnel)"
# Detached + self-reverting: `exit-node use` kills our SSH (the reply path to our
# public IP now goes through the exit node), so we cannot hold the session. The
# script probes, writes to /tmp, reverts, and a failsafe guarantees recovery.
push "$B" /tmp/exit-probe.sh <<PROBE
#!/usr/bin/env bash
# Failsafe: whatever happens, this box comes back in 180s.
( sleep 180; ray exit-node none $NET; ray down; ray up ) >/dev/null 2>&1 &
FAILSAFE=\$!
rm -f /tmp/exit-*.out
ray exit-node use $NET srv-a > /tmp/exit-use.out 2>&1
sleep 8
# The headline: which uplink did our traffic actually leave by?
curl -4 -s --max-time 25 https://api.ipify.org > /tmp/exit-pub4.out 2>/dev/null \
  || curl -4 -s --max-time 25 https://ifconfig.me/ip > /tmp/exit-pub4.out 2>/dev/null
curl -6 -s --max-time 15 https://api6.ipify.org > /tmp/exit-pub6.out 2>/dev/null
# Loop prevention: is the mesh connection to srv-a still alive under the tunnel?
ray status --json > /tmp/exit-status.out 2>/dev/null
ping -c 3 -W 2 $A_VPN > /tmp/exit-meshping.out 2>&1
# The kernel state we installed.
ip -4 rule show > /tmp/exit-rules.out 2>&1
ip -4 route show table $TABLE > /tmp/exit-table.out 2>&1
ray exit-node none $NET > /tmp/exit-none.out 2>&1
kill \$FAILSAFE 2>/dev/null
echo done > /tmp/exit-probe.done
PROBE
on "$B" 'chmod +x /tmp/exit-probe.sh; setsid nohup /tmp/exit-probe.sh >/dev/null 2>&1 < /dev/null &' || true
echo "   probe launched on srv-b (SSH will drop while the tunnel is up; waiting for it to revert)"

# Wait for the probe to finish and SSH to come back.
if retry_until 150 "on '$B' 'test -f /tmp/exit-probe.done' 2>/dev/null"; then
  pass "srv-b completed the full-tunnel probe and reverted (SSH recovered)"
else
  fail "srv-b never came back from the full-tunnel probe (check the instance)"
  summary
fi

B_VIA_EXIT="$(on "$B" 'cat /tmp/exit-pub4.out 2>/dev/null' | tr -d '[:space:]')"
echo "   srv-b public IP while tunneled: '$B_VIA_EXIT'  (srv-a=$A_PUB, srv-b own=$B_PUB)"
if [[ "$B_VIA_EXIT" == "$A_PUB" ]]; then
  pass "srv-b's internet traffic egressed via srv-a — the exit node works (IPv4)"
elif [[ "$B_VIA_EXIT" == "$B_PUB" ]]; then
  fail "srv-b still egressed via its own uplink — the full tunnel did not take effect"
else
  fail "srv-b egressed via an unexpected IP '$B_VIA_EXIT' (wanted srv-a's $A_PUB)"
fi

# The loop-prevention assertion. If SO_MARK / the fwmark rule were missing, iroh's
# own UDP would have looped into the tunnel and the mesh would be dead here.
if on "$B" 'grep -q "0% packet loss" /tmp/exit-meshping.out'; then
  pass "mesh still works under the full tunnel (srv-b pinged srv-a's mesh IP)"
else
  fail "mesh broke under the full tunnel — loop prevention failed (SO_MARK/ip rule)"
fi
if on "$B" "grep -q '$MARK' /tmp/exit-rules.out"; then
  pass "srv-b installed the fwmark bypass rule ($MARK -> main)"
else
  fail "srv-b has no fwmark bypass rule — iroh's transport would loop"
fi
if on "$B" "grep -q default /tmp/exit-table.out"; then
  pass "srv-b installed the tunnel default route (table $TABLE)"
else
  fail "srv-b has no default route in the tunnel table"
fi

# IPv6 is best-effort: not every instance/zone has working v6 egress.
B_V6="$(on "$B" 'cat /tmp/exit-pub6.out 2>/dev/null' | tr -d '[:space:]')"
if [[ -n "$B_V6" ]]; then
  A_V6="$(on "$A" 'curl -6 -s --max-time 15 https://api6.ipify.org' 2>/dev/null | tr -d '[:space:]')"
  [[ "$B_V6" == "$A_V6" ]] \
    && pass "srv-b's IPv6 traffic also egressed via srv-a ($B_V6)" \
    || fail "srv-b IPv6 egressed via '$B_V6', wanted srv-a's '$A_V6'"
else
  echo "   (no IPv6 egress on these instances — skipping the v6 assertion)"
fi

# ---------------------------------------------------------------------------
step "5. egress reverts after 'ray exit-node none'"
if retry_until 60 "[[ \"\$(pub4 '$B')\" == '$B_PUB' ]]"; then
  pass "srv-b egresses via its own uplink again ($B_PUB)"
else
  fail "srv-b did not revert to direct egress (got '$(pub4 "$B")')"
fi
on "$B" "ip -4 rule show" | grep -q "$MARK" \
  && fail "srv-b's fwmark rule survived 'exit-node none' (policy routing not torn down)" \
  || pass "srv-b's full-tunnel ip rules were removed"

# ---------------------------------------------------------------------------
step "6. deny path: srv-c is NOT allowed — its traffic is dropped, not leaked"
# srv-c can still *select* srv-a (the blob advertises the offer), but srv-a's
# allow-list has only srv-b, so the gateway drops srv-c's packets. The critical
# property: srv-c must not reach the internet via srv-a AND must not silently
# fall back to its own uplink (that would be a leak the user never asked for).
push "$C" /tmp/exit-probe.sh <<PROBE
#!/usr/bin/env bash
( sleep 120; ray exit-node none $NET; ray down; ray up ) >/dev/null 2>&1 &
FAILSAFE=\$!
rm -f /tmp/exit-*.out
ray exit-node use $NET srv-a > /tmp/exit-use.out 2>&1
sleep 5
curl -4 -s --max-time 15 https://api.ipify.org > /tmp/exit-pub4.out 2>/dev/null
ray exit-node none $NET > /tmp/exit-none.out 2>&1
kill \$FAILSAFE 2>/dev/null
echo done > /tmp/exit-probe.done
PROBE
on "$C" 'chmod +x /tmp/exit-probe.sh; setsid nohup /tmp/exit-probe.sh >/dev/null 2>&1 < /dev/null &' || true
if retry_until 120 "on '$C' 'test -f /tmp/exit-probe.done' 2>/dev/null"; then
  pass "srv-c completed the deny-path probe and reverted"
else
  fail "srv-c never came back from the deny-path probe"
  summary
fi
C_VIA_EXIT="$(on "$C" 'cat /tmp/exit-pub4.out 2>/dev/null' | tr -d '[:space:]')"
if [[ -z "$C_VIA_EXIT" ]]; then
  pass "srv-c got no internet through srv-a (dropped by the allow-list, no leak)"
elif [[ "$C_VIA_EXIT" == "$A_PUB" ]]; then
  fail "SECURITY: srv-c routed through srv-a despite not being on the allow-list"
else
  fail "LEAK: srv-c's traffic escaped via '$C_VIA_EXIT' instead of being dropped"
fi

# ---------------------------------------------------------------------------
step "7. gateway teardown: 'ray down' removes forwarding + NAT"
on "$A" 'ray down' 2>&1 | strip | sed 's/^/   a| /'
sleep 3
on "$A" 'nft list table inet rayfish_exit' >/dev/null 2>&1 \
  && fail "srv-a's nft masquerade table survived 'ray down'" \
  || pass "srv-a's nft masquerade table was removed on 'ray down'"
[[ "$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward')" == "0" ]] \
  && pass "srv-a's IPv4 forwarding sysctl was restored" \
  || fail "srv-a left IPv4 forwarding enabled after 'ray down' (host stays a router)"
# Restore for re-runs / a clean end state.
on "$A" 'ray up' >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
summary
