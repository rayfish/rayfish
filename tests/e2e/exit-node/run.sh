#!/usr/bin/env bash
# Exit-node (internet gateway) end-to-end test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `exit`, and THE EXIT NODE
#   srv-b  member ALLOWED to route its internet traffic through srv-a
#   srv-c  member NOT allowed (the deny path: its traffic must be dropped, not leaked)
#
# Proves the parts of the exit-node feature no unit test can reach: the kernel
# forwarding/NAT and the client's full-tunnel policy routing, on real Linux hosts:
#   - `ray exit-node allow` turns srv-a into a gateway: forwarding sysctls go on,
#     the IPv4 lease pool is routed into the TUN, and the nftables masquerade
#     table appears;
#   - the offer rides the signed roster, so srv-b/srv-c discover it (`exit-node
#     status` lists it, `ray status` flags the peer);
#   - `ray exit-node use` re-routes egress for both families: srv-b's public IPv4
#     (and IPv6, where both ends have it) as seen by an external echo service
#     becomes srv-a's;
#   - THE LOOP PREVENTION HOLDS: with both defaults pointed into the TUN, iroh's
#     own underlay UDP still egresses (SO_MARK + the fwmark ip rule), so the mesh
#     connection survives;
#   - INBOUND CONNECTIONS SURVIVE with no test-only exemption: the SSH sessions
#     this harness drives srv-b over keep working under the full tunnel, because
#     the conntrack-mark rules answer them out the interface they came in on;
#   - an outbound TCP flow opened before the selection keeps working, while a
#     new flow forced onto the physical uplink is refused by the client guard;
#   - the LAN (the VPC private network), a co-resident VPN's routes, and a
#     Docker-style bridge stay reachable, and the bridge's forwarded traffic
#     leaves through the exit;
#   - losing the tunnel's default route fails closed instead of leaking;
#   - a NON-allowed peer (srv-c) selecting the same exit gets dropped: no egress
#     via the gateway AND no leak out its own uplink, for either family;
#   - teardown restores everything: `exit-node none` reverts egress and removes the
#     rules, the client address and the guard; `ray down` on the gateway removes
#     the nft table, the pool route and the sysctls.
#
# Every step that turns a full tunnel on arms a self-revert failsafe on the host
# first: one bad rule is the difference between a working tunnel and an instance
# that has cut off its own SSH, and a test must never be able to strand a machine.
#
# Reads tests/e2e/exit-node/.servers (written by provision.sh). Does NOT modify
# infra. Re-runnable (resets rayfish state each run unless KEEP_STATE=1).
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
CLIENT_ADDR=192.0.0.2       # exit_node::ipv4::CLIENT_ADDR
POOL=198.19.0.0/16          # exit_node::ipv4::SERVER_PREFIX
FLOW_PORT=9099              # the pre-existing outbound flow in step 4

# pub4 <host> [curl args...] : the host's public IPv4 as an external service sees
# it (i.e. which uplink its traffic actually left by). Empty on failure/timeout.
pub4(){
  local h="$1"; shift
  on "$h" "curl -4 -s --max-time 20 $* https://api.ipify.org || curl -4 -s --max-time 20 $* https://ifconfig.me/ip" 2>/dev/null | tr -d '[:space:]'
}

# pub6 <host> : the host's public IPv6 as an external service sees it. Empty when
# the host has no IPv6 egress at all, which several instances do not.
#
# Two services, as `pub4` has: the baseline reading decides whether the IPv6
# assertions run at all, so one flaky probe would turn them into skips whose
# message claims something about the host that was never established.
pub6(){ on "$1" "curl -6 -s --max-time 20 https://api6.ipify.org || curl -6 -s --max-time 20 https://icanhazip.com" 2>/dev/null | tr -d '[:space:]'; }

# pub4_once / pub6_once <host> [curl args...] : one service and a short timeout,
# for probes expected to fail. The fallback in `pub4`/`pub6` only makes a refused
# probe sit through two long timeouts.
pub4_once(){
  local h="$1"; shift
  on "$h" "curl -4 -s --connect-timeout 5 --max-time 8 $* https://api.ipify.org" 2>/dev/null | tr -d '[:space:]'
}
pub6_once(){
  local h="$1"; shift
  on "$h" "curl -6 -s --connect-timeout 5 --max-time 8 $* https://api6.ipify.org" 2>/dev/null | tr -d '[:space:]'
}

# exit_json <host> : `ray exit-node status --json` from a host.
exit_json(){ on "$1" "ray exit-node status --json" 2>/dev/null; }

# tun_name <host> : the host's rayfish TUN interface.
tun_name(){ on "$1" "ip -o link show | awk -F': ' '\$2 ~ /^rayfish/ {print \$2; exit}'" 2>/dev/null | cut -d@ -f1; }

# uplink <host> : the interface holding main's IPv4 default route.
uplink(){ on "$1" "ip -4 route show default | awk '{for(i=1;i<NF;i++) if(\$i==\"dev\"){print \$(i+1); exit}}'" 2>/dev/null; }

# private4 <host> : the host's VPC private IPv4. DigitalOcean puts it on eth1;
# the 10.x address on eth0 is the anchor for reserved IPs and is not reachable
# from other droplets. Empty when there is none, which the LAN check then skips.
private4(){ on "$1" "ip -4 -o addr show dev eth1 scope global | awk '{split(\$4,a,\"/\"); print a[1]; exit}'" 2>/dev/null; }

# put_file <host> <path> <content> : write a file on a host. `on` runs ssh with
# -n, so content cannot go over stdin; base64 keeps quoting out of it.
put_file(){ on "$1" "echo $(printf '%s' "$3" | base64 | tr -d '\n') | base64 -d > $2"; }

# arm_failsafe <host> <seconds> : detached self-revert, armed BEFORE any full
# tunnel goes up. If we lose the host (a routing bug cutting our own SSH), it drops
# the tunnel on its own after <seconds> and the instance comes back. Cancelled by
# disarm_failsafe once egress is restored, so a passing run costs nothing.
arm_failsafe(){
  on "$1" "rm -f /tmp/exit-disarm; setsid nohup bash -c 'sleep $2; [ -f /tmp/exit-disarm ] || { ray exit-node none $NET; ray down; ray up; }' >/dev/null 2>&1 < /dev/null &" >/dev/null 2>&1
}
disarm_failsafe(){ on "$1" 'touch /tmp/exit-disarm' >/dev/null 2>&1; }

# The fixtures step 4 builds: the TCP flow's scripts, the Docker-style bridge, and
# the stand-in co-resident VPN (table 52 at pref 5250, in Tailscale's range). Left
# behind, the VPN would make the next run's mirror assertions pass on state that
# run never installed.
# Anchored on the interpreter: an unanchored pattern also matches the shell
# running this cleanup, whose command line names the same files, and kills it.
FIXTURE_CLEANUP="pkill -f '^python3 /tmp/exit-(echo|flow)\.py'
rm -f /tmp/exit-echo.py /tmp/exit-flow.py /tmp/exit-flow.log
ip netns del exitctr; ip link del veth-exit; nft delete table ip exit_test_docker
for f in -4 -6; do
  while ip \$f rule del pref 5250 2>/dev/null; do :; done
  ip \$f route flush table 52
done"

# drop_fixtures <host> : remove step 4's fixtures from a host.
drop_fixtures(){ on "$1" "$FIXTURE_CLEANUP" >/dev/null 2>&1; }

# clean_kernel <host...> : drop any exit-node kernel state a crashed earlier run
# may have left behind. `reset_state` wipes /etc/rayfish (including the forwarding
# snapshot), so without this a stale nft table / ip rule would survive into the
# next run and make assertions lie. Idempotent; ignores "not found".
#
# Pref 99 holds one rule per physical address, so a single `del` leaves the rest
# behind. 98 and 102 are one rule each, but both read back as `lookup 29793`, and
# a leftover would make step 5's "rules removed" grep fail on state this run never
# installed. The client address and the gateway's pool route both live on the
# TUN, which survives `reset_state` until the daemon restarts.
clean_kernel(){
  step "reset leftover exit-node kernel state (nft table, ip rules, tunnel table)"
  local h
  for h in "$@"; do
    (
      on "$h" "nft delete table inet rayfish_exit; nft delete table inet rayfish_exit_client
for f in -4 -6; do
  for p in 98 99 100 101 102; do
    while ip \$f rule del pref \$p 2>/dev/null; do :; done
  done
  ip \$f route flush table $TABLE
done
dev=\$(ip -o link show | awk -F': ' '\$2 ~ /^rayfish/ {print \$2; exit}' | cut -d@ -f1)
[ -n \"\$dev\" ] && { ip -4 addr del $CLIENT_ADDR/32 dev \$dev; ip -4 route del $POOL dev \$dev; }
$FIXTURE_CLEANUP
sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
rm -f /tmp/exit-disarm" >/dev/null 2>&1
      echo "   cleaned $h"
    ) &
  done
  wait
}

# select_exit <host> <label> <secs> <consequence> : arm a <secs> failsafe, then
# select srv-a on <host>. Sets USE_TOOK to how long `exit-node use` took. On
# failure it reverts before disarming, and in that order: `disarm_failsafe` only
# touches the flag file, so disarming a half-installed tunnel takes away the
# automatic revert without doing one. 255 is ssh itself failing, which is not a
# refusal. <consequence> ends the failure message.
select_exit(){
  local h="$1" label="$2" out rc started
  arm_failsafe "$h" "$3"
  started=$SECONDS
  out="$(on "$h" "ray exit-node use $NET srv-a" 2>&1)"; rc=$?
  USE_TOOK=$((SECONDS - started))
  printf '%s\n' "$out" | strip | sed "s/^/   ${label#srv-}| /"
  [[ $rc -eq 0 ]] && return 0
  on "$h" "ray exit-node none $NET" >/dev/null 2>&1
  disarm_failsafe "$h"
  if [[ $rc -eq 255 ]]; then
    fail "lost ssh to $label running \`exit-node use\` (rc=255): cannot tell what happened"
  else
    fail "$label's \`exit-node use\` failed (rc=$rc): $4"
  fi
  return 1
}

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all three hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"

# The gateway shells out to `nft` (and every host curls an echo service), so make
# sure both exist rather than failing later with a confusing "enable" error.
for h in "$A" "$B" "$C"; do
  on "$h" 'command -v nft >/dev/null && command -v curl >/dev/null && command -v python3 >/dev/null' \
    || on "$h" 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables curl python3' >/dev/null 2>&1
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

# Real public IPs (the baseline: each host normally egresses via its own uplink),
# and the v6 baseline, taken before any tunnel exists. A v6 reading is empty on an
# instance with no IPv6 egress, which the IPv6 assertions below then skip.
PROBES="$(mktemp -d)"
for pair in "a:$A" "b:$B" "c:$C"; do
  n="${pair%%:*}"; h="${pair#*:}"
  pub4 "$h" >"$PROBES/$n.4" &
  pub6 "$h" >"$PROBES/$n.6" &
done
wait
A_PUB="$(<"$PROBES/a.4")"; B_PUB="$(<"$PROBES/b.4")"; C_PUB="$(<"$PROBES/c.4")"
A_PUB_V6="$(<"$PROBES/a.6")"; B_PUB_V6="$(<"$PROBES/b.6")"; C_PUB_V6="$(<"$PROBES/c.6")"
rm -rf "$PROBES"
echo "   public IPv4: a=$A_PUB  b=$B_PUB  c=$C_PUB"
echo "   public IPv6: a=${A_PUB_V6:-<none>}  b=${B_PUB_V6:-<none>}  c=${C_PUB_V6:-<none>}"
[[ -n "$A_PUB" && -n "$B_PUB" && -n "$C_PUB" ]] || { fail "could not read baseline public IPs"; summary; }
[[ "$A_PUB" != "$B_PUB" ]] \
  && pass "baseline: srv-b egresses via its own uplink ($B_PUB), not srv-a's ($A_PUB)" \
  || fail "srv-a and srv-b already share a public IP: the egress assertion would be meaningless"

# The positive control for step 4's guard check: before any tunnel, a socket
# bound to the uplink does reach the internet, so a failure there means the guard.
B_UPLINK="$(uplink "$B")"
echo "   srv-b uplink = ${B_UPLINK:-<none>}"
[[ -n "$B_UPLINK" ]] || fail "could not read srv-b's IPv4 uplink interface"
[[ "$(pub4 "$B" --interface "$B_UPLINK")" == "$B_PUB" ]] \
  && pass "baseline: a socket bound to srv-b's uplink reaches the internet" \
  || fail "baseline: a socket bound to $B_UPLINK cannot reach the internet even without a tunnel"

# ---------------------------------------------------------------------------
step "2. srv-a becomes an exit node (allow srv-b only)"
on "$A" "ray exit-node allow $NET srv-b" 2>&1 | strip | sed 's/^/   a| /'
[[ "$(exit_json "$A" | jq -r --arg n "$NET" '.networks[] | select(.network==$n) | .offering')" == "true" ]] \
  && pass "srv-a reports offering: yes" || fail "srv-a does not report an exit-node offer"

# The gateway's kernel state must be live (it is already `up`, so the allow
# reconciles it immediately rather than waiting for the next `ray up`).
A_TUN="$(tun_name "$A")"
# Both forwarding sysctls in one read, IPv4 first.
read -r A_FWD4 A_FWD6 <<<"$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding' 2>/dev/null | tr '\n' ' ')"
A_NFT="$(on "$A" 'nft list table inet rayfish_exit' 2>/dev/null)"
[[ "$A_FWD6" == "1" ]] \
  && pass "srv-a: IPv6 forwarding enabled" || fail "srv-a: ipv6 forwarding not enabled"
if grep -q masquerade <<<"$A_NFT"; then
  pass "srv-a: nftables masquerade table installed"
else
  fail "srv-a: no nft masquerade table (traffic would forward but never come back)"
fi
# The IPv4 half: leased client addresses come out of the pool into the TUN, the
# kernel forwards them and masquerades them on the uplink, and replies to the pool
# route back into the TUN for the forwarder to hand to the right peer.
[[ "$A_FWD4" == "1" ]] \
  && pass "srv-a: IPv4 forwarding enabled" || fail "srv-a: IPv4 forwarding not enabled"
grep -q "ip saddr $POOL" <<<"$A_NFT" \
  && pass "srv-a: the IPv4 lease pool is masqueraded" || fail "srv-a: no IPv4 masquerade for $POOL"
on "$A" "ip -4 route show $POOL" 2>/dev/null | grep -q "dev ${A_TUN:-rayfish}" \
  && pass "srv-a: the IPv4 lease pool routes into the TUN" \
  || fail "srv-a: no $POOL route into ${A_TUN:-the TUN} (replies would never reach the forwarder)"

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

# The IPv6 claim follows srv-a's uplink. A gateway without one still carries
# IPv4, so the selection goes ahead either way; only the IPv6 assertion changes.
b_v6_available(){
  exit_json "$B" | jq -r --arg n "$NET" \
    '.networks[] | select(.network==$n) | .available_v6[]' 2>/dev/null | grep -c srv-a
}
if [[ -n "$A_PUB_V6" ]]; then
  retry_until 90 "[[ \"\$(b_v6_available)\" == '1' ]]" \
    && pass "srv-a is listed as carrying IPv6 in srv-b's exit-node status" \
    || fail "srv-a has an IPv6 uplink but is not advertised as carrying IPv6"
else
  retry_until 90 "[[ \"\$(b_v6_available)\" == '0' ]]" \
    && pass "srv-a is not listed as carrying IPv6 (it has no v6 uplink)" \
    || fail "srv-a claims IPv6 egress it does not have"
fi

# ---------------------------------------------------------------------------
step "4. srv-b sends both families through srv-a; LAN, other VPNs and bridges stay local"
# Stand in for a co-resident VPN: a route in a table of its own, reached by a
# rule far below ours. Our catch-all would swallow it (PREF_MAIN's
# suppress_prefixlength only rescues routes in `main`), so the install has to
# copy it into the tunnel table first or that VPN goes dark. Set up before the
# selection, because the copy happens at install time.
FOREIGN_NET6="fd7a:115c:a1e0::/48"
FOREIGN_NET4="100.100.64.0/24"
on "$B" "ip -6 route replace $FOREIGN_NET6 dev lo table 52; ip -6 rule add pref 5250 table 52" >/dev/null 2>&1
on "$B" "ip -4 route replace $FOREIGN_NET4 dev lo table 52; ip -4 rule add pref 5250 table 52" >/dev/null 2>&1

# Stand in for Docker: a namespace behind a veth, masqueraded on the way out the
# way Docker's own MASQUERADE rule does it. Its traffic is forwarded, not local,
# so it is what the guard's forward hook sees.
on "$B" "ip netns add exitctr \
  && ip link add veth-exit type veth peer name veth-exitns \
  && ip link set veth-exitns netns exitctr \
  && ip addr add 172.30.0.1/24 dev veth-exit && ip link set veth-exit up \
  && ip netns exec exitctr ip addr add 172.30.0.2/24 dev veth-exitns \
  && ip netns exec exitctr ip link set veth-exitns up \
  && ip netns exec exitctr ip link set lo up \
  && ip netns exec exitctr ip route add default via 172.30.0.1 \
  && sysctl -qw net.ipv4.ip_forward=1 \
  && nft add table ip exit_test_docker \
  && nft 'add chain ip exit_test_docker post { type nat hook postrouting priority srcnat; policy accept; }' \
  && nft 'add rule ip exit_test_docker post ip saddr 172.30.0.0/24 oifname != \"veth-exit\" masquerade'" >/dev/null 2>&1 \
  || fail "could not build the Docker-style bridge on srv-b"
# The namespace has no resolver of its own (the host's stub listens on its
# loopback), so the host resolves and curl pins the answer.
ctr_pub4(){
  on "$B" "ip=\$(getent ahostsv4 api.ipify.org | awk 'NR==1{print \$1}'); ip netns exec exitctr curl -4 -s --max-time 20 --resolve api.ipify.org:443:\$ip https://api.ipify.org" 2>/dev/null | tr -d '[:space:]'
}
[[ "$(ctr_pub4)" == "$B_PUB" ]] \
  && pass "baseline: the bridge reaches the internet through srv-b's uplink" \
  || fail "baseline: the Docker-style bridge has no internet before any tunnel"

# An outbound TCP flow opened before the selection: an echo server on srv-a's
# public IPv4, and a client on srv-b that sends a line a second and logs each
# reply. Its socket is bound to srv-b's physical address, so it must keep leaving
# directly (PREF_SRC) and the guard must let its mid-flow packets through.
put_file "$A" /tmp/exit-echo.py "import socket, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $FLOW_PORT))
s.listen(4)
def serve(c):
    while True:
        d = c.recv(64)
        if not d:
            return
        c.sendall(d)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"
put_file "$B" /tmp/exit-flow.py "import socket, sys, time
c = socket.create_connection(('$A_PUB', $FLOW_PORT), timeout=10)
c.settimeout(10)
for _ in range(600):
    try:
        c.sendall(b'x')
        c.recv(1)
        print('ok', flush=True)
    except OSError as e:
        print('ERR', e, flush=True)
        sys.exit(1)
    time.sleep(1)
"
on "$A" "setsid nohup python3 /tmp/exit-echo.py >/dev/null 2>&1 < /dev/null &" >/dev/null 2>&1
retry_until 10 "on '$A' \"ss -ltn 'sport = :$FLOW_PORT'\" 2>/dev/null | grep -q LISTEN" \
  || fail "the echo server on srv-a never listened on port $FLOW_PORT"
on "$B" "setsid nohup python3 /tmp/exit-flow.py >/tmp/exit-flow.log 2>&1 < /dev/null &" >/dev/null 2>&1
flow_count(){ on "$B" "grep -c '^ok' /tmp/exit-flow.log" 2>/dev/null; }
retry_until 15 "[[ \"\$(flow_count)\" -ge 2 ]]" \
  && pass "baseline: srv-b's long-lived TCP flow to srv-a is running" \
  || fail "baseline: the long-lived TCP flow to srv-a never started"

# The LAN, read before the selection: srv-a's VPC address.
A_PRIV="$(private4 "$A")"
echo "   srv-a private ipv4 = ${A_PRIV:-<none>}"

select_exit "$B" srv-b 300 "no tunnel to test" || summary
# The command runs over SSH, and the tunnel comes up underneath that very session.
# If the conntrack-mark rules do not cover a connection that predates the tunnel,
# the reply is swallowed and this returns minutes later, after the failsafe has
# already reverted the host: every assertion below then measures a torn-down
# tunnel and lies about which part is broken. Time it so that failure names itself.
[[ $USE_TOOK -le 30 ]] \
  && pass "\`exit-node use\` returned promptly (${USE_TOOK}s)" \
  || fail "\`exit-node use\` took ${USE_TOOK}s: the SSH session running it stalled under the tunnel"

# The assertion this whole feature lives or dies on for a headless host: we are
# still talking to srv-b over its PUBLIC IP while both its defaults point into the
# tunnel, with no test-only exemption. Without the conntrack-mark rules, sshd's
# replies egress via srv-a, come out NATed as srv-a's address, and every command
# below hangs instead of answering.
if on "$B" 'true' 2>/dev/null; then
  pass "SSH to srv-b's public IP survived the full tunnel (inbound conns bypass it)"
else
  fail "srv-b cut off its own SSH under the full tunnel: inbound-connection bypass is broken"
  echo "   (the failsafe will revert srv-b within 300s)"
  summary
fi

# The headline: IPv4 leaves through the gateway. Polled, since the gateway may
# still be leasing the client its address when `use` returns.
if retry_until 30 "[[ \"\$(pub4 '$B')\" == '$A_PUB' ]]"; then
  pass "srv-b's IPv4 traffic egressed via srv-a ($A_PUB): the IPv4 exit works"
else
  B_VIA_EXIT="$(pub4 "$B")"
  echo "   srv-b public IPv4 while tunneled: '$B_VIA_EXIT'  (srv-a=$A_PUB, srv-b own=$B_PUB)"
  if [[ "$B_VIA_EXIT" == "$B_PUB" ]]; then
    fail "LEAK: srv-b's IPv4 still leaves by its own uplink under the full tunnel"
  else
    fail "srv-b's IPv4 did not egress via srv-a (got '$B_VIA_EXIT')"
  fi
fi
# IPv6 goes through when both ends have it, and is blocked rather than leaked
# when only srv-b does.
if [[ -n "$B_PUB_V6" && -n "$A_PUB_V6" ]]; then
  B_V6="$(pub6 "$B")"
  [[ "$B_V6" == "$A_PUB_V6" ]] \
    && pass "srv-b's IPv6 traffic egressed via srv-a ($B_V6)" \
    || fail "srv-b IPv6 egressed via '$B_V6', wanted srv-a's '$A_PUB_V6'"
elif [[ -n "$B_PUB_V6" ]]; then
  [[ -z "$(pub6_once "$B")" ]] \
    && pass "srv-a cannot carry IPv6, and srv-b's IPv6 is blocked rather than leaked" \
    || fail "LEAK: srv-b's IPv6 bypassed an exit that cannot carry it"
else
  echo "   (srv-b has no IPv6 egress: no IPv6 to tunnel)"
fi

# The loop-prevention assertion. If SO_MARK / the fwmark rule were missing, iroh's
# own UDP would have looped into the tunnel and the mesh would be dead here.
#
# Read through `ping_loss` rather than grepping for "0% packet loss": that
# substring is also inside "100% packet loss".
if [[ "$(ping_loss "$B" "$A_VPN")" == "0" ]]; then
  pass "mesh still works under the full tunnel (srv-b pinged srv-a's mesh IP)"
else
  fail "mesh broke under the full tunnel: loop prevention failed (SO_MARK/ip rule)"
fi

# The kernel state behind it, for both families.
# Each family's rules and tunnel table in one read, reused by the co-resident VPN
# checks below.
B_TUN="$(tun_name "$B")"
B_KERNEL4="$(on "$B" "ip -4 rule show; ip -4 route show table $TABLE" 2>/dev/null)"
B_KERNEL6="$(on "$B" "ip -6 rule show; ip -6 route show table $TABLE" 2>/dev/null)"
for f in -4 -6; do
  [[ "$f" == -4 ]] && k="$B_KERNEL4" || k="$B_KERNEL6"
  grep -q "$MARK" <<<"$k" \
    && pass "srv-b ($f): fwmark bypass rule ($MARK -> main)" \
    || fail "srv-b ($f): no fwmark bypass rule: iroh's transport would loop"
  grep -qE "^102:.*lookup $TABLE" <<<"$k" \
    && pass "srv-b ($f): catch-all rule into the tunnel table" \
    || fail "srv-b ($f): no catch-all rule into table $TABLE"
  grep -q "^default dev ${B_TUN:-rayfish}" <<<"$k" \
    && pass "srv-b ($f): tunnel default route (table $TABLE)" \
    || fail "srv-b ($f): no default route into the TUN in table $TABLE"
  grep -q "^unreachable default" <<<"$k" \
    && pass "srv-b ($f): unreachable fallback behind the tunnel default" \
    || fail "srv-b ($f): no unreachable fallback: losing the tunnel route would leak"
done
on "$B" "ip -4 addr show dev ${B_TUN:-rayfish}" 2>/dev/null | grep -q "inet $CLIENT_ADDR/32" \
  && pass "srv-b holds the IPv4 client address $CLIENT_ADDR on its TUN" \
  || fail "srv-b has no $CLIENT_ADDR on its TUN: IPv4 has no source"

# The client guard: new flows leaving outside the tunnel are refused, and nothing
# else. A drop-all policy would cut the LAN, Docker and other VPNs.
B_CLIENT_NFT="$(on "$B" 'nft list table inet rayfish_exit_client' 2>/dev/null)"
grep -q "ct mark" <<<"$B_CLIENT_NFT" \
  && pass "srv-b installed the conntrack-mark chains (inbound connections bypass the tunnel)" \
  || fail "srv-b has no conntrack-mark chains: inbound connections would be swallowed"
grep -q "chain guard " <<<"$B_CLIENT_NFT" && grep -q "ct state new drop" <<<"$B_CLIENT_NFT" \
  && pass "srv-b installed the client guard (new flows outside the tunnel are dropped)" \
  || fail "srv-b has no client guard chain"
grep -q "policy drop" <<<"$B_CLIENT_NFT" \
  && fail "srv-b's client table has a drop policy: everything not excepted is cut" \
  || pass "srv-b's client table has no drop policy"
[[ -z "$(pub4_once "$B" --interface "$B_UPLINK")" ]] \
  && pass "a new connection bound to the uplink ($B_UPLINK) is refused" \
  || fail "LEAK: a socket bound to $B_UPLINK reached the internet around the tunnel"

# The flow that predates the tunnel kept going: its replies still arrive.
flow_before="$(flow_count)"
sleep 4
flow_after="$(flow_count)"
if on "$B" "grep -q '^ERR' /tmp/exit-flow.log" 2>/dev/null; then
  fail "the TCP flow opened before the selection broke: $(on "$B" "grep '^ERR' /tmp/exit-flow.log | head -1")"
elif [[ "${flow_after:-0}" -gt "${flow_before:-0}" ]]; then
  pass "the TCP flow opened before the selection is still answered ($flow_before -> $flow_after)"
else
  fail "the TCP flow opened before the selection stalled at $flow_after replies"
fi

# The LAN stays direct: the VPC route lives in `main` and the guard excepts
# private ranges.
if [[ -n "$A_PRIV" ]]; then
  ROUTE_PRIV="$(on "$B" "ip -4 route get $A_PRIV" 2>/dev/null | head -1)"
  echo "   srv-b route to srv-a's private address: $ROUTE_PRIV"
  [[ -n "$ROUTE_PRIV" && "$ROUTE_PRIV" != *"dev ${B_TUN:-rayfish}"* ]] \
    && pass "the LAN route stays off the tunnel" \
    || fail "srv-b routes its LAN peer ($A_PRIV) into the tunnel"
  png "$B" "$A_PRIV" "from srv-b to srv-a's private address (the LAN survives the tunnel)"
else
  echo "   (srv-a has no private IPv4: skipping the LAN check)"
fi

# The Docker-style bridge: reachable from the host, and its forwarded internet
# traffic leaves through the exit (masqueraded to the client address first).
png "$B" 172.30.0.2 "from srv-b to its Docker-style bridge (the bridge survives the tunnel)"
CTR_VIA="$(ctr_pub4)"
[[ "$CTR_VIA" == "$A_PUB" ]] \
  && pass "the bridge's forwarded traffic egressed via srv-a" \
  || fail "the bridge's forwarded traffic left as '$CTR_VIA', wanted srv-a's $A_PUB"

# The co-resident VPN's routes survive the tunnel. Our default is a catch-all far
# above that VPN's own preferences, so without the copy its prefixes go dark.
for f in -4 -6; do
  if [[ "$f" == -4 ]]; then FOREIGN_NET="$FOREIGN_NET4" k="$B_KERNEL4"; else FOREIGN_NET="$FOREIGN_NET6" k="$B_KERNEL6"; fi
  grep -q "$FOREIGN_NET" <<<"$k" \
    && pass "the co-resident VPN's $f route was mirrored into the tunnel table" \
    || fail "the co-resident VPN's $f route was not mirrored: our catch-all black-holes it"
  # The mirror is only half of it. PREF_SRC and PREF_BYPASS sit above the
  # catch-all and both look up `main`, where a policy-routing VPN keeps nothing,
  # so traffic sourced from its address still misses. One rule covers every
  # mirrored prefix: `suppress_prefixlength 0` matches the copies and suppresses
  # our own default.
  grep -q "lookup $TABLE suppress_prefixlength 0" <<<"$k" \
    && pass "the co-resident VPN's $f destinations are routed to the mirrored copy" \
    || fail "no $f pref-98 rule: traffic sourced from that VPN's own address is black-holed"
done
# Sourced from the foreign address, which is the case the mirror alone misses:
# this is what an inbound session's replies look like.
B_FOREIGN_SRC="$(on "$B" "ip -6 addr show scope global | awk '/inet6/{print \$2}' | cut -d/ -f1 | head -1")"
if [[ -n "$B_FOREIGN_SRC" ]]; then
  on "$B" "ip -6 route get ${FOREIGN_NET6%%/*}1 from $B_FOREIGN_SRC" 2>/dev/null | grep -q "table $TABLE\|dev lo" \
    && pass "traffic sourced from the co-resident VPN's address still reaches it" \
    || fail "traffic sourced from that VPN's address takes the physical default (an inbound session over it would die)"
else
  echo "   (srv-b has no global IPv6: skipping the foreign-source route check)"
fi

# DNS still resolves under the tunnel, public names and mesh names alike.
on "$B" "getent hosts example.com" >/dev/null 2>&1 \
  && pass "non-mesh DNS still resolves under the tunnel" \
  || fail "DNS broke under the tunnel"
on "$B" "getent hosts srv-a.ray" >/dev/null 2>&1 \
  && pass "'.ray' names still resolve under the tunnel" \
  || fail "'.ray' resolution broke under the tunnel"
# The exit column now names srv-a as the peer carrying our traffic, not just one
# offering to (it read `offers` in step 3, before we selected it).
on "$B" "ray status" | strip | grep -q 'srv-a.*in use' \
  && pass "ray status marks srv-a 'in use' in the exit column" \
  || fail "ray status does not mark srv-a as the exit node in use"

# Route loss fails closed: with the tunnel default gone, the unreachable fallback
# answers, and nothing falls through to `main`'s default. The daemon's kernel
# check may already have put the route back, which is also not a leak.
on "$B" "ip -4 route del default dev ${B_TUN:-rayfish} table $TABLE" >/dev/null 2>&1
LOST_VIA="$(pub4_once "$B")"
echo "   srv-b public IPv4 with the tunnel default removed: '${LOST_VIA:-<none>}'"
[[ "$LOST_VIA" != "$B_PUB" ]] \
  && pass "losing the tunnel default does not leak IPv4 out the uplink" \
  || fail "LEAK: with the tunnel default gone, IPv4 left by srv-b's own uplink"
on "$B" "ip -4 route replace default dev ${B_TUN:-rayfish} table $TABLE src $CLIENT_ADDR" >/dev/null 2>&1
retry_until 30 "[[ \"\$(pub4 '$B')\" == '$A_PUB' ]]" \
  && pass "IPv4 exits through srv-a again once the tunnel default is back" \
  || fail "IPv4 did not recover after restoring the tunnel default"

# ---------------------------------------------------------------------------
step "5. egress reverts after 'ray exit-node none'"
on "$B" "ray exit-node none $NET" 2>&1 | strip | sed 's/^/   b| /'
disarm_failsafe "$B"
if retry_until 60 "[[ \"\$(pub4 '$B')\" == '$B_PUB' ]]"; then
  pass "srv-b egresses via its own IPv4 uplink again ($B_PUB)"
else
  fail "srv-b did not revert to direct IPv4 egress (got '$(pub4 "$B")')"
fi
if [[ -n "$B_PUB_V6" ]]; then
  if retry_until 60 "[[ \"\$(pub6 '$B')\" == '$B_PUB_V6' ]]"; then
    pass "srv-b egresses via its own IPv6 uplink again ($B_PUB_V6)"
  else
    fail "srv-b did not revert to direct IPv6 egress (got '$(pub6 "$B")')"
  fi
fi
for f in -4 -6; do
  on "$B" "ip $f rule show" | grep -q "$MARK\|lookup $TABLE" \
    && fail "srv-b's $f full-tunnel rules survived 'exit-node none'" \
    || pass "srv-b's $f full-tunnel rules were removed"
done
on "$B" "ip -4 addr show" | grep -q "inet $CLIENT_ADDR/" \
  && fail "srv-b kept $CLIENT_ADDR after 'exit-node none'" \
  || pass "srv-b's IPv4 client address was removed"
on "$B" 'nft list table inet rayfish_exit_client' >/dev/null 2>&1 \
  && fail "srv-b's client table (conntrack marks and guard) survived 'exit-node none'" \
  || pass "srv-b's client table was removed"
[[ "$(ctr_pub4)" == "$B_PUB" ]] \
  && pass "the bridge egresses directly again" \
  || fail "the Docker-style bridge did not return to direct egress"
drop_fixtures "$A"
drop_fixtures "$B"
# The bridge turned it on; `clean_kernel` left it off.
on "$B" "sysctl -qw net.ipv4.ip_forward=0" >/dev/null 2>&1

# ---------------------------------------------------------------------------
step "6. deny path: srv-c is NOT allowed: its traffic is dropped, not leaked"
# srv-c can still *select* srv-a (the blob advertises the offer), but srv-a's
# allow-list has only srv-b, so the gateway drops srv-c's packets. The critical
# property: srv-c must not reach the internet via srv-a AND must not silently fall
# back to its own uplink (that would be a leak the user never asked for). Both
# families are captured now, so both are probed.
# `ray exit-node use` exits non-zero on a refusal, and a refused selection
# installs no tunnel. Reading the probes without checking this would report
# srv-c's untouched direct egress as a LEAK, for a test that never ran.
if select_exit "$C" srv-c 180 "the deny path never ran"; then
  # Probe only once the catch-all is in, or a not-yet-routed probe reads as a leak.
  retry_until 20 "on '$C' 'ip -4 rule show' 2>/dev/null | grep -qE '^102:.*lookup $TABLE'" \
    || echo "   (srv-c's catch-all rule never appeared: the probes below may read as a leak)"
  C_VIA_EXIT="$(pub4_once "$C")"
  C_VIA_EXIT_V6=""
  [[ -n "$C_PUB_V6" ]] && C_VIA_EXIT_V6="$(pub6_once "$C")"
  on "$C" "ray exit-node none $NET" >/dev/null 2>&1
  disarm_failsafe "$C"
  if [[ -z "$C_VIA_EXIT" ]]; then
    pass "srv-c got no IPv4 internet through srv-a (dropped by the allow-list, no leak)"
  elif [[ "$C_VIA_EXIT" == "$A_PUB" ]]; then
    fail "SECURITY: srv-c's IPv4 routed through srv-a despite not being on the allow-list"
  else
    fail "LEAK: srv-c's IPv4 escaped via '$C_VIA_EXIT' instead of being dropped"
  fi
  if [[ -z "$C_PUB_V6" ]]; then
    echo "   (srv-c has no IPv6 egress: nothing to probe for IPv6)"
  elif [[ -z "$C_VIA_EXIT_V6" ]]; then
    pass "srv-c got no IPv6 internet either (no leak)"
  elif [[ -n "$A_PUB_V6" && "$C_VIA_EXIT_V6" == "$A_PUB_V6" ]]; then
    fail "SECURITY: srv-c's IPv6 routed through srv-a despite not being on the allow-list"
  else
    fail "LEAK: srv-c's IPv6 escaped via '$C_VIA_EXIT_V6' instead of being dropped"
  fi
fi

# ---------------------------------------------------------------------------
step "7. gateway teardown: 'ray down' removes forwarding + NAT"
on "$A" 'ray down' 2>&1 | strip | sed 's/^/   a| /'
retry_until 15 "! on '$A' 'nft list table inet rayfish_exit' >/dev/null 2>&1" \
  && pass "srv-a's nft masquerade table was removed on 'ray down'" \
  || fail "srv-a's nft masquerade table survived 'ray down'"
on "$A" "ip -4 route show $POOL" 2>/dev/null | grep -q . \
  && fail "srv-a's IPv4 pool route survived 'ray down'" \
  || pass "srv-a's IPv4 pool route was removed"
# `clean_kernel` zeroed both, so 0 is what teardown has to put back.
read -r A_FWD4 A_FWD6 <<<"$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding' 2>/dev/null | tr '\n' ' ')"
[[ "$A_FWD6" == "0" ]] \
  && pass "srv-a's IPv6 forwarding sysctl was restored" \
  || fail "srv-a left IPv6 forwarding enabled after 'ray down' (host stays a router)"
[[ "$A_FWD4" == "0" ]] \
  && pass "srv-a's IPv4 forwarding was restored to 0" \
  || fail "srv-a left ip_forward at '$A_FWD4' after 'ray down' (wanted 0)"
# Restore for re-runs / a clean end state.
on "$A" 'ray up' >/dev/null 2>&1 || true
wait_daemons "$A"

# ---------------------------------------------------------------------------
step "8. the overlay survives the down/up cycle"
# Linux flushes an interface's global IPv6 addresses on link-down, so a standby
# cycle used to leave the node with no mesh address at all: it still routed
# 200::/7 into the TUN but owned nothing in it, and every peer silently got no
# answer.
A_V6=$(on "$A" "ip -o -6 addr show scope global | awk '\$2 ~ /^rayfish/ {print \$4}' | cut -d/ -f1")
[[ -n "$A_V6" ]] \
  && pass "srv-a kept its overlay IPv6 address across 'ray down' + 'ray up' ($A_V6)" \
  || fail "srv-a lost its overlay IPv6 address on the down/up cycle"
if [[ -n "$A_V6" ]] && on "$B" "ping6 -c2 -W2 $A_V6" >/dev/null 2>&1; then
  pass "srv-b still reaches srv-a over IPv6 after the cycle"
else
  fail "srv-b cannot reach srv-a over IPv6 after the cycle"
fi
# `ray status` must report the address the interface actually holds: the check
# above reads the link, this one reads what a user would be told to dial.
A_STATUS_V6="$(on "$A" 'ray status --json' 2>/dev/null \
  | jq -r --arg n "$NET" '.networks[] | select(.name==$n) | .my_ipv6')"
[[ "$A_STATUS_V6" == "$A_V6" ]] \
  && pass "srv-a's 'ray status' reports the address on its TUN" \
  || fail "srv-a's 'ray status' address disagrees with its TUN ($A_V6)"

# ---------------------------------------------------------------------------
summary
