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
#   - `ray exit-node allow` turns srv-a into a gateway: forwarding sysctls go on
#     and the nftables masquerade table appears;
#   - the offer rides the signed roster, so srv-b/srv-c discover it (`exit-node
#     status` lists it, `ray status` flags the peer);
#   - `ray exit-node use` actually re-routes egress: srv-b's public IP as seen by
#     an external echo service becomes srv-a's (IPv4, and IPv6 where available);
#   - THE LOOP PREVENTION HOLDS: with 0.0.0.0/0 pointed into the TUN, iroh's own
#     underlay UDP still egresses (SO_MARK + the fwmark ip rule), so the mesh
#     connection survives. Without it the tunnel deadlocks and everything dies;
#     this is the single assertion the whole SO_MARK fork chain exists for;
#   - mesh traffic still flows under the full tunnel (peers stay pingable);
#   - INBOUND CONNECTIONS SURVIVE: our own SSH session to the client's public IP
#     keeps working under the full tunnel. Naively it would not: sshd's replies
#     would follow the default route into the tunnel and come out NATed as the exit
#     node's address, so a headless box would lock itself out the instant you ran
#     `exit-node use`. The conntrack-mark rules keep connections that arrived from
#     outside the tunnel answering out the interface they came in on;
#   - a NON-allowed peer (srv-c) selecting the same exit gets dropped: no egress
#     via the gateway AND no leak out its own uplink;
#   - teardown restores everything: `exit-node none` reverts egress and removes the
#     ip rules; `ray down` on the gateway removes the nft table and the sysctls.
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
# Captured before the allow: the gateway must not turn IPv4 forwarding on, so the
# assertion is "unchanged", not "off". A box with Docker on it already has this at
# 1 for its own reasons and that is none of our business either way.
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
# The half that must NOT happen, and the gateway twin of step 4's client check.
# The overlay routes no IPv4, so nothing can enter the TUN from 100.64.0.0/10 to
# be masqueraded: a v4 masquerade rule could only ever catch a co-resident VPN's
# traffic, and turning ip_forward on would make the host a router for a family we
# cannot deliver. Both are ours to not do.
[[ "$(on "$A" 'cat /proc/sys/net/ipv4/ip_forward')" == "$A_IP4FWD_BEFORE" ]] \
  && pass "srv-a: IPv4 forwarding left as it was ($A_IP4FWD_BEFORE)" \
  || fail "srv-a: offering an exit node changed ip_forward to $(on "$A" 'cat /proc/sys/net/ipv4/ip_forward') (it carries no IPv4)"
on "$A" 'nft list table inet rayfish_exit 2>/dev/null | grep -q "ip saddr"' \
  && fail "srv-a installed an IPv4 masquerade rule: it claims a range that is not ours" \
  || pass "srv-a: no IPv4 masquerade rule (100.64.0.0/10 is left to whoever owns it)"

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
# Both steps need a tunnel to exist, and the gateway is what decides whether one
# can: with no IPv6 uplink on srv-a the selection is refused and there is nothing
# to measure. Skipped rather than fatal, the same way step 6 treats it, so a fleet
# without IPv6 still runs the steps that never needed it (7 and 8).
b_v6_available(){
  exit_json "$B" | jq -r --arg n "$NET" \
    '.networks[] | select(.network==$n) | .available_v6[]' 2>/dev/null | grep -c srv-a
}
if [[ -z "$A_PUB_V6" ]]; then
  # Not a skip: this is the *other* branch of `Member.exit_families`, and it has
  # assertions of its own. A gateway with no IPv6 uplink can carry nothing at all
  # now that the overlay routes no IPv4, so it must say so on the roster and the
  # client must refuse it by name rather than install a tunnel with nowhere to send.
  step "4-5. srv-a has no IPv6 uplink: the selection must be refused, with the reason"
  retry_until 90 "[[ \"\$(b_v6_available)\" == '0' ]]" \
    && pass "srv-a is not listed as carrying IPv6 (it has no v6 uplink)" \
    || fail "srv-a claims IPv6 egress it does not have"
  REFUSE_OUT="$(on "$B" "ray exit-node use $NET srv-a" 2>&1)"; REFUSE_RC=$?
  printf '%s\n' "$REFUSE_OUT" | strip | sed 's/^/   b| /'
  # The whole point of the field: name the reason now, rather than install a
  # tunnel whose traffic the gateway has nowhere to send.
  printf '%s\n' "$REFUSE_OUT" | grep -q 'cannot carry IPv6' \
    && pass "selecting a gateway with no IPv6 uplink is refused, with the reason" \
    || fail "srv-b accepted a gateway that cannot carry its only family"
  [[ $REFUSE_RC -ne 0 && $REFUSE_RC -ne 255 ]] \
    && pass "the refusal exits non-zero (rc=$REFUSE_RC)" \
    || fail "\`exit-node use\` reported success (rc=$REFUSE_RC) on a gateway it refused"
  on "$B" "ray exit-node none $NET" >/dev/null 2>&1
else
  retry_until 90 "[[ \"\$(b_v6_available)\" == '1' ]]" \
    && pass "srv-a is listed as carrying IPv6 in srv-b's exit-node status" \
    || fail "srv-a has an IPv6 uplink but is not advertised as carrying IPv6"
  # Stand in for a co-resident VPN: a route in a table of its own, reached by a
  # rule far below ours. Our catch-all would swallow it (PREF_MAIN's
  # suppress_prefixlength only rescues routes in `main`), so the install has to
  # copy it into the tunnel table first or that VPN goes dark. Set up before the
  # selection, because the copy happens at install time.
  FOREIGN_NET="fd7a:115c:a1e0::/48"
  on "$B" "ip -6 route replace $FOREIGN_NET dev lo table 52; ip -6 rule add pref 5250 table 52" >/dev/null 2>&1
  step "4. srv-b tunnels IPv6 through srv-a and leaves its IPv4 egress alone"
  arm_failsafe "$B" 240
  use_started=$SECONDS
  USE_OUT="$(on "$B" "ray exit-node use $NET srv-a" 2>&1)"; USE_RC=$?
  use_took=$((SECONDS - use_started))
  printf '%s\n' "$USE_OUT" | strip | sed 's/^/   b| /'
  # A refusal here is silent in the assertions below: with no tunnel installed they
  # all read a host egressing directly and blame the part that did not run. The
  # common cause is a gateway with no IPv6 uplink, which the CLI names.
  #
  # Revert before disarming, and in that order: `disarm_failsafe` only touches the
  # flag file, so disarming a half-installed tunnel takes away the automatic revert
  # without doing one. 255 is ssh itself failing, which is not a refusal.
  if [[ $USE_RC -ne 0 ]]; then
    on "$B" "ray exit-node none $NET" >/dev/null 2>&1
    disarm_failsafe "$B"
    [[ $USE_RC -eq 255 ]] \
      && fail "lost ssh to srv-b running \`exit-node use\` (rc=255): cannot tell what happened" \
      || fail "srv-b's \`exit-node use\` failed (rc=$USE_RC): no tunnel to test"
    summary
  fi
  # The command runs over SSH, and the tunnel comes up underneath that very session.
  # If the conntrack-mark rules do not cover a connection that predates the tunnel,
  # the reply is swallowed and this returns minutes later, after the failsafe has
  # already reverted the host: every assertion below then measures a torn-down
  # tunnel and lies about which part is broken. Time it so that failure names itself.
  [[ $use_took -le 30 ]] \
    && pass "\`exit-node use\` returned promptly (${use_took}s)" \
    || fail "\`exit-node use\` took ${use_took}s: the SSH session running it stalled under the tunnel"
  sleep 8

  # The assertion this whole feature lives or dies on for a headless host: we are
  # still talking to srv-b over its PUBLIC IP while its default route points into the
  # tunnel. Without the conntrack-mark rules, sshd's replies egress via srv-a, come
  # out NATed as srv-a's address, and every command below hangs instead of answering.
  if on "$B" 'true' 2>/dev/null; then
    pass "SSH to srv-b's public IP survived the full tunnel (inbound conns bypass it)"
  else
    fail "srv-b cut off its own SSH under the full tunnel: inbound-connection bypass is broken"
    echo "   (the failsafe will revert srv-b within 240s)"
    summary
  fi

  # The headline, and it is the *opposite* of what a dual-stack tunnel asserted:
  # the mesh carries no IPv4, so a tunnel cannot source IPv4 transit and the host's
  # own IPv4 egress must be left exactly where it was. Tunnelling it would take
  # IPv4 away from whatever else is using this box and send it into a hole.
  B_VIA_EXIT="$(pub4 "$B")"
  echo "   srv-b public IPv4 while tunneled: '$B_VIA_EXIT'  (srv-a=$A_PUB, srv-b own=$B_PUB)"
  if [[ "$B_VIA_EXIT" == "$B_PUB" ]]; then
    pass "srv-b's IPv4 egress is untouched by the tunnel (as it must be)"
  elif [[ "$B_VIA_EXIT" == "$A_PUB" ]]; then
    fail "srv-b's IPv4 egress was hijacked into the tunnel: it has no return path"
  else
    fail "srv-b egressed via an unexpected IPv4 '$B_VIA_EXIT' (wanted its own $B_PUB)"
  fi

  # The loop-prevention assertion. If SO_MARK / the fwmark rule were missing, iroh's
  # own UDP would have looped into the tunnel and the mesh would be dead here.
  if on "$B" "ping -c 3 -W 2 $A_VPN" 2>/dev/null | grep -q "0% packet loss"; then
    pass "mesh still works under the full tunnel (srv-b pinged srv-a's mesh IP)"
  else
    fail "mesh broke under the full tunnel: loop prevention failed (SO_MARK/ip rule)"
  fi
  on "$B" "ip -6 rule show" 2>/dev/null | grep -q "$MARK" \
    && pass "srv-b installed the fwmark bypass rule ($MARK -> main)" \
    || fail "srv-b has no fwmark bypass rule: iroh's transport would loop"
  on "$B" "ip -6 route show table $TABLE" 2>/dev/null | grep -q default \
    && pass "srv-b installed the tunnel default route (table $TABLE)" \
    || fail "srv-b has no default route in the tunnel table"
  # And nothing IPv4 was installed at all: the family the tunnel does not carry
  # must not have rules pointing at a table with no return path.
  on "$B" "ip -4 rule show" 2>/dev/null | grep -q "lookup $TABLE" \
    && fail "srv-b installed an IPv4 tunnel rule: its IPv4 egress is hijacked" \
    || pass "srv-b installed no IPv4 tunnel rule"
  on "$B" 'nft list table inet rayfish_exit_client 2>/dev/null | grep -q "ct mark"' \
    && pass "srv-b installed the conntrack-mark table (inbound connections bypass the tunnel)" \
    || fail "srv-b has no conntrack-mark table: inbound connections would be swallowed"
  # The co-resident VPN's routes survive the tunnel. Our default is a catch-all far
  # above that VPN's own preferences, so without the copy its prefixes go dark.
  on "$B" "ip -6 route show table $TABLE" 2>/dev/null | grep -q "$FOREIGN_NET" \
    && pass "the co-resident VPN's route was mirrored into the tunnel table" \
    || fail "the co-resident VPN's route was not mirrored: our catch-all black-holes it"
  # The mirror is only half of it. PREF_SRC and PREF_BYPASS sit above the catch-all
  # and both look up `main`, where a policy-routing VPN keeps nothing, so traffic
  # sourced from its address still misses. One rule covers every mirrored prefix:
  # `suppress_prefixlength 0` matches the copies and suppresses our own default, so
  # the lookup is its own selector and cannot drift with that VPN's route count.
  on "$B" "ip -6 rule show" 2>/dev/null | grep -q "lookup $TABLE suppress_prefixlength 0" \
    && pass "the co-resident VPN's destinations are routed to the mirrored copy" \
    || fail "no pref-98 rule: traffic sourced from that VPN's own address is black-holed"
  # Sourced from the foreign address, which is the case the mirror alone misses:
  # this is what an inbound session's replies look like.
  B_FOREIGN_SRC="$(on "$B" "ip -6 addr show scope global | awk '/inet6/{print \$2}' | cut -d/ -f1 | head -1")"
  if [[ -n "$B_FOREIGN_SRC" ]]; then
    on "$B" "ip -6 route get ${FOREIGN_NET%%/*}1 from $B_FOREIGN_SRC" 2>/dev/null | grep -q "table $TABLE\|dev lo" \
      && pass "traffic sourced from the co-resident VPN's address still reaches it" \
      || fail "traffic sourced from that VPN's address takes the physical default (an inbound session over it would die)"
  else
    fail "could not read srv-b's global IPv6: the foreign-source route check did not run"
  fi
  # DNS still resolves under the tunnel. Deliberately not asserting *where* the
  # query went: on a split-DNS backend only `.ray` reaches our forwarder, so
  # non-mesh lookups leave over the host's own IPv4 by design (the daemon warns
  # about it on Linux). What must not happen is losing name resolution.
  on "$B" "getent hosts example.com" >/dev/null 2>&1 \
    && pass "non-mesh DNS still resolves under the tunnel" \
    || fail "DNS broke under the tunnel"
  # `.ray` is the half that does go through our resolver in every backend.
  on "$B" "getent hosts srv-a.ray" >/dev/null 2>&1 \
    && pass "'.ray' names still resolve under the tunnel" \
    || fail "'.ray' resolution broke under the tunnel"
  # The exit column now names srv-a as the peer carrying our traffic, not just one
  # offering to (it read `offers` in step 3, before we selected it).
  on "$B" "ray status" | strip | grep -q 'srv-a.*in use' \
    && pass "ray status marks srv-a 'in use' in the exit column" \
    || fail "ray status does not mark srv-a as the exit node in use"

  # IPv6 is the family the tunnel actually carries, and the one assertion that
  # says the feature works at all. Still conditional, because not every instance
  # or zone has working v6 egress to tunnel in the first place.
  # srv-a's IPv6 is a given inside this branch; srv-b still needs its own to have
  # had anything to send.
  if [[ -n "$B_PUB_V6" ]]; then
    B_V6="$(pub6 "$B")"
    [[ "$B_V6" == "$A_PUB_V6" ]] \
      && pass "srv-b's IPv6 traffic egressed via srv-a ($B_V6): the exit node works" \
      || fail "srv-b IPv6 egressed via '$B_V6', wanted srv-a's '$A_PUB_V6'"
  else
    echo "   (srv-b has no IPv6 egress: the tunnel has nothing to carry)"
  fi

  # ---------------------------------------------------------------------------
  step "5. egress reverts after 'ray exit-node none'"
  # Asserted over IPv6, the family the tunnel carried. IPv4 never entered it, so a
  # v4 probe here would pass whether teardown worked or not.
  on "$B" "ray exit-node none $NET" 2>&1 | strip | sed 's/^/   b| /'
  disarm_failsafe "$B"
  if [[ -n "$B_PUB_V6" ]]; then
    if retry_until 60 "[[ \"\$(pub6 '$B')\" == '$B_PUB_V6' ]]"; then
      pass "srv-b egresses via its own IPv6 uplink again ($B_PUB_V6)"
    else
      fail "srv-b did not revert to direct IPv6 egress (got '$(pub6 "$B")')"
    fi
  else
    echo "   (srv-b has no IPv6 egress: nothing was tunnelled, nothing to revert)"
  fi
  on "$B" "ip -6 rule show" | grep -q "$MARK" \
    && fail "srv-b's fwmark rule survived 'exit-node none' (policy routing not torn down)" \
    || pass "srv-b's full-tunnel ip rules were removed"
  on "$B" 'nft list table inet rayfish_exit_client' >/dev/null 2>&1 \
    && fail "srv-b's conntrack-mark table survived 'exit-node none'" \
    || pass "srv-b's conntrack-mark table was removed"

fi

# ---------------------------------------------------------------------------
step "6. deny path: srv-c is NOT allowed: its traffic is dropped, not leaked"
# srv-c can still *select* srv-a (the blob advertises the offer), but srv-a's
# allow-list has only srv-b, so the gateway drops srv-c's packets. The critical
# property: srv-c must not reach the internet via srv-a AND must not silently fall
# back to its own uplink (that would be a leak the user never asked for).
# Probed over IPv6: that is the family the tunnel takes, so it is the only one
# whose fate the allow-list decides. srv-c's IPv4 keeps leaving directly either
# way, and reading it here would report a leak that is simply the design.
#
# Both ends have to have IPv6 for the probe to mean anything, and srv-a's is the
# one that is easy to forget: with no IPv6 uplink on the gateway the selection is
# refused outright, srv-c egresses directly, and the last branch below reports a
# leak that is really a skipped test.
if [[ -z "$A_PUB_V6" || -z "$C_PUB_V6" ]]; then
  [[ -z "$A_PUB_V6" ]] && WHO=srv-a || WHO=srv-c
  echo "   (no IPv6 egress on $WHO: the deny path has nothing to carry, skipping)"
else
  arm_failsafe "$C" 180
  # Same as step 4: `ray exit-node use` exits non-zero on a refusal, and a refused
  # selection installs no tunnel. Reading the probe below without checking this
  # reports srv-c's untouched direct egress as a LEAK, which is a security-shaped
  # message for a test that never ran. srv-a can narrow its claim between step 4
  # and here without anybody touching the selection.
  C_USE_OUT="$(on "$C" "ray exit-node use $NET srv-a" 2>&1)"; C_USE_RC=$?
  printf '%s\n' "$C_USE_OUT" | strip | sed 's/^/   c| /'
  if [[ $C_USE_RC -ne 0 ]]; then
    on "$C" "ray exit-node none $NET" >/dev/null 2>&1
    disarm_failsafe "$C"
    [[ $C_USE_RC -eq 255 ]] \
      && fail "lost ssh to srv-c running \`exit-node use\` (rc=255): cannot tell what happened" \
      || fail "srv-c's \`exit-node use\` was refused (rc=$C_USE_RC): the deny path never ran"
    summary
  fi
  sleep 5
  C_VIA_EXIT="$(pub6 "$C")"
  on "$C" "ray exit-node none $NET" >/dev/null 2>&1
  disarm_failsafe "$C"
  if [[ -z "$C_VIA_EXIT" ]]; then
    pass "srv-c got no internet through srv-a (dropped by the allow-list, no leak)"
  elif [[ "$C_VIA_EXIT" == "$A_PUB_V6" ]]; then
    fail "SECURITY: srv-c routed through srv-a despite not being on the allow-list"
  else
    fail "LEAK: srv-c's traffic escaped via '$C_VIA_EXIT' instead of being dropped"
  fi
fi

# ---------------------------------------------------------------------------
step "7. gateway teardown: 'ray down' removes forwarding + NAT"
on "$A" 'ray down' 2>&1 | strip | sed 's/^/   a| /'
sleep 3
on "$A" 'nft list table inet rayfish_exit' >/dev/null 2>&1 \
  && fail "srv-a's nft masquerade table survived 'ray down'" \
  || pass "srv-a's nft masquerade table was removed on 'ray down'"
[[ "$(on "$A" 'cat /proc/sys/net/ipv6/conf/all/forwarding')" == "0" ]] \
  && pass "srv-a's IPv6 forwarding sysctl was restored" \
  || fail "srv-a left IPv6 forwarding enabled after 'ray down' (host stays a router)"
# Never touched on the way in, so it must read the same on the way out. Teardown
# still *restores* it from the snapshot, though, because an older build did set it
# and teardown may not assume which build turned it on.
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
A_V6=$(on "$A" "ip -6 addr show dev tun0 scope global | awk '/inet6/{print \$2}' | cut -d/ -f1")
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
