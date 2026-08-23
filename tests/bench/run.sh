#!/usr/bin/env bash
# Rayfish throughput/latency benchmark: direct (public IP) vs rayfish (VPN tunnel).
#
# Topology:
#   srv-a  coordinator of an OPEN network "bench"
#   srv-b  joins it with the room id (open net = no invite needed)
#
# For both directions we measure, over the public IP (DIRECT) and over the
# rayfish 200::/7 TUN address (RAYFISH):
#   - ping RTT (latency)
#   - iperf3 TCP throughput
# so the delta isolates the cost rayfish (iroh QUIC datagrams, MTU 1200,
# encryption, userspace TUN) adds on top of the raw link.
#
# Reads tests/bench/.servers (written by provision.sh). Does NOT modify infra.
# Re-runnable. Results are printed as a table and saved to tests/bench/results/.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
SERVERS="$DIR/.servers"
DURATION="${DURATION:-10}"      # iperf3 seconds per run
ITERATIONS="${ITERATIONS:-3}"   # repeats per measurement; reported value is the mean
# shellcheck source=../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run $DIR/provision.sh first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"; A_PUB="$A"
B="$(server_ip "$SERVERS" srv-b || true)"; B_PUB="$B"
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

# ---------------------------------------------------------------------------
step "0. wait for SSH on both hosts"
wait_all_ssh "$A" "$B"
seed_known_hosts "$A" "$B"
reset_state "$A" "$B"
deploy_all "$ROOT" "$A" "$B"
step "1b. install iperf3 on both hosts"
for h in "$A" "$B"; do
  on "$h" 'command -v iperf3 >/dev/null || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 >/dev/null)' \
    && echo "   iperf3 ready on $h"
done
wait_daemons "$A" "$B"

# ---------------------------------------------------------------------------
step "2. create OPEN network on srv-a, srv-b joins"
NET=bench
CREATE="$(on "$A" "ray create --open --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   | /'
ROOM="$(echo "$CREATE" | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1)"
if [[ -z "$ROOM" ]]; then
  # maybe it already exists; pull the room id from status
  ROOM="$(on "$A" 'ray status' | strip | sed -n 's/.*\([A-Za-z0-9]\{40,\}\).*/\1/p' | head -1)"
fi
[[ -n "$ROOM" ]] && pass "network '$NET' created (room ${ROOM:0:12}…)" || { fail "no room id"; exit 1; }

on "$B" "ray join $ROOM --name srv-b --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'

# ---------------------------------------------------------------------------
step "3. wait for roster convergence"
converged=0
for _ in $(seq 1 24); do  # up to ~120s
  SA="$(on "$A" 'ray status' | strip)"
  if echo "$SA" | grep -q 'srv-b\.'; then converged=1; break; fi
  sleep 5
done
SA="$(on "$A" 'ray status' | strip)"; SB="$(on "$B" 'ray status' | strip)"
echo "---- srv-a status ----"; echo "$SA" | sed 's/^/   a| /'
echo "---- srv-b status ----"; echo "$SB" | sed 's/^/   b| /'
[[ "$converged" == 1 ]] && pass "roster converged (srv-a sees srv-b)" || fail "roster did not converge"

# own_ip comes from common.sh.
A_VPN="$(own_ip "$SA")"; B_VPN="$(own_ip "$SB")"
echo "   A_VPN=$A_VPN  B_VPN=$B_VPN"
[[ -n "$A_VPN" && -n "$B_VPN" ]] || { fail "could not resolve both VPN IPs"; exit 1; }

# sanity: both paths reachable before benchmarking
on "$A" "ping -c 2 -W 2 $B_PUB" >/dev/null 2>&1 && pass "direct path up (A->B public)" || fail "direct path down"
on "$A" "ping -c 2 -W 2 $B_VPN"  >/dev/null 2>&1 && pass "rayfish path up (A->B vpn)"  || fail "rayfish path down"

# ---------------------------------------------------------------------------
# Benchmark helpers.
RESDIR="$DIR/results"; mkdir -p "$RESDIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
RAW="$RESDIR/$STAMP.raw"; : > "$RAW"

# ping_rtt <from-ip> <target-ip> -> avg RTT in ms (mean of 20 pings)
ping_rtt(){
  local out; out="$(on "$1" "ping -c 20 -i 0.2 -W 2 $2" 2>/dev/null)"
  # rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
  echo "$out" | sed -n 's#.*= [0-9.]*/\([0-9.]*\)/.*#\1#p' | head -1
}

# tcp_bw <client-ip> <server-listen-ip> <server-host-ip> [reverse] -> Mbit/s
# server-listen-ip: address iperf3 -s binds to (so we pick public vs vpn iface)
# server-host-ip:   ssh target to start the server on
tcp_bw(){
  local client="$1" listen="$2" server_host="$3" reverse="${4:-}"
  # Run the server as a transient systemd unit so it survives the ssh session
  # closing (a plain backgrounded `iperf3 -s` gets SIGHUP'd and the client then
  # fails with "unable to send control message: Bad file descriptor").
  on "$server_host" "systemctl stop ipsrv 2>/dev/null; systemctl reset-failed ipsrv 2>/dev/null; systemd-run --unit=ipsrv --quiet iperf3 -s -p 5201 -B $listen; sleep 1"
  local rflag=""; [[ "$reverse" == "reverse" ]] && rflag="-R"
  local json; json="$(on "$client" "iperf3 -c $listen -p 5201 -t $DURATION -J $rflag" 2>/dev/null)"
  on "$server_host" "systemctl stop ipsrv 2>/dev/null; systemctl reset-failed ipsrv 2>/dev/null" || true
  # bits_per_second from the summed received interval
  echo "$json" | jq -r '(.end.sum_received.bits_per_second // .end.sum.bits_per_second // 0) / 1000000 | floor' 2>/dev/null
}

# Results live in $RAW as TAB-separated rows: dir<TAB>path<TAB>rtt<TAB>tx<TAB>rx.
# Portable to bash 3.2 (macOS) — no associative arrays.
get(){ # get <dir> <path> <col 3=rtt|4=tx|5=rx>
  awk -F'\t' -v d="$1" -v p="$2" -v c="$3" '$1==d && $2==p {print $c; exit}' "$RAW"
}

# mean of the numeric args (ignores empty/non-numeric), 2 decimals; "?" if none.
mean(){ printf '%s\n' "$@" | awk '/^[0-9.]+$/{s+=$1;n++} END{if(n)printf "%.2f",s/n; else printf "?"}'; }

bench_pair(){ # bench_pair <dir-label> <client-ip> <listen-ip> <server-host> <path>
  local dir="$1" client="$2" listen="$3" server_host="$4" path="$5"
  local rtts=() bws=() bwrs=() i
  for i in $(seq 1 "$ITERATIONS"); do
    printf '\r   %-22s %-8s iter %d/%d ...        ' "$dir" "$path" "$i" "$ITERATIONS"
    rtts+=("$(ping_rtt "$client" "$listen")")
    bws+=("$(tcp_bw "$client" "$listen" "$server_host")")
    bwrs+=("$(tcp_bw "$client" "$listen" "$server_host" reverse)")
  done
  local rtt bw bwr
  rtt="$(mean "${rtts[@]}")"; bw="$(mean "${bws[@]}")"; bwr="$(mean "${bwrs[@]}")"
  printf '\r   %-22s %-8s rtt=%-7s tx=%-6s rx=%-6s (mean of %d)\n' "$dir" "$path" "${rtt}ms" "${bw}M" "${bwr}M" "$ITERATIONS"
  printf '%s\t%s\t%s\t%s\t%s\n' "$dir" "$path" "$rtt" "$bw" "$bwr" >> "$RAW"
}

# ---------------------------------------------------------------------------
step "4. benchmark  A -> B"
bench_pair "A -> B" "$A" "$B_PUB" "$B" "direct"
bench_pair "A -> B" "$A" "$B_VPN" "$B" "rayfish"

step "5. benchmark  B -> A"
bench_pair "B -> A" "$B" "$A_PUB" "$A" "direct"
bench_pair "B -> A" "$B" "$A_VPN" "$A" "rayfish"

# ---------------------------------------------------------------------------
step "results"
ratio(){ # ratio <rayfish> <direct> -> percentage of direct
  local r="$1" d="$2"
  [[ "$r" =~ ^[0-9.]+$ && "$d" =~ ^[0-9.]+$ && "$d" != 0 ]] || { echo "—"; return; }
  awk -v r="$r" -v d="$d" 'BEGIN{printf "%.0f%%", (r/d)*100}'
}
overhead(){ # latency overhead in ms
  local r="$1" d="$2"
  [[ "$r" =~ ^[0-9.]+$ && "$d" =~ ^[0-9.]+$ ]] || { echo "—"; return; }
  awk -v r="$r" -v d="$d" 'BEGIN{printf "+%.2fms", r-d}'
}

REPORT="$RESDIR/$STAMP.md"
{
  echo "# Rayfish benchmark — $STAMP"
  echo
  echo "Two droplets in region $(awk 'NR==1{print $4}' "$SERVERS"), same region."
  echo "iperf3 TCP, ${DURATION}s/run, mean of ${ITERATIONS} iterations; ping = mean RTT over 20 packets."
  echo "tx = client→server, rx = server→client (iperf3 -R)."
  echo
  printf '| Direction | Metric | Direct | Rayfish | Rayfish/Direct |\n'
  printf '|---|---|---:|---:|---:|\n'
  for dir in "A -> B" "B -> A"; do
    printf '| %s | RTT (ms) | %s | %s | %s |\n' "$dir" "$(get "$dir" direct 3)" "$(get "$dir" rayfish 3)" "$(overhead "$(get "$dir" rayfish 3)" "$(get "$dir" direct 3)")"
    printf '| %s | TCP tx (Mbit/s) | %s | %s | %s |\n' "$dir" "$(get "$dir" direct 4)" "$(get "$dir" rayfish 4)" "$(ratio "$(get "$dir" rayfish 4)" "$(get "$dir" direct 4)")"
    printf '| %s | TCP rx (Mbit/s) | %s | %s | %s |\n' "$dir" "$(get "$dir" direct 5)" "$(get "$dir" rayfish 5)" "$(ratio "$(get "$dir" rayfish 5)" "$(get "$dir" direct 5)")"
  done
} | tee "$REPORT"

echo
echo "Saved: $REPORT"
echo "Raw:   $RAW"
echo
echo "Tear down with: tests/bench/teardown.sh"
