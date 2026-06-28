#!/usr/bin/env bash
# Rayfish reliability (packet-loss) end-to-end test.
#
# Topology:
#   srv-a  coordinator of an OPEN network "reli"
#   srv-b, srv-c, srv-d  join with the room id (open net = no invite needed)
#
# Open networks form a full mesh: once everyone has joined, every pair holds a
# direct QUIC connection. We then probe every unordered pair in BOTH directions,
# over two paths:
#   - direct   : the host's PUBLIC IP (raw Scaleway link, the baseline)
#   - rayfish  : the peer's 100.64.x.x TUN IP (iroh QUIC datagrams over the VPN)
#
# Three probes per direction, each run over both paths:
#   - ICMP burst : ping -c $PING_COUNT  -i 0.01      (100 pps)
#   - ICMP flood : ping -f -c $FLOOD_COUNT           (as fast as the link allows)
#   - iperf3 UDP : iperf3 -u -b $RATE -t $DURATION   (lost_packets / packets)
#
# rayfish carries datagrams unreliably (no retransmit), so any loss it ADDS on
# top of the raw link points at the protocol (congestion control, MTU, relay
# fallback, reader backpressure). To avoid blaming rayfish for genuine internet
# drops, a probe FAILs only when the rayfish-path loss exceeds the direct-path
# loss by more than $MARGIN percentage points; direct loss is always reported.
#
# Reads tests/e2e/reliability/.servers (written by provision.sh). Does NOT modify
# infra. Re-runnable (resets rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
NET=reli

RATE="${RATE:-50M}"             # iperf3 UDP target bitrate
DURATION="${DURATION:-10}"      # iperf3 seconds per run
PING_COUNT="${PING_COUNT:-1000}"   # ICMP burst packets at 0.01s interval
FLOOD_COUNT="${FLOOD_COUNT:-10000}" # ICMP flood packets
MARGIN="${MARGIN:-0.5}"         # rayfish loss may exceed direct by this many pp

# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run $DIR/provision.sh first"; exit 1; }

# Resolve the four hosts' public (SSH) IPs from .servers. Parallel indexed
# arrays (not associative) to stay bash-3.2 friendly like the rest of the suite:
# HOSTS[i] / PUBS[i] / VPNS[i] line up by index.
HOSTS=(srv-a srv-b srv-c srv-d)
PUBS=(); VPNS=()
for L in "${HOSTS[@]}"; do
  ip="$(server_ip "$SERVERS" "$L" || true)"
  [[ -n "$ip" ]] || { echo "missing $L in $SERVERS"; exit 1; }
  PUBS+=("$ip"); VPNS+=("")
done

# ---------------------------------------------------------------------------
# Loss probes. Each echoes a single packet-loss percentage (a number, possibly
# fractional), or "" if the run failed to produce one.
# ---------------------------------------------------------------------------

# ping_loss_n <from-pub-ip> <target-ip> <count> <interval> : ICMP loss %.
ping_loss_n(){
  on "$1" "ping -c $3 -i $4 -W 2 $2" 2>/dev/null \
    | grep -oE '[0-9.]+% packet loss' | grep -oE '^[0-9.]+'
}

# ping_flood <from-pub-ip> <target-ip> <count> : ICMP flood loss % (needs root).
ping_flood(){
  on "$1" "ping -f -c $3 -W 2 $2" 2>/dev/null \
    | grep -oE '[0-9.]+% packet loss' | grep -oE '^[0-9.]+'
}

# iperf_udp_loss <client-pub-ip> <listen-ip> <server-pub-ip> : UDP loss %.
# listen-ip selects which interface the server binds (public vs TUN) and which
# address the client targets, so the datagrams ride the chosen path.
iperf_udp_loss(){
  local client="$1" listen="$2" server="$3"
  on "$server" "systemctl stop ipsrv 2>/dev/null; systemctl reset-failed ipsrv 2>/dev/null; systemd-run --unit=ipsrv --quiet iperf3 -s -p 5201 -B $listen; sleep 1"
  local json; json="$(on "$client" "iperf3 -c $listen -p 5201 -u -b $RATE -t $DURATION -J" 2>/dev/null)"
  on "$server" "systemctl stop ipsrv 2>/dev/null; systemctl reset-failed ipsrv 2>/dev/null" || true
  echo "$json" | jq -r '(.end.sum.lost_percent // empty)' 2>/dev/null
}

# worse_by_margin <rayfish-loss> <direct-loss> : exit 0 if rayfish exceeds direct
# by more than $MARGIN percentage points (treats empty rayfish loss as a failure
# to measure -> worse; empty direct as 0).
worse_by_margin(){
  local r="$1" d="$2"
  [[ -n "$r" ]] || return 0
  [[ -n "$d" ]] || d=0
  awk -v r="$r" -v d="$d" -v m="$MARGIN" 'BEGIN{exit !(r > d + m)}'
}

# assert_loss <label> <rayfish-loss> <direct-loss> : PASS/FAIL by the margin rule.
assert_loss(){
  local label="$1" r="$2" d="$3"
  if worse_by_margin "$r" "$d"; then
    fail "$label  rayfish=${r:-?}%  direct=${d:-?}%  (> direct + ${MARGIN}pp)"
  else
    pass "$label  rayfish=${r:-?}%  direct=${d:-?}%"
  fi
}

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all hosts"
wait_all_ssh "${PUBS[@]}"
seed_known_hosts "${PUBS[@]}"
reset_state "${PUBS[@]}"
deploy_all "$ROOT" "${PUBS[@]}"
step "0b. install iperf3 on all hosts"
for i in "${!HOSTS[@]}"; do
  on "${PUBS[$i]}" 'command -v iperf3 >/dev/null || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 >/dev/null)' \
    && echo "   iperf3 ready on ${HOSTS[$i]}"
done
wait_daemons "${PUBS[@]}"

# ---------------------------------------------------------------------------
step "1. srv-a creates OPEN network '$NET'; srv-b/c/d join"
A_PUB="${PUBS[0]}"
CREATE="$(on "$A_PUB" "ray create --open --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   a| /'
ROOM="$(echo "$CREATE" | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1)"
[[ -n "$ROOM" ]] || ROOM="$(on "$A_PUB" 'ray status' | strip | sed -n 's/.*\([A-Za-z0-9]\{40,\}\).*/\1/p' | head -1)"
[[ -n "$ROOM" ]] && pass "network '$NET' created (room ${ROOM:0:12}…)" || { fail "no room id"; summary; }

# Join without --name so the joiner keeps the coordinator's network name
# ($NET); --hostname sets the roster/DNS identity. (--name would locally rename
# the network and break `my_ip4 <ip> $NET` lookups below.)
for i in 1 2 3; do
  L="${HOSTS[$i]}"
  on "${PUBS[$i]}" "ray join $ROOM --hostname $L" 2>&1 | strip | sed "s/^/   ${L#srv-}| /"
done

# ---------------------------------------------------------------------------
step "2. wait for full-mesh roster convergence (every node sees the other 3)"
for i in "${!HOSTS[@]}"; do
  others=(); for P in "${HOSTS[@]}"; do [[ "$P" != "${HOSTS[$i]}" ]] && others+=("$P"); done
  wait_roster "${PUBS[$i]}" "${others[@]}"
done

# Resolve every node's own VPN IPv4 (the address peers reach it at over the TUN).
for i in "${!HOSTS[@]}"; do
  VPNS[$i]="$(my_ip4 "${PUBS[$i]}" "$NET")"
  echo "   ${HOSTS[$i]}  public=${PUBS[$i]}  vpn=${VPNS[$i]}"
  [[ -n "${VPNS[$i]}" ]] || { fail "could not resolve VPN ip for ${HOSTS[$i]}"; summary; }
done

# ---------------------------------------------------------------------------
# Probe every unordered pair in both directions. Results also land in a report.
RESDIR="$DIR/results"; mkdir -p "$RESDIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
RAW="$RESDIR/$STAMP.raw"; : > "$RAW"   # rows: from<TAB>to<TAB>probe<TAB>rayfish<TAB>direct

# probe_pair <from-idx> <to-idx> : run all three probes both paths, assert, record.
probe_pair(){
  local fi="$1" ti="$2"
  local from="${HOSTS[$fi]}" to="${HOSTS[$ti]}"
  local fp="${PUBS[$fi]}" tp="${PUBS[$ti]}" tv="${VPNS[$ti]}"

  local r d
  r="$(ping_loss_n "$fp" "$tv" "$PING_COUNT" 0.01)"; d="$(ping_loss_n "$fp" "$tp" "$PING_COUNT" 0.01)"
  assert_loss "$from→$to  icmp  (-c $PING_COUNT -i 0.01)" "$r" "$d"
  printf '%s\t%s\ticmp\t%s\t%s\n' "$from" "$to" "${r:-?}" "${d:-?}" >> "$RAW"

  r="$(ping_flood "$fp" "$tv" "$FLOOD_COUNT")"; d="$(ping_flood "$fp" "$tp" "$FLOOD_COUNT")"
  assert_loss "$from→$to  flood (-f -c $FLOOD_COUNT)" "$r" "$d"
  printf '%s\t%s\tflood\t%s\t%s\n' "$from" "$to" "${r:-?}" "${d:-?}" >> "$RAW"

  r="$(iperf_udp_loss "$fp" "$tv" "$tp")"; d="$(iperf_udp_loss "$fp" "$tp" "$tp")"
  assert_loss "$from→$to  iperf-udp (-b $RATE -t ${DURATION}s)" "$r" "$d"
  printf '%s\t%s\tudp\t%s\t%s\n' "$from" "$to" "${r:-?}" "${d:-?}" >> "$RAW"
}

step "3. packet-loss probes over every mesh pair (rayfish vs direct baseline)"
for i in "${!HOSTS[@]}"; do
  for ((j=i+1; j<${#HOSTS[@]}; j++)); do
    echo "   -- pair ${HOSTS[$i]} <-> ${HOSTS[$j]} --"
    probe_pair "$i" "$j"
    probe_pair "$j" "$i"
  done
done

# ---------------------------------------------------------------------------
step "report"
REPORT="$RESDIR/$STAMP.md"
{
  echo "# Rayfish reliability — $STAMP"
  echo
  echo "Four Scaleway instances, OPEN network full mesh."
  echo "Loss % per probe; a probe fails when rayfish exceeds direct by > ${MARGIN}pp."
  echo "icmp = ping -c $PING_COUNT -i 0.01; flood = ping -f -c $FLOOD_COUNT; udp = iperf3 -u -b $RATE -t ${DURATION}s."
  echo
  printf '| From | To | Probe | Rayfish loss | Direct loss |\n'
  printf '|---|---|---|---:|---:|\n'
  while IFS=$'\t' read -r f t p r d; do
    printf '| %s | %s | %s | %s%% | %s%% |\n' "$f" "$t" "$p" "$r" "$d"
  done < "$RAW"
} | tee "$REPORT"

echo
echo "Saved: $REPORT"
echo "Raw:   $RAW"

# ---------------------------------------------------------------------------
summary
