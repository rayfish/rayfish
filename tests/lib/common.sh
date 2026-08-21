# Shared helpers for the rayfish e2e / benchmark test orchestrators.
# Sourced (not executed) by each scenario's run.sh after it sets DIR/ROOT/SERVERS.
# Provides SSH plumbing, PASS/FAIL accounting, and host-lifecycle helpers
# (wait-for-ssh, state reset, deploy, daemon-up) so the run.sh scripts contain
# only their scenario-specific steps.

KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=10 -o LogLevel=ERROR -o BatchMode=yes)

# PASS/FAIL accounting. FAILS is read by summary().
FAILS=0
pass(){ printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
# Same complaint, on stderr and without the tally. For helpers whose every caller
# reads them through `$(...)`: on stdout the message is captured into the command
# line the caller is building instead of leaving it empty, so the caller's own
# `[[ -n ... ]]` guard passes and every probe below runs against garbage. The
# increment is dropped for the same reason (it would happen in the subshell), so
# these helpers `return 1` and the caller counts the failure.
fail_out(){ printf '  \033[31mFAIL\033[0m %s\n' "$*" >&2; }
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# summary : print the final tally and exit non-zero if any check failed.
summary(){
  step "summary"
  if [[ "$FAILS" -eq 0 ]]; then
    printf '\033[32mALL CHECKS PASSED\033[0m\n'; exit 0
  else
    printf '\033[31m%d CHECK(S) FAILED\033[0m\n' "$FAILS"; exit 1
  fi
}

# on <ip> <command-string> : run a shell command on a host as root.
# -n: never read stdin, so calling `on` inside a `while read` loop can't eat it.
on(){ local ip="$1"; shift
  [[ -n "${E2E_TRACE:-}" ]] && echo "$(date -u +%T) -> $ip: $*" >> "$E2E_TRACE"
  ssh -n "${SSH_OPTS[@]}" -i "$KEY" "root@$ip" "$*"
  local rc=$?
  [[ -n "${E2E_TRACE:-}" ]] && echo "$(date -u +%T) <- $ip rc=$rc" >> "$E2E_TRACE"
  return $rc
}

# strip : remove ANSI colour codes from rayfish CLI output (stdin -> stdout).
strip(){ sed -r 's/\x1B\[[0-9;]*[mGKH]//g'; }

# own_ip <status-text> : extract a node's own mesh IPv6 (the 200::/7 range).
# The prefix is /7, so only the first seven bits are fixed and the leading hextet
# runs from 200 to 2ff: matching a literal `200:` finds 1 address in 256, which is
# how this read as "no mesh IPv6" against real output.
# Loud when there is none: every caller uses the result as a ping/ssh target, and
# an empty string there turns a real failure into a test that passes. See
# `fail_out` for why the complaint goes to stderr.
own_ip(){
  local ip; ip="$(echo "$1" | grep -oE '\b2[0-9a-f]{2}:[0-9a-f:]+' | head -1)"
  [[ -n "$ip" ]] || { fail_out "own_ip: no mesh IPv6 in status output"; return 1; }
  echo "$ip"
}

# peer_host <status-text> : first peer row's `<host>.<net>.ray` hostname label.
# peer_host <status-text> : the first peer row's hostname. Peer rows carry a
# status dot (●/○) and a mesh IP; the hostname is the token right after the dot.
# (The status peer row prints the bare hostname, not the `.ray` FQDN.)
peer_host(){ echo "$1" | sed 's/\x1b\[[0-9;]*m//g' | awk '/[●○]/ && /2[0-9a-f][0-9a-f]:/ {for(i=1;i<=NF;i++) if($i=="●"||$i=="○"){print $(i+1); exit}}'; }

# ping_loss <from-ip> <target-ip> : echo the packet-loss percentage (number only).
ping_loss(){ on "$1" "ping -c 3 -W 2 $2" 2>&1 | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+'; }

# png <from-ip> <target-ip> <label> : PASS if 0% loss, FAIL otherwise.
png(){
  local loss; loss="$(ping_loss "$1" "$2")"
  if [[ "${loss:-100}" == "0" ]]; then pass "ping $3"; else fail "ping $3 (loss=${loss:-?}%)"; fi
}

# server_ip <servers-file> <label> : echo the public ip for a label in a
# `id ip label zone` .servers file. Avoids bash-3.2 associative arrays.
server_ip(){
  local f="$1" want="$2" id ip label zone
  while read -r id ip label zone; do
    [[ "${label:-}" == "$want" ]] && { echo "$ip"; return 0; }
  done < "$f"
  return 1
}

# wait_all_ssh <ip...> : block until every host accepts SSH; abort on timeout.
wait_all_ssh(){
  local ip
  for ip in "$@"; do
    local ok=0 _
    for _ in $(seq 1 60); do on "$ip" true 2>/dev/null && { ok=1; break; }; sleep 5; done
    if [[ "$ok" == 1 ]]; then pass "ssh reachable ($ip)"; else fail "ssh ($ip) unreachable"; echo "aborting"; exit 1; fi
  done
}

# seed_known_hosts <ip...> : pre-seed ~/.ssh/known_hosts so `just deploy` (which
# uses the default known_hosts) doesn't block on an interactive host-key prompt.
seed_known_hosts(){
  local h
  for h in "$@"; do ssh-keyscan -T 10 "$h" >> ~/.ssh/known_hosts 2>/dev/null || true; done
}

# reset_state <ip...> : clean-slate the daemon (stop + wipe the config tree) so
# runs are reproducible on already-used servers. Set KEEP_STATE=1 to skip.
# Linux config lives in /etc/rayfish; /root/.config/rayfish is the pre-migration
# location (wiped too so an upgraded VM doesn't migrate stale state back in).
reset_state(){
  [[ "${KEEP_STATE:-0}" == "1" ]] && return 0
  step "reset rayfish state on all hosts (KEEP_STATE=1 to skip)"
  local h
  for h in "$@"; do
    on "$h" 'systemctl stop rayfish 2>/dev/null; rm -rf /etc/rayfish /root/.config/rayfish' && echo "   reset $h"
  done
}

# deploy_all <root> <ip...> : cross-build once + rsync + ray up on each host; abort on failure.
deploy_all(){
  local root="$1"; shift
  step "deploy ray to all hosts (cross build once + rsync + ray up)"
  echo ">> just cross"
  if ( cd "$root" && just cross ); then pass "cross build"; else fail "cross build"; echo "aborting"; exit 1; fi
  local ip
  for ip in "$@"; do
    echo ">> just scp $ip"
    if ( cd "$root" && just scp "$ip" ); then pass "deploy $ip"; else fail "deploy $ip"; echo "aborting"; exit 1; fi
  done
}

# wait_daemons <ip...> : give daemons a moment to settle, then confirm `ray status` responds.
wait_daemons(){
  sleep 5
  local ip
  for ip in "$@"; do
    if on "$ip" 'ray status' >/dev/null 2>&1; then pass "daemon up on $ip"; else fail "daemon not responding on $ip"; fi
  done
}

# ---------------------------------------------------------------------------
# JSON-backed status helpers. Every `ray` subcommand takes a global `--json`
# flag (color/spinners off, machine-readable). We run it on the remote host and
# parse the JSON *locally* with jq, so assertions don't scrape coloured tables.
# jq is already a provisioning prerequisite (see tests/e2e/README.md).
# ---------------------------------------------------------------------------

# status_json <ip> : echo `ray status --json` from a host (raw JSON).
status_json(){ on "$1" 'ray status --json' 2>/dev/null; }

# my_ip <ip> [net] : this node's own mesh IPv6, for the named network or the
# first if omitted. Fatal when absent, for the same reason as `own_ip`.
my_ip(){
  local ip
  ip="$(status_json "$1" | jq -r --arg n "${2:-}" '
    (.networks // [])
    | (if $n == "" then .[0] else (map(select(.name == $n)) | .[0]) end)
    | .my_ipv6 // empty')"
  [[ -n "$ip" ]] || { fail_out "my_ip: $1 reports no mesh IPv6 for network '${2:-<first>}'"; return 1; }
  echo "$ip"
}

# peer_ip <ip> <peer-hostname> [net] : a specific peer's mesh IPv6 as seen by
# <ip>. Searches the named network, or all networks if net omitted. Empty when
# the peer is genuinely absent, which several callers test for, so this one does
# not fail on empty.
peer_ip(){
  status_json "$1" | jq -r --arg h "$2" --arg n "${3:-}" '
    (.networks // [])
    | (if $n == "" then . else map(select(.name == $n)) end)
    | [ .[].peers[] | select((.hostname // "") == $h) ] | .[0].ipv6 // empty'
}

# peer_online <ip> <peer-hostname> [net] : echo 1 if that peer has a live
# connection (.connection != null), else 0.
peer_online(){
  local r
  r="$(status_json "$1" | jq -r --arg h "$2" --arg n "${3:-}" '
    (.networks // [])
    | (if $n == "" then . else map(select(.name == $n)) end)
    | [ .[].peers[] | select((.hostname // "") == $h) ] | .[0]
    | if . != null and .connection != null then "1" else "0" end')"
  echo "${r:-0}"
}

# net_role <ip> <net> : the node's role on a network (lowercased:
# coordinator/member/direct). Empty if the node isn't on that network.
net_role(){
  status_json "$1" | jq -r --arg n "$2" '
    (.networks // []) | map(select(.name == $n)) | .[0].role // empty' \
    | tr 'A-Z' 'a-z'
}

# has_net <ip> <net> : exit 0 if the node has a network by that name.
has_net(){
  [[ -n "$(status_json "$1" | jq -r --arg n "$2" \
    '(.networks // []) | map(select(.name == $n)) | .[0].name // empty')" ]]
}

# ---------------------------------------------------------------------------
# Polling / convergence
# ---------------------------------------------------------------------------

# retry_until <secs> <shell-cond...> : eval the condition every 3s until it
# succeeds or <secs> elapse. Returns the condition's last exit status.
retry_until(){
  local secs="$1"; shift
  local end=$((SECONDS + secs))
  while (( SECONDS < end )); do
    if eval "$*"; then return 0; fi
    sleep 3
  done
  return 1
}

# _roster_has <ip> <host...> : exit 0 iff every named host is online from <ip>.
_roster_has(){
  local ip="$1"; shift
  local h
  for h in "$@"; do [[ "$(peer_online "$ip" "$h")" == "1" ]] || return 1; done
}

# wait_roster <ip> <host...> : block (≤120s) until all named peers are online
# from <ip>'s view, then PASS/FAIL.
wait_roster(){
  local ip="$1"; shift
  if retry_until 120 "_roster_has '$ip' $*"; then
    pass "roster converged on $ip (sees: $*)"
  else
    fail "roster did not converge on $ip (want: $*)"
  fi
}

# ---------------------------------------------------------------------------
# Firewall reachability probes (data-plane, over the TUN)
# ---------------------------------------------------------------------------

# tcp_probe <from-ip> <dst-vpn-ip> <port> : echo OPEN if a TCP SYN handshake
# completes, CLOSED otherwise. A pure connect (no payload), so conntrack on the
# sender isn't a factor.
tcp_probe(){
  on "$1" "timeout 5 bash -c 'exec 3<>/dev/tcp/$2/$3' && echo OPEN || echo CLOSED" \
    2>/dev/null | strip | tr -d '[:space:]'
}

# start_tcp_listener <ip> <port> / stop_tcp_listener <ip> <port> : a detached
# HTTP server on the host, and its teardown.
#
# Binds `::`, not `0.0.0.0`. The overlay is IPv6-only, so a socket on the IPv4
# wildcard has no presence on the TUN at all and every probe against it reads
# CLOSED whatever the firewall says: the deny assertions would pass for the wrong
# reason and the allow assertions could never pass. `::` accepts both families
# on Linux (net.ipv6.bindv6only defaults to 0), which is the same fix a user hits
# when a service of theirs stops answering over the mesh.
start_tcp_listener(){
  on "$1" "setsid python3 -m http.server $2 --bind :: >/tmp/lst_$2.log 2>&1 </dev/null & sleep 1" \
    >/dev/null 2>&1 || true
}
stop_tcp_listener(){ on "$1" "pkill -f 'http.server $2'" >/dev/null 2>&1 || true; }

# udp_probe <from-pub-ip> <dst-pub-ip> <dst-vpn-ip> <port> : echo OPEN if a UDP
# datagram sent from <from-pub-ip> to <dst-vpn-ip> reaches a listener on the
# destination, CLOSED otherwise. Both hosts are reached over SSH by their PUBLIC
# ips (the test runner can't route the VPN range); the datagram itself is
# addressed to <dst-vpn-ip> so it rides the TUN and is subject to the firewall.
# A one-shot python receiver on the destination drops a marker on first packet.
udp_probe(){
  local from_pub="$1" dst_pub="$2" dst_vpn="$3" port="$4"
  # AF_INET6 on both ends: <dst-vpn-ip> is a mesh address and there is no other
  # family to fall back to, so an AF_INET socket here never sees the datagram.
  on "$dst_pub" "rm -f /tmp/udp_got_$port; setsid python3 -c 'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.settimeout(8); s.bind((\"::\",$port));
try:
 s.recvfrom(64); open(\"/tmp/udp_got_$port\",\"w\").write(\"1\")
except Exception: pass' >/dev/null 2>&1 </dev/null & sleep 1" >/dev/null 2>&1 || true
  on "$from_pub" "python3 -c 'import socket; socket.socket(socket.AF_INET6,socket.SOCK_DGRAM).sendto(b\"x\",(\"$dst_vpn\",$port))'" >/dev/null 2>&1 || true
  sleep 2
  on "$dst_pub" "[ -f /tmp/udp_got_$port ] && echo OPEN || echo CLOSED" 2>/dev/null | strip | tr -d '[:space:]'
}

# fw_allows / fw_denies <from-pub-ip> <dst-vpn-ip> <port> <label> [proto] [dst-pub-ip] :
# PASS/FAIL on the expected TCP (default) or UDP reachability. proto = tcp|udp.
# For UDP a receiver is started on the destination host, so <dst-pub-ip> (its
# PUBLIC/SSH ip) is required as the 6th argument; TCP ignores it.
fw_allows(){
  local proto="${5:-tcp}" dst_pub="${6:-}" r
  if [[ "$proto" == udp ]]; then r="$(udp_probe "$1" "$dst_pub" "$2" "$3")"; else r="$(tcp_probe "$1" "$2" "$3")"; fi
  [[ "$r" == OPEN ]] && pass "$4 ($proto:$3 open)" || fail "$4 (expected OPEN on $proto:$3, got '$r')"
}
fw_denies(){
  local proto="${5:-tcp}" dst_pub="${6:-}" r
  if [[ "$proto" == udp ]]; then r="$(udp_probe "$1" "$dst_pub" "$2" "$3")"; else r="$(tcp_probe "$1" "$2" "$3")"; fi
  [[ "$r" == CLOSED ]] && pass "$4 ($proto:$3 denied)" || fail "$4 (expected CLOSED on $proto:$3, got '$r')"
}

# fw_pending_count <ip> <net> : number of suggested rules queued for review on a
# node (from `ray firewall pending <net> --json`).
fw_pending_count(){
  on "$1" "ray firewall pending $2 --json" 2>/dev/null | jq -r '(.rules // []) | length'
}

# fw_suggested_count <ip> [net] : number of *installed* rules tagged as suggested
# (optionally by a specific network), from `ray firewall show --json`.
fw_suggested_count(){
  on "$1" 'ray firewall show --json' 2>/dev/null | jq -r --arg n "${2:-}" \
    '[ (.rules // [])[] | select(.suggested_by != null) | select($n == "" or .suggested_by == $n) ] | length'
}

# ---------------------------------------------------------------------------
# Invite minting (coordinator side)
# ---------------------------------------------------------------------------

# mint_invite <coord-ip> <net> <hostname> : mint a single-use, hostname-bound
# invite and echo its join code.
mint_invite(){
  on "$1" "ray invite $2 create --hostname $3" | strip \
    | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1
}

# mint_reusable <coord-ip> <net> : mint a reusable (multi-use) key, echo the code.
mint_reusable(){
  on "$1" "ray invite $2 create --reusable" | strip \
    | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1
}

# request_id <coord-ip> <net> <hostname> : the short id of a queued join request
# matching <hostname> (from `ray requests <net> --json`). Empty if none.
request_id(){
  on "$1" "ray requests $2 --json" 2>/dev/null \
    | jq -r --arg h "$3" 'map(select((.hostname // "") == $h)) | .[0].id // empty'
}

# peer_endpoint <ip> <peer-hostname> [net] : a peer's full endpoint id as seen by
# <ip> (for `ray admin add`, which prefix-matches). Empty if absent.
peer_endpoint(){
  status_json "$1" | jq -r --arg h "$2" --arg n "${3:-}" '
    (.networks // [])
    | (if $n == "" then . else map(select(.name == $n)) end)
    | [ .[].peers[] | select((.hostname // "") == $h) ] | .[0].endpoint_id // empty'
}

# send_recv <from-ip> <to-ip> <to-peer-hostname> <label> : ray send a 1MiB random
# file and verify the sha256 round-trips after `ray files accept`. SR_PREFIX sets
# the temp-file path prefix (default /tmp/ray_e2e).
send_recv(){
  local from="$1" to="$2" peer="$3" label="$4"
  local pfx="${SR_PREFIX:-/tmp/ray_e2e}"
  on "$from" "head -c 1048576 /dev/urandom > ${pfx}_src.bin; sha256sum ${pfx}_src.bin | cut -d' ' -f1 > ${pfx}_src.sha"
  local src_sha; src_sha="$(on "$from" "cat ${pfx}_src.sha")"
  on "$from" "ray send $peer ${pfx}_src.bin" 2>&1 | strip | sed 's/^/      send| /'
  # `ray files` rows are `<id> <from> <size> <file> …` with a numeric id; the
  # header row's first column is the literal "id", so match a numeric id.
  local fid=""
  for _ in $(seq 1 12); do
    fid="$(on "$to" 'ray files' 2>/dev/null | strip | awk '$1 ~ /^[0-9]+$/ {print $1; exit}')"
    [[ -n "$fid" ]] && break
    sleep 3
  done
  if [[ -z "$fid" ]]; then fail "$label: no incoming file offer on receiver"; return; fi
  on "$to" "rm -rf ${pfx}_recv && mkdir -p ${pfx}_recv && ray files accept $fid --output ${pfx}_recv" 2>&1 | strip | sed 's/^/      recv| /'
  local dst_sha=""
  for _ in $(seq 1 10); do
    dst_sha="$(on "$to" "f=\$(find ${pfx}_recv -type f | head -1); [ -n \"\$f\" ] && sha256sum \"\$f\" | cut -d' ' -f1")"
    [[ -n "$dst_sha" ]] && break
    sleep 2
  done
  if [[ -n "$dst_sha" && "$dst_sha" == "$src_sha" ]]; then
    pass "$label (sha ${src_sha:0:12}… verified)"
  else
    fail "$label (sent ${src_sha:0:12}… got ${dst_sha:0:12}…)"
  fi
}
