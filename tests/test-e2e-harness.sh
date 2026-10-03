#!/usr/bin/env bash
# Regression checks for the E2E harness; no Docker daemon or cloud credentials.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT
# shellcheck source=lib/common.sh
source "$ROOT/tests/lib/common.sh"

check(){
  if "$@" > "$TEST_TMP/check-output" 2>&1; then
    printf 'PASS %s\n' "$*"
  else
    cat "$TEST_TMP/check-output" >&2
    printf 'FAIL %s\n' "$*" >&2
    exit 1
  fi
}

activation(){ (
  # The CLI's config fallback exits zero before IPC appears. It must not count
  # as readiness, and an inactive IPC response must permit `ray up`.
  local attempts_file="$TEST_TMP/activation-attempts" activated=0
  echo 0 > "$attempts_file"
  sleep(){ :; }
  on(){
    case "$2" in
      'ray up') [[ $(cat "$attempts_file") == 3 ]] || return 1; activated=1 ;;
      'timeout --kill-after=2s 10s ray status --json')
        if [[ $activated == 1 ]]; then echo '{"active":true}'; return 0; fi
        local attempts
        attempts=$(( $(cat "$attempts_file") + 1 ))
        echo "$attempts" > "$attempts_file"
        if (( attempts < 3 )); then echo 'daemon not running'; else echo '{"active":false}'; fi
        ;;
      *) return 1 ;;
    esac
  }
  activate_daemons host || return 1
  [[ $(cat "$attempts_file") == 3 && $activated == 1 && $FAILS == 0 ]]
) ; }

activation_failure(){ (
  on(){
    [[ "$2" == 'timeout --kill-after=2s 10s ray status --json' ]] || return 1
    echo '{"active":false}'
  }
  if activate_daemons host; then return 1; fi
  [[ $FAILS == 1 ]]
) ; }

daemon_readiness(){ (
  local fixture
  on(){ printf '%s\n' "$fixture"; }
  for fixture in '{"active":false}' '{"active":true}'; do
    daemon_ready host || return 1
  done
  for fixture in 'daemon not running' '{}' '{"active":null}' '{"active":"false"}' 'invalid'; do
    if daemon_ready host; then return 1; fi
  done
  on(){ echo '{"active":true}'; return 255; }
  if daemon_ready host; then return 1; fi
) ; }

wait_daemons_readiness(){ (
  local attempts_file="$TEST_TMP/wait-attempts"
  echo 0 > "$attempts_file"
  sleep(){ :; }
  on(){
    [[ "$2" == 'timeout --kill-after=2s 10s ray status --json' ]] || return 1
    local attempts
    attempts=$(( $(cat "$attempts_file") + 1 ))
    echo "$attempts" > "$attempts_file"
    if (( attempts < 3 )); then echo 'daemon not running'; else echo '{"active":false}'; fi
  }
  wait_daemons host
  [[ $(cat "$attempts_file") == 3 && $FAILS == 0 ]] || return 1
  on(){ echo 'daemon not running'; }
  retry_until(){ shift; eval "$*"; }
  wait_daemons host
  [[ $FAILS == 1 ]]
) ; }

status_query_timeout(){ (
  local test_bin="$TEST_TMP/stuck-status" rc=0 start=$SECONDS
  mkdir -p "$test_bin"
  cat > "$test_bin/ray" <<'EOF'
#!/usr/bin/env bash
exec sleep 30
EOF
  chmod +x "$test_bin/ray"
  on(){ PATH="$test_bin:$PATH" bash -c "$2"; }
  status_json host || rc=$?
  [[ $rc == 124 && $((SECONDS - start)) -le 13 ]]
) ; }

standby_is_not_active(){ (
  on(){ return 0; }
  status_json(){ echo '{"active":false}'; }
  # Keep this failure-path check fast while still evaluating the real predicate.
  retry_until(){ shift; eval "$*"; }
  if activate_daemons host; then return 1; fi
  [[ $FAILS == 1 ]]
) ; }

network_absence(){ (
  local fixture
  status_json(){ printf '%s\n' "$fixture"; }
  fixture='{"networks":[]}'
  net_absent host priv || return 1
  fixture='{"networks":[{"name":"other"}]}'
  net_absent host priv || return 1
  for fixture in '{"networks":[{"name":"priv"}]}' '{}' 'null' '{"networks":{}}' 'invalid'; do
    if net_absent host priv; then return 1; fi
  done
  status_json(){ echo '{"networks":[]}'; return 255; }
  if net_absent host priv; then return 1; fi
) ; }

diagnostics(){ (
  # Exercise the dispatcher's actual function without provisioning a fleet.
  source <(sed -n '/^dump_diagnostics(){/,/^}/p' "$ROOT/tests/e2e.sh")
  local SERVERS="$TEST_TMP/diagnostic-servers" E2E_BACKEND=docker
  local SSH_KEY="$TEST_TMP/custom-key" scenario=closed-net
  printf 'a 1 srv-a docker\nb 2 srv-b docker\nc 3 srv-c docker\n' > "$SERVERS"
  ssh(){
    [[ "$*" == *'-n '* && "$*" == *'BatchMode=yes'* && "$*" == *"-i $SSH_KEY"* ]] || return 1
    echo "ssh $*" >> "$TEST_TMP/diagnostics"
    # A real ssh without -n would consume all the remaining server rows.
    [[ "$1" == -n ]] || cat >/dev/null
  }
  docker(){ echo "docker $*" >> "$TEST_TMP/diagnostics"; }
  timeout(){ shift 2; "$@"; }
  dump_diagnostics >/dev/null
  [[ $(grep -c '^ssh ' "$TEST_TMP/diagnostics") == 3 ]] || return 1
  [[ $(grep -c '^docker exec ' "$TEST_TMP/diagnostics") == 3 ]]
) ; }

lifecycle(){ (
  # A sandbox copy keeps the real dispatcher and substitutes only its backends.
  local sandbox="$TEST_TMP/lifecycle"
  mkdir -p "$sandbox/tests/lib" "$sandbox/tests/e2e/closed-net"
  cp "$ROOT/tests/e2e.sh" "$sandbox/tests/e2e.sh"
  cat > "$sandbox/tests/lib/docker.sh" <<'EOF'
case "$DOCKER_ACTION" in
  provision) echo provision >> "$CALLS"; exit "${PROVISION_RC:-0}" ;;
  teardown) echo teardown >> "$CALLS"; exit "${TEARDOWN_RC:-0}" ;;
esac
EOF
  cat > "$sandbox/tests/e2e/closed-net/run.sh" <<'EOF'
echo run >> "$CALLS"
exit "${SCENARIO_RC:-0}"
EOF
  docker(){ return 0; }; export -f docker
  timeout(){ shift 2; "$@"; }; export -f timeout
  export CALLS="$sandbox/calls" E2E_BACKEND=docker E2E_AUTO_TEARDOWN=1
  local spec expected rc
  for spec in '42 0 0 42' '0 17 0 17' '0 17 23 17' '0 0 23 23' '0 0 0 0'; do
    read -r PROVISION_RC SCENARIO_RC TEARDOWN_RC expected <<< "$spec"
    export PROVISION_RC SCENARIO_RC TEARDOWN_RC
    : > "$CALLS"
    rc=0
    bash "$sandbox/tests/e2e.sh" closed-net run > "$sandbox/output" 2>&1 || rc=$?
    [[ $rc == "$expected" ]] || { cat "$sandbox/output"; return 1; }
    [[ $(grep -c '^teardown$' "$CALLS") == 1 ]] || return 1
    if [[ $PROVISION_RC != 0 ]]; then
      if grep -q '^run$' "$CALLS"; then return 1; fi
    else
      grep -q '^run$' "$CALLS" || return 1
    fi
  done
) ; }

tcp_listeners(){ (
  local port held_pid="" end
  port="$(python3 -c 'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.bind(("::1",0)); print(s.getsockname()[1])')"
  on(){ bash -c "$2"; }
  trap 'stop_tcp_listener local "$port"; if [[ -n "$held_pid" ]]; then kill "$held_pid" 2>/dev/null || true; wait "$held_pid" 2>/dev/null || true; fi' EXIT
  start_tcp_listener local "$port" || return 1
  [[ "$(tcp_probe local ::1 "$port")" == OPEN && $FAILS == 0 ]] || return 1
  stop_tcp_listener local "$port"
  if ! retry_until 5 "[[ \"\$(tcp_probe local ::1 '$port')\" == CLOSED ]]"; then return 1; fi

  # Occupying the port proves that a detached Python bind failure is counted,
  # even though the remote shell that launched it exits successfully.
  python3 -c 'import socket, sys, time; s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.bind(("::",int(sys.argv[1]))); s.listen(); open(sys.argv[2],"w").write("1"); time.sleep(30)' "$port" "$TEST_TMP/tcp-held-ready" &
  held_pid=$!
  end=$((SECONDS + 5))
  while [[ ! -f "$TEST_TMP/tcp-held-ready" ]] && (( SECONDS < end )); do sleep 0.05; done
  [[ -f "$TEST_TMP/tcp-held-ready" ]] || return 1
  if start_tcp_listener local "$port"; then return 1; fi
  [[ $FAILS == 1 && ! -f /tmp/lst_ready_$port && ! -f /tmp/lst_pid_$port ]]
) ; }

tcp_probe_errors(){ (
  local probe_rc result rc
  on(){
    timeout(){ return "$probe_rc"; }
    eval "$2"
  }
  for probe_rc in 0 1 124 125 126 127 137; do
    rc=0
    result="$(tcp_probe local ::1 12345)" || rc=$?
    case "$probe_rc" in
      0) [[ "$result" == OPEN && $rc == 0 ]] ;;
      1|124) [[ "$result" == CLOSED && $rc == 0 ]] ;;
      *) [[ "$result" == ERROR && $rc != 0 ]] ;;
    esac || { echo "TCP exit $probe_rc: got $result (exit $rc)"; return 1; }
  done
  probe_rc=127
  fw_denies local ::1 12345 'broken tool must not prove denial'
  [[ $FAILS == 1 ]] || return 1
  on(){ echo OPEN; return 255; }
  rc=0
  result="$(tcp_probe local ::1 12345)" || rc=$?
  [[ "$result" == ERROR && $rc != 0 ]] || return 1
  on(){ echo unexpected; }
  rc=0
  result="$(tcp_probe local ::1 12345)" || rc=$?
  [[ "$result" == ERROR && $rc != 0 ]]
) ; }

udp_receivers(){ (
  local mode=normal result rc port
  port="$(python3 -c 'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(("::1",0)); print(s.getsockname()[1])')"
  on(){
    local cmd="$2"
    if [[ "$cmd" == *'sendto('* ]]; then
      case "$mode" in
        send_failure) return 1 ;;
        receiver_failure) kill "$(cat "/tmp/udp_pid_$port")"; return 0 ;;
        receive_error) touch "/tmp/udp_error_$port"; return 0 ;;
        denied|observation_failure) return 0 ;;
        receiver_timeout) sleep 0.3; return 0 ;;
      esac
    fi
    if [[ "$mode" == observation_failure && "$cmd" == *'echo GOT'* ]]; then return 255; fi
    if [[ "$mode" == setup_failure && "$cmd" == *'setsid python3'* ]]; then return 1; fi
    if [[ "$mode" == receiver_timeout ]]; then cmd="${cmd/s.settimeout(60)/s.settimeout(0.2)}"; fi
    bash -c "$cmd"
  }
  for mode in normal denied send_failure receiver_failure receive_error observation_failure setup_failure receiver_timeout; do
    rc=0
    result="$(udp_probe local local ::1 "$port")" || rc=$?
    case "$mode" in
      normal) [[ "$result" == OPEN && $rc == 0 ]] ;;
      denied) [[ "$result" == CLOSED && $rc == 0 ]] ;;
      *) [[ "$result" == ERROR && $rc != 0 ]] ;;
    esac || { echo "$mode: got $result (exit $rc)"; return 1; }
    [[ ! -f /tmp/udp_pid_$port && ! -f /tmp/udp_ready_$port && ! -f /tmp/udp_got_$port && ! -f /tmp/udp_error_$port ]] || return 1
  done
) ; }

abandoned_udp_receiver(){ (
  local port runner rc=0 end
  port="$(python3 -c 'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(("::1",0)); print(s.getsockname()[1])')"
  on(){ bash -c "$2"; }
  trap '_cleanup_udp_receiver local "$port"' EXIT
  cat > "$TEST_TMP/abandoned-udp-runner.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
source "$1/tests/lib/common.sh"
on(){
  local cmd="$2"
  # Interrupt after bind/readiness, without allowing the harness to clean up.
  if [[ "$cmd" == *'sendto('* ]]; then kill -TERM "$BASHPID"; return 1; fi
  # Shorten only the receiver's own deadline to keep this regression check fast.
  cmd="${cmd/s.settimeout(60)/s.settimeout(0.2)}"
  bash -c "$cmd"
}
udp_probe local local ::1 "$2"
EOF
  bash "$TEST_TMP/abandoned-udp-runner.sh" "$ROOT" "$port" > "$TEST_TMP/abandoned-udp-output" 2>&1 &
  runner=$!
  wait "$runner" || rc=$?
  [[ $rc == 143 ]] || return 1
  end=$((SECONDS + 3))
  while [[ ! -f /tmp/udp_error_$port ]] && (( SECONDS < end )); do sleep 0.05; done
  [[ -f /tmp/udp_error_$port ]] || return 1
  # The timed-out process must release its socket after losing its runner.
  python3 -c 'import socket, sys; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(("::",int(sys.argv[1])))' "$port"
) ; }

check activation
check activation_failure
check daemon_readiness
check wait_daemons_readiness
check status_query_timeout
check standby_is_not_active
check network_absence
check diagnostics
check lifecycle
check tcp_listeners
check tcp_probe_errors
check udp_receivers
check bash "$ROOT/tests/test-e2e-cleanup.sh"
check bash "$ROOT/tests/test-e2e-connect.sh"
check abandoned_udp_receiver
