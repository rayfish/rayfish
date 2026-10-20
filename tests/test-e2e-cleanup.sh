#!/usr/bin/env bash
# Regression checks for Docker cleanup and bounded failure diagnostics.
# Uses the real harness functions with fake Docker/SSH commands; no daemon needed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT

source <(sed -n '/^servers_backend(){/,/^}/p' "$ROOT/tests/lib/docker.sh")
source <(sed -n '/^do_teardown(){/,/^}/p' "$ROOT/tests/lib/docker.sh")

check(){
  if "$@" > "$TEST_TMP/check-output" 2>&1; then
    printf 'PASS %s\n' "$*"
  else
    cat "$TEST_TMP/check-output" >&2
    printf 'FAIL %s\n' "$*" >&2
    exit 1
  fi
}

# Container and network existence are files so changes survive command
# substitutions, just as successful removals persist on a real Docker daemon.
docker(){
  case "$1 ${2:-}" in
    'ps -a')
      [[ "${CONTAINER_QUERY_RC:-0}" == 0 ]] || return 1
      local name
      for name in a b other; do
        [[ ! -f "$FLEET/$name" ]] || printf '%s\n' "$name"
      done ;;
    'rm -f')
      printf 'rm %s\n' "$3" >> "$FLEET/calls"
      if [[ -f "$FLEET/$3.fail" ]]; then
        rm -f "$FLEET/$3.fail"
        return 1
      fi
      [[ -f "$FLEET/$3" ]] || return 1
      rm -f "$FLEET/$3" ;;
    'network ls')
      [[ "${NETWORK_QUERY_RC:-0}" == 0 ]] || return 1
      [[ ! -f "$FLEET/network" ]] || printf '%s\n' "$DOCKER_NET" ;;
    'network inspect')
      [[ "${NETWORK_INSPECT_RC:-0}" == 0 ]] || return 1
      local name attached=0
      for name in a b other; do
        [[ ! -f "$FLEET/$name" ]] || attached=$((attached + 1))
      done
      printf '%s\n' "$attached" ;;
    'network rm')
      [[ "${NETWORK_REMOVE_RC:-0}" == 0 ]] || return 1
      rm -f "$FLEET/network" ;;
    *) printf 'Unexpected Docker command: %s\n' "$*" >&2; return 1 ;;
  esac
}

cleanup_retry(){ (
  local FLEET="$TEST_TMP/retry" SERVERS="$TEST_TMP/retry/servers"
  local DOCKER_NET=rayfish-e2e NAMES=(a b) rc=0
  mkdir -p "$FLEET"
  printf 'a 1 srv-a docker\nb 2 srv-b docker\n' > "$SERVERS"
  touch "$FLEET/a" "$FLEET/b" "$FLEET/b.fail" "$FLEET/network"
  do_teardown || rc=$?
  [[ $rc == 1 && -f "$SERVERS" && ! -f "$FLEET/a" && -f "$FLEET/b" ]] || return 1
  do_teardown || return 1
  [[ ! -f "$SERVERS" && ! -f "$FLEET/b" && ! -f "$FLEET/network" ]] || return 1
  [[ $(grep -c '^rm a$' "$FLEET/calls") == 1 ]] || return 1
  [[ $(grep -c '^rm b$' "$FLEET/calls") == 2 ]] || return 1
  # Teardown also succeeds after all containers and metadata are absent.
  do_teardown
) ; }

cleanup_without_servers(){ (
  local FLEET="$TEST_TMP/fallback" SERVERS="$TEST_TMP/fallback/servers"
  local DOCKER_NET=rayfish-e2e NAMES=(a b)
  mkdir -p "$FLEET"
  touch "$FLEET/a" "$FLEET/b" "$FLEET/other" "$FLEET/network"
  do_teardown || return 1
  [[ ! -f "$FLEET/a" && ! -f "$FLEET/b" && -f "$FLEET/other" && -f "$FLEET/network" ]]
) ; }

cleanup_api_failures(){ (
  local FLEET="$TEST_TMP/api" SERVERS="$TEST_TMP/api/servers"
  local DOCKER_NET=rayfish-e2e NAMES=(a b) CONTAINER_QUERY_RC=1
  mkdir -p "$FLEET"
  printf 'a 1 srv-a docker\n' > "$SERVERS"
  touch "$FLEET/a"
  if do_teardown; then return 1; fi
  [[ -f "$SERVERS" && -f "$FLEET/a" && ! -f "$FLEET/calls" ]] || return 1
  rm -f "$SERVERS"
  if do_teardown; then return 1; fi
  [[ -f "$FLEET/a" ]] || return 1

  CONTAINER_QUERY_RC=0
  local NETWORK_QUERY_RC=1
  if do_teardown; then return 1; fi
  [[ ! -f "$FLEET/a" ]] || return 1
  NETWORK_QUERY_RC=0
  touch "$FLEET/network"
  local NETWORK_INSPECT_RC=1
  if do_teardown; then return 1; fi
  [[ -f "$FLEET/network" ]] || return 1
  NETWORK_INSPECT_RC=0
  local NETWORK_REMOVE_RC=1
  if do_teardown; then return 1; fi
  [[ -f "$FLEET/network" ]]
) ; }

diagnostics_timeout(){ (
  # Copy only the dispatcher; fake provision/run/teardown isolates the failure
  # lifecycle while PATH commands exercise its actual diagnostic timeouts.
  local sandbox="$TEST_TMP/diagnostics"
  mkdir -p "$sandbox/bin" "$sandbox/tests/lib" "$sandbox/tests/e2e/closed-net"
  cp "$ROOT/tests/e2e.sh" "$sandbox/tests/e2e.sh"
  cat > "$sandbox/tests/lib/docker.sh" <<'EOF'
case "$DOCKER_ACTION" in
  provision)
    echo provision >> "$CALLS"
    printf 'a 1 srv-a docker\nb 2 srv-b docker\n' > "$SERVERS" ;;
  teardown)
    echo teardown >> "$CALLS"
    rm -f "$SERVERS" ;;
esac
EOF
  cat > "$sandbox/tests/e2e/closed-net/run.sh" <<'EOF'
echo run >> "$CALLS"
exit 17
EOF
  cat > "$sandbox/bin/timeout" <<'EOF'
#!/usr/bin/env bash
echo "timeout $*" >> "$CALLS"
[[ "$1" == --kill-after=2s && "$2" == 10s ]] || exit 2
shift 2
exec "$REAL_TIMEOUT" --kill-after=0.1s 0.2s "$@"
EOF
  cat > "$sandbox/bin/ssh" <<'EOF'
#!/usr/bin/env bash
echo ssh >> "$CALLS"
sleep 30
EOF
  cat > "$sandbox/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $1" >> "$CALLS"
sleep 30
EOF
  chmod +x "$sandbox/bin/timeout" "$sandbox/bin/ssh" "$sandbox/bin/docker"
  export REAL_TIMEOUT="$(command -v timeout)" CALLS="$sandbox/calls"
  local rc=0
  PATH="$sandbox/bin:$PATH" E2E_BACKEND=docker E2E_AUTO_TEARDOWN=1 \
    "$REAL_TIMEOUT" --kill-after=1s 5s bash "$sandbox/tests/e2e.sh" closed-net run \
      > "$sandbox/output" 2>&1 || rc=$?
  [[ $rc == 17 ]] || { cat "$sandbox/output"; return 1; }
  [[ $(grep -c '^timeout ' "$CALLS") == 5 ]] || return 1
  [[ $(grep -c '^docker ps$' "$CALLS") == 1 ]] || return 1
  [[ $(grep -c '^docker exec$' "$CALLS") == 2 ]] || return 1
  [[ $(grep -c '^ssh$' "$CALLS") == 2 ]] || return 1
  [[ $(tail -n 1 "$CALLS") == teardown && ! -f "$sandbox/tests/e2e/closed-net/.servers" ]]
) ; }

check cleanup_retry
check cleanup_without_servers
check cleanup_api_failures
check diagnostics_timeout
