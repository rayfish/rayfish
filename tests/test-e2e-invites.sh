#!/usr/bin/env bash
# The legacy invite check waits for discovery but still rejects wrong outcomes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT
source "$ROOT/tests/lib/common.sh"
source <(sed -n '/^check_older_recipient(){/,/^}/p' "$ROOT/tests/e2e/invites/run.sh")

legacy_case(){ (
  local mode="$1" expected="$2" rc=0
  local attempts_file="$TEST_TMP/attempts"
  echo 0 > "$attempts_file"
  # Bounded attempts without wall-clock sleeps for the regression cases.
  retry_until(){
    shift
    local attempt
    for attempt in 1 2 3; do
      if eval "$*"; then return 0; fi
    done
    return 1
  }
  apply_invite(){
    local attempts
    attempts=$(( $(cat "$attempts_file") + 1 ))
    echo "$attempts" > "$attempts_file"
    [[ "$1 $2 $3" == 'alias peer network' ]] || return 1
    case "$mode" in
      unreachable) echo 'peer is unreachable; invite queued and retried until it expires' ;;
      delivered) echo 'invite delivered; awaiting the recipient' ;;
      command_error) echo 'older Rayfish that cannot receive invites; send them this code'; return 255 ;;
      discovery_delay)
        if (( attempts == 1 )); then
          echo 'peer is unreachable; invite queued and retried until it expires'
        else
          echo 'peer runs an older Rayfish that cannot receive invites; send them this code instead: example-code'
        fi ;;
      ready) echo 'peer runs an older Rayfish that cannot receive invites; send them this code instead: example-code' ;;
    esac
  }
  check_older_recipient alias peer network || rc=$?
  if [[ "$expected" == pass ]]; then
    [[ $rc == 0 && $FAILS == 0 ]]
  else
    [[ $rc == 1 && $FAILS == 1 ]]
  fi
) ; }

for mode in ready discovery_delay unreachable delivered command_error; do
  expected=fail
  case "$mode" in ready|discovery_delay) expected=pass ;; esac
  if legacy_case "$mode" "$expected" > "$TEST_TMP/output" 2>&1; then
    printf 'PASS older recipient: %s\n' "$mode"
  else
    cat "$TEST_TMP/output" >&2
    printf 'FAIL older recipient: %s\n' "$mode" >&2
    exit 1
  fi
done
