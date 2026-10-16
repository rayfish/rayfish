#!/usr/bin/env bash
# Regression checks for the direct-connect scenario's unknown-peer negative case.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT
# shellcheck source=lib/common.sh
source "$ROOT/tests/lib/common.sh"
# Load the actual scenario helper without provisioning or executing its flow.
source <(sed -n '/^check_unknown_peer(){/,/^}/p' "$ROOT/tests/e2e/connect/run.sh")

unknown_case(){ (
  local mode="$1" expected="$2" rc=0
  local peer=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  on(){
    case "$2" in
      "timeout --kill-after=5s 30s ray connect $peer")
        case "$mode" in
          unrelated_error) echo 'connect failed: cannot load configuration'; return 1 ;;
          success) echo 'connected'; return 0 ;;
          misleading_success) echo 'failed to reach peer: timed out'; return 0 ;;
          expected_error_with_extra_text) echo 'configuration failed: failed to reach peer: x'; return 1 ;;
          timeout) echo 'failed to reach peer: timed out'; return 124 ;;
          ssh_failure) echo 'failed to reach peer: timed out'; return 255 ;;
          *) printf '  ✗ connect failed\n    failed to reach peer: no addressing information\n'; return 1 ;;
        esac ;;
      *) echo "unexpected command: $2" >&2; return 42 ;;
    esac
  }
  check_unknown_peer src "$peer" || rc=$?
  if [[ "$expected" == pass ]]; then
    [[ $rc == 0 && $FAILS == 0 ]]
  else
    [[ $rc == 1 && $FAILS == 1 ]]
  fi
) ; }

for mode in normal unrelated_error success misleading_success \
            expected_error_with_extra_text timeout ssh_failure; do
  expected=fail
  [[ "$mode" != normal ]] || expected=pass
  if unknown_case "$mode" "$expected" > "$TEST_TMP/output" 2>&1; then
    printf 'PASS unknown peer: %s\n' "$mode"
  else
    cat "$TEST_TMP/output" >&2
    printf 'FAIL unknown peer: %s\n' "$mode" >&2
    exit 1
  fi
done
